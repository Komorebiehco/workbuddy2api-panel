package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

const credentialTable = "codebuddy_credentials"

// PostgresStore 与原 codebuddy2api 的凭证表兼容：
// payload 使用同一个 Fernet 密钥加密，删除通过 deleted tombstone 防复活。
type PostgresStore struct {
	db     *sql.DB
	cipher fernetCipher
}

type fernetCipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

// NewPostgresStore 建立连接并初始化/兼容已有 codebuddy_credentials 表。
func NewPostgresStore(dsn, encryptionKey string) (*PostgresStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("empty credentials database URL")
	}
	cipher, err := newFernetCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open credentials database: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)

	store := &PostgresStore{db: db, cipher: cipher}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping credentials database: %w", err)
	}
	if err := store.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS codebuddy_credentials (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    account_key TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL DEFAULT decode('', 'hex'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revision BIGINT NOT NULL DEFAULT 1,
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS id TEXT;
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS filename TEXT;
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS account_key TEXT;
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS ciphertext BYTEA;
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS nonce BYTEA NOT NULL DEFAULT '';
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE codebuddy_credentials
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS codebuddy_credentials_filename
    ON codebuddy_credentials (filename);
CREATE UNIQUE INDEX IF NOT EXISTS codebuddy_credentials_identity
    ON codebuddy_credentials (account_key)
    WHERE deleted = FALSE;
ALTER TABLE codebuddy_credentials ENABLE ROW LEVEL SECURITY;
CREATE TABLE IF NOT EXISTS workbuddy_documents (
    name TEXT PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE workbuddy_documents ENABLE ROW LEVEL SECURITY;
`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("initialize credentials table: %w", err)
	}
	return nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) PutAuth(a *Auth) error {
	if a == nil {
		return fmt.Errorf("put credential: nil auth")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, err := marshalAuth(a)
	uid := a.UID
	filename := a.RemoteName
	if filename == "" {
		filename = filepath.Base(a.FilePath)
	}
	if err != nil {
		return err
	}
	return s.PutRaw(uid, filename, raw)
}

func (s *PostgresStore) PutRaw(uid, filename string, raw []byte) error {
	return s.putRaw(uid, filename, raw, false)
}

func (s *PostgresStore) CreateRaw(uid, filename string, raw []byte) error {
	return s.putRaw(uid, filename, raw, true)
}

func (s *PostgresStore) putRaw(uid, filename string, raw []byte, allowRevive bool) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("credentials database is closed")
	}
	if strings.TrimSpace(uid) == "" {
		return fmt.Errorf("put credential: empty uid")
	}
	if len(raw) == 0 {
		return fmt.Errorf("put credential uid=%s: empty payload", uid)
	}
	filename = safeRemoteFilename(uid, filename)
	encrypted, err := s.cipher.Encrypt(raw)
	if err != nil {
		return fmt.Errorf("encrypt credential uid=%s: %w", uid, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 旧 Python 服务的 account_key 是 profile/UID/tenant 指纹，不是 UID。
	// 更新时按远端文件名复用原 account_key，避免触发部分唯一索引。
	var remoteAccountKey string
	if err := s.db.QueryRowContext(ctx,
		`SELECT account_key
		   FROM codebuddy_credentials
		  WHERE filename = $1
		  LIMIT 1`, filename).Scan(&remoteAccountKey); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("find existing credential filename=%s: %w", filename, err)
	}
	if strings.TrimSpace(remoteAccountKey) == "" {
		sum := sha256.Sum256([]byte(uid))
		remoteAccountKey = fmt.Sprintf("%x", sum[:])
	}
	id := sha256.Sum256([]byte(filename))

	// 保持与 Python 版相同的同名覆盖、同 UID 唯一和 revision 递增语义。
	const q = `
INSERT INTO codebuddy_credentials
    (id, filename, account_key, ciphertext, nonce, revision, deleted, updated_at)
VALUES ($1, $2, $3, $4, '', 1, FALSE, NOW())
ON CONFLICT (filename) DO UPDATE SET
    id = EXCLUDED.id,
    filename = EXCLUDED.filename,
    account_key = EXCLUDED.account_key,
    ciphertext = EXCLUDED.ciphertext,
    nonce = EXCLUDED.nonce,
    revision = codebuddy_credentials.revision + 1,
    deleted = FALSE,
    updated_at = NOW()
WHERE codebuddy_credentials.deleted = FALSE OR $5
`
	result, err := s.db.ExecContext(ctx, q, fmt.Sprintf("%x", id[:]), filename, remoteAccountKey, encrypted, allowRevive)
	if err != nil {
		return fmt.Errorf("upsert credential uid=%s: %w", uid, err)
	}
	if n, err := result.RowsAffected(); err != nil || n == 0 {
		return fmt.Errorf("credential was deleted; a new OAuth login is required")
	}
	return nil
}

func (s *PostgresStore) Delete(uid, filename string) error {
	if strings.TrimSpace(uid) == "" {
		return fmt.Errorf("delete credential: empty uid")
	}
	tombstone, err := json.Marshal(map[string]string{"uid": uid})
	if err != nil {
		return err
	}
	encrypted, err := s.cipher.Encrypt(tombstone)
	if err != nil {
		return fmt.Errorf("encrypt tombstone uid=%s: %w", uid, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if strings.TrimSpace(filename) == "" {
		filename = safeFilename(uid, "")
	}
	filename = filepath.Base(filename)
	filename = safeRemoteFilename(uid, filename)
	id := sha256.Sum256([]byte(filename))
	accountKey := "deleted:" + fmt.Sprintf("%x", sha256.Sum256([]byte(filename)))
	var existingAccountKey string
	if err := s.db.QueryRowContext(ctx,
		`SELECT account_key
		   FROM codebuddy_credentials
		  WHERE filename = $1
		  LIMIT 1`, filename).Scan(&existingAccountKey); err == nil && existingAccountKey != "" {
		accountKey = existingAccountKey
	} else if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("find credential filename=%s: %w", filename, err)
	}
	const q = `
INSERT INTO codebuddy_credentials
    (id, filename, account_key, ciphertext, nonce, revision, deleted, updated_at)
VALUES ($1, $2, $3, $4, '', 1, TRUE, NOW())
ON CONFLICT (filename) DO UPDATE SET
    id = EXCLUDED.id,
    filename = EXCLUDED.filename,
    account_key = EXCLUDED.account_key,
    ciphertext = EXCLUDED.ciphertext,
    nonce = EXCLUDED.nonce,
    revision = codebuddy_credentials.revision + 1,
    deleted = TRUE,
    updated_at = NOW()
`
	if _, err := s.db.ExecContext(ctx, q, fmt.Sprintf("%x", id[:]), filename, accountKey, encrypted); err != nil {
		return fmt.Errorf("tombstone credential uid=%s: %w", uid, err)
	}
	return nil
}

func (s *PostgresStore) RestoreDir(dir string) (*RemoteSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx,
		`SELECT filename, account_key, ciphertext, deleted
		   FROM codebuddy_credentials
		  ORDER BY filename`)
	if err != nil {
		return nil, fmt.Errorf("list remote credentials: %w", err)
	}
	defer rows.Close()

	out := &RemoteSnapshot{Auths: make([]*Auth, 0), Known: make(map[string]bool)}
	activeUIDs := make(map[string]bool)
	for rows.Next() {
		var filename, uid string
		var ciphertext []byte
		var deleted bool
		if err := rows.Scan(&filename, &uid, &ciphertext, &deleted); err != nil {
			return nil, fmt.Errorf("scan remote credential: %w", err)
		}
		out.HasRecords = true
		if deleted {
			if inferredUID := uidFromFilename(filename); inferredUID != "" {
				out.Known[inferredUID] = true
			}
			continue
		}
		raw, err := s.cipher.Decrypt(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypt remote credential uid=%s: %w", uid, err)
		}
		a, err := Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse remote credential uid=%s: %w", uid, err)
		}
		realUID := a.UID
		if realUID == "" {
			return nil, fmt.Errorf("remote credential has no account UID")
		}
		if activeUIDs[realUID] {
			return nil, fmt.Errorf("multiple remote credentials share a UID; this account pool requires distinct UIDs")
		}
		activeUIDs[realUID] = true
		a.UID = realUID
		a.RemoteName = filename
		a.FilePath = filepath.Join(dir, fmt.Sprintf("workbuddy-%s.json", safeUID(realUID)))
		if err := writeLocalAtomic(a.FilePath, raw); err != nil {
			return nil, fmt.Errorf("restore remote credential uid=%s: %w", uid, err)
		}
		out.Known[realUID] = true
		out.Auths = append(out.Auths, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read remote credentials: %w", err)
	}
	return out, nil
}

func safeFilename(uid, filename string) string {
	base := filepath.Base(strings.TrimSpace(filename))
	if base != "." && base != ".." &&
		strings.HasPrefix(base, "workbuddy-") &&
		strings.HasSuffix(base, ".json") &&
		!strings.ContainsAny(base, `/\`) {
		return base
	}
	return fmt.Sprintf("workbuddy-%s.json", safeUID(uid))
}

func safeRemoteFilename(uid, filename string) string {
	base := filepath.Base(strings.TrimSpace(filename))
	if base != "." && base != ".." &&
		(strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".info")) &&
		!strings.ContainsAny(base, `/\`) {
		return base
	}
	return fmt.Sprintf("workbuddy-%s.json", safeUID(uid))
}

func uidFromFilename(filename string) string {
	base := filepath.Base(filename)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	for _, prefix := range []string{"workbuddy-", "codebuddy-"} {
		if strings.HasPrefix(base, prefix) {
			uid := strings.TrimPrefix(base, prefix)
			if uid != "" {
				return uid
			}
		}
	}
	return ""
}

func safeUID(uid string) string {
	var b strings.Builder
	for _, r := range uid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func writeLocalAtomic(filePath string, raw []byte) error {
	if dir := filepath.Dir(filePath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir auth dir: %w", err)
		}
	}
	tmp := filePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write auth cache: %w", err)
	}
	if err := os.Rename(tmp, filePath); err != nil {
		return fmt.Errorf("replace auth cache: %w", err)
	}
	return nil
}

// Fernet token format is implemented locally to avoid bringing a second crypto
// library into the small Go binary while remaining compatible with Python's
// cryptography. The key is the standard 32-byte URL-safe base64 key.
type fernet struct {
	signingKey    []byte
	encryptionKey []byte
}

func newFernetCipher(raw string) (fernetCipher, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("credentials encryption key is required")
	}
	key, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.URLEncoding.DecodeString(raw)
	}
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("credentials encryption key must be a valid Fernet key")
	}
	return &fernet{signingKey: append([]byte(nil), key[:16]...), encryptionKey: append([]byte(nil), key[16:]...)}, nil
}

func (f *fernet) Encrypt(plain []byte) ([]byte, error) {
	// The complete Fernet wire implementation is kept in a small helper file.
	return fernetEncrypt(f.signingKey, f.encryptionKey, plain)
}

func (f *fernet) Decrypt(token []byte) ([]byte, error) {
	return fernetDecrypt(f.signingKey, f.encryptionKey, token)
}
