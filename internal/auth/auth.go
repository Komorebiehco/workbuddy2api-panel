// Package auth 解析 WorkBuddy auth 文件（嵌套形/扁平形双形态），
// 提供 refresh 后的原子写回。
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Auth 是归一化后的账号凭证（来源可以是插件 OAuth 嵌套形或手写扁平形）。
type Auth struct {
	// mu 串行化 RefreshToken 写与 SaveAtomic 读，防止并发写回半更新 token。
	mu sync.Mutex

	AccessToken  string
	RefreshToken string
	ExpiresAt    int64 // Unix 秒
	Domain       string
	UID          string
	EnterpriseID string
	Nickname     string
	FilePath     string // 来源文件；refresh 后原子写回此处
	RemoteName   string // 远端凭证表中的原始文件名（跨 Python/Go 分支迁移时保留）
	document     []byte
	deleted      bool
	pending      bool
}

// RemoteStore 是可选的凭证权威存储。磁盘文件仍作为本地热缓存，
// 远端实现负责加密保存、启动恢复和删除 tombstone。
type RemoteStore interface {
	PutAuth(a *Auth) error
	PutRaw(uid, filename string, raw []byte) error
	CreateRaw(uid, filename string, raw []byte) error
	RestoreDir(dir string) (*RemoteSnapshot, error)
	Delete(uid, filename string) error
	Close() error
}

// RemoteSnapshot 是启动时从远端恢复的结果。Known 包含 active 与 deleted UID，
// 用于防止旧的本地缓存把已删除账号重新导入。
type RemoteSnapshot struct {
	Auths      []*Auth
	Known      map[string]bool
	HasRecords bool
}

var (
	remoteMu    sync.RWMutex
	remoteStore RemoteStore
)

// SetRemoteStore 设置进程级凭证远端存储。传 nil 可关闭远端同步，主要供测试使用。
func SetRemoteStore(store RemoteStore) {
	remoteMu.Lock()
	remoteStore = store
	remoteMu.Unlock()
}

func currentRemoteStore() RemoteStore {
	remoteMu.RLock()
	defer remoteMu.RUnlock()
	return remoteStore
}

// Lock 供同进程内其他包（upstream.RefreshToken）在改写 Auth 字段期间加锁。
func (a *Auth) Lock() { a.mu.Lock() }

// Unlock 释放 a.Lock 获取的锁。
func (a *Auth) Unlock() { a.mu.Unlock() }

// NeedsRefresh 报告 token 是否将在 within 内过期（或已过期/无 expiry）。
func (a *Auth) NeedsRefresh(within time.Duration) bool {
	if a.ExpiresAt <= 0 {
		return true
	}
	return time.Now().Add(within).Unix() >= a.ExpiresAt
}

// Parse 兼容两种磁盘形态：
//
//	嵌套形 {"auth":{...},"account":{...}}  （插件 OAuth 输出）
//	扁平形 {"accessToken":...,"uid":...}   （手写/旧版）
func Parse(raw []byte) (*Auth, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty auth storage")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("storage_parse_error: %w", err)
	}
	var a Auth
	if _, nested := probe["auth"]; nested {
		var n struct {
			Auth struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
				ExpiresAt    int64  `json:"expiresAt"`
				Domain       string `json:"domain"`
			} `json:"auth"`
			Account struct {
				UID          string `json:"uid"`
				EnterpriseID string `json:"enterpriseId"`
				Nickname     string `json:"nickname"`
			} `json:"account"`
		}
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
		a = Auth{
			AccessToken:  n.Auth.AccessToken,
			RefreshToken: n.Auth.RefreshToken,
			ExpiresAt:    n.Auth.ExpiresAt,
			Domain:       n.Auth.Domain,
			UID:          n.Account.UID,
			EnterpriseID: n.Account.EnterpriseID,
			Nickname:     n.Account.Nickname,
		}
	} else {
		var f struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresAt    int64  `json:"expiresAt"`
			Domain       string `json:"domain"`
			UID          string `json:"uid"`
			EnterpriseID string `json:"enterpriseId"`
			Nickname     string `json:"nickname"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
		a = Auth{
			AccessToken:  f.AccessToken,
			RefreshToken: f.RefreshToken,
			ExpiresAt:    f.ExpiresAt,
			Domain:       f.Domain,
			UID:          f.UID,
			EnterpriseID: f.EnterpriseID,
			Nickname:     f.Nickname,
		}
	}
	if strings.TrimSpace(a.AccessToken) == "" {
		return nil, fmt.Errorf("parse_error: missing accessToken")
	}
	a.document = append([]byte(nil), raw...)
	return &a, nil
}

// SaveAtomic 以嵌套形原子写回 FilePath（tmp + rename），保持嵌套形（插件可读）格式。
// 先在 a.mu 保护下生成一致快照，再原子写回本地并同步远端，杜绝半更新。
// 防御：accessToken 为空时拒绝写回，避免误用空凭证覆盖有效文件。
func (a *Auth) SaveAtomic() error {
	return a.saveAtomic(false)
}

// SaveNew is reserved for an explicit OAuth login, which may restore a deleted account.
func (a *Auth) SaveNew() error {
	return a.saveAtomic(true)
}

func (a *Auth) saveAtomic(create bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.deleted {
		return fmt.Errorf("save refused: deleted credential")
	}
	if strings.TrimSpace(a.AccessToken) == "" {
		return fmt.Errorf("save refused: empty accessToken (uid=%s)", a.UID)
	}
	if a.FilePath == "" {
		return fmt.Errorf("no FilePath set")
	}
	raw, err := marshalAuth(a)
	if err != nil {
		return err
	}
	filePath := a.FilePath
	uid := a.UID
	filename := filepath.Base(filePath)
	remoteName := a.RemoteName
	if remoteName == "" {
		remoteName = filename
	}
	a.RemoteName = remoteName

	tmp := filePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		// Docker bind-mount 权限问题的典型现场：容器内 app 用户（uid 10001）
		// 对宿主机挂载目录无写权限。给出可操作指引而不是裸 syscall 错误。
		msg := fmt.Sprintf("写入 %s 失败: %v", tmp, err)
		if errors.Is(err, fs.ErrPermission) {
			msg += "\n（Docker 部署：容器内用户对宿主机挂载目录无写权限。解法任选：" +
				"1) 以本机 uid 运行容器：PUID=$(id -u) PGID=$(id -g) docker compose up -d；" +
				"2) sudo chown -R 10001:10001 ./auths ./data ./config.json；" +
				"3) compose 设 user: \"0:0\" 以 root 运行）"
		}
		return errors.New(msg)
	}
	if err := os.Rename(tmp, filePath); err != nil {
		return err
	}
	if store := currentRemoteStore(); store != nil {
		if create {
			err = store.CreateRaw(uid, remoteName, raw)
		} else {
			err = store.PutRaw(uid, remoteName, raw)
		}
		a.pending = err != nil
		if err != nil {
			return fmt.Errorf("remote credential sync failed: %w", err)
		}
	}
	return nil
}

// RetryPending only retries a failed save; it never imports an arbitrary cache.
func (a *Auth) RetryPending() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.pending || a.deleted {
		return nil
	}
	store := currentRemoteStore()
	if store == nil {
		return nil
	}
	raw, err := marshalAuth(a)
	if err != nil {
		return err
	}
	if err := store.PutRaw(a.UID, a.RemoteName, raw); err != nil {
		return err
	}
	a.pending = false
	return nil
}

// DeleteStored 先在远端写 deleted tombstone，再删除本地热缓存。
// 远端删除失败时保留本地文件并返回错误，避免半删除后重启复活。
func DeleteStored(a *Auth) error {
	if a == nil {
		return fmt.Errorf("delete refused: nil auth")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	uid := a.UID
	filePath := a.FilePath
	remoteName := a.RemoteName
	if remoteName == "" {
		remoteName = filepath.Base(filePath)
	}

	store := currentRemoteStore()
	if store != nil {
		if err := store.Delete(uid, remoteName); err != nil {
			return fmt.Errorf("delete remote credential uid=%s: %w", uid, err)
		}
		a.deleted = true
		a.pending = false
	}
	if filePath == "" {
		return nil
	}
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		if store != nil {
			log.Printf("auth: remote deletion committed; local cache cleanup failed: %v", err)
			return nil
		}
		return fmt.Errorf("delete local credential uid=%s: %w", uid, err)
	}
	a.deleted = true
	return nil
}

func marshalAuth(a *Auth) ([]byte, error) {
	if strings.TrimSpace(a.AccessToken) == "" {
		return nil, fmt.Errorf("save refused: empty accessToken (uid=%s)", a.UID)
	}
	doc := map[string]any{}
	if len(a.document) > 0 {
		if err := json.Unmarshal(a.document, &doc); err != nil {
			return nil, err
		}
	}
	for section, values := range map[string]map[string]any{
		"auth": {
			"accessToken":  a.AccessToken,
			"refreshToken": a.RefreshToken,
			"expiresAt":    a.ExpiresAt,
			"domain":       a.Domain,
		},
		"account": {
			"uid":          a.UID,
			"enterpriseId": a.EnterpriseID,
			"nickname":     a.Nickname,
		},
	} {
		target, ok := doc[section].(map[string]any)
		if !ok {
			target = map[string]any{}
		}
		for key, value := range values {
			target[key] = value
		}
		doc[section] = target
	}
	return json.MarshalIndent(doc, "", "  ")
}

// LoadDir 扫描并解析 dir 下 workbuddy*.json；解析失败的文件静默跳过（启动日志由调用方统计）。
func LoadDir(dir string) ([]*Auth, error) {
	files, err := filepath.Glob(filepath.Join(dir, "workbuddy*.json"))
	if err != nil {
		return nil, err
	}
	var out []*Auth
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		a, err := Parse(raw)
		if err != nil {
			continue
		}
		a.FilePath = f
		a.RemoteName = filepath.Base(f)
		out = append(out, a)
	}
	return out, nil
}
