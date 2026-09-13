package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeRemote struct {
	err     error
	name    string
	payload []byte
	creates int
	puts    int
}

func (s *fakeRemote) PutRaw(uid, name string, raw []byte) error {
	s.puts++
	s.name = name
	s.payload = append([]byte(nil), raw...)
	return s.err
}
func (s *fakeRemote) CreateRaw(uid, name string, raw []byte) error {
	s.creates++
	return s.PutRaw(uid, name, raw)
}
func (s *fakeRemote) PutAuth(*Auth) error { return s.err }
func (s *fakeRemote) RestoreDir(string) (*RemoteSnapshot, error) {
	return nil, s.err
}
func (s *fakeRemote) Delete(uid, name string) error {
	s.name = name
	return s.err
}
func (s *fakeRemote) Close() error { return nil }

func useFakeRemote(t *testing.T, store *fakeRemote) {
	t.Helper()
	SetRemoteStore(store)
	t.Cleanup(func() { SetRemoteStore(nil) })
}

func TestRemoteFailureIsReportedAndRetried(t *testing.T) {
	store := &fakeRemote{err: errors.New("offline")}
	useFakeRemote(t, store)
	a := &Auth{UID: "u1", AccessToken: "new", FilePath: filepath.Join(t.TempDir(), "workbuddy-custom.json")}
	if err := a.SaveAtomic(); err == nil {
		t.Fatal("remote failure must be reported")
	}
	if _, err := os.Stat(a.FilePath); err != nil {
		t.Fatal("new token must remain in the local cache")
	}
	store.err = nil
	if err := a.RetryPending(); err != nil {
		t.Fatal(err)
	}
	if store.puts != 2 || a.pending || store.name != "workbuddy-custom.json" {
		t.Fatal("failed save was not durably retried")
	}
	if err := a.RetryPending(); err != nil || store.puts != 2 {
		t.Fatal("successful saves should not be replayed")
	}
}

func TestDeleteUsesOriginalNameAndPreventsFurtherSaves(t *testing.T) {
	store := &fakeRemote{}
	useFakeRemote(t, store)
	a := &Auth{UID: "u1", AccessToken: "token", FilePath: filepath.Join(t.TempDir(), "workbuddy-custom.json")}
	if err := a.SaveAtomic(); err != nil {
		t.Fatal(err)
	}
	if err := DeleteStored(a); err != nil {
		t.Fatal(err)
	}
	if store.name != "workbuddy-custom.json" {
		t.Fatal("tombstone used a different filename")
	}
	if err := a.SaveAtomic(); err == nil {
		t.Fatal("deleted Auth must reject a late refresh")
	}
}

func TestDeleteCommitSurvivesCacheCleanupFailure(t *testing.T) {
	store := &fakeRemote{}
	useFakeRemote(t, store)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "child"), []byte("cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Auth{UID: "u1", FilePath: dir, RemoteName: "old.info", AccessToken: "token"}
	if err := DeleteStored(a); err != nil || !a.deleted {
		t.Fatalf("committed remote deletion should succeed: %v", err)
	}
	if err := a.SaveAtomic(); err == nil {
		t.Fatal("cache cleanup failure must not allow resurrection")
	}
}

func TestDeleteFailureRetainsCredential(t *testing.T) {
	store := &fakeRemote{err: errors.New("offline")}
	useFakeRemote(t, store)
	a := &Auth{UID: "u1", AccessToken: "token", FilePath: filepath.Join(t.TempDir(), "workbuddy-u1.json")}
	if err := os.WriteFile(a.FilePath, []byte("cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DeleteStored(a); err == nil || a.deleted {
		t.Fatal("failed remote delete must retain the active credential")
	}
	if _, err := os.Stat(a.FilePath); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitOAuthUsesCreate(t *testing.T) {
	store := &fakeRemote{}
	useFakeRemote(t, store)
	a := &Auth{UID: "u1", AccessToken: "token", FilePath: filepath.Join(t.TempDir(), "workbuddy-u1.json")}
	if err := a.SaveNew(); err != nil || store.creates != 1 {
		t.Fatal("explicit login should be allowed to restore a deleted credential")
	}
}

func TestLegacyFieldsAndRemoteNameSurviveRefresh(t *testing.T) {
	store := &fakeRemote{}
	useFakeRemote(t, store)
	a, err := Parse([]byte(`{"auth":{"accessToken":"old","refreshToken":"refresh","scope":"openid"},"account":{"uid":"u1","type":"personal"},"allAccounts":[{"uid":"u1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	a.AccessToken = "new"
	a.RemoteName = "original.info"
	a.FilePath = filepath.Join(t.TempDir(), "workbuddy-u1.json")
	if err := a.SaveAtomic(); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(store.payload, &doc); err != nil {
		t.Fatal(err)
	}
	if store.name != "original.info" || doc["allAccounts"] == nil ||
		doc["auth"].(map[string]any)["scope"] != "openid" ||
		doc["account"].(map[string]any)["type"] != "personal" ||
		doc["auth"].(map[string]any)["accessToken"] != "new" {
		t.Fatal("legacy metadata or token update was lost")
	}
}

func TestFernetRoundtripTamperingAndWrongKey(t *testing.T) {
	key := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	cipher, err := newFernetCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("secret"), bytes.Repeat([]byte("a"), 64)} {
		token, err := cipher.Encrypt(data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := cipher.Decrypt(token)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("Fernet roundtrip failed")
		}
		other, _ := newFernetCipher(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
		if _, err := other.Decrypt(token); err == nil {
			t.Fatal("wrong key was accepted")
		}
		token[len(token)/2] ^= 1
		if _, err := cipher.Decrypt(token); err == nil {
			t.Fatal("tampered token was accepted")
		}
	}
}

func TestLegacyMillisecondExpiryRoundtrip(t *testing.T) {
	a, err := Parse([]byte(`{"auth":{"accessToken":"token","expiresAt":1700000000000},"account":{"uid":"u1"}}`))
	if err != nil || a.ExpiresAt != 1700000000 || !a.NeedsRefresh(0) {
		t.Fatal("legacy milliseconds were treated as seconds")
	}
	a.ExpiresAt = 1900000000
	raw, err := marshalAuth(a)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Auth struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Auth.ExpiresAt != 1900000000000 {
		t.Fatal("legacy timestamp units were not preserved for rollback compatibility")
	}
}
