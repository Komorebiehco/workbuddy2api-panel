package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
)

type fakeDocuments struct {
	raw []byte
	err error
}

func (s *fakeDocuments) LoadDocument(string) ([]byte, bool, error) {
	return s.raw, len(s.raw) > 0, s.err
}
func (s *fakeDocuments) SaveDocument(name string, raw []byte) error {
	if s.err != nil {
		return s.err
	}
	s.raw = append([]byte(nil), raw...)
	return nil
}

func TestRestoreConfigIntoFreshContainer(t *testing.T) {
	fp := filepath.Join(t.TempDir(), "data", "config.json")
	store := &fakeDocuments{raw: []byte(`{"api_key":"test-key","pool":{"max_in_flight":2}}`)}
	if err := restoreConfig(fp, store); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(fp)
	if err != nil || cfg.APIKey != "test-key" || cfg.Pool.MaxInFlight != 2 {
		t.Fatal("persistent config was not restored")
	}
}

func TestInvalidRemoteConfigDoesNotOverwriteCache(t *testing.T) {
	fp := filepath.Join(t.TempDir(), "config.json")
	before := []byte(`{"api_key":"test-key"}`)
	if err := os.WriteFile(fp, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreConfig(fp, &fakeDocuments{raw: []byte(`{"server":{"max_body_mb":0}}`)}); err == nil {
		t.Fatal("invalid persisted config should fail startup")
	}
	after, _ := os.ReadFile(fp)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid remote config overwrote the local cache")
	}
}

func TestConfigRemoteFailureDoesNotApplyLocally(t *testing.T) {
	fp := filepath.Join(t.TempDir(), "config.json")
	before := []byte(`{"api_key":"test-key"}`)
	if err := os.WriteFile(fp, before, 0o600); err != nil {
		t.Fatal(err)
	}
	live := livecfg.New(livecfg.Snapshot{APIKey: "test-key"})
	_, err := saveConfig([]byte(`{"api_key":"new-test-key"}`), fp, live, nil, nil, nil,
		&fakeDocuments{err: errors.New("offline")})
	if err == nil {
		t.Fatal("database save failure must not report success")
	}
	after, _ := os.ReadFile(fp)
	if !bytes.Equal(before, after) {
		t.Fatal("uncommitted config was applied to the local cache")
	}
}
