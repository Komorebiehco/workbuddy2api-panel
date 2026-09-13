package pool

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

type durableTestStore struct {
	memStore
	loadErr error
	saveErr error
}

func (s *durableTestStore) SaveStateSync(raw []byte) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.SaveState(raw)
	return nil
}
func (s *durableTestStore) LoadStateSync() ([]byte, bool, error) {
	raw, ok := s.LoadState()
	return raw, ok, s.loadErr
}

func TestRestoreRemoteWithoutLocalFile(t *testing.T) {
	s := &memStore{loadOK: true}
	s.loadData, _ = json.Marshal(snapshot{
		stateFile: stateFile{Accounts: map[string]stateAccount{"u1": {Credits: 42, Disabled: true, SuccessCount: 7}}},
		SavedAt:   time.Now(),
	})
	p := New("")
	p.stateFp = filepath.Join(t.TempDir(), "missing.json")
	p.SetStore(s)
	if err := p.RestoreFromSnapshot(); err != nil {
		t.Fatal(err)
	}
	st, ok := p.Status("u1")
	if !ok || st.Credits != 42 || !st.Disabled || st.SuccessCount != 7 {
		t.Fatalf("fresh container did not restore remote state: %+v", st)
	}
}

func TestRemoteReadFailureDoesNotResetState(t *testing.T) {
	p := New("")
	p.stateFp = filepath.Join(t.TempDir(), "missing.json")
	p.SetStore(&durableTestStore{loadErr: errors.New("offline")})
	if err := p.RestoreFromSnapshot(); err == nil {
		t.Fatal("database read failure must block startup instead of resetting state")
	}
}

func TestRemoteWriteFailureRemainsDirtyForRetry(t *testing.T) {
	p := New("")
	p.stateFp = filepath.Join(t.TempDir(), "state.json")
	s := &durableTestStore{saveErr: errors.New("offline")}
	p.SetStore(s)
	p.Add(&auth.Auth{UID: "u1"})
	p.SetCredits("u1", 42)
	p.Flush()
	if !p.dirty.Load() {
		t.Fatal("failed remote write was not scheduled for retry")
	}
	s.saveErr = nil
	p.Flush()
	if p.dirty.Load() || len(s.saved) == 0 {
		t.Fatal("retry did not complete")
	}
}
