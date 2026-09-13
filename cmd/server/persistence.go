package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

type documentStore interface {
	LoadDocument(string) ([]byte, bool, error)
	SaveDocument(string, []byte) error
}

func openPersistence() (*auth.PostgresStore, error) {
	dsn := firstNonEmpty(os.Getenv("WB2A_CREDENTIALS_DATABASE_URL"), os.Getenv("CODEBUDDY_CREDENTIALS_DATABASE_URL"))
	if dsn == "" {
		return nil, nil
	}
	key := firstNonEmpty(os.Getenv("WB2A_CREDENTIALS_ENCRYPTION_KEY"), os.Getenv("CODEBUDDY_CREDENTIALS_ENCRYPTION_KEY"))
	return auth.NewPostgresStore(dsn, key)
}

func restoreConfig(path string, store documentStore) error {
	raw, exists, err := store.LoadDocument("config")
	if err != nil || !exists {
		return err
	}
	if _, err := ParseConfig(raw); err != nil {
		return fmt.Errorf("invalid persisted config: %w", err)
	}
	return writeConfigCache(path, raw)
}

func writeConfigCache(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func retryCredentialSaves(ctx context.Context, p *pool.Pool) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, status := range p.List() {
				if a := p.AuthByUID(status.UID); a != nil {
					if err := a.RetryPending(); err != nil {
						log.Printf("auth: persistent save retry failed: %v", err)
					}
				}
			}
		}
	}
}
