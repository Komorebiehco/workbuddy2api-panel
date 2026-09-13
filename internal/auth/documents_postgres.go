package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

func (s *PostgresStore) SaveDocument(name string, raw []byte) error {
	if !json.Valid(raw) {
		return fmt.Errorf("invalid JSON document")
	}
	encrypted, err := s.cipher.Encrypt(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO workbuddy_documents (name, ciphertext) VALUES ($1, $2)
ON CONFLICT (name) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = NOW()`,
		name, encrypted)
	if err != nil {
		return fmt.Errorf("save persistent document %s: %w", name, err)
	}
	return nil
}

func (s *PostgresStore) LoadDocument(name string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var encrypted []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT ciphertext FROM workbuddy_documents WHERE name = $1`, name).Scan(&encrypted)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load persistent document %s: %w", name, err)
	}
	raw, err := s.cipher.Decrypt(encrypted)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt persistent document %s: %w", name, err)
	}
	return raw, true, nil
}

func (s *PostgresStore) SaveStateSync(raw []byte) error {
	return s.SaveDocument("pool-state", raw)
}

func (s *PostgresStore) LoadStateSync() ([]byte, bool, error) {
	return s.LoadDocument("pool-state")
}

func (s *PostgresStore) SaveState(raw []byte) {
	if err := s.SaveStateSync(raw); err != nil {
		log.Printf("pool: PostgreSQL snapshot save failed: %v", err)
	}
}

func (s *PostgresStore) LoadState() ([]byte, bool) {
	raw, ok, err := s.LoadStateSync()
	if err != nil {
		log.Printf("pool: PostgreSQL snapshot load failed: %v", err)
	}
	return raw, ok
}
