package certstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

type Store struct {
	baseDir string
}

type metadata struct {
	KeyTag    string    `json:"key_tag"`
	ExpiresAt time.Time `json:"expires_at"`
}

func New(baseDir string) *Store {
	return &Store{baseDir: baseDir}
}

func (s *Store) profileDir(profile string) string {
	return filepath.Join(s.baseDir, profile)
}

func (s *Store) certFilePath(profile string) string {
	return filepath.Join(s.profileDir(profile), "id_ecdsa-cert.pub")
}

func (s *Store) CertPath(profile string) string {
	return s.certFilePath(profile)
}

func (s *Store) metadataPath(profile string) string {
	return filepath.Join(s.profileDir(profile), "metadata.json")
}

func (s *Store) Save(profile string, cert *ssh.Certificate, keyTag string) error {
	dir := s.profileDir(profile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	certPath := s.certFilePath(profile)
	certBytes := ssh.MarshalAuthorizedKey(cert)
	if err := os.WriteFile(certPath, certBytes, 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	meta := metadata{
		KeyTag:    keyTag,
		ExpiresAt: time.Unix(int64(cert.ValidBefore), 0),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(s.metadataPath(profile), metaBytes, 0o600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}

func (s *Store) Load(profile string) (*ssh.Certificate, error) {
	certPath := s.certFilePath(profile)
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("expected SSH certificate, got %T", pub)
	}

	return cert, nil
}

func (s *Store) Expiry(profile string) (time.Time, error) {
	metaPath := s.metadataPath(profile)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("read metadata: %w", err)
	}

	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return time.Time{}, fmt.Errorf("parse metadata: %w", err)
	}

	return meta.ExpiresAt, nil
}

func (s *Store) NeedsRefresh(profile string, margin time.Duration) bool {
	expiry, err := s.Expiry(profile)
	if err != nil {
		return true
	}
	return time.Until(expiry) < margin
}
