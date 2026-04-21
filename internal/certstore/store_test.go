package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}
	return pub
}

func createTestCert(t *testing.T, pubKey ssh.PublicKey, keyId string, principals []string, validFor time.Duration) *ssh.Certificate {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	validAfter := uint64(time.Now().Add(-1 * time.Minute).Unix())
	validBefore := uint64(time.Now().Add(validFor).Unix())

	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          uint64(time.Now().UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           keyId,
		ValidPrincipals: principals,
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	return cert
}

func TestStore_New(t *testing.T) {
	s := New("/tmp/test-certs")
	if s.baseDir != "/tmp/test-certs" {
		t.Errorf("expected baseDir /tmp/test-certs, got %s", s.baseDir)
	}
}

func TestStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	pubKey := testPublicKey(t)
	cert := createTestCert(t, pubKey, "test-user", []string{"testuser"}, 8*time.Hour)

	err := s.Save("test-profile", cert, "test-key-tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	certPath := filepath.Join(tmpDir, "test-profile", "id_ecdsa-cert.pub")
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not created at %s: %v", certPath, err)
	}

	metaPath := filepath.Join(tmpDir, "test-profile", "metadata.json")
	if _, err := os.Stat(metaPath); err != nil {
		t.Errorf("metadata file not created at %s: %v", metaPath, err)
	}

	loadedCert, err := s.Load("test-profile")
	if err != nil {
		t.Fatalf("unexpected error loading cert: %v", err)
	}

	if loadedCert.KeyId != "test-user" {
		t.Errorf("expected key ID test-user, got %s", loadedCert.KeyId)
	}

	if len(loadedCert.ValidPrincipals) != 1 || loadedCert.ValidPrincipals[0] != "testuser" {
		t.Errorf("expected principal testuser, got %v", loadedCert.ValidPrincipals)
	}
}

func TestStore_Expiry(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	pubKey := testPublicKey(t)
	expectedExpiry := time.Now().Add(8 * time.Hour)
	cert := createTestCert(t, pubKey, "user", []string{"user"}, 8*time.Hour)

	err := s.Save("test-profile", cert, "key-tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expiry, err := s.Expiry("test-profile")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allow 1 second tolerance for timing differences
	diff := expectedExpiry.Unix() - expiry.Unix()
	if diff < -1 || diff > 1 {
		t.Errorf("expected expiry close to %v, got %v", expectedExpiry, expiry)
	}
}

func TestStore_NeedsRefresh_TrueWhenNoCert(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	if !s.NeedsRefresh("nonexistent", time.Hour) {
		t.Error("expected NeedsRefresh to return true when cert doesn't exist")
	}
}

func TestStore_NeedsRefresh_TrueWhenExpired(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	pubKey := testPublicKey(t)
	cert := createTestCert(t, pubKey, "user", []string{"user"}, -1*time.Hour)

	s.Save("expired-profile", cert, "key-tag")

	if !s.NeedsRefresh("expired-profile", time.Hour) {
		t.Error("expected NeedsRefresh to return true for expired cert")
	}
}

func TestStore_NeedsRefresh_TrueWhenExpiringSoon(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	pubKey := testPublicKey(t)
	cert := createTestCert(t, pubKey, "user", []string{"user"}, 30*time.Minute)

	s.Save("expiring-soon-profile", cert, "key-tag")

	if !s.NeedsRefresh("expiring-soon-profile", time.Hour) {
		t.Error("expected NeedsRefresh to return true when expiring before margin")
	}
}

func TestStore_NeedsRefresh_FalseWhenValid(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	pubKey := testPublicKey(t)
	cert := createTestCert(t, pubKey, "user", []string{"user"}, 8*time.Hour)

	s.Save("valid-profile", cert, "key-tag")

	if s.NeedsRefresh("valid-profile", time.Hour) {
		t.Error("expected NeedsRefresh to return false for valid cert")
	}
}

func TestStore_CertPath(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	path := s.CertPath("my-profile")
	expected := filepath.Join(tmpDir, "my-profile", "id_ecdsa-cert.pub")

	if path != expected {
		t.Errorf("expected cert path %s, got %s", expected, path)
	}
}

func TestStore_Save_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	pubKey := testPublicKey(t)
	cert := createTestCert(t, pubKey, "user", []string{"user"}, 8*time.Hour)

	err := s.Save("nested/profile", cert, "key-tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	profileDir := filepath.Join(tmpDir, "nested", "profile")
	if _, err := os.Stat(profileDir); err != nil {
		t.Errorf("profile directory not created: %v", err)
	}
}

func TestStore_Load_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	_, err := s.Load("nonexistent")
	if err == nil {
		t.Error("expected error when loading nonexistent cert")
	}
}

func TestStore_Expiry_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	_, err := s.Expiry("nonexistent")
	if err == nil {
		t.Error("expected error when getting expiry for nonexistent cert")
	}
}
