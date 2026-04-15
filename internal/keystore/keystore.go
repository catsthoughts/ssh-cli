package keystore

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"

	"ssh-cli/internal/config"
)

// Key is the common interface for all key backends.
// Every implementation must also satisfy crypto.Signer so that
// x509 and ssh certificate code works without platform-specific changes.
type Key interface {
	crypto.Signer

	// SSHSigner returns an ssh.Signer backed by this key.
	SSHSigner() ssh.Signer

	// SSHPublicKey returns the parsed SSH public key.
	SSHPublicKey() ssh.PublicKey

	// AuthorizedKey returns the key in authorized_keys format
	// with the optional comment appended.
	AuthorizedKey() []byte

	// IsHardwareBacked reports whether the private key is stored
	// in a hardware security module (Secure Enclave, TPM, CNG).
	IsHardwareBacked() bool

	// Close releases any resources held by the key.
	Close()
}

// EnsureKey creates or loads a key using the backend specified in cfg.
// It returns the key, whether a new key was created, and any error.
func EnsureKey(cfg config.KeyConfig) (Key, bool, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	if backend == "" || backend == "auto" {
		backend = autoDetectBackend()
	}

	switch backend {
	case "secure-enclave", "keychain":
		return ensureKeyDarwin(cfg)
	case "tpm":
		return ensureKeyTPM(cfg)
	case "cng":
		return ensureKeyCNG(cfg)
	case "file":
		return ensureKeyFile(cfg)
	default:
		return nil, false, fmt.Errorf("unsupported key backend: %q", backend)
	}
}

func autoDetectBackend() string {
	switch runtime.GOOS {
	case "darwin":
		return "secure-enclave"
	case "linux":
		if _, err := os.Stat("/dev/tpmrm0"); err == nil {
			return "tpm"
		}
		return "file"
	case "windows":
		return "cng"
	default:
		return "file"
	}
}

// WriteAuthorizedKeyFile writes the authorized key data to path.
func WriteAuthorizedKeyFile(path string, data []byte) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
