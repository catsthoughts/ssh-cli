package keychain

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"ssh-cli/internal/config"
)

// EnsureKey returns a Key based on the configured key_source.
// The second return value indicates whether a new key was created.
func EnsureKey(cfg config.KeyConfig) (*Key, bool, error) {
	switch cfg.KeySource {
	case "secure_enclave", "":
		pub, backend, created, err := ensureSecureEnclave(cfg)
		if err != nil {
			return nil, false, err
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			backend.Close()
			return nil, false, err
		}
		k := &Key{
			cfg:     cfg,
			pub:     pub,
			sshPub:  sshPub,
			backend: backend,
		}
		return k, created, nil
	case "yubikey_piv":
		return ensureYubiKey(cfg)
	case "file":
		return nil, false, errors.New("file-based keys are not implemented; use secure_enclave or yubikey_piv")
	default:
		return nil, false, fmt.Errorf("unsupported key_source: %s", cfg.KeySource)
	}
}

// ForceCreateKey deletes any existing key and creates a fresh one.
// For secure_enclave: removes the key from Keychain by tag, then creates a new one.
// For yubikey_piv: resets the PIV slot, then generates a new key.
func ForceCreateKey(cfg config.KeyConfig) (*Key, error) {
	switch cfg.KeySource {
	case "yubikey_piv":
		return forceYubiKey(cfg)
	case "secure_enclave", "":
		if err := DeleteKey(cfg.Tag); err != nil {
			return nil, fmt.Errorf("delete existing key: %w", err)
		}
		key, _, err := EnsureKey(cfg)
		return key, err
	default:
		return nil, fmt.Errorf("force create not supported for key source %s", cfg.KeySource)
	}
}
