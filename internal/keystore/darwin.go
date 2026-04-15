//go:build darwin

package keystore

import (
	"ssh-cli/internal/config"
	"ssh-cli/internal/keychain"
)

func ensureKeyDarwin(cfg config.KeyConfig) (Key, bool, error) {
	return keychain.EnsureKey(cfg)
}
