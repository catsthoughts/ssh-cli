//go:build !linux && !darwin && !windows

package keychain

import (
	"errors"

	"ssh-cli/internal/config"
)

func ensureYubiKey(_ config.KeyConfig) (*Key, bool, error) {
	return nil, false, errors.New("yubikey_piv is not supported on this platform")
}

func forceYubiKey(_ config.KeyConfig) (*Key, error) {
	return nil, errors.New("yubikey_piv is not supported on this platform")
}
