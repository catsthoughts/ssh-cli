//go:build !darwin

package keychain

import (
	"errors"
	"ssh-cli/internal/config"
)

type Key struct{}

func EnsureKey(_ config.KeyConfig) (*Key, bool, error) {
	return nil, false, errors.New("non-exportable macOS keys are supported only on darwin")
}

func (k *Key) IsSecureEnclave() bool {
	return false
}

func (k *Key) Close() {}
