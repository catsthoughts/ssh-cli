//go:build !darwin

package keystore

import (
	"fmt"

	"ssh-cli/internal/config"
)

func ensureKeyDarwin(_ config.KeyConfig) (Key, bool, error) {
	return nil, false, fmt.Errorf("secure-enclave/keychain backend is only available on macOS")
}
