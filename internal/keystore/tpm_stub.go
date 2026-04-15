//go:build !linux

package keystore

import (
	"fmt"

	"ssh-cli/internal/config"
)

func ensureKeyTPM(_ config.KeyConfig) (Key, bool, error) {
	return nil, false, fmt.Errorf("TPM backend is only available on Linux")
}
