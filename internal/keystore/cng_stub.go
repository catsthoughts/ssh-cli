//go:build !windows

package keystore

import (
	"fmt"

	"ssh-cli/internal/config"
)

func ensureKeyCNG(_ config.KeyConfig) (Key, bool, error) {
	return nil, false, fmt.Errorf("CNG backend is only available on Windows")
}
