//go:build darwin

package keychain

import (
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"ssh-cli/internal/config"
)

func ensureYubiKey(cfg config.KeyConfig) (*Key, bool, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, false, fmt.Errorf("list readers: %w", err)
	}
	var reader string
	for _, r := range cards {
		if strings.Contains(strings.ToLower(r), "yubikey") {
			reader = r
			break
		}
	}
	if reader == "" {
		if len(cards) > 0 {
			reader = cards[0]
		} else {
			return nil, false, errors.New("no smart card readers found; insert YubiKey and ensure CCID interface is enabled")
		}
	}

	yk, err := piv.Open(reader)
	if err != nil {
		return nil, false, fmt.Errorf("open YubiKey (%s): %w", reader, err)
	}

	slot, err := parseSlot(cfg.YubiKey.Slot)
	if err != nil {
		yk.Close()
		return nil, false, err
	}

	_, err = yk.KeyInfo(slot)
	if err != nil {
		pub, signer, created, err := generateKey(yk, slot, cfg)
		if err != nil {
			yk.Close()
			return nil, false, err
		}
		k, created, err := buildKey(cfg, yk, slot, pub, signer, created)
		if err != nil {
			yk.Close()
			return nil, false, err
		}
		return k, created, nil
	}

	info, err := yk.KeyInfo(slot)
	if err != nil {
		yk.Close()
		return nil, false, fmt.Errorf("get key info: %w", err)
	}
	pub := info.PublicKey
	var auth piv.KeyAuth
	if cfg.YubiKey.PIN != "" {
		auth.PIN = cfg.YubiKey.PIN
	}
	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		yk.Close()
		return nil, false, fmt.Errorf("get private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		yk.Close()
		return nil, false, errors.New("private key does not implement crypto.Signer")
	}
	k, created, err := buildKey(cfg, yk, slot, pub, signer, false)
	if err != nil {
		yk.Close()
		return nil, false, err
	}
	return k, created, nil
}

func generateKey(yk *piv.YubiKey, slot piv.Slot, cfg config.KeyConfig) (interface{}, crypto.Signer, bool, error) {
	opts := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyCached,
	}
	pub, err := yk.GenerateKey(piv.DefaultManagementKey, slot, opts)
	if err != nil {
		return nil, nil, false, fmt.Errorf("generate key: %w", err)
	}
	var auth piv.KeyAuth
	if cfg.YubiKey.PIN != "" {
		auth.PIN = cfg.YubiKey.PIN
	}
	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		return nil, nil, false, fmt.Errorf("get private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, false, errors.New("private key does not implement crypto.Signer")
	}
	return pub, signer, true, nil
}

func forceYubiKey(cfg config.KeyConfig) (*Key, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("list readers: %w", err)
	}
	var reader string
	for _, r := range cards {
		if strings.Contains(strings.ToLower(r), "yubikey") {
			reader = r
			break
		}
	}
	if reader == "" {
		if len(cards) > 0 {
			reader = cards[0]
		} else {
			return nil, errors.New("no smart card readers found; insert YubiKey and ensure CCID interface is enabled")
		}
	}
	yk, err := piv.Open(reader)
	if err != nil {
		return nil, fmt.Errorf("open YubiKey (%s): %w", reader, err)
	}
	slot, err := parseSlot(cfg.YubiKey.Slot)
	if err != nil {
		yk.Close()
		return nil, err
	}
	// Regenerate key in the specific slot only — no full device reset.
	pub, signer, _, err := generateKey(yk, slot, cfg)
	if err != nil {
		yk.Close()
		return nil, err
	}
	k, _, err := buildKey(cfg, yk, slot, pub, signer, true)
	if err != nil {
		yk.Close()
		return nil, err
	}
	return k, nil
}
