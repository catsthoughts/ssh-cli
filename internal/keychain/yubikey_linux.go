//go:build linux

package keychain

import (
	"crypto"
	"errors"
	"fmt"
	"os"

	"github.com/go-piv/piv-go/v2/piv"
	"ssh-cli/internal/config"
)

func defaultPCSCLibrary() string {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libpcsclite.so",
		"/usr/lib64/libpcsclite.so",
		"/usr/local/lib/libpcsclite.so",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func ensureYubiKey(cfg config.KeyConfig) (*Key, bool, error) {
	libPath := cfg.YubiKey.PKCS11Path
	if libPath == "" {
		libPath = defaultPCSCLibrary()
		if libPath == "" {
			return nil, false, errors.New("PC/SC library not found; install libpcsclite-dev or set yubikey.pkcs11_path")
		}
	}
	yk, err := piv.Open(libPath)
	if err != nil {
		return nil, false, fmt.Errorf("open YubiKey: %w", err)
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
	libPath := cfg.YubiKey.PKCS11Path
	if libPath == "" {
		libPath = defaultPCSCLibrary()
		if libPath == "" {
			return nil, errors.New("PC/SC library not found; install libpcsclite-dev or set yubikey.pkcs11_path")
		}
	}
	yk, err := piv.Open(libPath)
	if err != nil {
		return nil, fmt.Errorf("open YubiKey: %w", err)
	}
	slot, err := parseSlot(cfg.YubiKey.Slot)
	if err != nil {
		yk.Close()
		return nil, err
	}
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
