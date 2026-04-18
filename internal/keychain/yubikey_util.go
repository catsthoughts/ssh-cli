//go:build linux || darwin || windows

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
	"ssh-cli/internal/config"
)

// touchCacheDuration mirrors YubiKey's TouchPolicyCached window.
const touchCacheDuration = 15 * time.Second

// yubikeyBackend is the keychain backend for YubiKey PIV.
type yubikeyBackend struct {
	yk          *piv.YubiKey
	slot        piv.Slot
	key         crypto.Signer
	pin         string
	pub         crypto.PublicKey
	TouchPrompt func() // called before sign when touch is needed; nil = no prompt

	touchMu       sync.Mutex
	lastTouchTime time.Time
}

func (b *yubikeyBackend) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if b.TouchPrompt != nil {
		b.touchMu.Lock()
		needsTouch := time.Since(b.lastTouchTime) >= touchCacheDuration
		b.touchMu.Unlock()
		if needsTouch {
			b.TouchPrompt()
		}
	}
	auth := piv.KeyAuth{}
	if b.pin != "" {
		auth.PIN = b.pin
	}
	priv, err := b.yk.PrivateKey(b.slot, b.pub, auth)
	if err != nil {
		return nil, fmt.Errorf("yubikey auth: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}
	sig, err := signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	b.touchMu.Lock()
	b.lastTouchTime = time.Now()
	b.touchMu.Unlock()
	return sig, nil
}

func (b *yubikeyBackend) Close() {
	if b.yk != nil {
		b.yk.Close()
	}
}

// defaultTouchPrompt prints a touch reminder to stderr.
func defaultTouchPrompt() {
	fmt.Fprint(os.Stderr, "Touch your YubiKey... ")
}

// parseSlot converts a string slot identifier to a piv.Slot.
// Supports 4 main PIV slots (9a, 9c, 9d, 9e) and 20 retired key management slots (82-95).
func parseSlot(s string) (piv.Slot, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "9a", "9A", "":
		return piv.SlotAuthentication, nil
	case "9c", "9C":
		return piv.SlotSignature, nil
	case "9d", "9D":
		return piv.SlotKeyManagement, nil
	case "9e", "9E":
		return piv.SlotCardAuthentication, nil
	}

	// Check retired key management slots (82-95)
	slotNum := parseHexSlot(s)
	if slot, ok := piv.RetiredKeyManagementSlot(slotNum); ok {
		return slot, nil
	}

	return piv.Slot{}, fmt.Errorf("unsupported yubikey slot: %s (supported: 9a, 9c, 9d, 9e, 82-95)", s)
}

// parseHexSlot parses a hex string (e.g. "82", "9a") to uint32.
func parseHexSlot(s string) uint32 {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	v, _ := strconv.ParseUint(s, 16, 32)
	return uint32(v)
}

// buildKey constructs a keychain.Key from piv components.
func buildKey(cfg config.KeyConfig, yk *piv.YubiKey, slot piv.Slot, pub crypto.PublicKey, key crypto.Signer, created bool) (*Key, bool, error) {
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, false, errors.New("key is not ECDSA")
	}
	sshPub, err := ssh.NewPublicKey(ecdsaPub)
	if err != nil {
		return nil, false, err
	}
	backend := &yubikeyBackend{
		yk:          yk,
		slot:        slot,
		key:         key,
		pin:         cfg.YubiKey.PIN,
		pub:         pub,
		TouchPrompt: defaultTouchPrompt,
	}
	k := &Key{
		cfg:     cfg,
		pub:     ecdsaPub,
		sshPub:  sshPub,
		backend: backend,
	}
	return k, created, nil
}
