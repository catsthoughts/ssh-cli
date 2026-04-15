package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"

	"ssh-cli/internal/config"
)

// fileKey wraps an ECDSA P-256 key stored as an encrypted PEM file.
// This is the cross-platform software fallback when no hardware
// security module is available.
type fileKey struct {
	mu      sync.Mutex
	priv    *ecdsa.PrivateKey
	pub     *ecdsa.PublicKey
	sshPub  ssh.PublicKey
	comment string
}

func ensureKeyFile(cfg config.KeyConfig) (Key, bool, error) {
	if cfg.Tag == "" {
		return nil, false, errors.New("key.tag is required")
	}
	keyPath := fileKeyPath(cfg.Tag)

	priv, err := loadFileKey(keyPath)
	if err == nil {
		return finishFileKey(cfg, priv, false)
	}

	// Key not found or unreadable — generate a new one.
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate ECDSA key: %w", err)
	}
	if err := saveFileKey(keyPath, priv); err != nil {
		return nil, false, fmt.Errorf("save file key: %w", err)
	}
	return finishFileKey(cfg, priv, true)
}

func finishFileKey(cfg config.KeyConfig, priv *ecdsa.PrivateKey, created bool) (Key, bool, error) {
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, false, fmt.Errorf("convert file key to SSH: %w", err)
	}
	k := &fileKey{
		priv:    priv,
		pub:     &priv.PublicKey,
		sshPub:  sshPub,
		comment: cfg.Comment,
	}
	return k, created, nil
}

func fileKeyPath(tag string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	// Use a deterministic filename derived from the tag.
	h := sha256.Sum256([]byte(tag))
	name := fmt.Sprintf("ssh-cli-%x.pem", h[:8])
	return filepath.Join(home, ".ssh-cli", "keys", name)
}

func loadFileKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return key, nil
}

func saveFileKey(path string, priv *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// --- Key interface ---

func (k *fileKey) Public() crypto.PublicKey { return k.pub }

func (k *fileKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.priv.Sign(rand, digest, opts)
}

func (k *fileKey) SSHSigner() ssh.Signer {
	signer, err := ssh.NewSignerFromSigner(k)
	if err != nil {
		panic(fmt.Sprintf("ssh.NewSignerFromSigner(fileKey): %v", err))
	}
	return signer
}

func (k *fileKey) SSHPublicKey() ssh.PublicKey { return k.sshPub }

func (k *fileKey) AuthorizedKey() []byte {
	buf := ssh.MarshalAuthorizedKey(k.sshPub)
	if k.comment == "" {
		return buf
	}
	return append(buf[:len(buf)-1], []byte(" "+k.comment+"\n")...)
}

func (k *fileKey) IsHardwareBacked() bool { return false }

func (k *fileKey) Close() {}
