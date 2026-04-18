package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"ssh-cli/internal/config"
)

// Key is a universal wrapper over platform-specific backends.
type Key struct {
	mu      sync.Mutex
	cfg     config.KeyConfig
	pub     *ecdsa.PublicKey
	sshPub  ssh.PublicKey
	backend keyBackend
}

type keyBackend interface {
	Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
	Close()
}

// softECDSABackend is a pure-software keyBackend backed by an *ecdsa.PrivateKey.
type softECDSABackend struct {
	priv *ecdsa.PrivateKey
}

func (s *softECDSABackend) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.priv.Sign(rand, digest, opts)
}
func (s *softECDSABackend) Close() {}

// NewKeyFromECDSA creates a Key backed by a software ECDSA P-256 private key.
// Used in tests and may be used for file-based key workflows.
func NewKeyFromECDSA(priv *ecdsa.PrivateKey, cfg config.KeyConfig) (*Key, error) {
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Key{
		cfg:     cfg,
		pub:     &priv.PublicKey,
		sshPub:  sshPub,
		backend: &softECDSABackend{priv: priv},
	}, nil
}

// Public returns *ecdsa.PublicKey.
func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

// SSHPublicKey returns ssh.PublicKey.
func (k *Key) SSHPublicKey() ssh.PublicKey {
	return k.sshPub
}

// AuthorizedKey returns the authorized_keys line.
func (k *Key) AuthorizedKey() []byte {
	buf := ssh.MarshalAuthorizedKey(k.sshPub)
	if k.cfg.Comment == "" {
		return buf
	}
	return append(buf[:len(buf)-1], []byte(" "+k.cfg.Comment+"\n")...)
}

// IsSecureEnclave returns true if the key is stored in Secure Enclave.
func (k *Key) IsSecureEnclave() bool {
	return k.cfg.SecureEnclave
}

// SSHSigner returns an ssh.Signer.
func (k *Key) SSHSigner() ssh.Signer {
	return &sshSigner{key: k}
}

// Close releases backend resources.
func (k *Key) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.backend != nil {
		k.backend.Close()
		k.backend = nil
	}
}

// Sign signs a digest (SHA-256 only).
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("only SHA-256 is supported")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.backend == nil {
		return nil, errors.New("key has been closed")
	}
	return k.backend.Sign(nil, digest, opts)
}

// sshSigner implements ssh.Signer by delegating to Key.Sign.
type sshSigner struct {
	key *Key
}

func (s *sshSigner) PublicKey() ssh.PublicKey {
	return s.key.sshPub
}

func (s *sshSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, ssh.KeyAlgoECDSA256)
}

func (s *sshSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if algorithm != "" && algorithm != ssh.KeyAlgoECDSA256 {
		return nil, errors.New("unsupported ssh algorithm")
	}
	digest := sha256.Sum256(data)
	der, err := s.key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var parsed ecdsaASN1Signature
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, errors.New("parse ecdsa signature")
	}
	blob := ssh.Marshal(parsed)
	return &ssh.Signature{Format: ssh.KeyAlgoECDSA256, Blob: blob}, nil
}

type ecdsaASN1Signature struct {
	R, S *big.Int
}

// ParseECDSAPublicKey parses a raw public key (65-byte uncompressed or PKIX).
func ParseECDSAPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) == 65 && raw[0] == 4 {
		x := new(big.Int).SetBytes(raw[1:33])
		y := new(big.Int).SetBytes(raw[33:65])
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}
	pk, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return pk, nil
}

// WriteAuthorizedKeyFile writes the authorized_key to a file.
func WriteAuthorizedKeyFile(path string, data []byte) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
