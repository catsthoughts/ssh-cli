//go:build linux

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"ssh-cli/internal/config"
)

const tpmDevicePath = "/dev/tpmrm0"

// tpmKey wraps a persistent ECDSA P-256 key stored in a TPM 2.0.
type tpmKey struct {
	mu       sync.Mutex
	cfg      config.KeyConfig
	pub      *ecdsa.PublicKey
	sshPub   ssh.PublicKey
	handle   tpm2.TPMHandle
	comment  string
}

func ensureKeyTPM(cfg config.KeyConfig) (Key, bool, error) {
	if cfg.Tag == "" {
		return nil, false, errors.New("key.tag is required")
	}

	t, err := openTPM()
	if err != nil {
		return nil, false, fmt.Errorf("open TPM: %w", err)
	}
	defer t.Close()

	handle := tagToHandle(cfg.Tag)

	// Try to read the existing key.
	pub, err := readPublicKey(t, handle)
	if err == nil && pub != nil {
		return finishTPMKey(cfg, pub, handle, false)
	}

	// Create a new primary key under the owner hierarchy, then
	// persist it at the chosen handle.
	pub, err = createAndPersistKey(t, handle)
	if err != nil {
		return nil, false, fmt.Errorf("create TPM key: %w", err)
	}
	return finishTPMKey(cfg, pub, handle, true)
}

func finishTPMKey(cfg config.KeyConfig, pub *ecdsa.PublicKey, handle tpm2.TPMHandle, created bool) (Key, bool, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, false, fmt.Errorf("convert TPM public key to SSH: %w", err)
	}
	k := &tpmKey{
		cfg:     cfg,
		pub:     pub,
		sshPub:  sshPub,
		handle:  handle,
		comment: cfg.Comment,
	}
	return k, created, nil
}

// tagToHandle converts a key tag string to a persistent TPM handle in the range
// 0x81000000–0x810000FF. The handle is deterministic for a given tag.
func tagToHandle(tag string) tpm2.TPMHandle {
	h := sha256.Sum256([]byte(tag))
	offset := uint32(h[0]) | uint32(h[1])<<8
	return tpm2.TPMHandle(0x81000000 + (offset & 0xFF))
}

func openTPM() (transport.TPMCloser, error) {
	return linuxtpm.Open(tpmDevicePath)
}

func readPublicKey(t transport.TPM, handle tpm2.TPMHandle) (*ecdsa.PublicKey, error) {
	resp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.NamedHandle{Handle: handle},
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	return extractECCPublicKey(resp.OutPublic)
}

func createAndPersistKey(t transport.TPM, persistHandle tpm2.TPMHandle) (*ecdsa.PublicKey, error) {
	// Create a primary ECC P-256 signing key under the owner hierarchy.
	createResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
					},
				}),
		}),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: createResp.ObjectHandle}.Execute(t)

	// Try to evict any previous key at the persistent handle.
	_ = evictKey(t, persistHandle)

	// Persist the new key.
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: createResp.ObjectHandle,
			Name:   createResp.Name,
		},
		PersistentHandle: persistHandle,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("EvictControl: %w", err)
	}

	return extractECCPublicKey(createResp.OutPublic)
}

func evictKey(t transport.TPM, handle tpm2.TPMHandle) error {
	_, err := tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: handle,
			Name:   tpm2.TPM2BName{Buffer: nil},
		},
		PersistentHandle: handle,
	}.Execute(t)
	return err
}

func extractECCPublicKey(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	p, err := pub.Contents()
	if err != nil {
		return nil, err
	}
	eccDetail, err := p.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	_ = eccDetail // just validate it's ECC
	eccUnique, err := p.Unique.ECC()
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(eccUnique.X.Buffer)
	y := new(big.Int).SetBytes(eccUnique.Y.Buffer)
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// --- Key interface ---

func (k *tpmKey) Public() crypto.PublicKey { return k.pub }

func (k *tpmKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("TPM key only supports SHA-256")
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	t, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("open TPM for signing: %w", err)
	}
	defer t.Close()

	resp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("TPM Sign: %w", err)
	}
	ecdsaSig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

func (k *tpmKey) SSHSigner() ssh.Signer {
	signer, err := ssh.NewSignerFromSigner(k)
	if err != nil {
		panic(fmt.Sprintf("ssh.NewSignerFromSigner(tpmKey): %v", err))
	}
	return signer
}

func (k *tpmKey) SSHPublicKey() ssh.PublicKey { return k.sshPub }

func (k *tpmKey) AuthorizedKey() []byte {
	buf := ssh.MarshalAuthorizedKey(k.sshPub)
	if k.comment == "" {
		return buf
	}
	return append(buf[:len(buf)-1], []byte(" "+k.comment+"\n")...)
}

func (k *tpmKey) IsHardwareBacked() bool { return true }

func (k *tpmKey) Close() {}
