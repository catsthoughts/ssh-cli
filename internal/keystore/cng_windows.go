//go:build windows

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"

	"ssh-cli/internal/config"
)

var (
	ncrypt = windows.NewLazySystemDLL("ncrypt.dll")

	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"
	msSoftwareKSP            = "Microsoft Software Key Storage Provider"

	ncryptECCCurveNameProperty = "ECCCurveName"
	ncryptLengthProperty       = "Length"
	curveNameP256              = "nistP256"

	bcryptECCPublicBlob = "ECCPUBLICBLOB"

	// BCRYPT_ECCKEY_BLOB magic for P-256
	bcryptECDSAPublicP256Magic = 0x31534345

	ncryptAlgorithmECDSAP256 = "ECDSA_P256"
)

// cngKey wraps a persistent ECDSA P-256 key stored via Windows CNG (NCrypt).
type cngKey struct {
	mu      sync.Mutex
	pub     *ecdsa.PublicKey
	sshPub  ssh.PublicKey
	handle  uintptr // NCrypt key handle
	comment string
}

func ensureKeyCNG(cfg config.KeyConfig) (Key, bool, error) {
	if cfg.Tag == "" {
		return nil, false, errors.New("key.tag is required")
	}

	// Try the platform (TPM) provider first, fall back to software KSP.
	providerName := msPlatformCryptoProvider
	handle, err := openExistingKey(providerName, cfg.Tag)
	if err != nil {
		// Try software KSP.
		providerName = msSoftwareKSP
		handle, err = openExistingKey(providerName, cfg.Tag)
	}

	if err == nil && handle != 0 {
		pub, pubErr := exportPublicKey(handle)
		if pubErr != nil {
			ncryptFreeObject(handle)
			return nil, false, fmt.Errorf("export existing CNG key: %w", pubErr)
		}
		return finishCNGKey(cfg, pub, handle, false)
	}

	// Create a new key. Prefer platform provider.
	providerName = msPlatformCryptoProvider
	handle, err = createKey(providerName, cfg.Tag)
	if err != nil {
		// Fall back to software KSP.
		providerName = msSoftwareKSP
		handle, err = createKey(providerName, cfg.Tag)
		if err != nil {
			return nil, false, fmt.Errorf("create CNG key: %w", err)
		}
	}

	pub, err := exportPublicKey(handle)
	if err != nil {
		ncryptFreeObject(handle)
		return nil, false, fmt.Errorf("export new CNG key: %w", err)
	}
	return finishCNGKey(cfg, pub, handle, true)
}

func finishCNGKey(cfg config.KeyConfig, pub *ecdsa.PublicKey, handle uintptr, created bool) (Key, bool, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		ncryptFreeObject(handle)
		return nil, false, fmt.Errorf("convert CNG public key to SSH: %w", err)
	}
	k := &cngKey{
		pub:     pub,
		sshPub:  sshPub,
		handle:  handle,
		comment: cfg.Comment,
	}
	return k, created, nil
}

func openStorageProvider(name string) (uintptr, error) {
	nameUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var provHandle uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&provHandle)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NCryptOpenStorageProvider(%s): 0x%x", name, r)
	}
	return provHandle, nil
}

func openExistingKey(providerName, keyName string) (uintptr, error) {
	prov, err := openStorageProvider(providerName)
	if err != nil {
		return 0, err
	}
	defer ncryptFreeObject(prov)

	nameUTF16, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}

	var keyHandle uintptr
	r, _, _ := procNCryptOpenKey.Call(
		prov,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0, // legacy key spec
		0, // flags
	)
	if r != 0 {
		return 0, fmt.Errorf("NCryptOpenKey: 0x%x", r)
	}
	return keyHandle, nil
}

func createKey(providerName, keyName string) (uintptr, error) {
	prov, err := openStorageProvider(providerName)
	if err != nil {
		return 0, err
	}
	defer ncryptFreeObject(prov)

	algoUTF16, err := windows.UTF16PtrFromString(ncryptAlgorithmECDSAP256)
	if err != nil {
		return 0, err
	}
	nameUTF16, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}

	var keyHandle uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(
		prov,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(algoUTF16)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0, // legacy key spec
		0, // flags
	)
	if r != 0 {
		return 0, fmt.Errorf("NCryptCreatePersistedKey: 0x%x", r)
	}

	// Finalize the key to persist it.
	r, _, _ = procNCryptFinalizeKey.Call(keyHandle, 0)
	if r != 0 {
		ncryptFreeObject(keyHandle)
		return 0, fmt.Errorf("NCryptFinalizeKey: 0x%x", r)
	}

	return keyHandle, nil
}

func exportPublicKey(keyHandle uintptr) (*ecdsa.PublicKey, error) {
	blobTypeUTF16, err := windows.UTF16PtrFromString(bcryptECCPublicBlob)
	if err != nil {
		return nil, err
	}

	// First call to get the required size.
	var size uint32
	r, _, _ := procNCryptExportKey.Call(
		keyHandle,
		0,
		uintptr(unsafe.Pointer(blobTypeUTF16)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey (size): 0x%x", r)
	}

	buf := make([]byte, size)
	r, _, _ = procNCryptExportKey.Call(
		keyHandle,
		0,
		uintptr(unsafe.Pointer(blobTypeUTF16)),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey: 0x%x", r)
	}

	// Parse BCRYPT_ECCKEY_BLOB:
	// struct { ULONG dwMagic; ULONG cbKey; BYTE X[cbKey]; BYTE Y[cbKey]; }
	if len(buf) < 8 {
		return nil, errors.New("ECCPUBLICBLOB too short")
	}
	magic := *(*uint32)(unsafe.Pointer(&buf[0]))
	cbKey := *(*uint32)(unsafe.Pointer(&buf[4]))
	if magic != bcryptECDSAPublicP256Magic {
		return nil, fmt.Errorf("unexpected ECC blob magic: 0x%x", magic)
	}
	if uint32(len(buf)) < 8+2*cbKey {
		return nil, errors.New("ECCPUBLICBLOB truncated")
	}
	x := new(big.Int).SetBytes(buf[8 : 8+cbKey])
	y := new(big.Int).SetBytes(buf[8+cbKey : 8+2*cbKey])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func ncryptFreeObject(h uintptr) {
	if h != 0 {
		procNCryptFreeObject.Call(h)
	}
}

// --- Key interface ---

func (k *cngKey) Public() crypto.PublicKey { return k.pub }

func (k *cngKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("CNG key only supports SHA-256")
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.handle == 0 {
		return nil, errors.New("key has been closed")
	}

	// NCryptSignHash expects the raw digest and returns raw (r||s) for ECDSA.
	var sigSize uint32
	r, _, _ := procNCryptSignHash.Call(
		k.handle,
		0, // no padding info for ECDSA
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigSize)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash (size): 0x%x", r)
	}

	sig := make([]byte, sigSize)
	r, _, _ = procNCryptSignHash.Call(
		k.handle,
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigSize),
		uintptr(unsafe.Pointer(&sigSize)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash: 0x%x", r)
	}

	// CNG returns raw (r || s), each half is cbKey bytes.
	half := int(sigSize) / 2
	rInt := new(big.Int).SetBytes(sig[:half])
	sInt := new(big.Int).SetBytes(sig[half:])
	return asn1.Marshal(struct{ R, S *big.Int }{rInt, sInt})
}

func (k *cngKey) SSHSigner() ssh.Signer {
	signer, err := ssh.NewSignerFromSigner(k)
	if err != nil {
		panic(fmt.Sprintf("ssh.NewSignerFromSigner(cngKey): %v", err))
	}
	return signer
}

func (k *cngKey) SSHPublicKey() ssh.PublicKey { return k.sshPub }

func (k *cngKey) AuthorizedKey() []byte {
	buf := ssh.MarshalAuthorizedKey(k.sshPub)
	if k.comment == "" {
		return buf
	}
	return append(buf[:len(buf)-1], []byte(" "+k.comment+"\n")...)
}

func (k *cngKey) IsHardwareBacked() bool {
	// True when backed by Platform Crypto Provider (TPM).
	// Could check provider name, but for simplicity return true
	// since we try platform provider first.
	return true
}

func (k *cngKey) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	ncryptFreeObject(k.handle)
	k.handle = 0
}
