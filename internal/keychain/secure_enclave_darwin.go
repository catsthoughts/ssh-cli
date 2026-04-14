//go:build darwin

package keychain

/*
#cgo darwin CFLAGS: -Wno-deprecated-declarations
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include "auth_darwin.h"
#include <string.h>

static char* cfstring_to_cstr(CFStringRef s) {
	if (!s) {
		char *buf = (char*)malloc(15);
		strcpy(buf, "unknown error");
		return buf;
	}
	CFIndex len = CFStringGetLength(s);
	CFIndex maxSize = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
	char *buf = (char*)malloc(maxSize);
	if (!CFStringGetCString(s, buf, maxSize, kCFStringEncodingUTF8)) {
		strcpy(buf, "unknown error");
	}
	return buf;
}

static char* cferror_to_cstr(CFErrorRef err) {
	if (!err) {
		char *buf = (char*)malloc(15);
		strcpy(buf, "unknown error");
		return buf;
	}
	CFStringRef desc = CFErrorCopyDescription(err);
	char *buf = cfstring_to_cstr(desc);
	if (desc) CFRelease(desc);
	return buf;
}

static char* osstatus_to_cstr(OSStatus status) {
	CFStringRef msg = SecCopyErrorMessageString(status, NULL);
	char *buf = cfstring_to_cstr(msg);
	if (msg) CFRelease(msg);
	return buf;
}

static CFDataRef data_from_cstr(const char *s) {
	return CFDataCreate(kCFAllocatorDefault, (const UInt8*)s, (CFIndex)strlen(s));
}

static CFStringRef string_from_cstr(const char *s) {
	return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

static int copy_cfdata(CFDataRef data, unsigned char **outBytes, int *outLen, char **errOut) {
	if (!data) {
		*errOut = strdup("missing output data");
		return 0;
	}
	CFIndex len = CFDataGetLength(data);
	*outBytes = (unsigned char*)malloc((size_t)len);
	if (!*outBytes) {
		*errOut = strdup("malloc failed");
		return 0;
	}
	memcpy(*outBytes, CFDataGetBytePtr(data), (size_t)len);
	*outLen = (int)len;
	return 1;
}

static SecKeyRef find_key(CFDataRef tagData, CFTypeRef authContext, char **errOut) {
	const void *keys[5];
	const void *vals[5];
	int count = 4;
	keys[0] = kSecClass;              vals[0] = kSecClassKey;
	keys[1] = kSecAttrApplicationTag; vals[1] = tagData;
	keys[2] = kSecAttrKeyClass;       vals[2] = kSecAttrKeyClassPrivate;
	keys[3] = kSecReturnRef;          vals[3] = kCFBooleanTrue;
	if (authContext) {
		keys[4] = kSecUseAuthenticationContext; vals[4] = authContext;
		count = 5;
	}
	CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, count, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef item = NULL;
	OSStatus status = SecItemCopyMatching(query, &item);
	CFRelease(query);
	if (status == errSecSuccess) {
		return (SecKeyRef)item;
	}
	if (status != errSecItemNotFound && errOut) {
		*errOut = osstatus_to_cstr(status);
	}
	return NULL;
}

static int gosec_ensure_key(const char *tag, const char *label, int useSecureEnclave, int useAccessControl, unsigned char **outBytes, int *outLen, SecKeyRef *outKeyRef, CFTypeRef *outAuthCtx, char **errOut) {
	int created = 0;
	CFTypeRef authCtx = NULL;
	if (useSecureEnclave) {
		authCtx = sshcli_create_auth_context();
		if (!authCtx) {
			*errOut = strdup("authentication cancelled");
			return 0;
		}
	}
	CFDataRef tagData = data_from_cstr(tag);
	SecKeyRef key = find_key(tagData, authCtx, errOut);
	if (!key && errOut && *errOut) {
		if (authCtx) CFRelease(authCtx);
		CFRelease(tagData);
		return 0;
	}

	if (!key) {
		if (authCtx) { CFRelease(authCtx); authCtx = NULL; }
		CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFMutableDictionaryRef privateAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		int bits = 256;
		CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
		CFStringRef labelRef = string_from_cstr(label);
		CFErrorRef accessErr = NULL;
		SecAccessControlRef access = NULL;

		if (useSecureEnclave) {
			access = SecAccessControlCreateWithFlags(
				kCFAllocatorDefault,
				kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
				kSecAccessControlPrivateKeyUsage,
				&accessErr);
			if (!access) {
				*errOut = cferror_to_cstr(accessErr);
				if (accessErr) CFRelease(accessErr);
				if (labelRef) CFRelease(labelRef);
				CFRelease(bitsNum);
				CFRelease(privateAttrs);
				CFRelease(attrs);
				CFRelease(tagData);
				return 0;
			}
		}

		CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
		CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsNum);
		CFDictionarySetValue(privateAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
		CFDictionarySetValue(privateAttrs, kSecAttrApplicationTag, tagData);
		if (labelRef) {
			CFDictionarySetValue(privateAttrs, kSecAttrLabel, labelRef);
		}
		if (access) {
			CFDictionarySetValue(privateAttrs, kSecAttrAccessControl, access);
		}
		CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, privateAttrs);
		if (useSecureEnclave) {
			CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
		}

		CFErrorRef err = NULL;
		key = SecKeyCreateRandomKey(attrs, &err);
		if (!key) {
			*errOut = cferror_to_cstr(err);
			if (err) CFRelease(err);
			if (labelRef) CFRelease(labelRef);
			if (access) CFRelease(access);
			CFRelease(bitsNum);
			CFRelease(privateAttrs);
			CFRelease(attrs);
			CFRelease(tagData);
			return 0;
		}
		created = 1;
		if (labelRef) CFRelease(labelRef);
		if (access) CFRelease(access);
		CFRelease(bitsNum);
		CFRelease(privateAttrs);
		CFRelease(attrs);
		authCtx = sshcli_create_auth_context();
	}

	SecKeyRef pubKey = SecKeyCopyPublicKey(key);
	CFErrorRef pubErr = NULL;
	CFDataRef pubData = SecKeyCopyExternalRepresentation(pubKey, &pubErr);
	if (!pubData) {
		*errOut = cferror_to_cstr(pubErr);
		if (pubErr) CFRelease(pubErr);
		CFRelease(pubKey);
		CFRelease(key);
		CFRelease(tagData);
		if (authCtx) CFRelease(authCtx);
		return 0;
	}

	int ok = copy_cfdata(pubData, outBytes, outLen, errOut);
	CFRelease(pubData);
	CFRelease(pubKey);
	CFRelease(tagData);
	if (!ok) {
		CFRelease(key);
		if (authCtx) CFRelease(authCtx);
		return 0;
	}
	*outKeyRef = key;
	*outAuthCtx = authCtx;
	return created ? 2 : 1;
}

static int gosec_sign_with_keyref(SecKeyRef key, const unsigned char *digest, int digestLen, unsigned char **outBytes, int *outLen, char **errOut) {
	if (!key) {
		*errOut = strdup("private key ref is nil");
		return 0;
	}

	CFDataRef digestData = CFDataCreate(kCFAllocatorDefault, digest, digestLen);
	if (!SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeSign, kSecKeyAlgorithmECDSASignatureDigestX962SHA256)) {
		*errOut = strdup("sha256 signing not supported for this key");
		CFRelease(digestData);
		return 0;
	}

	CFErrorRef err = NULL;
	CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digestData, &err);
	if (!sig) {
		*errOut = cferror_to_cstr(err);
		if (err) CFRelease(err);
		CFRelease(digestData);
		return 0;
	}

	int ok = copy_cfdata(sig, outBytes, outLen, errOut);
	CFRelease(sig);
	CFRelease(digestData);
	return ok;
}

static void gosec_release_key(SecKeyRef key) {
	if (key) CFRelease(key);
}
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"ssh-cli/internal/config"
)

type Key struct {
	mu      sync.Mutex
	cfg     config.KeyConfig
	pub     *ecdsa.PublicKey
	sshPub  ssh.PublicKey
	keyRef  unsafe.Pointer // cached SecKeyRef
	authCtx unsafe.Pointer // cached LAContext (keeps auth session alive)
}

type SSHSigner struct {
	key *Key
}

type ecdsaASN1Signature struct {
	R, S *big.Int
}

func EnsureKey(cfg config.KeyConfig) (*Key, bool, error) {
	key, created, err := ensureKey(cfg, true)
	if err == nil {
		return key, created, nil
	}
	if shouldRetryWithoutSecureEnclave(err) {
		key, created, retryErr := ensureKey(cfg, false)
		if retryErr == nil {
			return key, created, nil
		}
		if cfg.SecureEnclave {
			fallbackCfg := cfg
			fallbackCfg.SecureEnclave = false
			return ensureKey(fallbackCfg, false)
		}
		return nil, false, retryErr
	}
	return nil, false, err
}

func ensureKey(cfg config.KeyConfig, useAccessControl bool) (*Key, bool, error) {
	if cfg.Tag == "" {
		return nil, false, errors.New("key tag is required")
	}
	if cfg.Label == "" {
		cfg.Label = cfg.Tag
	}

	ctag := C.CString(cfg.Tag)
	clabel := C.CString(cfg.Label)
	defer C.free(unsafe.Pointer(ctag))
	defer C.free(unsafe.Pointer(clabel))

	var out *C.uchar
	var outLen C.int
	var cerr *C.char
	var cKeyRef C.SecKeyRef
	var cAuthCtx C.CFTypeRef

	status := C.gosec_ensure_key(ctag, clabel, boolToCInt(cfg.SecureEnclave), boolToCInt(useAccessControl), &out, &outLen, &cKeyRef, &cAuthCtx, &cerr)
	if status == 0 {
		return nil, false, cStringErr(cerr)
	}
	defer C.free(unsafe.Pointer(out))

	pubBytes := C.GoBytes(unsafe.Pointer(out), outLen)
	pub, err := parsePublicKey(pubBytes)
	if err != nil {
		C.gosec_release_key(cKeyRef)
		C.sshcli_release_auth_context(cAuthCtx)
		return nil, false, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		C.gosec_release_key(cKeyRef)
		C.sshcli_release_auth_context(cAuthCtx)
		return nil, false, err
	}

	return &Key{cfg: cfg, pub: pub, sshPub: sshPub, keyRef: unsafe.Pointer(cKeyRef), authCtx: unsafe.Pointer(cAuthCtx)}, status == 2, nil
}

func shouldRetryWithoutSecureEnclave(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "-34018") ||
		strings.Contains(msg, "missing entitlement") ||
		strings.Contains(msg, "failed to add key to keychain")
}

func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

func (k *Key) IsSecureEnclave() bool {
	return k.cfg.SecureEnclave
}

func (k *Key) SSHPublicKey() ssh.PublicKey {
	return k.sshPub
}

func (k *Key) AuthorizedKey() []byte {
	buf := ssh.MarshalAuthorizedKey(k.sshPub)
	if k.cfg.Comment == "" {
		return buf
	}
	return append(buf[:len(buf)-1], []byte(" "+k.cfg.Comment+"\n")...)
}

func (k *Key) SSHSigner() ssh.Signer {
	return &SSHSigner{key: k}
}

func (k *Key) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keyRef != nil {
		C.gosec_release_key(C.SecKeyRef(k.keyRef))
		k.keyRef = nil
	}
	if k.authCtx != nil {
		C.sshcli_release_auth_context(C.CFTypeRef(k.authCtx))
		k.authCtx = nil
	}
}

func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("only SHA-256 is supported for Secure Enclave signing")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keyRef == nil {
		return nil, errors.New("key has been closed")
	}

	var out *C.uchar
	var outLen C.int
	var cerr *C.char
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}
	if C.gosec_sign_with_keyref(C.SecKeyRef(k.keyRef), (*C.uchar)(unsafe.Pointer(&digest[0])), C.int(len(digest)), &out, &outLen, &cerr) == 0 {
		return nil, cStringErr(cerr)
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), outLen), nil
}

func (s *SSHSigner) PublicKey() ssh.PublicKey {
	return s.key.SSHPublicKey()
}

func (s *SSHSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, ssh.KeyAlgoECDSA256)
}

func (s *SSHSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if algorithm != "" && algorithm != ssh.KeyAlgoECDSA256 {
		return nil, fmt.Errorf("unsupported ssh algorithm: %s", algorithm)
	}
	digest := sha256.Sum256(data)
	der, err := s.key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var parsed ecdsaASN1Signature
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, fmt.Errorf("parse ecdsa signature: %w", err)
	}
	blob := ssh.Marshal(parsed)
	return &ssh.Signature{Format: ssh.KeyAlgoECDSA256, Blob: blob}, nil
}

func WriteAuthorizedKeyFile(path string, data []byte) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func parsePublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) == 65 && raw[0] == 4 {
		x := new(big.Int).SetBytes(raw[1:33])
		y := new(big.Int).SetBytes(raw[33:65])
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pk, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return pk, nil
}

func boolToCInt(v bool) C.int {
	if v {
		return 1
	}
	return 0
}

func cStringErr(cerr *C.char) error {
	if cerr == nil {
		return errors.New("unknown keychain error")
	}
	defer C.free(unsafe.Pointer(cerr))
	return errors.New(C.GoString(cerr))
}
