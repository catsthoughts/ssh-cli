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

static int gosec_delete_key(const char *tag, char **errOut) {
	CFDataRef tagData = data_from_cstr(tag);
	const void *keys[3];
	const void *vals[3];
	keys[0] = kSecClass;              vals[0] = kSecClassKey;
	keys[1] = kSecAttrApplicationTag; vals[1] = tagData;
	keys[2] = kSecAttrKeyClass;       vals[2] = kSecAttrKeyClassPrivate;
	CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	CFRelease(tagData);
	if (status != errSecSuccess && status != errSecItemNotFound) {
		if (errOut) *errOut = osstatus_to_cstr(status);
		return 0;
	}
	return 1;
}

static int gosec_sign_with_keyref(SecKeyRef key, const unsigned char *digest, int digestLen, unsigned char **outBytes, int *outLen, CFTypeRef authCtx, char **errOut) {
	if (!key) {
		*errOut = strdup("private key ref is nil");
		return 0;
	}

	SecKeyRef signKey = NULL;
	if (authCtx) {
		CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFDictionarySetValue(query, kSecClass, kSecClassKey);
		CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
		CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
		CFDictionarySetValue(query, kSecUseAuthenticationContext, authCtx);
		CFDictionarySetValue(query, kSecValueRef, key);
		SecItemCopyMatching(query, (CFTypeRef *)&signKey);
		CFRelease(query);
	}
	if (!signKey) {
		signKey = key;
	}

	CFDataRef digestData = CFDataCreate(kCFAllocatorDefault, digest, (CFIndex)digestLen);
	if (!SecKeyIsAlgorithmSupported(signKey, kSecKeyOperationTypeSign, kSecKeyAlgorithmECDSASignatureDigestX962SHA256)) {
		*errOut = strdup("sha256 signing not supported for this key");
		CFRelease(digestData);
		if (signKey != key) CFRelease(signKey);
		return 0;
	}

	CFErrorRef err = NULL;
	CFDataRef sig = SecKeyCreateSignature(signKey, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digestData, &err);
	CFRelease(digestData);
	if (signKey != key) CFRelease(signKey);
	if (!sig) {
		*errOut = cferror_to_cstr(err);
		if (err) CFRelease(err);
		return 0;
	}

	int ok = copy_cfdata(sig, outBytes, outLen, errOut);
	CFRelease(sig);
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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"unsafe"

	"ssh-cli/internal/config"
)

// darwinBackend implements keyBackend for macOS Secure Enclave / Keychain.
// keyRef and authCtx are stored as the concrete CGo types so that the CGo
// pointer-passing rules are satisfied and go vet does not flag conversions
// through unsafe.Pointer at assignment time.
type darwinBackend struct {
	mu      sync.Mutex
	keyRef  C.SecKeyRef  // retained SecKeyRef; nil when closed
	authCtx C.CFTypeRef  // optional LAContext; nil when not used or closed
}

func (b *darwinBackend) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keyRef == 0 {
		return nil, errors.New("key has been closed")
	}
	var out *C.uchar
	var outLen C.int
	var cerr *C.char
	if C.gosec_sign_with_keyref(b.keyRef, (*C.uchar)(unsafe.Pointer(&digest[0])), C.int(len(digest)), &out, &outLen, b.authCtx, &cerr) == 0 {
		return nil, cStringErr(cerr)
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), outLen), nil
}

func (b *darwinBackend) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keyRef != 0 {
		C.gosec_release_key(b.keyRef)
		b.keyRef = 0
	}
	if b.authCtx != 0 {
		C.sshcli_release_auth_context(b.authCtx)
		b.authCtx = 0
	}
}

// DeleteKey removes the private key with the given tag from the Keychain.
// Returns nil if the key did not exist.
func DeleteKey(tag string) error {
	ctag := C.CString(tag)
	defer C.free(unsafe.Pointer(ctag))
	var cerr *C.char
	if C.gosec_delete_key(ctag, &cerr) == 0 {
		return cStringErr(cerr)
	}
	return nil
}

func ensureSecureEnclave(cfg config.KeyConfig) (*ecdsa.PublicKey, *darwinBackend, bool, error) {
	pub, backend, created, err := ensureKey(cfg, true)
	if err != nil && shouldRetryWithoutSecureEnclave(err) {
		if backend != nil {
			backend.Close()
		}
		// Fallback: retry without Secure Enclave (plain Keychain)
		fallbackCfg := cfg
		fallbackCfg.SecureEnclave = false
		fallbackCfg.KeySource = ""
		return ensureKey(fallbackCfg, false)
	}
	return pub, backend, created, err
}

func ensureKey(cfg config.KeyConfig, useAccessControl bool) (*ecdsa.PublicKey, *darwinBackend, bool, error) {
	if cfg.Tag == "" {
		return nil, nil, false, errors.New("key tag is required")
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

	useSeEnclave := cfg.SecureEnclave || cfg.KeySource == "secure_enclave"
	status := C.gosec_ensure_key(ctag, clabel, boolToCInt(useSeEnclave), boolToCInt(useAccessControl), &out, &outLen, &cKeyRef, &cAuthCtx, &cerr)
	if status == 0 {
		return nil, nil, false, cStringErr(cerr)
	}
	defer C.free(unsafe.Pointer(out))

	pubBytes := C.GoBytes(unsafe.Pointer(out), outLen)
	pub, err := parsePublicKey(pubBytes)
	if err != nil {
		C.gosec_release_key(cKeyRef)
		C.sshcli_release_auth_context(cAuthCtx)
		return nil, nil, false, err
	}

	backend := &darwinBackend{
		keyRef:  cKeyRef,
		authCtx: cAuthCtx,
	}
	return pub, backend, status == 2, nil
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
