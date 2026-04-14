package keychain

import (
	"errors"
	"testing"
)

func TestShouldRetryWithoutSecureEnclaveDetectsMissingEntitlement(t *testing.T) {
	err := errors.New("The operation couldn't be completed. (OSStatus error -34018 - failed to add key to keychain: <SecKeyRef:('com.apple.setoken')>)")
	if !shouldRetryWithoutSecureEnclave(err) {
		t.Fatal("expected missing entitlement error to trigger fallback")
	}
}

func TestShouldRetryWithoutSecureEnclaveIgnoresUnrelatedErrors(t *testing.T) {
	err := errors.New("some other keychain problem")
	if shouldRetryWithoutSecureEnclave(err) {
		t.Fatal("did not expect unrelated errors to trigger fallback")
	}
}
