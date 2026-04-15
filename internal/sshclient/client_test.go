package sshclient

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"ssh-cli/internal/config"
)

func TestBuildHostKeyCallbackAcceptsAndPersistsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "known_hosts")
	proxy := config.SingleProxy{
		KnownHosts:    knownHosts,
		HostKeyPolicy: "accept-new",
	}

	cb := buildHostKeyCallback(proxy)
	key := mustSigner(t).PublicKey()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}

	if err := cb("127.0.0.1:2222", addr, key); err != nil {
		t.Fatalf("expected unknown host to be accepted and persisted, got %v", err)
	}

	cb2 := buildHostKeyCallback(proxy)
	if err := cb2("127.0.0.1:2222", addr, key); err != nil {
		t.Fatalf("expected stored host key to verify, got %v", err)
	}
}

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
