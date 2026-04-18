//go:build e2e

// Package e2e contains end-to-end tests for ssh-cli.
//
// Run with:
//
//	go test -v -tags e2e -timeout 120s ./e2e/
//
// Prerequisites:
//   - ssh-proxy-server listening on 127.0.0.1:2222
//   - Credentials loaded from e2e/testenv.json (see testenv.json.example — never commit real credentials)
//
// Test flow for each key backend (SE, YubiKey):
//  1. EnsureKey — create/load key
//  2. Authorise — upload public key to jump target via direct SSH
//  3. Connect via proxy — run a command on the jump target and verify output
//  4. Cleanup — remove the public key from the target's authorized_keys
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	gossh_agent "golang.org/x/crypto/ssh/agent"

	agentutil "ssh-cli/internal/agent"
	"ssh-cli/internal/config"
	"ssh-cli/internal/keychain"
	_ "ssh-cli/internal/sshclient" // imported for side effects / build check
)

// ──────────────────────────────────────────────────────────────────────────────
// Test environment (loaded from e2e/testenv.json — never commit real values)
// ──────────────────────────────────────────────────────────────────────────────

type testEnv struct {
	// Proxy (ssh-proxy-server)
	ProxyAddr string `json:"proxy_addr"` // e.g. "127.0.0.1:2222"
	ProxyUser string `json:"proxy_user"` // e.g. "ekilimchuk"

	// Jump target (accessed through the proxy)
	TargetHost string `json:"target_host"` // e.g. "spacepilot.ru"
	TargetPort string `json:"target_port"` // e.g. "22"
	TargetUser string `json:"target_user"` // e.g. "ekilimchuk"

	// Direct SSH credentials for the target (used ONLY to upload/remove the public key)
	TargetDirectPassword string `json:"target_direct_password"` // or leave empty to use agent

	// Secure Enclave key config
	SEKeyTag   string `json:"se_key_tag"`   // e.g. "com.example.sshcli.e2e.se"
	SEKeyLabel string `json:"se_key_label"` // e.g. "E2E Secure Enclave Key"

	// YubiKey config
	YubiKeySlot string `json:"yubikey_slot"` // e.g. "9a"
}

func loadTestEnv(t *testing.T) testEnv {
	t.Helper()
	data, err := os.ReadFile("testenv.json")
	if err != nil {
		t.Fatalf("testenv.json not found — copy testenv.json.example and fill in values: %v", err)
	}
	var env testEnv
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse testenv.json: %v", err)
	}
	if env.ProxyAddr == "" {
		t.Fatal("testenv.json: proxy_addr is required")
	}
	if env.TargetHost == "" {
		t.Fatal("testenv.json: target_host is required")
	}
	if env.TargetUser == "" {
		t.Fatal("testenv.json: target_user is required")
	}
	return env
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// targetAddr returns "host:port" for the jump target.
func (e testEnv) targetAddr() string {
	port := e.TargetPort
	if port == "" {
		port = "22"
	}
	return net.JoinHostPort(e.TargetHost, port)
}

// directClient opens a direct SSH connection to the jump target.
// Auth order: password (if set in testenv.json) → system ssh-agent → fallback error.
// Used only to modify authorized_keys before/after the actual test.
func directClient(t *testing.T, env testEnv) *ssh.Client {
	t.Helper()

	var authMethods []ssh.AuthMethod

	// 1. Password auth if provided.
	if env.TargetDirectPassword != "" {
		authMethods = append(authMethods, ssh.Password(env.TargetDirectPassword))
	}

	// 2. System ssh-agent.
	if agentSock := os.Getenv("SSH_AUTH_SOCK"); agentSock != "" {
		conn, err := net.Dial("unix", agentSock)
		if err == nil {
			agentClient := gossh_agent.NewClient(conn)
			authMethods = append(authMethods, ssh.PublicKeysCallback(agentClient.Signers))
			t.Cleanup(func() { conn.Close() })
		}
	}

	if len(authMethods) == 0 {
		t.Skip("no direct auth available (set target_direct_password or start ssh-agent)")
	}

	cfg := &ssh.ClientConfig{
		User:            env.TargetUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // e2e only
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", env.targetAddr(), cfg)
	if err != nil {
		t.Fatalf("direct SSH to %s: %v", env.targetAddr(), err)
	}
	return client
}

// authorizeKey appends the given authorized-key line to ~/.ssh/authorized_keys on the target.
func authorizeKey(t *testing.T, client *ssh.Client, authorizedKeyLine string) {
	t.Helper()
	authorizedKeyLine = strings.TrimRight(authorizedKeyLine, "\n")
	cmd := fmt.Sprintf(
		`mkdir -p ~/.ssh && chmod 700 ~/.ssh && `+
			`echo %q >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
		authorizedKeyLine,
	)
	runRemote(t, client, cmd)
	t.Logf("authorized key on target: %s", authorizedKeyLine[:min(len(authorizedKeyLine), 60)]+"…")
}

// deauthorizeKey removes lines matching the public key from authorized_keys.
func deauthorizeKey(t *testing.T, client *ssh.Client, authorizedKeyLine string) {
	t.Helper()
	// Extract just the base64 blob (second field) to grep on.
	parts := strings.Fields(authorizedKeyLine)
	if len(parts) < 2 {
		return
	}
	blob := parts[1]
	// Use grep -v to filter out the key (avoids sed delimiter issues with base64 '/').
	cmd := fmt.Sprintf(
		`grep -v %q ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys || true`,
		blob,
	)
	runRemote(t, client, cmd)
}

// runRemote runs cmd on client and returns stdout.
func runRemote(t *testing.T, client *ssh.Client, cmd string) string {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = os.Stderr
	if err := sess.Run(cmd); err != nil {
		t.Fatalf("remote cmd %q: %v", cmd, err)
	}
	return strings.TrimSpace(buf.String())
}

// runViaProxy connects to the proxy with the given signer and executes cmd on the
// jump target. The proxy opens a shell session and tunnels stdin/stdout to the
// target — so we pipe the command through stdin and read stdout until EOF.
func runViaProxy(t *testing.T, env testEnv, cfg config.Config, signer ssh.Signer, cmd string) string {
	t.Helper()

	proxyClientCfg := &ssh.ClientConfig{
		User:            env.ProxyUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // e2e only
		Timeout:         30 * time.Second,
	}

	proxyConn, err := ssh.Dial("tcp", env.ProxyAddr, proxyClientCfg)
	if err != nil {
		t.Fatalf("connect to proxy %s: %v", env.ProxyAddr, err)
	}
	defer proxyConn.Close()

	// Forward agent so proxy can auth to target.
	fwdAgent := agentutil.NewReadOnlyAgent(cfg.Key.Comment, signer)
	if err := gossh_agent.ForwardToAgent(proxyConn, fwdAgent); err != nil {
		t.Fatalf("forward agent: %v", err)
	}

	sess, err := proxyConn.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	if err := gossh_agent.RequestAgentForwarding(sess); err != nil {
		t.Fatalf("request agent forwarding: %v", err)
	}

	// Tell the proxy which target to jump to.
	target := fmt.Sprintf("%s@%s", env.TargetUser, env.targetAddr())
	if err := sess.Setenv("LC_SSH_SERVER", target); err != nil {
		t.Fatalf("setenv LC_SSH_SERVER: %v", err)
	}

	var stdoutBuf bytes.Buffer
	sess.Stdout = &stdoutBuf
	sess.Stderr = os.Stderr

	// Pipe the command through stdin — proxy tunnels it to the target shell.
	// We send the command followed by 'exit' to close the shell cleanly.
	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}

	if err := sess.Shell(); err != nil {
		t.Fatalf("start shell: %v", err)
	}

	// Write command + exit to stdin, then close.
	fmt.Fprintf(stdinPipe, "%s; exit $?\n", cmd)
	stdinPipe.Close()

	if err := sess.Wait(); err != nil {
		t.Fatalf("session wait: %v\noutput: %s", err, stdoutBuf.String())
	}

	// The proxy/target may prepend MOTD before command output.
	// Take only the last non-empty line as the command result.
	return lastLine(stdoutBuf.String())
}

// lastLine returns the last non-empty line from s (strips MOTD etc).
func lastLine(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return strings.TrimSpace(s)
}

// ──────────────────────────────────────────────────────────────────────────────
// Core test logic (backend-agnostic)
// ──────────────────────────────────────────────────────────────────────────────

// testBackend runs the full e2e flow for a given key config.
func testBackend(t *testing.T, env testEnv, keyCfg config.KeyConfig, proxyUser string) {
	t.Helper()

	cfg := config.Config{
		Key: keyCfg,
		Proxy: config.ProxyConfig{
			Address:               config.Addresses{env.ProxyAddr},
			User:                  proxyUser,
			InsecureIgnoreHostKey: true,
			UseAgentForwarding:    true,
			ConnectTimeoutSeconds: 15,
			BalanceMode:           "failover",
			RetryAttempts:         1,
		},
	}

	// ── Step 0: Delete/recreate key so we always test key creation ───────────
	var key *keychain.Key
	if keyCfg.KeySource == "yubikey_piv" {
		// YubiKey: use ForceCreateKey which resets the PIV slot and generates new key.
		t.Logf("step 0: force-creating new key on YubiKey slot %s", keyCfg.YubiKey.Slot)
		var err error
		key, err = keychain.ForceCreateKey(keyCfg)
		if err != nil {
			t.Fatalf("ForceCreateKey: %v", err)
		}
		defer key.Close()
		t.Logf("created new YubiKey key: %s", keyCfg.Tag)
	} else {
		// SE / software Keychain: delete then recreate.
		t.Logf("step 0: deleting existing key %s from Keychain (if any)", keyCfg.Tag)
		if err := keychain.DeleteKey(keyCfg.Tag); err != nil {
			t.Fatalf("DeleteKey: %v", err)
		}

		// ── Step 1: EnsureKey ────────────────────────────────────────────────
		t.Log("step 1: creating key")
		var created bool
		var err error
		key, created, err = keychain.EnsureKey(keyCfg)
		if err != nil {
			t.Fatalf("EnsureKey: %v", err)
		}
		defer key.Close()
		if !created {
			t.Errorf("expected key to be created (was deleted in step 0), got loaded=true")
		}
		t.Logf("created new key: %s", keyCfg.Tag)
	}

	authorizedKeyLine := strings.TrimRight(string(key.AuthorizedKey()), "\n")
	t.Logf("public key: %s", authorizedKeyLine)

	// ── Step 2: Authorise public key on target ───────────────────────────────
	t.Log("step 2: authorising key on target via direct SSH")
	directConn := directClient(t, env)
	defer directConn.Close()

	authorizeKey(t, directConn, authorizedKeyLine)
	// Cleanup: remove the key when the test finishes.
	t.Cleanup(func() {
		t.Log("cleanup: removing test key from target authorized_keys")
		cleanConn := directClient(t, env)
		defer cleanConn.Close()
		deauthorizeKey(t, cleanConn, authorizedKeyLine)
	})

	// Give sshd a moment to reload authorized_keys (usually instant, but be safe).
	time.Sleep(500 * time.Millisecond)

	// ── Step 3: Connect via proxy and run a command ──────────────────────────
	t.Log("step 3: connecting via proxy")
	signer := key.SSHSigner()
	output := runViaProxy(t, env, cfg, signer, "hostname")

	if output == "" {
		t.Fatal("expected non-empty output from hostname command via proxy")
	}
	t.Logf("hostname via proxy: %q", output)

	// Also verify whoami returns expected user.
	whoami := runViaProxy(t, env, cfg, signer, "whoami")
	if whoami != env.TargetUser {
		t.Errorf("expected whoami=%q, got %q", env.TargetUser, whoami)
	}
	t.Logf("whoami via proxy: %q", whoami)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestE2E_SecureEnclave(t *testing.T) {
	env := loadTestEnv(t)

	tag := env.SEKeyTag
	if tag == "" {
		tag = "com.example.sshcli.e2e.se.test"
	}
	label := env.SEKeyLabel
	if label == "" {
		label = "ssh-cli e2e test SE key"
	}

	keyCfg := config.KeyConfig{
		Tag:       tag,
		Label:     label,
		Comment:   "e2e-se@test",
		KeySource: "secure_enclave",
		// PublicKeyPath intentionally empty — we use key.AuthorizedKey() directly.
	}

	testBackend(t, env, keyCfg, env.ProxyUser)
}

func TestE2E_YubiKey(t *testing.T) {
	env := loadTestEnv(t)

	slot := env.YubiKeySlot
	if slot == "" {
		slot = "9a"
	}

	keyCfg := config.KeyConfig{
		Tag:       fmt.Sprintf("com.example.sshcli.e2e.yk.%s", slot),
		Label:     fmt.Sprintf("ssh-cli e2e YubiKey slot %s", slot),
		Comment:   fmt.Sprintf("e2e-yubikey-%s@test", slot),
		KeySource: "yubikey_piv",
		YubiKey:   config.YubiKeyConfig{Slot: slot},
	}

	k, _, err := keychain.EnsureKey(keyCfg)
	if err != nil {
		// Skip instead of fail if no YubiKey is available.
		if isNoYubiKeyError(err) {
			t.Skipf("YubiKey not available: %v", err)
		}
		t.Fatalf("EnsureKey (yubikey probe): %v", err)
	}
	k.Close()

	testBackend(t, env, keyCfg, env.ProxyUser)
}

// isNoYubiKeyError returns true when the error indicates no smart card reader.
func isNoYubiKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no smart card") ||
		strings.Contains(msg, "no readers") ||
		strings.Contains(msg, "reader not found") ||
		strings.Contains(msg, "scard_e_no_readers_available") ||
		strings.Contains(msg, "yubikey not available") ||
		strings.Contains(msg, "not supported on this platform")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
