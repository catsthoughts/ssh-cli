package sshclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	agentutil "ssh-cli/internal/agent"
	"ssh-cli/internal/config"
	"ssh-cli/internal/keychain"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

func Connect(cfg config.Config, route string) error {
	if cfg.Proxy.Address == "" {
		return fmt.Errorf("proxy.address is required")
	}
	if cfg.Proxy.User == "" {
		return fmt.Errorf("proxy.user is required")
	}

	key, _, err := keychain.EnsureKey(cfg.Key)
	if err != nil {
		return err
	}
	defer key.Close()
	baseSigner := key.SSHSigner()
	authSigner, err := maybeWrapWithCert(baseSigner, cfg.Certificate.AuthCertPath)
	if err != nil {
		return err
	}

	clientConfig := &ssh.ClientConfig{
		User:            cfg.Proxy.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(authSigner)},
		HostKeyCallback: buildHostKeyCallback(cfg),
		Timeout:         time.Duration(cfg.Proxy.ConnectTimeoutSeconds) * time.Second,
	}

	conn, err := ssh.Dial("tcp", cfg.Proxy.Address, clientConfig)
	if err != nil {
		return fmt.Errorf("connect to proxy %s: %w", cfg.Proxy.Address, err)
	}
	defer conn.Close()

	if cfg.Proxy.UseAgentForwarding {
		forwardedAgent := agentutil.NewReadOnlyAgent(cfg.Key.Comment, authSigner)
		if err := agent.ForwardToAgent(conn, forwardedAgent); err != nil {
			return fmt.Errorf("forward agent: %w", err)
		}
	}

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer session.Close()

	if cfg.Proxy.UseAgentForwarding {
		if err := agent.RequestAgentForwarding(session); err != nil {
			return fmt.Errorf("request agent forwarding: %w", err)
		}
	}
	if route != "" {
		if err := session.Setenv("LC_SSH_SERVER", route); err != nil {
			return fmt.Errorf("set env LC_SSH_SERVER: %w", err)
		}
	}

	return attachAndRun(session, cfg)
}

func maybeWrapWithCert(base ssh.Signer, path string) (ssh.Signer, error) {
	if path == "" {
		return base, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auth certificate: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse auth certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("auth_cert_path must contain an SSH certificate")
	}
	return ssh.NewCertSigner(cert, base)
}

func buildHostKeyCallback(cfg config.Config) ssh.HostKeyCallback {
	policy := strings.ToLower(strings.TrimSpace(cfg.Proxy.HostKeyPolicy))
	if cfg.Proxy.InsecureIgnoreHostKey || policy == "insecure" || policy == "no" {
		return ssh.InsecureIgnoreHostKey()
	}
	if cfg.Proxy.KnownHosts == "" {
		return ssh.InsecureIgnoreHostKey()
	}
	if policy == "" {
		policy = "accept-new"
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		cb, err := knownhosts.New(cfg.Proxy.KnownHosts)
		if err == nil {
			verifyErr := cb(hostname, remote, key)
			if verifyErr == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if policy == "accept-new" && errors.As(verifyErr, &keyErr) && len(keyErr.Want) == 0 {
				if err := appendKnownHost(cfg.Proxy.KnownHosts, hostname, remote, key); err != nil {
					return fmt.Errorf("persist known host: %w", err)
				}
				return nil
			}
			return verifyErr
		}
		if policy == "accept-new" && os.IsNotExist(err) {
			if err := appendKnownHost(cfg.Proxy.KnownHosts, hostname, remote, key); err != nil {
				return fmt.Errorf("persist known host: %w", err)
			}
			return nil
		}
		return fmt.Errorf("load known_hosts %s: %w", cfg.Proxy.KnownHosts, err)
	}
}

func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	entry := knownhosts.Line(hostPatterns(hostname, remote), key)
	_, err = f.WriteString(entry + "\n")
	return err
}

func hostPatterns(hostname string, remote net.Addr) []string {
	host := strings.TrimSpace(hostname)
	if h, p, err := net.SplitHostPort(hostname); err == nil {
		if p == "22" {
			return []string{h}
		}
		return []string{knownhosts.Normalize(hostname)}
	}
	if tcp, ok := remote.(*net.TCPAddr); ok {
		addr := tcp.IP.String()
		if tcp.Port == 22 {
			if host != "" {
				return []string{host, addr}
			}
			return []string{addr}
		}
		if host != "" {
			return []string{knownhosts.Normalize(net.JoinHostPort(host, fmt.Sprint(tcp.Port))), knownhosts.Normalize(net.JoinHostPort(addr, fmt.Sprint(tcp.Port)))}
		}
		return []string{knownhosts.Normalize(net.JoinHostPort(addr, fmt.Sprint(tcp.Port)))}
	}
	return []string{host}
}

func attachAndRun(session *ssh.Session, cfg config.Config) error {
	fd := int(os.Stdin.Fd())
	requestTTY := cfg.Target.RequestTTY || cfg.Target.Command == ""
	if requestTTY && term.IsTerminal(fd) {
		width, height, err := term.GetSize(fd)
		if err != nil {
			width, height = 80, 24
		}
		modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
		if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
			return fmt.Errorf("request pty: %w", err)
		}
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if requestTTY && term.IsTerminal(fd) && cfg.Target.Command == "" {
		oldState, err := term.MakeRaw(fd)
		if err == nil {
			defer term.Restore(fd, oldState)
		}
		stopResize := watchTerminalResize(session, fd)
		defer stopResize()
	}

	if cfg.Target.Command != "" {
		return session.Run(cfg.Target.Command)
	}
	if err := session.Shell(); err != nil {
		return err
	}
	return session.Wait()
}

func watchTerminalResize(session *ssh.Session, fd int) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			w, h, err := term.GetSize(fd)
			if err == nil {
				_ = session.WindowChange(h, w)
			}
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
}
