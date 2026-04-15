package sshclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	agentutil "ssh-cli/internal/agent"
	"ssh-cli/internal/config"
	"ssh-cli/internal/keystore"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

func Connect(cfg config.Config, route string) error {
	proxies := cfg.ResolvedProxies()
	if len(proxies) == 0 {
		return fmt.Errorf("at least one proxy with an address is required")
	}

	fmt.Fprintf(os.Stderr, "\xF0\x9F\x90\xB1\nWaiting for key access\u2026\n")
	key, _, err := keystore.EnsureKey(cfg.Key)
	if err != nil {
		return err
	}
	defer key.Close()
	baseSigner := key.SSHSigner()
	authSigner, err := maybeWrapWithCert(baseSigner, cfg.Certificate.AuthCertPath)
	if err != nil {
		return err
	}
	if cfg.Certificate.AuthCertPath != "" {
		fmt.Fprintf(os.Stderr, "Key and certificate loaded\n")
	} else {
		fmt.Fprintf(os.Stderr, "Key loaded\n")
	}

	ordered := orderProxies(proxies, cfg.Proxy.BalanceMode)
	var lastErr error
	for attempt := 1; attempt <= cfg.Proxy.RetryAttempts; attempt++ {
		if attempt > 1 {
			fmt.Fprintf(os.Stderr, "Retry %d/%d in %ds\u2026\n", attempt, cfg.Proxy.RetryAttempts, cfg.Proxy.RetryDelaySeconds)
			time.Sleep(time.Duration(cfg.Proxy.RetryDelaySeconds) * time.Second)
		}
		for _, p := range ordered {
			fmt.Fprintf(os.Stderr, "Connecting to %s\u2026\n", p.Address)
			lastErr = connectViaProxy(cfg, p, authSigner, route)
			if lastErr == nil {
				return nil
			}
			fmt.Fprintf(os.Stderr, "Proxy %s failed: %v\n", p.Address, lastErr)
		}
	}
	return fmt.Errorf("all proxies failed: %w", lastErr)
}

func orderProxies(proxies []config.SingleProxy, mode string) []config.SingleProxy {
	out := make([]config.SingleProxy, len(proxies))
	copy(out, proxies)
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "round-robin":
		if len(out) > 1 {
			offset := int(time.Now().UnixNano()/int64(time.Millisecond)) % len(out)
			rotated := make([]config.SingleProxy, len(out))
			for i := range out {
				rotated[i] = out[(i+offset)%len(out)]
			}
			return rotated
		}
	case "random":
		rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out
}

func connectViaProxy(cfg config.Config, proxy config.SingleProxy, authSigner ssh.Signer, route string) error {
	if proxy.Address == "" {
		return fmt.Errorf("proxy.address is required")
	}
	if proxy.User == "" {
		return fmt.Errorf("proxy.user is required")
	}

	clientConfig := &ssh.ClientConfig{
		User:            proxy.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(authSigner)},
		HostKeyCallback: buildHostKeyCallback(proxy),
		Timeout:         time.Duration(proxy.ConnectTimeoutSeconds) * time.Second,
	}

	conn, err := ssh.Dial("tcp", proxy.Address, clientConfig)
	if err != nil {
		return fmt.Errorf("connect to proxy %s: %w", proxy.Address, err)
	}
	defer conn.Close()

	if proxy.UseAgentForwarding {
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

	if proxy.UseAgentForwarding {
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

func buildHostKeyCallback(proxy config.SingleProxy) ssh.HostKeyCallback {
	policy := strings.ToLower(strings.TrimSpace(proxy.HostKeyPolicy))
	if proxy.InsecureIgnoreHostKey || policy == "insecure" || policy == "no" {
		return ssh.InsecureIgnoreHostKey()
	}
	if proxy.KnownHosts == "" {
		return ssh.InsecureIgnoreHostKey()
	}
	if policy == "" {
		policy = "accept-new"
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		cb, err := knownhosts.New(proxy.KnownHosts)
		if err == nil {
			verifyErr := cb(hostname, remote, key)
			if verifyErr == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if policy == "accept-new" && errors.As(verifyErr, &keyErr) && len(keyErr.Want) == 0 {
				if err := appendKnownHost(proxy.KnownHosts, hostname, remote, key); err != nil {
					return fmt.Errorf("persist known host: %w", err)
				}
				return nil
			}
			return verifyErr
		}
		if policy == "accept-new" && os.IsNotExist(err) {
			if err := appendKnownHost(proxy.KnownHosts, hostname, remote, key); err != nil {
				return fmt.Errorf("persist known host: %w", err)
			}
			return nil
		}
		return fmt.Errorf("load known_hosts %s: %w", proxy.KnownHosts, err)
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
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.ICRNL:         1,
			ssh.OPOST:         1,
			ssh.ONLCR:         1,
			ssh.ISIG:          1,
			ssh.ICANON:        1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
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

			// Ensure terminal is restored even if the process receives
			// SIGINT (e.g. from the double Ctrl+C handler).
			restoreCh := make(chan os.Signal, 1)
			signal.Notify(restoreCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-restoreCh
				term.Restore(fd, oldState)
				os.Exit(1)
			}()
			defer signal.Stop(restoreCh)

			// In raw mode the local terminal does not translate \n → \r\n.
			// If the remote side writes bare \n (e.g. proxy SSO prompts
			// that bypass the PTY), lines "drift" to the right.  Wrap
			// stdout/stderr so every \n becomes \r\n locally.
			crlf := &crlfWriter{w: os.Stdout}
			session.Stdout = crlf
			session.Stderr = &crlfWriter{w: os.Stderr}
		}
		if cfg.Target.ForwardCtrlC {
			session.Stdin = &ctrlCInterceptor{
				r:      os.Stdin,
				stderr: &crlfWriter{w: os.Stderr},
			}
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

// ctrlCInterceptor wraps stdin and intercepts 0x03 (Ctrl+C) bytes.
// First Ctrl+C is forwarded to the remote session as-is.
// Two Ctrl+C presses within 1 second terminate the local process.
type ctrlCInterceptor struct {
	r         io.Reader
	stderr    io.Writer
	lastPress time.Time
}

func (c *ctrlCInterceptor) Read(dst []byte) (int, error) {
	n, err := c.r.Read(dst)
	if n > 0 && err == nil {
		for i := 0; i < n; i++ {
			if dst[i] == 0x03 {
				now := time.Now()
				if now.Sub(c.lastPress) < 1*time.Second {
					fmt.Fprintf(c.stderr, "\r\nDouble Ctrl+C — exiting\r\n")
					syscall.Kill(syscall.Getpid(), syscall.SIGINT)
					return 0, io.EOF
				}
				c.lastPress = now
				fmt.Fprintf(c.stderr, "\r\n[Ctrl+C sent to remote — press again within 1s to exit]\r\n")
			}
		}
	}
	return n, err
}

// crlfWriter translates bare \n into \r\n so that output from the remote
// side renders correctly when the local terminal is in raw mode.
type crlfWriter struct {
	w   io.Writer
	prev byte
}

func (c *crlfWriter) Write(p []byte) (int, error) {
	var buf bytes.Buffer
	for _, b := range p {
		if b == '\n' && c.prev != '\r' {
			buf.WriteByte('\r')
		}
		buf.WriteByte(b)
		c.prev = b
	}
	_, err := c.w.Write(buf.Bytes())
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
