//go:build linux || darwin

package sshclient

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

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

func (c *ctrlCInterceptor) Read(dst []byte) (int, error) {
	n, err := c.r.Read(dst)
	if n > 0 && err == nil {
		for i := 0; i < n; i++ {
			if dst[i] == 0x03 {
				now := time.Now()
				c.mu.Lock()
				prev := c.lastPress
				c.lastPress = now
				c.mu.Unlock()
				if now.Sub(prev) < 1*time.Second {
					fmt.Fprintf(c.stderr, "\r\nDouble Ctrl+C — exiting\r\n")
					syscall.Kill(syscall.Getpid(), syscall.SIGINT)
					return 0, io.EOF
				}
				fmt.Fprintf(c.stderr, "\r\n[Ctrl+C sent to remote — press again within 1s to exit]\r\n")
			}
		}
	}
	return n, err
}
