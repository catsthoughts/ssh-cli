//go:build windows

package sshclient

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const resizePollInterval = 250 * time.Millisecond

func watchTerminalResize(session *ssh.Session, fd int) func() {
	stop := make(chan struct{})
	go func() {
		w, h, _ := term.GetSize(fd)
		ticker := time.NewTicker(resizePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				nw, nh, err := term.GetSize(fd)
				if err == nil && (nw != w || nh != h) {
					w, h = nw, nh
					_ = session.WindowChange(h, w)
				}
			}
		}
	}()
	return func() { close(stop) }
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
					fmt.Fprintf(os.Stderr, "\r\n")
					os.Exit(1)
				}
				fmt.Fprintf(c.stderr, "\r\n[Ctrl+C sent to remote — press again within 1s to exit]\r\n")
			}
		}
	}
	return n, err
}
