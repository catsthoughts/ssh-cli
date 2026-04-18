//go:build !linux && !darwin && !windows

package sshclient

import (
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func watchTerminalResize(session *ssh.Session, fd int) func() {
	return func() {}
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
					os.Exit(1)
				}
			}
		}
	}
	return n, err
}
