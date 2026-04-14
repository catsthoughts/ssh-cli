package target

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sshconfig "github.com/kevinburke/ssh_config"
)

func Resolve(destination, sshConfigPath, defaultUser string) (string, error) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return "", fmt.Errorf("destination is required")
	}

	user, host, port := splitDestination(destination)
	if host == "" {
		return "", fmt.Errorf("invalid destination %q", destination)
	}
	alias := host

	cfg, err := loadSSHConfig(sshConfigPath)
	if err == nil && cfg != nil {
		if hostName, err := cfg.Get(alias, "HostName"); err == nil && hostName != "" {
			host = hostName
		}
		if user == "" {
			if configuredUser, err := cfg.Get(alias, "User"); err == nil && configuredUser != "" {
				user = configuredUser
			}
		}
		if port == "" {
			if configuredPort, err := cfg.Get(alias, "Port"); err == nil && configuredPort != "" {
				port = configuredPort
			}
		}
	}

	if user == "" {
		user = strings.TrimSpace(defaultUser)
	}
	if port == "" {
		port = "22"
	}
	if user != "" {
		return fmt.Sprintf("%s@%s:%s", user, host, port), nil
	}
	return fmt.Sprintf("%s:%s", host, port), nil
}

func splitDestination(destination string) (user, host, port string) {
	if at := strings.Index(destination, "@"); at >= 0 {
		user = destination[:at]
		destination = destination[at+1:]
	}
	if colon := strings.LastIndex(destination, ":"); colon >= 0 && !strings.Contains(destination[colon+1:], "/") {
		host = destination[:colon]
		port = destination[colon+1:]
	} else {
		host = destination
	}
	return strings.TrimSpace(user), strings.TrimSpace(host), strings.TrimSpace(port)
}

func loadSSHConfig(path string) (*sshconfig.Config, error) {
	if strings.TrimSpace(path) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".ssh", "config")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return sshconfig.Decode(file)
}
