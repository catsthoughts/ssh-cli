package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

type Config struct {
	Profile     string            `json:"profile"`
	Key         KeyConfig         `json:"key"`
	Proxy       ProxyConfig       `json:"proxy"`
	Target      TargetConfig      `json:"target"`
	Certificate CertificateConfig `json:"certificate"`
}

type KeyConfig struct {
	Tag           string `json:"tag"`
	Label         string `json:"label"`
	Comment       string `json:"comment"`
	SecureEnclave bool   `json:"secure_enclave"`
	PublicKeyPath string `json:"public_key_path"`
}

type ProxyConfig struct {
	Address               string `json:"address"`
	User                  string `json:"user"`
	KnownHosts            string `json:"known_hosts"`
	HostKeyPolicy         string `json:"host_key_policy"`
	InsecureIgnoreHostKey bool   `json:"insecure_ignore_hostkey"`
	UseAgentForwarding    bool   `json:"use_agent_forwarding"`
	ConnectTimeoutSeconds int    `json:"connect_timeout_seconds"`
}

type TargetConfig struct {
	Command    string `json:"command"`
	RequestTTY bool   `json:"request_tty"`
}

type CertificateConfig struct {
	Type              string   `json:"type"`
	CAKeyPath         string   `json:"ca_key_path"`
	OutputPath        string   `json:"output_path"`
	AuthCertPath      string   `json:"auth_cert_path"`
	Identity          string   `json:"identity"`
	Principals        []string `json:"principals"`
	ValidFor          string   `json:"valid_for"`
	SubjectCommonName string   `json:"subject_common_name"`
}

func Default() Config {
	currentUser := currentUsername()
	return Config{
		Profile: "default",
		Key: KeyConfig{
			Tag:           "com.example.sshcli.default",
			Label:         "SSH CLI Default",
			Comment:       "secure-enclave@mac",
			SecureEnclave: true,
			PublicKeyPath: "./id_secure_enclave.pub",
		},
		Proxy: ProxyConfig{
			Address:               "127.0.0.1:2222",
			User:                  currentUser,
			KnownHosts:            "~/.ssh/known_hosts",
			HostKeyPolicy:         "accept-new",
			UseAgentForwarding:    true,
			ConnectTimeoutSeconds: 10,
		},
		Target: TargetConfig{
			RequestTTY: true,
		},
		Certificate: CertificateConfig{
			Type:              "ssh-user",
			OutputPath:        "./id_secure_enclave-cert.pub",
			Identity:          currentUser,
			Principals:        []string{currentUser},
			ValidFor:          "8h",
			SubjectCommonName: currentUser,
		},
	}
}

func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".ssh-cli", "config.json"), nil
}

func MustDefaultConfigPath() string {
	path, err := DefaultConfigPath()
	if err != nil {
		return "config.json"
	}
	return path
}

func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse json config: %w", err)
	}
	cfg.normalize(path)
	return cfg, nil
}

func (c *Config) normalize(basePath string) {
	c.Key.PublicKeyPath = resolvePath(basePath, c.Key.PublicKeyPath)
	c.Proxy.KnownHosts = resolvePath(basePath, c.Proxy.KnownHosts)
	c.Certificate.CAKeyPath = resolvePath(basePath, c.Certificate.CAKeyPath)
	c.Certificate.OutputPath = resolvePath(basePath, c.Certificate.OutputPath)
	c.Certificate.AuthCertPath = resolvePath(basePath, c.Certificate.AuthCertPath)

	if strings.TrimSpace(c.Proxy.User) == "" {
		c.Proxy.User = currentUsername()
	}
	if strings.TrimSpace(c.Proxy.HostKeyPolicy) == "" {
		c.Proxy.HostKeyPolicy = "accept-new"
	}
	if c.Proxy.ConnectTimeoutSeconds <= 0 {
		c.Proxy.ConnectTimeoutSeconds = 10
	}
}

func currentUsername() string {
	if name := strings.TrimSpace(os.Getenv("USER")); name != "" {
		return name
	}
	if u, err := user.Current(); err == nil {
		if name := strings.TrimSpace(u.Username); name != "" {
			return name
		}
	}
	return ""
}

func (c Config) Validate() error {
	if c.Key.Tag == "" {
		return errors.New("key.tag is required")
	}
	if c.Key.Label == "" {
		return errors.New("key.label is required")
	}
	if c.Key.PublicKeyPath == "" {
		return errors.New("key.public_key_path is required")
	}
	return nil
}

func WriteExample(path string) error {
	cfg := Default()
	cfg.normalize(path)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return nil
}

func resolvePath(basePath, value string) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	value = os.ExpandEnv(value)
	if filepath.IsAbs(value) {
		return value
	}
	baseDir := filepath.Dir(basePath)
	if baseDir == "." || baseDir == "" {
		wd, err := os.Getwd()
		if err == nil {
			baseDir = wd
		}
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}
