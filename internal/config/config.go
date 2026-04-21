package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
)

type Config struct {
	Profile     string            `json:"profile,omitempty"`
	Key         KeyConfig         `json:"key"`
	Proxy       ProxyConfig       `json:"proxy"`
	Target      TargetConfig      `json:"target"`
	Certificate CertificateConfig `json:"certificate"`
}

type KeyConfig struct {
	Tag           string        `json:"tag"`
	Label         string        `json:"label"`
	Comment       string        `json:"comment,omitempty"`
	SecureEnclave bool          `json:"secure_enclave,omitempty"` // deprecated: use KeySource="secure_enclave"
	PublicKeyPath string        `json:"public_key_path"`
	KeySource     string        `json:"key_source,omitempty"` // "secure_enclave", "yubikey_piv"
	YubiKey       YubiKeyConfig `json:"yubikey,omitempty"`
}

type YubiKeyConfig struct {
	Slot       string `json:"slot,omitempty"`        // PIV slot: "9a", "9c", "9d", "9e"
	PIN        string `json:"pin,omitempty"`         // optional PIN
	PKCS11Path string `json:"pkcs11_path,omitempty"` // path to PC/SC library (Linux only)
}

func (y YubiKeyConfig) isEmpty() bool {
	return y.Slot == "" && y.PIN == "" && y.PKCS11Path == ""
}

// MarshalJSON omits the yubikey field entirely when it is empty.
func (k KeyConfig) MarshalJSON() ([]byte, error) {
	type Alias KeyConfig
	if k.YubiKey.isEmpty() {
		type KeyConfigNoYubiKey struct {
			Tag           string `json:"tag"`
			Label         string `json:"label"`
			Comment       string `json:"comment,omitempty"`
			SecureEnclave bool   `json:"secure_enclave,omitempty"`
			PublicKeyPath string `json:"public_key_path"`
			KeySource     string `json:"key_source,omitempty"`
		}
		return json.Marshal(KeyConfigNoYubiKey{
			Tag:           k.Tag,
			Label:         k.Label,
			Comment:       k.Comment,
			SecureEnclave: k.SecureEnclave,
			PublicKeyPath: k.PublicKeyPath,
			KeySource:     k.KeySource,
		})
	}
	return json.Marshal(Alias(k))
}

type ProxyConfig struct {
	UseProxy              bool      `json:"use_proxy"`
	Address               Addresses `json:"address"`
	User                  string    `json:"user"`
	KnownHosts            string    `json:"known_hosts"`
	HostKeyPolicy         string    `json:"host_key_policy"`
	InsecureIgnoreHostKey bool      `json:"insecure_ignore_hostkey"`
	UseAgentForwarding    bool      `json:"use_agent_forwarding"`
	ConnectTimeoutSeconds int       `json:"connect_timeout_seconds"`
	BalanceMode           string    `json:"balance_mode,omitempty"`
	RetryAttempts         int       `json:"retry_attempts,omitempty"`
	RetryDelaySeconds     int       `json:"retry_delay_seconds,omitempty"`
}

// Addresses is a JSON type that accepts either a single string or an array of strings.
type Addresses []string

func (a *Addresses) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Addresses{single}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("address must be a string or array of strings")
	}
	*a = list
	return nil
}

func (a Addresses) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

type TargetConfig struct {
	Command      string `json:"command"`
	RequestTTY   bool   `json:"request_tty"`
	ForwardCtrlC bool   `json:"forward_ctrl_c"`
}

type CertificateConfig struct {
	Type               string        `json:"type"`
	CAKeyPath          string        `json:"ca_key_path"`
	OutputPath         string        `json:"output_path"`
	AuthCertPath       string        `json:"auth_cert_path"`
	Identity           string        `json:"identity"`
	Principals         []string      `json:"principals"`
	ValidFor           string        `json:"valid_for"`
	SubjectCommonName  string        `json:"subject_common_name"`
	StepCA             StepCAConfig  `json:"step_ca,omitempty"`
	OIDC               OIDCConfig    `json:"oidc,omitempty"`
	CertRefreshBefore  string        `json:"cert_refresh_before,omitempty"`
}

type StepCAConfig struct {
	AuthorityID string `json:"authority_id"`
	CAURL       string `json:"ca_url"`
}

type OIDCConfig struct {
	ProviderURL  string `json:"provider_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
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
			UseProxy:              true,
			Address:               Addresses{"127.0.0.1:2222"},
			User:                  currentUser,
			KnownHosts:            "~/.ssh/known_hosts",
			HostKeyPolicy:         "accept-new",
			UseAgentForwarding:    true,
			ConnectTimeoutSeconds: 10,
		},
		Target: TargetConfig{
			RequestTTY:   true,
			ForwardCtrlC: false,
		},
		Certificate: CertificateConfig{
			Type:              "ssh-user",
			OutputPath:        "./id_secure_enclave-cert.pub",
			Identity:          currentUser,
			Principals:        []string{currentUser},
			ValidFor:          "8h",
			SubjectCommonName: currentUser,
			CertRefreshBefore: "1h",
			OIDC: OIDCConfig{
				Scope: "openid profile email",
			},
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

// ConfigFile is the top-level JSON structure supporting multi-profile format.
type ConfigFile struct {
	Profiles      map[string]Config `json:"profiles,omitempty"`
	ActiveProfile string            `json:"active_profile,omitempty"`
}

// Load reads the config file and returns the active profile.
// Supports both flat (legacy) format and multi-profile format.
func Load(path string) (Config, error) {
	return LoadProfile(path, "")
}

// LoadProfile reads the config file and returns the named profile.
// If profile is empty, uses active_profile from the file, or the first profile.
// Falls back to flat format if no "profiles" key is present.
func LoadProfile(path, profile string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	// Try multi-profile format first.
	var file ConfigFile
	if err := json.Unmarshal(data, &file); err != nil {
		return Config{}, fmt.Errorf("parse json config: %w", err)
	}

	if len(file.Profiles) > 0 {
		name := profile
		if name == "" {
			name = file.ActiveProfile
		}
		if name == "" {
			// Pick first profile alphabetically for determinism.
			for k := range file.Profiles {
				if name == "" || k < name {
					name = k
				}
			}
		}
		cfg, ok := file.Profiles[name]
		if !ok {
			return Config{}, fmt.Errorf("profile %q not found", name)
		}
		cfg.Profile = name
		cfg.normalize(path)
		return cfg, nil
	}

	// Fall back to flat (legacy) format.
	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse json config: %w", err)
	}
	cfg.normalize(path)
	return cfg, nil
}

// ResolvedProxies returns one entry per address in proxy.address,
// each carrying the shared proxy settings.
func (c Config) ResolvedProxies() []SingleProxy {
	var out []SingleProxy
	for _, addr := range c.Proxy.Address {
		if strings.TrimSpace(addr) == "" {
			continue
		}
		out = append(out, SingleProxy{
			Address:               addr,
			User:                  c.Proxy.User,
			KnownHosts:            c.Proxy.KnownHosts,
			HostKeyPolicy:         c.Proxy.HostKeyPolicy,
			InsecureIgnoreHostKey: c.Proxy.InsecureIgnoreHostKey,
			UseAgentForwarding:    c.Proxy.UseAgentForwarding,
			ConnectTimeoutSeconds: c.Proxy.ConnectTimeoutSeconds,
		})
	}
	return out
}

// SingleProxy holds a resolved proxy with a single address.
type SingleProxy struct {
	Address               string
	User                  string
	KnownHosts            string
	HostKeyPolicy         string
	InsecureIgnoreHostKey bool
	UseAgentForwarding    bool
	ConnectTimeoutSeconds int
}

func hasNonEmptyAddress(addrs Addresses) bool {
	for _, a := range addrs {
		if strings.TrimSpace(a) != "" {
			return true
		}
	}
	return false
}

func (c *Config) normalize(basePath string) {
	c.Key.PublicKeyPath = resolvePath(basePath, c.Key.PublicKeyPath)
	c.Certificate.CAKeyPath = resolvePath(basePath, c.Certificate.CAKeyPath)
	c.Certificate.OutputPath = resolvePath(basePath, c.Certificate.OutputPath)
	c.Certificate.AuthCertPath = resolvePath(basePath, c.Certificate.AuthCertPath)

	c.Proxy.KnownHosts = resolvePath(basePath, c.Proxy.KnownHosts)
	if hasNonEmptyAddress(c.Proxy.Address) && !c.Proxy.UseProxy {
		c.Proxy.UseProxy = true
	}
	if strings.TrimSpace(c.Proxy.User) == "" {
		c.Proxy.User = currentUsername()
	}
	if strings.TrimSpace(c.Proxy.HostKeyPolicy) == "" {
		c.Proxy.HostKeyPolicy = "accept-new"
	}
	if c.Proxy.ConnectTimeoutSeconds <= 0 {
		c.Proxy.ConnectTimeoutSeconds = 10
	}

	if strings.TrimSpace(c.Proxy.BalanceMode) == "" {
		c.Proxy.BalanceMode = "failover"
	}
	if c.Proxy.RetryAttempts <= 0 {
		c.Proxy.RetryAttempts = 1
	}
	if c.Proxy.RetryDelaySeconds < 0 {
		c.Proxy.RetryDelaySeconds = 0
	}

	// Derive KeySource from legacy SecureEnclave flag for backward compatibility
	if c.Key.KeySource == "" {
		if c.Key.SecureEnclave {
			c.Key.KeySource = "secure_enclave"
		}
	}
	// YubiKey defaults
	if c.Key.KeySource == "yubikey_piv" && c.Key.YubiKey.Slot == "" {
		c.Key.YubiKey.Slot = "9a"
	}
	// OIDC defaults
	if strings.TrimSpace(c.Certificate.OIDC.Scope) == "" {
		c.Certificate.OIDC.Scope = "openid profile email"
	}
	if strings.TrimSpace(c.Certificate.CertRefreshBefore) == "" {
		c.Certificate.CertRefreshBefore = "1h"
	}
}

func normalizeProxy(p *ProxyConfig, basePath string) {
	p.KnownHosts = resolvePath(basePath, p.KnownHosts)
	if strings.TrimSpace(p.User) == "" {
		p.User = currentUsername()
	}
	if strings.TrimSpace(p.HostKeyPolicy) == "" {
		p.HostKeyPolicy = "accept-new"
	}
	if p.ConnectTimeoutSeconds <= 0 {
		p.ConnectTimeoutSeconds = 10
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
	if c.Proxy.UseProxy && len(c.Proxy.Address) == 0 {
		return errors.New("proxy.address is required when proxy is enabled")
	}
	return nil
}

func WriteExample(path string) error {
	currentUser := currentUsername()
	file := ConfigFile{
		ActiveProfile: "prod-se",
		Profiles: map[string]Config{
			"prod-se": {
				Key: KeyConfig{
					Tag:           "com.example.sshcli.prod",
					Label:         "Production Key (Secure Enclave)",
					Comment:       "prod@mac",
					KeySource:     "secure_enclave",
					PublicKeyPath: "~/.ssh-cli/id_prod.pub",
				},
				Proxy: ProxyConfig{
					UseProxy:              true,
					Address:               Addresses{"proxy.example.com:2222"},
					User:                  currentUser,
					KnownHosts:            "~/.ssh/known_hosts",
					HostKeyPolicy:         "accept-new",
					UseAgentForwarding:    true,
					ConnectTimeoutSeconds: 10,
					BalanceMode:           "failover",
					RetryAttempts:         1,
					RetryDelaySeconds:     5,
				},
				Target: TargetConfig{
					RequestTTY:   true,
					ForwardCtrlC: false,
				},
				Certificate: CertificateConfig{
					Type:              "ssh-user",
					OutputPath:        "~/.ssh-cli/id_prod-cert.pub",
					Identity:          currentUser,
					Principals:        []string{currentUser},
					ValidFor:          "8h",
					SubjectCommonName: currentUser,
				},
			},
			"prod-yubikey": {
				Key: KeyConfig{
					Tag:           "com.example.sshcli.prod",
					Label:         "Production Key (YubiKey)",
					Comment:       "prod@mac",
					KeySource:     "yubikey_piv",
					PublicKeyPath: "~/.ssh-cli/id_prod.pub",
					YubiKey:       YubiKeyConfig{Slot: "9a"},
				},
				Proxy: ProxyConfig{
					UseProxy:              true,
					Address:               Addresses{"proxy.example.com:2222"},
					User:                  currentUser,
					KnownHosts:            "~/.ssh/known_hosts",
					HostKeyPolicy:         "accept-new",
					UseAgentForwarding:    true,
					ConnectTimeoutSeconds: 10,
					BalanceMode:           "failover",
					RetryAttempts:         1,
					RetryDelaySeconds:     5,
				},
				Target: TargetConfig{
					RequestTTY:   true,
					ForwardCtrlC: false,
				},
				Certificate: CertificateConfig{
					Type:              "ssh-user",
					OutputPath:        "~/.ssh-cli/id_prod-cert.pub",
					Identity:          currentUser,
					Principals:        []string{currentUser},
					ValidFor:          "8h",
					SubjectCommonName: currentUser,
				},
			},
			"staging": {
				Key: KeyConfig{
					Tag:           "com.example.sshcli.staging",
					Label:         "Staging Key",
					Comment:       "staging@mac",
					KeySource:     "yubikey_piv",
					PublicKeyPath: "~/.ssh-cli/id_staging.pub",
					YubiKey:       YubiKeyConfig{Slot: "9a"},
				},
				Proxy: ProxyConfig{
					UseProxy:              true,
					Address:               Addresses{"proxy-staging.example.com:2222"},
					User:                  currentUser,
					KnownHosts:            "~/.ssh/known_hosts",
					HostKeyPolicy:         "accept-new",
					UseAgentForwarding:    true,
					ConnectTimeoutSeconds: 10,
					BalanceMode:           "failover",
					RetryAttempts:         1,
					RetryDelaySeconds:     5,
				},
				Target: TargetConfig{
					RequestTTY:   true,
					ForwardCtrlC: false,
				},
				Certificate: CertificateConfig{
					Type:              "ssh-user",
					OutputPath:        "~/.ssh-cli/id_staging-cert.pub",
					Identity:          currentUser,
					Principals:        []string{currentUser},
					ValidFor:          "8h",
					SubjectCommonName: currentUser,
				},
			},
			"dev-se": {
				Key: KeyConfig{
					Tag:           "com.example.sshcli.dev",
					Label:         "Dev Key (Secure Enclave)",
					Comment:       "dev@mac",
					KeySource:     "secure_enclave",
					PublicKeyPath: "~/.ssh-cli/id_dev.pub",
				},
				Proxy: ProxyConfig{
					UseProxy:              true,
					Address:               Addresses{"proxy-dev.example.com:2222"},
					User:                  currentUser,
					KnownHosts:            "~/.ssh/known_hosts",
					HostKeyPolicy:         "accept-new",
					UseAgentForwarding:    false,
					ConnectTimeoutSeconds: 5,
				},
				Target: TargetConfig{
					RequestTTY:   true,
					ForwardCtrlC: false,
				},
				Certificate: CertificateConfig{
					Type:              "ssh-user",
					OutputPath:        "~/.ssh-cli/id_dev-cert.pub",
					Identity:          currentUser,
					Principals:        []string{currentUser},
					ValidFor:          "24h",
					SubjectCommonName: currentUser,
				},
			},
			"direct-se": {
				Key: KeyConfig{
					Tag:           "com.example.sshcli.direct",
					Label:         "Direct Connection Key (Secure Enclave)",
					Comment:       "direct@mac",
					KeySource:     "secure_enclave",
					PublicKeyPath: "~/.ssh-cli/id_direct.pub",
				},
				Proxy: ProxyConfig{
					UseProxy:              false,
					User:                  currentUser,
					KnownHosts:            "~/.ssh/known_hosts",
					HostKeyPolicy:         "accept-new",
					UseAgentForwarding:    false,
					ConnectTimeoutSeconds: 10,
				},
				Target: TargetConfig{
					RequestTTY:   true,
					ForwardCtrlC: false,
				},
				Certificate: CertificateConfig{
					Type:              "ssh-user",
					OutputPath:        "~/.ssh-cli/id_direct-cert.pub",
					Identity:          currentUser,
					Principals:        []string{currentUser},
					ValidFor:          "8h",
					SubjectCommonName: currentUser,
				},
			},
			"direct-yubikey": {
				Key: KeyConfig{
					Tag:           "com.example.sshcli.direct",
					Label:         "Direct Connection Key (YubiKey)",
					Comment:       "direct@yubikey",
					KeySource:     "yubikey_piv",
					PublicKeyPath: "~/.ssh-cli/id_direct.pub",
					YubiKey:       YubiKeyConfig{Slot: "9a"},
				},
				Proxy: ProxyConfig{
					UseProxy:              false,
					User:                  currentUser,
					KnownHosts:            "~/.ssh/known_hosts",
					HostKeyPolicy:         "accept-new",
					UseAgentForwarding:    false,
					ConnectTimeoutSeconds: 10,
				},
				Target: TargetConfig{
					RequestTTY:   true,
					ForwardCtrlC: false,
				},
				Certificate: CertificateConfig{
					Type:              "ssh-user",
					OutputPath:        "~/.ssh-cli/id_direct-cert.pub",
					Identity:          currentUser,
					Principals:        []string{currentUser},
					ValidFor:          "8h",
					SubjectCommonName: currentUser,
				},
			},
		},
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// ListProfiles returns the profile names from a multi-profile config file.
// Returns an error if the file is not in multi-profile format.
func ListProfiles(path string) (names []string, active string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read config: %w", err)
	}
	var file ConfigFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, "", fmt.Errorf("parse json config: %w", err)
	}
	if len(file.Profiles) == 0 {
		return nil, "", errors.New("config is not in multi-profile format")
	}
	for name := range file.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, file.ActiveProfile, nil
}

// SetActiveProfile updates active_profile in a multi-profile config file.
func SetActiveProfile(path, profile string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var file ConfigFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse json config: %w", err)
	}
	if len(file.Profiles) == 0 {
		return errors.New("config is not in multi-profile format")
	}
	if _, ok := file.Profiles[profile]; !ok {
		return fmt.Errorf("profile %q not found", profile)
	}
	file.ActiveProfile = profile
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
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
