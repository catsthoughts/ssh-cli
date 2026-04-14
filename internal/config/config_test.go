package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePath(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config.json")
	got := resolvePath(base, "./id_key.pub")
	if filepath.Base(got) != "id_key.pub" {
		t.Fatalf("unexpected resolved path: %s", got)
	}
}

func TestLoadWithoutSendEnvStillWorks(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	data := []byte(`{
		"key": {"tag": "tag", "label": "label", "public_key_path": "./id.pub"},
		"proxy": {"address": "127.0.0.1:2222", "user": "tester"},
		"target": {"request_tty": true}
	}`)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Address != "127.0.0.1:2222" {
		t.Fatalf("unexpected proxy address: %q", cfg.Proxy.Address)
	}
}

func TestDefaultConfigPathUsesSSHCLIDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got, err := DefaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".ssh-cli", "config.json")
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestLoadFillsProxyUserFromSystem(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	t.Setenv("USER", "system-user")
	data := []byte(`{
		"key": {"tag": "tag", "label": "label", "public_key_path": "./id.pub"},
		"proxy": {"address": "127.0.0.1:2222", "user": ""}
	}`)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.User != "system-user" {
		t.Fatalf("expected system-user, got %q", cfg.Proxy.User)
	}
}

func TestWriteExampleCreatesParentDirectory(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), ".ssh-cli", "config.json")
	if err := WriteExample(cfgPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}
}
