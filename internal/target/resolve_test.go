package target

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDestinationUsesSSHConfigAlias(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssh_config")
	content := []byte("Host r\n  HostName real.example.com\n  User deploy\n  Port 2222\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	route, err := Resolve("r", cfgPath, "localuser")
	if err != nil {
		t.Fatal(err)
	}
	if route != "deploy@real.example.com:2222" {
		t.Fatalf("unexpected route: %s", route)
	}
}

func TestResolveDestinationFallsBackToSystemUser(t *testing.T) {
	route, err := Resolve("host.internal", "", "localuser")
	if err != nil {
		t.Fatal(err)
	}
	if route != "localuser@host.internal:22" {
		t.Fatalf("unexpected route: %s", route)
	}
}
