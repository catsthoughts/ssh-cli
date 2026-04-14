package main

import (
	"strings"
	"testing"
)

func TestResolveTargetArgPrefersCLIValue(t *testing.T) {
	route, err := resolveTargetArg([]string{"alice@example-host:2222"})
	if err != nil {
		t.Fatal(err)
	}
	if route != "alice@example-host:2222" {
		t.Fatalf("expected CLI route to be preserved, got %q", route)
	}
}

func TestResolveTargetArgAllowsBastionOnlyConnection(t *testing.T) {
	route, err := resolveTargetArg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if route != "" {
		t.Fatalf("expected empty route, got %q", route)
	}
}

func TestInitCommandsAreRedirectedToInitBinary(t *testing.T) {
	for _, arg := range []string{"create-key", "show-public-key", "create-cert", "init-config"} {
		err := run([]string{arg})
		if err == nil || !strings.Contains(err.Error(), "ssh-cli-init") {
			t.Fatalf("expected redirect to ssh-cli-init for %s, got %v", arg, err)
		}
	}
}
