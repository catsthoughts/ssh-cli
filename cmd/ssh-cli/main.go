package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"ssh-cli/internal/config"
	"ssh-cli/internal/sshclient"
	"ssh-cli/internal/target"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "--help":
			printUsage()
			return nil
		case "init-config", "create-key", "show-public-key", "create-cert":
			return fmt.Errorf("initialization commands were moved to ssh-cli-init; use: ssh-cli-init %s", args[0])
		case "connect":
			return runSSH(args[1:])
		}
	}
	return runSSH(args)
}

func loadConfigFromArgs(args []string) (config.Config, []string, error) {
	fs := flag.NewFlagSet("ssh-cli", flag.ContinueOnError)
	path := fs.String("config", config.MustDefaultConfigPath(), "path to JSON config")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, nil, err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return config.Config{}, nil, err
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, nil, err
	}
	return cfg, fs.Args(), nil
}

func runSSH(args []string) error {
	cfg, positional, err := loadConfigFromArgs(args)
	if err != nil {
		return err
	}
	rawRoute, err := resolveTargetArg(positional)
	if err != nil {
		return err
	}
	route := ""
	if rawRoute != "" {
		route, err = target.Resolve(rawRoute, "", cfg.Proxy.User)
		if err != nil {
			return err
		}
	}
	return sshclient.Connect(cfg, route)
}

func resolveTargetArg(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	if strings.TrimSpace(args[0]) == "" {
		return "", nil
	}
	return strings.TrimSpace(args[0]), nil
}

func printUsage() {
	fmt.Print(`ssh-cli - SSH-style client for macOS non-exportable keys

Usage:
  ssh-cli [options] [destination]

Examples:
  ssh-cli
  ssh-cli prod-host
  ssh-cli your-user@prod-host:22
  ssh-cli -config ~/.ssh-cli/config.json

Initialization:
  ssh-cli-init init-config
  ssh-cli-init create-key
  ssh-cli-init create-cert

Default config path:
  ~/.ssh-cli/config.json
`)
}
