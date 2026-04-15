package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"ssh-cli/internal/certutil"
	"ssh-cli/internal/config"
	"ssh-cli/internal/keystore"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "init-config":
		return runInitConfig(args[1:])
	case "create-key":
		return runCreateKey(args[1:])
	case "show-public-key":
		return runShowPublicKey(args[1:])
	case "create-cert":
		return runCreateCert(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInitConfig(args []string) error {
	fs := flag.NewFlagSet("init-config", flag.ExitOnError)
	path := fs.String("config", config.MustDefaultConfigPath(), "path to JSON config")
	fs.Parse(args)
	return config.WriteExample(*path)
}

func loadConfig(flagSet *flag.FlagSet, args []string) (config.Config, error) {
	path := flagSet.String("config", config.MustDefaultConfigPath(), "path to JSON config")
	flagSet.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil {
		return config.Config{}, err
	}
	return cfg, cfg.Validate()
}

func runCreateKey(args []string) error {
	fs := flag.NewFlagSet("create-key", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}

	key, created, err := keystore.EnsureKey(cfg.Key)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := keystore.WriteAuthorizedKeyFile(cfg.Key.PublicKeyPath, key.AuthorizedKey()); err != nil {
		return err
	}

	state := "loaded"
	if created {
		state = "created"
	}
	storage := "software"
	if key.IsHardwareBacked() {
		storage = "hardware-backed"
	}
	fmt.Printf("%s non-exportable key in %s: %s\n", state, storage, cfg.Key.Tag)
	fmt.Printf("public key saved to %s\n", cfg.Key.PublicKeyPath)
	fmt.Print(string(key.AuthorizedKey()))
	return nil
}

func runShowPublicKey(args []string) error {
	fs := flag.NewFlagSet("show-public-key", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	key, _, err := keystore.EnsureKey(cfg.Key)
	if err != nil {
		return err
	}
	defer key.Close()
	fmt.Print(string(key.AuthorizedKey()))
	return nil
}

func runCreateCert(args []string) error {
	fs := flag.NewFlagSet("create-cert", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	key, _, err := keystore.EnsureKey(cfg.Key)
	if err != nil {
		return err
	}
	defer key.Close()

	switch strings.ToLower(cfg.Certificate.Type) {
	case "ssh", "ssh-user", "ssh-user-cert":
		path, err := certutil.CreateSSHUserCertificate(cfg, key)
		if err != nil {
			return err
		}
		fmt.Printf("ssh certificate written to %s\n", path)
		return nil
	case "x509", "x509-selfsigned":
		certPath, keyPath, err := certutil.CreateSelfSignedX509(cfg, key)
		if err != nil {
			return err
		}
		fmt.Printf("x509 certificate written to %s\n", certPath)
		if keyPath != "" {
			fmt.Printf("public key written to %s\n", keyPath)
		}
		return nil
	case "csr", "x509-csr":
		path, err := certutil.CreateCSR(cfg, key)
		if err != nil {
			return err
		}
		fmt.Printf("csr written to %s\n", path)
		return nil
	default:
		return errors.New("certificate.type must be one of ssh-user, x509-selfsigned, x509-csr")
	}
}

func printUsage() {
	fmt.Print(`ssh-cli-init - initialization and certificate management for ssh-cli

Commands:
  init-config      Create an example JSON config
  create-key       Create or load a non-exportable key and save the public key
  show-public-key  Show the SSH public key
  create-cert      Create an SSH certificate, X.509 CSR, or self-signed X.509 cert

Examples:
  ssh-cli-init init-config
  ssh-cli-init create-key
  ssh-cli-init show-public-key
  ssh-cli-init create-cert

Default config path:
  ~/.ssh-cli/config.json
`)
}
