package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"ssh-cli/internal/certutil"
	"ssh-cli/internal/config"
	"ssh-cli/internal/keychain"
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
	case "use-profile":
		return runUseProfile(args[1:])
	case "list-profiles":
		return runListProfiles(args[1:])
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
	force := fs.Bool("force", false, "overwrite existing config without prompting")
	fs.Parse(args)

	if !*force {
		if _, err := os.Stat(*path); err == nil {
			fmt.Fprintf(os.Stderr, "config already exists at %s\noverwrite? [y/N] ", *path)
			var answer string
			fmt.Fscan(os.Stdin, &answer)
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stderr, "aborted")
				return nil
			}
		}
	}

	if err := config.WriteExample(*path); err != nil {
		return err
	}
	fmt.Printf("config written to %s\n", *path)
	return nil
}

func loadConfig(flagSet *flag.FlagSet, args []string) (config.Config, error) {
	path := flagSet.String("config", config.MustDefaultConfigPath(), "path to JSON config")
	profile := flagSet.String("profile", "", "profile name (for multi-profile configs)")
	flagSet.Parse(args)
	cfg, err := config.LoadProfile(*path, *profile)
	if err != nil {
		return config.Config{}, err
	}
	return cfg, cfg.Validate()
}

func runUseProfile(args []string) error {
	fs := flag.NewFlagSet("use-profile", flag.ExitOnError)
	configPath := fs.String("config", config.MustDefaultConfigPath(), "path to JSON config")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: use-profile [-config path] <profile-name>")
	}
	name := fs.Arg(0)
	if err := config.SetActiveProfile(*configPath, name); err != nil {
		return err
	}
	fmt.Printf("active profile set to %q\n", name)
	return nil
}

func runListProfiles(args []string) error {
	fs := flag.NewFlagSet("list-profiles", flag.ExitOnError)
	configPath := fs.String("config", config.MustDefaultConfigPath(), "path to JSON config")
	fs.Parse(args)
	names, active, err := config.ListProfiles(*configPath)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == active {
			fmt.Printf("* %s\n", name)
		} else {
			fmt.Printf("  %s\n", name)
		}
	}
	return nil
}

func runCreateKey(args []string) error {
	fs := flag.NewFlagSet("create-key", flag.ExitOnError)
	force := fs.Bool("force", false, "delete existing key and create a new one")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}

	var key *keychain.Key
	var created bool

	if *force {
		fmt.Fprintf(os.Stderr, "this will permanently delete the existing key %q\nare you sure? [y/N] ", cfg.Key.Tag)
		var answer string
		fmt.Fscan(os.Stdin, &answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Fprintln(os.Stderr, "aborted")
			return nil
		}
		key, err = keychain.ForceCreateKey(cfg.Key)
		created = true
	} else {
		key, created, err = keychain.EnsureKey(cfg.Key)
	}
	if err != nil {
		return err
	}
	defer key.Close()

	if err := keychain.WriteAuthorizedKeyFile(cfg.Key.PublicKeyPath, key.AuthorizedKey()); err != nil {
		return err
	}

	state := "loaded"
	if created {
		state = "created"
	}
	var storage string
	switch cfg.Key.KeySource {
	case "yubikey_piv":
		storage = fmt.Sprintf("YubiKey PIV slot %s", cfg.Key.YubiKey.Slot)
	case "secure_enclave":
		storage = "Secure Enclave"
	default:
		if key.IsSecureEnclave() {
			storage = "Secure Enclave"
		} else {
			storage = "macOS Keychain"
		}
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
	key, _, err := keychain.EnsureKey(cfg.Key)
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
	key, _, err := keychain.EnsureKey(cfg.Key)
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
  init-config      Create an example JSON config (multi-profile format); prompts before overwriting
  list-profiles    List profiles in the config, marking the active one with *
  use-profile      Set the active profile
  create-key       Create or load a non-exportable key and save the public key; use -force to replace existing
  show-public-key  Show the SSH public key
  create-cert      Create an SSH certificate, X.509 CSR, or self-signed X.509 cert

Flags (for create-key, show-public-key, create-cert):
  -config   path to JSON config (default: ~/.ssh-cli/config.json)
  -profile  profile name in multi-profile config (default: active_profile)

Examples:
  ssh-cli-init init-config
  ssh-cli-init init-config -force
  ssh-cli-init list-profiles
  ssh-cli-init use-profile staging
  ssh-cli-init create-key
  ssh-cli-init create-key -force
  ssh-cli-init create-key -profile staging
  ssh-cli-init show-public-key -profile prod
  ssh-cli-init create-cert -profile prod

Default config path:
  ~/.ssh-cli/config.json
`)
}
