package certutil

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"ssh-cli/internal/config"
)

// Signer is the subset of keystore.Key needed by certificate operations.
type Signer interface {
	crypto.Signer
	SSHPublicKey() ssh.PublicKey
}

func CreateSSHUserCertificate(cfg config.Config, key Signer) (string, error) {
	if cfg.Certificate.CAKeyPath == "" {
		return "", fmt.Errorf("certificate.ca_key_path is required for ssh-user certificates")
	}
	caPEM, err := os.ReadFile(cfg.Certificate.CAKeyPath)
	if err != nil {
		return "", fmt.Errorf("read ca key: %w", err)
	}
	caSigner, err := ssh.ParsePrivateKey(caPEM)
	if err != nil {
		return "", fmt.Errorf("parse ca key: %w", err)
	}
	validFor, err := time.ParseDuration(cfg.Certificate.ValidFor)
	if err != nil {
		return "", fmt.Errorf("parse certificate.valid_for: %w", err)
	}
	if validFor <= 0 {
		validFor = 8 * time.Hour
	}
	principals := cfg.Certificate.Principals
	if len(principals) == 0 && cfg.Proxy.User != "" {
		principals = []string{cfg.Proxy.User}
	}
	identity := cfg.Certificate.Identity
	if identity == "" {
		identity = cfg.Proxy.User
	}
	cert := &ssh.Certificate{
		Key:             key.SSHPublicKey(),
		Serial:          uint64(time.Now().UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           identity,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(validFor).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return "", fmt.Errorf("sign ssh certificate: %w", err)
	}
	path := cfg.Certificate.OutputPath
	if path == "" {
		path = "./id_secure_enclave-cert.pub"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func CreateCSR(cfg config.Config, key Signer) (string, error) {
	name := cfg.Certificate.SubjectCommonName
	if name == "" {
		name = cfg.Proxy.User
	}
	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return "", fmt.Errorf("create csr: %w", err)
	}
	path := cfg.Certificate.OutputPath
	if path == "" {
		path = "./client.csr"
	}
	block := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func CreateSelfSignedX509(cfg config.Config, key Signer) (string, string, error) {
	name := cfg.Certificate.SubjectCommonName
	if name == "" {
		name = cfg.Proxy.User
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", "", err
	}
	certTpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTpl, certTpl, key.Public(), key)
	if err != nil {
		return "", "", fmt.Errorf("create self-signed certificate: %w", err)
	}
	path := cfg.Certificate.OutputPath
	if path == "" {
		path = "./client.crt"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return path, "", nil
	}
	pubPath := path + ".pub.pem"
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		return path, "", nil
	}
	return path, pubPath, nil
}
