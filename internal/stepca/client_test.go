package stepca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func ecdsaPublicKey(t *testing.T) ssh.PublicKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}
	return pub
}

func rsaPrivateKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func createSignedCert(t *testing.T, pubKey ssh.PublicKey, keyId string, principals []string, validFor time.Duration) []byte {
	rsaKey := rsaPrivateKey(t)

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	validAfter := uint64(time.Now().Add(-1 * time.Minute).Unix())
	validBefore := uint64(time.Now().Add(validFor).Unix())

	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          uint64(time.Now().UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           keyId,
		ValidPrincipals: principals,
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	return ssh.MarshalAuthorizedKey(cert)
}

func TestNewClient(t *testing.T) {
	c := NewClient("https://ca.example.com", "oidc-provisioner")
	if c.caURL != "https://ca.example.com" {
		t.Errorf("expected CA URL https://ca.example.com, got %s", c.caURL)
	}
	if c.authorityID != "oidc-provisioner" {
		t.Errorf("expected authority ID, got %s", c.authorityID)
	}
}

func TestNewClientTrimsSuffix(t *testing.T) {
	c := NewClient("https://ca.example.com/", "prov")
	if c.caURL != "https://ca.example.com" {
		t.Errorf("expected trimmed URL, got %s", c.caURL)
	}
}

func TestClient_RequestSSHCertificate_Success(t *testing.T) {
	var capturedBody map[string]interface{}
	var capturedAuthHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ssh/sign" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		capturedAuthHeader = r.Header.Get("Authorization")

		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Errorf("decode body: %v", err)
		}

		pubKey := ecdsaPublicKey(t)
		certBytes := createSignedCert(t, pubKey, "test-user", []string{"testuser"}, 8*time.Hour)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"crt": string(certBytes)})
	}))
	defer server.Close()

	c := NewClient(server.URL, "oidc-provisioner")
	pubKey := ecdsaPublicKey(t)

	cert, err := c.RequestSSHCertificate(context.Background(), "test-token", SignOptions{
		PublicKey:     pubKey,
		Identity:      "test-user",
		Principals:    []string{"testuser"},
		ValidForHours: 8,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cert == nil {
		t.Fatal("expected certificate")
	}

	if cert.KeyId != "test-user" {
		t.Errorf("expected key ID test-user, got %s", cert.KeyId)
	}

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "testuser" {
		t.Errorf("expected principal testuser, got %v", cert.ValidPrincipals)
	}

	if capturedAuthHeader != "Bearer test-token" {
		t.Errorf("expected Authorization: Bearer test-token, got %s", capturedAuthHeader)
	}
	if capturedBody["ott"] != "test-token" {
		t.Errorf("expected ott=test-token, got %v", capturedBody["ott"])
	}
	if capturedBody["certtype"] != "user" {
		t.Errorf("expected certtype=user, got %v", capturedBody["certtype"])
	}
	if capturedBody["keyId"] != "test-user" {
		t.Errorf("expected keyId=test-user, got %v", capturedBody["keyId"])
	}
	if capturedBody["validFor"] != "8h0m0s" {
		t.Errorf("expected validFor=8h0m0s, got %v", capturedBody["validFor"])
	}
}

func TestClient_RequestSSHCertificate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	c := NewClient(server.URL, "prov")
	pubKey := ecdsaPublicKey(t)

	_, err := c.RequestSSHCertificate(context.Background(), "token", SignOptions{
		PublicKey:     pubKey,
		Identity:      "user",
		Principals:    []string{"user"},
		ValidForHours: 8,
	})
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestClient_RequestSSHCertificate_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not a valid ssh certificate"))
	}))
	defer server.Close()

	c := NewClient(server.URL, "prov")
	pubKey := ecdsaPublicKey(t)

	_, err := c.RequestSSHCertificate(context.Background(), "token", SignOptions{
		PublicKey:     pubKey,
		Identity:      "user",
		Principals:    []string{"user"},
		ValidForHours: 8,
	})
	if err == nil {
		t.Error("expected error for invalid cert")
	}
}

func TestClient_RequestSSHCertificate_MultiplePrincipals(t *testing.T) {
	var capturedBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		pubKey := ecdsaPublicKey(t)
		certBytes := createSignedCert(t, pubKey, "admin", []string{"admin", "root", "web"}, 24*time.Hour)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"crt": string(certBytes)})
	}))
	defer server.Close()

	c := NewClient(server.URL, "prov")
	pubKey := ecdsaPublicKey(t)

	cert, err := c.RequestSSHCertificate(context.Background(), "token", SignOptions{
		PublicKey:     pubKey,
		Identity:      "admin",
		Principals:    []string{"admin", "root", "web"},
		ValidForHours: 24,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// principals is sent as a JSON array
	principals, ok := capturedBody["principals"].([]interface{})
	if !ok || len(principals) != 3 {
		t.Errorf("expected 3 principals in request body, got %v", capturedBody["principals"])
	}

	if len(cert.ValidPrincipals) != 3 {
		t.Errorf("expected 3 principals in cert, got %d", len(cert.ValidPrincipals))
	}
}

func TestSignOptions_Defaults(t *testing.T) {
	c := NewClient("https://ca.example.com", "prov")
	if c.caURL == "" {
		t.Error("caURL should not be empty")
	}
	if c.authorityID == "" {
		t.Error("authorityID should not be empty")
	}
}

func TestClient_RequestSSHCertificate_WithX509Certificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pubKey := ecdsaPublicKey(t)
		certBytes := createSignedCert(t, pubKey, "user", []string{"user"}, 8*time.Hour)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"crt": string(certBytes)})
	}))
	defer server.Close()

	c := NewClient(server.URL, "prov")
	pubKey := ecdsaPublicKey(t)

	cert, err := c.RequestSSHCertificate(context.Background(), "token", SignOptions{
		PublicKey:     pubKey,
		Identity:      "user",
		Principals:    []string{"user"},
		ValidForHours: 8,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("expected user cert type, got %v", cert.CertType)
	}
}

func getRSAPEMPrivateKey(t *testing.T) []byte {
	key := rsaPrivateKey(t)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(block)
}
