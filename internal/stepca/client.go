package stepca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	caURL       string
	authorityID string
	httpClient  *http.Client
}

type SignOptions struct {
	PublicKey     ssh.PublicKey
	Identity      string
	Principals    []string
	ValidForHours int
}

func NewClient(caURL, authorityID string) *Client {
	return &Client{
		caURL:       strings.TrimSuffix(caURL, "/"),
		authorityID: authorityID,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func NewClientWithCA(caURL, authorityID string, caCertPool *x509.CertPool) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	return &Client{
		caURL:       strings.TrimSuffix(caURL, "/"),
		authorityID: authorityID,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: tr,
		},
	}
}

func NewClientSkipVerify(caURL, authorityID string) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &Client{
		caURL:       strings.TrimSuffix(caURL, "/"),
		authorityID: authorityID,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: tr,
		},
	}
}

func (c *Client) RequestSSHCertificate(ctx context.Context, token string, opts SignOptions) (*ssh.Certificate, error) {
	pubKeyBytes := opts.PublicKey.Marshal()
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	validFor := strconv.Itoa(opts.ValidForHours) + "h0m0s"

	payload := map[string]interface{}{
		"publicKey":   pubKeyBase64,
		"ott":         token,
		"certtype":    "user",
		"keyId":       opts.Identity,
		"principals":  opts.Principals,
		"validFor":    validFor,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.caURL+"/ssh/sign", bytes.NewReader(jsonPayload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("signSSH request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("signSSH failed: %s", string(body))
	}

	var result struct {
		Certificate string `json:"crt"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// step-ca возвращает сырой wire-формат сертификата в base64.
	// Пробуем сначала ParseAuthorizedKey (текстовый authorized_keys формат),
	// если не получается — декодируем base64 и используем ParsePublicKey.
	var sshCert *ssh.Certificate
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(result.Certificate))
	if err == nil {
		var ok bool
		sshCert, ok = pub.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("expected SSH certificate, got %T", pub)
		}
	} else {
		wireBytes, decErr := base64.StdEncoding.DecodeString(result.Certificate)
		if decErr != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		parsedPub, parseErr := ssh.ParsePublicKey(wireBytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse certificate wire format: %w", parseErr)
		}
		var ok bool
		sshCert, ok = parsedPub.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("expected SSH certificate, got %T", parsedPub)
		}
	}

	return sshCert, nil
}
