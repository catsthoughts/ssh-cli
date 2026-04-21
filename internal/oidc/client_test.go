package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	c := NewClient("https://example.com", "client-id", "secret", "")
	if c.providerURL != "https://example.com" {
		t.Errorf("expected provider URL https://example.com, got %s", c.providerURL)
	}
	if c.clientID != "client-id" {
		t.Errorf("expected client ID client-id, got %s", c.clientID)
	}
	if c.scope != "openid profile email" {
		t.Errorf("expected default scope, got %s", c.scope)
	}
}

func TestNewClientWithScope(t *testing.T) {
	c := NewClient("https://example.com", "client-id", "secret", "custom scope")
	if c.scope != "custom scope" {
		t.Errorf("expected custom scope, got %s", c.scope)
	}
}

func TestNewClientTrimsSuffix(t *testing.T) {
	c := NewClient("https://example.com/", "client-id", "secret", "")
	if c.providerURL != "https://example.com" {
		t.Errorf("expected trimmed URL, got %s", c.providerURL)
	}
}

func TestClient_Authenticate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/protocol/openid-connect/auth/device":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(deviceCodeResponse{
				DeviceCode:      "device-code-123",
				UserCode:        "ABCD-1234",
				VerificationURI: "https://example.com/device",
				ExpiresIn:       300,
				Interval:        1,
			})
		case "/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResponse{
				AccessToken: "access-token-123",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		}
	}))
	defer server.Close()

	c := NewClient(server.URL, "client-id", "secret", "")

	token, err := c.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "access-token-123" {
		t.Errorf("expected access token, got %s", token)
	}
}

func TestClient_Authenticate_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(deviceCodeResponse{
			DeviceCode:      "device-code-123",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://example.com/device",
			ExpiresIn:       1,
			Interval:        1,
		})
	}))
	defer server.Close()

	c := NewClient(server.URL, "client-id", "secret", "")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := c.Authenticate(ctx)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestClient_requestDeviceCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protocol/openid-connect/auth/device" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(deviceCodeResponse{
			DeviceCode:      "test-device-code",
			UserCode:        "TEST-CODE",
			VerificationURI: "https://test.com/verify",
			ExpiresIn:       600,
			Interval:        5,
		})
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-client", "test-secret", "openid")
	dc, err := c.requestDeviceCode(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dc.DeviceCode != "test-device-code" {
		t.Errorf("expected device code, got %s", dc.DeviceCode)
	}
	if dc.UserCode != "TEST-CODE" {
		t.Errorf("expected user code, got %s", dc.UserCode)
	}
}

func TestClient_pollForToken_AuthorizationPending(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount < 3 {
			json.NewEncoder(w).Encode(tokenResponse{
				Error:       "authorization_pending",
				ErrorDesc:   "authorization pending",
			})
		} else {
			json.NewEncoder(w).Encode(tokenResponse{
				AccessToken: "final-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		}
	}))
	defer server.Close()

	c := NewClient(server.URL, "client-id", "secret", "")
	token, err := c.pollForToken(context.Background(), "device-code", 1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "final-token" {
		t.Errorf("expected final token, got %s", token)
	}
}

func TestClient_pollForToken_SlowDown(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			json.NewEncoder(w).Encode(tokenResponse{
				Error:     "slow_down",
				ErrorDesc: "polling too fast",
			})
		} else {
			json.NewEncoder(w).Encode(tokenResponse{
				AccessToken: "slow-down-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		}
	}))
	defer server.Close()

	c := NewClient(server.URL, "client-id", "secret", "")
	_, err := c.pollForToken(context.Background(), "device-code", 1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClient_requestToken_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			Error:     "invalid_client",
			ErrorDesc: "client authentication failed",
		})
	}))
	defer server.Close()

	c := NewClient(server.URL, "client-id", "secret", "")
	_, err := c.requestToken(context.Background(), "device-code")
	if err == nil {
		t.Error("expected error for invalid_client")
	}
}
