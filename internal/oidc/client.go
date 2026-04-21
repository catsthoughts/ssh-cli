package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	providerURL  string
	clientID    string
	clientSecret string
	scope        string
	httpClient   *http.Client
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

type authCodeResponse struct {
	code  string
	state string
	err   error
}

func NewClient(providerURL, clientID, clientSecret, scope string) *Client {
	if scope == "" {
		scope = "openid profile email"
	}
	return &Client{
		providerURL:  strings.TrimSuffix(providerURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:        scope,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) Authenticate(ctx context.Context) (token string, err error) {
	deviceCode, err := c.requestDeviceCode(ctx)
	if err != nil {
		return "", fmt.Errorf("device code request: %w", err)
	}

	// Prefer verification_uri_complete from the server response — it already
	// contains the user_code and the correct hostname (the same one Keycloak
	// uses for session cookies). Fall back to verification_uri if the server
	// did not return the complete URI.
	authURL := deviceCode.VerificationURIComplete
	if authURL == "" {
		authURL = deviceCode.VerificationURI
		if authURL == "" {
			// Last resort: construct the URL from providerURL.
			authURL = fmt.Sprintf("%s/protocol/openid-connect/auth/device", c.providerURL)
		}
		if deviceCode.UserCode != "" {
			authURL = fmt.Sprintf("%s?user_code=%s", authURL, deviceCode.UserCode)
		}
	}
	fmt.Printf("Open this URL in your browser:\n%s\n", authURL)
	fmt.Print("Waiting for authentication...")

	interval := deviceCode.Interval
	if interval == 0 {
		interval = 5
	}

	token, err = c.pollForToken(ctx, deviceCode.DeviceCode, interval, deviceCode.ExpiresIn)
	if err != nil {
		return "", fmt.Errorf("token polling: %w", err)
	}

	fmt.Println(" done")
	return token, nil
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (c *Client) AuthenticateInteractive(ctx context.Context) (token string, err error) {
	redirectURI := "http://localhost:9876/callback"
	state := generateState()
	codeChan := make(chan authCodeResponse, 1)
	serverErrChan := make(chan error, 1)

	mux := http.NewServeMux()
	server := &http.Server{Addr: "localhost:9876", Handler: mux}
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		returnedState := r.URL.Query().Get("state")
		if returnedState != state {
			codeChan <- authCodeResponse{err: fmt.Errorf("state mismatch")}
			return
		}
		if code == "" {
			codeChan <- authCodeResponse{err: fmt.Errorf("no code received")}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>"))
		codeChan <- authCodeResponse{code: code, state: state}
	})

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()
	defer server.Shutdown(context.Background())

	authURL := c.buildAuthURL(state, redirectURI)
	fmt.Printf("Open this URL in your browser:\n%s\n", authURL)
	fmt.Print("Waiting for authentication...")

	select {
	case result := <-codeChan:
		if result.err != nil {
			return "", result.err
		}
		return c.exchangeCode(ctx, result.code, redirectURI)
	case srvErr := <-serverErrChan:
		return "", fmt.Errorf("callback server failed to start: %w", srvErr)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *Client) buildAuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", c.scope)
	params.Set("state", state)
	return c.providerURL + "/protocol/openid-connect/auth?" + params.Encode()
}

func (c *Client) exchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL+"/protocol/openid-connect/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s", string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if tr.Error != "" {
		return "", fmt.Errorf("token error: %s - %s", tr.Error, tr.ErrorDesc)
	}

	return tr.AccessToken, nil
}

func (c *Client) AuthenticatePassword(ctx context.Context, username, password string) (token string, err error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("scope", c.scope)
	data.Set("username", username)
	data.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL+"/protocol/openid-connect/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s", string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if tr.Error != "" {
		return "", fmt.Errorf("token error: %s - %s", tr.Error, tr.ErrorDesc)
	}

	return tr.AccessToken, nil
}

func (c *Client) requestDeviceCode(ctx context.Context) (*deviceCodeResponse, error) {
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("scope", c.scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL+"/protocol/openid-connect/auth/device", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed: %s", string(body))
	}

	var dc deviceCodeResponse
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, err
	}

	return &dc, nil
}

func (c *Client) pollForToken(ctx context.Context, deviceCode string, interval, expiresIn int) (string, error) {
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return "", fmt.Errorf("authentication timed out")
		}

		token, err := c.requestToken(ctx, deviceCode)
		if err != nil {
			return "", err
		}
		if token != "" {
			return token, nil
		}

		select {
		case <-time.After(time.Duration(interval) * time.Second):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func (c *Client) requestToken(ctx context.Context, deviceCode string) (string, error) {
	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL+"/protocol/openid-connect/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
		return "", fmt.Errorf("token request failed: %s", string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}

	if tr.Error == "authorization_pending" {
		return "", nil
	}
	if tr.Error == "slow_down" {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return "", ctx.Err()
		}
		return "", nil
	}
	if tr.Error != "" {
		return "", fmt.Errorf("token error: %s - %s", tr.Error, tr.ErrorDesc)
	}

	return tr.AccessToken, nil
}
