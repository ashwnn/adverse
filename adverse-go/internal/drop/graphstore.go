package drop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// GraphStore is a Store backed by Microsoft Graph API (OneDrive/SharePoint
// drive items) using an app registration with client-credentials OAuth.
//
// Traffic terminates at graph.microsoft.com (and the identity endpoint), which
// is an allowlisted destination on virtually every network — the documented
// LOTS (living off trusted services) pattern.
//
// Requirements: an Entra app registration with an app role granting
// Files.ReadWrite.All (application permission), a client secret, and a
// OneDrive-licensed user (UPN) whose drive holds the blob folder.
//
// Blob mapping: /v1.0/users/{upn}/drive/root:/{path}/{name}:/content
//
// No secrets are logged. The client secret is read from ClientSecret or the
// environment variable named by ClientSecretEnv.
type GraphStore struct {
	// TokenURL is the OAuth2 token endpoint (defaults to the v2.0 common
	// tenant endpoint derived from TenantID). Overridable for tests.
	TokenURL string
	// GraphURL is the Graph API root (default https://graph.microsoft.com).
	// Overridable for tests.
	GraphURL string

	TenantID        string
	ClientID        string
	ClientSecret    string
	ClientSecretEnv string
	UserUPN         string // user with a OneDrive drive; e.g. c2box@example.onmicrosoft.com

	Client *http.Client

	tokenMu   sync.Mutex
	accessTok string
	tokenExp  time.Time
}

// NewGraphStore returns a GraphStore with a bounded client.
func NewGraphStore(tenantID, clientID, clientSecret, userUPN string) *GraphStore {
	return &GraphStore{
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		UserUPN:      userUPN,
		Client:       &http.Client{Timeout: 60 * time.Second},
		GraphURL:     "https://graph.microsoft.com",
	}
}

func (s *GraphStore) tokenURL() string {
	if s.TokenURL != "" {
		return s.TokenURL
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", s.TenantID)
}

func (s *GraphStore) secret() string {
	if s.ClientSecret != "" {
		return s.ClientSecret
	}
	if s.ClientSecretEnv != "" {
		return os.Getenv(s.ClientSecretEnv)
	}
	return ""
}

// token returns a valid access token, acquiring or refreshing it as needed.
func (s *GraphStore) token(ctx context.Context) (string, error) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	if s.accessTok != "" && time.Now().Before(s.tokenExp) {
		return s.accessTok, nil
	}

	secret := s.secret()
	if secret == "" {
		return "", fmt.Errorf("drop graph: no client secret configured")
	}

	form := url.Values{
		"client_id":     {s.ClientID},
		"client_secret": {secret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("drop graph token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("drop graph token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("drop graph token read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("drop graph token: status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var tok struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("drop graph token parse: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("drop graph token: empty access_token")
	}
	s.accessTok = tok.AccessToken
	// Skew: refresh 5 minutes before expiry; default 1h if unspecified.
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	s.tokenExp = time.Now().Add(ttl - 5*time.Minute)
	return s.accessTok, nil
}

// driveItemURL builds the Graph URL for a blob: PUT/GET use the :/content
// suffix; DELETE targets the item.
func (s *GraphStore) driveItemURL(name string, content bool) string {
	base := strings.TrimRight(s.GraphURL, "/")
	segs := strings.Split(name, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	path := fmt.Sprintf("/v1.0/users/%s/drive/root:/%s", url.PathEscape(s.UserUPN), strings.Join(segs, "/"))
	if content {
		return base + path + ":/content"
	}
	return base + path
}

func (s *GraphStore) do(ctx context.Context, method, name string, body io.Reader, contentType string) (*http.Response, error) {
	tok, err := s.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, s.driveItemURL(name, method != http.MethodDelete), body)
	if err != nil {
		return nil, fmt.Errorf("drop graph request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drop graph %s %s: %w", method, name, err)
	}
	return resp, nil
}

// Put uploads a blob via the OneDrive upload endpoint (small files, <4MB).
func (s *GraphStore) Put(ctx context.Context, name string, data []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := s.ensureParent(ctx, name); err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodPut, name, strings.NewReader(string(data)), "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("drop graph put %s: status %d", name, resp.StatusCode)
	}
	return nil
}

// Get retrieves a blob; 404 maps to ErrNotFound.
func (s *GraphStore) Get(ctx context.Context, name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	resp, err := s.do(ctx, http.MethodGet, name, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("drop graph get %s: status %d", name, resp.StatusCode)
	}
	// Read one byte past the cap so an over-limit blob is an explicit error
	// rather than a silent truncation.
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBlobBytes+1))
	if err != nil {
		return nil, fmt.Errorf("drop graph get %s: %w", name, err)
	}
	if len(data) > MaxBlobBytes {
		return nil, fmt.Errorf("drop graph get %s: blob exceeds %d bytes", name, MaxBlobBytes)
	}
	return data, nil
}

// Delete removes a blob; 404 is tolerated.
func (s *GraphStore) Delete(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodDelete, name, nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("drop graph delete %s: status %d", name, resp.StatusCode)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
