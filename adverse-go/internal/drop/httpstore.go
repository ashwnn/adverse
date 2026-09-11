package drop

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// HTTPStore is a Store over generic HTTPS PUT/GET/DELETE on paths under a base
// URL. It works against WebDAV servers (e.g. Nextcloud), simple object stores
// with path-style PUT/GET/DELETE, or a lab relay. Optional auth:
//   - basic: username/password (Basic auth header)
//   - bearer: static token, or a token read from the env var named by BearerEnv
//
// 404 on GET maps to ErrNotFound; other non-2xx responses are errors.
type HTTPStore struct {
	BaseURL   string
	Client    *http.Client
	Username  string
	Password  string
	Bearer    string // static bearer token (or use BearerEnv)
	BearerEnv string // env var name holding the bearer token
}

// NewHTTPStore returns an HTTPStore with a bounded client and the given base
// URL. baseURL is the storage root, e.g. https://files.example.com/dav/adverse.
func NewHTTPStore(baseURL string) *HTTPStore {
	return &HTTPStore{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *HTTPStore) blobURL(name string) string {
	segs := strings.Split(strings.TrimLeft(name, "/"), "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return s.BaseURL + "/" + strings.Join(segs, "/")
}

func (s *HTTPStore) applyAuth(req *http.Request) {
	switch {
	case s.Bearer != "":
		req.Header.Set("Authorization", "Bearer "+s.Bearer)
	case s.BearerEnv != "":
		if tok := os.Getenv(s.BearerEnv); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	case s.Username != "":
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.Username+":"+s.Password)))
	}
}

// Put uploads data to name.
func (s *HTTPStore) Put(ctx context.Context, name string, data []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.blobURL(name), strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("drop http put: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	s.applyAuth(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("drop http put %s: %w", name, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("drop http put %s: status %d", name, resp.StatusCode)
	}
	return nil
}

// Get retrieves name; 404 maps to ErrNotFound.
func (s *HTTPStore) Get(ctx context.Context, name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.blobURL(name), nil)
	if err != nil {
		return nil, fmt.Errorf("drop http get: %w", err)
	}
	s.applyAuth(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drop http get %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("drop http get %s: status %d", name, resp.StatusCode)
	}
	// Read one byte past the cap so an over-limit blob is an explicit error
	// rather than a silent truncation.
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBlobBytes+1))
	if err != nil {
		return nil, fmt.Errorf("drop http get %s: %w", name, err)
	}
	if len(data) > MaxBlobBytes {
		return nil, fmt.Errorf("drop http get %s: blob exceeds %d bytes", name, MaxBlobBytes)
	}
	return data, nil
}

// Delete removes name; 404 is tolerated.
func (s *HTTPStore) Delete(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.blobURL(name), nil)
	if err != nil {
		return fmt.Errorf("drop http delete: %w", err)
	}
	s.applyAuth(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("drop http delete %s: %w", name, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("drop http delete %s: status %d", name, resp.StatusCode)
	}
	return nil
}
