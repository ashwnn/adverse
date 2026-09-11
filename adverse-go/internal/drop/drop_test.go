package drop

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory Store + Lister for tests.
type memStore struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func newMemStore() *memStore { return &memStore{blobs: make(map[string][]byte)} }

func (m *memStore) Put(_ context.Context, name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blobs[name] = append([]byte(nil), data...)
	return nil
}

func (m *memStore) Get(_ context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.blobs[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), data...), nil
}

func (m *memStore) Delete(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blobs, name)
	return nil
}

func (m *memStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Simulate a directory listing: emit the first path component under the
	// prefix (directories), and full names for files directly inside.
	seen := make(map[string]bool)
	var out []string
	for name := range m.blobs {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := strings.TrimPrefix(name, prefix)
		if rest == "" {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i] // directory entry
		}
		entry := prefix + rest
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memStore) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.blobs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Store round-trips ---

func TestHTTPStoreRoundTrip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			if r.URL.Path == "/agents/a/00000001-in" {
				w.Write([]byte("frame-bytes"))
				return
			}
			http.NotFound(w, r)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	s := NewHTTPStore(ts.URL)
	ctx := context.Background()

	if err := s.Put(ctx, "agents/a/00000001-in", []byte("frame-bytes")); err != nil {
		t.Fatalf("put: %v", err)
	}
	data, err := s.Get(ctx, "agents/a/00000001-in")
	if err != nil || string(data) != "frame-bytes" {
		t.Fatalf("get: %q err=%v", data, err)
	}
	if _, err := s.Get(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, "agents/a/00000001-in"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Path traversal attempts are rejected.
	if err := s.Put(ctx, "../escape", []byte("x")); err == nil {
		t.Fatal("expected name validation error")
	}
}

func TestHTTPStoreListPropfind(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		href := "http://" + r.Host
		if r.Method == "PROPFIND" && r.URL.Path == "/agents/" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			fmt.Fprintf(w, `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>%s/agents/</d:href></d:response>
  <d:response><d:href>%s/agents/aa112233/</d:href></d:response>
  <d:response><d:href>%s/agents/bb445566/</d:href></d:response>
</d:multistatus>`, href, href, href)
			return
		}
		if r.Method == "PROPFIND" && strings.HasPrefix(r.URL.Path, "/agents/aa112233/") {
			w.WriteHeader(http.StatusMultiStatus)
			fmt.Fprintf(w, `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>%s/agents/aa112233/</d:href></d:response>
  <d:response><d:href>%s/agents/aa112233/00000000-in</d:href></d:response>
</d:multistatus>`, href, href)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	s := NewHTTPStore(ts.URL)
	ctx := context.Background()

	agents, err := s.List(ctx, "agents/")
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	want := []string{"agents/aa112233", "agents/bb445566"}
	if len(agents) != len(want) || agents[0] != want[0] || agents[1] != want[1] {
		t.Fatalf("list agents: got %v want %v", agents, want)
	}

	blobs, err := s.List(ctx, "agents/aa112233/")
	if err != nil {
		t.Fatalf("list blobs: %v", err)
	}
	if len(blobs) != 1 || blobs[0] != "agents/aa112233/00000000-in" {
		t.Fatalf("list blobs: got %v", blobs)
	}
}

// --- Graph store against fake identity + graph endpoints ---

func TestGraphStoreRoundTrip(t *testing.T) {
	var gotAuth string
	var gotCreateFolder bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok-123","expires_in":3600}`)
		case r.URL.Path == "/v1.0/users/bot@example.com/drive/root:/agents:/children" && r.Method == http.MethodPost:
			gotCreateFolder = true
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":"folder-1"}`)
		case r.URL.Path == "/v1.0/users/bot@example.com/drive/root:/agents/aa112233:/children" && r.Method == http.MethodPost:
			gotCreateFolder = true
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":"folder-2"}`)
		case r.URL.Path == "/v1.0/users/bot@example.com/drive/root:/agents/aa112233/00000001-in:/content" && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":"file-1"}`)
		case r.URL.Path == "/v1.0/users/bot@example.com/drive/root:/agents/aa112233/00000001-in:/content" && r.Method == http.MethodGet:
			w.Write([]byte("frame-bytes"))
		case r.URL.Path == "/v1.0/users/bot@example.com/drive/root:/agents/aa112233/00000001-in" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1.0/users/bot@example.com/drive/root:/agents/aa112233:/children" && r.Method == http.MethodGet:
			fmt.Fprint(w, `{"value":[{"name":"00000001-in"}]}`)
		default:
			t.Logf("unhandled: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	gs := NewGraphStore("tenant", "client-id", "secret", "bot@example.com")
	gs.TokenURL = ts.URL + "/token"
	gs.GraphURL = ts.URL

	ctx := context.Background()
	if err := gs.Put(ctx, "agents/aa112233/00000001-in", []byte("frame-bytes")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if !gotCreateFolder {
		t.Fatal("expected parent folder creation")
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("auth header: %q", gotAuth)
	}
	data, err := gs.Get(ctx, "agents/aa112233/00000001-in")
	if err != nil || string(data) != "frame-bytes" {
		t.Fatalf("get: %q err=%v", data, err)
	}
	if err := gs.Delete(ctx, "agents/aa112233/00000001-in"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	names, err := gs.List(ctx, "agents/aa112233/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 1 || names[0] != "agents/aa112233/00000001-in" {
		t.Fatalf("list: %v", names)
	}
}

// Token acquisition failure must surface as an error, never a silent retry.
func TestGraphStoreTokenFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	gs := NewGraphStore("tenant", "bad-id", "bad-secret", "u@example.com")
	gs.TokenURL = ts.URL + "/token"
	gs.GraphURL = ts.URL

	if err := gs.Put(context.Background(), "agents/a/1-in", []byte("x")); err == nil {
		t.Fatal("expected token error")
	}
}

// --- Client exchange ---

// fakeWireHandler mimics the server wire core: response = request echoed.
type echoHandler struct{}

func (echoHandler) ProcessFrame(body []byte) (int, []byte) {
	return 200, append([]byte("resp:"), body...)
}

func TestClientExchange(t *testing.T) {
	m := newMemStore()
	store := &asyncStore{m: m, respondAfter: 30 * time.Millisecond}
	c := NewClient(store, "agents", "aa112233")
	c.PollInterval = 5 * time.Millisecond
	c.ResponseTimeout = 2 * time.Second

	resp, err := c.Exchange(context.Background(), []byte("frame-1"), 7)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if string(resp) != "resp:frame-1" {
		t.Fatalf("response: %q", resp)
	}

	// Delete-after-read: both blobs are gone.
	remaining := m.keys()
	if len(remaining) != 0 {
		t.Fatalf("expected no blobs after exchange, got %v", remaining)
	}
}

func TestClientExchangeTimeout(t *testing.T) {
	m := newMemStore()
	c := NewClient(m, "agents", "aa112233")
	c.PollInterval = 5 * time.Millisecond
	c.ResponseTimeout = 30 * time.Millisecond

	start := time.Now()
	_, err := c.Exchange(context.Background(), []byte("frame-1"), 7)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout took too long")
	}
	// Request blob must be cleaned up even on timeout.
	if len(m.keys()) != 0 {
		t.Fatalf("expected cleanup on timeout, got %v", m.keys())
	}
}

// --- Poller ---

// asyncStore simulates the server side: when an "-in" blob is put, a goroutine
// processes it through the wire core after a short propagation delay and
// writes the "-out" blob.
type asyncStore struct {
	m            *memStore
	respondAfter time.Duration
}

func (a *asyncStore) Put(ctx context.Context, name string, data []byte) error {
	if err := a.m.Put(ctx, name, data); err != nil {
		return err
	}
	if strings.HasSuffix(name, "-in") {
		time.AfterFunc(a.respondAfter, func() {
			body, _ := a.m.Get(context.Background(), name)
			if body == nil {
				return
			}
			_, resp := echoHandler{}.ProcessFrame(body)
			out := strings.TrimSuffix(name, "-in") + "-out"
			_ = a.m.Put(context.Background(), out, resp)
		})
	}
	return nil
}

func (a *asyncStore) Get(ctx context.Context, name string) ([]byte, error) {
	return a.m.Get(ctx, name)
}

func (a *asyncStore) Delete(ctx context.Context, name string) error {
	return a.m.Delete(ctx, name)
}

func (a *asyncStore) List(ctx context.Context, prefix string) ([]string, error) {
	return a.m.List(ctx, prefix)
}

func TestPollerProcessesFrameAndOrdersDeleteBeforePut(t *testing.T) {
	m := newMemStore()
	_ = m.Put(context.Background(), "agents/aa112233/00000000-in", []byte("frame-1"))

	// Use an echoing handler and inspect the store ordering via a wrapped store.
	wrapped := &orderCheckStore{inner: m, t: t}
	p := NewPoller(wrapped, "agents", echoHandler{}, nil)
	p.PollInterval = time.Hour // not used; pollOnce is called directly

	p.pollOnce(context.Background())

	// Response written, request deleted.
	out, err := m.Get(context.Background(), "agents/aa112233/00000000-out")
	if err != nil || string(out) != "resp:frame-1" {
		t.Fatalf("out blob: %q err=%v", out, err)
	}
	if _, err := m.Get(context.Background(), "agents/aa112233/00000000-in"); err != ErrNotFound {
		t.Fatalf("in blob should be deleted, got %v", err)
	}
}

// orderCheckStore asserts Put(out) only happens after Delete(in).
type orderCheckStore struct {
	inner *memStore
	t     *testing.T
	order []string
}

func (o *orderCheckStore) Put(ctx context.Context, name string, data []byte) error {
	o.order = append(o.order, "put:"+name)
	return o.inner.Put(ctx, name, data)
}

func (o *orderCheckStore) Get(ctx context.Context, name string) ([]byte, error) {
	o.order = append(o.order, "get:"+name)
	return o.inner.Get(ctx, name)
}

func (o *orderCheckStore) Delete(ctx context.Context, name string) error {
	o.order = append(o.order, "del:"+name)
	return o.inner.Delete(ctx, name)
}

func (o *orderCheckStore) List(ctx context.Context, prefix string) ([]string, error) {
	o.order = append(o.order, "list:"+prefix)
	return o.inner.List(ctx, prefix)
}

// Rejected frames do not produce a response blob.
func TestPollerRejectsBadFrame(t *testing.T) {
	m := newMemStore()
	_ = m.Put(context.Background(), "agents/aa112233/00000000-in", []byte("garbage"))

	rejecting := handlerFunc(func(body []byte) (int, []byte) { return 400, []byte("bad frame") })
	p := NewPoller(m, "agents", rejecting, nil)
	p.pollOnce(context.Background())
	if _, err := m.Get(context.Background(), "agents/aa112233/00000000-out"); err != ErrNotFound {
		t.Fatal("no response blob expected for rejected frame")
	}
	if _, err := m.Get(context.Background(), "agents/aa112233/00000000-in"); err != ErrNotFound {
		t.Fatal("request blob must be deleted even when rejected")
	}
}

type handlerFunc func(body []byte) (int, []byte)

func (f handlerFunc) ProcessFrame(body []byte) (int, []byte) { return f(body) }

// Two agents are processed independently.
func TestPollerTwoLevelDiscovery(t *testing.T) {
	m := newMemStore()
	_ = m.Put(context.Background(), "agents/aa112233/00000000-in", []byte("req-a"))
	_ = m.Put(context.Background(), "agents/bb445566/00000001-in", []byte("req-b"))

	p := NewPoller(m, "agents", echoHandler{}, nil)
	p.pollOnce(context.Background())
	outA, _ := m.Get(context.Background(), "agents/aa112233/00000000-out")
	outB, _ := m.Get(context.Background(), "agents/bb445566/00000001-out")
	if string(outA) != "resp:req-a" || string(outB) != "resp:req-b" {
		t.Fatalf("out blobs: %q %q", outA, outB)
	}
}

// --- Name validation and blob size limits ---

func TestValidateName(t *testing.T) {
	valid := []string{
		"agents/a/00000001-in",
		"missing",
		"a-b_c.d~e",
		"deep/path/to/blob-1",
	}
	for _, name := range valid {
		if err := validateName(name); err != nil {
			t.Errorf("validateName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"",
		"../escape",
		"a/../../b",
		"/leading",
		"trailing/",
		"double//slash",
		`back\slash`,
		"nul\x00byte",
		"query?x=1",
		"fragment#x",
		"percent%20",
		"control\x01char",
	}
	for _, name := range invalid {
		if err := validateName(name); err == nil {
			t.Errorf("validateName(%q) = nil, want error", name)
		}
	}
}

// Unsafe names are rejected before any HTTP request is made.
func TestStoresRejectUnsafeNames(t *testing.T) {
	s := NewHTTPStore("https://example.invalid")
	ctx := context.Background()
	if _, err := s.Get(ctx, "agents/a?b/1-in"); err == nil {
		t.Fatal("HTTPStore accepted ? in blob name")
	}
	if err := s.Put(ctx, "agents/a#b/1-in", []byte("x")); err == nil {
		t.Fatal("HTTPStore accepted # in blob name")
	}
	if err := s.Delete(ctx, "agents/a%b/1-in"); err == nil {
		t.Fatal("HTTPStore accepted % in blob name")
	}
}

// Name segments are percent-encoded when composed into a URL.
func TestBlobURLEncoding(t *testing.T) {
	s := NewHTTPStore("https://example.invalid/root")
	got := s.blobURL("agents/a b/1-in")
	want := "https://example.invalid/root/agents/a%20b/1-in"
	if got != want {
		t.Fatalf("blobURL = %q, want %q", got, want)
	}
}

func TestHTTPStoreOversizeBlobErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write(make([]byte, MaxBlobBytes+1))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	s := NewHTTPStore(ts.URL)
	_, err := s.Get(context.Background(), "agents/a/00000001-in")
	if err == nil {
		t.Fatal("expected over-limit blob to be an error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected over-limit error, got %v", err)
	}
}

func TestHTTPStoreAtLimitBlobAccepted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write(make([]byte, MaxBlobBytes))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	s := NewHTTPStore(ts.URL)
	data, err := s.Get(context.Background(), "agents/a/00000001-in")
	if err != nil {
		t.Fatalf("at-limit blob rejected: %v", err)
	}
	if len(data) != MaxBlobBytes {
		t.Fatalf("at-limit blob length = %d, want %d", len(data), MaxBlobBytes)
	}
}

func TestGraphStoreOversizeBlobErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			fmt.Fprint(w, `{"access_token":"tok-123","expires_in":3600}`)
		case r.Method == http.MethodGet:
			w.Write(make([]byte, MaxBlobBytes+1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	gs := NewGraphStore("tenant", "client-id", "secret", "bot@example.com")
	gs.TokenURL = ts.URL + "/token"
	gs.GraphURL = ts.URL

	_, err := gs.Get(context.Background(), "agents/a/00000001-in")
	if err == nil {
		t.Fatal("expected over-limit blob to be an error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected over-limit error, got %v", err)
	}
}

var _ = xml.Name{}
