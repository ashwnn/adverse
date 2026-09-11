package netshape

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDeterministicForSeed(t *testing.T) {
	a := NewProfile("/api", []byte("fixed-seed"))
	b := NewProfile("/api", []byte("fixed-seed"))

	if a.Path() != b.Path() {
		t.Fatalf("path not deterministic: %q != %q", a.Path(), b.Path())
	}
	if a.UserAgent() != b.UserAgent() {
		t.Fatalf("user agent not deterministic: %q != %q", a.UserAgent(), b.UserAgent())
	}
	ha, hb := a.Headers(), b.Headers()
	if len(ha) != len(hb) {
		t.Fatalf("header count differs: %d != %d", len(ha), len(hb))
	}
	for k, v := range ha {
		if hb[k] != v {
			t.Fatalf("header %q not deterministic: %q != %q", k, v, hb[k])
		}
	}
}

func TestDifferentSeedsDiverge(t *testing.T) {
	seen := make(map[string]bool)
	for _, seed := range []string{"one", "two", "three", "four", "five", "six"} {
		p := NewProfile("", []byte(seed))
		seen[p.Path()+"|"+p.UserAgent()] = true
	}
	if len(seen) < 2 {
		t.Fatalf("distinct seeds produced identical shapes: %d", len(seen))
	}
}

func TestPathSafety(t *testing.T) {
	bases := []string{
		"", "/", "/api", "/api/", "/tenant/42", "/../admin", "/admin",
		"admin", "https://example.com/api", "/base?q=1#frag", "/administrator",
		"/nested//path/", "/a/./b/../c",
	}
	seeds := []string{"alpha", "beta", "gamma"}
	for _, base := range bases {
		for _, seed := range seeds {
			for i := 0; i < 25; i++ {
				p := NewProfile(base, []byte(fmt.Sprintf("%s-%d", seed, i)))
				got := p.Path()
				if got == "" {
					t.Fatalf("empty path (base=%q seed=%q)", base, seed)
				}
				if !strings.HasPrefix(got, "/") {
					t.Fatalf("path not absolute: %q (base=%q)", got, base)
				}
				if strings.Contains(got, "..") {
					t.Fatalf("path contains dot segment: %q", got)
				}
				if strings.Contains(got, "//") {
					t.Fatalf("path contains double slash: %q", got)
				}
				if strings.Contains(got, "://") {
					t.Fatalf("path contains scheme: %q", got)
				}
				if strings.ContainsAny(got, "?#") {
					t.Fatalf("path contains query or fragment: %q", got)
				}
				lower := strings.ToLower(got)
				if lower == "/admin" || strings.HasPrefix(lower, "/admin/") {
					t.Fatalf("path targets admin: %q", got)
				}
				for _, seg := range strings.Split(strings.TrimPrefix(got, "/"), "/") {
					if seg == "" {
						t.Fatalf("empty path segment: %q", got)
					}
					for _, r := range seg {
						ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
						if !ok {
							t.Fatalf("implausible path character %q in %q", r, got)
						}
					}
				}
			}
		}
	}
}

func TestPathStable(t *testing.T) {
	p := NewProfile("/api", []byte("stable"))
	first := p.Path()
	for i := 0; i < 10; i++ {
		if p.Path() != first {
			t.Fatalf("path changed without mutation: %q -> %q", first, p.Path())
		}
	}
}

func TestUserAgentsBrowserLike(t *testing.T) {
	for _, seed := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		ua := NewProfile("", []byte(seed)).UserAgent()
		if !strings.HasPrefix(ua, "Mozilla/5.0 ") {
			t.Fatalf("implausible user agent: %q", ua)
		}
		if !strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Firefox/") {
			t.Fatalf("user agent is not Chrome or Firefox: %q", ua)
		}
		lower := strings.ToLower(ua)
		for _, marker := range []string{"adverse", "beacon", "c2", "bot", "headless", "python", "curl"} {
			if strings.Contains(lower, marker) {
				t.Fatalf("user agent contains marker %q: %q", marker, ua)
			}
		}
	}
}

func TestHeadersBrowserLike(t *testing.T) {
	p := NewProfile("", []byte("headers"))
	h := p.Headers()

	required := []string{"Accept", "Accept-Language", "Cache-Control", "DNT"}
	for _, k := range required {
		if h[k] == "" {
			t.Fatalf("missing or empty header %q", k)
		}
	}
	if !strings.Contains(h["Accept"], "text/html") {
		t.Fatalf("Accept not browser-like: %q", h["Accept"])
	}
	if !strings.Contains(h["Accept-Language"], "en-US") {
		t.Fatalf("Accept-Language not browser-like: %q", h["Accept-Language"])
	}
	for k, v := range h {
		if strings.EqualFold(k, "Content-Type") {
			t.Fatalf("Headers must not set Content-Type")
		}
		joined := strings.ToLower(k + " " + v)
		for _, marker := range []string{"adverse", "beacon", "x-c2", "sx1"} {
			if strings.Contains(joined, marker) {
				t.Fatalf("header %q contains C2 marker %q", k, marker)
			}
		}
	}
}

func TestHeadersIsolation(t *testing.T) {
	p := NewProfile("", []byte("isolation"))
	h := p.Headers()
	h["Accept"] = "tampered"
	h["X-Injected"] = "1"
	if p.Headers()["Accept"] == "tampered" {
		t.Fatalf("caller mutation leaked into profile state")
	}
	if _, ok := p.Headers()["X-Injected"]; ok {
		t.Fatalf("caller mutation leaked into profile headers")
	}
}

func TestJitterBounds(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	base := 30 * time.Second
	max := 5 * time.Second
	for i := 0; i < 10000; i++ {
		d := Jitter(base, max, rng)
		if d < base-max || d > base+max {
			t.Fatalf("jitter out of bounds: %v not in [%v, %v]", d, base-max, base+max)
		}
		if d < 0 {
			t.Fatalf("negative jitter: %v", d)
		}
	}
}

func TestJitterClampsToZero(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 1000; i++ {
		d := Jitter(time.Millisecond, time.Second, rng)
		if d < 0 {
			t.Fatalf("negative jitter result: %v", d)
		}
		if d = Jitter(time.Duration(math.MinInt64), time.Second, rng); d < 0 {
			t.Fatalf("underflow not clamped: %v", d)
		}
	}
}

func TestJitterDeterministic(t *testing.T) {
	a := rand.New(rand.NewSource(42))
	b := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		if Jitter(time.Second, 250*time.Millisecond, a) != Jitter(time.Second, 250*time.Millisecond, b) {
			t.Fatalf("jitter not deterministic at step %d", i)
		}
	}
}

func TestJitterDegenerateInputs(t *testing.T) {
	if got := Jitter(2*time.Second, 0, rand.New(rand.NewSource(1))); got != 2*time.Second {
		t.Fatalf("zero max: got %v", got)
	}
	if got := Jitter(2*time.Second, -time.Second, rand.New(rand.NewSource(1))); got != 2*time.Second {
		t.Fatalf("negative max: got %v", got)
	}
	if got := Jitter(2*time.Second, time.Second, nil); got != 2*time.Second {
		t.Fatalf("nil rng: got %v", got)
	}
	if got := Jitter(-time.Second, 0, nil); got != 0 {
		t.Fatalf("negative base without rng: got %v", got)
	}
}

func TestConcurrentUse(t *testing.T) {
	p := NewProfile("/api", []byte("concurrent"))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = p.Path()
				_ = p.UserAgent()
				_ = p.Headers()
			}
		}(g)
	}
	wg.Wait()
}
