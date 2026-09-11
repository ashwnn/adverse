// Package profile provides the server profile configuration for the ADVERSE C2
// server. A profile is a JSON document specifying the listen address, beacon
// cadence, result limits, state directory, and response headers for blending.
//
// Defaults are applied when fields are absent; the loader merges them with any
// explicit values from the JSON file.
package profile

import (
	"encoding/json"
	"os"
)

// DropAuth is the optional authentication for the drop store (mirrors the
// agent config schema).
type DropAuth struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	BearerEnv string `json:"bearer_env"`
}

// DropProfile enables the dead-drop collector. When Enabled, the server polls
// the configured store for agent request blobs instead of (or in addition to)
// the HTTPS listener.
type DropProfile struct {
	Enabled         bool     `json:"enabled"`
	Store           string   `json:"store"` // "http" | "graph"
	BaseURL         string   `json:"base_url"`
	Auth            DropAuth `json:"auth"`
	TenantID        string   `json:"tenant_id"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	ClientSecretEnv string   `json:"client_secret_env"`
	UserUPN         string   `json:"user_upn"`
	Dir             string   `json:"dir"`
	PollIntervalS   int      `json:"poll_interval_s"`
}

// Profile holds the server configuration.
type Profile struct {
	Name               string            `json:"name"`
	Listen             string            `json:"listen"`
	BeaconIntervalS    int               `json:"beacon_interval_s"`
	BeaconJitterS      int               `json:"beacon_jitter_s"`
	MaxResultsPerAgent int               `json:"max_results_per_agent"`
	StateDir           string            `json:"state_dir"`
	Headers            map[string]string `json:"headers"`
	Drop               DropProfile       `json:"drop"`
}

// Default returns a Profile with production-safe defaults for lab use.
func Default() Profile {
	return Profile{
		Name:               "default",
		Listen:             "127.0.0.1:8443",
		BeaconIntervalS:    30,
		BeaconJitterS:      10,
		MaxResultsPerAgent: 1000,
		StateDir:           ".adverse",
		Headers:            map[string]string{},
	}
}

// Load reads a JSON profile from path and merges it with defaults.
// An empty path returns the default profile.
func Load(path string) (Profile, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	// Apply zero-value guards: if JSON left a field at zero, use the default.
	if p.BeaconIntervalS == 0 {
		p.BeaconIntervalS = 30
	}
	if p.BeaconJitterS == 0 {
		p.BeaconJitterS = 10
	}
	if p.MaxResultsPerAgent == 0 {
		p.MaxResultsPerAgent = 1000
	}
	if p.StateDir == "" {
		p.StateDir = ".adverse"
	}
	if p.Name == "" {
		p.Name = "default"
	}
	if p.Headers == nil {
		p.Headers = map[string]string{}
	}
	// Drop defaults: dir and poll interval when enabled.
	if p.Drop.PollIntervalS <= 0 {
		p.Drop.PollIntervalS = 2
	}
	return p, nil
}
