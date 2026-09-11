package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// embeddedConfigB64 holds the base64-encoded agent Config injected into a
// self-contained stub at build time:
//
//	go build -ldflags "-X github.com/ashwnn/adverse-go/internal/agent.embeddedConfigB64=<base64(JSON)>" ./cmd/registryfil
//
// It stays empty in the lab build (no -X), which selects --config mode.
// EmbeddedConfig references it so the linker retains it even though nothing
// else in the package reads it directly. The value must not be logged.
var embeddedConfigB64 string

// ParseEmbeddedConfig decodes a base64-encoded JSON agent config.
//
// Validation is deliberately NOT performed here: the caller runs
// (*Config).Validate at the same call site as for file-loaded configs so all
// sources enforce identical rules.
func ParseEmbeddedConfig(b64 string) (*Config, error) {
	if b64 == "" {
		return nil, fmt.Errorf("embedded config is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode embedded config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse embedded config: %w", err)
	}
	return cfg, nil
}

// EmbeddedConfig returns the build-time-baked config, or (nil, nil) when the
// binary was built without one (lab build). A non-nil error means the injected
// value was corrupt and the stub must not run.
func EmbeddedConfig() (*Config, error) {
	if embeddedConfigB64 == "" {
		return nil, nil
	}
	return ParseEmbeddedConfig(embeddedConfigB64)
}
