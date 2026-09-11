package main

import (
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/ashwnn/adverse-go/internal/agent"
)

func TestVersionDefaults(t *testing.T) {
	// version/buildTime/gitCommit are set via ldflags at build time.
	// In unit tests they retain their default values.
	if version == "" {
		t.Error("version default should not be empty")
	}
	if buildTime == "" {
		t.Error("buildTime default should not be empty")
	}
	if gitCommit == "" {
		t.Error("gitCommit default should not be empty")
	}
}

func testCfg(agentID string) *agent.Config {
	return &agent.Config{AgentID: agentID}
}

func TestResolveAgentOptions(t *testing.T) {
	embedded := testCfg("embedded")
	lab := testCfg("labconfg")
	loader := func(path string) (*agent.Config, error) {
		if path == "lab.json" {
			return lab, nil
		}
		return nil, errors.New("load failed: " + path)
	}

	tests := []struct {
		name        string
		embedded    *agent.Config
		configPath  string
		dryRunSet   bool
		dryRunValue bool
		wantCfg     *agent.Config
		wantDryRun  bool
		wantErrIs   error
		wantErrMsg  string
	}{
		{"stub_defaults_to_real_run", embedded, "", false, false, embedded, false, nil, ""},
		{"stub_explicit_dry_run_true", embedded, "", true, true, embedded, true, nil, ""},
		{"stub_explicit_dry_run_false", embedded, "", true, false, embedded, false, nil, ""},
		{"stub_ignores_config_flag", embedded, "lab.json", false, false, embedded, false, nil, ""},
		{"lab_defaults_to_dry_run", nil, "lab.json", false, false, lab, true, nil, ""},
		{"lab_explicit_dry_run_true", nil, "lab.json", true, true, lab, true, nil, ""},
		{"lab_explicit_dry_run_false", nil, "lab.json", true, false, lab, false, nil, ""},
		{"neither_source", nil, "", false, false, nil, false, errConfigRequired, ""},
		{"loader_error", nil, "missing.json", false, false, nil, false, nil, "load failed: missing.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCfg, gotDryRun, err := resolveAgentOptions(tt.embedded, loader, tt.configPath, tt.dryRunSet, tt.dryRunValue)
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("error = %v, want %v", err, tt.wantErrIs)
				}
			} else if tt.wantErrMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErrMsg)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotCfg != tt.wantCfg {
				t.Errorf("cfg = %p, want %p", gotCfg, tt.wantCfg)
			}
			if gotDryRun != tt.wantDryRun {
				t.Errorf("dryRun = %v, want %v", gotDryRun, tt.wantDryRun)
			}
		})
	}
}

func TestResolveAgentOptionsStubNeverCallsLoader(t *testing.T) {
	embedded := testCfg("embedded")
	loader := func(string) (*agent.Config, error) {
		t.Fatal("loader must not be called when an embedded config is present")
		return nil, nil
	}

	got, dryRun, err := resolveAgentOptions(embedded, loader, "/definitely/not/read.json", false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != embedded {
		t.Fatalf("expected embedded config, got %p", got)
	}
	if dryRun {
		t.Fatal("stub mode must default to dry-run=false")
	}
}

// TestResumeFlagParses pins that the persistence watchdog's relaunch argument
// is accepted by the CLI flag set; an unknown flag would make a relaunched
// agent exit 2 (which the watchdog reads as an intentional kill-switch stop).
func TestResumeFlagParses(t *testing.T) {
	fs := flag.NewFlagSet("registryfil-test", flag.ContinueOnError)
	fs.String("config", "", "")
	fs.Bool("dry-run", true, "")
	resume := fs.Bool("resume", false, "")
	if err := fs.Parse([]string{"--resume"}); err != nil {
		t.Fatalf("--resume must parse: %v", err)
	}
	if !*resume {
		t.Fatal("--resume must be true after parsing")
	}
}

func newTestFlagSet(stub bool, args ...string) *flag.FlagSet {
	fs := flag.NewFlagSet("registryfil-test", flag.ContinueOnError)
	fs.String("config", "", "")
	fs.Bool("dry-run", !stub, "")
	if err := fs.Parse(args); err != nil {
		panic(err)
	}
	return fs
}

func TestResolveFromFlagSet(t *testing.T) {
	embedded := testCfg("embedded")
	lab := testCfg("labconfg")
	loader := func(path string) (*agent.Config, error) {
		if path == "lab.json" {
			return lab, nil
		}
		return nil, errors.New("load failed: " + path)
	}

	tests := []struct {
		name       string
		stub       bool
		args       []string
		wantCfg    *agent.Config
		wantDryRun bool
		wantErrIs  error
		wantErrMsg string
	}{
		{"lab_no_flags", false, nil, nil, false, errConfigRequired, ""},
		{"lab_config_defaults_dry_run", false, []string{"--config", "lab.json"}, lab, true, nil, ""},
		{"lab_explicit_dry_run_false", false, []string{"--config", "lab.json", "--dry-run=false"}, lab, false, nil, ""},
		{"lab_missing_config", false, []string{"--dry-run=true"}, nil, false, errConfigRequired, ""},
		{"stub_no_flags", true, nil, embedded, false, nil, ""},
		{"stub_explicit_dry_run_true", true, []string{"--dry-run=true"}, embedded, true, nil, ""},
		{"stub_config_ignored", true, []string{"--config", "lab.json", "--dry-run=false"}, embedded, false, nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newTestFlagSet(tt.stub, tt.args...)
			var emb *agent.Config
			if tt.stub {
				emb = embedded
			}
			gotCfg, gotDryRun, err := resolveFromFlagSet(fs, emb, loader)
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("error = %v, want %v", err, tt.wantErrIs)
				}
			} else if tt.wantErrMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErrMsg)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotCfg != tt.wantCfg {
				t.Errorf("cfg = %p, want %p", gotCfg, tt.wantCfg)
			}
			if gotDryRun != tt.wantDryRun {
				t.Errorf("dryRun = %v, want %v", gotDryRun, tt.wantDryRun)
			}
		})
	}
}

func TestResolveFromFlagSetExplicitDryRunDetection(t *testing.T) {
	// In lab mode the flag default is true; only an explicit --dry-run=false
	// may flip it, which is what fs.Visit-based detection guarantees.
	lab := testCfg("labconfg")
	loader := func(string) (*agent.Config, error) { return lab, nil }

	explicit := newTestFlagSet(false, "--config", "any.json", "--dry-run=false")
	_, dryRun, err := resolveFromFlagSet(explicit, nil, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dryRun {
		t.Fatal("explicit --dry-run=false must take effect in lab mode")
	}

	implicit := newTestFlagSet(false, "--config", "any.json")
	_, dryRun, err = resolveFromFlagSet(implicit, nil, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dryRun {
		t.Fatal("lab mode must default to dry-run=true")
	}
}
