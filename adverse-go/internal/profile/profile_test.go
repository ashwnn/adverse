package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	p := Default()
	if p.BeaconIntervalS != 30 {
		t.Fatalf("expected BeaconIntervalS=30, got %d", p.BeaconIntervalS)
	}
	if p.BeaconJitterS != 10 {
		t.Fatalf("expected BeaconJitterS=10, got %d", p.BeaconJitterS)
	}
	if p.MaxResultsPerAgent != 1000 {
		t.Fatalf("expected MaxResultsPerAgent=1000, got %d", p.MaxResultsPerAgent)
	}
	if p.StateDir != ".adverse" {
		t.Fatalf("expected StateDir=.adverse, got %s", p.StateDir)
	}
	if p.Listen != "127.0.0.1:8443" {
		t.Fatalf("expected Listen=127.0.0.1:8443, got %s", p.Listen)
	}
}

func TestLoadEmptyPath(t *testing.T) {
	p, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.BeaconIntervalS != 30 {
		t.Fatalf("expected default interval, got %d", p.BeaconIntervalS)
	}
}

func TestLoadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	content := `{"name":"lab","listen":"0.0.0.0:9999","beacon_interval_s":60,"beacon_jitter_s":5,"max_results_per_agent":500,"state_dir":"/tmp/state","headers":{"X-Custom":"yes"}}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "lab" {
		t.Fatalf("expected name=lab, got %s", p.Name)
	}
	if p.Listen != "0.0.0.0:9999" {
		t.Fatalf("expected listen=0.0.0.0:9999, got %s", p.Listen)
	}
	if p.BeaconIntervalS != 60 {
		t.Fatalf("expected interval=60, got %d", p.BeaconIntervalS)
	}
	if p.BeaconJitterS != 5 {
		t.Fatalf("expected jitter=5, got %d", p.BeaconJitterS)
	}
	if p.MaxResultsPerAgent != 500 {
		t.Fatalf("expected max_results=500, got %d", p.MaxResultsPerAgent)
	}
	if p.StateDir != "/tmp/state" {
		t.Fatalf("expected state_dir=/tmp/state, got %s", p.StateDir)
	}
	if p.Headers["X-Custom"] != "yes" {
		t.Fatalf("expected header X-Custom=yes, got %s", p.Headers["X-Custom"])
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPartialJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.json")
	content := `{"name":"partial"}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "partial" {
		t.Fatalf("expected name=partial, got %s", p.Name)
	}
	// Zero-value fields should get defaults.
	if p.BeaconIntervalS != 30 {
		t.Fatalf("expected default interval, got %d", p.BeaconIntervalS)
	}
	if p.MaxResultsPerAgent != 1000 {
		t.Fatalf("expected default max_results, got %d", p.MaxResultsPerAgent)
	}
}
