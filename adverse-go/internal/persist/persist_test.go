package persist

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func TestModeNoneIsNoop(t *testing.T) {
	m, err := New(Config{Mode: ModeNone, ExePath: `C:\agent.exe`, Args: []string{"--resume"}})
	if err != nil {
		t.Fatalf("New(ModeNone): %v", err)
	}
	if m == nil {
		t.Fatal("New(ModeNone) returned a nil manager")
	}
	if m.Armed() {
		t.Fatal("no-op manager must not be armed before Arm")
	}
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if m.Armed() {
		t.Fatal("no-op manager must not report armed")
	}
	if err := m.Arm(); err != nil {
		t.Fatalf("second Arm must be idempotent: %v", err)
	}
	if err := m.Disarm(); err != nil {
		t.Fatalf("Disarm: %v", err)
	}
	if err := m.Disarm(); err != nil {
		t.Fatalf("second Disarm must be idempotent: %v", err)
	}
}

func TestNewRejectsInvalidMode(t *testing.T) {
	for _, mode := range []Mode{"", "bogus", "WATCHDOG", "watchdog ", "None"} {
		if _, err := New(Config{Mode: mode}); err == nil {
			t.Errorf("New(Config{Mode: %q}) succeeded, want error", mode)
		}
	}
}

func TestNewAcceptsValidModes(t *testing.T) {
	for _, mode := range []Mode{ModeNone, ModeWatchdog, ModeRunKey, ModeBoth} {
		if _, err := New(Config{Mode: mode, ExePath: `C:\agent.exe`}); err != nil {
			t.Errorf("New(Config{Mode: %q}) = %v, want success", mode, err)
		}
	}
}

func TestMaybeRunWatchdogChildFalseDuringNormalStartup(t *testing.T) {
	// The test binary's argv never carries the watchdog control triplet, so a
	// normal startup must not be intercepted.
	handled, code := MaybeRunWatchdogChild()
	if handled {
		t.Fatalf("MaybeRunWatchdogChild() handled = true, want false")
	}
	if code != 0 {
		t.Fatalf("MaybeRunWatchdogChild() exitCode = %d, want 0", code)
	}
}

func TestWatchdogDeadlineAccessor(t *testing.T) {
	origDeadline, hadDeadline := os.LookupEnv(envDeadline)
	defer func() {
		if hadDeadline {
			os.Setenv(envDeadline, origDeadline)
		} else {
			os.Unsetenv(envDeadline)
		}
	}()

	os.Unsetenv(envDeadline)
	if _, ok := WatchdogDeadline(); ok {
		t.Fatal("absent deadline must report ok=false")
	}
	os.Setenv(envDeadline, "not-a-number")
	if _, ok := WatchdogDeadline(); ok {
		t.Fatal("malformed deadline must report ok=false")
	}
	when := time.Now().Add(time.Minute).Truncate(time.Nanosecond)
	os.Setenv(envDeadline, strconv.FormatInt(when.UnixNano(), 10))
	got, ok := WatchdogDeadline()
	if !ok || !got.Equal(when) {
		t.Fatalf("WatchdogDeadline() = (%v, %v), want (%v, true)", got, ok, when)
	}
}

func TestParseWatchdogArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantFound    bool
		wantParent   int
		wantBudget   int
		wantRelaunch []string
		wantErr      bool
	}{
		{
			name:       "absent",
			args:       []string{"--config", "agent.json", "--resume"},
			wantFound:  false,
			wantParent: 0,
			wantBudget: 0,
		},
		{
			name:         "present with surrounding args",
			args:         []string{"--config", "agent.json", watchdogFlag, "4242", "3", "--resume"},
			wantFound:    true,
			wantParent:   4242,
			wantBudget:   3,
			wantRelaunch: []string{"--config", "agent.json", "--resume"},
		},
		{
			name:         "present alone",
			args:         []string{watchdogFlag, "1", "0"},
			wantFound:    true,
			wantParent:   1,
			wantBudget:   0,
			wantRelaunch: []string{},
		},
		{
			name:         "budget clamped to max",
			args:         []string{watchdogFlag, "7", "99"},
			wantFound:    true,
			wantParent:   7,
			wantBudget:   maxRelaunchBudget,
			wantRelaunch: []string{},
		},
		{
			name:      "missing values",
			args:      []string{"--x", watchdogFlag, "7"},
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "non-numeric parent",
			args:      []string{watchdogFlag, "abc", "3"},
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "zero parent",
			args:      []string{watchdogFlag, "0", "3"},
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "negative budget",
			args:      []string{watchdogFlag, "5", "-1"},
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "non-numeric budget",
			args:      []string{watchdogFlag, "5", "many"},
			wantFound: true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, parent, budget, relaunch, err := parseWatchdogArgs(tt.args)
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v", found, tt.wantFound)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parent != tt.wantParent {
				t.Errorf("parentPID = %d, want %d", parent, tt.wantParent)
			}
			if budget != tt.wantBudget {
				t.Errorf("budget = %d, want %d", budget, tt.wantBudget)
			}
			if len(relaunch) != len(tt.wantRelaunch) {
				t.Fatalf("relaunchArgs = %v, want %v", relaunch, tt.wantRelaunch)
			}
			for i := range relaunch {
				if relaunch[i] != tt.wantRelaunch[i] {
					t.Errorf("relaunchArgs[%d] = %q, want %q", i, relaunch[i], tt.wantRelaunch[i])
				}
			}
		})
	}
}
