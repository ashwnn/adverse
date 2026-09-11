//go:build windows

package persist

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNewValidatesExePath(t *testing.T) {
	cases := []struct {
		name string
		exe  string
	}{
		{"empty", ""},
		{"relative", `agent.exe`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Config{Mode: ModeWatchdog, ExePath: tc.exe}); err == nil {
				t.Fatalf("New(ExePath=%q) succeeded, want error", tc.exe)
			}
		})
	}
}

func TestFormatRunValue(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		args []string
		want string
	}{
		{
			name: "exe always quoted",
			exe:  `C:\agent.exe`,
			want: `"C:\agent.exe"`,
		},
		{
			name: "plain args",
			exe:  `C:\agent.exe`,
			args: []string{"--resume"},
			want: `"C:\agent.exe" --resume`,
		},
		{
			name: "spaced arg is quoted",
			exe:  `C:\Program Files\agent.exe`,
			args: []string{"--config", `C:\Program Files\c.json`},
			want: `"C:\Program Files\agent.exe" --config "C:\Program Files\c.json"`,
		},
		{
			name: "empty arg is quoted",
			exe:  `C:\agent.exe`,
			args: []string{""},
			want: `"C:\agent.exe" ""`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatRunValue(tc.exe, tc.args); got != tc.want {
				t.Errorf("formatRunValue(%q, %v) = %q, want %q", tc.exe, tc.args, got, tc.want)
			}
		})
	}
}

func TestWatchdogBudget(t *testing.T) {
	tests := []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{raw: "", want: maxRelaunchBudget},
		{raw: "2", want: 2},
		{raw: "0", want: 0},
		{raw: "99", want: maxRelaunchBudget},
		{raw: "-1", wantErr: true},
		{raw: "nope", wantErr: true},
	}
	for _, tc := range tests {
		got, err := watchdogBudget(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("watchdogBudget(%q) succeeded, want error", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("watchdogBudget(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("watchdogBudget(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestWatchdogEnvReplacesChainValues(t *testing.T) {
	t.Setenv(envBudget, "9")
	t.Setenv(envDeadline, "111")
	deadline := time.Unix(0, 456)

	env := watchdogEnv(2, deadline)
	if n := countEnv(env, envBudget); n != 1 {
		t.Errorf("%s entries = %d, want 1", envBudget, n)
	}
	if n := countEnv(env, envDeadline); n != 1 {
		t.Errorf("%s entries = %d, want 1", envDeadline, n)
	}
	if !envHas(env, envBudget+"=2") {
		t.Errorf("env missing fresh %s=2", envBudget)
	}
	if !envHas(env, envDeadline+"=456") {
		t.Errorf("env missing fresh %s=456", envDeadline)
	}
}

func TestWatchdogEnvOmitsAbsentDeadline(t *testing.T) {
	env := watchdogEnv(1, time.Time{})
	if envHas(env, envDeadline+"=") {
		t.Errorf("env unexpectedly carries %s", envDeadline)
	}
	if !envHas(env, envBudget+"=1") {
		t.Errorf("env missing %s=1", envBudget)
	}
}

func TestDurationToWaitMillis(t *testing.T) {
	if got := durationToWaitMillis(0); got != 1 {
		t.Errorf("durationToWaitMillis(0) = %d, want 1", got)
	}
	if got := durationToWaitMillis(-time.Second); got != 1 {
		t.Errorf("durationToWaitMillis(-1s) = %d, want 1", got)
	}
	if got := durationToWaitMillis(1500 * time.Millisecond); got != 1500 {
		t.Errorf("durationToWaitMillis(1.5s) = %d, want 1500", got)
	}
	if got := durationToWaitMillis(1000 * time.Hour); got != windows.INFINITE-1 {
		t.Errorf("durationToWaitMillis(1000h) = %d, want %d", got, uint32(windows.INFINITE-1))
	}
}

func countEnv(env []string, key string) int {
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			n++
		}
	}
	return n
}

func envHas(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}
