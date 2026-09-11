//go:build windows

package antiforensic

import (
	"errors"
	"io"
	"log"
	"testing"

	"golang.org/x/sys/windows"
)

// These tests never exercise the destructive paths: they only cover guards
// that return before any file or registry mutation.

func TestScrubDisabledNoopWindows(t *testing.T) {
	r := Scrub(Config{
		Enabled: false,
		ExePath: `C:\Tools\agent.exe`,
		Args:    []string{"--profile=lab"},
		Logger:  log.New(io.Discard, "", 0),
	})
	assertEmptyReport(t, r)
}

func TestScrubEmptyExePathNoopWindows(t *testing.T) {
	r := Scrub(Config{Enabled: true, ExePath: ""})
	if len(r.Removed) != 0 || len(r.Errors) != 0 {
		t.Fatalf("empty ExePath must not remove or error: %+v", r)
	}
	if len(r.Skipped) == 0 {
		t.Fatalf("empty ExePath should be reported as skipped: %+v", r)
	}
}

func TestScrubDirectoryExePathNoopWindows(t *testing.T) {
	r := Scrub(Config{Enabled: true, ExePath: `C:\Tools\`})
	if len(r.Removed) != 0 || len(r.Errors) != 0 {
		t.Fatalf("directory ExePath must not remove or error: %+v", r)
	}
	if len(r.Skipped) == 0 {
		t.Fatalf("directory ExePath should be reported as skipped: %+v", r)
	}
}

func TestBenignTraceErrWindows(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"access denied", windows.ERROR_ACCESS_DENIED, true},
		{"sharing violation", windows.ERROR_SHARING_VIOLATION, true},
		{"lock violation", windows.ERROR_LOCK_VIOLATION, true},
		{"privilege not held", windows.ERROR_PRIVILEGE_NOT_HELD, true},
		{"file not found", windows.ERROR_FILE_NOT_FOUND, true},
		{"other", errors.New("unexpected"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := benignTraceErr(tc.err); got != tc.want {
			t.Errorf("benignTraceErr(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
