//go:build !windows

package antiforensic

import (
	"io"
	"log"
	"testing"
)

// TestScrubNonWindowsNoop verifies that an enabled scrub is inert off Windows:
// the Windows trace surface does not exist, and Scrub must not touch anything.
func TestScrubNonWindowsNoop(t *testing.T) {
	r := Scrub(Config{
		Enabled: true,
		ExePath: "/opt/agent/agent",
		Args:    []string{"--profile=lab"},
		Logger:  log.New(io.Discard, "", 0),
	})
	assertEmptyReport(t, r)
}
