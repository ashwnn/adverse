//go:build !windows

package persist

import "testing"

// On non-Windows hosts every valid non-none mode must degrade to a no-op
// manager: Arm reports success but never claims an artifact exists.
func TestNonWindowsManagersAreNoop(t *testing.T) {
	for _, mode := range []Mode{ModeWatchdog, ModeRunKey, ModeBoth} {
		m, err := New(Config{Mode: mode, ExePath: `C:\agent.exe`, Args: []string{"--resume"}})
		if err != nil {
			t.Fatalf("New(%q): %v", mode, err)
		}
		if m.Armed() {
			t.Fatalf("New(%q).Armed() = true before Arm", mode)
		}
		if err := m.Arm(); err != nil {
			t.Fatalf("New(%q).Arm(): %v", mode, err)
		}
		if m.Armed() {
			t.Fatalf("New(%q).Armed() = true on a non-Windows host", mode)
		}
		if err := m.Disarm(); err != nil {
			t.Fatalf("New(%q).Disarm(): %v", mode, err)
		}
	}
}
