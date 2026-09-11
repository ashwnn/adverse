//go:build linux

package audit

import "syscall"

// lockBytes attempts to mlock pages to prevent them from being swapped to disk.
// Falls back silently if mlock is unavailable (e.g., ulimit -l).
func lockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = syscall.Mlock(b)
}

// unlockBytes releases mlocked pages.
func unlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = syscall.Munlock(b)
}
