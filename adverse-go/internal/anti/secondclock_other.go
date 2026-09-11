//go:build !windows && !linux

package anti

// secondClockMS is a stub for platforms other than Windows and Linux.
func secondClockMS() (int64, bool) { return 0, false }
