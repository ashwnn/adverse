//go:build !windows

package hygiene

// Apply is a no-op on non-Windows platforms.
func Apply() {}
