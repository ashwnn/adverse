//go:build !windows

package persist

// newManager returns a no-op manager on non-Windows hosts: persistence
// targets Windows, and the caller's fail-closed guards remain authoritative.
// Arm succeeds but never reports armed, so a non-Windows run cannot pretend
// an artifact exists.
func newManager(cfg Config) (Manager, error) {
	return noopManager{}, nil
}

// MaybeRunWatchdogChild is a no-op off Windows: the watchdog is a Windows
// process-wait implementation, so there is never a child to handle.
func MaybeRunWatchdogChild() (handled bool, exitCode int) {
	return false, 0
}
