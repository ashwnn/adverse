//go:build !windows

package syscalls

// getTrampolinePool returns nil on non-Windows platforms. The simulated
// executeSyscall path (syscalls_other.go) never uses the pool; this accessor
// exists so the shared trampoline_pool.go types compile everywhere.
func getTrampolinePool() *trampolinePool {
	return nil
}
