//go:build !windows

package syscalls

import (
	"errors"
	"fmt"
)

// ErrSimulation is returned by all non-Windows syscall simulations.
// Callers must not treat a nil error as success on non-Windows platforms;
// every return through this path signals that no real kernel operation was performed.
var ErrSimulation = errors.New("syscalls: non-Windows simulation does not perform real operations")

// executeSyscall SIMULATES syscall execution on non-Windows platforms.
// It always returns ErrSimulation so callers cannot silently assume success.
// Argument counts are still validated to catch caller bugs early.
func (s *SyscallInvoker) executeSyscall(stub *syscallStub, args []uintptr) (uintptr, error) {
	name := SyscallNames[stub.number]
	if name == "" {
		name = fmt.Sprintf("Unknown(0x%04x)", stub.number)
	}

	// Validate argument count to catch caller bugs (same as Windows path).
	if len(args) < stub.argCount {
		return 0, fmt.Errorf("%s: requires %d arguments, got %d", name, stub.argCount, len(args))
	}

	// All syscalls are simulated on non-Windows — never return nil error.
	return 0, fmt.Errorf("%s: %w", name, ErrSimulation)
}

// EnumerateProcesses is not supported on non-Windows platforms.
// It returns ErrSimulation instead of fake data so callers cannot
// silently proceed with fabricated process information.
func (s *SyscallInvoker) EnumerateProcesses() ([]ProcessEntry, error) {
	return nil, fmt.Errorf("EnumerateProcesses: %w", ErrSimulation)
}

// ProcessEntry represents a process from system enumeration.
type ProcessEntry struct {
	PID  uint32
	Name string
}

// EnableSeBackupPrivilege is not available on non-Windows platforms.
func EnableSeBackupPrivilege(invoker *SyscallInvoker) error {
	return fmt.Errorf("EnableSeBackupPrivilege: not supported on non-Windows")
}
