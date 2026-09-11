//go:build !windows

package syscalls

import (
	"errors"
	"testing"
)

// TestSyscallInvocation verifies that every syscall returns ErrSimulation on
// non-Windows — never nil — so callers cannot silently assume a real kernel
// operation succeeded.
func TestSyscallInvocation(t *testing.T) {
	invoker := NewSyscallInvoker()

	tests := []struct {
		name    string
		syscall uint16
		args    []uintptr
	}{
		{"NtOpenKey", SysNtOpenKey, []uintptr{0, 0, 0}},
		{"NtClose", SysNtClose, []uintptr{0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := invoker.Invoke(tt.syscall, tt.args...)
			if err == nil {
				t.Errorf("%s: expected error on non-Windows; got nil (simulation was silent)", tt.name)
				return
			}
			if !errors.Is(err, ErrSimulation) {
				t.Errorf("%s: expected ErrSimulation, got: %v", tt.name, err)
			}
		})
	}
}

// TestSyscallSimulationReturnsErrSimulation verifies that every registered
// syscall returns ErrSimulation on non-Windows. This is the primary invariant
// that prevents callers from silently assuming a real kernel operation succeeded.
func TestSyscallSimulationReturnsErrSimulation(t *testing.T) {
	invoker := NewSyscallInvoker()

	// Every syscall number registered in NewSyscallInvoker must be covered.
	allSyscalls := []struct {
		name string
		num  uint16
		args []uintptr
	}{
		{"NtOpenKey", SysNtOpenKey, []uintptr{0, 0, 0}},
		{"NtClose", SysNtClose, []uintptr{0}},
		{"NtAllocateVirtualMemory", SysNtAllocateVirtualMemory, []uintptr{0, 0, 0, 0, 0}},
		{"NtFreeVirtualMemory", SysNtFreeVirtualMemory, []uintptr{0, 0, 0, 0}},
		{"NtProtectVirtualMemory", SysNtProtectVirtualMemory, []uintptr{0, 0, 0, 0, 0}},
		{"NtQuerySystemInformation", SysNtQuerySystemInformation, []uintptr{0, 0, 0, 0}},
		{"NtSaveKey", SysNtSaveKey, []uintptr{0, 0}},
		{"NtCreateFile", SysNtCreateFile, []uintptr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"NtOpenProcessToken", SysNtOpenProcessToken, []uintptr{0, 0, 0}},
		{"NtAdjustPrivilegesToken", SysNtAdjustPrivilegesToken, []uintptr{0, 0, 0, 0, 0, 0}},
		{"NtReadFile", SysNtReadFile, []uintptr{0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, tt := range allSyscalls {
		t.Run(tt.name, func(t *testing.T) {
			status, err := invoker.Invoke(tt.num, tt.args...)
			if err == nil {
				t.Errorf("%s: expected error on non-Windows; got status=0x%X, err=nil — simulation is silent",
					tt.name, status)
				return
			}
			if !errors.Is(err, ErrSimulation) {
				t.Errorf("%s: expected ErrSimulation, got: %v", tt.name, err)
			}
		})
	}
}

// TestSyscallSimulationArgValidation verifies that the simulation still
// validates argument counts before returning ErrSimulation.
func TestSyscallSimulationArgValidation(t *testing.T) {
	invoker := NewSyscallInvoker()

	_, err := invoker.Invoke(SysNtOpenKey) // needs 3 args, got 0
	if err == nil {
		t.Fatal("expected error for NtOpenKey with 0 args")
	}
	// The error should NOT be ErrSimulation — it's a caller-bug error.
	if errors.Is(err, ErrSimulation) {
		t.Error("arg-count error should not wrap ErrSimulation")
	}
}

// TestEnumerateProcessesSimulationReturnsError verifies that
// EnumerateProcesses returns an error on non-Windows rather than fake data.
func TestEnumerateProcessesSimulationReturnsError(t *testing.T) {
	invoker := NewSyscallInvoker()
	processes, err := invoker.EnumerateProcesses()
	if err == nil {
		t.Errorf("expected error on non-Windows; got %d processes, err=nil — simulation is silent",
			len(processes))
		return
	}
	if !errors.Is(err, ErrSimulation) {
		t.Errorf("expected ErrSimulation, got: %v", err)
	}
	if len(processes) != 0 {
		t.Errorf("expected nil process list on error, got %d entries", len(processes))
	}
}
