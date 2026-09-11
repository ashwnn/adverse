// Package syscalls provides direct Windows syscall access for bypassing user-mode API hooks.
//
// Direct syscalls invoke the kernel via the SYSCALL instruction, bypassing hooked
// ntdll.dll user-mode functions. This avoids detection by products that hook
// user-mode API calls (e.g., RegOpenKeyEx, NtOpenKey in ntdll).
//
// IMPORTANT: Direct syscalls do NOT hide operations from:
//   - Kernel telemetry (ETW-TI, Kernel-Process, Kernel-Network, Kernel-Registry)
//   - Sysmon kernel callbacks (CmRegisterCallbackEx, ObRegisterCallbacks)
//   - Defender behavior monitoring (kernel-mode)
//   - MDE EDR correlation (kernel-mode)
//
// On non-Windows platforms, all syscalls are SIMULATED and return fake handles.
package syscalls

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unicode/utf16"
	"unsafe"
)

// Windows syscall numbers — reference values for fallback/simulation.
// At runtime, SSNs are resolved dynamically via stealth.SyscallResolver.
const (
	SysNtOpenKey                uint16 = 0x0019
	SysNtClose                  uint16 = 0x000F
	SysNtAllocateVirtualMemory  uint16 = 0x0018
	SysNtFreeVirtualMemory      uint16 = 0x001D
	SysNtProtectVirtualMemory   uint16 = 0x0050
	SysNtQuerySystemInformation uint16 = 0x0036
	SysNtSaveKey                uint16 = 0x0100
	SysNtCreateFile             uint16 = 0x0052
	// Real extraction syscalls
	SysNtOpenProcessToken      uint16 = 0x00F9
	SysNtAdjustPrivilegesToken uint16 = 0x0128
	SysNtReadFile              uint16 = 0x0006
)

// Registry access masks
const (
	KEY_READ       = 0x20019
	KEY_WRITE      = 0x20006
	KEY_ALL_ACCESS = 0xF003F
)

// NT status codes
const (
	STATUS_SUCCESS              = 0x00000000
	STATUS_BUFFER_TOO_SMALL     = 0xC0000023
	STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
)

// File creation constants for NtCreateFile
const (
	FILE_GENERIC_READ         = 0x00120089
	FILE_GENERIC_WRITE        = 0x00120116
	FILE_ATTRIBUTE_TEMPORARY  = 0x100
	FILE_ATTRIBUTE_HIDDEN     = 0x00000002
	FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
	FILE_SUPERSEDE            = 0x00000000
	FILE_OPEN_IF              = 0x00000003
	FILE_CREATE               = 0x00000002
	FILE_OPEN                 = 0x00000000
)

// File sharing and option constants
const (
	FILE_SHARE_READ                = 0x00000001
	FILE_SHARE_WRITE               = 0x00000002
	FILE_SHARE_DELETE              = 0x00000004
	FILE_NON_DIRECTORY_FILE        = 0x00000040
	FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020
	FILE_DELETE_ON_CLOSE_CREATEOPT = 0x00001000
	// FILE_DELETE is the DELETE access right (0x00010000), required by
	// FILE_FLAG_DELETE_ON_CLOSE (declared with the file creation constants).
	FILE_DELETE = 0x00010000
)

// Token access constants
const (
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008
	SE_PRIVILEGE_ENABLED    = 0x00000002
)

// Process access constants (for NtOpenProcessToken with pseudo-handle)
const (
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

// NT_SUCCESS returns true if status is a success code.
func NT_SUCCESS(status uintptr) bool { return status&0x80000000 == 0 }

// NTStatusString returns a human-readable description of common NTSTATUS codes.
func NTStatusString(status uintptr) string {
	switch status {
	case 0x00000000:
		return "STATUS_SUCCESS"
	case 0xC0000004:
		return "STATUS_INFO_LENGTH_MISMATCH"
	case 0xC0000005:
		return "STATUS_ACCESS_VIOLATION"
	case 0xC0000008:
		return "STATUS_INVALID_HANDLE"
	case 0xC000000D:
		return "STATUS_INVALID_PARAMETER"
	case 0xC0000022:
		return "STATUS_ACCESS_DENIED"
	case 0xC0000023:
		return "STATUS_BUFFER_TOO_SMALL"
	case 0xC0000034:
		return "STATUS_OBJECT_NAME_NOT_FOUND"
	case 0xC0000035:
		return "STATUS_OBJECT_NAME_COLLISION"
	case 0xC0000061:
		return "STATUS_PRIVILEGE_NOT_HELD"
	default:
		return "UNKNOWN"
	}
}

// Memory constants
const (
	PAGE_READWRITE    = 0x04
	PAGE_EXECUTE_READ = 0x20
	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	MEM_RELEASE       = 0x8000
)

// UnicodeString represents the Windows UNICODE_STRING structure.
// Buffer is an unsafe.Pointer so the GC traces it and keeps the UTF-16
// backing array alive as long as the UnicodeString is reachable.
type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte
	Buffer        unsafe.Pointer
}

// ObjectAttributes represents OBJECT_ATTRIBUTES
type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *UnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// IoStatusBlock represents the NT IO_STATUS_BLOCK structure (x64 layout).
type IoStatusBlock struct {
	Status      uintptr // union: NTSTATUS or Pointer (pointer-sized on x64)
	Information uintptr
}

// LUID represents a locally unique identifier.
type LUID struct {
	LowPart  uint32
	HighPart int32
}

// TOKEN_PRIVILEGES represents the NT TOKEN_PRIVILEGES structure.
type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Luid           LUID
	Attributes     uint32
}

// SyscallInvoker provides direct syscall invocation
type SyscallInvoker struct {
	mu     sync.RWMutex
	stubs  map[uint16]*syscallStub
	loaded bool
}

type syscallStub struct {
	number   uint16
	argCount int
	assembly []byte
}

var (
	globalInvoker *SyscallInvoker
	once          sync.Once
)

// GetInvoker returns the global syscall invoker (singleton)
func GetInvoker() *SyscallInvoker {
	once.Do(func() {
		globalInvoker = NewSyscallInvoker()
	})
	return globalInvoker
}

// NewSyscallInvoker creates a new syscall invoker with all required stubs
func NewSyscallInvoker() *SyscallInvoker {
	invoker := &SyscallInvoker{
		stubs: make(map[uint16]*syscallStub),
	}

	syscalls := []struct {
		number   uint16
		argCount int
	}{
		{SysNtOpenKey, 3},
		{SysNtClose, 1},
		{SysNtAllocateVirtualMemory, 5},
		{SysNtFreeVirtualMemory, 4},
		{SysNtProtectVirtualMemory, 5},
		{SysNtQuerySystemInformation, 4},
		{SysNtSaveKey, 2},
		{SysNtCreateFile, 11},
		// Real extraction syscalls
		{SysNtOpenProcessToken, 3},
		{SysNtAdjustPrivilegesToken, 6},
		{SysNtReadFile, 9},
	}

	for _, s := range syscalls {
		invoker.stubs[s.number] = &syscallStub{
			number:   s.number,
			argCount: s.argCount,
			assembly: generateSyscallStub(s.number),
		}
	}

	invoker.loaded = true
	return invoker
}

// generateSyscallStub generates x86-64 syscall stub assembly
func generateSyscallStub(syscallNum uint16) []byte {
	stub := make([]byte, 0, 64)
	// Prologue: save callee-saved registers
	stub = append(stub, 0x48, 0x89, 0x5c, 0x24, 0x08) // mov [rsp+8], rbx
	stub = append(stub, 0x48, 0x89, 0x6c, 0x24, 0x10) // mov [rsp+10h], rbp
	stub = append(stub, 0x48, 0x89, 0x74, 0x24, 0x18) // mov [rsp+18h], rsi
	// Load syscall number
	stub = append(stub, 0x48, 0xc7, 0xc0)
	stub = binary.LittleEndian.AppendUint32(stub, uint32(syscallNum))
	// SYSCALL
	stub = append(stub, 0x0f, 0x05)
	// Epilogue: restore registers
	stub = append(stub, 0x48, 0x8b, 0x5c, 0x24, 0x08) // mov rbx, [rsp+8]
	stub = append(stub, 0x48, 0x8b, 0x6c, 0x24, 0x10) // mov rbp, [rsp+10h]
	stub = append(stub, 0x48, 0x8b, 0x74, 0x24, 0x18) // mov rsi, [rsp+18h]
	stub = append(stub, 0xc3)                         // ret
	return stub
}

// Invoke executes a direct syscall with the given arguments
func (s *SyscallInvoker) Invoke(syscallNum uint16, args ...uintptr) (uintptr, error) {
	s.mu.RLock()
	stub, ok := s.stubs[syscallNum]
	s.mu.RUnlock()

	if !ok {
		return 0, fmt.Errorf("unknown syscall: 0x%04x", syscallNum)
	}
	return s.executeSyscall(stub, args)
}

// GetStubAssembly returns the raw assembly bytes for a syscall
func (s *SyscallInvoker) GetStubAssembly(syscallNum uint16) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stub, ok := s.stubs[syscallNum]
	if !ok {
		return nil, fmt.Errorf("unknown syscall: 0x%04x", syscallNum)
	}
	return stub.assembly, nil
}

// Name returns the human-readable name for a syscall number
func (s *SyscallInvoker) Name(syscallNum uint16) string {
	if name, ok := SyscallNames[syscallNum]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04x)", syscallNum)
}

// UnicodeStringFromGo creates a UnicodeString from a Go string.
// Uses unicode/utf16.Encode for correct UTF-16 encoding including surrogates.
// The returned UnicodeString's Buffer is an unsafe.Pointer that keeps the
// UTF-16 backing array alive as long as the UnicodeString is reachable. Callers
// that pass the resulting ObjectAttributes to a syscall via uintptr must keep
// the UnicodeString and its backing array alive with runtime.KeepAlive until
// after the syscall returns.
func UnicodeStringFromGo(s string) UnicodeString {
	encoded := utf16.Encode([]rune(s))
	// Append explicit NUL terminator.
	encoded = append(encoded, 0)
	// Length is the byte count of the UTF-16 encoded string (excluding NUL terminator).
	size := uint16(len(encoded)-1) * 2
	// The encoded slice's backing array escapes to the heap because its
	// address is stored in the returned struct's Buffer (unsafe.Pointer). The GC
	// will keep it alive as long as the UnicodeString is reachable.
	return UnicodeString{
		Length:        size,
		MaximumLength: size + 2,
		Buffer:        unsafe.Pointer(&encoded[0]),
	}
}

// OwnedUnicodeString bundles a UnicodeString with its backing UTF-16 buffer so
// callers can keep the buffer alive with runtime.KeepAlive.
type OwnedUnicodeString struct {
	US  UnicodeString
	Buf []uint16
}

// OwnedObjectAttributes bundles an ObjectAttributes with its name string storage.
type OwnedObjectAttributes struct {
	OA      ObjectAttributes
	NameUS  UnicodeString
	NameBuf []uint16
}

// UnicodeStringFromGoOwned creates a UnicodeString and retains its backing slice.
func UnicodeStringFromGoOwned(s string) OwnedUnicodeString {
	encoded := utf16.Encode([]rune(s))
	encoded = append(encoded, 0)
	size := uint16(len(encoded)-1) * 2
	us := UnicodeString{
		Length:        size,
		MaximumLength: size + 2,
		Buffer:        unsafe.Pointer(&encoded[0]),
	}
	return OwnedUnicodeString{US: us, Buf: encoded}
}

// ObjectAttributesFromNameOwned creates an ObjectAttributes and retains the name buffer.
func ObjectAttributesFromNameOwned(name string) OwnedObjectAttributes {
	ous := UnicodeStringFromGoOwned(name)
	oa := ObjectAttributes{
		Length:     uint32(unsafe.Sizeof(ObjectAttributes{})),
		ObjectName: &ous.US,
		Attributes: 0x40, // OBJ_CASE_INSENSITIVE
	}
	return OwnedObjectAttributes{OA: oa, NameUS: ous.US, NameBuf: ous.Buf}
}

// ObjectAttributesFromName creates ObjectAttributes for a named object.
// It is kept for compatibility; prefer ObjectAttributesFromNameOwned when the
// attributes are passed to a syscall via uintptr so you can KeepAlive the buffer.
func ObjectAttributesFromName(name string) ObjectAttributes {
	us := UnicodeStringFromGo(name)
	return ObjectAttributes{
		Length:     uint32(unsafe.Sizeof(ObjectAttributes{})),
		ObjectName: &us,
		Attributes: 0x40, // OBJ_CASE_INSENSITIVE
	}
}

// SyscallNames maps syscall numbers to human-readable names.
var SyscallNames = map[uint16]string{
	SysNtOpenKey:                "NtOpenKey",
	SysNtClose:                  "NtClose",
	SysNtAllocateVirtualMemory:  "NtAllocateVirtualMemory",
	SysNtFreeVirtualMemory:      "NtFreeVirtualMemory",
	SysNtProtectVirtualMemory:   "NtProtectVirtualMemory",
	SysNtQuerySystemInformation: "NtQuerySystemInformation",
	SysNtSaveKey:                "NtSaveKey",
	SysNtCreateFile:             "NtCreateFile",
	SysNtOpenProcessToken:       "NtOpenProcessToken",
	SysNtAdjustPrivilegesToken:  "NtAdjustPrivilegesToken",
	SysNtReadFile:               "NtReadFile",
}
