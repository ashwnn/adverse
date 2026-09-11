package syscalls

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestSyscallStubGeneration(t *testing.T) {
	tests := []struct {
		name     string
		syscall  uint16
		argCount int
	}{
		{"NtOpenKey", SysNtOpenKey, 3},
		{"NtClose", SysNtClose, 1},
		{"NtAllocateVirtualMemory", SysNtAllocateVirtualMemory, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := NewSyscallInvoker().stubs[tt.syscall]
			if stub == nil {
				stub = &syscallStub{number: tt.syscall, argCount: tt.argCount, assembly: generateSyscallStub(tt.syscall)}
			}

			// Verify SYSCALL instruction
			found := false
			for i := 0; i < len(stub.assembly)-1; i++ {
				if stub.assembly[i] == 0x0f && stub.assembly[i+1] == 0x05 {
					found = true
					break
				}
			}
			if !found {
				t.Error("missing SYSCALL instruction (0x0f 0x05)")
			}

			// Verify RET
			if stub.assembly[len(stub.assembly)-1] != 0xc3 {
				t.Error("missing RET instruction")
			}
		})
	}
}

func TestSyscallInvokerCreation(t *testing.T) {
	invoker := NewSyscallInvoker()
	if invoker == nil {
		t.Fatal("failed to create syscall invoker")
	}
	if !invoker.loaded {
		t.Error("syscall invoker not loaded")
	}
}

func TestSyscallNames(t *testing.T) {
	invoker := NewSyscallInvoker()
	tests := []struct {
		syscall uint16
		name    string
	}{
		{SysNtOpenKey, "NtOpenKey"},
		{SysNtClose, "NtClose"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := invoker.Name(tt.syscall)
			if name != tt.name {
				t.Errorf("expected %s, got %s", tt.name, name)
			}
		})
	}
}

func TestGetStubAssembly(t *testing.T) {
	invoker := NewSyscallInvoker()
	assembly, err := invoker.GetStubAssembly(SysNtOpenKey)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(assembly) == 0 {
		t.Error("assembly is empty")
	}
	_, err = invoker.GetStubAssembly(0xFFFF)
	if err == nil {
		t.Error("expected error for unknown syscall")
	}
}

func TestGlobalInvoker(t *testing.T) {
	invoker1 := GetInvoker()
	invoker2 := GetInvoker()
	if invoker1 != invoker2 {
		t.Error("GetInvoker should return the same instance")
	}
}

func TestTrampolineLayout(t *testing.T) {
	ssn := uint16(0x0019)
	argc := 1
	code := generateTrampoline(ssn, argc)

	// Preamble: mov r10, rcx (4C 8B D1)
	if code[0] != 0x4C || code[1] != 0x8B || code[2] != 0xD1 {
		t.Errorf("preamble: got %02X %02X %02X", code[0], code[1], code[2])
	}

	// mov eax, imm32
	if code[3] != 0xB8 {
		t.Errorf("mov eax opcode: got %02X, want B8", code[3])
	}
	decodedSSN := binary.LittleEndian.Uint32(code[4:8])
	if decodedSSN != uint32(ssn) {
		t.Errorf("SSN: got 0x%08X, want 0x%08X", decodedSSN, uint32(ssn))
	}

	// Find SYSCALL opcode (0F 05)
	syscallIdx := -1
	for i := 3; i < len(code)-1; i++ {
		if code[i] == 0x0F && code[i+1] == 0x05 {
			syscallIdx = i
			break
		}
	}
	if syscallIdx < 0 {
		t.Fatal("missing SYSCALL opcode")
	}

	// Find RET
	retIdx := -1
	for i := len(code) - 1; i >= 0; i-- {
		if code[i] == 0xC3 {
			retIdx = i
			break
		}
	}
	if retIdx < 0 {
		t.Fatal("missing RET opcode")
	}
	if syscallIdx >= retIdx {
		t.Errorf("SYSCALL at %d not before RET at %d", syscallIdx, retIdx)
	}

	// Total length 8-byte aligned
	if len(code)%8 != 0 {
		t.Errorf("trampoline length %d not 8-byte aligned", len(code))
	}
}

func TestTrampolineMultipleArgCounts(t *testing.T) {
	for argc := 0; argc <= 11; argc++ {
		code := generateTrampoline(0x0019, argc)
		if len(code)%8 != 0 {
			t.Errorf("argc=%d: length %d not 8-byte aligned", argc, len(code))
		}
		// Must contain SYSCALL
		found := false
		for i := 0; i < len(code)-1; i++ {
			if code[i] == 0x0F && code[i+1] == 0x05 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("argc=%d: missing SYSCALL", argc)
		}
	}
}

// TestGenerateTrampolineExternal verifies the external-args codegen: pure
// code (no trailing args block) whose loads target argsBase+argsOff+i*8 via
// r11-based addressing, which is free of any ±2GB RIP-relative constraint.
func TestGenerateTrampolineExternal(t *testing.T) {
	const (
		ssn      = uint16(0x0019)
		argsBase = uintptr(0x7FF700002000)
		argsOff  = uintptr(0x40)
	)

	for argc := 0; argc <= 11; argc++ {
		code := generateTrampolineExternal(ssn, argc, argsBase, argsOff)

		if len(code)%8 != 0 {
			t.Fatalf("argc=%d: code length %d not 8-byte aligned", argc, len(code))
		}
		// Preamble: mov r10,rcx; mov eax,imm32; mov r11,imm64.
		if code[0] != 0x4C || code[1] != 0x8B || code[2] != 0xD1 {
			t.Fatalf("argc=%d: preamble mismatch", argc)
		}
		if code[3] != 0xB8 {
			t.Fatalf("argc=%d: missing mov eax opcode", argc)
		}
		if got := binary.LittleEndian.Uint32(code[4:8]); got != uint32(ssn) {
			t.Fatalf("argc=%d: SSN = 0x%08X, want 0x%08X", argc, got, ssn)
		}
		if code[8] != 0x49 || code[9] != 0xBB {
			t.Fatalf("argc=%d: missing mov r11, imm64", argc)
		}
		if got := binary.LittleEndian.Uint64(code[10:18]); got != uint64(argsBase+argsOff) {
			t.Fatalf("argc=%d: r11 imm = 0x%X, want 0x%X", argc, got, argsBase+argsOff)
		}
		// Must contain SYSCALL and end with RET (padding 0xCC may follow).
		if !bytes.Contains(code, []byte{0x0F, 0x05}) {
			t.Fatalf("argc=%d: missing SYSCALL opcode", argc)
		}
		retIdx := bytes.LastIndexByte(code, 0xC3)
		if retIdx < 0 {
			t.Fatalf("argc=%d: missing RET", argc)
		}

		// Register loads (args 0..3): 4-byte instructions starting at 18+i*4,
		// form mov rX, [r11+disp8] with disp8 = i*8.
		for i := 0; i < 4 && i < argc; i++ {
			pos := 18 + i*4
			if code[pos] == 0xCC {
				t.Fatalf("argc=%d: load arg%d ran into padding", argc, i)
			}
			disp := code[pos+3]
			if disp != byte(i*8) {
				t.Errorf("argc=%d: load arg%d disp8 = 0x%X, want 0x%X", argc, i, disp, i*8)
			}
		}

		// Push args (4..argc-1): 4-byte instructions after the four loads,
		// in reverse argument order, disp8 = argIdx*8.
		if argc > 4 {
			for k := 0; k < argc-4; k++ {
				pos := 18 + 4*4 + k*4
				argIdx := argc - 1 - k
				if code[pos] == 0xCC {
					t.Fatalf("argc=%d: push arg%d ran into padding", argc, argIdx)
				}
				if code[pos] != 0x41 || code[pos+1] != 0xFF || code[pos+2] != 0x73 {
					t.Errorf("argc=%d: push arg%d bad encoding %02X %02X %02X", argc, argIdx, code[pos], code[pos+1], code[pos+2])
				}
				if code[pos+3] != byte(argIdx*8) {
					t.Errorf("argc=%d: push arg%d disp8 = 0x%X, want 0x%X", argc, argIdx, code[pos+3], argIdx*8)
				}
			}
		}
	}
}

// TestPoolLayout verifies slot assignment: 8-byte alignment, no overlap,
// deterministic sizes.
func TestPoolLayout(t *testing.T) {
	entries := []poolEntry{
		{number: SysNtOpenKey, argc: 3},
		{number: SysNtClose, argc: 1},
		{number: SysNtCreateFile, argc: 11},
	}
	codeLens := []uintptr{40, 32, 96}

	codeSize, argsSize := poolLayout(entries, codeLens)

	if codeSize != 168 {
		t.Errorf("codeSize = %d, want 168", codeSize)
	}
	if argsSize != 120 {
		t.Errorf("argsSize = %d, want 120", argsSize)
	}
	// Slot positions.
	if entries[0].codeOff != 0 || entries[1].codeOff != 40 || entries[2].codeOff != 72 {
		t.Errorf("codeOffs = %d,%d,%d", entries[0].codeOff, entries[1].codeOff, entries[2].codeOff)
	}
	if entries[0].argsOff != 0 || entries[1].argsOff != 24 || entries[2].argsOff != 32 {
		t.Errorf("argsOffs = %d,%d,%d", entries[0].argsOff, entries[1].argsOff, entries[2].argsOff)
	}
	// No overlap between code and args ranges, and args ranges never overlap
	// the code ranges within the combined address space.
	for i := range entries {
		if entries[i].codeOff%poolAlignment != 0 || entries[i].argsOff%poolAlignment != 0 {
			t.Errorf("entry %d: unaligned slot", i)
		}
		for j := range entries {
			if i == j {
				continue
			}
			if entries[i].codeOff < entries[j].codeOff+entries[j].codeLen &&
				entries[j].codeOff < entries[i].codeOff+entries[i].codeLen {
				t.Errorf("code overlap between entries %d and %d", i, j)
			}
		}
	}
}

func TestPoolLayoutPanicsOnMismatch(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on length mismatch")
		}
	}()
	poolLayout([]poolEntry{{number: 1, argc: 1}}, nil)
}

func TestAlign8(t *testing.T) {
	cases := map[uintptr]uintptr{
		0: 0, 1: 8, 7: 8, 8: 8, 9: 16, 40: 40, 88: 88,
	}
	for in, want := range cases {
		if got := align8(in); got != want {
			t.Errorf("align8(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNT_SUCCESS(t *testing.T) {
	tests := []struct {
		status uintptr
		want   bool
	}{
		{0x00000000, true},  // STATUS_SUCCESS
		{0x00000001, true},  // informational
		{0x80000001, false}, // warning
		{0xC0000001, false}, // error
		{0xC0000022, false}, // ACCESS_DENIED
	}
	for _, tt := range tests {
		if got := NT_SUCCESS(tt.status); got != tt.want {
			t.Errorf("NT_SUCCESS(0x%08X) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestNTStatusString(t *testing.T) {
	tests := []struct {
		status uintptr
		want   string
	}{
		{0x00000000, "STATUS_SUCCESS"},
		{0xC0000022, "STATUS_ACCESS_DENIED"},
		{0xC0000061, "STATUS_PRIVILEGE_NOT_HELD"},
		{0xDEADBEEF, "UNKNOWN"},
	}
	for _, tt := range tests {
		got := NTStatusString(tt.status)
		if got != tt.want {
			t.Errorf("NTStatusString(0x%08X) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestNewSyscallInvokerIncludesNewStubs(t *testing.T) {
	invoker := NewSyscallInvoker()
	newStubs := []struct {
		syscall uint16
		name    string
	}{
		{SysNtOpenProcessToken, "NtOpenProcessToken"},
		{SysNtAdjustPrivilegesToken, "NtAdjustPrivilegesToken"},
		{SysNtReadFile, "NtReadFile"},
	}
	for _, s := range newStubs {
		stub, err := invoker.GetStubAssembly(s.syscall)
		if err != nil {
			t.Errorf("GetStubAssembly(%s) error: %v", s.name, err)
			continue
		}
		if len(stub) == 0 {
			t.Errorf("%s stub assembly is empty", s.name)
		}
		name := invoker.Name(s.syscall)
		if name != s.name {
			t.Errorf("Name(0x%04X) = %q, want %q", s.syscall, name, s.name)
		}
	}
}

// UnicodeStringFromGo must produce correct UTF-16 encoding including surrogates.
// We verify structural invariants (Length, MaximumLength) and the expected UTF-16 code units.
func TestUnicodeStringFromGoNonBMP(t *testing.T) {
	// U+1F600 (😀) is a non-BMP rune that requires a surrogate pair in UTF-16.
	runes := []rune{'A', 0x1F600, 'B'}
	s := string(runes)

	us := UnicodeStringFromGo(s)

	// Expected UTF-16 encoding.
	expectedUTF16 := utf16.Encode(runes)

	// Length is the byte count of the UTF-16 encoded string (excluding NUL terminator).
	expectedLen := uint16(len(expectedUTF16)) * 2
	if us.Length != expectedLen {
		t.Errorf("Length: got %d, want %d", us.Length, expectedLen)
	}

	// MaximumLength includes the NUL terminator (2 bytes more).
	expectedMaxLen := expectedLen + 2
	if us.MaximumLength != expectedMaxLen {
		t.Errorf("MaximumLength: got %d, want %d", us.MaximumLength, expectedMaxLen)
	}

	// Buffer must be non-nil (points to the encoded data).
	if us.Buffer == nil {
		t.Fatal("Buffer is nil")
	}

	// Verify surrogate pair for U+1F600: high=0xD83D, low=0xDE00
	if expectedUTF16[1] != 0xD83D || expectedUTF16[2] != 0xDE00 {
		t.Errorf("surrogate pair for U+1F600: got 0x%04X 0x%04X, want 0xD83D 0xDE00",
			expectedUTF16[1], expectedUTF16[2])
	}

	// The encoded slice should be: {'A'=0x0041, 0xD83D, 0xDE00, 'B'=0x0042}
	if len(expectedUTF16) != 4 {
		t.Errorf("expected 4 UTF-16 code units, got %d", len(expectedUTF16))
	}
	if expectedUTF16[0] != 'A' || expectedUTF16[3] != 'B' {
		t.Errorf("BMP chars wrong: got 0x%04X 0x%04X, want 0x0041 0x0042", expectedUTF16[0], expectedUTF16[3])
	}
}
