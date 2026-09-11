package audit

import (
	"bytes"
	"testing"
)

func TestNewSecureBuffer(t *testing.T) {
	sb, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("NewSecureBuffer failed: %v", err)
	}
	if sb == nil {
		t.Fatal("expected buffer")
	}
	if len(sb.Bytes()) != 1024 {
		t.Errorf("expected 1024 bytes, got %d", len(sb.Bytes()))
	}
}

func TestNewSecureBufferZeroSize(t *testing.T) {
	sb, err := NewSecureBuffer(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sb != nil {
		t.Error("expected nil for zero size")
	}
}

func TestSecureBufferWrite(t *testing.T) {
	sb, _ := NewSecureBuffer(1024)
	n, err := sb.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5, got %d", n)
	}
	if string(sb.Bytes()[:5]) != "hello" {
		t.Error("write content mismatch")
	}
}

func TestSecureBufferWriteRealloc(t *testing.T) {
	sb, _ := NewSecureBuffer(4)
	// Write more than 4 bytes triggers reallocation
	data := make([]byte, 100)
	for i := range data {
		data[i] = 'x'
	}
	n, _ := sb.Write(data)
	if n != 100 {
		t.Errorf("expected 100, got %d", n)
	}
	if len(sb.Bytes()) != 100 {
		t.Errorf("expected 100 bytes after realloc, got %d", len(sb.Bytes()))
	}
}

// TestSecureBufferWriteReallocKeepsLocked is the M4 regression: after a growth
// reallocation the NEW buffer must be locked again (mlock/VirtualLock), so the
// swapped-in memory is not silently left swappable.
func TestSecureBufferWriteReallocKeepsLocked(t *testing.T) {
	sb, _ := NewSecureBuffer(4)
	if !sb.locked {
		t.Fatal("new buffer should start locked")
	}
	sb.Write(make([]byte, 4096)) // forces reallocation
	if !sb.locked {
		t.Error("buffer must remain locked after reallocation (M4)")
	}
	sb.Free()
	if sb.locked {
		t.Error("buffer must be unlocked after Free")
	}
}

func TestSecureZeroBytes(t *testing.T) {
	b := []byte("sensitive data here")
	SecureZeroBytes(b)
	if !VerifyZeroed(b) {
		t.Error("expected zeroed after SecureZeroBytes")
	}
}

func TestSecureZeroBytesEmpty(t *testing.T) {
	SecureZeroBytes(nil)
	SecureZeroBytes([]byte{})
}

func TestSecureBufferSecureZero(t *testing.T) {
	sb, _ := NewSecureBuffer(1024)
	sb.Write([]byte("secret"))
	sb.SecureZero()
	if !VerifyZeroed(sb.Bytes()) {
		t.Error("expected zeroed after SecureZero")
	}
}

func TestSecureBufferFree(t *testing.T) {
	sb, _ := NewSecureBuffer(1024)
	sb.Write([]byte("secret"))
	sb.Free()
	if sb.Bytes() != nil {
		t.Error("expected nil after Free")
	}
}

func TestVerifyZeroed(t *testing.T) {
	if !VerifyZeroed(make([]byte, 100)) {
		t.Error("empty should be zeroed")
	}
	b := []byte{0, 0, 1, 0}
	if VerifyZeroed(b) {
		t.Error("should not be zeroed")
	}
	if !VerifyZeroed(nil) {
		t.Error("nil should be zeroed")
	}
}

func TestGenerateSyntheticHive(t *testing.T) {
	plain, sb, err := GenerateSyntheticHive("SYSTEM", 2048, "CANARY-test123")
	if err != nil {
		t.Fatalf("GenerateSyntheticHive failed: %v", err)
	}
	defer sb.Free()

	if string(plain[:4]) != "regf" {
		t.Errorf("expected regf, got %q", plain[:4])
	}
	if len(plain) != 2048 {
		t.Errorf("expected 2048, got %d", len(plain))
	}

	// Check canary embedded
	found := false
	for i := 0; i <= len(plain)-len("CANARY-test123"); i++ {
		if string(plain[i:i+len("CANARY-test123")]) == "CANARY-test123" {
			found = true
			break
		}
	}
	if !found {
		t.Error("canary not found in hive")
	}

	// Verify hive-specific marker for SYSTEM
	if string(plain[80:88]) != "BootKey:" {
		t.Errorf("expected BootKey: marker at offset 80, got %q", plain[80:88])
	}

	// Secure buffer should contain same regf header
	if string(sb.Bytes()[:4]) != "regf" {
		t.Error("secure buffer header mismatch")
	}
}

func TestGenerateSyntheticHiveSAM(t *testing.T) {
	plain, _, err := GenerateSyntheticHive("SAM", 1024, "CANARY-sam")
	if err != nil {
		t.Fatalf("GenerateSyntheticHive(SAM) failed: %v", err)
	}
	if string(plain[80:89]) != "UserNames" {
		t.Errorf("expected UserNames marker, got %q", plain[80:89])
	}
}

func TestGenerateSyntheticHiveSECURITY(t *testing.T) {
	plain, _, err := GenerateSyntheticHive("SECURITY", 1024, "CANARY-sec")
	if err != nil {
		t.Fatalf("GenerateSyntheticHive(SECURITY) failed: %v", err)
	}
	if string(plain[80:87]) != "Policy:" {
		t.Errorf("expected Policy: marker, got %q", plain[80:87])
	}
}

// TestGenerateSyntheticHiveCopiesIndependent pins the ownership contract:
// the returned plaintext slice and the SecureBuffer are separate allocations.
// Zeroing either one must not affect the other.
func TestGenerateSyntheticHiveCopiesIndependent(t *testing.T) {
	plain, sb, err := GenerateSyntheticHive("SYSTEM", 1024, "CANARY-ownership")
	if err != nil {
		t.Fatalf("GenerateSyntheticHive failed: %v", err)
	}
	defer sb.Free()

	// Zeroing the locked copy must not touch the returned slice.
	sb.SecureZero()
	if !VerifyZeroed(sb.Bytes()) {
		t.Fatal("SecureBuffer must be zeroed after SecureZero")
	}
	if !bytes.Contains(plain, []byte("CANARY-ownership")) {
		t.Fatal("zeroing SecureBuffer must not affect the returned plaintext copy")
	}

	// Zeroing the returned slice must not alter the locked copy.
	SecureZeroBytes(plain)
	if !VerifyZeroed(plain) {
		t.Fatal("returned plaintext must be independently zeroable by the caller")
	}
	if !VerifyZeroed(sb.Bytes()) {
		t.Fatal("zeroing the returned copy must not affect the SecureBuffer")
	}
}

func TestGenerateSyntheticHiveSmallSize(t *testing.T) {
	plain, sb, err := GenerateSyntheticHive("SYSTEM", 50, "CANARY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sb.Free()
	// Size should be bumped to 1024
	if len(plain) != 1024 {
		t.Errorf("expected 1024, got %d", len(plain))
	}
}

func TestSecureBufferNilBytes(t *testing.T) {
	var sb *SecureBuffer
	if sb.Bytes() != nil {
		t.Error("nil buffer Bytes should return nil")
	}
}
