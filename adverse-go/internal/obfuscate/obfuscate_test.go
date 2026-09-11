package obfuscate

import (
	"bytes"
	"testing"
)

func TestRotatingXOR_RoundTrip(t *testing.T) {
	for _, s := range []string{"hello", "ntdll.dll", "adverse/session/v2", "", "X25519_chacha20poly1305_NtSaveKey_Registry_Machine_SYSTEM"} {
		enc := RotatingXOR([]byte(s), 0x5A)
		// With data-dependent feedback, RotatingXOR is NOT self-inverse.
		// Decrypt via RotatingXORInPlace which mirrors the encrypt path.
		dec := make([]byte, len(enc))
		copy(dec, enc)
		RotatingXORInPlace(dec, 0x5A)
		if string(dec) != s {
			t.Fatalf("roundtrip failed %q got %q", s, string(dec))
		}
		SecureZero(dec)
		if !bytes.Equal(enc, RotatingXOR([]byte(s), 0x5A)) {
			t.Fatal("deterministic")
		}
	}
	// Build-seeded round-trip: RotatingXOR(0) encrypts with buildSeed();
	// DecryptInline decrypts with buildSeed(). Consistent within a process.
	for _, s := range []string{"test-build-seed"} {
		enc := RotatingXOR([]byte(s), 0)
		dec := DecryptInline(enc)
		if string(dec) != s {
			t.Fatalf("build-seed roundtrip failed %q got %q", s, string(dec))
		}
		SecureZero(dec)
	}
	// Verify RotatingXORInPlace is the inverse of RotatingXOR for all seeds.
	for _, seed := range []byte{0x01, 0x5A, 0xFF, 0x00} {
		for _, s := range []string{"a", "ab", "abc", "test123"} {
			enc := RotatingXOR([]byte(s), seed)
			dec := make([]byte, len(enc))
			copy(dec, enc)
			RotatingXORInPlace(dec, seed)
			if string(dec) != s {
				t.Fatalf("seed=%x roundtrip failed %q got %q", seed, s, string(dec))
			}
		}
	}
}

// TestStringTableIgnoresBuildSeed is the regression guard for the seed
// override bug: linking with
//
//	-ldflags "-X github.com/ashwnn/adverse-go/internal/obfuscate.BuildSeed=5a"
//
// must not change how Get decrypts the committed table. The table seed lives
// in stringtable_gen.go (genStringSeed) and is the only seed Get may use.
func TestStringTableIgnoresBuildSeed(t *testing.T) {
	old := BuildSeed
	BuildSeed = "5a"
	t.Cleanup(func() { BuildSeed = old })

	for id, want := range map[uint32]string{
		StrNtOpenKey:        "NtOpenKey",
		StrRegMachineSystem: "\\Registry\\Machine\\SYSTEM",
		StrAdversaryMagic:   "ADVERSARY",
	} {
		got, ok := Get(id)
		if !ok {
			t.Fatalf("Get(%#x) not found", id)
		}
		if got != want {
			t.Fatalf("Get(%#x) = %q, want %q (BuildSeed must not alter the string-table seed)", id, got, want)
		}
	}
}

func TestGeneratedStringTable(t *testing.T) {
	cases := map[uint32]string{
		StrNtdllDLL:         "ntdll.dll",
		StrNtSaveKey:        "NtSaveKey",
		StrNtOpenKey:        "NtOpenKey",
		StrRegMachineSystem: "\\Registry\\Machine\\SYSTEM",
		StrAdversaryMagic:   "ADVERSARY",
		StrSessionV2:        "adverse/session/v2",
		StrBootstrapMagic:   "adverse-bootstrap",
		StrAppOctetStream:   "application/octet-stream",
		StrX25519:           "X25519",
		StrChacha20Poly1305: "chacha20poly1305",
		StrGolang:           "golang",
	}
	for id, want := range cases {
		got, ok := Get(id)
		if !ok {
			t.Fatalf("Get(%#x) not found", id)
		}
		if got != want {
			t.Fatalf("Get(%#x) = %q, want %q", id, got, want)
		}
		// The committed table MUST store ciphertext, never the plaintext value.
		ct, ok := genStringTable[id]
		if !ok {
			t.Fatalf("genStringTable[%#x] missing", id)
		}
		if bytes.Equal(ct, []byte(want)) {
			t.Fatalf("genStringTable[%#x] stores plaintext %q!", id, want)
		}
	}
}

func TestOpaquePredicates(t *testing.T) {
	for _, seed := range []uint64{0, 1, 0xDEADBEEF, 0xFFFFFFFFFFFFFFFF} {
		if !OpaqueAlwaysTrue(seed) {
			t.Fatalf("always true failed %x", seed)
		}
		if OpaqueAlwaysFalse(seed) {
			t.Fatalf("always false failed %x", seed)
		}
	}
}

func TestFlattenedDispatcher_Permutes(t *testing.T) {
	d := FlattenedDispatcher(8, 0x1234)
	if len(d) != 8 {
		t.Fatal("len")
	}
	seen := map[int]bool{}
	for _, v := range d {
		if seen[v] {
			t.Fatal("dup")
		}
		seen[v] = true
	}
}

func TestDispatchWrappers(t *testing.T) {
	// HKDF
	out1, err := DispatchHKDF([]byte("ikm"), []byte("salt"), "info", 32)
	if err != nil || len(out1) != 32 {
		t.Fatalf("hkdf %v %d", err, len(out1))
	}
	// SHA256
	sum := DispatchSHA256([]byte("abc"))
	if len(sum) != 32 {
		t.Fatal("sha256 len")
	}
	// ChaCha AEAD
	aead, err := NewAEADIndirect(make([]byte, 32))
	if err != nil {
		t.Fatalf("aead %v", err)
	}
	if aead == nil {
		t.Fatal("nil aead")
	}
	// Append
	b := AppendUint32BE(nil, 0xDEADBEEF)
	if len(b) != 4 {
		t.Fatal("append")
	}
}

func TestJunkIsland(t *testing.T) {
	if JunkIsland(0xABCD, 3) != 1 {
		t.Fatal("JunkIsland(n>0) should be 1")
	}
	if JunkIsland(0xABCD, 1) != 1 {
		t.Fatal("JunkIsland(n=1) should be 1")
	}
	if JunkIsland(0xABCD, 0) != 0 {
		t.Fatal("JunkIsland(n=0) should be 0")
	}
	called := 0
	SplitFunction(func() { called++ }, func() { called++ })
	if called != 2 {
		t.Fatal("split")
	}
}

func TestObfuscatedCompare(t *testing.T) {
	if !ObfuscatedCompare([]byte("abc"), []byte("abc")) {
		t.Fatal("eq")
	}
	if ObfuscatedCompare([]byte("abc"), []byte("abd")) {
		t.Fatal("neq")
	}
}

func TestPolymorphicOverlay(t *testing.T) {
	b := PolymorphicOverlay(256)
	if len(b) != 256 {
		t.Fatal("len")
	}
	// not all zero
	allZero := true
	for _, c := range b {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("all zero")
	}
}
