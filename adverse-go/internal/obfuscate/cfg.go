package obfuscate

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

// Opaque predicate and control-flow flattening primitives.
// These defeat pattern-matching and bytecode/IL analysis by inserting
// branches that are dynamically constant but statically under-determined.

// OpaqueAlwaysTrue returns true for every input, but the compiler and
// Ghidra's data-flow analysis cannot prove it without emulating the hash.
// Uses a cheap mixing function so compilation does not optimize it away.
//
//go:noinline
func OpaqueAlwaysTrue(seed uint64) bool {
	x := seed ^ 0xA5A5A5A5A5A5A5A5
	x ^= x >> 33
	x *= 0xFF51AFD7ED558CCD
	x ^= x >> 33
	// ((x|1)+1)>1 is always true for uint64, but requires bit reasoning to prove.
	return ((x | 0x1) + 1) > 1
}

// OpaqueAlwaysFalse is the dual — proves false only via emulation.
//
//go:noinline
func OpaqueAlwaysFalse(seed uint64) bool { return !OpaqueAlwaysTrue(seed ^ 0xDEADBEEFCAFEBABE) }

// FlattenedDispatcher implements control-flow flattening. The caller drives
// a state machine: for { next = dispatch[state]; switch next { ... } }.
// Each block index is shuffled with the per-build seed so Ghidra's
// recovered switch does not map 1:1 to source ordering.
//
//go:noinline
func FlattenedDispatcher(blocks int, seed uint64) []int {
	if blocks <= 0 {
		return nil
	}
	order := make([]int, blocks)
	for i := range order {
		order[i] = i
	}
	r := rand.New(rand.NewSource(int64(seed ^ 0x123456789ABCDEF0)))
	r.Shuffle(blocks, func(i, j int) { order[i], order[j] = order[j], order[i] })
	return order
}

// JunkWork performs useless arithmetic that survives in bytecode but is
// removed by the CPU branch predictor. Useful to inflate function size and
// break function-hash signatures (e.g., TLSH, ssdeep) used by VT.
//
//go:noinline
func JunkWork(iter int, seed uint64) uint64 {
	var acc uint64 = seed ^ 0x9E3779B97F4A7C15
	for i := 0; i < iter; i++ {
		acc ^= uint64(i) * 0x9E3779B97F4A7C15
		acc = (acc << 13) | (acc >> 51)
		if OpaqueAlwaysTrue(acc) {
			acc += 0x7F4A7C15
		}
	}
	return acc
}

// ---------- Indirect dispatch table ----------
//
// Design: each stdlib/crypto call is wrapped in a //go:noinline function so its
// body (the real call) is isolated in a separate symbol. The wrappers are
// collected into a slice, and their PHYSICAL order is shuffled per build via
// FlattenedDispatcher. Dispatch functions index the shuffled slice by a stable
// LOGICAL id and call the wrapper through an interface value — an indirect
// call, not a direct `CALL chacha20poly1305.New` mnemonic at the call site.
//
// Hardening (vs. upstream):
//   - Table construction happens once during package init(), and the wrapper
//     slice is shuffled with a seed derived from the build seed mixed with a
//     derived XOR key, so the physical layout is a runtime product of both
//     values rather than source order.
//   - Call sites invoke wrappers through interface values, so no direct
//     `CALL hkdf.Key` / `CALL chacha20poly1305.New` mnemonic appears at the
//     call site.
//
// Honest assessment: this breaks naive static CALL-graph / YARA call-site
// patterns.  The wrapper still contains a direct call to the real symbol.
// Fully hiding the symbol also requires garble `-tiny` / pclntab stripping.
// This is defense-in-depth alongside YARA string encryption and pclntab
// minimization — not a standalone evasion.

//go:noinline
func hkdfKeyWrapper(h func() hash.Hash, ikm, salt []byte, info string, n int) ([]byte, error) {
	return hkdf.Key(h, ikm, salt, info, n)
}

//go:noinline
func chaChaNewWrapper(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

//go:noinline
func x25519GenWrapper(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(pub)
}

//go:noinline
func sha256SumWrapper(data []byte) [32]byte {
	return sha256.Sum256(data)
}

//go:noinline
func binaryBEAppendUint32Wrapper(b []byte, v uint32) []byte {
	return binary.BigEndian.AppendUint32(b, v)
}

// Logical slot indices (stable API).
const (
	IdxHKDFKey    = 0
	IdxChaChaNew  = 1
	IdxX25519Gen  = 2
	IdxSHA256Sum  = 3
	IdxBEAppend32 = 4
	numDispatch   = 5
)

// dispatch holds wrapper function values in shuffled (physical) order.
var dispatch []any

// dispatchPerm maps logical slot index -> physical slot index.
var dispatchPerm []int

// dispatchSeed is derived from BuildSeed for per-build uniqueness.
var dispatchSeed uint64

// dispatchXORKey is derived from dispatchSeed; mixed into the FlattenedDispatcher
// seed so the physical table layout depends on both values.
var dispatchXORKey uint64

// initDispatch builds the dispatch table. Called exactly once from init().
func initDispatch() {
	// Derive seed from BuildSeed mixed with a fixed mixer; per-artifact unique.
	var s uint64 = uint64(buildSeed())<<56 | 0x4F52_4353_4341_5452
	if s == 0x4F52435343415452 {
		s ^= 0xA53C_9E7D_1F2B_4C8A
	}
	dispatchSeed = s

	// Derive XOR key for secondary shuffle perturbation.  Mixed into the
	// FlattenedDispatcher seed so the physical layout varies even when the
	// primary seed is known, requiring an analyst to resolve both values.
	xorKey := s ^ 0x6B3E_7D2F_A1C8_9457
	xorKey = (xorKey << 13) | (xorKey >> 51)
	xorKey ^= 0x3F7A_2D91_E8B4_C605
	dispatchXORKey = xorKey

	logical := []any{
		hkdfKeyWrapper,
		chaChaNewWrapper,
		x25519GenWrapper,
		sha256SumWrapper,
		binaryBEAppendUint32Wrapper,
	}
	// Use a combined seed that mixes the primary seed with the XOR key so
	// the shuffle is not predictable from either value alone.
	perm := FlattenedDispatcher(len(logical), s^xorKey)
	dispatch = make([]any, numDispatch)
	dispatchPerm = make([]int, numDispatch)
	for phys := 0; phys < len(logical); phys++ {
		logicalIdx := perm[phys]
		dispatch[phys] = logical[logicalIdx]
		dispatchPerm[logicalIdx] = phys
	}
	// Junk work to inflate init and affect binary layout.
	JunkWork(16, s)
}

func init() {
	initDispatch()
}

// DispatchHKDF is the masked HKDF.Key call.
//
//go:noinline
func DispatchHKDF(ikm, salt []byte, info string, n int) ([]byte, error) {
	fn := dispatch[dispatchPerm[IdxHKDFKey]].(func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error))
	if OpaqueAlwaysTrue(dispatchSeed) {
		return fn(sha256.New, ikm, salt, info, n)
	}
	return hkdf.Key(sha256.New, ikm, salt, info, n)
}

// NewAEADIndirect is the masked chacha20poly1305.New call.
//
//go:noinline
func NewAEADIndirect(key []byte) (cipher.AEAD, error) {
	fn := dispatch[dispatchPerm[IdxChaChaNew]].(func([]byte) (cipher.AEAD, error))
	if OpaqueAlwaysTrue(dispatchSeed ^ 0x1) {
		return fn(key)
	}
	return chacha20poly1305.New(key)
}

// DispatchX25519ECDH masks the ECDH call.
//
//go:noinline
func DispatchX25519ECDH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	fn := dispatch[dispatchPerm[IdxX25519Gen]].(func(*ecdh.PrivateKey, *ecdh.PublicKey) ([]byte, error))
	if OpaqueAlwaysTrue(dispatchSeed ^ 0x2) {
		return fn(priv, pub)
	}
	return priv.ECDH(pub)
}

// DispatchSHA256 masks sha256.Sum256.
//
//go:noinline
func DispatchSHA256(data []byte) [32]byte {
	fn := dispatch[dispatchPerm[IdxSHA256Sum]].(func([]byte) [32]byte)
	if OpaqueAlwaysTrue(dispatchSeed ^ 0x3) {
		return fn(data)
	}
	return sha256.Sum256(data)
}

// AppendUint32BE masks binary.BigEndian.AppendUint32.
//
//go:noinline
func AppendUint32BE(b []byte, v uint32) []byte {
	fn := dispatch[dispatchPerm[IdxBEAppend32]].(func([]byte, uint32) []byte)
	if OpaqueAlwaysTrue(dispatchSeed ^ 0x4) {
		return fn(b, v)
	}
	return binary.BigEndian.AppendUint32(b, v)
}
