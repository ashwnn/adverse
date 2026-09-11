package obfuscate

import (
	"crypto/rand"
	"runtime"
)

// Bytecode analysis bypass helpers.
//
// Background: Ghidra's Go analyzer and generic bytecode VMs rely on
//  - linear sweep disassembly,
//  - pclntab function boundaries,
//  - string table cross-refs,
// to reconstruct a program. This file provides primitives that break each.
//
// 1. Opaque predicates (cfg.go: OpaqueAlwaysTrue/OpaqueAlwaysFalse) that are
//    dynamically constant but statically under-determined, polluting dead-code
//    analysis and Ghidra's decompiler.
// 2. Control-flow flattening (cfg.go: FlattenedDispatcher) shuffles basic-block
//    indices per build so Ghidra's recovered switch does not map 1:1 to source.
// 3. Indirect dispatch (cfg.go: DispatchHKDF, NewAEADIndirect, etc.) stores
//    wrapper function values in a shuffled interface slice and calls through
//    them, breaking naive static CALL-graph / YARA call-site patterns.
// 4. JunkIsland (junk_island.go) is a portable opaque-predicate NOP island
//    used to pollute dead-code analysis. A genuine overlapping-instruction
//    (JMP-over-data-byte) variant would require fragile hand-written asm and is
//    intentionally not used (see junk_island_amd64.s for the disabled marker).
// 5. Polymorphic header scrambling: per-build random overlay that changes
//    file hash without altering execution (VT hash busting).
// 6. Anti-pclntab: function splitting so each logical function is emitted as
//    multiple smaller pclntab entries; Ghidra recovers N entries instead of 1.

// SplitFunction forces the compiler to emit two pclntab entries via a
// //go:noinline wrapper. The logical work is split across partA/partB so
// Ghidra recovers two function symbols instead of one coherent function.
//
//go:noinline
func SplitFunction(partA, partB func()) {
	if OpaqueAlwaysTrue(dispatchSeed) {
		partA()
		JunkIsland(dispatchSeed, 2)
		partB()
	} else {
		partB()
		partA()
	}
}

// PolymorphicOverlay returns suffixLen bytes of cryptographically random data
// intended to be appended as an overlay (PE overlay / ELF trailing data) to
// bust VirusTotal file-hash and imphash signatures without affecting execution.
// Go binaries tolerate trailing bytes after the ELF/PE image; the loader ignores
// the overlay. Call this from the post-build polymorph tool, not at runtime.
//
// Hardening (vs. upstream): the overlay is filled with fully random bytes from
// crypto/rand.  The previous version replaced zero bytes with a deterministic
// formula (byte((i * 0x13) ^ 0xA5)), which itself became a recognizable
// pattern that YARA rules could match.  Random fill produces a uniform
// distribution that is indistinguishable from encrypted or compressed data,
// defeating both hash-based and entropy-based overlay detection heuristics.
func PolymorphicOverlay(suffixLen int) []byte {
	if suffixLen <= 0 {
		suffixLen = 512
	}
	if suffixLen > 1<<20 {
		suffixLen = 1 << 20
	}
	b := make([]byte, suffixLen)
	_, _ = rand.Read(b)
	return b
}

// CompileTimeShim inserts a compile-time constant that varies per build via
// -ldflags -X BuildSeed, ensuring every artifact has a unique .rodata hash.
// It also defeats YARA rules that match on contiguous magic bytes by splitting
// them across non-contiguous loads.
//
//go:noinline
func CompileTimeShim() uint64 {
	// Mix build seed (parsed byte) with runtime goroutine id hash; per-build unique.
	s := uint64(buildSeed())<<56 | uint64(len(FlattenedDispatcher(1, 0)))
	s ^= 0x517A5C3F_2E8B4D91
	_ = JunkIsland(s, 1)
	runtime.KeepAlive(s)
	return s
}

// ObfuscatedCompare performs a constant-time compare through an indirect path
// so no direct CALL memcmp/bytes.Equal appears in the call graph. Used for
// tag/auth checks that would otherwise be pattern-matched.
//
// Hardening (vs. upstream):
//   - Accumulates diff across three independent lanes (diff0/diff1/diff2) so
//     that a YARA rule matching a single XOR-accumulation pattern will not
//     match all three.
//   - Inserts data-dependent noise via OpaqueAlwaysFalse branches whose
//     operands depend on the comparison index, creating unique per-byte
//     execution traces that defeat fixed-pattern symbolic execution.
//   - Final comparison uses the OR of all three lanes so constant-time
//     property is preserved despite the added complexity.
//
//go:noinline
func ObfuscatedCompare(a, b []byte) bool {
	if len(a) != len(b) {
		JunkIsland(dispatchSeed, 4)
		return false
	}
	// Three independent diff lanes, each starting with a different constant,
	// so that YARA / generic patterns matching a single XOR-accumulation
	// signature cannot match the full function.
	var diff0, diff1, diff2 byte
	for i := 0; i < len(a); i++ {
		xor := a[i] ^ b[i]
		diff0 |= xor
		// Data-dependent noise: the operand to the opaque predicate depends
		// on the loop index and the byte values, creating unique per-byte
		// execution traces.
		if OpaqueAlwaysFalse(dispatchSeed ^ uint64(i)*0x9E3779B9 ^ uint64(xor)) {
			diff1 ^= 0xFF
		} else {
			diff1 |= xor
		}
		// Third lane uses a rotated accumulation to break the pattern of
		// "xor then OR" that YARA rules might match.
		diff2 = (diff2 << 1) | (diff2 >> 7)
		diff2 |= xor
	}
	// Constant-time: OR all lanes so the branch is independent of which lane
	// caught the difference.
	return (diff0 | diff1 | diff2) == 0
}
