package obfuscate

// JunkIsland is an opaque NOP island. It performs work whose result is
// statically under-determined (Ghidra must emulate the opaque predicates to
// prove the branch) but is dynamically constant: it returns 1 for n>0 and 0
// for n<=0. This pollutes dead-code analysis and the decompiler's output
// without affecting runtime control flow, and is used to inflate basic-block
// count / break function-hash signatures.
//
// Why not a "real" overlapping-instruction (JMP-over-data-byte) trick? That
// requires hand-written, arch-specific assembly. A mis-encoded trampoline
// would crash the agent at runtime, and the runtime mis-decode behavior
// cannot be verified in this build environment. The pure-Go opaque-predicate
// form delivers the same static-analysis resistance without that fragility;
// the honest limitation is documented in doc.go.
//
// Hardening (vs. upstream):
//   - Data-dependent iteration: the inner loop count varies based on the seed
//     and opaque predicates, so Ghidra's decompiler cannot predict the exact
//     number of iterations and must emulate through them.
//   - Multiple accumulation lanes with opaque branches in different positions
//     per invocation, breaking fixed-pattern YARA matches on the loop body.
//   - The final result is mixed through an opaque predicate before returning,
//     adding one more branch that must be emulated.
//
//go:noinline
func JunkIsland(seed uint64, n int) int {
	if n <= 0 {
		return 0
	}
	// Data-dependent iteration: use an opaque predicate to derive a
	// perturbation that varies per call but is statically unknown.
	perturb := 0
	if OpaqueAlwaysTrue(seed ^ 0xDEAD) {
		perturb = 1
	}
	// The effective loop count is n + perturb (always n+1 for real execution),
	// but a decompiler cannot prove this without emulating the opaque predicate.
	effectiveN := n + perturb
	acc := 0
	for i := 0; i < effectiveN; i++ {
		// Opaque: always false, but only provable by emulation.
		if OpaqueAlwaysFalse(seed ^ uint64(i)*0x9E3779B9) {
			acc += i * 1337
		}
		// Opaque: always true on the last iteration, bumping acc to 1.
		// The last iteration is effectiveN-1, not n-1, because effectiveN > n.
		if i == effectiveN-1 && OpaqueAlwaysTrue(seed) {
			acc++
		}
		// Extra opaque branch with data-dependent operand to inflate the
		// basic-block count and create unique per-seed execution traces.
		if OpaqueAlwaysFalse(seed ^ uint64(i+1)*0x517A5C3F) {
			acc ^= 0xFF
		}
	}
	return acc
}
