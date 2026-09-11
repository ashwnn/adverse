package anti

import (
	"runtime"

	"github.com/ashwnn/adverse-go/internal/obfuscate"
)

// BytecodeBypassChallenge is a self-check that bytecode VMs and Ghidra's
// decompiler will mis-evaluate because the integrity counters below hinge on
// opaque predicates whose values are dynamically constant but statically
// under-determined. Real execution always takes the "clean" path;
// instrumentation that patches OpaqueAlwaysTrue to false will diverge.
//
// Call this before any sensitive operation (e.g., before agent hello) and
// abort or delay if diverge is detected. Returns true when execution diverged.
func BytecodeBypassChallenge() bool {
	seed := obfuscate.CompileTimeShim()
	// Seed-mixing touch: RotatingXOR with seed 0 resolves the per-build
	// obfuscate seed and executes the same rotating schedule used by the
	// generated string table. The encrypted placeholder is intentionally
	// discarded — the divergence counters below are the actual integrity test.
	goodEnc := obfuscate.RotatingXOR([]byte("0"), 0)
	_ = goodEnc
	// Opaque-integrity: if a VM patches this predicate, the two counters diverge.
	good := 0
	bad := 0
	if obfuscate.OpaqueAlwaysTrue(seed) {
		good++
		obfuscate.JunkIsland(seed^0x1, 2)
	} else {
		bad++
	}
	if obfuscate.OpaqueAlwaysFalse(seed) {
		bad++
	} else {
		good++
	}
	// Divergence: VM would report good==1 or bad!=0 on mis-evaluation.
	runtime.KeepAlive(seed)
	return bad != 0 || good != 2
}
