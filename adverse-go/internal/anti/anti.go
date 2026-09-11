package anti

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/ashwnn/adverse-go/internal/obfuscate"
)

// CheckResult reports a single analysis-environment signal.
type CheckResult struct {
	Name      string `json:"name"`
	Triggered bool   `json:"triggered"`
	Detail    string `json:"detail"`
}

// AllSignals runs the cross-platform checks that are safe without OS-specific
// syscalls. Platform-specific disasm/debug checks are in anti_windows.go /
// anti_linux.go and are appended by PlatformChecks().
func AllSignals() []CheckResult {
	var out []CheckResult
	out = append(out, timingCheck())
	out = append(out, opaqueIntegrityCheck())
	out = append(out, jitterCheck())
	out = append(out, PlatformChecks()...)
	return out
}

// --- cross-platform primitives ---

// medianDuration returns the median of a slice of durations.
// For an empty slice it returns 0. For even-length slices it returns the
// lower-middle element (index (n-1)/2 after sorting), which is a
// deterministic choice. For odd-length slices it returns the true median.
func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(ds))
	copy(sorted, ds)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[(len(sorted)-1)/2]
}

// timingCheck measures a tight XOR-fold loop with the Go monotonic clock.
// Emulators and heavy instrumentation inflate per-iteration cost 10-100x.
//
// Per research §5 the 120ms threshold is an application-specific heuristic
// calibrated to the 500k-iteration XOR-fold on commodity CPUs; it is NOT
// portable across arbitrary CPU classes. A warm-up pass mitigates first-run
// allocator/GC effects, and the median of 5 timed runs filters outlier spikes
// from scheduler preemption or GC pauses on loaded physical machines.
func timingCheck() CheckResult {
	// Warm-up pass (untimed): prime allocator, JIT, caches.
	{
		n, _ := rand.Int(rand.Reader, big.NewInt(1<<20))
		acc := uint64(n.Int64())
		for i := 0; i < 50_000; i++ {
			acc ^= uint64(i) * 0x9E3779B97F4A7C15
			if obfuscate.OpaqueAlwaysFalse(acc) {
				acc++
			}
		}
		obfuscate.JunkWork(1, acc) // prevent DCE of warm-up
	}

	const runs = 5
	durations := make([]time.Duration, runs)
	var acc uint64
	for r := 0; r < runs; r++ {
		start := time.Now()
		n, _ := rand.Int(rand.Reader, big.NewInt(1<<20))
		// Do N xor folds; emulator with per-insn tracing is 10-100x slower.
		acc = uint64(n.Int64())
		for i := 0; i < 500_000; i++ {
			acc ^= uint64(i) * 0x9E3779B97F4A7C15
			if obfuscate.OpaqueAlwaysFalse(acc) {
				acc++
			}
		}
		durations[r] = time.Since(start)
	}

	median := medianDuration(durations)
	// Real hardware: <15ms. Sandbox/emulator: >80ms on same loop.
	// Threshold applies to the median and is NOT portable across CPU classes.
	triggered := median > 120*time.Millisecond
	detail := "median=" + median.String()
	// Use accumulator to prevent DCE.
	if acc == 0xDEADBEEF {
		detail += " deadbeef"
	}
	return CheckResult{Name: "timing_emulation", Triggered: triggered, Detail: detail}
}

// opaqueIntegrityCheck validates that our opaque predicates behave as modelled.
// Under a bytecode VM that constant-folds incorrectly, this will flip.
//
//go:noinline
func opaqueIntegrityCheck() CheckResult {
	v := obfuscate.CompileTimeShim()
	ok := obfuscate.OpaqueAlwaysTrue(v) && !obfuscate.OpaqueAlwaysFalse(v)
	return CheckResult{Name: "opaque_integrity", Triggered: !ok, Detail: "predicate mismatch ⇒ VM mis-emulation"}
}

// jitterCheck inserts a stalling loop invisible to VMs that fast-forward sleep.
// It reports triggered if time.After scheduling variance is impossibly low
// (indicating sleep is being skipped by emulator).
//
// Three rounds of 18ms sleep are measured by two independent clocks:
// (1) Go's monotonic time.Now and (2) a platform second clock independent
// of the Go runtime (GetTickCount64 on Windows, CLOCK_BOOTTIME on Linux).
// Triggered requires ALL 3 rounds to show d1 < 5ms AND every round in which
// the second clock was successfully read to also show d2 < 5ms. If the second
// clock is unavailable in all rounds, the monotonic-only requirement applies.
func jitterCheck() CheckResult {
	const rounds = 3
	const sleepDur = 18 * time.Millisecond
	var monoDiffs [rounds]time.Duration
	var secondClockDiffs [rounds]int64
	var secondClockOK [rounds]bool
	secondRead := 0

	for i := 0; i < rounds; i++ {
		t0 := time.Now()
		t1ms, ok := secondClockMS()
		time.Sleep(sleepDur)
		d1 := time.Since(t0)
		monoDiffs[i] = d1
		if ok {
			t2ms, ok2 := secondClockMS()
			if ok2 {
				secondClockOK[i] = true
				secondRead++
				secondClockDiffs[i] = t2ms - t1ms
			}
		}
	}

	allMonoSkipped := true
	for _, d := range monoDiffs {
		if d >= 5*time.Millisecond {
			allMonoSkipped = false
			break
		}
	}

	// Every round with a successful second-clock read must agree that the
	// sleep was skipped. Rounds without a read do not contribute a verdict.
	allSecondSkipped := true
	for i := 0; i < rounds; i++ {
		if secondClockOK[i] && secondClockDiffs[i] >= 5 {
			allSecondSkipped = false
			break
		}
	}

	triggered := allMonoSkipped && (allSecondSkipped || secondRead == 0)

	// Compute median of mono diffs for the detail string.
	monoSlice := make([]time.Duration, rounds)
	copy(monoSlice, monoDiffs[:])
	medianMono := medianDuration(monoSlice)

	clkStatus := "second-clock unavailable"
	if secondRead > 0 {
		clkStatus = fmt.Sprintf("second-clock %d/%d rounds", secondRead, rounds)
	}
	detail := "median_d1=" + medianMono.String() + " " + clkStatus
	return CheckResult{Name: "sleep_skipped", Triggered: triggered, Detail: detail}
}

// StallForAnalysisBypass performs wall-clock stalling that sandboxes must
// either wait through or be detected skipping. It mixes real sleep with
// CPU work so not all delay is skippable by hooking NtDelayExecution.
func StallForAnalysisBypass(minMS int) {
	if minMS <= 0 {
		minMS = 800
	}
	if minMS > 5000 {
		minMS = 5000
	}
	end := time.Now().Add(time.Duration(minMS) * time.Millisecond)
	for time.Now().Before(end) {
		// CPU-bound chunk
		obfuscate.JunkWork(4096, uint64(time.Now().UnixNano()))
		// IO-bound chunk — emulator cannot fast-forward without clock drift
		time.Sleep(time.Duration(3+time.Now().UnixNano()%7) * time.Millisecond)
	}
}

// APIHammerScore estimates emulation via API-spam burst. Real execution
// completes fast; emu with per-call logging is an order of magnitude slower.
func APIHammerScore(calls int) time.Duration {
	if calls <= 0 {
		calls = 32
	}
	start := time.Now()
	for i := 0; i < calls; i++ {
		obfuscate.JunkWork(1024, uint64(i)*0x9E3779B9)
	}
	return time.Since(start)
}
