package anti

import (
	"runtime"
	"testing"
	"time"
)

func TestTimingAndOpaque(t *testing.T) {
	if c := timingCheck(); c.Name == "" {
		t.Fatal("name")
	}
	if c := opaqueIntegrityCheck(); c.Triggered {
		t.Fatalf("opaque should not trigger in native execution: %v", c)
	}
	if BytecodeBypassChallenge() {
		t.Fatal("bypass challenge diverged")
	}
}

func TestAllSignalsShape(t *testing.T) {
	sigs := AllSignals()
	if len(sigs) == 0 {
		t.Fatal("no signals")
	}
	seen := map[string]bool{}
	for _, s := range sigs {
		if s.Name == "" {
			t.Fatal("empty name")
		}
		seen[s.Name] = true
	}
	if !seen["timing_emulation"] || !seen["opaque_integrity"] {
		t.Fatal("missing core signals")
	}
}

func TestStallDoesNotHang(t *testing.T) {
	// Short stall — should return quickly on real host.
	StallForAnalysisBypass(10)
}

func TestAPIHammer(t *testing.T) {
	d := APIHammerScore(4)
	if d < 0 {
		t.Fatal("neg")
	}
}

func TestCPUIDCheck(t *testing.T) {
	// cpuidHypervisorCheck must return a valid CheckResult on any platform.
	// On non-Windows it returns the no-op; on Windows it reads CPUID leaf 1.
	// Names are vm_cpuid_* to align with behavioural signalWeights.
	c := cpuidHypervisorCheck()
	if c.Name != "vm_cpuid_hypervisor" {
		t.Fatalf("expected name vm_cpuid_hypervisor, got %q", c.Name)
	}
	// Detail must never be empty.
	if c.Detail == "" {
		t.Fatal("empty detail")
	}

	// cpuidVendorCheck likewise.
	v := cpuidVendorCheck()
	if v.Name != "vm_cpuid_vendor" {
		t.Fatalf("expected name vm_cpuid_vendor, got %q", v.Name)
	}
	if v.Detail == "" {
		t.Fatal("empty detail")
	}

	// Both checks must appear in AllSignals.
	sigs := AllSignals()
	seen := map[string]bool{}
	for _, s := range sigs {
		seen[s.Name] = true
	}
	if !seen["vm_cpuid_hypervisor"] || !seen["vm_cpuid_vendor"] {
		t.Fatalf("cpuid checks missing from AllSignals: %v", sigs)
	}
}

// ---------------------------------------------------------------------------
// TestMedianDuration — pure helper unit tests
// ---------------------------------------------------------------------------

func TestMedianDurationOddCount(t *testing.T) {
	ds := []time.Duration{10 * time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond}
	got := medianDuration(ds)
	if got != 10*time.Millisecond {
		t.Fatalf("expected 10ms, got %v", got)
	}
}

func TestMedianDurationEvenCount(t *testing.T) {
	// Even-length: lower-middle element (index (n-1)/2 after sort, i.e.
	// the lower of the two middle values). Sorted: [10, 20, 30, 40] →
	// index 1 → 20ms.
	ds := []time.Duration{30 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}
	got := medianDuration(ds)
	if got != 20*time.Millisecond {
		t.Fatalf("expected 20ms (lower-middle), got %v", got)
	}
}

func TestMedianDurationEmpty(t *testing.T) {
	got := medianDuration(nil)
	if got != 0 {
		t.Fatalf("expected 0 for nil slice, got %v", got)
	}
	got = medianDuration([]time.Duration{})
	if got != 0 {
		t.Fatalf("expected 0 for empty slice, got %v", got)
	}
}

func TestMedianDurationSingle(t *testing.T) {
	ds := []time.Duration{42 * time.Millisecond}
	got := medianDuration(ds)
	if got != 42*time.Millisecond {
		t.Fatalf("expected 42ms, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// TestSecondClockShape — platform second clock must be available
// ---------------------------------------------------------------------------

func TestSecondClockShape(t *testing.T) {
	ms, ok := secondClockMS()
	switch runtime.GOOS {
	case "windows", "linux":
		if !ok {
			t.Fatalf("secondClockMS should be available on %s", runtime.GOOS)
		}
	default:
		if ok || ms != 0 {
			t.Fatalf("secondClockMS on %s: got (%d, %v), want (0, false)", runtime.GOOS, ms, ok)
		}
		return
	}
	if ms < 0 {
		t.Fatalf("secondClockMS returned negative value: %d", ms)
	}
	t.Logf("secondClockMS: %d ms (ok=%v)", ms, ok)
}

// ---------------------------------------------------------------------------
// TestCPUIDHypervisorPresent — shape check
// ---------------------------------------------------------------------------

func TestCPUIDHypervisorPresent(t *testing.T) {
	present, detail := CPUIDHypervisorPresent()
	_ = present // bool; no assertion on value since CI hardware varies
	if detail == "" {
		t.Fatal("CPUIDHypervisorPresent returned empty detail")
	}
	t.Logf("CPUIDHypervisorPresent: present=%v detail=%q", present, detail)
}
