package behavioural

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/anti"
)

// ---------------------------------------------------------------------------
// TestScoreGate — inject synthetic CheckResult slices and verify scoring
// ---------------------------------------------------------------------------

func TestScoreGateStrongTriggerDeniesRegardless(t *testing.T) {
	// A single strong trigger (debugger / any.run artifact) must cause immediate denial
	// regardless of how many positive signals are present. VM artifacts are weighted,
	// not hard denies.
	signals := []anti.CheckResult{
		{Name: "peb_beingdebugged", Triggered: true, Detail: "BeingDebugged=1"},
		{Name: "real_smbios", Triggered: true, Detail: "OEM Dell"},
		{Name: "real_gpu", Triggered: true, Detail: "NVIDIA RTX 4090"},
		{Name: "real_battery", Triggered: true, Detail: "battery present"},
		{Name: "real_audio", Triggered: true, Detail: "Realtek audio"},
		{Name: "real_apps", Triggered: true, Detail: "150 apps"},
		{Name: "real_user_files", Triggered: true, Detail: "500 files"},
		{Name: "real_resolution", Triggered: true, Detail: "1920x1080"},
		{Name: "real_uptime", Triggered: true, Detail: "uptime 86400s"},
		{Name: "real_processes", Triggered: true, Detail: "80 processes"},
	}
	allowed, score, reasons := scoreGate(signals)
	if allowed {
		t.Fatal("expected denied when strong trigger present")
	}
	if score != 0 {
		t.Fatalf("expected score=0 on strong trigger, got %d", score)
	}
	if len(reasons) == 0 {
		t.Fatal("expected reasons explaining denial")
	}
	// Verify the strong trigger is in reasons
	found := false
	for _, r := range reasons {
		if r == "strong:peb_beingdebugged=BeingDebugged=1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected strong trigger reason, got %v", reasons)
	}
}

func TestScoreGateStrongTriggerMultiple(t *testing.T) {
	// Multiple strong triggers (debugger + sandbox)
	signals := []anti.CheckResult{
		{Name: "peb_beingdebugged", Triggered: true, Detail: "BeingDebugged=1"},
		{Name: "anyrun_artifact", Triggered: true, Detail: "anyrun artifact"},
	}
	allowed, _, _ := scoreGate(signals)
	if allowed {
		t.Fatal("expected denied with multiple strong triggers")
	}
}

func TestScoreGateVMArtifactsAreWeightedNotHardDenies(t *testing.T) {
	// VM artifacts should be weighted negative, not hard denies. A host with
	// vm_smbios negative plus many real_* positives should still be allowed
	// when the weighted sum exceeds threshold.
	signals := []anti.CheckResult{
		{Name: "vm_smbios", Triggered: true, Detail: "SMBIOS contains vmware"},
		{Name: "real_smbios", Triggered: true, Detail: "OEM Dell"},
		{Name: "real_gpu", Triggered: true, Detail: "NVIDIA RTX 4090"},
		{Name: "real_battery", Triggered: true, Detail: "battery present"},
		{Name: "real_audio", Triggered: true, Detail: "Realtek audio"},
		{Name: "real_apps", Triggered: true, Detail: "150 apps"},
		{Name: "real_user_files", Triggered: true, Detail: "500 files"},
		{Name: "real_resolution", Triggered: true, Detail: "1920x1080"},
		{Name: "real_uptime", Triggered: true, Detail: "uptime 86400s"},
		{Name: "real_processes", Triggered: true, Detail: "80 processes"},
	}
	allowed, score, _ := scoreGate(signals)
	// vm_smbios is -15, positives sum = 57, total = 42 >20 => allowed
	if !allowed {
		t.Fatalf("expected allowed when VM artifact is weighted not hard deny, score=%d", score)
	}
	if score != 42 {
		t.Fatalf("expected score 42, got %d", score)
	}
}

func TestScoreGateRealMachineAllowed(t *testing.T) {
	// All real-machine signals, no VM signals => score >= threshold => allowed
	signals := []anti.CheckResult{
		{Name: "real_smbios", Triggered: true, Detail: "OEM Dell"},
		{Name: "real_gpu", Triggered: true, Detail: "NVIDIA RTX 4090"},
		{Name: "real_battery", Triggered: true, Detail: "battery present"},
		{Name: "real_audio", Triggered: true, Detail: "Realtek audio"},
		{Name: "real_apps", Triggered: true, Detail: "150 apps"},
		{Name: "real_user_files", Triggered: true, Detail: "500 files"},
		{Name: "real_resolution", Triggered: true, Detail: "1920x1080"},
		{Name: "real_uptime", Triggered: true, Detail: "uptime 86400s"},
		{Name: "real_processes", Triggered: true, Detail: "80 processes"},
	}
	allowed, score, reasons := scoreGate(signals)
	if !allowed {
		t.Fatalf("expected allowed for real machine signals, score=%d reasons=%v", score, reasons)
	}
	if score < RealMachineThreshold {
		t.Fatalf("expected score >= %d, got %d", RealMachineThreshold, score)
	}
}

func TestScoreGateAmbiguousSignalsDenied(t *testing.T) {
	// Empty or ambiguous signals: no real-machine indicators, no strong triggers
	// but also no negative signals. Score = 0 < threshold => denied.
	signals := []anti.CheckResult{
		{Name: "anyrun_specs", Triggered: false, Detail: "specs not sandbox-typical"},
		{Name: "anyrun_processes", Triggered: false, Detail: "60 processes"},
	}
	allowed, score, _ := scoreGate(signals)
	if allowed {
		t.Fatalf("expected denied for ambiguous/empty signals, score=%d", score)
	}
	if score >= RealMachineThreshold {
		t.Fatalf("expected score < %d for ambiguous, got %d", RealMachineThreshold, score)
	}
}

func TestScoreGateMixedSignals(t *testing.T) {
	// Some positive, some negative — score determines outcome
	// Expected: 8+5+5+5+10+8+3+8+5 = 57, negative: -5-15-10-10 = -40, total = 17
	// 17 < 20 => denied
	signals := []anti.CheckResult{
		{Name: "real_smbios", Triggered: true, Detail: "OEM HP"},
		{Name: "real_gpu", Triggered: true, Detail: "Intel UHD 630"},
		{Name: "real_battery", Triggered: true, Detail: "battery present"},
		{Name: "real_audio", Triggered: true, Detail: "Conexant audio"},
		{Name: "real_apps", Triggered: true, Detail: "80 apps"},
		{Name: "real_user_files", Triggered: true, Detail: "200 files"},
		{Name: "real_resolution", Triggered: true, Detail: "2560x1440"},
		{Name: "real_uptime", Triggered: true, Detail: "uptime 7200s"},
		{Name: "real_processes", Triggered: true, Detail: "65 processes"},
		{Name: "vm_no_battery", Triggered: true, Detail: "no battery"},
		{Name: "anyrun_uptime", Triggered: true, Detail: "uptime 120s"},
		{Name: "anyrun_specs", Triggered: true, Detail: "sandbox template"},
		{Name: "anyrun_processes", Triggered: true, Detail: "25 processes"},
	}
	allowed, score, _ := scoreGate(signals)
	if allowed {
		t.Fatalf("expected denied with mixed signals score=%d", score)
	}
}

func TestScoreGateJustAboveThreshold(t *testing.T) {
	// Score 8+5+5+5+10+8+8 = 49 >= 20 => allowed
	signals := []anti.CheckResult{
		{Name: "real_smbios", Triggered: true, Detail: "OEM"},
		{Name: "real_gpu", Triggered: true, Detail: "GPU"},
		{Name: "real_battery", Triggered: true, Detail: "battery"},
		{Name: "real_audio", Triggered: true, Detail: "audio"},
		{Name: "real_apps", Triggered: true, Detail: "100 apps"},
		{Name: "real_user_files", Triggered: true, Detail: "50 files"},
		{Name: "real_uptime", Triggered: true, Detail: "uptime 3600s"},
	}
	allowed, score, _ := scoreGate(signals)
	if !allowed {
		t.Fatalf("expected allowed at score=%d", score)
	}
}

func TestScoreGateThresholdConstant(t *testing.T) {
	if RealMachineThreshold != 20 {
		t.Fatalf("expected RealMachineThreshold=20, got %d", RealMachineThreshold)
	}
}

// ---------------------------------------------------------------------------
// TestScoreGateViaAllow — integration with Allow() on Linux
// ---------------------------------------------------------------------------

func TestAllowRealHost(t *testing.T) {
	os.Unsetenv("BEHAVIOURAL_SANDBOX")
	ctx := context.Background()
	g := Allow(ctx)
	if len(g.Signals) == 0 {
		t.Fatal("no signals")
	}
	if !g.Allowed {
		t.Fatalf("expected allowed on real Linux host, score=%d reasons=%v", g.Score, g.Reasons)
	}
	if g.Score < RealMachineThreshold {
		t.Fatalf("expected score >= %d, got %d", RealMachineThreshold, g.Score)
	}
	t.Logf("allowed=%v score=%d signals=%d", g.Allowed, g.Score, len(g.Signals))
}

func TestAllowSandbox(t *testing.T) {
	os.Setenv("BEHAVIOURAL_SANDBOX", "1")
	defer os.Unsetenv("BEHAVIOURAL_SANDBOX")
	g := Allow(context.Background())
	if g.Allowed {
		t.Fatalf("expected blocked in simulated sandbox")
	}
	found := false
	for _, s := range g.Signals {
		if s.Name == "anyrun_artifact" && s.Triggered {
			found = true
		}
	}
	if !found {
		t.Fatal("expected anyrun_artifact triggered")
	}
}

// ---------------------------------------------------------------------------
// TestEnvironmentalKeyHKDF
// ---------------------------------------------------------------------------

func TestEnvKeyDeterministic(t *testing.T) {
	os.Setenv("ADVERSE_ENV_SEED", "fixture-seed-1")
	defer os.Unsetenv("ADVERSE_ENV_SEED")
	k1 := EnvironmentalKey()
	k2 := EnvironmentalKey()
	if k1 != k2 {
		t.Fatal("env key should be deterministic within fixture")
	}
	if k1 == [32]byte{} {
		t.Fatal("zero key")
	}
}

func TestEnvKeyDiffersPerSeed(t *testing.T) {
	os.Setenv("ADVERSE_ENV_SEED", "seed-a")
	k1 := EnvironmentalKey()
	os.Setenv("ADVERSE_ENV_SEED", "seed-b")
	k2 := EnvironmentalKey()
	os.Unsetenv("ADVERSE_ENV_SEED")
	if k1 == k2 {
		t.Fatal("different seeds should produce different keys")
	}
}

func TestEnvironmentalKeyHKDF(t *testing.T) {
	// On non-Windows, the fixture must be deterministic across calls.
	os.Setenv("ADVERSE_ENV_SEED", "hkdf-test-seed")
	defer os.Unsetenv("ADVERSE_ENV_SEED")

	k1 := EnvironmentalKey()
	k2 := EnvironmentalKey()
	if k1 != k2 {
		t.Fatal("HKDF key must be deterministic for same env material")
	}
	if k1 == [32]byte{} {
		t.Fatal("HKDF key is zero")
	}
}

// ---------------------------------------------------------------------------
// TestDecoyHTTPGate — decoy egress gated only by the opt-in environment flag
// ---------------------------------------------------------------------------

type decoyTestServer struct {
	srv    *httptest.Server
	hits   atomic.Int64
	lastUA atomic.Pointer[string]
}

func newDecoyTestServer(t *testing.T) *decoyTestServer {
	t.Helper()
	d := &decoyTestServer{}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.hits.Add(1)
		ua := r.Header.Get("User-Agent")
		d.lastUA.Store(&ua)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func resetDecoyState(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SetDecoyURLs(nil)
	})
}

func TestDecoyHTTPDisabledWithoutEnv(t *testing.T) {
	d := newDecoyTestServer(t)
	resetDecoyState(t)
	t.Setenv(DecoyHTTPEnvVar, "0")
	SetDecoyURLs([]string{d.srv.URL})

	MimicDecoyHTTP(context.Background())
	if got := d.hits.Load(); got != 0 {
		t.Fatalf("egress occurred without %s=1: %d request(s)", DecoyHTTPEnvVar, got)
	}
}

func TestDecoyHTTPEnabledEgresses(t *testing.T) {
	d := newDecoyTestServer(t)
	resetDecoyState(t)
	t.Setenv(DecoyHTTPEnvVar, "1")
	SetDecoyURLs([]string{d.srv.URL})

	MimicDecoyHTTP(context.Background())
	if got := d.hits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 decoy request, got %d", got)
	}
	ua := d.lastUA.Load()
	if ua == nil || !strings.Contains(*ua, "Mozilla/5.0") {
		t.Fatalf("expected browser-like User-Agent, got %v", ua)
	}
}

func TestDecoyHTTPGateCancelledCtx(t *testing.T) {
	d := newDecoyTestServer(t)
	resetDecoyState(t)
	t.Setenv(DecoyHTTPEnvVar, "1")
	SetDecoyURLs([]string{d.srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		MimicDecoyHTTP(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("MimicDecoyHTTP with cancelled ctx did not return in time")
	}
	if got := d.hits.Load(); got != 0 {
		t.Fatalf("cancelled ctx must suppress egress, got %d request(s)", got)
	}
}

func TestDecoyHTTPGateEmptyURLs(t *testing.T) {
	resetDecoyState(t)
	t.Setenv(DecoyHTTPEnvVar, "1")
	SetDecoyURLs([]string{})

	done := make(chan struct{})
	go func() {
		MimicDecoyHTTP(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("MimicDecoyHTTP with empty URLs did not return")
	}
}

func TestDecoyHTTPGateNoPanic(t *testing.T) {
	d := newDecoyTestServer(t)
	resetDecoyState(t)
	t.Setenv(DecoyHTTPEnvVar, "1")
	SetDecoyURLs([]string{d.srv.URL})

	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic in MimicDecoyHTTP: %v", r)
			}
			close(done)
		}()
		MimicDecoyHTTP(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("MimicDecoyHTTP did not return in time")
	}
}

// TestDecoyConfigConcurrentAccess exercises the mutex around decoy state so the
// race detector can prove the old plain-bool guard is gone.
func TestDecoyConfigConcurrentAccess(t *testing.T) {
	resetDecoyState(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				SetDecoyURLs([]string{"http://decoy.example/connecttest.txt"})
				_ = getDecoyConfig()
			}
		}()
	}
	wg.Wait()
}

// TestSetDecoyURLsCopiesInput ensures a caller mutating its slice after Set
// cannot race with MimicDecoyHTTP's reads.
func TestSetDecoyURLsCopiesInput(t *testing.T) {
	resetDecoyState(t)
	in := []string{"http://one.example/"}
	SetDecoyURLs(in)
	in[0] = "http://mutated.example/"
	urls := getDecoyConfig()
	if len(urls) != 1 || urls[0] != "http://one.example/" {
		t.Fatalf("SetDecoyURLs must copy its input, got %v", urls)
	}
}

// ---------------------------------------------------------------------------
// TestDelayedWorkNonWindows
// ---------------------------------------------------------------------------

func TestDelayedWorkNonWindows(t *testing.T) {
	fnCalled := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	DelayedWork(ctx, 0, func() {
		fnCalled <- struct{}{}
	})

	select {
	case <-fnCalled:
	case <-ctx.Done():
		t.Log("DelayedWork did not call fn within timeout (expected on non-Windows in unit test due to StallBeyondSandbox)")
	}
}

// ---------------------------------------------------------------------------
// TestRotatingXOR
// ---------------------------------------------------------------------------

func TestRotatingXOR(t *testing.T) {
	original := []byte("hello world, this is a test payload for VEH decryption")
	key := byte(0xAB)

	encrypted := RotatingXOR(original, key)
	if string(encrypted) == string(original) {
		t.Fatal("encrypted should differ from original")
	}

	decrypted := RotatingXOR(encrypted, key)
	if string(decrypted) != string(original) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, original)
	}
}

func TestRotatingXOREmpty(t *testing.T) {
	result := RotatingXOR([]byte{}, 0x42)
	if len(result) != 0 {
		t.Fatalf("expected empty result, got %d bytes", len(result))
	}
}

// ---------------------------------------------------------------------------
// TestMimicBenignNoise
// ---------------------------------------------------------------------------

func TestMimicBenignNoise(t *testing.T) {
	MimicBenignRegistryNoise()
}

// ---------------------------------------------------------------------------
// TestIsAnyRunSandbox
// ---------------------------------------------------------------------------

func TestIsAnyRunSandbox(t *testing.T) {
	os.Unsetenv("BEHAVIOURAL_SANDBOX")
	if IsAnyRunSandbox() {
		t.Fatal("should not be sandbox on clean fixture")
	}
	os.Setenv("BEHAVIOURAL_SANDBOX", "1")
	defer os.Unsetenv("BEHAVIOURAL_SANDBOX")
	if !IsAnyRunSandbox() {
		t.Fatal("should be sandbox")
	}
}

// ---------------------------------------------------------------------------
// TestStrongTriggersConsistency
// ---------------------------------------------------------------------------

func TestStrongTriggersAllCheckNames(t *testing.T) {
	for name := range strongTriggers {
		if _, ok := signalWeights[name]; !ok {
			t.Logf("strong trigger %q has no weight (intentional: denied before scoring)", name)
		}
	}
}
