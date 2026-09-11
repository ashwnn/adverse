package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/wire"
)

// TestValidateSecretMalformedErrorDoesNotLeakSecret pins the P0 fix: a
// malformed secret must never be interpolated into the validation error
// (which cmd/registryfil logs on startup).
func TestValidateSecretMalformedErrorDoesNotLeakSecret(t *testing.T) {
	secrets := []string{
		strings.Repeat("z", 64),       // right length, non-hex
		"deadbeef",                    // wrong length
		strings.Repeat("a", 63) + "!", // 64 chars, bad first/last
		"aabbccddeeff00112233445566778899aabbccddeeff0011223344556677889f!", // 65 chars
	}
	for _, secret := range secrets {
		cfg := validTestConfig()
		cfg.Secret = secret
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("expected validation error for secret %q", secret)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error leaks secret value: %v", err)
		}
	}
}

func newTestAgent(t *testing.T, cfg Config) *Agent {
	t.Helper()
	a, err := New(&cfg, log.New(io.Discard, "", 0), false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// taskMsg renders a wire task message for handleTask.
func taskMsg(t *testing.T, jobID string, payload map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal task payload: %v", err)
	}
	return map[string]any{"task_id": jobID, "payload": string(raw)}
}

// ackViaHook returns a postFrame hook that synthesizes a valid server ack
// frame on the agent's current session keys.
func ackViaHook(a *Agent) func(context.Context, []byte, uint32) ([]byte, error) {
	return func(_ context.Context, _ []byte, seq uint32) ([]byte, error) {
		ackMsg := message.Make("beacon", a.cfg.AgentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9)
		ackJSON, _ := json.Marshal(ackMsg)
		return wire.Build(ackJSON, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":in"), seq+1, wire.DirectionServerToClient)
	}
}

// TestExtractResumesAfterFailedChunk pins the extract-retry fix: a failed
// chunk stops the loop, progress is recorded, and a re-dispatched job resumes
// at the failed seq (1) without re-sending earlier chunks. The job is only
// marked terminal after all chunks are acked, and a third dispatch is a no-op.
func TestExtractResumesAfterFailedChunk(t *testing.T) {
	os.Setenv("ADVERSE_BEHAVIOURAL", "0")
	defer os.Unsetenv("ADVERSE_BEHAVIOURAL")

	a := newTestAgent(t, validTestConfig())

	var (
		mu              sync.Mutex
		sentSeqs        []int
		failSeq         = 1
		failedOnce      bool
		hookInvocations int
	)

	a.postFrameHook = func(_ context.Context, frame []byte, seq uint32) ([]byte, error) {
		plain, _, _, err := wire.Parse(frame, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":out"), wire.DirectionClientToServer)
		if err != nil {
			return nil, fmt.Errorf("hook parse: %w", err)
		}
		var msg struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(plain, &msg); err != nil {
			return nil, fmt.Errorf("hook unmarshal: %w", err)
		}
		var rp struct {
			Seq int `json:"seq"`
		}
		if err := json.Unmarshal([]byte(msg.Payload), &rp); err != nil {
			return nil, fmt.Errorf("hook payload unmarshal: %w", err)
		}

		mu.Lock()
		hookInvocations++
		sentSeqs = append(sentSeqs, rp.Seq)
		fail := rp.Seq == failSeq && !failedOnce
		if fail {
			failedOnce = true
		}
		mu.Unlock()

		if fail {
			return nil, fmt.Errorf("injected chunk send failure")
		}
		ackJSON, _ := json.Marshal(message.Make("beacon", a.cfg.AgentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9))
		return wire.Build(ackJSON, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":in"), seq+1, wire.DirectionServerToClient)
	}

	payload := map[string]any{
		"action":     "extract",
		"hives":      []any{"SYSTEM"},
		"chunk_size": float64(256), // 1024-byte synthetic hive => 4 chunks
	}
	jobID := "job-resume"

	if rc := a.handleTask(context.Background(), taskMsg(t, jobID, payload)); rc != 0 {
		t.Fatalf("first dispatch rc=%d, want 0", rc)
	}
	if a.processedJobs.has(jobID) {
		t.Fatal("job must not be terminal after a failed chunk")
	}
	if next, ok := a.extractProgress.get(jobID); !ok || next != 1 {
		t.Fatalf("progress after failure = %d (ok=%v), want 1", next, ok)
	}

	if rc := a.handleTask(context.Background(), taskMsg(t, jobID, payload)); rc != 0 {
		t.Fatalf("re-dispatch rc=%d, want 0", rc)
	}
	if !a.processedJobs.has(jobID) {
		t.Fatal("job must be terminal after all chunks are acked")
	}
	if _, ok := a.extractProgress.get(jobID); ok {
		t.Fatal("progress must be cleared once the job is terminal")
	}

	mu.Lock()
	got := append([]int(nil), sentSeqs...)
	invocations := hookInvocations
	mu.Unlock()

	want := []int{0, 1, 1, 2, 3}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("sent chunk seqs = %v, want %v (resume at 1)", got, want)
	}

	// Third dispatch of a terminal job must not touch the transport.
	if rc := a.handleTask(context.Background(), taskMsg(t, jobID, payload)); rc != 0 {
		t.Fatalf("third dispatch rc=%d, want 0", rc)
	}
	mu.Lock()
	after := hookInvocations
	mu.Unlock()
	if after != invocations {
		t.Fatalf("terminal job re-sent %d frames on re-dispatch", after-invocations)
	}
}

// TestExtractRejectsOversizedChunkSize pins the chunk bound: a task-supplied
// chunk_size above 512 KB is rejected fail-closed (one error status result,
// no chunks sent) rather than producing multi-MB frames.
func TestExtractRejectsOversizedChunkSize(t *testing.T) {
	os.Setenv("ADVERSE_BEHAVIOURAL", "0")
	defer os.Unsetenv("ADVERSE_BEHAVIOURAL")

	a := newTestAgent(t, validTestConfig())
	posts := 0
	a.postFrameHook = func(ctx context.Context, frame []byte, seq uint32) ([]byte, error) {
		posts++
		return ackViaHook(a)(ctx, frame, seq)
	}

	jobID := "job-big"
	rc := a.handleTask(context.Background(), taskMsg(t, jobID, map[string]any{
		"action":     "extract",
		"hives":      []any{"SYSTEM"},
		"chunk_size": float64(2 * 1024 * 1024),
	}))
	if rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if posts != 1 {
		t.Fatalf("posts=%d, want 1 (error status only, no chunks)", posts)
	}
	if !a.processedJobs.has(jobID) {
		t.Fatal("rejected job must be marked terminal")
	}
}

// TestProcessedJobsDeterministicFIFOEviction pins the eviction fix: the
// bounded tracking maps drop the oldest entry (not a random map entry).
func TestProcessedJobsDeterministicFIFOEviction(t *testing.T) {
	a := newTestAgent(t, validTestConfig())

	if maxTrackedJobs <= 0 {
		t.Fatal("maxTrackedJobs must be positive")
	}
	for i := 0; i < maxTrackedJobs+1; i++ {
		a.markProcessed(fmt.Sprintf("job-%d", i))
	}
	if a.processedJobs.has("job-0") {
		t.Error("oldest terminal job must be evicted first")
	}
	for i := 1; i <= maxTrackedJobs; i++ {
		if !a.processedJobs.has(fmt.Sprintf("job-%d", i)) {
			t.Fatalf("job-%d missing after FIFO eviction", i)
		}
	}

	for i := 0; i < maxTrackedJobs+1; i++ {
		a.extractProgress.set(fmt.Sprintf("p-%d", i), i)
	}
	if _, ok := a.extractProgress.get("p-0"); ok {
		t.Error("oldest progress entry must be evicted first")
	}
	if next, ok := a.extractProgress.get(fmt.Sprintf("p-%d", maxTrackedJobs)); !ok || next != maxTrackedJobs {
		t.Errorf("newest progress entry lost: next=%d ok=%v", next, ok)
	}
}
