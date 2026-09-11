package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/message"
)

// sendProgressChunk feeds one chunked result into the server directly. total 0
// (or omitted by the caller) leaves the job's total unknown.
func sendProgressChunk(t *testing.T, srv *Server, agentID, jobID string, seq uint32, total int) {
	t.Helper()
	payload := map[string]any{
		"job_id":   jobID,
		"seq":      float64(seq),
		"data_b64": base64.StdEncoding.EncodeToString(makeTestChunkWire(seq, []byte("chunk-data"))),
	}
	if total > 0 {
		payload["total"] = float64(total)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal chunk payload: %v", err)
	}
	srv.HandleMessage(agentID, message.Make("result", agentID, jobID, string(raw), float64(time.Now().Unix())))
}

// Partial chunk state reports the correct Received count, sorted Missing list,
// hive, and Complete=false.
func TestJobProgressPartial(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.EnqueueTask(agentID, "job-partial", "extract", map[string]any{"job_id": "job-partial"})
	sendProgressChunk(t, srv, agentID, "job-partial", 0, 4)
	sendProgressChunk(t, srv, agentID, "job-partial", 2, 4)
	sendProgressChunk(t, srv, agentID, "job-partial", 3, 4)

	got := srv.JobProgressForAgent(agentID)
	if len(got) != 1 {
		t.Fatalf("expected 1 job, got %d: %+v", len(got), got)
	}
	jp := got[0]
	if jp.JobID != "job-partial" || jp.Total != 4 || jp.Received != 3 {
		t.Fatalf("unexpected progress: %+v", jp)
	}
	if jp.Complete {
		t.Fatal("partial job reported complete")
	}
	if jp.Hive != "SYS" {
		t.Fatalf("hive = %q, want SYS", jp.Hive)
	}
	if !reflect.DeepEqual(jp.Missing, []uint32{1}) {
		t.Fatalf("missing = %v, want [1]", jp.Missing)
	}
}

// A job with every seq 0..total-1 present reports Complete:true and omits
// Missing, matching allChunksPresentLocked semantics exactly.
func TestJobProgressComplete(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.EnqueueTask(agentID, "job-done", "extract", map[string]any{"job_id": "job-done"})
	for seq := uint32(0); seq < 3; seq++ {
		sendProgressChunk(t, srv, agentID, "job-done", seq, 3)
	}

	got := srv.JobProgressForAgent(agentID)
	if len(got) != 1 {
		t.Fatalf("expected 1 job, got %d", len(got))
	}
	jp := got[0]
	if !jp.Complete {
		t.Fatalf("job should be complete: %+v", jp)
	}
	if jp.Received != 3 || jp.Total != 3 {
		t.Fatalf("received/total = %d/%d, want 3/3", jp.Received, jp.Total)
	}
	if len(jp.Missing) != 0 {
		t.Fatalf("complete job must omit missing, got %v", jp.Missing)
	}

	// The complete job's task lifecycle is unchanged.
	tk, ok := srv.GetTaskForAgent(agentID, "job-done")
	if !ok || tk.State != TaskCompleted {
		t.Fatalf("task lifecycle changed: ok=%v state=%s", ok, tk.State)
	}
}

// The per-agent job list is capped at MaxJobProgressJobs, newest first, with a
// deterministic tie-break.
func TestJobProgressJobBound(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	total := MaxJobProgressJobs + 2
	for i := 0; i < total; i++ {
		jobID := fmt.Sprintf("job-%02d", i)
		srv.EnqueueTask(agentID, jobID, "extract", map[string]any{"job_id": jobID})
		sendProgressChunk(t, srv, agentID, jobID, 0, 5)
		time.Sleep(time.Millisecond) // distinct CreatedAt ordering
	}

	got := srv.JobProgressForAgent(agentID)
	if len(got) != MaxJobProgressJobs {
		t.Fatalf("expected %d jobs, got %d", MaxJobProgressJobs, len(got))
	}
	for i, jp := range got {
		want := fmt.Sprintf("job-%02d", total-1-i)
		if jp.JobID != want {
			t.Fatalf("job[%d] = %s, want %s (newest first)", i, jp.JobID, want)
		}
	}

	// Same call twice must return the identical order (map iteration order
	// must not leak through truncation).
	again := srv.JobProgressForAgent(agentID)
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("non-deterministic truncation:\n first=%+v\nsecond=%+v", got, again)
	}
}

// The Missing list is capped at MaxJobProgressMissing entries, ascending, even
// for a job with many unreceived seqs.
func TestJobProgressMissingBound(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.EnqueueTask(agentID, "job-wide", "extract", map[string]any{"job_id": "job-wide"})
	sendProgressChunk(t, srv, agentID, "job-wide", 0, 10000)

	got := srv.JobProgressForAgent(agentID)
	if len(got) != 1 {
		t.Fatalf("expected 1 job, got %d", len(got))
	}
	jp := got[0]
	if jp.Total != 10000 || jp.Received != 1 {
		t.Fatalf("unexpected total/received: %+v", jp)
	}
	if len(jp.Missing) != MaxJobProgressMissing {
		t.Fatalf("missing length = %d, want %d", len(jp.Missing), MaxJobProgressMissing)
	}
	for i, seq := range jp.Missing {
		if seq != uint32(i+1) {
			t.Fatalf("missing[%d] = %d, want %d (ascending window)", i, seq, i+1)
		}
	}
}

// Progress is scoped to the owning agent and only live, total-known jobs are
// reported: orphan chunk state, unknown totals, and other agents' jobs are
// omitted.
func TestJobProgressScopedAndLive(t *testing.T) {
	srv := newTestServer(t)
	agentA := "aaaa"
	agentB := "bbbb"

	srv.EnqueueTask(agentA, "job-a", "extract", map[string]any{"job_id": "job-a"})
	sendProgressChunk(t, srv, agentA, "job-a", 0, 2)

	srv.EnqueueTask(agentB, "job-b", "extract", map[string]any{"job_id": "job-b"})
	sendProgressChunk(t, srv, agentB, "job-b", 0, 2)

	// Unknown total: chunk accepted but total never declared.
	srv.EnqueueTask(agentA, "job-nototal", "extract", map[string]any{"job_id": "job-nototal"})
	sendProgressChunk(t, srv, agentA, "job-nototal", 0, 0)

	// Orphan chunk state: no task record maps it to any agent.
	sendProgressChunk(t, srv, agentA, "orphan", 0, 2)

	gotA := srv.JobProgressForAgent(agentA)
	if len(gotA) != 1 || gotA[0].JobID != "job-a" {
		t.Fatalf("agent A progress = %+v, want only job-a", gotA)
	}
	gotB := srv.JobProgressForAgent(agentB)
	if len(gotB) != 1 || gotB[0].JobID != "job-b" {
		t.Fatalf("agent B progress = %+v, want only job-b", gotB)
	}
	if got := srv.JobProgressForAgent("unknown-agent"); len(got) != 0 {
		t.Fatalf("unknown agent progress = %+v, want none", got)
	}
}

// Pruned terminal chunk state is no longer reported.
func TestJobProgressPrunedNotReported(t *testing.T) {
	srv := newTestServer(t)
	srv.ChunkRetention = 10 * time.Millisecond
	agentID := "aabbccdd"
	srv.EnqueueTask(agentID, "job-expired", "extract", map[string]any{"job_id": "job-expired"})
	sendProgressChunk(t, srv, agentID, "job-expired", 0, 1)

	if got := srv.JobProgressForAgent(agentID); len(got) != 1 || !got[0].Complete {
		t.Fatalf("complete job missing before retention: %+v", got)
	}

	time.Sleep(25 * time.Millisecond)
	srv.flushState() // lazy prune on state mutation

	if got := srv.JobProgressForAgent(agentID); len(got) != 0 {
		t.Fatalf("pruned job still reported: %+v", got)
	}
}

// An oversized (agent-supplied) hive label is omitted instead of inflating the
// beacon payload.
func TestJobProgressHiveCap(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.EnqueueTask(agentID, "job-hive", "extract", map[string]any{"job_id": "job-hive"})

	payload, err := json.Marshal(map[string]any{
		"job_id":   "job-hive",
		"hive":     strings.Repeat("A", maxJobProgressHive+1),
		"total":    float64(2),
		"data_b64": base64.StdEncoding.EncodeToString(makeTestChunkWire(0, []byte("x"))),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.HandleMessage(agentID, message.Make("result", agentID, "job-hive", string(payload), float64(time.Now().Unix())))

	got := srv.JobProgressForAgent(agentID)
	if len(got) != 1 {
		t.Fatalf("expected 1 job, got %d", len(got))
	}
	if got[0].Hive != "" {
		t.Fatalf("oversized hive should be omitted, got %d bytes", len(got[0].Hive))
	}
}
