package server

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// A dispatched task that is never acked is retried, then expired after the
// retry budget is exhausted.
func TestTaskExpiryRetryBudget(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"

	srv.EnqueueTask(agentID, "t-retry", "noop", nil)
	if _, ok := srv.NextTask(agentID); !ok {
		t.Fatal("expected dispatch")
	}

	timeout := srv.TaskTimeout()
	now := time.Now()
	// One expiry cycle: retry (still under budget).
	srv.ExpireTasksLocked(agentID, now.Add(timeout+time.Second), timeout)
	tk, _ := srv.GetTask("t-retry")
	if tk.State != TaskQueued || tk.Retries != 1 {
		t.Fatalf("expected requeued with 1 retry, got state=%s retries=%d", tk.State, tk.Retries)
	}

	// Redispatch and burn the remaining retries.
	for i := 0; i < MaxTaskRetries; i++ {
		if _, ok := srv.NextTask(agentID); !ok {
			t.Fatal("expected redispatch")
		}
		srv.ExpireTasksLocked(agentID, now.Add(time.Duration(i+2)*timeout), timeout)
	}
	tk, _ = srv.GetTask("t-retry")
	if tk.State != TaskExpired {
		t.Fatalf("expected expired after budget, got state=%s retries=%d", tk.State, tk.Retries)
	}
}

// Acked tasks time out from AckedAt, not DispatchedAt.
func TestTaskExpiryAckedRef(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"

	srv.EnqueueTask(agentID, "t-ack", "sleep", map[string]any{"seconds": 1})
	if _, ok := srv.NextTask(agentID); !ok {
		t.Fatal("expected dispatch")
	}
	srv.AckTask(agentID, "t-ack")
	tk, _ := srv.GetTask("t-ack")
	if tk.State != TaskAcked {
		t.Fatalf("expected acked, got %s", tk.State)
	}

	// Just before the deadline: still acked.
	timeout := srv.TaskTimeout()
	srv.ExpireTasksLocked(agentID, tk.AckedAt.Add(timeout/2), timeout)
	tk, _ = srv.GetTask("t-ack")
	if tk.State != TaskAcked {
		t.Fatalf("should not expire early, got %s", tk.State)
	}
}

// Queued tasks survive a state save/load cycle; dispatched/acked revert to
// queued because sessions are memory-only.
func TestTaskPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	srv := newTestServer(t)
	srv.SetStateDir(dir)
	agentID := "aabbccdd"

	srv.EnqueueTask(agentID, "t-persist", "noop", nil)
	srv.EnqueueTask(agentID, "t-flown", "sleep", map[string]any{"seconds": 1})
	if _, ok := srv.NextTask(agentID); !ok {
		t.Fatal("expected dispatch of t-flown")
	}
	srv.AckTask(agentID, "t-flown")
	srv.CompleteTask(agentID, "t-persist", "") // t-persist was never dispatched; mark directly for coverage

	// Simulate restart.
	srv2 := newTestServer(t)
	srv2.SetStateDir(dir)
	if err := srv2.LoadState(); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Join(dir, "state.json")

	tk, ok := srv2.GetTask("t-persist")
	if !ok {
		t.Fatal("completed task not restored")
	}
	if tk.State != TaskCompleted {
		t.Fatalf("completed task should stay completed, got %s", tk.State)
	}

	tk, ok = srv2.GetTask("t-flown")
	if !ok {
		t.Fatal("acked task not restored")
	}
	if tk.State != TaskQueued {
		t.Fatalf("in-flight task should revert to queued on restart, got %s", tk.State)
	}

	// The FIFO should be usable after restore.
	msg, ok := srv2.NextTask(agentID)
	if !ok || msg["task_id"] != "t-flown" {
		t.Fatalf("expected t-flown next after restore, got %v (ok=%v)", msg, ok)
	}
}

// Re-enqueueing the same task ID is idempotent.
func TestTaskIdempotentEnqueue(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	id1 := srv.EnqueueTask(agentID, "t-idem", "noop", nil)
	id2 := srv.EnqueueTask(agentID, "t-idem", "noop", nil)
	if id1 != id2 {
		t.Fatalf("expected same id, got %s vs %s", id1, id2)
	}
	// Only one dispatch should come out.
	if _, ok := srv.NextTask(agentID); !ok {
		t.Fatal("expected one dispatch")
	}
	if _, ok := srv.NextTask(agentID); ok {
		t.Fatal("expected no second dispatch for duplicate enqueue")
	}
}

// Kill task completion on dispatch and epoch round-trip.
func TestKillTaskLifecycle(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	_, epoch, err := srv.EnqueueKill(agentID, "kill_switch")
	if err != nil {
		t.Fatal(err)
	}
	tk, _ := srv.GetTask("kill-" + itoa(epoch))
	if tk.State != TaskQueued {
		t.Fatalf("expected queued kill, got %s", tk.State)
	}
	msg, ok := srv.NextTask(agentID)
	if !ok {
		t.Fatal("expected kill dispatch")
	}
	if msg["type"] != "kill" || uint64(msg["epoch"].(float64)) != epoch {
		t.Fatalf("unexpected kill msg: %v", msg)
	}
	tk, _ = srv.GetTask("kill-" + itoa(epoch))
	if tk.State != TaskCompleted {
		t.Fatalf("expected completed kill on dispatch, got %s", tk.State)
	}
}

// Consumed task IDs are written back out of the FIFO, requeue does not append
// duplicates, and every task is dispatched exactly once.
func TestTaskOrderTrimAndRequeue(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.EnqueueTask(agentID, "t1", "noop", nil)
	srv.EnqueueTask(agentID, "t2", "noop", nil)
	srv.EnqueueTask(agentID, "t3", "noop", nil)

	srv.mu.Lock()
	if got := len(srv.TaskOrder[agentID]); got != 3 {
		srv.mu.Unlock()
		t.Fatalf("initial FIFO length = %d, want 3", got)
	}
	srv.mu.Unlock()

	if msg, ok := srv.NextTask(agentID); !ok || msg["task_id"] != "t1" {
		t.Fatalf("expected t1 dispatched, got %v (ok=%v)", msg, ok)
	}

	srv.mu.Lock()
	if got := len(srv.TaskOrder[agentID]); got != 2 {
		srv.mu.Unlock()
		t.Fatalf("consumed ID not written back: FIFO length = %d, want 2", got)
	}
	for _, id := range srv.TaskOrder[agentID] {
		if id == "t1" {
			srv.mu.Unlock()
			t.Fatal("dispatched task ID still present in FIFO")
		}
	}
	// Requeue the dispatched task: exactly one FIFO entry may result.
	tk, _ := srv.taskLocked(agentID, "t1")
	srv.requeueLocked(tk)
	dup := 0
	for _, id := range srv.TaskOrder[agentID] {
		if id == "t1" {
			dup++
		}
	}
	srv.mu.Unlock()
	if dup != 1 {
		t.Fatalf("requeue produced %d FIFO entries for t1, want 1", dup)
	}

	seen := map[string]int{}
	for {
		msg, ok := srv.NextTask(agentID)
		if !ok {
			break
		}
		seen[msg["task_id"].(string)]++
	}
	for _, id := range []string{"t1", "t2", "t3"} {
		if seen[id] != 1 {
			t.Fatalf("task %s dispatched %d times, want 1 (all: %v)", id, seen[id], seen)
		}
	}
	srv.mu.Lock()
	if got := len(srv.TaskOrder[agentID]); got != 0 {
		srv.mu.Unlock()
		t.Fatalf("FIFO not empty after draining: %d entries", got)
	}
	srv.mu.Unlock()
}

// Pruning terminal tasks also removes consumed/dangling IDs from TaskOrder.
func TestPruneTasksReconcilesTaskOrder(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"

	for i := 0; i < maxPersistedTasks+5; i++ {
		id := fmt.Sprintf("t-%04d", i)
		srv.EnqueueTask(agentID, id, "noop", nil)
		// Complete without dispatching so the ID remains in the FIFO; the
		// prune pass must reconcile it away.
		srv.CompleteTask(agentID, id, "")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if got := len(srv.Tasks); got > maxPersistedTasks {
		t.Fatalf("task table not pruned: %d > %d", got, maxPersistedTasks)
	}
	var dangling int
	for _, id := range srv.TaskOrder[agentID] {
		if _, ok := srv.taskLocked(agentID, id); !ok {
			dangling++
		}
	}
	if dangling != 0 {
		t.Fatalf("TaskOrder contains %d dangling IDs after prune", dangling)
	}
	if got := len(srv.TaskOrder[agentID]); got != 0 {
		t.Fatalf("terminal IDs should not remain queued: %d entries", got)
	}
}

// Idempotency is keyed on (agentID, taskID): reusing a job_id for a second
// agent creates a distinct task instead of silently dropping the enqueue.
func TestTaskIdempotentPerAgent(t *testing.T) {
	srv := newTestServer(t)
	agentA := "aaaa"
	agentB := "bbbb"

	// Same agent: idempotent.
	if id := srv.EnqueueTask(agentA, "job-x", "noop", nil); id != "job-x" {
		t.Fatalf("id = %q, want job-x", id)
	}
	if id := srv.EnqueueTask(agentA, "job-x", "noop", nil); id != "job-x" {
		t.Fatalf("idempotent re-enqueue returned %q, want job-x", id)
	}
	if n := srv.PendingTaskCount(agentA); n != 1 {
		t.Fatalf("agent A pending tasks = %d, want 1", n)
	}

	// Different agent with the same job_id: not dropped.
	if id := srv.EnqueueTask(agentB, "job-x", "noop", nil); id != "job-x" {
		t.Fatalf("cross-agent id = %q, want job-x", id)
	}
	if n := srv.PendingTaskCount(agentB); n != 1 {
		t.Fatalf("agent B pending tasks = %d, want 1", n)
	}

	// Each agent dispatches its own task.
	msgA, ok := srv.NextTask(agentA)
	if !ok || msgA["task_id"] != "job-x" {
		t.Fatalf("agent A dispatch = %v (ok=%v)", msgA, ok)
	}
	if _, ok := srv.NextTask(agentA); ok {
		t.Fatal("agent A had an extra queued task")
	}
	msgB, ok := srv.NextTask(agentB)
	if !ok || msgB["task_id"] != "job-x" {
		t.Fatalf("agent B dispatch = %v (ok=%v)", msgB, ok)
	}

	// Task records are addressable per agent.
	if _, ok := srv.GetTaskForAgent(agentA, "job-x"); !ok {
		t.Fatal("agent A task record missing")
	}
	if _, ok := srv.GetTaskForAgent(agentB, "job-x"); !ok {
		t.Fatal("agent B task record missing")
	}
}

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}
