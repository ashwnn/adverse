package server

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// TaskState enumerates the operator-visible lifecycle of a task.
//
//	queued     -> waiting for the next agent beacon
//	dispatched -> sent to the agent in a task frame, awaiting ack
//	acked      -> agent confirmed receipt, execution in progress
//	completed  -> result received (status result or final data chunk)
//	failed     -> terminal error (validation, retry budget exhausted)
//	expired    -> dispatched/acked task timed out and was retired
//
// Kill tasks skip acked: they transition queued -> dispatched -> completed
// because the agent exits without sending an ack after accepting the kill.
type TaskState string

const (
	TaskQueued     TaskState = "queued"
	TaskDispatched TaskState = "dispatched"
	TaskAcked      TaskState = "acked"
	TaskCompleted  TaskState = "completed"
	TaskFailed     TaskState = "failed"
	TaskExpired    TaskState = "expired"
)

// Task timeout and retry policy. TaskTimeout is expressed in beacon periods so
// the policy survives server restarts and profile changes.
const (
	MaxTaskRetries       = 3
	TaskTimeoutBeaconMul = 3 // timeout = 3 * (interval + jitter)
)

// Task is the server-side lifecycle record for one operator-issued task.
type Task struct {
	ID           string         `json:"id"`
	AgentID      string         `json:"agent_id"`
	Action       string         `json:"action"`
	Payload      map[string]any `json:"payload,omitempty"`
	Epoch        uint64         `json:"epoch,omitempty"` // kill epoch (kill tasks only)
	State        TaskState      `json:"state"`
	CreatedAt    time.Time      `json:"created_at"`
	DispatchedAt time.Time      `json:"dispatched_at,omitempty"`
	AckedAt      time.Time      `json:"acked_at,omitempty"`
	CompletedAt  time.Time      `json:"completed_at,omitempty"`
	Retries      int            `json:"retries"`
	Err          string         `json:"error,omitempty"`
}

// maxPersistedTasks caps the number of tasks kept in memory/state per agent.
const maxPersistedTasks = 500

// taskMapKey is the internal Tasks map key. Keying on (agentID, taskID) keeps
// task IDs unique per agent: operator-visible IDs stay stable but the same
// job_id reused by two agents is two distinct tasks instead of one dropped
// enqueue.
func taskMapKey(agentID, taskID string) string {
	return agentID + "\x00" + taskID
}

// taskLocked returns the task for (agentID, taskID). Caller must hold s.mu.
func (s *Server) taskLocked(agentID, taskID string) (*Task, bool) {
	t, ok := s.Tasks[taskMapKey(agentID, taskID)]
	return t, ok
}

// taskQueuedLocked reports whether the ID is already present in the agent's
// FIFO. Caller must hold s.mu.
func (s *Server) taskQueuedLocked(agentID, taskID string) bool {
	for _, id := range s.TaskOrder[agentID] {
		if id == taskID {
			return true
		}
	}
	return false
}

// newTask creates a queued task. Caller must hold s.mu.
func newTask(agentID, taskID, action string, extra map[string]any) *Task {
	payload := map[string]any{"action": action}
	for k, v := range extra {
		payload[k] = v
	}
	if taskID == "" {
		taskID = fmt.Sprintf("task-%d", time.Now().UnixNano())
	}
	return &Task{
		ID:        taskID,
		AgentID:   agentID,
		Action:    action,
		Payload:   payload,
		State:     TaskQueued,
		CreatedAt: time.Now().UTC(),
	}
}

// enqueueTaskLocked stores a task and appends its ID to the agent FIFO.
// Caller must hold s.mu.
func (s *Server) enqueueTaskLocked(t *Task) {
	if s.Tasks == nil {
		s.Tasks = make(map[string]*Task)
	}
	key := taskMapKey(t.AgentID, t.ID)
	if existing, ok := s.Tasks[key]; ok {
		// Idempotent: an operator retry of the same job returns the same task.
		_ = existing
		return
	}
	s.Tasks[key] = t
	s.TaskOrder[t.AgentID] = append(s.TaskOrder[t.AgentID], t.ID)
	s.Audit("task.enqueue", map[string]any{
		"agent": t.AgentID, "task": t.ID, "action": t.Action,
	})
}

// popQueuedLocked returns and marks-dispatched the oldest queued task for an
// agent. The consumed prefix is written back to the FIFO even on success, so
// dispatched IDs do not accumulate or get requeued twice. Returns nil if the
// queue is empty. Caller must hold s.mu.
func (s *Server) popQueuedLocked(agentID string) *Task {
	q := s.TaskOrder[agentID]
	for len(q) > 0 {
		id := q[0]
		q = q[1:]
		t, ok := s.taskLocked(agentID, id)
		if !ok || t.State != TaskQueued {
			continue
		}
		s.TaskOrder[agentID] = q
		t.State = TaskDispatched
		t.DispatchedAt = time.Now().UTC()
		s.Audit("task.dispatch", map[string]any{
			"agent": agentID, "task": t.ID, "action": t.Action,
		})
		return t
	}
	s.TaskOrder[agentID] = nil
	return nil
}

// requeueLocked puts a task back in the FIFO for retry. Caller must hold s.mu.
func (s *Server) requeueLocked(t *Task) {
	t.State = TaskQueued
	t.DispatchedAt = time.Time{}
	t.AckedAt = time.Time{}
	if !s.taskQueuedLocked(t.AgentID, t.ID) {
		s.TaskOrder[t.AgentID] = append(s.TaskOrder[t.AgentID], t.ID)
	}
	s.Audit("task.retry", map[string]any{
		"agent": t.AgentID, "task": t.ID, "retries": t.Retries,
	})
}

// taskDoneLocked records a terminal (or acked) transition. Caller must hold s.mu.
func (s *Server) taskDoneLocked(t *Task, state TaskState, errMsg string) {
	t.State = state
	if state == TaskCompleted || state == TaskFailed || state == TaskExpired {
		t.CompletedAt = time.Now().UTC()
		// Chunk state is retrievable until retention elapses after the task
		// terminal state; mark it so pruneChunksLocked can reclaim it.
		if ch, ok := s.Chunks[t.ID]; ok && ch.CompletedAt.IsZero() {
			ch.CompletedAt = t.CompletedAt
		}
	}
	if errMsg != "" {
		t.Err = errMsg
	}
	s.Audit("task."+string(state), map[string]any{
		"agent": t.AgentID, "task": t.ID, "error": errMsg,
	})
}

// AckTask transitions a dispatched task to acked. No-op for other states.
// The acked state is persisted so a restart cannot revert a running task.
func (s *Server) AckTask(agentID, taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.taskLocked(agentID, taskID)
	if !ok {
		return
	}
	if t.State == TaskDispatched {
		t.State = TaskAcked
		t.AckedAt = time.Now().UTC()
		s.Audit("task.ack", map[string]any{"agent": agentID, "task": taskID})
		s.flushState()
	}
}

// CompleteTask marks a task completed. If errMsg is non-empty the task is
// marked failed instead. No-op for unknown or already-terminal tasks.
func (s *Server) CompleteTask(agentID, taskID string, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.taskLocked(agentID, taskID)
	if !ok {
		return
	}
	if t.State == TaskCompleted || t.State == TaskFailed || t.State == TaskExpired {
		return
	}
	state := TaskCompleted
	if errMsg != "" {
		state = TaskFailed
	}
	s.taskDoneLocked(t, state, errMsg)
	s.flushState()
}

// ExpireTasksLocked retires tasks whose dispatch/ack deadline passed. Caller
// must hold s.mu. Tasks still under the retry budget are requeued.
func (s *Server) ExpireTasksLocked(agentID string, now time.Time, timeout time.Duration) {
	var pending []*Task
	for _, t := range s.Tasks {
		if t.AgentID != agentID || t.State != TaskDispatched && t.State != TaskAcked {
			continue
		}
		ref := t.DispatchedAt
		if t.State == TaskAcked {
			ref = t.AckedAt
		}
		if ref.IsZero() || now.Sub(ref) < timeout {
			continue
		}
		pending = append(pending, t)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].CreatedAt.Before(pending[j].CreatedAt) })
	for _, t := range pending {
		if t.Retries < MaxTaskRetries {
			t.Retries++
			s.requeueLocked(t)
		} else {
			s.taskDoneLocked(t, TaskExpired, fmt.Sprintf("timed out after %d retries", t.Retries))
		}
	}
}

// TaskTimeout returns the dispatch/ack deadline derived from beacon cadence.
func (s *Server) TaskTimeout() time.Duration {
	interval := s.BeaconIntervalS
	if interval <= 0 {
		interval = 30
	}
	jitter := s.BeaconJitterS
	if jitter < 0 {
		jitter = 0
	}
	return time.Duration((interval+jitter)*TaskTimeoutBeaconMul) * time.Second
}

// GetTask returns a copy of a task by ID. Task IDs are unique per agent, not
// globally; if the same ID is queued for more than one agent the most recently
// created task is returned. Use GetTaskForAgent when the agent is known.
func (s *Server) GetTask(taskID string) (Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *Task
	for _, t := range s.Tasks {
		if t.ID != taskID {
			continue
		}
		if found == nil || t.CreatedAt.After(found.CreatedAt) {
			found = t
		}
	}
	if found == nil {
		return Task{}, false
	}
	return *found, true
}

// GetTaskForAgent returns a copy of the task for (agentID, taskID).
func (s *Server) GetTaskForAgent(agentID, taskID string) (Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.taskLocked(agentID, taskID)
	if !ok {
		return Task{}, false
	}
	return *t, true
}

// ListTasks returns all tasks for an agent, newest first. A nil or empty
// agentID returns tasks for all agents.
func (s *Server) ListTasks(agentID string) []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Task, 0, len(s.Tasks))
	for _, t := range s.Tasks {
		if agentID != "" && t.AgentID != agentID {
			continue
		}
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// pruneTasksLocked drops the oldest completed/failed/expired tasks when the
// per-agent budget is exceeded, and removes consumed/dangling IDs from the
// per-agent FIFOs so TaskOrder cannot grow without bound. Caller must hold s.mu.
func (s *Server) pruneTasksLocked() {
	perAgent := make(map[string][]*Task)
	for _, t := range s.Tasks {
		if t.State == TaskQueued || t.State == TaskDispatched || t.State == TaskAcked {
			continue // never prune in-flight tasks
		}
		perAgent[t.AgentID] = append(perAgent[t.AgentID], t)
	}
	for _, list := range perAgent {
		if len(list) <= maxPersistedTasks {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].CompletedAt.Before(list[j].CompletedAt) })
		for _, t := range list[:len(list)-maxPersistedTasks] {
			delete(s.Tasks, taskMapKey(t.AgentID, t.ID))
		}
	}
	// Reconcile FIFOs with the task table: keep only IDs that still exist and
	// are queued (dispatched/terminal IDs are tracked by their task state).
	for agentID, ids := range s.TaskOrder {
		kept := ids[:0]
		for _, id := range ids {
			t, ok := s.taskLocked(agentID, id)
			if ok && t.State == TaskQueued {
				kept = append(kept, id)
			}
		}
		s.TaskOrder[agentID] = kept
	}
}

// serializeTasksLocked builds the persisted task set, keyed by operator-visible
// task ID to preserve the on-disk format. If two agents share a task ID, the
// second entry falls back to the internal composite key so neither is lost.
// Caller must hold s.mu.
func (s *Server) serializeTasksLocked() map[string]Task {
	out := make(map[string]Task, len(s.Tasks))
	for _, t := range s.Tasks {
		key := t.ID
		if _, exists := out[key]; exists {
			key = taskMapKey(t.AgentID, t.ID)
		}
		out[key] = *t
	}
	return out
}

// restoreTasksLocked restores persisted tasks and rebuilds FIFOs. Caller must
// hold s.mu. Dispatched/acked tasks revert to queued because a server restart
// requires agents to re-hello and sessions are memory-only. Persisted keys may
// be plain task IDs (legacy format) or composite keys for cross-agent ID
// collisions; Task.AgentID/ID are authoritative.
func (s *Server) restoreTasksLocked(tasks map[string]Task) {
	if s.Tasks == nil {
		s.Tasks = make(map[string]*Task)
	}
	for _, t := range tasks {
		if t.State == TaskDispatched || t.State == TaskAcked {
			t.State = TaskQueued
			t.DispatchedAt = time.Time{}
			t.AckedAt = time.Time{}
		}
		cp := t
		s.Tasks[taskMapKey(t.AgentID, t.ID)] = &cp
	}
	// Rebuild per-agent FIFOs in CreatedAt order.
	s.TaskOrder = make(map[string][]string)
	for _, t := range s.Tasks {
		if t.State == TaskQueued {
			s.TaskOrder[t.AgentID] = append(s.TaskOrder[t.AgentID], t.ID)
		}
	}
	for agent := range s.TaskOrder {
		ids := s.TaskOrder[agent]
		sort.Slice(ids, func(i, j int) bool {
			a, _ := s.taskLocked(agent, ids[i])
			b, _ := s.taskLocked(agent, ids[j])
			return a.CreatedAt.Before(b.CreatedAt)
		})
		s.TaskOrder[agent] = ids
	}
}

// taskWireMessage renders a task as a wire task message (type "task").
func (t *Task) taskWireMessage(ts time.Time) map[string]any {
	payloadBytes, _ := json.Marshal(t.Payload)
	return map[string]any{
		"type":     "task",
		"agent_id": t.AgentID,
		"task_id":  t.ID,
		"payload":  string(payloadBytes),
		"ts":       float64(ts.Unix()),
	}
}
