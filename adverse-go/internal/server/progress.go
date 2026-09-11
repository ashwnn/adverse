package server

import (
	"sort"
	"time"
)

// Bounds on the per-agent JobProgress beacon extension. Four jobs with 128
// sequence numbers each is a few KB of JSON even before job/hive strings, so
// the extension stays far below the 2MB frame cap.
const (
	// MaxJobProgressJobs caps how many jobs are reported per agent.
	MaxJobProgressJobs = 4
	// MaxJobProgressMissing caps how many missing sequence numbers are listed
	// per job.
	MaxJobProgressMissing = 128

	// maxJobProgressHive bounds the agent-supplied hive label echoed in
	// progress output. Hive identifiers are short; a longer value cannot be a
	// legitimate hive name and is omitted rather than inflating the frame.
	maxJobProgressHive = 256
)

// JobProgress reports the server's chunk reassembly state for one job so an
// agent can resend only missing sequence numbers, prune acknowledged chunks,
// and detect completion.
type JobProgress struct {
	JobID    string   `json:"job_id"`
	Hive     string   `json:"hive,omitempty"`
	Total    int      `json:"total"`
	Received int      `json:"received"`
	Missing  []uint32 `json:"missing,omitempty"`
	Complete bool     `json:"complete"`
}

// JobProgressForAgent returns bounded chunk-recovery progress for the jobs the
// server can attribute to agentID via its task records (tasks are keyed per
// agent; a job's chunk state is keyed by the task/job ID). Only jobs with a
// known total (Total > 0) and live reassembly state are included; pruned or
// total-less jobs are omitted. At most MaxJobProgressJobs jobs are returned
// (newest task first, job ID ascending on ties) and each job lists at most
// MaxJobProgressMissing missing sequence numbers in ascending order. Complete
// jobs report Complete:true and omit Missing.
func (s *Server) JobProgressForAgent(agentID string) []JobProgress {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobProgressForAgentLocked(agentID)
}

// jobProgressForAgentLocked implements JobProgressForAgent. Caller must hold
// s.mu.
func (s *Server) jobProgressForAgentLocked(agentID string) []JobProgress {
	type jobRef struct {
		id      string
		created time.Time
	}
	refs := make([]jobRef, 0, MaxJobProgressJobs)
	for _, t := range s.Tasks {
		if t.AgentID != agentID {
			continue
		}
		ch, ok := s.Chunks[t.ID]
		if !ok || ch.Total <= 0 {
			continue
		}
		refs = append(refs, jobRef{id: t.ID, created: t.CreatedAt})
	}
	// Deterministic order: newest task first, job ID ascending on ties, so
	// truncation is stable regardless of map iteration order.
	sort.Slice(refs, func(i, j int) bool {
		if !refs[i].created.Equal(refs[j].created) {
			return refs[i].created.After(refs[j].created)
		}
		return refs[i].id < refs[j].id
	})
	if len(refs) > MaxJobProgressJobs {
		refs = refs[:MaxJobProgressJobs]
	}

	out := make([]JobProgress, 0, len(refs))
	for _, ref := range refs {
		ch := s.Chunks[ref.id]
		if ch == nil {
			continue
		}
		jp := JobProgress{
			JobID:    ref.id,
			Total:    ch.Total,
			Received: len(ch.Chunks),
			Complete: allChunksPresentLocked(ch),
		}
		// Hive: from the lowest received seq so the value is deterministic
		// even for interleaved multi-hive jobs. Omitted when no chunk exists.
		minSeq, haveFirst := uint32(0), false
		for seq, piece := range ch.Chunks {
			if !haveFirst || seq < minSeq {
				minSeq, haveFirst = seq, true
				jp.Hive = piece.hive
			}
		}
		if len(jp.Hive) > maxJobProgressHive {
			jp.Hive = ""
		}
		if !jp.Complete {
			for seq := 0; seq < ch.Total && len(jp.Missing) < MaxJobProgressMissing; seq++ {
				if _, ok := ch.Chunks[uint32(seq)]; !ok {
					jp.Missing = append(jp.Missing, uint32(seq))
				}
			}
		}
		out = append(out, jp)
	}
	return out
}
