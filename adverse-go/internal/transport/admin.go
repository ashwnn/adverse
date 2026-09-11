package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ashwnn/adverse-go/internal/adminapi"
	"github.com/ashwnn/adverse-go/internal/server"
)

// AdminHandler serves the operator API under /admin/v1/*. Every route
// requires a bearer token that matches the server's configured operator token
// (constant-time compare). Without a configured token the handler fails
// closed with 503.
type AdminHandler struct {
	Server    *server.Server
	Logger    *slog.Logger
	StartedAt time.Time
	Version   string

	tokenHash [32]byte
	hasToken  bool
	limiter   *ipLimiter
}

// NewAdminHandler creates the admin handler. operatorToken is the shared
// secret operators must present; empty disables the API (fail closed).
func NewAdminHandler(s *server.Server, logger *slog.Logger, operatorToken, version string) *AdminHandler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &AdminHandler{
		Server:    s,
		Logger:    logger,
		StartedAt: time.Now(),
		Version:   version,
		limiter:   newIPLimiter(300, 60), // 300 req/min burst 60: operator CLIs with --wait poll every 2s
	}
	if operatorToken != "" {
		h.tokenHash = sha256.Sum256([]byte(operatorToken))
		h.hasToken = true
	}
	return h
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(r.URL.Path, adminapi.AdminPrefix) {
		writeAdminError(w, http.StatusNotFound, "unknown admin path")
		return
	}

	// Operator authentication: fail closed.
	if !h.hasToken {
		writeAdminError(w, http.StatusServiceUnavailable, "operator token not configured on server")
		return
	}

	// Rate limit before authentication so invalid-token brute force is bounded
	// and cannot append unbounded audit entries. Operator CLIs using --wait
	// poll every 2s, far below the 300/min budget.
	if !h.limiter.allow(clientIP(r)) {
		writeAdminError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		h.auditAuthFailure(r)
		writeAdminError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	token := strings.TrimPrefix(auth, prefix)
	if len(token) == 0 || subtle.ConstantTimeCompare(hashToken(token), h.tokenHash[:]) != 1 {
		h.auditAuthFailure(r)
		writeAdminError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}

	sub := strings.TrimPrefix(r.URL.Path, adminapi.AdminPrefix)
	switch {
	case sub == "/health" && r.Method == http.MethodGet:
		h.handleHealth(w, r)
	case sub == "/agents" && r.Method == http.MethodGet:
		h.handleAgents(w, r)
	case sub == "/tasks" && r.Method == http.MethodGet:
		h.handleListTasks(w, r)
	case sub == "/tasks" && r.Method == http.MethodPost:
		h.handleEnqueueTask(w, r)
	case sub == "/kill" && r.Method == http.MethodPost:
		h.handleKill(w, r)
	case sub == "/results" && r.Method == http.MethodGet:
		h.handleResults(w, r)
	default:
		writeAdminError(w, http.StatusNotFound, "unknown admin endpoint")
	}
}

func (h *AdminHandler) auditAuthFailure(r *http.Request) {
	h.Server.Audit("admin.auth_fail", map[string]any{"ip": clientIP(r), "path": r.URL.Path})
}

func (h *AdminHandler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	agents := h.Server.ListAgents()
	online := 0
	for _, a := range agents {
		if a.Online {
			online++
		}
	}
	tasks := h.Server.ListTasks("")
	queued := 0
	for _, t := range tasks {
		switch t.State {
		case server.TaskQueued, server.TaskDispatched, server.TaskAcked:
			queued++
		}
	}
	resp := adminapi.Health{
		Status:        "ok",
		Version:       h.Version,
		UptimeSeconds: time.Since(h.StartedAt).Seconds(),
		Agents:        len(agents),
		OnlineAgents:  online,
		QueuedTasks:   queued,
		ResultsStored: h.Server.ResultCount(),
	}
	writeAdminJSON(w, resp)
}

func (h *AdminHandler) handleAgents(w http.ResponseWriter, _ *http.Request) {
	agents := h.Server.ListAgents()
	out := make([]adminapi.AgentInfo, 0, len(agents))
	for _, a := range agents {
		out = append(out, adminapi.AgentInfo{
			AgentID:      a.AgentID,
			LastSeen:     a.LastSeen,
			Online:       a.Online,
			KillEpoch:    a.KillEpoch,
			PendingTasks: h.Server.PendingTaskCount(a.AgentID),
		})
	}
	writeAdminJSON(w, out)
}

func (h *AdminHandler) handleListTasks(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")
	out := make([]adminapi.TaskInfo, 0)
	for _, t := range h.Server.ListTasks(agent) {
		out = append(out, taskToInfo(t))
	}
	writeAdminJSON(w, out)
}

func (h *AdminHandler) handleEnqueueTask(w http.ResponseWriter, r *http.Request) {
	var req adminapi.EnqueueTaskRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AgentID == "" {
		writeAdminError(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	switch req.Action {
	case "extract", "sleep", "noop":
	default:
		writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("unknown action %q", req.Action))
		return
	}
	if req.JobID == "" {
		req.JobID = fmt.Sprintf("task-%d", time.Now().UnixNano())
	}

	extra := map[string]any{"job_id": req.JobID}
	switch req.Action {
	case "extract":
		// Mirror the agent config bound: chunk_size must be in (0, 512KB].
		// Zero (omitted) is invalid here because the CLI always supplies a
		// value, and an out-of-range value would otherwise be forwarded to
		// the agent unchecked.
		if req.ChunkSize <= 0 || req.ChunkSize > 512*1024 {
			writeAdminError(w, http.StatusBadRequest, fmt.Sprintf("chunk_size must be in (0, 512KB], got %d", req.ChunkSize))
			return
		}
		hives := req.Hives
		if len(hives) == 0 {
			hives = []string{"SYSTEM"}
		}
		extra["hives"] = hives
		extra["chunk_size"] = req.ChunkSize
	case "sleep":
		extra["seconds"] = req.Seconds
	}

	taskID := h.Server.EnqueueTask(req.AgentID, req.JobID, req.Action, extra)
	h.Server.Audit("admin.task_enqueue", map[string]any{"agent": req.AgentID, "task": taskID, "action": req.Action, "ip": clientIP(r)})
	writeAdminJSON(w, adminapi.EnqueueTaskResponse{TaskID: taskID})
}

func (h *AdminHandler) handleKill(w http.ResponseWriter, r *http.Request) {
	var req adminapi.KillRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AgentID == "" {
		writeAdminError(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	if req.Payload == "" {
		req.Payload = "kill"
	}
	if req.Payload != "kill" && req.Payload != "kill_switch" {
		writeAdminError(w, http.StatusBadRequest, `payload must be "kill" or "kill_switch"`)
		return
	}
	taskID, epoch, err := h.Server.EnqueueKill(req.AgentID, req.Payload)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.Server.Audit("admin.kill", map[string]any{"agent": req.AgentID, "task": taskID, "epoch": epoch, "payload": req.Payload, "ip": clientIP(r)})
	writeAdminJSON(w, adminapi.KillResponse{TaskID: taskID, Epoch: epoch})
}

func (h *AdminHandler) handleResults(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")
	if agent == "" {
		writeAdminError(w, http.StatusBadRequest, "agent is required")
		return
	}
	task := r.URL.Query().Get("task")
	withReassembled := r.URL.Query().Get("reassembled") == "1"

	resp := adminapi.ResultsResponse{Agent: agent, Task: task}
	all := h.Server.ResultsFor(agent)
	filtered := all
	if task != "" {
		filtered = nil
		for _, e := range all {
			if e.TaskID == task {
				filtered = append(filtered, e)
			}
		}
	}
	for _, e := range filtered {
		resp.Results = append(resp.Results, adminapi.ResultEntry{TaskID: e.TaskID, Payload: e.Payload, Ts: e.Ts})
	}
	if withReassembled && task != "" {
		if byHive, ok := h.Server.GetReassembledByHive(task); ok {
			resp.Reassembled = make(map[string]string, len(byHive))
			for hive, data := range byHive {
				resp.Reassembled[hive] = base64.StdEncoding.EncodeToString(data)
			}
			resp.Complete = true
		} else if _, _, exists := h.Server.ChunkStatus(task); exists {
			resp.Complete = false
		}
	}
	writeAdminJSON(w, resp)
}

func taskToInfo(t server.Task) adminapi.TaskInfo {
	info := adminapi.TaskInfo{
		ID:        t.ID,
		AgentID:   t.AgentID,
		Action:    t.Action,
		Payload:   t.Payload,
		State:     string(t.State),
		Retries:   t.Retries,
		Error:     t.Err,
		CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if !t.DispatchedAt.IsZero() {
		info.DispatchedAt = t.DispatchedAt.UTC().Format(time.RFC3339Nano)
	}
	if !t.AckedAt.IsZero() {
		info.AckedAt = t.AckedAt.UTC().Format(time.RFC3339Nano)
	}
	if !t.CompletedAt.IsZero() {
		info.CompletedAt = t.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	return info
}

func writeAdminJSON(w http.ResponseWriter, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "encode failure")
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(raw)
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	raw, _ := json.Marshal(adminapi.ErrorResponse{Error: msg})
	w.WriteHeader(status)
	w.Write(raw)
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// clientIP extracts the source IP from RemoteAddr.
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// ipLimiter is a minimal per-IP token bucket (rate per minute, burst).
type ipLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per minute
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(ratePerMin, burst float64) *ipLimiter {
	return &ipLimiter{rate: ratePerMin, burst: burst, buckets: make(map[string]*bucket)}
}

func (l *ipLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Minutes()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	// Opportunistic cleanup to bound memory.
	if len(l.buckets) > 4096 {
		for k, v := range l.buckets {
			if now.Sub(v.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
	}
	return true
}
