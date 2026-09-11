package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/server"
	"github.com/ashwnn/adverse-go/internal/wire"
)

// progressHello registers an agent via the full forward-secret handshake and
// returns the session key material needed to build/parse session frames.
func progressHello(t *testing.T, h *Handler, srv *server.Server, agentID, sid string) (fsKey [32]byte, fsPrefix [3]byte) {
	t.Helper()
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral: %v", err)
	}
	var ephPub [32]byte
	copy(ephPub[:], ephPriv.PublicKey().Bytes())
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	return doHello(t, h, srv, agentID, ephPriv, ephPub, salt, sid)
}

// deliverProgressChunk feeds one chunked result into the server core directly
// (the wire path for results is exercised elsewhere).
func deliverProgressChunk(t *testing.T, srv *server.Server, agentID, jobID string, seq uint32, total int) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"job_id":   jobID,
		"hive":     "SYSTEM",
		"total":    float64(total),
		"data_b64": base64.StdEncoding.EncodeToString(makeChunkWire(seq, "SYSTEM", "chunk-data")),
	})
	if err != nil {
		t.Fatalf("marshal chunk payload: %v", err)
	}
	srv.HandleMessage(agentID, message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix())))
}

// postFrame sends one client frame through the HTTP handler and returns the
// decrypted response message map plus the raw response frame.
func postFrame(t *testing.T, h *Handler, body []byte, fsKey [32]byte, fsPrefix [3]byte, agentID string) (map[string]any, []byte) {
	t.Helper()
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	aadIn := []byte(agentID + ":in")
	plain, _, complete, err := wire.Parse(w.Body.Bytes(), fsKey[:], fsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !complete {
		t.Fatal("response incomplete")
	}
	var msg map[string]any
	if err := json.Unmarshal(plain, &msg); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return msg, w.Body.Bytes()
}

// workspace for one agent with a partially received job: the queued extract
// task is consumed so follow-up beacons return beacon payloads, not tasks.
func progressWorkspace(t *testing.T, srv *server.Server, h *Handler, agentID string) {
	t.Helper()
	srv.EnqueueTask(agentID, "job-progress", "extract", map[string]any{"job_id": "job-progress"})
	if _, ok := srv.NextTask(agentID); !ok {
		t.Fatal("expected queued task dispatch")
	}
	deliverProgressChunk(t, srv, agentID, "job-progress", 0, 3)
	deliverProgressChunk(t, srv, agentID, "job-progress", 2, 3)
}

// A beacon response carries the bounded "jobs" array when the agent has live
// chunk state, and the response still passes message validation.
func TestBeaconFrameIncludesJobProgress(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"
	fsKey, fsPrefix := progressHello(t, h, srv, agentID, "sid-progress-include")
	progressWorkspace(t, srv, h, agentID)

	beaconMsg := message.Make("beacon", agentID, "beacon-1", "{}", float64(time.Now().Unix()))
	beaconBytes, _ := json.Marshal(beaconMsg)
	aadOut := []byte(agentID + ":out")
	beaconFrame, err := wire.Build(beaconBytes, fsKey[:], fsPrefix[:], aadOut, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	respMsg, _ := postFrame(t, h, beaconFrame, fsKey, fsPrefix, agentID)
	if respMsg["type"] != "beacon" {
		t.Fatalf("expected beacon, got %v", respMsg["type"])
	}
	// The extended beacon must satisfy the existing schema validation.
	if err := message.Validate(respMsg); err != nil {
		t.Fatalf("extended beacon failed message validation: %v", err)
	}

	payloadStr, _ := respMsg["payload"].(string)
	var payload struct {
		Interval int                  `json:"interval"`
		Jitter   int                  `json:"jitter"`
		Jobs     []server.JobProgress `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		t.Fatalf("unmarshal beacon payload %q: %v", payloadStr, err)
	}
	if payload.Interval != srv.BeaconIntervalS || payload.Jitter != srv.BeaconJitterS {
		t.Fatalf("timing fields changed: %+v", payload)
	}
	if len(payload.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d: %+v", len(payload.Jobs), payload.Jobs)
	}
	jp := payload.Jobs[0]
	if jp.JobID != "job-progress" || jp.Total != 3 || jp.Received != 2 || jp.Complete {
		t.Fatalf("unexpected job progress: %+v", jp)
	}
	if len(jp.Missing) != 1 || jp.Missing[0] != 1 {
		t.Fatalf("missing = %v, want [1]", jp.Missing)
	}
}

// With no live jobs the payload omits "jobs" entirely, keeping the original
// beacon payload byte-for-byte.
func TestBeaconFrameOmitsJobProgressWhenEmpty(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"
	fsKey, fsPrefix := progressHello(t, h, srv, agentID, "sid-progress-omit")

	beaconMsg := message.Make("beacon", agentID, "beacon-1", "{}", float64(time.Now().Unix()))
	beaconBytes, _ := json.Marshal(beaconMsg)
	aadOut := []byte(agentID + ":out")
	beaconFrame, err := wire.Build(beaconBytes, fsKey[:], fsPrefix[:], aadOut, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	respMsg, _ := postFrame(t, h, beaconFrame, fsKey, fsPrefix, agentID)
	payloadStr, _ := respMsg["payload"].(string)
	if strings.Contains(payloadStr, "jobs") {
		t.Fatalf("empty job list must omit the field, payload=%q", payloadStr)
	}
	want := `{"interval":30,"jitter":10}`
	if payloadStr != want {
		t.Fatalf("payload = %q, want %q", payloadStr, want)
	}
}

// The ack/result session response path (beaconFrame) also carries job
// progress.
func TestAckResponseIncludesJobProgress(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"
	fsKey, fsPrefix := progressHello(t, h, srv, agentID, "sid-progress-ack")

	srv.EnqueueTask(agentID, "job-ack", "extract", map[string]any{"job_id": "job-ack"})
	if _, ok := srv.NextTask(agentID); !ok {
		t.Fatal("expected queued task dispatch")
	}
	deliverProgressChunk(t, srv, agentID, "job-ack", 0, 2)

	ackMsg := message.Make("ack", agentID, "job-ack", "", float64(time.Now().Unix()))
	ackBytes, _ := json.Marshal(ackMsg)
	aadOut := []byte(agentID + ":out")
	ackFrame, err := wire.Build(ackBytes, fsKey[:], fsPrefix[:], aadOut, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	respMsg, _ := postFrame(t, h, ackFrame, fsKey, fsPrefix, agentID)
	if respMsg["type"] != "beacon" {
		t.Fatalf("expected beacon response to ack, got %v", respMsg["type"])
	}
	payloadStr, _ := respMsg["payload"].(string)
	if !strings.Contains(payloadStr, `"jobs"`) {
		t.Fatalf("ack response missing jobs, payload=%q", payloadStr)
	}
	var payload struct {
		Jobs []server.JobProgress `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		t.Fatalf("unmarshal ack response payload: %v", err)
	}
	if len(payload.Jobs) != 1 || payload.Jobs[0].JobID != "job-ack" || payload.Jobs[0].Received != 1 {
		t.Fatalf("unexpected ack job progress: %+v", payload.Jobs)
	}
}

// Worst-bound payload: MaxJobProgressJobs jobs each listing
// MaxJobProgressMissing sequence numbers. The assembled session frame must stay
// far below the 2MB frame cap and remain parseable/valid.
func TestBeaconJobProgressFrameSizeBound(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"
	fsKey, fsPrefix := progressHello(t, h, srv, agentID, "sid-progress-bound")

	for i := 0; i < server.MaxJobProgressJobs; i++ {
		jobID := "job-bound-" + string(rune('a'+i))
		srv.EnqueueTask(agentID, jobID, "extract", map[string]any{"job_id": jobID})
		if _, ok := srv.NextTask(agentID); !ok {
			t.Fatal("expected queued task dispatch")
		}
		deliverProgressChunk(t, srv, agentID, jobID, 0, 10000)
	}

	jobs := srv.JobProgressForAgent(agentID)
	if len(jobs) != server.MaxJobProgressJobs {
		t.Fatalf("expected %d jobs, got %d", server.MaxJobProgressJobs, len(jobs))
	}
	for _, jp := range jobs {
		if len(jp.Missing) != server.MaxJobProgressMissing {
			t.Fatalf("job %s missing=%d, want %d", jp.JobID, len(jp.Missing), server.MaxJobProgressMissing)
		}
	}

	snap, ok := srv.SnapshotAgentRecord(agentID)
	if !ok {
		t.Fatal("missing agent snapshot")
	}
	frame, err := h.beaconFrame(snap, agentID)
	if err != nil {
		t.Fatalf("beaconFrame: %v", err)
	}
	if len(frame) >= MaxBodySize {
		t.Fatalf("worst-bound frame %d bytes exceeds body cap %d", len(frame), MaxBodySize)
	}
	if len(frame) > 64*1024 {
		t.Fatalf("worst-bound frame unexpectedly large: %d bytes", len(frame))
	}
	t.Logf("worst-bound beacon frame: %d bytes (cap %d)", len(frame), MaxBodySize)

	aadIn := []byte(agentID + ":in")
	plain, _, complete, err := wire.Parse(frame, fsKey[:], fsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil || !complete {
		t.Fatalf("worst-bound frame parse: complete=%v err=%v", complete, err)
	}
	var respMsg map[string]any
	if err := json.Unmarshal(plain, &respMsg); err != nil {
		t.Fatalf("unmarshal worst-bound response: %v", err)
	}
	if err := message.Validate(respMsg); err != nil {
		t.Fatalf("worst-bound response failed validation: %v", err)
	}
}
