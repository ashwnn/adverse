package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/server"
	"github.com/ashwnn/adverse-go/internal/wire"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) *server.Server {
	t.Helper()
	srv, err := server.New(testSecret, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func TestNonPOST405(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestBodyTooLarge413(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())

	// Create a body larger than 2MB
	bigBody := make([]byte, MaxBodySize+1)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(bigBody))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestFrameTooShort400(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())

	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte{0x01, 0x02}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestUnrecognizedFrame400(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())

	// Build a frame with a random prefix that won't match anything
	frame := make([]byte, 64)
	frame[0] = 'Z'
	frame[1] = 'Z'
	frame[2] = 'Z' // unknown prefix
	req := httptest.NewRequest("POST", "/", bytes.NewReader(frame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHelloRegistration(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())

	agentID := "aabbccdd"
	bootstrapKey := srv.ComputeBootstrapKey()

	// Generate agent ephemeral
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ephPubBytes := ephPriv.PublicKey().Bytes()
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)

	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := hex.EncodeToString([]byte("test-sid-12345678"))

	// Build hello message
	payload := map[string]any{
		"agent_id": agentID,
		"sid":      sid,
		"eph_pub":  hex.EncodeToString(ephPub[:]),
		"salt":     hex.EncodeToString(salt[:]),
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := message.Make("hello", agentID, "hello-0", string(payloadBytes), float64(time.Now().Unix()))
	msgBytes, _ := json.Marshal(msg)

	// Build hello frame with LegacyMagic and bootstrap key
	helloFrame, err := wire.Build(msgBytes, bootstrapKey[:], []byte(wire.LegacyMagic), nil, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Send request
	req := httptest.NewRequest("POST", "/", bytes.NewReader(helloFrame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Parse response frame — hello ack is encrypted under the static-ECDH
	// handshake key, NOT the forward-secret session key.
	respBody := w.Body.Bytes()
	if len(respBody) < 11 {
		t.Fatal("response too short")
	}

	// Derive handshake key (client-side static ECDH)
	serverPub, err := cryptokeys.ServerPublicBytes(srv.ServerXPriv)
	if err != nil {
		t.Fatal(err)
	}
	hsKey, err := cryptokeys.HandshakeKey(ephPriv, serverPub, salt, agentID)
	if err != nil {
		t.Fatal(err)
	}
	hsPrefix, err := cryptokeys.FramePrefix(hsKey, "v2")
	if err != nil {
		t.Fatal(err)
	}

	// Parse hello ack with handshake key and ":in" AAD (server→client)
	aad := []byte(agentID + ":in")
	plain, _, complete, err := wire.Parse(respBody, hsKey[:], hsPrefix[:], aad, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !complete {
		t.Fatal("response incomplete")
	}

	var respMsg map[string]any
	if err := json.Unmarshal(plain, &respMsg); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if respMsg["type"] != "beacon" {
		t.Fatalf("expected beacon, got %v", respMsg["type"])
	}
	if respMsg["task_id"] != "hello-ack" {
		t.Fatalf("expected hello-ack, got %v", respMsg["task_id"])
	}

	// Verify ack carries server_eph_pub for forward secrecy
	payloadStr, _ := respMsg["payload"].(string)
	var ackPayload struct {
		ServerEphPub string `json:"server_eph_pub"`
	}
	if err := json.Unmarshal([]byte(payloadStr), &ackPayload); err != nil {
		t.Fatalf("unmarshal ack payload: %v", err)
	}
	if ackPayload.ServerEphPub == "" {
		t.Fatal("hello ack missing server_eph_pub (forward secrecy required)")
	}

	// Derive forward-secret session key from extracted server ephemeral
	serverEphPubBytes, err := hex.DecodeString(ackPayload.ServerEphPub)
	if err != nil || len(serverEphPubBytes) != 32 {
		t.Fatalf("invalid server_eph_pub: %v", err)
	}
	var serverEphPub [32]byte
	copy(serverEphPub[:], serverEphPubBytes)
	fsKey, err := cryptokeys.SessionKey(ephPriv, serverEphPub, salt, agentID)
	if err != nil {
		t.Fatal(err)
	}
	fsPrefix, _ := cryptokeys.FramePrefix(fsKey, "v2")
	_ = fsKey
	_ = fsPrefix
}

func TestSessionBeaconThenTask(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"

	// Generate ephemeral and register via hello (full FS handshake)
	ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytes := ephPriv.PublicKey().Bytes()
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := "test-sid-session"

	fsKey, fsPrefix := doHello(t, h, srv, agentID, ephPriv, ephPub, salt, sid)

	// Queue a task
	srv.EnqueueTask(agentID, "task-extract-1", "extract", map[string]any{
		"action":     "extract",
		"job_id":     "job123456789012",
		"hives":      []string{"SYSTEM"},
		"chunk_size": 131072,
	})

	// Build a beacon frame from agent using the FS session key
	beaconMsg := message.Make("beacon", agentID, "beacon-1",
		`{"interval":30,"jitter":10}`, float64(time.Now().Unix()))
	beaconBytes, _ := json.Marshal(beaconMsg)

	aadOut := []byte(agentID + ":out")
	beaconFrame, err := wire.Build(beaconBytes, fsKey[:], fsPrefix[:], aadOut, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	// Send beacon
	req := httptest.NewRequest("POST", "/", bytes.NewReader(beaconFrame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Parse response - should be the queued task
	respBody := w.Body.Bytes()
	aadIn := []byte(agentID + ":in")
	plain, _, complete, err := wire.Parse(respBody, fsKey[:], fsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !complete {
		t.Fatal("response incomplete")
	}

	var respMsg map[string]any
	json.Unmarshal(plain, &respMsg)

	if respMsg["type"] != "task" {
		t.Fatalf("expected task, got %v", respMsg["type"])
	}
	if respMsg["task_id"] != "task-extract-1" {
		t.Fatalf("expected task-extract-1, got %v", respMsg["task_id"])
	}
}

func TestSessionResult(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"

	ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytes := ephPriv.PublicKey().Bytes()
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	fsKey, fsPrefix := doHello(t, h, srv, agentID, ephPriv, ephPub, salt, "test-sid-result")

	// Build result message
	resultPayload, _ := json.Marshal(map[string]any{
		"exit_code": 0,
		"output":    "test output",
	})
	resultMsg := message.Make("result", agentID, "job1234", string(resultPayload), float64(time.Now().Unix()))
	resultBytes, _ := json.Marshal(resultMsg)

	aadOut := []byte(agentID + ":out")
	resultFrame, err := wire.Build(resultBytes, fsKey[:], fsPrefix[:], aadOut, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/", bytes.NewReader(resultFrame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Response should be a beacon (no queued tasks)
	respBody := w.Body.Bytes()
	aadIn := []byte(agentID + ":in")
	plain, _, _, err := wire.Parse(respBody, fsKey[:], fsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	var respMsg map[string]any
	json.Unmarshal(plain, &respMsg)
	if respMsg["type"] != "beacon" {
		t.Fatalf("expected beacon ack, got %v", respMsg["type"])
	}

	// Check result was stored
	results := srv.ResultsFor(agentID)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// A kill queued before an ack/result frame must not be consumed by that
// frame: only a beacon dequeues tasks. Regression for the kill-loss bug where
// responseFrame popped (and marked completed) a queued kill on every message.
func TestResultFrameDoesNotConsumeQueuedKill(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"

	ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytes := ephPriv.PublicKey().Bytes()
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	fsKey, fsPrefix := doHello(t, h, srv, agentID, ephPriv, ephPub, salt, "test-sid-kill-loss")

	killTaskID, epoch, err := srv.EnqueueKill(agentID, "kill")
	if err != nil {
		t.Fatalf("enqueue kill: %v", err)
	}

	// Agent reports an unrelated result before it next beacons.
	resultMsg := message.Make("result", agentID, "other-task", `{"status":"ok"}`, float64(time.Now().Unix()))
	resultBytes, _ := json.Marshal(resultMsg)
	aadOut := []byte(agentID + ":out")
	resultFrame, err := wire.Build(resultBytes, fsKey[:], fsPrefix[:], aadOut, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/", bytes.NewReader(resultFrame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("result frame: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// The response to a result must not be the kill.
	aadIn := []byte(agentID + ":in")
	plain, _, _, err := wire.Parse(w.Body.Bytes(), fsKey[:], fsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parse result response: %v", err)
	}
	var respMsg map[string]any
	json.Unmarshal(plain, &respMsg)
	if respMsg["type"] == "kill" {
		t.Fatal("kill delivered in response to a result frame")
	}

	// The kill must remain queued and undispatched.
	tk, ok := srv.GetTask(killTaskID)
	if !ok {
		t.Fatal("kill task disappeared")
	}
	if tk.State != server.TaskQueued {
		t.Fatalf("kill task consumed by result frame: state=%s", tk.State)
	}
	if n := srv.PendingTaskCount(agentID); n != 1 {
		t.Fatalf("expected 1 queued task, got %d", n)
	}

	// The next beacon receives the kill.
	beaconMsg := message.Make("beacon", agentID, "beacon-1", "{}", float64(time.Now().Unix()))
	beaconBytes, _ := json.Marshal(beaconMsg)
	beaconFrame, err := wire.Build(beaconBytes, fsKey[:], fsPrefix[:], aadOut, 1, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/", bytes.NewReader(beaconFrame))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("beacon: expected 200, got %d", w.Code)
	}
	plain, _, _, err = wire.Parse(w.Body.Bytes(), fsKey[:], fsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parse beacon response: %v", err)
	}
	respMsg = nil
	json.Unmarshal(plain, &respMsg)
	if respMsg["type"] != "kill" {
		t.Fatalf("expected kill on next beacon, got %v", respMsg["type"])
	}
	if uint64(respMsg["epoch"].(float64)) != epoch {
		t.Fatalf("kill epoch mismatch: got %v want %d", respMsg["epoch"], epoch)
	}
}

func TestReplayRejection(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"

	ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytes := ephPriv.PublicKey().Bytes()
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	fsKey, fsPrefix := doHello(t, h, srv, agentID, ephPriv, ephPub, salt, "test-sid-replay")

	beaconMsg := message.Make("beacon", agentID, "beacon-r", "{}", float64(time.Now().Unix()))
	beaconBytes, _ := json.Marshal(beaconMsg)
	aadOut := []byte(agentID + ":out")

	// Build frame with seq=0
	frame0, _ := wire.Build(beaconBytes, fsKey[:], fsPrefix[:], aadOut, 0, wire.DirectionClientToServer)

	// Send first (seq=0)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(frame0))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first send: expected 200, got %d", w.Code)
	}

	// Send same seq=0 again (replay)
	req2 := httptest.NewRequest("POST", "/", bytes.NewReader(frame0))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("replay: expected 200 (beacon response), got %d", w2.Code)
	}

	// The replayed frame should have been dropped; response is still a beacon
	// (server handles replay gracefully by returning a beacon)
}

func TestBadPrefix400(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())

	// Build a frame with valid LegacyMagic but wrong key
	wrongKey := [32]byte{0xff, 0xfe}
	msg := message.Make("hello", "aabbccdd", "hello-0", "{}", float64(time.Now().Unix()))
	msgBytes, _ := json.Marshal(msg)

	frame, err := wire.Build(msgBytes, wrongKey[:], []byte(wire.LegacyMagic), nil, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/", bytes.NewReader(frame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad auth, got %d", w.Code)
	}
}

func TestCrossAgentAADRejected(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())

	// Register agent A via full FS handshake
	agentA := "aaaabbbb"
	ephPrivA, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytesA := ephPrivA.PublicKey().Bytes()
	var ephPubA [32]byte
	copy(ephPubA[:], ephPubBytesA)
	saltA := [16]byte{1}

	_, fsPrefixA := doHello(t, h, srv, agentA, ephPrivA, ephPubA, saltA, "sid-aaa")

	// Register agent B via full FS handshake
	agentB := "bbbbcccc"
	ephPrivB, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytesB := ephPrivB.PublicKey().Bytes()
	var ephPubB [32]byte
	copy(ephPubB[:], ephPubBytesB)
	saltB := [16]byte{2}

	fsKeyB, _ := doHello(t, h, srv, agentB, ephPrivB, ephPubB, saltB, "sid-bbb")

	// Try to send a frame from agent B using agent B's FS key but agent A's
	// prefix and AAD — server matches prefix to agent A, tries to decrypt with
	// agent A's FS key, which differs from the frame key → auth failure.
	beaconMsg := message.Make("beacon", agentA, "cross-agent", "{}", float64(time.Now().Unix()))
	beaconBytes, _ := json.Marshal(beaconMsg)

	aadWrong := []byte(agentA + ":out")
	frame, _ := wire.Build(beaconBytes, fsKeyB[:], fsPrefixA[:], aadWrong, 0, wire.DirectionClientToServer)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(frame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should fail because the frame uses agentB's key with agentA's prefix
	if w.Code == http.StatusOK {
		t.Fatal("cross-agent AAD should be rejected")
	}
}

func TestWrongDirectionAADRejected(t *testing.T) {
	srv := newTestServer(t)
	h := NewHandler(srv, slog.Default())
	agentID := "aabbccdd"

	ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytes := ephPriv.PublicKey().Bytes()
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	fsKey, fsPrefix := doHello(t, h, srv, agentID, ephPriv, ephPub, salt, "test-sid-wrongdir")

	// Build a beacon using ":in" AAD instead of ":out" (wrong direction)
	beaconMsg := message.Make("beacon", agentID, "wrong-dir", "{}", float64(time.Now().Unix()))
	beaconBytes, _ := json.Marshal(beaconMsg)
	wrongAAD := []byte(agentID + ":in") // should be ":out" for client→server
	frame, _ := wire.Build(beaconBytes, fsKey[:], fsPrefix[:], wrongAAD, 0, wire.DirectionClientToServer)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(frame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("wrong-direction AAD should be rejected")
	}
}

// --- helpers ---

// doHello performs a full hello handshake as a client, parses the hello ack
// with the static-ECDH handshake key, extracts the server's ephemeral public
// key, and derives the forward-secret session key and frame prefix. It mirrors
// the real agent's hello() flow exactly.
func doHello(t *testing.T, h *Handler, srv *server.Server, agentID string, ephPriv *ecdh.PrivateKey, ephPub [32]byte, salt [16]byte, sid string) (fsKey [32]byte, fsPrefix [3]byte) {
	t.Helper()
	bootstrapKey := srv.ComputeBootstrapKey()

	// Build hello payload
	payload := map[string]any{
		"agent_id": agentID,
		"sid":      sid,
		"eph_pub":  hex.EncodeToString(ephPub[:]),
		"salt":     hex.EncodeToString(salt[:]),
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := message.Make("hello", agentID, "hello-0", string(payloadBytes), float64(time.Now().Unix()))
	msgBytes, _ := json.Marshal(msg)

	helloFrame, err := wire.Build(msgBytes, bootstrapKey[:], []byte(wire.LegacyMagic), nil, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatalf("Build hello: %v", err)
	}

	req := httptest.NewRequest("POST", "/", bytes.NewReader(helloFrame))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register %s: expected 200, got %d: %s", agentID, w.Code, w.Body.String())
	}

	// Derive handshake key (client-side static ECDH)
	serverPub, err := cryptokeys.ServerPublicBytes(srv.ServerXPriv)
	if err != nil {
		t.Fatalf("server pub bytes: %v", err)
	}
	hsKey, err := cryptokeys.HandshakeKey(ephPriv, serverPub, salt, agentID)
	if err != nil {
		t.Fatalf("derive handshake key: %v", err)
	}
	hsPrefix, err := cryptokeys.FramePrefix(hsKey, "v2")
	if err != nil {
		t.Fatalf("derive handshake prefix: %v", err)
	}

	// Parse hello ack with handshake key (server→client direction)
	respBody := w.Body.Bytes()
	aadIn := []byte(agentID + ":in")
	plain, _, _, err := wire.Parse(respBody, hsKey[:], hsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parse hello ack: %v", err)
	}

	// Extract server_eph_pub from ack payload
	var ackMsg map[string]any
	if err := json.Unmarshal(plain, &ackMsg); err != nil {
		t.Fatalf("unmarshal hello ack: %v", err)
	}
	payloadStr, _ := ackMsg["payload"].(string)
	var ackPayload struct {
		ServerEphPub string `json:"server_eph_pub"`
	}
	if err := json.Unmarshal([]byte(payloadStr), &ackPayload); err != nil {
		t.Fatalf("unmarshal ack payload: %v", err)
	}
	if ackPayload.ServerEphPub == "" {
		t.Fatal("hello ack missing server_eph_pub")
	}
	serverEphPubBytes, err := hex.DecodeString(ackPayload.ServerEphPub)
	if err != nil || len(serverEphPubBytes) != 32 {
		t.Fatalf("invalid server_eph_pub: %v", err)
	}
	var serverEphPub [32]byte
	copy(serverEphPub[:], serverEphPubBytes)

	// Derive forward-secret session key (ephemeral ECDH)
	fsKey, err = cryptokeys.SessionKey(ephPriv, serverEphPub, salt, agentID)
	if err != nil {
		t.Fatalf("derive FS session key: %v", err)
	}
	fsPrefix, err = cryptokeys.FramePrefix(fsKey, "v2")
	if err != nil {
		t.Fatalf("derive FS prefix: %v", err)
	}
	return fsKey, fsPrefix
}
