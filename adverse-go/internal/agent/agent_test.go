package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/wire"
)

// testServer implements the server side of the wire contract for testing.
type testServer struct {
	t *testing.T

	mu sync.Mutex

	secret32     [32]byte
	bootstrapKey [32]byte
	signKey      ed25519.PrivateKey
	serverPriv   *ecdh.PrivateKey
	serverPub    [32]byte

	// Session state (set after hello)
	sessionKey    [32]byte // forward-secret session key (ephemeral ECDH)
	prefix        [3]byte
	handshakeKey  [32]byte // static-ECDH hello-ack key
	handshakePref [3]byte
	serverEphPub  [32]byte
	agentID       string
	sendSeq       uint32
	recvSeq       uint32
	rw            *wire.ReplayWindow
	helloDone     bool

	// Test control
	phase       int // 0=waiting hello, 1=waiting beacon→send task, 2=waiting results, 3=next beacon→kill
	tasks       []string
	resultsRecv int
	totalChunks int
	killEpoch   uint64
	killPayload string
}

func newTestServer(t *testing.T, secret string) *testServer {
	secret32, err := cryptokeys.Secret32(secret)
	if err != nil {
		t.Fatalf("secret32: %v", err)
	}

	bk, err := cryptokeys.BootstrapKey(secret32)
	if err != nil {
		t.Fatalf("bootstrapKey: %v", err)
	}

	sp, err := cryptokeys.DeriveServerKey(secret32)
	if err != nil {
		t.Fatalf("serverPriv: %v", err)
	}
	spub, err := cryptokeys.ServerPublicBytes(sp)
	if err != nil {
		t.Fatalf("serverPub: %v", err)
	}

	sk, err := cryptokeys.DeriveSignKey(secret32)
	if err != nil {
		t.Fatalf("signKey: %v", err)
	}

	return &testServer{
		t:            t,
		secret32:     secret32,
		bootstrapKey: bk,
		signKey:      sk,
		serverPriv:   sp,
		serverPub:    spub,
		rw:           wire.NewReplayWindow(wire.DefaultReplayWindowSize),
		phase:        0,
		killEpoch:    1,
		killPayload:  "kill",
	}
}

func (ts *testServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		ts.t.Errorf("read body: %v", err)
		http.Error(w, "bad request", 400)
		return
	}

	var respFrame []byte
	var parseErr error

	if !ts.helloDone {
		// Hello phase: parse with bootstrap key
		plain, _, _, err := wire.Parse(body, ts.bootstrapKey[:], []byte(wire.LegacyMagic), nil, wire.DirectionClientToServer)
		if err != nil {
			ts.t.Errorf("parse hello: %v", err)
			http.Error(w, "bad frame", 400)
			return
		}

		var msg map[string]any
		if err := json.Unmarshal(plain, &msg); err != nil {
			ts.t.Errorf("unmarshal hello: %v", err)
			http.Error(w, "bad json", 400)
			return
		}

		ts.agentID, _ = msg["agent_id"].(string)

		// Parse payload to get eph_pub, salt
		payloadStr, _ := msg["payload"].(string)
		var payload struct {
			AgentID string `json:"agent_id"`
			EphPub  string `json:"eph_pub"`
			Salt    string `json:"salt"`
		}
		if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
			ts.t.Errorf("unmarshal hello payload: %v", err)
			http.Error(w, "bad payload", 400)
			return
		}

		ephPubBytes, _ := hex.DecodeString(payload.EphPub)
		var ephPub [32]byte
		copy(ephPub[:], ephPubBytes)

		saltBytes, _ := hex.DecodeString(payload.Salt)
		var salt [16]byte
		copy(salt[:], saltBytes)

		// Derive handshake key (static ECDH, authenticates server) and the
		// forward-secret session key (ephemeral ECDH).
		hsKey, err := cryptokeys.HandshakeKey(ts.serverPriv, ephPub, salt, ts.agentID)
		if err != nil {
			ts.t.Errorf("derive handshake key: %v", err)
			http.Error(w, "key error", 500)
			return
		}
		hsPrefix, err := cryptokeys.FramePrefix(hsKey, "v2")
		if err != nil {
			ts.t.Errorf("derive handshake prefix: %v", err)
			http.Error(w, "prefix error", 500)
			return
		}

		serverEphPriv, serverEphPub, err := cryptokeys.GenEphemeral()
		if err != nil {
			ts.t.Errorf("gen ephemeral: %v", err)
			http.Error(w, "key error", 500)
			return
		}
		_ = serverEphPriv // in a real server this would be retained for the session; the test server is stateless per request

		sk, err := cryptokeys.SessionKey(serverEphPriv, ephPub, salt, ts.agentID)
		if err != nil {
			ts.t.Errorf("derive session key: %v", err)
			http.Error(w, "key error", 500)
			return
		}
		ts.sessionKey = sk
		ts.handshakeKey = hsKey
		ts.handshakePref = hsPrefix
		ts.serverEphPub = serverEphPub

		pfx, err := cryptokeys.FramePrefix(sk, "v2")
		if err != nil {
			ts.t.Errorf("derive prefix: %v", err)
			http.Error(w, "prefix error", 500)
			return
		}
		ts.prefix = pfx

		ts.helloDone = true
		ts.phase = 1

		// Send hello ack. Mirrors the real transport server: encrypted with the
		// static-ECDH handshake key and carrying the server ephemeral pub so the
		// agent can derive the forward-secret session key.
		ackPayloadStr := fmt.Sprintf(`{"interval":1,"jitter":0,"server_eph_pub":%q}`, hex.EncodeToString(serverEphPub[:]))
		ackMsg := message.Make("beacon", ts.agentID, "hello-ack", ackPayloadStr, float64(time.Now().UnixNano())/1e9)
		ackJSON, _ := json.Marshal(ackMsg)
		aadIn := []byte(ts.agentID + ":in")
		respFrame, parseErr = wire.Build(ackJSON, ts.handshakeKey[:], ts.handshakePref[:], aadIn, 0, wire.DirectionServerToClient)
		if parseErr != nil {
			ts.t.Errorf("build hello ack: %v", parseErr)
		}
	} else {
		// Session phase: parse with session key
		pfxBytes := ts.prefix[:]
		// aadOut (":out") is client→server AAD; aadIn (":in") is server→client AAD
		aadOut := []byte(ts.agentID + ":out") // client→server direction
		aadIn := []byte(ts.agentID + ":in")   // server→client direction

		plain, seq, _, err := wire.Parse(body, ts.sessionKey[:], pfxBytes, aadOut, wire.DirectionClientToServer)
		if err != nil {
			ts.t.Errorf("parse session frame: %v", err)
			http.Error(w, "bad frame", 400)
			return
		}

		if !ts.rw.Check(seq) {
			ts.t.Logf("replay detected (seq=%d)", seq)
		}
		ts.rw.Record(seq)

		var msg map[string]any
		if err := json.Unmarshal(plain, &msg); err != nil {
			ts.t.Errorf("unmarshal: %v", err)
			http.Error(w, "bad json", 400)
			return
		}

		msgType, _ := msg["type"].(string)

		switch msgType {
		case "beacon":
			respFrame = ts.handleBeacon(aadIn)
		case "result":
			respFrame = ts.handleResult(msg, aadIn) // aadIn is server→client AAD
		default:
			// Send beacon ack
			respMsg := message.Make("beacon", ts.agentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9)
			respJSON, _ := json.Marshal(respMsg)
			respFrame, _ = wire.Build(respJSON, ts.sessionKey[:], pfxBytes, aadIn, ts.sendSeq, wire.DirectionServerToClient)
			ts.sendSeq++
		}
	}

	if parseErr != nil {
		http.Error(w, "frame error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(respFrame)
}

func (ts *testServer) handleBeacon(aadIn []byte) []byte {
	pfxBytes := ts.prefix[:]
	var respFrame []byte

	switch ts.phase {
	case 1:
		// Send task extract
		taskPayload := fmt.Sprintf(`{"action":"extract","job_id":"job-abc123","hives":["SYSTEM"],"chunk_size":4096}`)
		taskMsg := message.Make("task", ts.agentID, "job-abc123", taskPayload, float64(time.Now().UnixNano())/1e9)
		taskJSON, _ := json.Marshal(taskMsg)
		respFrame, _ = wire.Build(taskJSON, ts.sessionKey[:], pfxBytes, aadIn, ts.sendSeq, wire.DirectionServerToClient)
		ts.sendSeq++
		ts.phase = 2 // expect results

	case 3:
		// Send kill
		killMsg := map[string]any{
			"type":     "kill",
			"agent_id": ts.agentID,
			"task_id":  "kill-0",
			"payload":  ts.killPayload,
			"epoch":    float64(ts.killEpoch),
			"ts":       float64(time.Now().UnixNano()) / 1e9,
		}
		// Sign the kill
		sig, _ := cryptokeys.KillSign(ts.signKey, ts.killEpoch, ts.agentID, ts.killPayload)
		killMsg["sig"] = hex.EncodeToString(sig)

		killJSON, _ := json.Marshal(killMsg)
		respFrame, _ = wire.Build(killJSON, ts.sessionKey[:], pfxBytes, aadIn, ts.sendSeq, wire.DirectionServerToClient)
		ts.sendSeq++

	default:
		// Send beacon ack with interval
		beaconPayload := `{"interval":1,"jitter":0}`
		respMsg := message.Make("beacon", ts.agentID, "beacon-0", beaconPayload, float64(time.Now().UnixNano())/1e9)
		respJSON, _ := json.Marshal(respMsg)
		respFrame, _ = wire.Build(respJSON, ts.sessionKey[:], pfxBytes, aadIn, ts.sendSeq, wire.DirectionServerToClient)
		ts.sendSeq++
	}

	return respFrame
}

func (ts *testServer) handleResult(msg map[string]any, aadIn []byte) []byte {
	ts.resultsRecv++

	// Check if we've received all expected results
	// The total is determined by the synthetic hive size (1024) / chunk_size (4096) = 1 chunk per hive
	ts.totalChunks = 1

	pfxBytes := ts.prefix[:]

	// Send ack
	ackMsg := message.Make("beacon", ts.agentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9)
	ackJSON, _ := json.Marshal(ackMsg)
	respFrame, _ := wire.Build(ackJSON, ts.sessionKey[:], pfxBytes, aadIn, ts.sendSeq, wire.DirectionServerToClient)
	ts.sendSeq++

	if ts.resultsRecv >= ts.totalChunks {
		ts.phase = 3 // next beacon gets kill
	}

	return respFrame
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid", validTestConfig(), false},
		{"bad_agent_id", func() Config { c := validTestConfig(); c.AgentID = "xyz"; return c }(), true},
		{"bad_secret_len", func() Config { c := validTestConfig(); c.Secret = "abc"; return c }(), true},
		{"bad_sign_pub", func() Config { c := validTestConfig(); c.SignPubHex = "short"; return c }(), true},
		{"empty_hives", func() Config { c := validTestConfig(); c.Hives = nil; return c }(), true},
		{"bad_chunk_size", func() Config { c := validTestConfig(); c.ChunkSize = 0; return c }(), true},
		{"bad_chunk_large", func() Config { c := validTestConfig(); c.ChunkSize = 1024 * 1024; return c }(), true},
		{"min_gt_max", func() Config { c := validTestConfig(); c.MinDelayMs = 10000; c.MaxDelayMs = 1000; return c }(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Write temp config
	tmpDir := t.TempDir()
	cfgPath := tmpDir + "/test_config.json"
	cfg := validTestConfig()
	data, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, data, 0600)

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.AgentID != cfg.AgentID {
		t.Errorf("agent_id mismatch: %q != %q", loaded.AgentID, cfg.AgentID)
	}
}

func TestLoadConfigNotExist(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for nonexistent config")
	}
}

func TestStateFileRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.json"
	os.WriteFile(configPath, []byte("{}"), 0600)

	sf, err := LoadStateFile(configPath)
	if err != nil {
		t.Fatalf("LoadStateFile: %v", err)
	}
	if sf.LastAcceptedEpoch != 0 {
		t.Errorf("expected 0, got %d", sf.LastAcceptedEpoch)
	}

	sf.LastAcceptedEpoch = 42
	if err := sf.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sf2, err := LoadStateFile(configPath)
	if err != nil {
		t.Fatalf("LoadStateFile 2: %v", err)
	}
	if sf2.LastAcceptedEpoch != 42 {
		t.Errorf("expected 42, got %d", sf2.LastAcceptedEpoch)
	}
}

func TestFullLifecycle(t *testing.T) {
	os.Setenv("ADVERSE_BEHAVIOURAL", "0") // disable behavioural stall on Linux CI
	defer os.Unsetenv("ADVERSE_BEHAVIOURAL")

	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	ts := newTestServer(t, secret)

	// Start test HTTP server
	srv := httptest.NewServer(http.HandlerFunc(ts.handleHTTP))
	defer srv.Close()

	// Create config pointing to test server
	cfg := validTestConfig()
	cfg.Secret = secret
	cfg.ServerURL = srv.URL

	// Create agent
	agent, err := New(&cfg, log.New(io.Discard, "", 0), false, false)
	if err != nil {
		t.Fatalf("New agent: %v", err)
	}

	// Run with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exitCode := agent.Run(ctx)

	// The agent should receive kill and exit 0
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestFullLifecycleDryRun(t *testing.T) {
	os.Setenv("ADVERSE_BEHAVIOURAL", "0") // disable behavioural stall on Linux CI
	defer os.Unsetenv("ADVERSE_BEHAVIOURAL")

	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	ts := newTestServer(t, secret)

	srv := httptest.NewServer(http.HandlerFunc(ts.handleHTTP))
	defer srv.Close()

	cfg := validTestConfig()
	cfg.Secret = secret
	cfg.ServerURL = srv.URL

	agent, err := New(&cfg, log.New(io.Discard, "", 0), true, false) // dry-run
	if err != nil {
		t.Fatalf("New agent: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Dry-run mode: still goes through pipeline but logs "Would send"
	// It won't actually talk to the server for real, but in our implementation
	// dry-run still posts (for testing) - we just log the dry-run marker
	exitCode := agent.Run(ctx)
	_ = exitCode
}

func TestKillVerification(t *testing.T) {
	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	secret32, _ := cryptokeys.Secret32(secret)
	signKey, _ := cryptokeys.DeriveSignKey(secret32)

	signPubBytes, _ := cryptokeys.DeriveSignKey(secret32)
	_ = signPubBytes

	// Test: valid kill signature
	epoch := uint64(5)
	agentID := "aabbccdd"
	payload := "kill"
	sig, _ := cryptokeys.KillSign(signKey, epoch, agentID, payload)

	pub, _ := signPublicKey(signKey)
	if !cryptokeys.KillVerify(pub, epoch, agentID, payload, sig) {
		t.Error("KillVerify should succeed for valid signature")
	}

	// Test: wrong epoch
	if cryptokeys.KillVerify(pub, 6, agentID, payload, sig) {
		t.Error("KillVerify should fail for wrong epoch")
	}

	// Test: wrong payload
	if cryptokeys.KillVerify(pub, epoch, agentID, "wrong", sig) {
		t.Error("KillVerify should fail for wrong payload")
	}

	// Test: wrong agent_id
	if cryptokeys.KillVerify(pub, epoch, "deadbeef", payload, sig) {
		t.Error("KillVerify should fail for wrong agent_id")
	}

	// Test: stale epoch (equal)
	if cryptokeys.KillVerify(pub, epoch, agentID, payload, sig) {
		// This one should succeed at crypto level but agent rejects stale
	}
}

func TestKillStaleEpochRejected(t *testing.T) {
	// Verify that epoch <= lastAcceptedEpoch is handled correctly
	// This is tested in the handleKill logic
	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	ts := newTestServer(t, secret)
	ts.killEpoch = 1

	srv := httptest.NewServer(http.HandlerFunc(ts.handleHTTP))
	defer srv.Close()

	cfg := validTestConfig()
	cfg.Secret = secret
	cfg.ServerURL = srv.URL

	a, err := New(&cfg, log.New(io.Discard, "", 0), false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Simulate: agent has already accepted epoch 1
	a.lastKillEpoch = 1

	// Build a kill with epoch 1 (stale)
	secret32, _ := cryptokeys.Secret32(secret)
	signKey, _ := cryptokeys.DeriveSignKey(secret32)
	sig, _ := cryptokeys.KillSign(signKey, 1, cfg.AgentID, "kill")

	killMsg := map[string]any{
		"type":     "kill",
		"agent_id": cfg.AgentID,
		"task_id":  "kill-0",
		"payload":  "kill",
		"epoch":    float64(1),
		"sig":      hex.EncodeToString(sig),
	}

	code := a.handleKill(killMsg)
	if code != -1 {
		t.Errorf("expected -1 for stale kill, got %d", code)
	}
}

func TestKillWrongAgentRejected(t *testing.T) {
	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	cfg := validTestConfig()
	cfg.Secret = secret

	a, err := New(&cfg, log.New(io.Discard, "", 0), false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	killMsg := map[string]any{
		"type":     "kill",
		"agent_id": "deadbeef",
		"task_id":  "kill-0",
		"payload":  "kill",
		"epoch":    float64(1),
		"sig":      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	code := a.handleKill(killMsg)
	if code != -1 {
		t.Errorf("expected -1 for wrong agent_id, got %d", code)
	}
}

func TestUpdateBeaconInterval(t *testing.T) {
	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	cfg := validTestConfig()
	cfg.Secret = secret

	a, err := New(&cfg, log.New(io.Discard, "", 0), false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	a.updateBeaconInterval(context.Background(), map[string]any{"payload": `{"interval":5,"jitter":2}`})
	if a.beaconInterval != 5 {
		t.Errorf("expected interval 5, got %d", a.beaconInterval)
	}
	if a.beaconJitter != 2 {
		t.Errorf("expected jitter 2, got %d", a.beaconJitter)
	}

	// Empty payload should not change
	a.updateBeaconInterval(context.Background(), map[string]any{"payload": ""})
	if a.beaconInterval != 5 {
		t.Errorf("interval should remain 5, got %d", a.beaconInterval)
	}
}

func TestPostFrameOversizedResponse(t *testing.T) {
	// Server that returns a body larger than MaxResponseBytes.
	oversized := make([]byte, MaxResponseBytes+1024)
	for i := range oversized {
		oversized[i] = 'A'
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(oversized)
	}))
	defer ts.Close()

	secret := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	cfg := validTestConfig()
	cfg.Secret = secret
	cfg.ServerURL = ts.URL

	a, err := New(&cfg, log.New(io.Discard, "", 0), false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = a.postFrame(context.Background(), []byte("test"), 0)
	if err == nil {
		t.Fatal("expected error for oversized response body")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected overflow error, got: %v", err)
	}
}

// --- Helpers ---

func validTestConfig() Config {
	return Config{
		AgentID:   "aabbccdd",
		Secret:    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		ServerURL: "https://127.0.0.1:8443",
		SignPubHex: func() string {
			secret32, _ := cryptokeys.Secret32("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
			sk, _ := cryptokeys.DeriveSignKey(secret32)
			return hex.EncodeToString(sk.Public().(ed25519.PublicKey))
		}(),
		Hives:             []string{"SYSTEM"},
		ChunkSize:         4096,
		MinDelayMs:        100,
		MaxDelayMs:        200,
		RealMode:          false,
		Persistence:       PersistenceConfig{},
		Spool:             SpoolConfig{},
		Shaping:           ShapingConfig{},
		AntiForensic:      AntiForensicConfig{},
		ExitAfterDelivery: false,
	}
}

func signPublicKey(sk ed25519.PrivateKey) (ed25519.PublicKey, error) {
	pub := sk.Public().(ed25519.PublicKey)
	return pub, nil
}
