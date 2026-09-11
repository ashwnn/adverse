package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/adminapi"
	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/server"
)

const testOperatorToken = "op-token-0123456789abcdef"

func newAdminTestServer(t *testing.T) (*httptest.Server, *server.Server, *AdminHandler) {
	t.Helper()
	srv, err := server.New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	admin := NewAdminHandler(srv, slog.Default(), testOperatorToken, "test")
	ts := httptest.NewServer(admin)
	t.Cleanup(ts.Close)
	return ts, srv, admin
}

func adminPost(t *testing.T, url, token string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func adminGet(t *testing.T, url, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// The admin API must fail closed without a configured token.
func TestAdminNoTokenFailsClosed(t *testing.T) {
	srv, err := server.New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	admin := NewAdminHandler(srv, slog.Default(), "", "test")
	ts := httptest.NewServer(admin)
	defer ts.Close()

	code, _ := adminGet(t, ts.URL+adminapi.AdminPrefix+"/health", testOperatorToken)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without operator token, got %d", code)
	}
}

func TestAdminAuthRequired(t *testing.T) {
	ts, _, _ := newAdminTestServer(t)

	// Missing token
	code, _ := adminGet(t, ts.URL+adminapi.AdminPrefix+"/health", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", code)
	}
	// Wrong token
	code, _ = adminGet(t, ts.URL+adminapi.AdminPrefix+"/health", "wrong-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", code)
	}
	// Correct token
	code, body := adminGet(t, ts.URL+adminapi.AdminPrefix+"/health", testOperatorToken)
	if code != http.StatusOK {
		t.Fatalf("expected 200 with token, got %d: %s", code, body)
	}
	var h adminapi.Health
	if err := json.Unmarshal(body, &h); err != nil {
		t.Fatal(err)
	}
	if h.Status != "ok" {
		t.Fatalf("expected ok, got %s", h.Status)
	}
}

// Full operator workflow over the API: enqueue -> task dispatch -> ack ->
// status result -> completed -> results query.
func TestAdminTaskLifecycleWorkflow(t *testing.T) {
	ts, srv, _ := newAdminTestServer(t)
	agentID := "aabbccdd"
	srv.RegisterAgent(agentID, map[string]any{
		"payload": `{"eph_pub":"` + testEphPubHex(t) + `","salt":"` + testSaltHex + `","sid":"sess-1"}`,
	})

	// Enqueue a noop task via the API.
	reqBody, _ := json.Marshal(adminapi.EnqueueTaskRequest{AgentID: agentID, Action: "noop"})
	code, body := adminPost(t, ts.URL+adminapi.AdminPrefix+"/tasks", testOperatorToken, reqBody)
	if code != http.StatusOK {
		t.Fatalf("enqueue failed: %d %s", code, body)
	}
	var enq adminapi.EnqueueTaskResponse
	if err := json.Unmarshal(body, &enq); err != nil {
		t.Fatal(err)
	}
	if enq.TaskID == "" {
		t.Fatal("empty task id")
	}

	// Server dispatch.
	msg, ok := srv.NextTask(agentID)
	if !ok {
		t.Fatal("no task dispatched")
	}
	if msg["type"] != "task" {
		t.Fatalf("expected task message, got %v", msg["type"])
	}
	task, _ := srv.GetTask(enq.TaskID)
	if task.State != server.TaskDispatched {
		t.Fatalf("expected dispatched, got %s", task.State)
	}

	// Agent acks.
	srv.HandleMessage(agentID, message.Make("ack", agentID, enq.TaskID, "", float64(time.Now().Unix())))
	task, _ = srv.GetTask(enq.TaskID)
	if task.State != server.TaskAcked {
		t.Fatalf("expected acked, got %s", task.State)
	}

	// Agent reports status result -> completed.
	statusPayload, _ := json.Marshal(map[string]any{"job_id": enq.TaskID, "action": "noop", "status": "ok"})
	srv.HandleMessage(agentID, message.Make("result", agentID, enq.TaskID, string(statusPayload), float64(time.Now().Unix())))
	task, _ = srv.GetTask(enq.TaskID)
	if task.State != server.TaskCompleted {
		t.Fatalf("expected completed, got %s", task.State)
	}

	// Operator sees the lifecycle.
	code, body = adminGet(t, ts.URL+adminapi.AdminPrefix+"/tasks?agent="+agentID, testOperatorToken)
	if code != http.StatusOK {
		t.Fatalf("list tasks failed: %d %s", code, body)
	}
	var tasks []adminapi.TaskInfo
	if err := json.Unmarshal(body, &tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].State != "completed" || tasks[0].AckedAt == "" {
		t.Fatalf("unexpected task info: %+v", tasks)
	}
}

// Kill over the API: signed epoch delivered, operator sees kill task.
func TestAdminKill(t *testing.T) {
	ts, srv, _ := newAdminTestServer(t)
	agentID := "aabbccdd"
	srv.RegisterAgent(agentID, map[string]any{
		"payload": `{"eph_pub":"` + testEphPubHex(t) + `","salt":"` + testSaltHex + `","sid":"sess-2"}`,
	})

	reqBody, _ := json.Marshal(adminapi.KillRequest{AgentID: agentID, Payload: "kill"})
	code, body := adminPost(t, ts.URL+adminapi.AdminPrefix+"/kill", testOperatorToken, reqBody)
	if code != http.StatusOK {
		t.Fatalf("kill failed: %d %s", code, body)
	}
	var kr adminapi.KillResponse
	if err := json.Unmarshal(body, &kr); err != nil {
		t.Fatal(err)
	}
	if kr.Epoch == 0 {
		t.Fatal("expected non-zero epoch")
	}

	msg, ok := srv.NextTask(agentID)
	if !ok {
		t.Fatal("no kill dispatched")
	}
	if msg["type"] != "kill" || msg["epoch"].(float64) != float64(kr.Epoch) {
		t.Fatalf("unexpected kill message: %v", msg)
	}
	// Kill delivery is terminal on the server side.
	task, _ := srv.GetTask(kr.TaskID)
	if task.State != server.TaskCompleted {
		t.Fatalf("expected kill task completed on dispatch, got %s", task.State)
	}
}

// Reassembled hives are returned per hive name for completed jobs.
func TestAdminResultsReassembled(t *testing.T) {
	ts, srv, _ := newAdminTestServer(t)
	agentID := "aabbccdd"
	jobID := "job-reassembly-1"

	srv.EnqueueTask(agentID, jobID, "extract", map[string]any{"job_id": jobID})

	// Two chunks: one for SYSTEM, one for SAM.
	chunks := []struct {
		seq   uint32
		hive  string
		data  string
		index int
	}{
		{0, "SYSTEM", "regf-system-data", 0},
		{1, "SAM", "regf-sam-data", 1},
	}
	for _, c := range chunks {
		wire := makeChunkWire(c.seq, c.hive, c.data)
		payload, _ := json.Marshal(map[string]any{
			"job_id":   jobID,
			"hive":     c.hive,
			"index":    float64(c.index),
			"total":    float64(2),
			"data_b64": base64.StdEncoding.EncodeToString(wire),
		})
		srv.HandleMessage(agentID, message.Make("result", agentID, jobID, string(payload), float64(time.Now().Unix())))
	}

	// Task completed by final chunk.
	task, _ := srv.GetTask(jobID)
	if task.State != server.TaskCompleted {
		t.Fatalf("expected completed, got %s", task.State)
	}

	code, body := adminGet(t, ts.URL+adminapi.AdminPrefix+"/results?agent="+agentID+"&task="+jobID+"&reassembled=1", testOperatorToken)
	if code != http.StatusOK {
		t.Fatalf("results failed: %d %s", code, body)
	}
	var rr adminapi.ResultsResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		t.Fatal(err)
	}
	if !rr.Complete {
		t.Fatal("expected complete reassembly")
	}
	if len(rr.Reassembled) != 2 {
		t.Fatalf("expected 2 hives, got %d", len(rr.Reassembled))
	}
	for hive, want := range map[string]string{"SYSTEM": "regf-system-data", "SAM": "regf-sam-data"} {
		got, err := base64.StdEncoding.DecodeString(rr.Reassembled[hive])
		if err != nil || string(got) != want {
			t.Fatalf("hive %s reassembly mismatch: %q (err=%v)", hive, got, err)
		}
	}
}

// Invalid-token brute force is rate limited before authentication, so it
// cannot append unbounded audit entries; operator polling still recovers at
// the configured refill rate.
func TestAdminInvalidAuthRateLimited(t *testing.T) {
	ts, _, h := newAdminTestServer(t)

	var got429 int
	for i := 0; i < 200; i++ {
		code, _ := adminGet(t, ts.URL+adminapi.AdminPrefix+"/health", "wrong-token")
		if code == http.StatusTooManyRequests {
			got429++
		}
	}
	if got429 == 0 {
		t.Fatal("expected repeated unauthenticated requests to be rate limited")
	}

	// Emulate 2s of elapsed time (one --wait poll interval) for every bucket:
	// the refill must let valid operator traffic through again.
	h.limiter.mu.Lock()
	for _, b := range h.limiter.buckets {
		b.last = b.last.Add(-2 * time.Second)
	}
	h.limiter.mu.Unlock()
	code, body := adminGet(t, ts.URL+adminapi.AdminPrefix+"/health", testOperatorToken)
	if code != http.StatusOK {
		t.Fatalf("valid request after refill: expected 200, got %d: %s", code, body)
	}
}

// Task-supplied chunk_size is validated to (0, 512KB] before it reaches the
// agent, matching agent config validation.
func TestAdminChunkSizeValidation(t *testing.T) {
	ts, _, _ := newAdminTestServer(t)

	cases := []struct {
		name      string
		chunkSize int
		want      int
	}{
		{"zero", 0, http.StatusBadRequest},
		{"negative", -1, http.StatusBadRequest},
		{"over max", 512*1024 + 1, http.StatusBadRequest},
		{"max ok", 512 * 1024, http.StatusOK},
		{"small ok", 1, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, _ := json.Marshal(adminapi.EnqueueTaskRequest{
				AgentID:   "aabbccdd",
				Action:    "extract",
				Hives:     []string{"SYSTEM"},
				JobID:     "job-" + c.name,
				ChunkSize: c.chunkSize,
			})
			code, body := adminPost(t, ts.URL+adminapi.AdminPrefix+"/tasks", testOperatorToken, raw)
			if code != c.want {
				t.Fatalf("chunk_size=%d: got %d, want %d: %s", c.chunkSize, code, c.want, body)
			}
			if code == http.StatusBadRequest {
				var e adminapi.ErrorResponse
				if err := json.Unmarshal(body, &e); err != nil || e.Error == "" {
					t.Fatalf("expected structured error, got %s", body)
				}
			}
		})
	}
}

// Invalid admin requests are rejected with structured errors.
func TestAdminValidation(t *testing.T) {
	ts, _, _ := newAdminTestServer(t)

	cases := []struct {
		path string
		body any
	}{
		{"/tasks", adminapi.EnqueueTaskRequest{AgentID: "", Action: "noop"}},
		{"/tasks", adminapi.EnqueueTaskRequest{AgentID: "x", Action: "shell"}},
		{"/kill", adminapi.KillRequest{AgentID: ""}},
		{"/kill", adminapi.KillRequest{AgentID: "x", Payload: "reboot"}},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(c.body)
		code, body := adminPost(t, ts.URL+adminapi.AdminPrefix+c.path, testOperatorToken, raw)
		if code < 400 {
			t.Fatalf("POST %s with %+v: expected 4xx, got %d", c.path, c.body, code)
		}
		var e adminapi.ErrorResponse
		if err := json.Unmarshal(body, &e); err != nil || e.Error == "" {
			t.Fatalf("expected structured error, got %s", body)
		}
	}

	// Results requires an agent.
	code, _ := adminGet(t, ts.URL+adminapi.AdminPrefix+"/results", testOperatorToken)
	if code != http.StatusBadRequest {
		t.Fatalf("results without agent: expected 400, got %d", code)
	}
}

func makeChunkWire(seq uint32, hive, data string) []byte {
	hiveBytes := []byte(hive)
	path := `\REGISTRY\` + hive
	pathBytes := []byte(path)
	wire := make([]byte, 12+len(hiveBytes)+len(pathBytes)+len(data))
	wire[0] = byte(seq >> 24)
	wire[1] = byte(seq >> 16)
	wire[2] = byte(seq >> 8)
	wire[3] = byte(seq)
	wire[4] = byte(len(hiveBytes) >> 8)
	wire[5] = byte(len(hiveBytes))
	wire[6] = byte(len(pathBytes) >> 8)
	wire[7] = byte(len(pathBytes))
	dl := uint32(len(data))
	wire[8] = byte(dl >> 24)
	wire[9] = byte(dl >> 16)
	wire[10] = byte(dl >> 8)
	wire[11] = byte(dl)
	copy(wire[12:], hiveBytes)
	copy(wire[12+len(hiveBytes):], pathBytes)
	copy(wire[12+len(hiveBytes)+len(pathBytes):], []byte(data))
	return wire
}

// testSaltHex is a fixed 16-byte salt used across admin tests.
const testSaltHex = "deadbeef0102030405060708090a0b0c"

func testEphPubHex(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(priv.PublicKey().Bytes())
}
