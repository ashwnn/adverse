package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ashwnn/adverse-go/internal/server"
)

const clientTestToken = "client-test-token"

// The client serializes requests correctly and parses responses, including
// structured error bodies.
func TestClientEndpoints(t *testing.T) {
	srv, err := server.New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil)
	if err != nil {
		t.Fatal(err)
	}
	agentID := "aabbccdd"
	srv.EnqueueTask(agentID, "job-1", "noop", nil)

	// A minimal fake admin handler exercising the JSON contract.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+clientTestToken {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid bearer token"})
			return
		}
		switch r.URL.Path {
		case AdminPrefix + "/health":
			json.NewEncoder(w).Encode(Health{Status: "ok", Agents: 1, OnlineAgents: 1})
		case AdminPrefix + "/agents":
			json.NewEncoder(w).Encode([]AgentInfo{{AgentID: agentID, Online: true}})
		case AdminPrefix + "/tasks":
			if r.Method == http.MethodPost {
				var req EnqueueTaskRequest
				json.NewDecoder(r.Body).Decode(&req)
				json.NewEncoder(w).Encode(EnqueueTaskResponse{TaskID: "job-1"})
				return
			}
			json.NewEncoder(w).Encode([]TaskInfo{{ID: "job-1", AgentID: agentID, Action: "noop", State: "queued"}})
		case AdminPrefix + "/kill":
			var req KillRequest
			json.NewDecoder(r.Body).Decode(&req)
			json.NewEncoder(w).Encode(KillResponse{TaskID: "kill-1", Epoch: 1})
		case AdminPrefix + "/results":
			json.NewEncoder(w).Encode(ResultsResponse{Agent: agentID, Complete: true})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "not found"})
		}
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	c := NewClient(ts.URL, clientTestToken)
	ctx := context.Background()

	if h, err := c.Health(ctx); err != nil || h.Status != "ok" {
		t.Fatalf("health: %+v err=%v", h, err)
	}
	agents, err := c.Agents(ctx)
	if err != nil || len(agents) != 1 || agents[0].AgentID != agentID {
		t.Fatalf("agents: %+v err=%v", agents, err)
	}
	taskID, err := c.EnqueueTask(ctx, EnqueueTaskRequest{AgentID: agentID, Action: "noop"})
	if err != nil || taskID != "job-1" {
		t.Fatalf("enqueue: %s err=%v", taskID, err)
	}
	tasks, err := c.Tasks(ctx, agentID)
	if err != nil || len(tasks) != 1 || tasks[0].State != "queued" {
		t.Fatalf("tasks: %+v err=%v", tasks, err)
	}
	kill, err := c.Kill(ctx, KillRequest{AgentID: agentID, Payload: "kill"})
	if err != nil || kill.Epoch != 1 {
		t.Fatalf("kill: %+v err=%v", kill, err)
	}
	results, err := c.Results(ctx, agentID, "", true)
	if err != nil || !results.Complete {
		t.Fatalf("results: %+v err=%v", results, err)
	}
}

// Wrong tokens produce the server's structured error, not a parse failure.
func TestClientAuthError(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid bearer token"})
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	c := NewClient(ts.URL, "wrong")
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected auth error")
	}
	if err.Error() != "server error (401): invalid bearer token" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestClientResponseLimit pins the truncation fix: an oversized body returns a
// clear limit error instead of being silently cut off (which used to surface
// as a JSON unmarshal failure in `adversed results --out`).
func TestClientResponseLimit(t *testing.T) {
	old := maxResponseBytes
	maxResponseBytes = 256
	defer func() { maxResponseBytes = old }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("A", 1024)))
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "token")
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected response-limit error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected clear limit error, got: %v", err)
	}

	// A response within the (lowered) bound still parses.
	tsOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Health{Status: "ok"})
	}))
	defer tsOK.Close()
	h, err := NewClient(tsOK.URL, "token").Health(context.Background())
	if err != nil || h.Status != "ok" {
		t.Fatalf("small response failed: %+v err=%v", h, err)
	}
}
