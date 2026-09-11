// Package integration runs the ADVERSE C2 server (adversed) and the
// registryfil client as two separate binaries against each other, exercising
// the full wire contract end-to-end: hello → registration → task dispatch →
// chunked result collection with reassembly → signed kill.
//
// The two agents were built against a shared wire contract but never run
// against each other; this test proves (or fixes) real interop.
package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/cryptokeys"
)

// binaries built once per test run into a temp dir.
var (
	adversedBin    string
	registryfilBin string
)

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "adverse-interop-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdir temp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	adversedBin = filepath.Join(tmp, "adversed")
	registryfilBin = filepath.Join(tmp, "registryfil")

	build := func(out, pkg string) {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n", pkg, err)
			os.Exit(1)
		}
	}

	build(adversedBin, "github.com/ashwnn/adverse-go/cmd/adversed")
	build(registryfilBin, "github.com/ashwnn/adverse-go/cmd/registryfil")

	os.Exit(m.Run())
}

// ----------------------------- helpers -------------------------------------

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for {
		ok, msg := fn()
		if ok {
			return
		}
		last = msg
		if time.Now().After(deadline) {
			t.Fatalf("timeout after %v: %s", timeout, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// --------------------------- state file shapes ----------------------------

type stateFile struct {
	Updated float64                    `json:"updated"`
	Agents  map[string]json.RawMessage `json:"agents"`
	Results map[string][]resultEntry   `json:"results"`
}

type resultEntry struct {
	TaskID  string  `json:"task_id"`
	Payload string  `json:"payload"`
	Ts      float64 `json:"ts"`
}

type resultPayload struct {
	JobID   string `json:"job_id"`
	Hive    string `json:"hive"`
	Seq     int    `json:"seq"`
	Total   int    `json:"total"`
	SHA256  string `json:"sha256"`
	DataB64 string `json:"data_b64"`
}

func readState(t *testing.T, statePath string) stateFile {
	t.Helper()
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var s stateFile
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	return s
}

// ----------------------------- the test ------------------------------------

func TestInterop(t *testing.T) {
	// 1. Generate a fresh fleet secret.
	secret, err := cryptokeys.Keygen()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// 2. Find a free port for the server.
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	serverURL := fmt.Sprintf("https://%s", addr)

	// 3. Create temp dirs for agent config, state, and profile.
	testDir := t.TempDir()
	agentCfgPath := filepath.Join(testDir, "agent.json")
	stateDir := filepath.Join(testDir, "state")
	profilePath := filepath.Join(testDir, "profile.json")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}

	// 4. Generate agent config via adversed gen-agent.
	cmd := exec.Command(adversedBin, "gen-agent",
		"--secret", secret,
		"--out", agentCfgPath,
		"--server-url", serverURL,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-agent: %v\n%s", err, out)
	}

	// Read agent_id from the generated config.
	var genCfg struct {
		AgentID string `json:"agent_id"`
	}
	gdata, err := os.ReadFile(agentCfgPath)
	if err != nil {
		t.Fatalf("read agent cfg: %v", err)
	}
	if err := json.Unmarshal(gdata, &genCfg); err != nil {
		t.Fatalf("parse agent cfg: %v", err)
	}
	agentID := genCfg.AgentID
	t.Logf("agent_id=%s server=%s state=%s", agentID, serverURL, stateDir)

	// 5. Edit agent.json for the test: small chunk, fast delays, synthetic mode,
	//    and TLS skip verify (server uses a self-signed ephemeral cert).
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
	edited, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	if err := os.WriteFile(agentCfgPath, edited, 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	// 6. Write a profile that makes the server beacon fast so the agent picks up
	//    tasks quickly.
	profData := []byte(`{"name":"lab","beacon_interval_s":1,"beacon_jitter_s":0}`)
	if err := os.WriteFile(profilePath, profData, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	// 6b. Write an operator token file for the admin API.
	operatorToken := "interop-op-token-00112233445566778899aabbccddeeff"
	operatorTokenPath := filepath.Join(testDir, "operator.token")
	if err := os.WriteFile(operatorTokenPath, []byte(operatorToken+"\n"), 0o600); err != nil {
		t.Fatalf("write operator token: %v", err)
	}

	// 7. Start the adversed server. Use a process-group kill on cleanup so the
	//    OS-level listener is released. The admin API is enabled via the token.
	serverCmd := exec.Command(adversedBin, "serve",
		"--secret", secret,
		"--listen", addr,
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

	// 8. Wait for the server to accept TCP connections.
	waitForTCP(t, addr, 10*time.Second)
	t.Logf("server listening on %s", addr)

	// 9. Start the registryfil agent (real network egress).
	agentCmd := exec.Command(registryfilBin,
		"--config", agentCfgPath,
		"--dry-run=false",
	)
	agentCmd.Stdout = os.Stderr
	agentCmd.Stderr = os.Stderr
	agentCmd.Dir = testDir // so .agent_state.json lands here
	setSysProcAttr(agentCmd)
	// Disable the behavioural gate on the spawned agent so it does not stall
	// past the analysis window in CI (agent.go stalls 120s when the env-keyed
	// gate scores below RealMachineThreshold on a Linux/VM host). The gate is
	// exercised separately by internal/behavioural; this test only covers the
	// wire contract.
	agentCmd.Env = append(os.Environ(), "ADVERSE_BEHAVIOURAL=0")
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	t.Cleanup(func() { killProcess(agentCmd) })

	// 10. Wait for the agent to register (hello) with the server.
	statePath := filepath.Join(stateDir, "state.json")
	waitForCondition(t, 20*time.Second, func() (bool, string) {
		if _, err := os.Stat(statePath); err != nil {
			return false, "state.json not yet written"
		}
		s := readState(t, statePath)
		if _, ok := s.Agents[agentID]; !ok {
			return false, fmt.Sprintf("agent %s not registered (agents=%v)", agentID, keysOf(s.Agents))
		}
		return true, ""
	})
	t.Logf("agent registered with server")

	// 10b. Health via the admin API (operator auth).
	statusCmd := exec.Command(adversedBin, "status",
		"--server", serverURL, "--token-file", operatorTokenPath)
	if out, err := statusCmd.CombinedOutput(); err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	} else {
		t.Logf("status: %s", strings.TrimSpace(string(out)))
	}

	// 11. Push an extract task for SYSTEM and SAM via the admin API and wait
	//     for the full lifecycle (enqueue -> dispatch -> ack -> completed).
	taskCmd := exec.Command(adversedBin, "task",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID,
		"--action", "extract",
		"--hives", "SYSTEM,SAM",
		"--wait", "--timeout", "60s",
	)
	taskOut, err := taskCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("task: %v\n%s", err, taskOut)
	}
	// Parse "queued extract (task <id>) for <agent>" from the output.
	jobID := parseTaskID(t, string(taskOut))
	t.Logf("task %s completed for hives SYSTEM,SAM", jobID)

	// 12. Verify the task lifecycle via the admin API: completed, acked.
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
		if ti.State != "completed" {
			t.Fatalf("task %s state=%s, want completed (lifecycle=%+v)", jobID, ti.State, ti)
		}
		if ti.AckedAt == "" {
			t.Fatalf("task %s never acked by agent (lifecycle=%+v)", jobID, ti)
		}
		t.Logf("task %s lifecycle: state=%s acked_at=%s completed_at=%s", jobID, ti.State, ti.AckedAt, ti.CompletedAt)
	}
	if !found {
		t.Fatalf("task %s not found in %+v", jobID, taskInfos)
	}

	// 13. Fetch reassembled hives via the admin API and verify contents. This
	//     exercises server-side chunk reassembly end-to-end (not manual
	//     reconstruction from state.json).
	outDir := filepath.Join(testDir, "reassembled")
	resultsCmd := exec.Command(adversedBin, "results",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID,
		"--task", jobID,
		"--out", outDir,
	)
	if out, err := resultsCmd.CombinedOutput(); err != nil {
		t.Fatalf("results: %v\n%s", err, out)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no reassembled hive files in %s: %v", outDir, err)
	}
	hiveCount := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if len(data) < 4 {
			t.Fatalf("%s: too short (%d bytes)", e.Name(), len(data))
		}
		if string(data[:4]) != "regf" {
			t.Errorf("%s: reassembled data does not start with 'regf': %q", e.Name(), string(data[:4]))
		}
		if !strings.Contains(string(data), "CANARY") {
			t.Errorf("%s: reassembled data missing CANARY marker", e.Name())
		}
		t.Logf("hive file %s: %d bytes, regf+CANARY OK", e.Name(), len(data))
		hiveCount++
	}
	if hiveCount < 2 {
		t.Fatalf("expected >=2 reassembled hive files (SYSTEM, SAM), got %d", hiveCount)
	}

	// 13b. Noop task via the admin API with --wait: exercises ack + status result.
	noopCmd := exec.Command(adversedBin, "task",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID,
		"--action", "noop",
		"--wait", "--timeout", "30s",
	)
	noopOut, err := noopCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("noop task: %v\n%s", err, noopOut)
	}
	noopID := parseTaskID(t, string(noopOut))
	t.Logf("noop task %s completed", noopID)

	// 14. Run a kill against the agent via the admin API.
	killCmd := exec.Command(adversedBin, "kill",
		"--server", serverURL, "--token-file", operatorTokenPath,
		"--agent", agentID,
	)
	killOut, err := killCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kill: %v\n%s", err, killOut)
	}
	t.Logf("kill pushed for agent %s: %s", agentID, strings.TrimSpace(string(killOut)))

	// 15. The agent should receive the kill on its next beacon and exit 0.
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
			t.Fatalf("agent exited with code %d, want 0", code)
		}
		t.Logf("agent exited 0 (kill accepted)")
	case <-time.After(15 * time.Second):
		t.Fatal("agent did not exit within 15s of kill")
	}
}

// --------------------------- small utilities ------------------------------

// parseTaskID extracts the task ID from `adversed task` output of the form
// "queued extract (task <id>) for <agent>".
func parseTaskID(t *testing.T, out string) string {
	t.Helper()
	const marker = "(task "
	idx := strings.Index(out, marker)
	if idx < 0 {
		t.Fatalf("task output missing task id: %q", out)
	}
	rest := out[idx+len(marker):]
	end := strings.Index(rest, ")")
	if end < 0 {
		t.Fatalf("task output malformed: %q", out)
	}
	id := rest[:end]
	if id == "" {
		t.Fatalf("empty task id in output: %q", out)
	}
	return id
}

type taskInfoJSON struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	Action      string `json:"action"`
	State       string `json:"state"`
	AckedAt     string `json:"acked_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// runTasksJSON invokes `adversed tasks --json` and returns the raw JSON.
func runTasksJSON(t *testing.T, bin, serverURL, tokenPath, agentID string) []byte {
	t.Helper()
	cmd := exec.Command(bin, "tasks",
		"--server", serverURL, "--token-file", tokenPath,
		"--agent", agentID, "--json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tasks: %v\n%s", err, out)
	}
	return out
}

func keysOf(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
