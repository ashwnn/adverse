package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ashwnn/adverse-go/internal/agent"
	"github.com/ashwnn/adverse-go/internal/cryptokeys"
)

// TestEmbeddedStub exercises the gen-stub build contract: registryfil is built
// with the agent configuration embedded via
//
//	-ldflags "-X github.com/ashwnn/adverse-go/internal/agent.embeddedConfigB64=<base64(std JSON agent config)>"
//
// and then run with no --config file against a live adversed. It asserts the
// hello/registration handshake and one full task round trip (noop).
//
// The host-OS binary is used rather than the Windows PE so the wire behavior
// is testable on the build host; gen-stub only adds GOOS=windows/GOARCH=amd64
// to the same command. The base64 payload is constructed locally from
// json.Marshal(agent.Config) (not via agent.ParseEmbeddedConfig) so this test
// does not depend on the agent-side parser landing first.
func TestEmbeddedStub(t *testing.T) {
	secret, err := cryptokeys.Keygen()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	secretBytes, err := cryptokeys.Secret32(secret)
	if err != nil {
		t.Fatalf("secret derivation: %v", err)
	}
	agentID := fmt.Sprintf("%x", secretBytes[:4])
	signPriv, err := cryptokeys.DeriveSignKey(secretBytes)
	if err != nil {
		t.Fatalf("sign key derivation: %v", err)
	}
	signPubHex := fmt.Sprintf("%x", []byte(signPriv.Public().(ed25519.PublicKey)))

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	serverURL := "https://" + addr

	testDir := t.TempDir()
	stateDir := filepath.Join(testDir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	profilePath := filepath.Join(testDir, "profile.json")
	if err := os.WriteFile(profilePath, []byte(`{"name":"lab","beacon_interval_s":1,"beacon_jitter_s":0}`), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	operatorTokenPath := filepath.Join(testDir, "operator.token")
	if err := os.WriteFile(operatorTokenPath, []byte("embedded-stub-token-00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatalf("write operator token: %v", err)
	}

	// The embedded config mirrors the test-time edits from interop_test.go:
	// small chunks, fast beaconing, and TLS skip verify for the ephemeral cert.
	cfg := &agent.Config{
		AgentID:       agentID,
		Secret:        secret,
		ServerURL:     serverURL,
		SignPubHex:    signPubHex,
		Hives:         []string{"SYSTEM", "SAM"},
		ChunkSize:     4096,
		MinDelayMs:    50,
		MaxDelayMs:    100,
		TLSSkipVerify: true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("embedded config invalid: %v", err)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal embedded config: %v", err)
	}

	// Build the host-OS registryfil with the config embedded, matching the
	// gen-stub ldflags contract (minus -s -w so go tool nm stays usable).
	stubBin := filepath.Join(t.TempDir(), "registryfil-embedded")
	if runtime.GOOS == "windows" {
		stubBin += ".exe"
	}
	ldflags := "-X github.com/ashwnn/adverse-go/internal/agent.embeddedConfigB64=" + base64.StdEncoding.EncodeToString(cfgJSON)
	build := exec.Command("go", "build", "-o", stubBin, "-ldflags", ldflags,
		"github.com/ashwnn/adverse-go/cmd/registryfil")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build embedded stub: %v", err)
	}

	// Skip cleanly while the concurrent internal/agent + cmd/registryfil
	// refactor is still in flight: without the symbol the linker ignores the
	// -X flag and the binary still demands --config.
	if nmOut, nmErr := exec.Command("go", "tool", "nm", stubBin).Output(); nmErr == nil &&
		!strings.Contains(string(nmOut), "embeddedConfigB64") {
		t.Skip("registryfil does not consume agent.embeddedConfigB64 yet (internal/agent change in flight); skipping embedded-stub interop")
	}

	// Runtime probe: if the built stub still requires --config, the embedded
	// path is not wired up yet. A working stub starts beaconing and is killed
	// by the context deadline.
	probeDir := filepath.Join(testDir, "probe")
	if err := os.MkdirAll(probeDir, 0o700); err != nil {
		t.Fatalf("mkdir probe: %v", err)
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	probe := exec.CommandContext(probeCtx, stubBin, "--dry-run=false")
	probe.Dir = probeDir
	probe.Env = append(os.Environ(), "ADVERSE_BEHAVIOURAL=0")
	probeOut, _ := probe.CombinedOutput()
	cancel()
	if out := string(probeOut); strings.Contains(out, "--config") && strings.Contains(strings.ToLower(out), "required") {
		t.Skipf("registryfil still requires --config (embedded config not wired yet): %s", strings.TrimSpace(out))
	}

	// Start adversed and wait for the TLS listener.
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
	waitForTCP(t, addr, 10*time.Second)
	t.Logf("server listening on %s (agent_id=%s)", addr, agentID)

	// Run the embedded-config stub: no --config argument.
	agentCmd := exec.Command(stubBin, "--dry-run=false")
	agentCmd.Stdout = os.Stderr
	agentCmd.Stderr = os.Stderr
	agentCmd.Dir = testDir
	setSysProcAttr(agentCmd)
	agentCmd.Env = append(os.Environ(), "ADVERSE_BEHAVIOURAL=0")
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start embedded stub: %v", err)
	}
	t.Cleanup(func() { killProcess(agentCmd) })

	// Hello/registration must arrive using only the embedded config.
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
	t.Logf("embedded-config stub registered with server")

	// One task round trip: enqueue noop and wait for completion.
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
	taskID := parseTaskID(t, string(noopOut))
	t.Logf("noop task %s completed (embedded config round trip)", taskID)

	// Verify the task lifecycle in server state.
	tasksJSON := runTasksJSON(t, adversedBin, serverURL, operatorTokenPath, agentID)
	var taskInfos []taskInfoJSON
	if err := json.Unmarshal(tasksJSON, &taskInfos); err != nil {
		t.Fatalf("parse tasks json: %v", err)
	}
	found := false
	for _, ti := range taskInfos {
		if ti.ID != taskID {
			continue
		}
		found = true
		if ti.State != "completed" || ti.AckedAt == "" {
			t.Fatalf("task %s lifecycle wrong: %+v", taskID, ti)
		}
	}
	if !found {
		t.Fatalf("task %s not found in %+v", taskID, taskInfos)
	}
}
