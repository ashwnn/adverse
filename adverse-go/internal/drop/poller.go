package drop

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Handler is the subset of the transport wire core the poller needs. It is
// satisfied by *transport.Handler so both channels share one code path.
type Handler interface {
	// ProcessFrame consumes one envelope frame and returns (status, response).
	// A 200 response is a wire frame; non-200 is an error message.
	ProcessFrame(body []byte) (int, []byte)
}

// Poller is the server-side dead-drop collector. On each tick it lists the
// agent request blobs (<dir>/<agentID>/*-in), processes each frame through the
// shared wire core, writes the response blob (<seq>-out), then deletes the
// request blob. Response blobs are left for the agent to fetch and delete.
type Poller struct {
	Store        Store
	Dir          string
	Handler      Handler
	Logger       *slog.Logger
	PollInterval time.Duration
}

// NewPoller returns a Poller with default logging and interval.
func NewPoller(store Store, dir string, h Handler, logger *slog.Logger) *Poller {
	if logger == nil {
		logger = slog.Default()
	}
	if dir == "" {
		dir = "agents"
	}
	return &Poller{
		Store:        store,
		Dir:          dir,
		Handler:      h,
		Logger:       logger,
		PollInterval: 2 * time.Second,
	}
}

// Run polls until ctx is cancelled. One pass processes all currently visible
// request blobs; the poller is deliberately sequential and bounded per tick.
func (p *Poller) Run(ctx context.Context) {
	interval := p.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollOnce(ctx)
		}
	}
}

// pollOnce processes every visible request blob once. Discovery is two-level:
// list the agents directory, then list each agent directory for "-in" blobs.
func (p *Poller) pollOnce(ctx context.Context) {
	dir := strings.Trim(p.Dir, "/")
	agents, err := p.list(ctx, dir+"/")
	if err != nil {
		p.Logger.Warn("drop poller: list agents failed", "err", err)
		return
	}
	for _, agentDir := range agents {
		// Only direct children (agent dirs), not files.
		rest := strings.TrimPrefix(agentDir, dir+"/")
		if rest == "" || strings.Contains(rest, "/") {
			continue
		}
		blobs, err := p.list(ctx, agentDir+"/")
		if err != nil {
			p.Logger.Warn("drop poller: list agent dir failed", "agent", rest, "err", err)
			continue
		}
		for _, name := range blobs {
			if !strings.HasSuffix(name, "-in") {
				continue
			}
			if err := p.processOne(ctx, name); err != nil {
				p.Logger.Warn("drop poller: process failed", "blob", name, "err", err)
			}
		}
	}
}

// list resolves the optional Lister; stores without List support are skipped
// (single-blob-known layouts are handled by processOne on a fixed agent path
// in future adapters).
func (p *Poller) list(ctx context.Context, prefix string) ([]string, error) {
	if l, ok := p.Store.(Lister); ok {
		return l.List(ctx, prefix)
	}
	return nil, nil
}

// processOne reads one request blob, runs it through the wire core, deletes
// the request blob, and writes the response blob. Ordering matters: the
// request blob is deleted BEFORE the response is written, so a concurrent
// agent retry cannot have its new request blob deleted by a stale delete.
// A crash between delete and response write loses one frame; the agent times
// out and retries with backoff.
func (p *Poller) processOne(ctx context.Context, inName string) error {
	body, err := p.Store.Get(ctx, inName)
	if err != nil {
		return fmt.Errorf("get %s: %w", inName, err)
	}
	if len(body) == 0 {
		return fmt.Errorf("get %s: empty blob", inName)
	}

	status, resp := p.Handler.ProcessFrame(body)

	// Delete the request blob first (see ordering note above).
	if err := p.Store.Delete(ctx, inName); err != nil {
		return fmt.Errorf("delete %s: %w", inName, err)
	}

	// Only success responses are wire frames; error responses are dropped and
	// logged (the agent times out and retries with backoff).
	if status == 200 && len(resp) > 0 {
		outName := strings.TrimSuffix(inName, "-in") + "-out"
		if err := p.Store.Put(ctx, outName, resp); err != nil {
			return fmt.Errorf("put %s: %w", outName, err)
		}
	} else {
		p.Logger.Warn("drop poller: frame rejected",
			"blob", inName, "status", status, "error", truncate(string(resp), 120))
	}
	return nil
}
