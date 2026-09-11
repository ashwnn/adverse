package drop

import (
	"context"
	"fmt"
	"time"
)

// Client is the agent-side dead-drop transport. It exchanges one wire frame
// per Exchange call: upload <seq>-in, poll for <seq>-out, return the response
// frame, then delete both blobs (delete-after-read).
type Client struct {
	Store           Store
	Dir             string // folder prefix under the store root, e.g. "agents"
	AgentID         string
	PollInterval    time.Duration
	ResponseTimeout time.Duration
}

// NewClient returns a Client with sane polling defaults.
func NewClient(store Store, dir, agentID string) *Client {
	return &Client{
		Store:           store,
		Dir:             dir,
		AgentID:         agentID,
		PollInterval:    2 * time.Second,
		ResponseTimeout: 120 * time.Second,
	}
}

// blobName builds "<dir>/<agentID>/<seq>-<suffix>".
func (c *Client) blobName(seq uint32, suffix string) string {
	dir := c.Dir
	if dir == "" {
		dir = "agents"
	}
	return fmt.Sprintf("%s/%s/%08d-%s", dir, c.AgentID, seq, suffix)
}

// Exchange uploads the request frame and blocks until the response frame is
// available, then returns it. Both blobs are deleted on the way out. Errors
// from the store surface as-is; the caller applies its own retry/backoff.
func (c *Client) Exchange(ctx context.Context, frame []byte, seq uint32) ([]byte, error) {
	in := c.blobName(seq, "in")
	out := c.blobName(seq, "out")

	// Delete a stale response blob from a previous session before uploading
	// (defensive: sessions are memory-only, an old response would fail parse).
	_ = c.Store.Delete(ctx, out)

	if err := c.Store.Put(ctx, in, frame); err != nil {
		return nil, fmt.Errorf("drop upload %s: %w", in, err)
	}
	// Best-effort cleanup of both blobs regardless of outcome (delete-after-read).
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = c.Store.Delete(cleanupCtx, out)
		_ = c.Store.Delete(cleanupCtx, in)
	}()

	poll := c.PollInterval
	if poll <= 0 {
		poll = 2 * time.Second
	}
	timeout := c.ResponseTimeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		data, err := c.Store.Get(ctx, out)
		if err == nil {
			return data, nil
		}
		if err != ErrNotFound {
			return nil, fmt.Errorf("drop poll %s: %w", out, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("drop response timeout for %s", out)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}
