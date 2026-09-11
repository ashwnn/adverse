// Package drop implements the dead-drop transport ("living off trusted
// services"): the agent and server exchange the same wire envelopes as opaque
// blobs through third-party file storage instead of direct HTTPS connections.
//
// The wire contract is unchanged — the same framed, authenticated envelopes
// (wire.Build/Parse) are uploaded as blobs and collected by polling. The
// transport core (transport.Handler.ProcessFrame) is shared, so the drop
// channel cannot drift from the HTTP channel.
//
// Blob layout under a store root:
//
//	<dir>/<agentID>/<seq>-in     agent -> server (request frame)
//	<dir>/<agentID>/<seq>-out    server -> agent (response frame)
//
// Both sides delete blobs after processing (delete-after-read): the storage
// holds only ephemeral encrypted blobs with no plaintext, no session keys.
//
// Store implementations:
//   - HTTPStore: generic PUT/GET/DELETE over HTTPS (WebDAV/Nextcloud-style or
//     any compatible endpoint). Optional basic/bearer auth.
//   - GraphStore: Microsoft Graph API OneDrive (app registration +
//     client-credentials OAuth). Traffic terminates at graph.microsoft.com,
//     an allowlisted endpoint on virtually every network (documented LOTS
//     technique).
//
// Importing this package does not perform any network activity.
package drop

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound is returned by Store.Get when the blob does not exist.
var ErrNotFound = errors.New("drop: blob not found")

// MaxBlobBytes is the maximum blob size stores will read. Reads that hit the
// limit are treated as an error rather than silently truncated.
const MaxBlobBytes = 2 << 20

// Store is the dead-drop storage primitive. Implementations must be safe for
// concurrent use. Blob names are path segments relative to the store root and
// must not escape it.
type Store interface {
	// Put writes data under name, overwriting any existing blob.
	Put(ctx context.Context, name string, data []byte) error
	// Get returns the blob contents, or ErrNotFound.
	Get(ctx context.Context, name string) ([]byte, error)
	// Delete removes the blob. Deleting a missing blob is not an error.
	Delete(ctx context.Context, name string) error
}

// Lister is the optional discovery capability the server-side poller needs:
// enumerate blob names under a prefix (directory listing). Stores that cannot
// list (e.g. pure HTTP stores without WebDAV) cannot serve the poller.
type Lister interface {
	// List returns blob names under prefix, sorted, or an error. Missing
	// prefixes return an empty list.
	List(ctx context.Context, prefix string) ([]string, error)
}

// validateName rejects names that could escape the store root (empty segments,
// "." / ".." traversal, backslashes, NUL bytes) or corrupt a URL when the name
// is concatenated into a blob URL ("?", "#", "%"; "%" would also be
// double-decoded by some servers). Control characters are rejected too. Unsafe
// characters are rejected rather than percent-encoded so every Store
// implementation agrees on the accepted name space; generated names use only
// safe segments (<agentID>/<seq>-in).
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("drop: empty blob name")
	}
	for _, c := range name {
		if c == '\\' || c == '\x00' || c == '?' || c == '#' || c == '%' {
			return fmt.Errorf("drop: invalid blob name %q", name)
		}
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("drop: invalid blob name %q", name)
		}
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("drop: invalid blob name %q", name)
		}
	}
	return nil
}
