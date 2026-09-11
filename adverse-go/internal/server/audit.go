package server

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditLogger writes a JSONL audit trail of operator- and server-side events
// to <StateDir>/audit.jsonl. Every entry carries an RFC3339 timestamp, the
// action, and structured fields. Session keys, hive contents, and secrets are
// never written.
type auditLogger struct {
	mu     sync.Mutex
	path   string
	logger *slog.Logger
}

// newAuditLogger returns a logger writing to the given state directory.
func newAuditLogger(stateDir string, logger *slog.Logger) *auditLogger {
	if logger == nil {
		logger = slog.Default()
	}
	if stateDir == "" {
		return &auditLogger{logger: logger} // disabled
	}
	return &auditLogger{path: filepath.Join(stateDir, "audit.jsonl"), logger: logger}
}

func (a *auditLogger) setStateDir(stateDir string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if stateDir == "" {
		a.path = ""
	} else {
		a.path = filepath.Join(stateDir, "audit.jsonl")
	}
}

// Log appends one audit entry. Field values must be strings or JSON-marshalable
// scalars; never hive bytes or secrets. Failures are best-effort: auditing must
// not take down the C2.
func (a *auditLogger) Log(action string, fields map[string]any) {
	if a == nil || a.path == "" {
		return
	}
	entry := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "action": action}
	for k, v := range fields {
		entry[k] = v
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		a.logger.Warn("audit marshal failed", "action", action, "err", err)
		return
	}
	raw = append(raw, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.path), 0700); err != nil {
		a.logger.Warn("audit log dir create failed", "path", a.path, "err", err)
		return
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		a.logger.Warn("audit log open failed", "path", a.path, "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		a.logger.Warn("audit log write failed", "path", a.path, "err", err)
	}
}
