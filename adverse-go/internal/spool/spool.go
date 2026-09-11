package spool

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// MaxChunkSize is the largest chunk Put accepts (1 MiB). Larger chunks must be
// split by the caller; the cap bounds per-file memory and limits the cost of
// an accidental huge read.
const MaxChunkSize = 1 << 20

const (
	journalName = "journal.json.enc"
	metaName    = "meta.enc"
	chunkSuffix = ".chunk"
	aadJournal  = "journal"
	maxJobIDLen = 200
)

// Sentinel errors returned (wrapped) by Store methods. Callers can test them
// with errors.Is.
var (
	// ErrSecretSize indicates secret32 was not exactly 32 bytes.
	ErrSecretSize = errors.New("spool: secret32 must be exactly 32 bytes")
	// ErrEmptyAgentID indicates an empty agent ID was passed to Open.
	ErrEmptyAgentID = errors.New("spool: agentID must be non-empty")
	// ErrBadDir indicates an empty spool directory was requested.
	ErrBadDir = errors.New("spool: dir must be non-empty")
	// ErrBadJobID indicates a job ID containing anything other than ASCII
	// letters, digits, '-' or '_' (in particular path separators and dots).
	ErrBadJobID = errors.New("spool: job id must be non-empty ASCII alphanumeric, '-' or '_'")
	// ErrBadSeq indicates seq < 0 or seq >= total.
	ErrBadSeq = errors.New("spool: invalid sequence number")
	// ErrBadTotal indicates total <= 0.
	ErrBadTotal = errors.New("spool: total must be > 0")
	// ErrEmptyChunk indicates a zero-length chunk.
	ErrEmptyChunk = errors.New("spool: chunk must not be empty")
	// ErrChunkTooLarge indicates a chunk larger than MaxChunkSize.
	ErrChunkTooLarge = errors.New("spool: chunk exceeds 1 MiB")
	// ErrTotalMismatch indicates a Put whose total differs from the total
	// recorded for the job. Total is bound into every chunk's AAD, so it must
	// stay constant for the life of a job.
	ErrTotalMismatch = errors.New("spool: total does not match the job's original total")
	// ErrNoJob indicates the requested job is not spooled.
	ErrNoJob = errors.New("spool: no such job")
	// ErrCorrupt indicates data that failed authentication: tampered, truncated,
	// or encrypted under a different key. No plaintext is ever returned with it.
	ErrCorrupt = errors.New("spool: corrupt, tampered, or wrong-key data")
)

// Progress is the durable per-job bookmark. It is safe to copy.
type Progress struct {
	JobID  string `json:"job_id"`
	Hive   string `json:"hive"`
	Total  int    `json:"total"`
	Next   int    `json:"next"`   // one past the highest seq ever Put or Acked
	Acked  []int  `json:"acked"`  // seqs the server confirmed and that were pruned
	Chunks int    `json:"chunks"` // chunk files currently on disk for this job
}

// Store is a concurrency-safe handle to one encrypted spool directory. All
// mutations are persisted (atomic write + best-effort fsync) before the method
// returns. A Store is intended for use by a single process; no cross-process
// locking is performed.
type Store struct {
	dir  string
	key  [32]byte
	aead cipher.AEAD

	mu   sync.Mutex
	jobs map[string]*Progress
}

// Open prepares (creating if needed, mode 0700) the spool directory dir and
// loads any durable state. secret32 is the raw 32-byte per-agent secret; the
// AEAD key is HKDF-SHA256(secret32, salt=nil, info="adverse-spool-v1|"+agentID).
// If the journal is missing or unreadable, Open rebuilds what it can from the
// per-job encrypted metadata and chunk files (see the package documentation).
func Open(dir string, secret32 []byte, agentID string) (*Store, error) {
	if len(secret32) != 32 {
		return nil, ErrSecretSize
	}
	if agentID == "" {
		return nil, ErrEmptyAgentID
	}
	if dir == "" {
		return nil, ErrBadDir
	}
	key, err := deriveKey(secret32, agentID)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("spool: aead init: %w", err)
	}
	s := &Store{
		dir:  dir,
		key:  key,
		aead: aead,
		jobs: make(map[string]*Progress),
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: create dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// DefaultDir returns os.TempDir()/adverse/<agentID>/spool. The agent ID is
// reduced to a filesystem-safe path component; Open creates the directory
// 0700. Because it lives under the system temp directory it may be reaped by
// the OS, which is acceptable: the spool is a resume aid, not primary storage.
func DefaultDir(agentID string) string {
	return filepath.Join(os.TempDir(), "adverse", cleanComponent(agentID), "spool")
}

// Put encrypts and atomically writes one chunk for jobID, then persists the
// job's progress. Re-Putting the same (jobID, seq) is idempotent: the file is
// overwritten in place and the sequence is removed from Acked (the caller
// wants it sent again). total must match the job's first Put because it is
// bound into every chunk's AAD.
func (s *Store) Put(jobID, hive string, seq, total int, chunk []byte) error {
	if err := validateJobID(jobID); err != nil {
		return err
	}
	if total <= 0 {
		return ErrBadTotal
	}
	if seq < 0 || seq >= total {
		return fmt.Errorf("%w: seq %d, total %d", ErrBadSeq, seq, total)
	}
	if len(chunk) == 0 {
		return ErrEmptyChunk
	}
	if len(chunk) > MaxChunkSize {
		return ErrChunkTooLarge
	}
	blob, err := s.encrypt(chunkAAD(jobID, seq, total), chunk)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, known := s.jobs[jobID]
	if !known {
		rec = &Progress{JobID: jobID, Hive: hive, Total: total, Acked: []int{}}
		if err := os.MkdirAll(s.jobDir(jobID), 0o700); err != nil {
			return fmt.Errorf("spool: create job dir: %w", err)
		}
		if err := s.writeMeta(jobID, rec); err != nil {
			return err
		}
		s.jobs[jobID] = rec
	} else {
		if rec.Total != total {
			return fmt.Errorf("%w: job %s has total %d, got %d", ErrTotalMismatch, jobID, rec.Total, total)
		}
		if hive != "" && hive != rec.Hive {
			rec.Hive = hive
			if err := s.writeMeta(jobID, rec); err != nil {
				return err
			}
		}
		rec.Acked = removeInt(rec.Acked, seq)
	}

	path := s.chunkPath(jobID, seq)
	existed := false
	if _, statErr := os.Stat(path); statErr == nil {
		existed = true
	}
	if err := writeFileAtomic(path, blob, 0o600); err != nil {
		return fmt.Errorf("spool: write chunk: %w", err)
	}
	if !existed {
		rec.Chunks++
	}
	if seq+1 > rec.Next {
		rec.Next = seq + 1
	}
	return s.writeJournalLocked()
}

// Get authenticates and returns the spooled chunk for (jobID, seq). A missing
// chunk returns an error satisfying errors.Is(err, fs.ErrNotExist); tampered,
// truncated, or wrong-key data returns an error satisfying
// errors.Is(err, ErrCorrupt), never plaintext.
func (s *Store) Get(jobID string, seq int) ([]byte, error) {
	if err := validateJobID(jobID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.jobs[jobID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoJob, jobID)
	}
	if seq < 0 || seq >= rec.Total {
		return nil, fmt.Errorf("%w: seq %d, total %d", ErrBadSeq, seq, rec.Total)
	}
	blob, err := os.ReadFile(s.chunkPath(jobID, seq))
	if err != nil {
		return nil, err
	}
	return s.decrypt(chunkAAD(jobID, seq, rec.Total), blob)
}

// Jobs returns the sorted IDs of all incomplete jobs: every job with durable
// state and no Complete call. An empty store returns an empty, non-nil slice.
func (s *Store) Jobs() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.jobs))
	for id := range s.jobs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// Progress returns a copy of the durable bookmark for jobID. Chunks is
// recomputed from the directory listing so it always reflects the files on
// disk. Unknown jobs return an error satisfying errors.Is(err, ErrNoJob).
func (s *Store) Progress(jobID string) (Progress, error) {
	if err := validateJobID(jobID); err != nil {
		return Progress{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.jobs[jobID]
	if !ok {
		return Progress{}, fmt.Errorf("%w: %s", ErrNoJob, jobID)
	}
	p := *rec
	p.Acked = append([]int(nil), rec.Acked...)
	if p.Acked == nil {
		p.Acked = []int{}
	}
	p.Chunks = s.countChunks(jobID)
	return p, nil
}

// Ack records that the server confirmed seqs and deletes exactly those chunk
// files. It is idempotent: re-acking an already-pruned sequence, a sequence
// that was never spooled, or an unknown job is a no-op, and Next never moves
// backwards. Ack is the normal steady-state cleanup path.
func (s *Store) Ack(jobID string, seqs []int) error {
	if err := validateJobID(jobID); err != nil {
		return err
	}
	for _, seq := range seqs {
		if seq < 0 {
			return fmt.Errorf("%w: %d", ErrBadSeq, seq)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.jobs[jobID]
	if !ok {
		return nil
	}
	changed := false
	for _, seq := range seqs {
		if err := os.Remove(s.chunkPath(jobID, seq)); err == nil {
			if rec.Chunks > 0 {
				rec.Chunks--
			}
			changed = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("spool: ack remove: %w", err)
		}
		if !slices.Contains(rec.Acked, seq) {
			rec.Acked = append(rec.Acked, seq)
			changed = true
		}
		if seq+1 > rec.Next {
			rec.Next = seq + 1
			changed = true
		}
	}
	if !changed {
		return nil
	}
	sort.Ints(rec.Acked)
	if rec.Next > rec.Total {
		rec.Next = rec.Total
	}
	return s.writeJournalLocked()
}

// Complete removes all state for a finished job: its whole chunk directory and
// its journal entry. It is idempotent, including for unknown jobs.
func (s *Store) Complete(jobID string) error {
	if err := validateJobID(jobID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.jobs[jobID]
	if err := os.RemoveAll(s.jobDir(jobID)); err != nil {
		return fmt.Errorf("spool: complete: %w", err)
	}
	if !known {
		return nil
	}
	delete(s.jobs, jobID)
	return s.writeJournalLocked()
}

// Wipe removes the entire spool tree (the root directory and everything under
// it) and forgets all in-memory progress. It is idempotent and safe to call
// after the directory is already gone. The Store remains usable: the next Put
// recreates the tree. Call Wipe on agent kill and from any TTL sweep.
func (s *Store) Wipe() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.RemoveAll(s.dir); err != nil {
		return fmt.Errorf("spool: wipe: %w", err)
	}
	s.jobs = make(map[string]*Progress)
	return nil
}

// validateJobID enforces the id charset: ASCII letters, digits, '-' and '_'.
// Dots, path separators, whitespace, and non-ASCII are rejected. The charset
// keeps AAD unambiguous ('|' cannot occur) and is a hard requirement even
// though directory names are keyed hashes, so a bad ID can never influence a
// path.
func validateJobID(jobID string) error {
	if jobID == "" || len(jobID) > maxJobIDLen {
		return ErrBadJobID
	}
	for i := 0; i < len(jobID); i++ {
		if !isJobIDByte(jobID[i]) {
			return ErrBadJobID
		}
	}
	return nil
}

// cleanComponent reduces an arbitrary agent ID to a safe single path
// component (used by DefaultDir). Unlike validateJobID this never fails: it
// maps unsafe bytes to '_' and falls back to "agent" when nothing survives.
func cleanComponent(agentID string) string {
	var b strings.Builder
	for i := 0; i < len(agentID); i++ {
		c := agentID[i]
		if isJobIDByte(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		out = "agent"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// isJobIDByte is the shared id charset used by validateJobID (which rejects
// offenders) and cleanComponent (which sanitizes them).
func isJobIDByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		return true
	}
	return false
}

func removeInt(xs []int, v int) []int {
	out := xs[:0]
	for _, x := range xs {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
