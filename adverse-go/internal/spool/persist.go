package spool

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const journalVersion = 1

// journalData is the plaintext shape of journal.json.enc.
type journalData struct {
	Version int                  `json:"v"`
	Jobs    map[string]*Progress `json:"jobs"`
}

// metaRecord is the plaintext shape of a job's meta.enc, used to rebuild the
// journal when it is lost or damaged.
type metaRecord struct {
	JobID string `json:"job_id"`
	Hive  string `json:"hive"`
	Total int    `json:"total"`
}

// deriveKey is HKDF-SHA256(secret32, salt=nil, info="adverse-spool-v1|"+agentID).
func deriveKey(secret32 []byte, agentID string) ([32]byte, error) {
	var key [32]byte
	derived, err := hkdf.Key(sha256.New, secret32, nil, "adverse-spool-v1|"+agentID, len(key))
	if err != nil {
		return key, fmt.Errorf("spool: hkdf: %w", err)
	}
	copy(key[:], derived)
	return key, nil
}

// encrypt returns nonce || ciphertext for plaintext bound to aad.
func (s *Store) encrypt(aad string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("spool: nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+s.aead.Overhead())
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, []byte(aad)), nil
}

// decrypt authenticates blob and returns its plaintext. Every failure mode
// (short, tampered, truncated, wrong key) collapses to ErrCorrupt.
func (s *Store) decrypt(aad string, blob []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(blob) < ns+s.aead.Overhead() {
		return nil, ErrCorrupt
	}
	pt, err := s.aead.Open(nil, blob[:ns], blob[ns:], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return pt, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// fsyncs it (best effort), and renames it into place. A crash therefore leaves
// either the old file or the complete new file under path, never a partial
// one. The temp file is removed on every error path.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// Durability is best effort: some filesystems/platforms reject fsync.
	_ = f.Sync()
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// load restores durable state. A readable, authentic journal is authoritative
// and is reconciled against disk. Otherwise progress is rebuilt from the
// per-job encrypted metadata and chunk listings; that rebuilt state is
// persisted lazily by the next mutation, so a wrong-key or hostile Open can
// never clobber a valid journal file.
func (s *Store) load() error {
	jobs, ok, err := s.readJournal()
	if err != nil {
		return err
	}
	if !ok {
		s.jobs = make(map[string]*Progress)
		for _, p := range s.rebuild() {
			s.jobs[p.JobID] = p
		}
		return nil
	}
	s.jobs = jobs
	return s.reconcile()
}

// readJournal returns (jobs, true, nil) when the journal decrypts and parses.
// A missing file or any authentication/parse failure returns (nil, false, nil):
// the caller rebuilds. Unexpected I/O errors are returned as-is.
func (s *Store) readJournal() (map[string]*Progress, bool, error) {
	blob, err := os.ReadFile(s.journalPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	pt, err := s.decrypt(aadJournal, blob)
	if err != nil {
		return nil, false, nil
	}
	var jd journalData
	if err := json.Unmarshal(pt, &jd); err != nil {
		return nil, false, nil
	}
	if jd.Jobs == nil {
		jd.Jobs = make(map[string]*Progress)
	}
	return jd.Jobs, true, nil
}

// reconcile makes the authenticated journal agree with the files on disk:
// stale entries (directory gone) are dropped; Chunks/Next are repaired from
// chunk listings (heals the crash window between a chunk write and its journal
// update); and each job's meta.enc is rewritten from the authoritative
// journal. It never deletes chunk data.
func (s *Store) reconcile() error {
	for id, rec := range s.jobs {
		if rec == nil || validateJobID(id) != nil || rec.JobID != id {
			delete(s.jobs, id)
			continue
		}
		seqs, err := s.listChunks(id)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				delete(s.jobs, id)
				continue
			}
			return fmt.Errorf("spool: reconcile %s: %w", id, err)
		}
		if rec.Acked == nil {
			rec.Acked = []int{}
		}
		sort.Ints(rec.Acked)
		rec.Acked = dedupeInts(rec.Acked)
		rawMax := -1
		for _, sq := range seqs {
			if sq > rawMax {
				rawMax = sq
			}
		}
		if rec.Total <= 0 {
			// The journal is authenticated, so this should not happen; fall
			// back to the chunk count rather than leaving an unusable record.
			rec.Total = rawMax + 1
			if rec.Total <= 0 {
				delete(s.jobs, id)
				continue
			}
		}
		maxSeq := -1
		kept := 0
		for _, sq := range seqs {
			if sq >= rec.Total {
				continue // ignore stray files outside [0, total)
			}
			kept++
			if sq > maxSeq {
				maxSeq = sq
			}
		}
		rec.Next = clampNext(rec.Next, maxSeq, rec.Acked, rec.Total)
		rec.Chunks = kept
		if err := s.writeMeta(id, rec); err != nil {
			return err
		}
	}
	return nil
}

// rebuild reconstructs progress records from per-job meta.enc files plus chunk
// listings. Entries whose metadata cannot be authenticated are skipped and
// left on disk for Wipe. Acked starts empty: an unknown ack is re-sent, never
// lost.
func (s *Store) rebuild() []*Progress {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var out []*Progress
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dirName := e.Name()
		m, err := s.readMeta(dirName)
		if err != nil || validateJobID(m.JobID) != nil || m.Total <= 0 {
			continue
		}
		seqs, err := s.listChunks(m.JobID)
		if err != nil {
			continue
		}
		maxSeq := -1
		kept := 0
		for _, sq := range seqs {
			if sq >= m.Total {
				continue // ignore stray files outside [0, total)
			}
			kept++
			if sq > maxSeq {
				maxSeq = sq
			}
		}
		out = append(out, &Progress{
			JobID:  m.JobID,
			Hive:   m.Hive,
			Total:  m.Total,
			Next:   maxSeq + 1,
			Acked:  []int{},
			Chunks: kept,
		})
	}
	return out
}

// writeJournalLocked persists the whole journal atomically. Callers must hold
// s.mu.
func (s *Store) writeJournalLocked() error {
	data, err := json.Marshal(journalData{Version: journalVersion, Jobs: s.jobs})
	if err != nil {
		return fmt.Errorf("spool: journal marshal: %w", err)
	}
	blob, err := s.encrypt(aadJournal, data)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.journalPath(), blob, 0o600)
}

// readMeta decrypts <dir>/meta.enc with AAD bound to the directory name.
func (s *Store) readMeta(dirName string) (metaRecord, error) {
	var m metaRecord
	blob, err := os.ReadFile(filepath.Join(s.dir, dirName, metaName))
	if err != nil {
		return m, err
	}
	pt, err := s.decrypt(metaAAD(dirName), blob)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(pt, &m); err != nil {
		return m, fmt.Errorf("%w: meta json: %v", ErrCorrupt, err)
	}
	return m, nil
}

// writeMeta encrypts and atomically writes a job's metadata.
func (s *Store) writeMeta(jobID string, rec *Progress) error {
	dirName := s.dirName(jobID)
	data, err := json.Marshal(metaRecord{JobID: rec.JobID, Hive: rec.Hive, Total: rec.Total})
	if err != nil {
		return fmt.Errorf("spool: meta marshal: %w", err)
	}
	blob, err := s.encrypt(metaAAD(dirName), data)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, dirName, metaName), blob, 0o600)
}

// listChunks returns the sorted sequence numbers of the job's chunk files.
func (s *Store) listChunks(jobID string) ([]int, error) {
	entries, err := os.ReadDir(s.jobDir(jobID))
	if err != nil {
		return nil, err
	}
	seqs := make([]int, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if seq, ok := parseChunkName(e.Name()); ok {
			seqs = append(seqs, seq)
		}
	}
	sort.Ints(seqs)
	return seqs, nil
}

// countChunks is listChunks for callers that only need the count and treat a
// missing directory as zero.
func (s *Store) countChunks(jobID string) int {
	seqs, err := s.listChunks(jobID)
	if err != nil {
		return 0
	}
	return len(seqs)
}

// parseChunkName accepts exactly "<canonical non-negative int>.chunk" so
// aliases like "+1", "01", or "1.chunk.tmp" are never mistaken for chunks.
func parseChunkName(name string) (int, bool) {
	raw, ok := strings.CutSuffix(name, chunkSuffix)
	if !ok {
		return 0, false
	}
	seq, err := strconv.Atoi(raw)
	if err != nil || seq < 0 || strconv.Itoa(seq) != raw {
		return 0, false
	}
	return seq, true
}

// journalPath is the encrypted journal location.
func (s *Store) journalPath() string { return filepath.Join(s.dir, journalName) }

// jobDir is the directory for one job; its name is a keyed hash so it leaks no
// job identifier.
func (s *Store) jobDir(jobID string) string {
	return filepath.Join(s.dir, s.dirName(jobID))
}

// dirName is HMAC-SHA256(key, "adverse-spool-dir|"+jobID) in hex.
func (s *Store) dirName(jobID string) string {
	mac := hmac.New(sha256.New, s.key[:])
	_, _ = mac.Write([]byte("adverse-spool-dir|" + jobID))
	return hex.EncodeToString(mac.Sum(nil))
}

// chunkPath is <jobdir>/<seq>.chunk.
func (s *Store) chunkPath(jobID string, seq int) string {
	return filepath.Join(s.jobDir(jobID), strconv.Itoa(seq)+chunkSuffix)
}

// chunkAAD binds a chunk to its job, sequence, and total.
func chunkAAD(jobID string, seq, total int) string {
	return fmt.Sprintf("%s|%d|%d", jobID, seq, total)
}

// metaAAD binds a job's metadata to its hashed directory name, so meta files
// cannot be swapped between job directories.
func metaAAD(dirName string) string { return "job-meta|" + dirName }

// dedupeInts removes duplicates from an already-sorted slice in place.
func dedupeInts(xs []int) []int {
	if len(xs) < 2 {
		return xs
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// clampNext normalizes a Next bookmark: one past the highest chunk seq or
// acked seq, never negative, never past total.
func clampNext(next, maxSeq int, acked []int, total int) int {
	if maxSeq+1 > next {
		next = maxSeq + 1
	}
	for _, sq := range acked {
		if sq+1 > next {
			next = sq + 1
		}
	}
	if next < 0 {
		next = 0
	}
	if next > total {
		next = total
	}
	return next
}
