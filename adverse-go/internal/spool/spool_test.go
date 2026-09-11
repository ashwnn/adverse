package spool

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	testAgent = "agent-test"
	secretA   = 0x11
	secretB   = 0x22
)

func testSecret(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func openTest(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, testSecret(secretA), testAgent)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func putN(t *testing.T, s *Store, job, hive string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		payload := []byte(fmt.Sprintf("chunk-%s-%d", job, i))
		if err := s.Put(job, hive, i, n, payload); err != nil {
			t.Fatalf("Put(%s, %d): %v", job, i, err)
		}
	}
}

func chunkFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), chunkSuffix) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestDeriveKeyKnownAnswer pins the HKDF-SHA256 output for the spool key
// schedule so a future implementation swap cannot silently change on-disk key
// derivation.
func TestDeriveKeyKnownAnswer(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	key, err := deriveKey(secret, "agent-test")
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	const want = "f509e64a49daf7b719bcfc14e09c7949a9b3edd730741db3e5fa8ba90db8d724"
	if got := hex.EncodeToString(key[:]); got != want {
		t.Fatalf("deriveKey = %s, want %s", got, want)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)

	putN(t, s, "job1", "HIVE_ALPHA", 3)

	for i, want := range []string{"chunk-job1-0", "chunk-job1-1", "chunk-job1-2"} {
		got, err := s.Get("job1", i)
		if err != nil {
			t.Fatalf("Get(%d): %v", i, err)
		}
		if string(got) != want {
			t.Fatalf("Get(%d) = %q, want %q", i, got, want)
		}
	}

	p, err := s.Progress("job1")
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if p.JobID != "job1" || p.Hive != "HIVE_ALPHA" || p.Total != 3 || p.Next != 3 || p.Chunks != 3 {
		t.Fatalf("Progress = %+v", p)
	}
	if len(p.Acked) != 0 {
		t.Fatalf("Acked = %v, want empty", p.Acked)
	}

	jobs, err := s.Jobs()
	if err != nil {
		t.Fatalf("Jobs: %v", err)
	}
	if len(jobs) != 1 || jobs[0] != "job1" {
		t.Fatalf("Jobs = %v", jobs)
	}

	if _, err := s.Get("job1", 3); !errors.Is(err, ErrBadSeq) {
		t.Fatalf("Get(out of range) err = %v, want ErrBadSeq", err)
	}
	if _, err := s.Get("nope", 0); !errors.Is(err, ErrNoJob) {
		t.Fatalf("Get(unknown job) err = %v, want ErrNoJob", err)
	}
	if _, err := s.Progress("nope"); !errors.Is(err, ErrNoJob) {
		t.Fatalf("Progress(unknown job) err = %v, want ErrNoJob", err)
	}
}

func TestPutIsIdempotentPerSeq(t *testing.T) {
	s := openTest(t, t.TempDir())
	if err := s.Put("job", "H", 0, 2, []byte("first")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put("job", "H", 0, 2, []byte("second")); err != nil {
		t.Fatalf("re-Put: %v", err)
	}
	got, err := s.Get("job", 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("Get = %q, want second", got)
	}
	p, err := s.Progress("job")
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if p.Chunks != 1 || p.Next != 1 {
		t.Fatalf("Progress = %+v, want Chunks=1 Next=1", p)
	}
}

func TestReopenResumesProgress(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	putN(t, s, "resume", "HIVE_BRAVO", 4)

	s2 := openTest(t, dir)
	p, err := s2.Progress("resume")
	if err != nil {
		t.Fatalf("Progress after reopen: %v", err)
	}
	if p.Total != 4 || p.Next != 4 || p.Chunks != 4 || p.Hive != "HIVE_BRAVO" {
		t.Fatalf("resumed Progress = %+v", p)
	}
	if err := s2.Ack("resume", []int{0, 2}); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	s3 := openTest(t, dir)
	p, err = s3.Progress("resume")
	if err != nil {
		t.Fatalf("Progress after second reopen: %v", err)
	}
	if p.Chunks != 2 || p.Next != 4 || len(p.Acked) != 2 || p.Acked[0] != 0 || p.Acked[1] != 2 {
		t.Fatalf("Progress after ack + reopen = %+v", p)
	}
	for _, seq := range []int{1, 3} {
		if _, err := s3.Get("resume", seq); err != nil {
			t.Fatalf("Get(%d): %v", seq, err)
		}
	}
	for _, seq := range []int{0, 2} {
		if _, err := s3.Get("resume", seq); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Get(%d) err = %v, want not-exist", seq, err)
		}
	}
}

func TestWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	putN(t, s, "jobW", "HIVE_CHARLIE", 2)

	wrong, err := Open(dir, testSecret(secretB), testAgent)
	if err != nil {
		t.Fatalf("Open(wrong key): %v", err)
	}
	if _, err := wrong.Get("jobW", 0); err == nil {
		t.Fatal("Get with wrong key succeeded")
	}
	if _, err := wrong.Progress("jobW"); !errors.Is(err, ErrNoJob) {
		t.Fatalf("Progress with wrong key err = %v, want ErrNoJob", err)
	}

	// A wrong-key Open must not destroy the real store's state.
	right := openTest(t, dir)
	got, err := right.Get("jobW", 1)
	if err != nil {
		t.Fatalf("Get after wrong-key Open: %v", err)
	}
	if string(got) != "chunk-jobW-1" {
		t.Fatalf("Get = %q", got)
	}
	p, err := right.Progress("jobW")
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if p.Hive != "HIVE_CHARLIE" || p.Chunks != 2 {
		t.Fatalf("Progress = %+v", p)
	}
}

func TestTamperFails(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	if err := s.Put("tamper", "H", 0, 1, bytes.Repeat([]byte("A"), 128)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	files := chunkFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("chunk files = %v", files)
	}
	blob, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read chunk: %v", err)
	}
	blob[len(blob)-1] ^= 0xff
	if err := os.WriteFile(files[0], blob, 0o600); err != nil {
		t.Fatalf("write tampered chunk: %v", err)
	}
	if _, err := s.Get("tamper", 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get(tampered) err = %v, want ErrCorrupt", err)
	}
}

func TestJobIDValidationAndTraversal(t *testing.T) {
	s := openTest(t, t.TempDir())

	bad := []string{
		"", "..", "../evil", "a/b", `a\b`, "a.b", "a b", "a|b", "a:b", "café", strings.Repeat("x", maxJobIDLen+1),
	}
	for _, id := range bad {
		if err := s.Put(id, "h", 0, 1, []byte("x")); !errors.Is(err, ErrBadJobID) {
			t.Fatalf("Put(%q) err = %v, want ErrBadJobID", id, err)
		}
		if _, err := s.Get(id, 0); !errors.Is(err, ErrBadJobID) {
			t.Fatalf("Get(%q) err = %v, want ErrBadJobID", id, err)
		}
		if err := s.Ack(id, []int{0}); !errors.Is(err, ErrBadJobID) {
			t.Fatalf("Ack(%q) err = %v, want ErrBadJobID", id, err)
		}
		if err := s.Complete(id); !errors.Is(err, ErrBadJobID) {
			t.Fatalf("Complete(%q) err = %v, want ErrBadJobID", id, err)
		}
	}

	for _, id := range []string{"job-1", "Job_2", "ABC123"} {
		if err := s.Put(id, "h", 0, 1, []byte("x")); err != nil {
			t.Fatalf("Put(%q): %v", id, err)
		}
	}
}

func TestSizeAndSeqValidation(t *testing.T) {
	s := openTest(t, t.TempDir())

	cases := []struct {
		name   string
		seq    int
		total  int
		chunk  []byte
		wantIs error
	}{
		{"zero total", 0, 0, []byte("x"), ErrBadTotal},
		{"negative total", 0, -1, []byte("x"), ErrBadTotal},
		{"negative seq", -1, 3, []byte("x"), ErrBadSeq},
		{"seq equals total", 3, 3, []byte("x"), ErrBadSeq},
		{"seq past total", 9, 3, []byte("x"), ErrBadSeq},
		{"empty chunk", 0, 3, nil, ErrEmptyChunk},
		{"oversize chunk", 0, 3, make([]byte, MaxChunkSize+1), ErrChunkTooLarge},
	}
	for _, tc := range cases {
		err := s.Put("val", "H", tc.seq, tc.total, tc.chunk)
		if !errors.Is(err, tc.wantIs) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantIs)
		}
	}

	if err := s.Put("val", "H", 0, 3, make([]byte, MaxChunkSize)); err != nil {
		t.Fatalf("Put(exactly MaxChunkSize): %v", err)
	}
	if err := s.Put("val", "H", 1, 4, []byte("x")); !errors.Is(err, ErrTotalMismatch) {
		t.Fatalf("Put(total mismatch) err = %v, want ErrTotalMismatch", err)
	}
}

func TestAckPrunes(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	putN(t, s, "ackjob", "H", 3)

	if err := s.Ack("ackjob", []int{0, 1}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if got := len(chunkFiles(t, dir)); got != 1 {
		t.Fatalf("chunk files after Ack = %d, want 1", got)
	}
	for _, seq := range []int{0, 1} {
		if _, err := s.Get("ackjob", seq); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Get(%d) err = %v, want not-exist", seq, err)
		}
	}
	if _, err := s.Get("ackjob", 2); err != nil {
		t.Fatalf("Get(2): %v", err)
	}

	p, err := s.Progress("ackjob")
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if p.Chunks != 1 || p.Next != 3 || len(p.Acked) != 2 || p.Acked[0] != 0 || p.Acked[1] != 1 {
		t.Fatalf("Progress = %+v", p)
	}

	if err := s.Ack("ackjob", []int{1, 0, 1}); err != nil {
		t.Fatalf("re-Ack: %v", err)
	}
	p2, _ := s.Progress("ackjob")
	if p2.Chunks != 1 || len(p2.Acked) != 2 || p2.Next != 3 {
		t.Fatalf("Progress after re-Ack = %+v", p2)
	}

	if err := s.Ack("never-spooled", []int{0}); err != nil {
		t.Fatalf("Ack(unknown job): %v", err)
	}
	if err := s.Ack("ackjob", []int{-1}); !errors.Is(err, ErrBadSeq) {
		t.Fatalf("Ack(negative) err = %v, want ErrBadSeq", err)
	}

	// Re-Putting an acked seq makes it resendable and clears the ack marker.
	if err := s.Put("ackjob", "H", 0, 3, []byte("resent")); err != nil {
		t.Fatalf("re-Put acked seq: %v", err)
	}
	p3, _ := s.Progress("ackjob")
	if len(p3.Acked) != 1 || p3.Acked[0] != 1 {
		t.Fatalf("Acked after re-Put = %v, want [1]", p3.Acked)
	}
	if got, err := s.Get("ackjob", 0); err != nil || string(got) != "resent" {
		t.Fatalf("Get(0) = %q, %v", got, err)
	}
}

func TestCompleteRemoves(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	putN(t, s, "done", "H", 2)
	putN(t, s, "other", "H2", 2)

	if err := s.Complete("done"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, err := s.Progress("done"); !errors.Is(err, ErrNoJob) {
		t.Fatalf("Progress(done) err = %v, want ErrNoJob", err)
	}
	if _, err := s.Get("done", 0); !errors.Is(err, ErrNoJob) {
		t.Fatalf("Get(done) err = %v, want ErrNoJob", err)
	}
	jobs, _ := s.Jobs()
	if len(jobs) != 1 || jobs[0] != "other" {
		t.Fatalf("Jobs = %v, want [other]", jobs)
	}
	if err := s.Complete("done"); err != nil {
		t.Fatalf("idempotent Complete: %v", err)
	}
	if err := s.Complete("never-spooled"); err != nil {
		t.Fatalf("Complete(unknown): %v", err)
	}

	// The job can be spooled again from scratch.
	if err := s.Put("done", "H", 0, 1, []byte("fresh")); err != nil {
		t.Fatalf("Put after Complete: %v", err)
	}
	if got, err := s.Get("done", 0); err != nil || string(got) != "fresh" {
		t.Fatalf("Get after recreate = %q, %v", got, err)
	}
}

func TestWipeRemoves(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	putN(t, s, "j1", "H", 2)
	putN(t, s, "j2", "H", 1)

	if err := s.Wipe(); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("spool dir still present: %v", err)
	}
	jobs, err := s.Jobs()
	if err != nil || len(jobs) != 0 {
		t.Fatalf("Jobs after Wipe = %v, %v", jobs, err)
	}
	if err := s.Wipe(); err != nil {
		t.Fatalf("second Wipe: %v", err)
	}

	// The store remains usable and recreates the tree.
	if err := s.Put("j3", "H", 0, 1, []byte("back")); err != nil {
		t.Fatalf("Put after Wipe: %v", err)
	}
	if got, err := s.Get("j3", 0); err != nil || string(got) != "back" {
		t.Fatalf("Get after Wipe = %q, %v", got, err)
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	const (
		jobMarker  = "JOBMARKER7f3a"
		hiveMarker = "HIVEMARKERdeadbeef"
	)
	if err := s.Put(jobMarker, hiveMarker, 0, 1, []byte("extremely sensitive hive bytes")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(jobMarker, hiveMarker, 0, 1, []byte("rewrite")); err != nil {
		t.Fatalf("re-Put: %v", err)
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		for _, marker := range []string{jobMarker, hiveMarker, "sensitive hive bytes"} {
			if strings.Contains(path, marker) {
				t.Errorf("path %q leaks marker %q", path, marker)
			}
		}
		if d.IsDir() {
			return nil
		}
		if strings.Contains(d.Name(), ".tmp-") {
			t.Errorf("temp file %q left behind", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range []string{jobMarker, hiveMarker, "sensitive hive bytes"} {
			if bytes.Contains(data, []byte(marker)) {
				t.Errorf("file %q leaks marker %q", path, marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

func TestJournalRecovery(t *testing.T) {
	mutations := map[string]func(t *testing.T, path string){
		"deleted": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove journal: %v", err)
			}
		},
		"garbage": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("this is not authenticated ciphertext"), 0o600); err != nil {
				t.Fatalf("write garbage journal: %v", err)
			}
		},
		"truncated": func(t *testing.T, path string) {
			blob, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read journal: %v", err)
			}
			if err := os.WriteFile(path, blob[:5], 0o600); err != nil {
				t.Fatalf("truncate journal: %v", err)
			}
		},
		"bitflip": func(t *testing.T, path string) {
			blob, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read journal: %v", err)
			}
			blob[len(blob)/2] ^= 0x40
			if err := os.WriteFile(path, blob, 0o600); err != nil {
				t.Fatalf("corrupt journal: %v", err)
			}
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s := openTest(t, dir)
			putN(t, s, "recover", "HIVE_RECOVER", 3)

			mutate(t, filepath.Join(dir, journalName))

			// Must not panic and must rebuild from encrypted meta + chunks.
			r := openTest(t, dir)
			jobs, err := r.Jobs()
			if err != nil {
				t.Fatalf("Jobs: %v", err)
			}
			if len(jobs) != 1 || jobs[0] != "recover" {
				t.Fatalf("Jobs = %v, want [recover]", jobs)
			}
			p, err := r.Progress("recover")
			if err != nil {
				t.Fatalf("Progress: %v", err)
			}
			if p.Hive != "HIVE_RECOVER" || p.Total != 3 || p.Next != 3 || p.Chunks != 3 {
				t.Fatalf("recovered Progress = %+v", p)
			}
			if got, err := r.Get("recover", 2); err != nil || string(got) != "chunk-recover-2" {
				t.Fatalf("Get after rebuild = %q, %v", got, err)
			}

			// The rebuilt bookmark persists through subsequent mutations.
			if err := r.Ack("recover", []int{0}); err != nil {
				t.Fatalf("Ack after rebuild: %v", err)
			}
			r2 := openTest(t, dir)
			p2, err := r2.Progress("recover")
			if err != nil {
				t.Fatalf("Progress after re-open: %v", err)
			}
			if p2.Chunks != 2 || len(p2.Acked) != 1 || p2.Acked[0] != 0 {
				t.Fatalf("Progress after re-open = %+v", p2)
			}
		})
	}
}

func TestConcurrentPutProgress(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)

	const n = 40
	// Create the job before spawning readers so Progress/Jobs always find it;
	// the concurrency under test is the concurrent mutation afterwards.
	if err := s.Put("jobC", "H", 0, n, []byte("payload-0")); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	var wg sync.WaitGroup
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.Put("jobC", "H", i, n, []byte(fmt.Sprintf("payload-%d", i))); err != nil {
				t.Errorf("Put(%d): %v", i, err)
			}
		}(i)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 25; k++ {
				if _, err := s.Progress("jobC"); err != nil {
					t.Errorf("Progress: %v", err)
				}
				if _, err := s.Jobs(); err != nil {
					t.Errorf("Jobs: %v", err)
				}
				if _, err := s.Get("jobC", k%n); err != nil && !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("Get(%d): %v", k, err)
				}
			}
		}()
	}
	wg.Wait()

	p, err := s.Progress("jobC")
	if err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if p.Chunks != n || p.Next != n {
		t.Fatalf("Progress = %+v, want Chunks=Next=%d", p, n)
	}
	for i := 0; i < n; i++ {
		if _, err := s.Get("jobC", i); err != nil {
			t.Fatalf("Get(%d): %v", i, err)
		}
	}
}

func TestDefaultDir(t *testing.T) {
	id := "agent-" + strings.ReplaceAll(t.Name(), "/", "_")
	dir := DefaultDir(id)
	want := filepath.Join(os.TempDir(), "adverse", id, "spool")
	if dir != want {
		t.Fatalf("DefaultDir = %q, want %q", dir, want)
	}

	s, err := Open(dir, testSecret(secretA), id)
	if err != nil {
		t.Fatalf("Open(DefaultDir): %v", err)
	}
	defer s.Wipe()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir perm = %o, want 700", perm)
	}

	// Hostile agent IDs must not escape the adverse/ component.
	traversal := DefaultDir("../../etc")
	if !strings.HasPrefix(traversal, filepath.Join(os.TempDir(), "adverse")+string(os.PathSeparator)) {
		t.Fatalf("DefaultDir traversal escaped: %q", traversal)
	}
}
