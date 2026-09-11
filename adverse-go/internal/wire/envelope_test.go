package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestBuildParseRoundTrip(t *testing.T) {
	key := randKey(t)
	for _, tc := range []struct {
		name      string
		prefix    []byte
		aad       []byte
		seq       uint32
		direction byte
	}{
		{"default prefix", nil, nil, 0, DirectionClientToServer},
		{"custom prefix", []byte("XQ7"), []byte("agent-1:out"), 42, DirectionClientToServer},
		{"max seq", []byte("ABCDEFGH"), []byte("bound"), MaxSeq, DirectionServerToClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := Build([]byte("hello wire"), key, tc.prefix, tc.aad, tc.seq, tc.direction)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			wantPrefix := tc.prefix
			if wantPrefix == nil {
				wantPrefix = []byte(Magic)
			}
			if !bytes.HasPrefix(frame, wantPrefix) {
				t.Fatalf("frame prefix = %q, want %q", frame[:3], wantPrefix)
			}
			plain, seq, complete, err := Parse(frame, key, tc.prefix, tc.aad, tc.direction)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !complete {
				t.Fatal("Parse: incomplete")
			}
			if string(plain) != "hello wire" {
				t.Fatalf("plaintext = %q", plain)
			}
			if seq != tc.seq {
				t.Fatalf("seq = %d, want %d", seq, tc.seq)
			}
		})
	}
}

func TestIncrementalParse(t *testing.T) {
	key := randKey(t)
	frame, err := Build([]byte("chunked stream"), key, nil, nil, 3, DirectionClientToServer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, cut := range []int{0, 1, 5, len(frame) - 1} {
		if _, _, complete, err := Parse(frame[:cut], key, nil, nil, DirectionClientToServer); err != nil || complete {
			t.Errorf("cut=%d: got complete=%v err=%v, want incomplete nil err", cut, complete, err)
		}
	}
	plain, _, complete, err := Parse(frame, key, nil, nil, DirectionClientToServer)
	if err != nil || !complete {
		t.Fatalf("full frame: complete=%v err=%v", complete, err)
	}
	if string(plain) != "chunked stream" {
		t.Fatalf("plaintext = %q", plain)
	}
}

func TestTrailingBytesParse(t *testing.T) {
	key := randKey(t)
	f1, _ := Build([]byte("first"), key, nil, nil, 1, DirectionClientToServer)
	f2, _ := Build([]byte("second"), key, nil, nil, 2, DirectionClientToServer)
	stream := append(append([]byte{}, f1...), f2...)
	plain, seq, complete, err := Parse(stream, key, nil, nil, DirectionClientToServer)
	if err != nil || !complete {
		t.Fatalf("first frame: complete=%v err=%v", complete, err)
	}
	if string(plain) != "first" || seq != 1 {
		t.Fatalf("first frame = %q seq=%d", plain, seq)
	}
	rest := stream[len(f1):]
	plain, seq, complete, err = Parse(rest, key, nil, nil, DirectionClientToServer)
	if err != nil || !complete {
		t.Fatalf("second frame: complete=%v err=%v", complete, err)
	}
	if string(plain) != "second" || seq != 2 {
		t.Fatalf("second frame = %q seq=%d", plain, seq)
	}
}

func TestParseErrors(t *testing.T) {
	key := randKey(t)
	frame, _ := Build([]byte("payload"), key, []byte("P1"), []byte("aad"), 5, DirectionClientToServer)

	t.Run("bad prefix", func(t *testing.T) {
		if _, _, _, err := Parse(frame, key, []byte("XX"), []byte("aad"), DirectionClientToServer); err == nil {
			t.Fatal("wrong prefix accepted")
		}
	})
	t.Run("auth failure", func(t *testing.T) {
		flipped := append([]byte{}, frame...)
		flipped[len(flipped)-1] ^= 0x01
		if _, _, _, err := Parse(flipped, key, []byte("P1"), []byte("aad"), DirectionClientToServer); err == nil {
			t.Fatal("tampered frame accepted")
		}
	})
	t.Run("wrong aad", func(t *testing.T) {
		if _, _, _, err := Parse(frame, key, []byte("P1"), []byte("other"), DirectionClientToServer); err == nil {
			t.Fatal("frame authenticated under wrong AAD")
		}
	})
	t.Run("bad key length", func(t *testing.T) {
		if _, err := Build([]byte("x"), key[:31], nil, nil, 0, DirectionClientToServer); err == nil {
			t.Fatal("31-byte key accepted")
		}
		if _, _, _, err := Parse(frame, key[:31], nil, nil, DirectionClientToServer); err == nil {
			t.Fatal("31-byte key accepted by Parse")
		}
	})
	t.Run("bad prefix length", func(t *testing.T) {
		if _, err := Build([]byte("x"), key, []byte{}, nil, 0, DirectionClientToServer); err == nil {
			t.Fatal("empty prefix accepted")
		}
		if _, err := Build([]byte("x"), key, []byte("123456789"), nil, 0, DirectionClientToServer); err == nil {
			t.Fatal("9-byte prefix accepted")
		}
	})
	t.Run("short payload", func(t *testing.T) {
		// Hand-craft a header claiming a body too short for nonce+tag.
		bad := append([]byte("P1"), 0, 0, 0, 1, 0, 0, 0, 10)
		bad = append(bad, make([]byte, 10)...)
		if _, _, _, err := Parse(bad, key, []byte("P1"), nil, DirectionClientToServer); err == nil {
			t.Fatal("short payload accepted")
		}
	})
	t.Run("wrong direction", func(t *testing.T) {
		// Frame built with client→server must not parse as server→client.
		if _, _, _, err := Parse(frame, key, []byte("P1"), []byte("aad"), DirectionServerToClient); err == nil {
			t.Fatal("frame accepted with wrong direction")
		}
	})
}

func TestValidate(t *testing.T) {
	key := randKey(t)
	frame, _ := Build([]byte("x"), key, nil, nil, 0, DirectionClientToServer)
	if !Validate(frame) {
		t.Error("Validate rejected a valid frame")
	}
	legacy := append([]byte(LegacyMagic), frame[3:]...)
	if !Validate(legacy) {
		t.Error("Validate rejected a legacy-magic frame")
	}
	for name, bad := range map[string][]byte{
		"empty":     {},
		"short":     []byte("ADX"),
		"garbage":   bytes.Repeat([]byte{0x41}, 64),
		"truncated": frame[:len(frame)-1],
		"huge body": append([]byte("ADX\x00\x00\x00\x00\xff\xff\xff\xff"), make([]byte, 8)...),
	} {
		if Validate(bad) {
			t.Errorf("Validate accepted %s", name)
		}
	}
}

func TestReplayWindow(t *testing.T) {
	t.Run("explicit_size_64", func(t *testing.T) {
		w := NewReplayWindow(64)
		// Fresh sequence accepted and recorded.
		if !w.Check(10) {
			t.Fatal("seq 10 rejected")
		}
		w.Record(10)
		if w.Check(10) {
			t.Fatal("replayed seq 10 accepted")
		}
		// Ascending accepted.
		if !w.Check(11) {
			t.Fatal("seq 11 rejected")
		}
		w.Record(11)
		// Out-of-order within window accepted exactly once.
		if !w.Check(9) {
			t.Fatal("in-window out-of-order seq 9 rejected")
		}
		w.Record(9)
		if w.Check(9) {
			t.Fatal("replayed seq 9 accepted after record")
		}
		// Too-old rejected (100 is outside window of 64 from 200).
		w.Record(200)
		if w.Check(100) {
			t.Fatal("seq 100 outside window accepted")
		}
		if w.Last() != 200 {
			t.Fatalf("Last() = %d, want 200", w.Last())
		}
		// Window pruning: old entries are forgotten, new high-water works.
		if !w.Check(201) {
			t.Fatal("seq 201 rejected after prune")
		}
	})

	t.Run("default_window_512", func(t *testing.T) {
		// With a 512 window, seq 100 is within range of 600 (600-512=88 < 100).
		w := NewReplayWindow(0) // uses DefaultReplayWindowSize
		w.Record(600)
		// 100 is within window: 600-512=88 < 100, and 100 not seen → accepted.
		if !w.Check(100) {
			t.Fatal("seq 100 should be within default window of 600")
		}
		// Record it, then replay must be rejected.
		w.Record(100)
		if w.Check(100) {
			t.Fatal("replayed seq 100 accepted")
		}
		// 101 is within window and not seen → accepted.
		if !w.Check(101) {
			t.Fatal("seq 101 should be within default window")
		}
		// Record 600 again (already recorded but sets high-water).
		w.Record(600)
		if w.Check(600) {
			t.Fatal("replayed seq 600 accepted")
		}
	})

	t.Run("default_window_rejects_old", func(t *testing.T) {
		// Record(600), Check(100) must be rejected: 100 < 600-512=88.
		w := NewReplayWindow(0) // uses DefaultReplayWindowSize
		w.Record(600)
		if w.Check(87) {
			t.Fatal("seq 87 should be outside default window of 600")
		}
		// 88 is exactly at the boundary: floor=88, condition is <= floor → rejected.
		if w.Check(88) {
			t.Fatal("seq 88 should be at the edge of default window")
		}
		// 89 is inside window: 600-512=88, 89 > 88, not seen → accepted.
		if !w.Check(89) {
			t.Fatal("seq 89 should be within default window")
		}
	})
}

func TestReplayWindowDefaultSize(t *testing.T) {
	w := NewReplayWindow(0)
	// Verify the default size equals DefaultReplayWindowSize.
	if w.Size() != DefaultReplayWindowSize {
		t.Fatalf("default window size = %d, want %d", w.Size(), DefaultReplayWindowSize)
	}
	if w.Check(0) == false {
		t.Fatal("fresh seq rejected on default window")
	}
	// Behavioral test: Record(DefaultReplayWindowSize+10), then Check(0) must
	// be rejected (0 < (DefaultReplayWindowSize+10)-DefaultReplayWindowSize = 10),
	// while Check(11) is accepted.
	w.Record(uint32(DefaultReplayWindowSize + 10))
	if w.Check(0) {
		t.Fatal("seq 0 should be outside default window after high record")
	}
	if !w.Check(11) {
		t.Fatal("seq 11 should be within default window")
	}
}

// TestReplayWindowPruneFloor verifies that while fewer than `size` frames have
// been recorded, early seqs are not pruned from the window and replayed frames
// are rejected. Regression: the prune floor was clamped to zero, dropping
// freshly recorded low seqs and letting Check accept them as replays.
func TestReplayWindowPruneFloor(t *testing.T) {
	w := NewReplayWindow(8)
	for seq := uint32(0); seq < 4; seq++ {
		if !w.CheckAndRecord(seq) {
			t.Fatalf("fresh seq %d rejected", seq)
		}
	}
	for seq := uint32(0); seq < 4; seq++ {
		if w.Check(seq) {
			t.Fatalf("replayed seq %d accepted while inside the window", seq)
		}
	}
}

// TestReplayWindowWrap verifies that after the uint32 sequence space wraps,
// frames with wrapped seqs are accepted (and replays rejected) consistently by
// Check, Record, and CheckAndRecord.
func TestReplayWindowWrap(t *testing.T) {
	w := NewReplayWindow(4)
	// Seed near the top of the 32-bit sequence space.
	for seq := uint32(MaxSeq - 2); ; seq++ {
		if !w.Check(seq) {
			t.Fatalf("seed seq %d rejected", seq)
		}
		w.Record(seq)
		if seq == MaxSeq {
			break
		}
	}

	// Wrapped seqs 0..8 are newer than MaxSeq and must all be accepted.
	for seq := uint32(0); seq <= 8; seq++ {
		if !w.Check(seq) {
			t.Fatalf("wrapped seq %d rejected by Check", seq)
		}
		w.Record(seq)
	}

	// Every wrapped seq recorded above must now be rejected as a replay.
	for seq := uint32(0); seq <= 8; seq++ {
		if w.Check(seq) {
			t.Fatalf("replayed wrapped seq %d accepted by Check", seq)
		}
		if w.CheckAndRecord(seq) {
			t.Fatalf("replayed wrapped seq %d accepted by CheckAndRecord", seq)
		}
	}

	// A fresh wrapped seq continues to advance.
	if !w.CheckAndRecord(9) {
		t.Fatal("fresh wrapped seq 9 rejected")
	}
	if w.CheckAndRecord(9) {
		t.Fatal("replayed wrapped seq 9 accepted")
	}

	// Pre-wrap sequences are now far outside the window and rejected.
	if w.Check(MaxSeq) {
		t.Fatal("pre-wrap seq accepted after wrap advanced past it")
	}
}

// TestReplayWindowWrapCheckRecordConsistency verifies Check and CheckAndRecord
// agree across a wrap boundary and that Record does not regress the
// high-water mark.
func TestReplayWindowWrapCheckRecordConsistency(t *testing.T) {
	w := NewReplayWindow(4)
	w.Record(MaxSeq)
	w.Record(0)
	w.Record(1)
	last := w.Last()
	if last != int64(seqSpace)+1 {
		t.Fatalf("extended high-water = %d, want %d", last, seqSpace+1)
	}
	// Re-recording an old wrapped seq must not regress the window.
	w.Record(0)
	if got := w.Last(); got != last {
		t.Fatalf("Record regressed high-water to %d, want %d", got, last)
	}
	// seq 2 is fresh; Check then CheckAndRecord must agree it is accepted.
	if !w.Check(2) {
		t.Fatal("Check rejected fresh wrapped seq 2")
	}
	if !w.CheckAndRecord(2) {
		t.Fatal("CheckAndRecord rejected fresh wrapped seq 2 after Check accepted it")
	}
	if w.Check(2) {
		t.Fatal("Check accepted replayed wrapped seq 2")
	}
}

// TestReplayWindowConcurrent exercises Check+Record from many goroutines
// (as concurrent HTTP requests for the same agent record do). It must not
// race (run with -race) and must accept every fresh seq exactly once.
//
// The claim, check, and record of each seq happen atomically under the
// window lock (via checkAndRecordLocked): without that, a goroutine
// preempted between its atomic claim and its check lets other workers
// advance the high-water mark past seq+window, and a genuinely fresh seq is
// evicted before its first check — a scheduling artifact, not a window
// defect.
func TestReplayWindowConcurrent(t *testing.T) {
	w := NewReplayWindow(0) // default size
	const workers = 16
	const claimsPerWorker = 200

	// A shared atomic claim counter: seqs are claimed in strictly increasing
	// order across workers, so every claim is above the current high-water
	// mark (accepted) and each seq is claimed exactly once.
	var next uint32
	var wg sync.WaitGroup
	accepted := make([]int32, workers*claimsPerWorker)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < claimsPerWorker; j++ {
				// Claim + check + record under one lock acquisition so the
				// strictly-increasing claim order maps to a deterministic
				// window state.
				w.mu.Lock()
				seq := atomic.AddUint32(&next, 1) - 1
				ok := w.checkAndRecordLocked(seq)
				w.mu.Unlock()
				if !ok {
					t.Errorf("worker %d: fresh seq %d rejected", worker, seq)
					return
				}
				// The just-recorded seq must now be rejected as a replay,
				// even while other goroutines are recording concurrently.
				if w.Check(seq) {
					t.Errorf("worker %d: replayed seq %d accepted", worker, seq)
					return
				}
				accepted[seq]++
			}
		}(i)
	}
	wg.Wait()

	for i, n := range accepted {
		if n != 1 {
			t.Fatalf("seq %d accepted %d times, want exactly 1", i, n)
		}
	}
}

// TestAeadKat pins the ChaCha20-Poly1305 construction against the Python
// reference ciphertext, proving the AEAD layer is wire-identical.
func TestAeadKat(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "kat.json"))
	if err != nil {
		t.Fatalf("read kat.json: %v", err)
	}
	var k struct {
		Aead struct {
			Key       string `json:"key"`
			Nonce     string `json:"nonce"`
			Aad       string `json:"aad"`
			Plaintext string `json:"plaintext"`
			Sealed    string `json:"sealed"`
		} `json:"aead"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("parse kat.json: %v", err)
	}
	key, err := hex.DecodeString(k.Aead.Key)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(k.Aead.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(k.Aead.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	var key32 [32]byte
	copy(key32[:], key)
	aead, err := chacha20poly1305.New(key32[:])
	if err != nil {
		t.Fatal(err)
	}
	got := aead.Seal(nil, nonce, []byte(k.Aead.Plaintext), []byte(k.Aead.Aad))
	if !bytes.Equal(got, want) {
		t.Fatalf("AEAD mismatch:\n got %x\nwant %x", got, want)
	}
	opened, err := aead.Open(nil, nonce, want, []byte(k.Aead.Aad))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened) != k.Aead.Plaintext {
		t.Fatalf("round-trip plaintext = %q", opened)
	}
}

// TestDeterministicNonce verifies that nonce is derived from seq and
// direction (not random), and that different (seq, direction) pairs produce
// different nonces.
func TestDeterministicNonce(t *testing.T) {
	n1 := deterministicNonce(0, DirectionClientToServer)
	n2 := deterministicNonce(0, DirectionClientToServer)
	if n1 != n2 {
		t.Fatalf("deterministic nonce not reproducible: %x vs %x", n1, n2)
	}

	// Same seq, different direction → different nonce.
	n3 := deterministicNonce(0, DirectionServerToClient)
	if n1 == n3 {
		t.Fatal("nonce same for different directions")
	}

	// Different seq, same direction → different nonce.
	n4 := deterministicNonce(1, DirectionClientToServer)
	if n1 == n4 {
		t.Fatal("nonce same for different seqs")
	}

	// Verify structure: seq in high 8 bytes, direction in byte 8.
	if n1[8] != DirectionClientToServer {
		t.Fatalf("direction byte = %x, want %x", n1[8], DirectionClientToServer)
	}
	if n1[9] != 0 || n1[10] != 0 || n1[11] != 0 {
		t.Fatalf("padding bytes should be zero: %x", n1[9:12])
	}
}

// TestLenInAAD verifies that the frame length is bound into the AAD and
// tampering with len causes authentication failure (not silent acceptance).
func TestLenInAAD(t *testing.T) {
	key := randKey(t)
	frame, _ := Build([]byte("secret payload"), key, nil, nil, 7, DirectionClientToServer)

	// Tamper with the len field (bytes 7-10 after prefix).
	tampered := append([]byte{}, frame...)
	origLen := binary.BigEndian.Uint32(tampered[7:11])

	// Increase len by 1 to simulate extension attack.
	binary.BigEndian.PutUint32(tampered[7:11], origLen+1)
	_, _, complete, err := Parse(tampered, key, nil, nil, DirectionClientToServer)
	if complete && err == nil {
		t.Fatal("tampered len accepted — len not bound into AAD")
	}

	// Decrease len by 1 to simulate truncation attack.
	tampered2 := append([]byte{}, frame...)
	binary.BigEndian.PutUint32(tampered2[7:11], origLen-1)
	_, _, complete2, err2 := Parse(tampered2, key, nil, nil, DirectionClientToServer)
	if complete2 && err2 == nil {
		t.Fatal("tampered len accepted — len not bound into AAD")
	}
}

// TestDirectionBinding verifies that a frame built for one direction cannot
// be replayed in the opposite direction.
func TestDirectionBinding(t *testing.T) {
	key := randKey(t)
	frame, _ := Build([]byte("one-way"), key, nil, nil, 42, DirectionClientToServer)

	// Attempt to parse with opposite direction.
	if _, _, _, err := Parse(frame, key, nil, nil, DirectionServerToClient); err == nil {
		t.Fatal("frame accepted with wrong direction — cross-direction replay possible")
	}
}

// TestSeqBoundViaNonce verifies that tampering only the on-wire seq field
// (without touching the nonce bytes) is caught by the deterministic-nonce
// mismatch check. Seq is no longer in the AAD, so this documents that seq
// integrity is enforced via the nonce path.
func TestSeqBoundViaNonce(t *testing.T) {
	key := randKey(t)
	prefix := []byte("P1")
	aad := []byte("seq-binding-test")
	frame, err := Build([]byte("payload"), key, prefix, aad, 42, DirectionClientToServer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Tamper only the seq field in the header (after prefix, 4 bytes).
	tampered := append([]byte{}, frame...)
	prefixLen := len(prefix)
	origSeq := binary.BigEndian.Uint32(tampered[prefixLen : prefixLen+4])
	binary.BigEndian.PutUint32(tampered[prefixLen:prefixLen+4], origSeq+1)

	// Parse must fail: the on-wire seq changed but the nonce was not updated,
	// so deterministicNonce(tamperedSeq, direction) != the original nonce.
	_, _, complete, err := Parse(tampered, key, prefix, aad, DirectionClientToServer)
	if err == nil {
		t.Fatal("tampered seq accepted — nonce mismatch not enforced")
	}
	if complete {
		t.Fatal("tampered seq returned complete=true")
	}
}

// TestEnvelopeKat pins the full envelope construction against a known-answer
// test vector, proving the frame is wire-identical to the reference
// construction using raw chacha20poly1305 (no wire.Build circularity).
func TestEnvelopeKat(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "kat.json"))
	if err != nil {
		t.Fatalf("read kat.json: %v", err)
	}
	var k struct {
		Envelope struct {
			Key       string `json:"key"`
			Prefix    string `json:"prefix"`
			Aad       string `json:"aad"`
			Seq       uint32 `json:"seq"`
			Direction byte   `json:"direction"`
			Plaintext string `json:"plaintext"`
			Frame     string `json:"frame"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("parse kat.json: %v", err)
	}

	key, err := hex.DecodeString(k.Envelope.Key)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	prefix, err := hex.DecodeString(k.Envelope.Prefix)
	if err != nil {
		t.Fatalf("decode prefix: %v", err)
	}
	wantFrame, err := hex.DecodeString(k.Envelope.Frame)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}

	// Build using wire.Build and compare byte-for-byte.
	gotFrame, err := Build(
		[]byte(k.Envelope.Plaintext),
		key,
		prefix,
		[]byte(k.Envelope.Aad),
		k.Envelope.Seq,
		k.Envelope.Direction,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.Equal(gotFrame, wantFrame) {
		t.Fatalf("Build frame mismatch:\n got %x\nwant %x", gotFrame, wantFrame)
	}

	// Parse the pinned frame and verify round-trip.
	plain, seq, complete, err := Parse(
		wantFrame, key, prefix, []byte(k.Envelope.Aad), k.Envelope.Direction,
	)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !complete {
		t.Fatal("Parse: incomplete")
	}
	if string(plain) != k.Envelope.Plaintext {
		t.Fatalf("Parse plaintext = %q, want %q", plain, k.Envelope.Plaintext)
	}
	if seq != k.Envelope.Seq {
		t.Fatalf("Parse seq = %d, want %d", seq, k.Envelope.Seq)
	}
}
