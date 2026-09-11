package registrywin

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestChunkRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"small", []byte{0x01, 0x02, 0x03, 0x04}},
		{"128KB", make([]byte, 128*1024)},
		{"boundary-11", make([]byte, 11)},
		{"boundary-12", make([]byte, 12)},
		{"boundary-13", make([]byte, 13)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := &Chunk{
				Seq:          42,
				HiveName:     "SYSTEM",
				RegistryPath: "SYSTEM",
				Data:         tt.data,
			}

			serialized := original.Serialize()
			if len(serialized) == 0 {
				t.Fatal("serialization produced empty result")
			}

			restored, err := Deserialize(serialized)
			if err != nil {
				t.Fatalf("deserialize failed: %v", err)
			}

			if restored.Seq != original.Seq {
				t.Errorf("seq mismatch: %d != %d", restored.Seq, original.Seq)
			}
			if restored.HiveName != original.HiveName {
				t.Errorf("hive mismatch: %q != %q", restored.HiveName, original.HiveName)
			}
			if restored.RegistryPath != original.RegistryPath {
				t.Errorf("path mismatch: %q != %q", restored.RegistryPath, original.RegistryPath)
			}
			if !bytes.Equal(restored.Data, original.Data) {
				t.Errorf("data mismatch (len %d != %d)", len(restored.Data), len(original.Data))
			}
		})
	}
}

func TestChunk128KB(t *testing.T) {
	data := make([]byte, 128*1024)
	rand.Read(data)

	original := &Chunk{
		Seq:          0,
		HiveName:     "SYSTEM",
		RegistryPath: "SYSTEM",
		Data:         data,
	}

	serialized := original.Serialize()
	restored, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("deserialize 128KB chunk: %v", err)
	}

	if !bytes.Equal(restored.Data, data) {
		t.Error("128KB data mismatch")
	}
}

func TestDeserializeRejectsTooShort(t *testing.T) {
	_, err := Deserialize([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for short data")
	}
	_, err = Deserialize(make([]byte, 11))
	if err == nil {
		t.Error("expected error for 11 bytes")
	}
	_, err = Deserialize(nil)
	if err == nil {
		t.Error("expected error for nil data")
	}
}

func TestDeserializeRejectsTruncated(t *testing.T) {
	// Header says 100 bytes of data but only 20 provided
	header := make([]byte, 12)
	// seq=0
	// hiveLen=4, pathLen=4, dataLen=100
	header[4] = 0
	header[5] = 4
	header[6] = 0
	header[7] = 4
	header[8] = 0
	header[9] = 0
	header[10] = 0
	header[11] = 100
	// Add hive + path bytes (8 total)
	header = append(header, "hive"...)
	header = append(header, "path"...)
	// Only 12 bytes of data (not 100)
	header = append(header, make([]byte, 12)...)

	_, err := Deserialize(header)
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestBuildResultPayload(t *testing.T) {
	raw := []byte("test chunk data")
	payload := BuildResultPayload("job-123", "SYSTEM", 0, 3, raw)
	if payload == "" {
		t.Fatal("empty payload")
	}
	// Check it contains expected fields
	for _, field := range []string{"job-123", "SYSTEM", "sha256", "data_b64"} {
		if !bytes.Contains([]byte(payload), []byte(field)) {
			t.Errorf("payload missing field %q", field)
		}
	}
}

// jobID with quotes/backslashes produces valid JSON that unmarshals to identical fields.
func TestBuildResultPayloadSpecialChars(t *testing.T) {
	raw := []byte("test data for special chars")
	jobID := `job"with\backslashes`
	hive := `HIVE"VAL`

	payload := BuildResultPayload(jobID, hive, 5, 10, raw)
	if payload == "" {
		t.Fatal("empty payload")
	}

	// Must be valid JSON.
	var rp ResultPayload
	if err := json.Unmarshal([]byte(payload), &rp); err != nil {
		t.Fatalf("invalid JSON: %v\npayload: %s", err, payload)
	}

	// Fields must round-trip exactly.
	if rp.JobID != jobID {
		t.Errorf("jobID mismatch: got %q, want %q", rp.JobID, jobID)
	}
	if rp.Hive != hive {
		t.Errorf("hive mismatch: got %q, want %q", rp.Hive, hive)
	}
	if rp.Seq != 5 {
		t.Errorf("seq mismatch: got %d, want 5", rp.Seq)
	}
	if rp.Total != 10 {
		t.Errorf("total mismatch: got %d, want 10", rp.Total)
	}
	if rp.SHA256 == "" {
		t.Error("empty sha256")
	}
	if rp.DataB64 == "" {
		t.Error("empty data_b64")
	}

	// No unescaped quotes in the raw JSON string for job_id/hive fields.
	// json.Marshal escapes " to \", which is valid JSON.
	if strings.Contains(payload, `"job_id":"job`) && !strings.Contains(payload, `"job_id":"job\\"`) {
		// Just verify the JSON is well-formed by re-marshaling.
		b, _ := json.Marshal(rp)
		if string(b) == "" {
			t.Error("re-marshal produced empty output")
		}
	}
}

func TestSyntheticInvariant(t *testing.T) {
	extractor := NewExtractor(ExtractorConfig{
		Hives:     []string{"SYSTEM"},
		ChunkSize: 1024,
	}, "CANARY-test")

	data, err := extractor.ExtractHive("SYSTEM")
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	// Must have regf magic
	if string(data[:4]) != "regf" {
		t.Errorf("expected regf, got %q", data[:4])
	}
	// Must contain CANARY marker
	if !bytes.Contains(data, []byte("CANARY-test")) {
		t.Error("missing CANARY marker")
	}
}

func TestRealModeOnLinuxReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows error path only")
	}
	extractor := NewExtractor(ExtractorConfig{
		Hives:     []string{"SYSTEM"},
		ChunkSize: 1024,
		RealMode:  true,
	}, "CANARY")

	_, err := extractor.ExtractHive("SYSTEM")
	// On non-Windows, real mode must return a clear error naming the host OS.
	if err == nil {
		t.Fatalf("expected error for real mode on %s", runtime.GOOS)
	}
	if !strings.Contains(err.Error(), runtime.GOOS) {
		t.Errorf("error should name runtime.GOOS %q, got %q", runtime.GOOS, err.Error())
	}
}

func TestExtractChunksRejectsNonPositiveChunkSize(t *testing.T) {
	extractor := NewExtractor(ExtractorConfig{
		Hives: []string{"SYSTEM"},
	}, "CANARY")

	for _, chunkSize := range []int{0, -1, -1024} {
		chunks, err := extractor.ExtractChunks([]string{"SYSTEM"}, chunkSize)
		if err == nil {
			t.Errorf("chunkSize=%d: expected error, got %d chunks", chunkSize, len(chunks))
		}
		if chunks != nil {
			t.Errorf("chunkSize=%d: expected nil chunks on error", chunkSize)
		}
	}
}

func TestExtractChunks(t *testing.T) {
	extractor := NewExtractor(ExtractorConfig{
		Hives:     []string{"SYSTEM"},
		ChunkSize: 64,
	}, "CANARY")

	chunks, err := extractor.ExtractChunks([]string{"SYSTEM"}, 64)
	if err != nil {
		t.Fatalf("extract chunks: %v", err)
	}

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	for i, c := range chunks {
		if c.Seq != uint32(i) {
			t.Errorf("chunk %d: seq %d != %d", i, c.Seq, i)
		}
		if len(c.Data) == 0 {
			t.Errorf("chunk %d: empty data", i)
		}
	}
}

func TestGetExtracted(t *testing.T) {
	extractor := NewExtractor(ExtractorConfig{
		Hives:     []string{"SYSTEM", "SAM"},
		ChunkSize: 1024,
	}, "CANARY")

	extracted := extractor.GetExtracted()
	if len(extracted) != 0 {
		t.Error("expected no extracted data initially")
	}

	extractor.ExtractHive("SYSTEM")
	extracted = extractor.GetExtracted()
	if len(extracted) != 1 {
		t.Errorf("expected 1 extracted hive, got %d", len(extracted))
	}
}

func TestChunkWireFormatBytes(t *testing.T) {
	// Verify exact byte layout
	c := &Chunk{
		Seq:          0x01020304,
		HiveName:     "AB",
		RegistryPath: "CD",
		Data:         []byte{0xDE, 0xAD},
	}
	buf := c.Serialize()

	// u32 seq BE = 01 02 03 04
	if buf[0] != 0x01 || buf[1] != 0x02 || buf[2] != 0x03 || buf[3] != 0x04 {
		t.Errorf("seq bytes: %X", buf[0:4])
	}
	// u16 hiveLen BE = 00 02
	if buf[4] != 0x00 || buf[5] != 0x02 {
		t.Errorf("hiveLen: %X", buf[4:6])
	}
	// u16 pathLen BE = 00 02
	if buf[6] != 0x00 || buf[7] != 0x02 {
		t.Errorf("pathLen: %X", buf[6:8])
	}
	// u32 dataLen BE = 00 00 00 02
	if buf[8] != 0x00 || buf[9] != 0x00 || buf[10] != 0x00 || buf[11] != 0x02 {
		t.Errorf("dataLen: %X", buf[8:12])
	}
	// hive "AB"
	if string(buf[12:14]) != "AB" {
		t.Errorf("hive: %q", buf[12:14])
	}
	// path "CD"
	if string(buf[14:16]) != "CD" {
		t.Errorf("path: %q", buf[14:16])
	}
	// data
	if buf[16] != 0xDE || buf[17] != 0xAD {
		t.Errorf("data: %X", buf[16:18])
	}
}

func TestGenerateTempNTPath(t *testing.T) {
	path := GenerateTempNTPath("C:\\Users\\test\\AppData\\Local\\Temp")
	if path == "" {
		t.Fatal("empty path")
	}
	if path[:4] != "\\??\\" {
		t.Errorf("NT path must start with \\??\\, got prefix %q", path[:4])
	}
	if path[len(path)-4:] != ".tmp" {
		t.Errorf("path must end with .tmp, got %q", path[len(path)-4:])
	}
	if !bytes.Contains([]byte(path), []byte("~AD")) {
		t.Errorf("path must contain ~AD prefix, got %q", path)
	}

	p1 := GenerateTempNTPath("C:\\Temp")
	p2 := GenerateTempNTPath("C:\\Temp")
	if p1 == p2 {
		t.Error("two calls should produce different paths")
	}
}

func TestGenerateTempGoPath(t *testing.T) {
	path := GenerateTempGoPath("/tmp")
	if path == "" {
		t.Fatal("empty path")
	}
	if path[len(path)-4:] != ".tmp" {
		t.Errorf("path must end with .tmp, got %q", path)
	}
	if !bytes.Contains([]byte(path), []byte("~AD")) {
		t.Errorf("path must contain ~AD prefix, got %q", path)
	}
}

func TestValidateRegfHeader(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"valid", []byte("regf\x00\x01\x02\x03"), false},
		{"valid_min", []byte("regf"), false},
		{"bad_magic", []byte("XXXX"), true},
		{"too_short", []byte("re"), true},
		{"empty", []byte{}, true},
		{"nil", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegfHeader(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRegfHeader() error=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
