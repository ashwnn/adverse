package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestAlignUp is a pure unit test for the alignUp helper.
func TestAlignUp(t *testing.T) {
	tests := []struct {
		v, align, want int
	}{
		{0, 512, 0},
		{1, 512, 512},
		{511, 512, 512},
		{512, 512, 512},
		{513, 512, 1024},
		{1024, 512, 1024},
		{40, 512, 512},
		{80, 512, 512},
		{513, 1024, 1024},
		{1025, 1024, 2048},
		{0, 4096, 0},
		{1, 4096, 4096},
		{4096, 4096, 4096},
		{4097, 4096, 8192},
	}
	for _, tc := range tests {
		got := alignUp(tc.v, tc.align)
		if got != tc.want {
			t.Errorf("alignUp(%d, %d) = %d, want %d", tc.v, tc.align, got, tc.want)
		}
	}
}

// buildTrivialBinary compiles a trivial Go program for the given GOOS/GOARCH
// and returns the path to the output binary. Returns ("", error) on failure.
func buildTrivialBinary(t *testing.T, goos, goarch string) (string, error) {
	t.Helper()
	tmpDir := t.TempDir()

	// Write a trivial Go program.
	mainGo := filepath.Join(tmpDir, "main.go")
	src := []byte("package main\n\nfunc main() { println(\"hello\") }\n")
	if err := os.WriteFile(mainGo, src, 0644); err != nil {
		return "", err
	}

	outBin := filepath.Join(tmpDir, "test.exe")
	if goos == "linux" {
		outBin = filepath.Join(tmpDir, "test")
	}

	cmd := exec.Command("go", "build", "-o", outBin, "-ldflags=-s -w", mainGo)
	cmd.Dir = tmpDir

	// Inherit the current environment, then override GOOS/GOARCH.
	env := os.Environ()
	env = append(env, "GOOS="+goos, "GOARCH="+goarch)
	cmd.Env = env

	if _, err := cmd.CombinedOutput(); err != nil {
		return "", err
	}
	return outBin, nil
}

// TestPESections cross-builds a trivial Windows amd64 PE, adds sections, and
// verifies the output with debug/pe.
func TestPESections(t *testing.T) {
	exePath, err := buildTrivialBinary(t, "windows", "amd64")
	if err != nil {
		t.Skipf("cross-compile unavailable (GOOS=windows GOARCH=amd64): %v", err)
	}

	input, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	t.Logf("input PE size: %d bytes", len(input))

	// Parse original PE to get baseline section count and raw data.
	origPE, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("debug/pe cannot parse original: %v", err)
	}
	origNumSections := len(origPE.Sections)
	t.Logf("original section count: %d", origNumSections)

	// Save original section raw data for comparison.
	type secData struct {
		name string
		data []byte
	}
	origSections := make([]secData, origNumSections)
	for i, sec := range origPE.Sections {
		raw, err := sec.Data()
		if err != nil {
			t.Fatalf("original section %d (%s) Data(): %v", i, sec.Name, err)
		}
		origSections[i] = secData{name: sec.Name, data: raw}
	}

	// Add 1 PE section with 2 MiB of random data.
	output, err := applyPESections(input, 1, 2*1024*1024)
	if err != nil {
		t.Fatalf("applyPESections failed: %v", err)
	}
	t.Logf("output PE size: %d bytes (+%d)", len(output), len(output)-len(input))

	// The output must be larger.
	if len(output) <= len(input) {
		t.Fatalf("output not larger: in=%d out=%d", len(input), len(output))
	}

	// Parse output PE.
	outPE, err := pe.NewFile(bytes.NewReader(output))
	if err != nil {
		t.Fatalf("debug/pe cannot parse output: %v", err)
	}

	// Section count must have increased by 1.
	outNumSections := len(outPE.Sections)
	if outNumSections != origNumSections+1 {
		t.Errorf("section count: got %d, want %d", outNumSections, origNumSections+1)
	}
	t.Logf("output section count: %d", outNumSections)

	// Check the new section name.
	lastSec := outPE.Sections[outNumSections-1]
	foundName := false
	for _, n := range sectionNames {
		if lastSec.Name == n {
			foundName = true
			break
		}
	}
	if !foundName {
		t.Errorf("new section name %q not in expected list %v", lastSec.Name, sectionNames)
	}

	// Verify every original section's raw data is identical.
	for _, want := range origSections {
		// Find matching section in output by name.
		var outSec *pe.Section
		for _, s := range outPE.Sections {
			if s.Name == want.name {
				outSec = s
				break
			}
		}
		if outSec == nil {
			t.Errorf("original section %q not found in output", want.name)
			continue
		}
		got, err := outSec.Data()
		if err != nil {
			t.Errorf("output section %q Data(): %v", want.name, err)
			continue
		}
		if !bytes.Equal(want.data, got) {
			t.Errorf("section %q data mismatch: orig=%d bytes, out=%d bytes, content differs", want.name, len(want.data), len(got))
		} else {
			t.Logf("section %q data preserved (%d bytes)", want.name, len(want.data))
		}
	}

	// Verify DOS + PE signatures in output.
	if output[0] != 'M' || output[1] != 'Z' {
		t.Error("output missing MZ signature")
	}
	eLfanew := int(binary.LittleEndian.Uint32(output[0x3c:]))
	if eLfanew+4 > len(output) {
		t.Error("e_lfanew out of range")
	}
	if string(output[eLfanew:eLfanew+4]) != "PE\x00\x00" {
		t.Error("output missing PE signature")
	}

	// Verify NumberOfSections field increased.
	fileHdr := eLfanew + 4
	numSec := binary.LittleEndian.Uint16(output[fileHdr+2:])
	if int(numSec) != origNumSections+1 {
		t.Errorf("NumberOfSections in header: got %d, want %d", numSec, origNumSections+1)
	}
}

// TestPESectionsMultiple adds multiple sections.
func TestPESectionsMultiple(t *testing.T) {
	exePath, err := buildTrivialBinary(t, "windows", "amd64")
	if err != nil {
		t.Skipf("cross-compile unavailable: %v", err)
	}

	input, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}

	origPE, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("debug/pe parse original: %v", err)
	}
	origNumSections := len(origPE.Sections)

	// Add 3 PE sections.
	output, err := applyPESections(input, 3, 3*1024*1024)
	if err != nil {
		t.Fatalf("applyPESections(3) failed: %v", err)
	}

	outPE, err := pe.NewFile(bytes.NewReader(output))
	if err != nil {
		t.Fatalf("debug/pe parse output: %v", err)
	}
	if len(outPE.Sections) != origNumSections+3 {
		t.Errorf("section count: got %d, want %d", len(outPE.Sections), origNumSections+3)
	}
	t.Logf("original=%d, output=%d sections", origNumSections, len(outPE.Sections))
}

// TestOverlay builds a Linux ELF binary, applies overlay, and verifies the
// original prefix is unchanged and size increased.
func TestOverlay(t *testing.T) {
	elfPath, err := buildTrivialBinary(t, "linux", "amd64")
	if err != nil {
		t.Skipf("cross-compile unavailable (GOOS=linux): %v", err)
	}

	input, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	origSize := len(input)
	t.Logf("input ELF size: %d bytes", origSize)

	// Save a copy of the original for comparison.
	origCopy := make([]byte, origSize)
	copy(origCopy, input)

	// Apply 1 MiB overlay.
	output, err := applyOverlay(input, 1*1024*1024)
	if err != nil {
		t.Fatalf("applyOverlay failed: %v", err)
	}
	t.Logf("output ELF size: %d bytes (+%d)", len(output), len(output)-origSize)

	// The output must be at least 1 MiB larger.
	minExpected := origSize + 1024*1024
	if len(output) < minExpected {
		t.Errorf("output too small: got %d, want >= %d", len(output), minExpected)
	}

	// The first len(orig) bytes must be unchanged.
	if !bytes.Equal(output[:origSize], origCopy) {
		t.Error("overlay changed original file prefix (must be unchanged)")
	} else {
		t.Log("original file prefix preserved")
	}
}

// TestInvalidInput verifies that applyPESections returns an error for garbage input.
func TestInvalidInput(t *testing.T) {
	junk := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	_, err := applyPESections(junk, 1, 1024*1024)
	if err == nil {
		t.Error("expected error for junk input, got nil")
	}
	t.Logf("correctly returned error: %v", err)

	// Also test with a 4096-byte buffer that has "MZ" but invalid PE.
	bigJunk := make([]byte, 4096)
	bigJunk[0] = 'M'
	bigJunk[1] = 'Z'
	_, err = applyPESections(bigJunk, 1, 1024*1024)
	if err == nil {
		t.Error("expected error for invalid PE header, got nil")
	}
	t.Logf("correctly returned error for bad PE: %v", err)
}

// TestNoMarker verifies that no "ADVERSE" string appears in overlay output.
func TestNoMarker(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}

	output, err := applyOverlay(data, 4096)
	if err != nil {
		t.Fatalf("applyOverlay: %v", err)
	}

	// Search for the old marker pattern.
	if bytes.Contains(output, []byte("ADVERSE")) {
		t.Error("output contains 'ADVERSE' plaintext marker — must not")
	}
	if bytes.Contains(output, []byte("POLY")) {
		t.Error("output contains 'POLY' plaintext marker — must not")
	}
}

// TestOverlaySmallSize tests overlay with minimum size.
func TestOverlaySmallSize(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03}

	output, err := applyOverlay(data, minSize)
	if err != nil {
		t.Fatalf("applyOverlay(minSize): %v", err)
	}

	// Must be at least minSize larger.
	if len(output) < len(data)+minSize {
		t.Errorf("output too small: got %d, want >= %d", len(output), len(data)+minSize)
	}
	// Original prefix unchanged.
	if !bytes.Equal(output[:len(data)], data) {
		t.Error("original prefix changed")
	}
}

// TestPESectionsTiny verifies that applyPESections rejects a file smaller than the PE minimum.
func TestPESectionsTiny(t *testing.T) {
	tiny := []byte("MZ") // way too small for PE
	_, err := applyPESections(tiny, 1, 1024)
	if err == nil {
		t.Error("expected error for tiny file")
	}
}

// TestPESectionsCertificateTableShift verifies that a non-zero certificate
// table offset (DataDirectory[4]) is shifted along with the raw data.
func TestPESectionsCertificateTableShift(t *testing.T) {
	exePath, err := buildTrivialBinary(t, "windows", "amd64")
	if err != nil {
		t.Skipf("cross-compile unavailable: %v", err)
	}
	input, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}

	eLfanew := int(binary.LittleEndian.Uint32(input[0x3c:]))
	optStart := eLfanew + 24
	magic := binary.LittleEndian.Uint16(input[optStart:])

	var dataDirOff int
	var fileAlign uint32
	switch magic {
	case 0x10b: // PE32
		dataDirOff = optStart + 96
		fileAlign = binary.LittleEndian.Uint32(input[optStart+36:])
	case 0x20b: // PE32+
		dataDirOff = optStart + 112
		fileAlign = binary.LittleEndian.Uint32(input[optStart+32:])
	default:
		t.Fatalf("unexpected PE magic 0x%x", magic)
	}
	if fileAlign < 512 {
		t.Fatalf("unexpected file alignment %d", fileAlign)
	}

	certDirOff := dataDirOff + 4*8
	binary.LittleEndian.PutUint32(input[certDirOff:], uint32(len(input)))

	output, err := applyPESections(input, 1, 1024*1024)
	if err != nil {
		t.Fatalf("applyPESections: %v", err)
	}

	shift := alignUp(40, int(fileAlign)) // one new 40-byte section header
	want := uint32(len(input)) + uint32(shift)
	if got := binary.LittleEndian.Uint32(output[certDirOff:]); got != want {
		t.Errorf("certificate table offset = %#x, want %#x", got, want)
	}
}
