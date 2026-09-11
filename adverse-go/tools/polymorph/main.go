// Command polymorph inflates compiled agent binaries to hinder AV / any.run /
// VirusTotal content and ML scanning. It appends structured overlays and/or
// injects new PE sections carrying incompressible random data.
//
// IMPORTANT: Size inflation slows scanning but does NOT defeat memory
// scanning, behavioral analysis, or determined content/ML analysis. This is
// a lab research technique for authorized red-team builds, not evasion.
//
// No plaintext markers or IOCs are written into the padded binary.
//
// Usage:
//
//	go run ./tools/polymorph --in bin/agent.exe --mode overlay --size 4194304
//	go run ./tools/polymorph --in bin/agent.exe --mode pesections --sections 2
//	go run ./tools/polymorph --in bin/agent.exe --mode both --size 4194304 --sections 2
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ashwnn/adverse-go/internal/obfuscate"
)

const (
	defaultSize = 4 * 1024 * 1024 // 4 MiB
	minSize     = 1024
	maxSize     = 256 * 1024 * 1024 // 256 MiB

	chunkSize = 64 * 1024 // 64 KiB random chunks for overlay
	gapSize   = 512       // zero-gap between random chunks
)

// Section names cycled when adding PE sections.
var sectionNames = []string{".rdata2", ".rsrc1", ".reloc1", ".debug$2", ".pdata1"}

func main() {
	inFlag := flag.String("in", "", "input binary path (required)")
	outFlag := flag.String("out", "", "output path (default: overwrite in place)")
	modeFlag := flag.String("mode", "overlay", "padding mode: overlay, pesections, both")
	sizeFlag := flag.Int("size", defaultSize, "total padding bytes (1024..268435456)")
	sectionsFlag := flag.Int("sections", 1, "number of PE sections to add (pesections/both mode)")
	flag.Parse()

	if *inFlag == "" {
		fmt.Fprintln(os.Stderr, "error: --in is required")
		flag.Usage()
		os.Exit(2)
	}

	// Clamp size.
	size := *sizeFlag
	if size < minSize {
		size = minSize
	}
	if size > maxSize {
		size = maxSize
	}
	numSections := *sectionsFlag
	if numSections < 1 {
		numSections = 1
	}

	mode := strings.ToLower(*modeFlag)
	switch mode {
	case "overlay", "pesections", "both":
	default:
		fmt.Fprintf(os.Stderr, "error: unknown mode %q (must be overlay, pesections, or both)\n", *modeFlag)
		os.Exit(2)
	}

	// Read input.
	input, err := os.ReadFile(*inFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}
	if len(input) < 2 {
		fmt.Fprintln(os.Stderr, "error: input file too small")
		os.Exit(1)
	}

	// Determine output path.
	target := *inFlag
	if *outFlag != "" {
		target = *outFlag
	}

	// Apply modes, producing the output buffer.
	var output []byte
	switch mode {
	case "overlay":
		output, err = applyOverlay(input, size)
	case "pesections":
		output, err = applyPESections(input, numSections, size)
	case "both":
		// Overlay first, then PE sections.
		output, err = applyOverlay(input, size)
		if err != nil {
			break
		}
		output, err = applyPESections(output, numSections, size)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(target, output, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("polymorphed %s (%s mode, %d bytes -> %d bytes)\n", target, mode, len(input), len(output))
}

// applyOverlay appends structured, incompressible padding as a trailing
// overlay. The overlay consists of alternating 64 KiB random chunks and
// 512-byte zero gaps, so it is NOT a single obvious contiguous random blob.
// Go/PE/ELF loaders ignore trailing overlay data; execution is unchanged.
//
// No plaintext markers are written.
func applyOverlay(b []byte, size int) ([]byte, error) {
	result := make([]byte, len(b))
	copy(result, b)

	remaining := size
	for remaining > 0 {
		chunkLen := chunkSize
		if chunkLen > remaining {
			chunkLen = remaining
		}
		// Random chunk via obfuscate.PolymorphicOverlay (crypto/rand, never all-zero).
		chunk := obfuscate.PolymorphicOverlay(chunkLen)
		result = append(result, chunk...)
		remaining -= chunkLen

		// Zero gap (unless we're done).
		if remaining > 0 {
			gap := gapSize
			if gap > remaining {
				gap = remaining
			}
			result = append(result, make([]byte, gap)...)
			remaining -= gap
		}
	}
	return result, nil
}

// applyPESections adds new PE sections with benign-looking names to a Windows
// PE binary. Each new section carries incompressible random data (crypto/rand).
// This is best-effort and SAFE: it only appends; it does not modify existing
// section data. The PE header is rewritten correctly to reflect the new layout.
//
// If the input is not a valid PE, or any offset would be out of range, the
// function returns an error and writes nothing.
func applyPESections(b []byte, numNewSections int, totalSize int) ([]byte, error) {
	if !isPE(b) {
		return nil, errors.New("input is not a valid PE (missing MZ/PE signature)")
	}

	eLfanew := int(binary.LittleEndian.Uint32(b[0x3c:]))
	fileHdr := eLfanew + 4
	numSections := int(LE16(b, fileHdr+2))
	sizeOpt := int(LE16(b, fileHdr+16))
	optStart := eLfanew + 24
	magic := LE16(b, optStart)

	// Determine alignment and header field offsets based on PE32 vs PE32+.
	var fileAlign, sectAlign uint32
	var sizeOfImageOff, sizeOfHeadersOff, dataDirOff int

	switch magic {
	case 0x10b: // PE32
		fileAlign = LE32(b, optStart+36)
		sectAlign = LE32(b, optStart+40)
		sizeOfImageOff = optStart + 60
		sizeOfHeadersOff = optStart + 64
		dataDirOff = optStart + 96 // data directories follow NumberOfRvaAndSizes at +92
	case 0x20b: // PE32+
		fileAlign = LE32(b, optStart+32)
		sectAlign = LE32(b, optStart+36)
		sizeOfImageOff = optStart + 56
		sizeOfHeadersOff = optStart + 60
		dataDirOff = optStart + 112 // data directories follow NumberOfRvaAndSizes at +108
	default:
		return nil, fmt.Errorf("unsupported PE magic: 0x%x (need 0x10b or 0x20b)", magic)
	}

	// Sanity check alignment values (must be power of two, at least 512).
	if fileAlign < 512 || sectAlign < 512 || !isPowerOf2(fileAlign) || !isPowerOf2(sectAlign) {
		return nil, fmt.Errorf("invalid alignment: fileAlign=%d sectAlign=%d", fileAlign, sectAlign)
	}

	// Section table starts after optional header.
	sectionTableStart := optStart + sizeOpt
	sectionTableEnd := sectionTableStart + numSections*40

	if sectionTableEnd > len(b) {
		return nil, fmt.Errorf("section table extends past file: end=%d fileLen=%d", sectionTableEnd, len(b))
	}

	// Read existing section headers.
	existing := make([]peSectionHeader, numSections)
	for i := 0; i < numSections; i++ {
		existing[i] = readSectionHeader(b, sectionTableStart+i*40)
	}

	// Calculate per-section data size.
	perSection := totalSize / numNewSections
	if perSection < 512 {
		perSection = 512
	}

	// The shift: insert numNewSections * 40 bytes of new section headers at
	// sectionTableEnd, then shift all existing raw data forward by the
	// aligned shift amount so raw-data alignment is preserved.
	newHeadersSize := numNewSections * 40
	shift := alignUp(newHeadersSize, int(fileAlign))

	// Calculate new raw data placement for new sections.
	// New raw data starts after the original file data + shift, aligned to fileAlign.
	newRawStart := alignUp(len(b)+shift, int(fileAlign))

	// Build the new image.
	newImg := make([]byte, newRawStart+numNewSections*alignUp(perSection, int(fileAlign)))

	// Copy original data up to section table end.
	copy(newImg, b[:sectionTableEnd])

	// The shift area (sectionTableEnd .. sectionTableEnd+shift) is already zero
	// from make().

	// Copy the rest of the original data (everything after section table end),
	// shifted forward by `shift`.
	copy(newImg[sectionTableEnd+shift:], b[sectionTableEnd:])

	// Write new section headers at sectionTableEnd.
	names := make([]string, numNewSections)
	for i := 0; i < numNewSections; i++ {
		names[i] = sectionNames[i%len(sectionNames)]
	}

	// Determine starting VA for new sections: after the last existing section.
	lastVA := uint32(0)
	if len(existing) > 0 {
		lastVA = existing[len(existing)-1].VirtualAddress
		lastVSize := existing[len(existing)-1].VirtualSize
		// Use SizeOfRawData if VirtualSize is 0.
		if lastVSize == 0 {
			lastVSize = existing[len(existing)-1].SizeOfRawData
		}
		if lastVSize == 0 {
			lastVSize = 1
		}
		lastVA = existing[len(existing)-1].VirtualAddress + lastVSize
	}

	for i := 0; i < numNewSections; i++ {
		hdrOff := sectionTableEnd + i*40
		newVA := alignUp(int(lastVA), int(sectAlign))
		// Accumulate VA for next section.
		lastVA = uint32(newVA + alignUp(perSection, int(sectAlign)))

		newRawSize := alignUp(perSection, int(fileAlign))
		newPtrRaw := uint32(newRawStart + i*newRawSize)

		var sh peSectionHeader
		copy(sh.Name[:], []byte(names[i]))
		sh.VirtualSize = uint32(perSection)
		sh.VirtualAddress = uint32(newVA)
		sh.SizeOfRawData = uint32(newRawSize)
		sh.PointerToRawData = newPtrRaw
		// IMAGE_SCN_CNT_INITIALIZED_DATA (0x40) | IMAGE_SCN_MEM_READ (0x40000000)
		sh.Characteristics = 0x00000040 | 0x40000000

		writeSectionHeader(newImg, hdrOff, &sh)

		// Fill raw data with crypto/rand (incompressible).
		if int(newPtrRaw)+newRawSize <= len(newImg) {
			randChunk := make([]byte, newRawSize)
			if _, err := rand.Read(randChunk); err != nil {
				return nil, fmt.Errorf("crypto/rand failed: %v", err)
			}
			// Ensure not all zeros (avoids VT normalization).
			for j := range randChunk {
				if randChunk[j] == 0 {
					randChunk[j] = byte((j * 0x13) ^ 0xA5)
				}
			}
			copy(newImg[newPtrRaw:], randChunk)
		}
	}

	// Patch scalar header fields.
	// NumberOfSections.
	putLE16(newImg, fileHdr+2, uint16(numSections+numNewSections))

	// PointerToSymbolTable (COFF file header offset +8): shift if non-zero.
	if ptrSym := LE32(newImg, fileHdr+8); ptrSym != 0 {
		putLE32(newImg, fileHdr+8, ptrSym+uint32(shift))
	}

	// SizeOfHeaders: existing + shift.
	if sizeOfHeadersOff > 0 && sizeOfHeadersOff+4 <= len(newImg) {
		oldSOH := LE32(newImg, sizeOfHeadersOff)
		putLE32(newImg, sizeOfHeadersOff, oldSOH+uint32(shift))
	}

	// SizeOfImage: last new section's VA + aligned VirtualSize.
	newImageSize := alignUp(int(lastVA), int(sectAlign))
	if sizeOfImageOff > 0 && sizeOfImageOff+4 <= len(newImg) {
		putLE32(newImg, sizeOfImageOff, uint32(newImageSize))
	}

	// Patch each existing section's PointerToRawData += shift.
	for i := 0; i < numSections; i++ {
		off := sectionTableStart + i*40
		oldPtr := LE32(newImg, off+20)
		putLE32(newImg, off+20, oldPtr+uint32(shift))
	}

	// Certificate Table (DataDirectory[4]): VirtualAddress is a FILE OFFSET to
	// the attribute certificate blob, which sits after the section data, so it
	// must move with the shifted file contents. The entry is 8 bytes
	// (offset,size); only the offset shifts. Entries pointing before the
	// insertion point are left alone.
	certDirOff := dataDirOff + 4*8
	if dataDirOff > 0 && certDirOff+4 <= len(newImg) {
		if certOff := LE32(newImg, certDirOff); certOff != 0 && int(certOff) >= sectionTableEnd {
			putLE32(newImg, certDirOff, certOff+uint32(shift))
		}
	}

	// DataDirectory[6] (Debug) holds an RVA, so it needs no patch: existing
	// sections keep their VirtualAddress. Debug-directory *entries* may carry
	// file offsets (PointerToRawData) that are shifted with the section bytes;
	// those are not rewritten. Loaders ignore the debug directory for
	// execution, and debuggers should analyze the unmodified binary.

	// Verify original section data is preserved.
	if err := verifyPEPreserved(b, newImg, shift, existing); err != nil {
		return nil, fmt.Errorf("verification failed: %v", err)
	}

	return newImg, nil
}

// verifyPEPreserved checks that every original PE section's raw bytes in the
// output match the input, and that the DOS/PE signatures are intact.
func verifyPEPreserved(input, output []byte, shift int, sections []peSectionHeader) error {
	// Check DOS signature.
	if len(output) < 2 || output[0] != 'M' || output[1] != 'Z' {
		return errors.New("output missing DOS MZ signature")
	}

	// Check PE signature.
	eLfanew := int(binary.LittleEndian.Uint32(output[0x3c:]))
	if eLfanew+4 > len(output) || string(output[eLfanew:eLfanew+4]) != "PE\x00\x00" {
		return errors.New("output missing PE signature")
	}

	// Verify each original section's raw bytes are identical.
	for _, sec := range sections {
		if sec.SizeOfRawData == 0 || sec.PointerToRawData == 0 {
			continue
		}
		origStart := int(sec.PointerToRawData)
		origEnd := origStart + int(sec.SizeOfRawData)
		if origEnd > len(input) {
			return fmt.Errorf("original section extends past input: %d > %d", origEnd, len(input))
		}
		newStart := origStart + shift
		newEnd := newStart + int(sec.SizeOfRawData)
		if newEnd > len(output) {
			return fmt.Errorf("shifted section extends past output: %d > %d", newEnd, len(output))
		}
		if !bytes.Equal(input[origStart:origEnd], output[newStart:newEnd]) {
			return fmt.Errorf("section %q data mismatch after shift", string(sec.Name[:]))
		}
	}

	return nil
}

// isPE returns true if b looks like a valid PE (DOS "MZ" + PE signature).
func isPE(b []byte) bool {
	if len(b) < 0x40+4 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	eLfanew := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if eLfanew+4 > len(b) {
		return false
	}
	return string(b[eLfanew:eLfanew+4]) == "PE\x00\x00"
}

// isPowerOf2 returns true if n > 0 and n is a power of two.
func isPowerOf2(n uint32) bool {
	return n > 0 && (n&(n-1)) == 0
}

// alignUp rounds v up to the next multiple of align. align must be a power of two.
func alignUp(v, align int) int {
	return (v + align - 1) &^ (align - 1)
}

// LE16 reads a little-endian uint16 at off.
func LE16(b []byte, off int) uint16 {
	return binary.LittleEndian.Uint16(b[off:])
}

// LE32 reads a little-endian uint32 at off.
func LE32(b []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(b[off:])
}

// putLE16 writes a little-endian uint16 at off.
func putLE16(b []byte, off int, v uint16) {
	binary.LittleEndian.PutUint16(b[off:], v)
}

// putLE32 writes a little-endian uint32 at off.
func putLE32(b []byte, off int, v uint32) {
	binary.LittleEndian.PutUint32(b[off:], v)
}

// peSectionHeader represents a single 40-byte PE section header.
type peSectionHeader struct {
	Name             [8]byte
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
}

// readSectionHeader reads a 40-byte section header from b at offset.
func readSectionHeader(b []byte, off int) peSectionHeader {
	var h peSectionHeader
	copy(h.Name[:], b[off:off+8])
	h.VirtualSize = LE32(b, off+8)
	h.VirtualAddress = LE32(b, off+12)
	h.SizeOfRawData = LE32(b, off+16)
	h.PointerToRawData = LE32(b, off+20)
	h.Characteristics = LE32(b, off+36)
	return h
}

// writeSectionHeader writes a 40-byte section header to b at offset.
func writeSectionHeader(b []byte, off int, h *peSectionHeader) {
	copy(b[off:off+8], h.Name[:])
	putLE32(b, off+8, h.VirtualSize)
	putLE32(b, off+12, h.VirtualAddress)
	putLE32(b, off+16, h.SizeOfRawData)
	putLE32(b, off+20, h.PointerToRawData)
	putLE32(b, off+36, h.Characteristics)
}
