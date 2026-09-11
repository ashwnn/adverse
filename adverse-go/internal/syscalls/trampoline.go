package syscalls

import "encoding/binary"

// generateTrampoline produces position-independent x86-64 syscall trampoline code.
// Layout: [code] [pad to 8-byte aligned] [args block (zeroed)]
//
// Code handles 1–11 arguments:
//   - Args 0–3: mov <reg>, [rip+disp32] from args block
//   - Args 4+: push [rip+disp32] in reverse order
//   - Alignment: sub rsp,8 if needed before SYSCALL
//   - SYSCALL + cleanup + RET
//
// The args block is embedded at the end of the buffer; the caller copies the
// whole buffer into executable memory and fills the args block in place.
// Used by the legacy per-call path and EnumerateProcesses.
func generateTrampoline(ssn uint16, argc int) []byte {
	if argc < 0 {
		argc = 0
	}
	if argc > 11 {
		argc = 11
	}

	code := make([]byte, 0, 256)

	// mov r10, rcx (3 bytes)
	code = append(code, 0x4C, 0x8B, 0xD1)

	// mov eax, imm32 (5 bytes)
	code = append(code, 0xB8)
	code = binary.LittleEndian.AppendUint32(code, uint32(ssn))

	loadStarts := make([]int, 4)

	type loadEnc struct {
		rex    byte
		opcode byte
		modrm  byte
	}
	regEnc := [4]loadEnc{
		{0x48, 0x8B, 0x0D}, // mov rcx, [rip+disp32]
		{0x48, 0x8B, 0x15}, // mov rdx, [rip+disp32]
		{0x4C, 0x8B, 0x05}, // mov r8,  [rip+disp32]
		{0x4C, 0x8B, 0x0D}, // mov r9,  [rip+disp32]
	}

	for i := 0; i < 4 && i < argc; i++ {
		loadStarts[i] = len(code)
		code = append(code, regEnc[i].rex, regEnc[i].opcode, regEnc[i].modrm, 0x00, 0x00, 0x00, 0x00)
	}

	pushStarts := make([]int, 0, max(argc-4, 0))
	for i := argc - 1; i >= 4; i-- {
		pushStarts = append(pushStarts, len(code))
		code = append(code, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00)
	}

	pushCount := argc - 4
	if pushCount < 0 {
		pushCount = 0
	}
	needsAlign := (1+pushCount)%2 != 0
	if needsAlign {
		code = append(code, 0x48, 0x83, 0xEC, 0x08) // sub rsp, 0x08
	}

	code = append(code, 0x0F, 0x05) // SYSCALL

	if needsAlign {
		code = append(code, 0x48, 0x83, 0xC4, 0x08) // add rsp, 0x08
	}

	if pushCount > 0 {
		cleanup := uint32(pushCount * 8)
		if cleanup <= 127 {
			code = append(code, 0x48, 0x83, 0xC4, byte(cleanup))
		} else {
			code = append(code, 0x48, 0x81, 0xC4)
			code = binary.LittleEndian.AppendUint32(code, cleanup)
		}
	}

	code = append(code, 0xC3) // RET

	// Pad to 8-byte alignment
	for len(code)%8 != 0 {
		code = append(code, 0xCC) // int3 padding
	}
	argsBlockOff := len(code)

	// Patch disp32 for register loads (args 0–3). The 7-byte instruction ends
	// at pos+7, which is the RIP base for the RIP-relative displacement.
	for i := 0; i < 4 && i < argc; i++ {
		pos := loadStarts[i]
		target := argsBlockOff + i*8
		disp := int32(target) - int32(pos+7)
		code[pos+3] = byte(disp)
		code[pos+4] = byte(disp >> 8)
		code[pos+5] = byte(disp >> 16)
		code[pos+6] = byte(disp >> 24)
	}

	// Patch disp32 for push args (args 4..argc-1 in reverse order).
	// The 6-byte instruction ends at pos+6.
	for k := 0; k < len(pushStarts); k++ {
		pos := pushStarts[k]
		argIdx := argc - 1 - k
		target := argsBlockOff + argIdx*8
		disp := int32(target) - int32(pos+6)
		code[pos+2] = byte(disp)
		code[pos+3] = byte(disp >> 8)
		code[pos+4] = byte(disp >> 16)
		code[pos+5] = byte(disp >> 24)
	}

	// Append args block (zeroed; caller fills in)
	argsBlock := make([]byte, argc*8)
	code = append(code, argsBlock...)

	return code
}

// generateTrampolineExternal produces a syscall trampoline whose argument
// loads reference an EXTERNAL args block at absolute address argsBase+argsOff.
//
// The args base is materialized with mov r11, imm64 and all loads use
// [r11+disp8] addressing, so there is no ±2GB RIP-relative constraint between
// the code region and the args region — the code can live in a loaded image's
// slack while the writable args live in a separate RW allocation. The code
// region can therefore be written once and made read-only with no per-call
// protection flips. r11 is caller-saved in the Windows x64 ABI and scratch in
// the Go runtime, so clobbering it is safe.
//
// No args block is appended; the returned buffer is pure code, padded to
// 8-byte alignment.
//
// Layout:
//
//	mov r10, rcx                 (3)
//	mov eax, imm32               (5)
//	mov r11, imm64               (10)  <- argsBase + argsOff
//	args 0..3:  mov rX, [r11+disp8]    (4 each)
//	args 4+:    push qword [r11+disp8] (4 each, reverse order)
//	alignment / SYSCALL / cleanup / RET / pad
func generateTrampolineExternal(ssn uint16, argc int, argsBase, argsOff uintptr) []byte {
	if argc < 0 {
		argc = 0
	}
	if argc > 11 {
		argc = 11
	}

	argsPtr := argsBase + argsOff

	code := make([]byte, 0, 256)

	// mov r10, rcx
	code = append(code, 0x4C, 0x8B, 0xD1)
	// mov eax, imm32
	code = append(code, 0xB8)
	code = binary.LittleEndian.AppendUint32(code, uint32(ssn))
	// mov r11, imm64
	code = append(code, 0x49, 0xBB)
	code = binary.LittleEndian.AppendUint64(code, uint64(argsPtr))

	// mov rcx/rdx/r8/r9, [r11+disp8]
	loadEnc := [4]struct{ rex, opcode, modrm byte }{
		{0x49, 0x8B, 0x4B}, // mov rcx, [r11+disp8]
		{0x49, 0x8B, 0x53}, // mov rdx, [r11+disp8]
		{0x4D, 0x8B, 0x43}, // mov r8,  [r11+disp8]
		{0x4D, 0x8B, 0x4B}, // mov r9,  [r11+disp8]
	}
	for i := 0; i < 4 && i < argc; i++ {
		code = append(code, loadEnc[i].rex, loadEnc[i].opcode, loadEnc[i].modrm, byte(i*8))
	}

	// push qword [r11+disp8], in reverse argument order
	for i := argc - 1; i >= 4; i-- {
		code = append(code, 0x41, 0xFF, 0x73, byte(i*8))
	}

	pushCount := argc - 4
	if pushCount < 0 {
		pushCount = 0
	}
	needsAlign := (1+pushCount)%2 != 0
	if needsAlign {
		code = append(code, 0x48, 0x83, 0xEC, 0x08) // sub rsp, 0x08
	}

	code = append(code, 0x0F, 0x05) // SYSCALL

	if needsAlign {
		code = append(code, 0x48, 0x83, 0xC4, 0x08) // add rsp, 0x08
	}

	if pushCount > 0 {
		cleanup := uint32(pushCount * 8)
		if cleanup <= 127 {
			code = append(code, 0x48, 0x83, 0xC4, byte(cleanup))
		} else {
			code = append(code, 0x48, 0x81, 0xC4)
			code = binary.LittleEndian.AppendUint32(code, cleanup)
		}
	}

	code = append(code, 0xC3) // RET

	// Pad to 8-byte alignment
	for len(code)%8 != 0 {
		code = append(code, 0xCC) // int3 padding
	}
	return code
}
