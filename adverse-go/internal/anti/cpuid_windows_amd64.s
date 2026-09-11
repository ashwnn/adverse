#include "textflag.h"

// func cpuid(leaf uint32, ecxIn uint32) (eaxOut, ebxOut, ecxOut, edxOut uint32)
// Executes the x86 CPUID instruction. leaf selects the CPUID function;
// ecxIn is the sub-leaf input (typically 0). Returns all four output registers.
TEXT ·cpuid(SB), NOSPLIT, $0-24
	MOVL	leaf+0(FP), AX
	MOVL	ecxIn+4(FP), CX
	CPUID
	MOVL	AX, eaxOut+8(FP)
	MOVL	BX, ebxOut+12(FP)
	MOVL	CX, ecxOut+16(FP)
	MOVL	DX, edxOut+20(FP)
	RET
