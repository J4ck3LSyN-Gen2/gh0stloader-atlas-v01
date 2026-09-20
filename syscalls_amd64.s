#include "textflag.h"

// func sysCall5(ssn uint16, a1..a5 uintptr) uintptr
TEXT ·sysCall5(SB), NOSPLIT, $48-56
    MOVW ssn+0(FP), AX
    MOVQ a1+8(FP), R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    MOVQ a5+40(FP), R11
    MOVQ R11, 40(SP)
    SYSCALL
    MOVQ AX, ret+48(FP)
    RET

// func sysCall6(ssn uint16, a1..a6 uintptr) uintptr
TEXT ·sysCall6(SB), NOSPLIT, $64-64
    MOVW ssn+0(FP), AX
    MOVQ a1+8(FP), R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    MOVQ a5+40(FP), R11
    MOVQ R11, 40(SP)
    MOVQ a6+48(FP), R11
    MOVQ R11, 48(SP)
    SYSCALL
    MOVQ AX, ret+56(FP)
    RET

// func sysCall11(ssn uint16, a1..a11 uintptr) uintptr
TEXT ·sysCall11(SB), NOSPLIT, $112-104
    MOVW ssn+0(FP), AX
    MOVQ a1+8(FP), R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    MOVQ a5+40(FP), R11
    MOVQ R11, 40(SP)
    MOVQ a6+48(FP), R11
    MOVQ R11, 48(SP)
    MOVQ a7+56(FP), R11
    MOVQ R11, 56(SP)
    MOVQ a8+64(FP), R11
    MOVQ R11, 64(SP)
    MOVQ a9+72(FP), R11
    MOVQ R11, 72(SP)
    MOVQ a10+80(FP), R11
    MOVQ R11, 80(SP)
    MOVQ a11+88(FP), R11
    MOVQ R11, 88(SP)
    SYSCALL
    MOVQ AX, ret+96(FP)
    RET
