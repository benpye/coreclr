//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//
//
// Implementation of _CONTEXT_CaptureContext for the ARM platform.
// This function is processor dependent.  It is used by exception handling,
// and is always apply to the current thread.
//

#include "unixasmmacros.inc"

#define CONTEXT_ARM     0x00200000

#define CONTEXT_CONTROL 1 // Sp, Lr, Pc, Cpsr
#define CONTEXT_INTEGER 2 // R0-R12
#define CONTEXT_SEGMENTS 4 // 
#define CONTEXT_FLOATING_POINT 8
#define CONTEXT_DEBUG_REGISTERS 16 //

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

#define CONTEXT_ContextFlags 0
#define CONTEXT_R0           CONTEXT_ContextFlags+4
#define CONTEXT_R1           CONTEXT_R0+4
#define CONTEXT_R2           CONTEXT_R1+4
#define CONTEXT_R3           CONTEXT_R2+4
#define CONTEXT_R4           CONTEXT_R3+4
#define CONTEXT_R5           CONTEXT_R4+4
#define CONTEXT_R6           CONTEXT_R5+4
#define CONTEXT_R7           CONTEXT_R6+4
#define CONTEXT_R8           CONTEXT_R7+4
#define CONTEXT_R9           CONTEXT_R8+4
#define CONTEXT_R10          CONTEXT_R9+4
#define CONTEXT_R11          CONTEXT_R10+4
#define CONTEXT_R12          CONTEXT_R11+4
#define CONTEXT_Sp           CONTEXT_R12+4
#define CONTEXT_Lr           CONTEXT_Sp+4
#define CONTEXT_Pc           CONTEXT_Lr+4
#define CONTEXT_Cpsr         CONTEXT_Pc+4

// Incoming:
//  R0: Context*
//
LEAF_ENTRY CONTEXT_CaptureContext, _TEXT
    // Ensure we save these registers
    push {R4-R11}
    // Save processor flags before calling any of the following 'test' instructions
    // because they will modify state of some flags
    push {R1}
    mrs R1, APSR // Get APSR - equivalent to eflags
    push {R1} // Save APSR
    END_PROLOGUE
    
    push {R2}
    ldr R2, [R0, #(CONTEXT_ContextFlags)]
    tst R2, #(CONTEXT_INTEGER)
    pop {R2}
    
    // Add 4 to stack so we point at R1, pop, then sub 8 to point at APSR
    add sp, sp, #4
    pop {R1}
    sub sp, sp, #8
    
    strne R0, [R0, #(CONTEXT_R0)]
    addne R0, CONTEXT_R1
    stmiane R0, {R1-R12}
    subne R0, CONTEXT_R1
    
    ldr R2, [R0, #(CONTEXT_ContextFlags)]
    tst R2, #(CONTEXT_CONTROL)
    
    addne sp, sp, #(10*4) // This needs to put the stack in the same state as it started
    strne sp, [R0, #(CONTEXT_Sp)]
    subne sp, sp, #(10*4)
    
    strne lr, [R0, #(CONTEXT_Lr)]
    strne lr, [R0, #(CONTEXT_Pc)]
    
    // Get the APSR pushed onto the stack at the start
    pop {R1}
    strne R1, [R0, #(CONTEXT_Cpsr)]
    
    // Make sure sp is restored
    add sp, sp, #4

    // Restore callee saved registers
    pop {R4-R11}
    bx lr
LEAF_END CONTEXT_CaptureContext, _TEXT

LEAF_ENTRY RtlCaptureContext, _TEXT
    push {r1}
    mov r1, #0
    orr r1, r1, #CONTEXT_ARM
    orr r1, r1, #CONTEXT_INTEGER
    orr r1, r1, #CONTEXT_CONTROL
    orr r1, r1, #CONTEXT_FLOATING_POINT
    str r1, [r0, #(CONTEXT_ContextFlags)]
    pop {r1}
    b C_FUNC(CONTEXT_CaptureContext)
LEAF_END RtlCaptureContext, _TEXT