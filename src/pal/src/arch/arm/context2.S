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

// Incoming:
//  r0: Context*
//
LEAF_ENTRY CONTEXT_CaptureContext, _TEXT
    // Save processor flags before calling any of the following 'test' instructions
    // because they will modify state of some flags
    END_PROLOGUE

    bx lr
LEAF_END CONTEXT_CaptureContext, _TEXT

LEAF_ENTRY RtlCaptureContext, _TEXT
    bx lr
LEAF_END RtlCaptureContext, _TEXT

LEAF_ENTRY RtlRestoreContext, _TEXT
    bx lr
LEAF_END RtlRestoreContext, _TEXT