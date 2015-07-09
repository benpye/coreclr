//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information. 
//

#include "unixasmmacros.inc"
#include "asmconstants.h"

.syntax unified
.thumb

//
// void *memcpy(void *dst, const void *src, size_t length)
//
// Copy a block of memory in a forward direction.
//

    LEAF_ENTRY FCallMemcpy, _TEXT
        push {lr}
        blx C_FUNC(memcpy)
        pop {lr}
        ldr r0, =g_TrapReturningThreads
        ldr r0, [r0]
        cmp r0, #0
        bne FCallMemCpy_GCPoll
        bx lr
    LEAF_END FCallMemcpy, _TEXT