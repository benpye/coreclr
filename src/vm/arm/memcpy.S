//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information. 
//

//

//

// This is the fast memcpy implementation for ARM stolen from the CRT (original location 
// vctools\crt\crtw32\string\arm\memcpy.asm) and modified to be compatible with CLR.
//
// For reference, the unmodified crt version of memcpy is preserved as memcpy_crt.asm

#include "unixasmmacros.inc"
#include "asmconstants.h"

.syntax unified
.thumb

        //IMPORT FCallMemCpy_GCPoll
        //IMPORT g_TrapReturningThreads

        //AREA    |.text|,ALIGN=5,CODE,READONLY

//
// void *memcpy(void *dst, const void *src, size_t length)
//
// Copy a block of memory in a forward direction.
//

        LEAF_ENTRY FCallMemcpy, _TEXT
        b C_FUNC(memcpy)
        LEAF_END FCallMemcpy, _TEXT