//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information. 
//

// ==++==
//

//
// ==--==
// ***********************************************************************
// File: CrtHelpers.asm
//
// ***********************************************************************

#include "unixasmmacros.inc"
#include "asmconstants.h"

// JIT_MemSet/JIT_MemCpy
//
// It is IMPORANT that the exception handling code is able to find these guys
// on the stack, but to keep them from being tailcalled by VC++ we need to turn
// off optimization and it ends up being a wasteful implementation.
//
// Hence these assembly helpers.
// 
//EXTERN_C void __stdcall JIT_MemSet(void* _dest, int c, size_t count)
LEAF_ENTRY JIT_MemSet, _TEXT

        cmp r0, #0
        beq Exit_MemSet
        
        b C_PLTFUNC(memset)
        
EXIT_MemSet:
        bx lr

LEAF_END_MARKED JIT_MemSet, _TEXT


//EXTERN_C void __stdcall JIT_MemCpy(void* _dest, const void *_src, size_t count)
LEAF_ENTRY JIT_MemCpy, _TEXT
//
// It only requires 4 byte alignment
// and doesn't return a value

        cmp r0, #0
        beq Exit_MemCpy
        
        b C_PLTFUNC(memcpy)
        
EXIT_MemCpy:
        bx lr

LEAF_END_MARKED JIT_MemCpy, _TEXT

