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
        b C_FUNC(memcpy)
        LEAF_END FCallMemcpy, _TEXT