/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfheap.h                                                                                     */
/* Provides debuggable, integrity checked heap interface.                                        */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2023 Supurloop Software LLC                                                         */
/*                                                                                               */
/* Redistribution and use in source and binary forms, with or without modification, are          */
/* permitted provided that the following conditions are met:                                     */
/*                                                                                               */
/* 1. Redistributions of source code must retain the above copyright notice, this list of        */
/* conditions and the following disclaimer.                                                      */
/* 2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/* conditions and the following disclaimer in the documentation and/or other materials provided  */
/* with the distribution.                                                                        */
/* 3. Neither the name of the copyright holder nor the names of its contributors may be used to  */
/* endorse or promote products derived from this software without specific prior written         */
/* permission.                                                                                   */
/*                                                                                               */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE    */
/* COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL      */
/* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_HEAP_INCLUDE_H
#define SSF_HEAP_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "ssfport.h"
#include "ssfll.h"

/* Public heap handle structure */
typedef void * SSFHeapHandle_t;

typedef struct
{
    uint32_t allocatableSize;        /* # of allocatable bytes determined at heap init */
    uint32_t allocatableLen;         /* # of allocatable bytes right now */
    uint32_t minAllocatableLen;      /* Low water mark of allocatable bytes */
    uint32_t numBlocks;              /* # of heap blocks right now */
    uint32_t numAllocatableBlocks;   /* # of allocatable heap blocks right now */
    uint32_t maxAllocatableBlockLen; /* # of bytes in biggest allocatable block right now */
    uint32_t numTotalAllocRequests;  /* # of allocation requests */
    uint32_t numAllocRequests;       /* # of successful allocation requests */
    uint32_t numFreeRequests;        /* # of deallocation requests */
} SSFHeapStatus_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFHeapInitMinMemSize(void);
void SSFHeapInit(SSFHeapHandle_t *heapHandleOut, uint8_t *heapMem, uint32_t heapMemSize,
                 uint8_t heapMark, bool isZeroed);
void SSFHeapDeInit(SSFHeapHandle_t *heapHandleOut, bool isZeroed);
void SSFHeapCheck(SSFHeapHandle_t handle);
void SSFHeapStatus(SSFHeapHandle_t handle, SSFHeapStatus_t *heapStatusOut);

bool SSFHeapAlloc(SSFHeapHandle_t handle, void **heapMemOut, uint32_t size, uint8_t mark,
                  bool isZeroed);
#define SSFHeapMalloc(handle, heapMemOut, size, mark) \
                      SSFHeapAlloc(handle, (void **)heapMemOut, size, mark, false)
#define SSFHeapMallocAndZero(handle, heapMemOut, size, mark) \
                             SSFHeapAlloc(handle, (void **)heapMemOut, size, mark, true)

bool SSFHeapAllocResize(SSFHeapHandle_t handle, void **heapMemOut, uint32_t newSize,
                        uint8_t newMark, bool newIsZeroed);
#define SSFHeapRealloc(handle, heapMemOut, newSize, newMark) \
                       SSFHeapAllocResize(handle, (void **)heapMemOut, newSize, newMark, false)
#define SSFHeapReallocAndZeroNew(handle, heapMemOut, newSize, newMark) \
                              SSFHeapAllocResize(handle, (void **)heapMemOut, newSize, newMark, \
                                                 true)

void SSFHeapDealloc(SSFHeapHandle_t handle, void **heapMemOut, uint8_t *markOutOpt,
                    bool isZeroed);
#define SSFHeapFree(handle, heapMemOut, markOutOpt) \
                    SSFHeapDealloc(handle, (void **)heapMemOut, markOutOpt, false)
#define SSFHeapFreeAndZero(handle, heapMemOut, markOutOpt) \
                           SSFHeapDealloc(handle, (void **)heapMemOut, markOutOpt, true)

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_HEAP_UNIT_TEST == 1
void SSFHeapUnitTest(void);
#endif /* SSF_CONFIG_HEAP_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_HEAP_INCLUDE_H */

