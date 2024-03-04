/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfheap_ut.c                                                                                  */
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
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfheap.h"
#include "ssfport.h"
#include "ssfassert.h"

#if SSF_CONFIG_HEAP_UNIT_TEST == 1

#define HEAP_MARK 'H'
#define APP_MARK 'A'
#define HEAP_SIZE SSF_HEAP_MAX_SIZE_FOR_UNIT_TEST
#define MAX_ALLOCS (HEAP_SIZE)

typedef struct
{
    uint8_t* base;                  /* User supplied pointer to start of heap area */
    uint32_t baseSize;              /* User supplied size of heap area */
    uint8_t* start;                 /* Aligned pointer to start of working heap area */
    uint8_t* end;                   /* Aligned pointer to end of working heap area */
    uint32_t len;                   /* Aligned length of working heap area */
    uint8_t mark;                   /* Block mark for debugging */
    uint32_t numTotalAllocRequests; /* # of allocation requests */
    uint32_t numAllocRequests;      /* # of successful allocation requests */
    uint32_t numFreeRequests;       /* # of deallocation requests */
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_DECLARATION;
#endif
    uint32_t magic;                 /* Magic number indicating that stuct is inited */
} SSFHeapPrivateHandle_t;

#define SSF_HEAP_ALIGNMENT_SIZE (uint64_t)(sizeof(uint64_t))
#define SSF_HEAP_ALIGNMENT_MASK (uint64_t)-((int64_t)SSF_HEAP_ALIGNMENT_SIZE)
#define SSF_HEAP_MIN_HEAP_MEM_SIZE ((SSF_HEAP_ALIGNMENT_SIZE << 2) + \
                                    sizeof(SSFHeapPrivateHandle_t) + \
                                    (sizeof(SSFHeapBlock_t) << 1))
#define SSF_HEAP_ALIGN_PTR(p) p = (void *)(uintptr_t)((SSF_PTR_CAST_TYPE)(((uint8_t *)p) + \
                                  (SSF_HEAP_ALIGNMENT_SIZE - 1)) & SSF_HEAP_ALIGNMENT_MASK)
#define SSF_HEAP_ALIGN_LEN(l) l = (uint32_t)((uint64_t)(l + (SSF_HEAP_ALIGNMENT_SIZE - 1)) & \
                                  SSF_HEAP_ALIGNMENT_MASK)

uint8_t heap[HEAP_SIZE];
uint8_t *ptrs[MAX_ALLOCS];

SSFHeapHandle_t heapHandle;
SSFHeapStatus_t heapStatusOut;
SSFHeapStatus_t heapStatusOut1;

uint32_t frees, allocs, allocs1;

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfheap's external interface.                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFHeapUnitTest(void)
{
    uint32_t i, j, k;
    uint32_t rindex;
    uint32_t rsize;
    uint8_t *ptr;
    uint8_t *ptr2;
    uint32_t size;
    uint32_t len;
    uint8_t mark;
    uint32_t allocatableSize;

    /* Test SSFHeapInit assertions */
    SSF_ASSERT_TEST(SSFHeapInit(NULL, heap, sizeof(heap), HEAP_MARK, false));
    heapHandle = (SSFHeapHandle_t) (1u);
    SSF_ASSERT_TEST(SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false));
    heapHandle = NULL;
    SSF_ASSERT_TEST(SSFHeapInit(&heapHandle, NULL, sizeof(heap), HEAP_MARK, false));
    SSF_ASSERT_TEST(SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize() - 1, HEAP_MARK, false));
    SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false);
    heapHandle = NULL;
    SSF_ASSERT_TEST(SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false));

    /* Test SSFHeapDeInit assertions */
    memset(heap, 0, sizeof(heap));
    SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false);
    memset(heap, 0, sizeof(heap));
    SSF_ASSERT_TEST(SSFHeapDeInit(NULL, false));
    SSF_ASSERT_TEST(SSFHeapDeInit(&heapHandle, false));
    heapHandle = NULL;
    SSF_ASSERT_TEST(SSFHeapDeInit(&heapHandle, false));

    /* Test SSFHeapAlloc assertions */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false);
    ptr = NULL;
    SSF_ASSERT_TEST(SSFHeapAlloc(NULL, (void **)&ptr, 0, APP_MARK, false));
    SSF_ASSERT_TEST(SSFHeapAlloc(heapHandle, NULL, 0, APP_MARK, false));
    ptr = (uint8_t *)1;
    SSF_ASSERT_TEST(SSFHeapAlloc(heapHandle, (void **)&ptr, 0, APP_MARK, false));
    memset(heap, 0, sizeof(heap));
    SSF_ASSERT_TEST(SSFHeapAlloc(heapHandle, (void **)&ptr, 0, APP_MARK, false));
    heapHandle = NULL;

    /* Test SSFHeapAllocResize assertions */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false);
    ptr = NULL;
    SSF_ASSERT_TEST(SSFHeapAllocResize(NULL, (void **)&ptr, 0, APP_MARK, false));
    SSF_ASSERT_TEST(SSFHeapAllocResize(heapHandle, NULL, 0, APP_MARK, false));
    memset(heap, 0, sizeof(heap));
    SSF_ASSERT_TEST(SSFHeapAllocResize(heapHandle, (void **)&ptr, 0, APP_MARK, false));
    heapHandle = NULL;

    /* Test SSFHeapDealloc assertions */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false);
    ptr = NULL;
    SSF_ASSERT_TEST(SSFHeapDealloc(NULL, (void **)&ptr, NULL, false));
    SSF_ASSERT_TEST(SSFHeapDealloc(heapHandle, NULL, NULL, false));
    ptr = NULL;
    SSF_ASSERT_TEST(SSFHeapDealloc(heapHandle, (void **)&ptr, NULL, false));
    memset(heap, 0, sizeof(heap));
    ptr = (uint8_t *) (void **)&ptr;
    SSF_ASSERT_TEST(SSFHeapDealloc(heapHandle, (void **)&ptr, NULL, false));
    heapHandle = NULL;

    /* Test SSFHeapCheck assertions */
    heapHandle = NULL;
    SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false);
    SSF_ASSERT_TEST(SSFHeapCheck(NULL));
    memset(heap, 0, sizeof(heap));
    SSF_ASSERT_TEST(SSFHeapCheck(heapHandle));

    /* Test SSFHeapStatus assertions */
    heapHandle = NULL;
    SSFHeapInit(&heapHandle, heap, SSFHeapInitMinMemSize(), HEAP_MARK, false);
    SSF_ASSERT_TEST(SSFHeapStatus(NULL, &heapStatusOut));
    SSF_ASSERT_TEST(SSFHeapStatus(heapHandle, NULL));
    memset(heap, 0, sizeof(heap));
    SSF_ASSERT_TEST(SSFHeapStatus(heapHandle, &heapStatusOut));

    /* Iterate over every alignment possible for raw heap area */
    for (i = 0; i < sizeof(void *); i++)
    {
        /* Iterate over every len "alignment" possible for alloc */
        for (j = 0; j < sizeof(void *); j++)
        {
            heapHandle = NULL;
            memset(heap, 0, sizeof(heap));
            ptr = NULL;
            SSFHeapInit(&heapHandle, heap + i, sizeof(heap) - i, HEAP_MARK, false);
            SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, sizeof(void *) + j, APP_MARK, false));
            SSF_ASSERT((((SSF_PTR_CAST_TYPE)ptr) % sizeof(void *)) == 0);
            memset(ptr, 0, sizeof(void *) + j);
            SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, (sizeof(void *) << 1) + j, APP_MARK,
                                          false));
            SSF_ASSERT((((SSF_PTR_CAST_TYPE)ptr) % sizeof(void *)) == 0);
            memset(ptr, 0, (sizeof(void *) << 1) + j);
            SSFHeapDealloc(heapHandle, (void **)&ptr, NULL, false);
            SSF_ASSERT(ptr == NULL);
            SSFHeapCheck(heapHandle);
            SSFHeapStatus(heapHandle, &heapStatusOut);
            SSFHeapCheck(heapHandle);
            SSFHeapDeInit(&heapHandle, false);
        }
    }

    /* Iterate over every alloc/resize to ensure that proper zeroing occurs */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    ptr = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);
    for (i = 0; i < (sizeof(void *) << 2); i++)
    {
        /* Iterate over every len possible for resize no zero */
        for (j = 0; j < (sizeof(void *) << 2); j++)
        {
            SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, i, APP_MARK, false));
            SSF_ASSERT((((SSF_PTR_CAST_TYPE)ptr) % sizeof(void *)) == 0);
            memset(ptr, i | 0x80, i);
            /* Set any spare bytes of allocation to non 0 value */
            len = i;
            SSF_HEAP_ALIGN_LEN(len);
            len -= i;
            memset(ptr + i, ~(i | 0x80) | 0x40, len);

            SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, j, APP_MARK, false));
            SSF_ASSERT((((SSF_PTR_CAST_TYPE)ptr) % sizeof(void *)) == 0);
            /* Make sure all data from original alloc was preserved */
            if (j <= i)
            {
                for (k = 0; k < j; k++)
                {
                    SSF_ASSERT(ptr[k] == (i | 0x80));
                }
            }
            else
            {
                for (k = 0; k < i; k++)
                {
                    SSF_ASSERT(ptr[k] == (i | 0x80));
                }
            }
            SSFHeapDealloc(heapHandle, (void **)&ptr, NULL, false);
            SSF_ASSERT(ptr == NULL);
        }

        /* Iterate over every len possible for resize w zero */
        for (j = 0; j < (sizeof(void *) << 2); j++)
        {
            SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, i, APP_MARK, false));
            SSF_ASSERT((((SSF_PTR_CAST_TYPE)ptr) % sizeof(void *)) == 0);
            memset(ptr, i | 0x40, i);
            /* Set any spare bytes of allocation to non 0 value */
            len = i;
            SSF_HEAP_ALIGN_LEN(len);
            len -= i;
            memset(ptr + i, ~(i | 0x40) | 0x20, len);

            SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, j, APP_MARK, true));
            SSF_ASSERT((((SSF_PTR_CAST_TYPE)ptr) % sizeof(void *)) == 0);
            /* Make sure all data from original alloc was preserved and zeros added as requested */
            if (j <= i)
            {
                for (k = 0; k < j; k++)
                {
                    SSF_ASSERT(ptr[k] == (i | 0x40));
                }
            }
            else
            {
                for (k = 0; k < i; k++)
                {
                    SSF_ASSERT(ptr[k] == (i | 0x40));
                }
                for (k = i; k < j; k++)
                {
                    SSF_ASSERT(ptr[k] == 0);
                }
            }
            SSFHeapDealloc(heapHandle, (void **)&ptr, NULL, false);
            SSF_ASSERT(ptr == NULL);
        }
    }
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSFHeapCheck(heapHandle);
    SSFHeapDeInit(&heapHandle, false);

    /* Check that basics of  SSFHeapStatus work */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    ptr = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);

    ptr = heap;
    SSF_HEAP_ALIGN_PTR(ptr);
    size = sizeof(heap) - (uint32_t)(ptr - heap) - sizeof(SSFHeapPrivateHandle_t) - 32u;
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize >= size);
    allocatableSize = heapStatusOut.allocatableSize;
    SSF_ASSERT(heapStatusOut.allocatableLen == heapStatusOut.allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == 1);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 1);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen == heapStatusOut.allocatableSize);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == 0);
    SSF_ASSERT(heapStatusOut.numAllocRequests == 0);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 0);

    for (i = 0; i < SSF_HEAP_ALIGNMENT_SIZE + 1; i++)
    {
        ptrs[i] = NULL;
        SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptrs[i], i, APP_MARK, false));

        SSFHeapCheck(heapHandle);
        SSFHeapStatus(heapHandle, &heapStatusOut);
        SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
        SSF_ASSERT(heapStatusOut.numBlocks == 1 + (i + 1));
        SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 1);
        SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen == heapStatusOut.allocatableLen);
        SSF_ASSERT(heapStatusOut.numTotalAllocRequests == (i + 1));
        SSF_ASSERT(heapStatusOut.numAllocRequests == (i + 1));
        SSF_ASSERT(heapStatusOut.numFreeRequests == 0);
    }
    
    /* Remove in between allocation */
    SSFHeapDealloc(heapHandle, (void**)&ptrs[1], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == 1 + SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 2);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 1);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[0], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 2);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 2);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[3], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 3);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 3);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[2], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == SSF_HEAP_ALIGNMENT_SIZE - 1);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 2);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 4);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[8], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == SSF_HEAP_ALIGNMENT_SIZE - 2);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 2);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 5);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[6], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == 6);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 3);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 6);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[5], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == 5);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 3);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 7);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[4], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == 3);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 2);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen < heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 8);

    SSFHeapDealloc(heapHandle, (void**)&ptrs[7], NULL, false);
    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(heapStatusOut.allocatableSize == allocatableSize);
    SSF_ASSERT(heapStatusOut.numBlocks == 1);
    SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 1);
    SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen == heapStatusOut.allocatableLen);
    SSF_ASSERT(heapStatusOut.numTotalAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numAllocRequests == SSF_HEAP_ALIGNMENT_SIZE + 1);
    SSF_ASSERT(heapStatusOut.numFreeRequests == 9);

    /* Keep making allocatable requests until completely full */
    for (i = 0; i < MAX_ALLOCS; i++)
    {
        SSFHeapCheck(heapHandle);
        SSFHeapStatus(heapHandle, &heapStatusOut);
        ptrs[i] = NULL;
        SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptrs[i], heapStatusOut.maxAllocatableBlockLen + 1,
                                APP_MARK, false) == false);
        if (heapStatusOut.maxAllocatableBlockLen == 0) break;
        SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptrs[i],
                                (heapStatusOut.maxAllocatableBlockLen >> 2), APP_MARK, false));
    }

    /* Dealloc in reverse */
    for (j = i; j > 0; j--)
    {
        SSFHeapCheck(heapHandle);
        SSFHeapStatus(heapHandle, &heapStatusOut);
        SSFHeapDealloc(heapHandle, (void **)&ptrs[j - 1], NULL, false);
    }

    SSFHeapCheck(heapHandle);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSFHeapCheck(heapHandle);
    SSFHeapDeInit(&heapHandle, false);

    /* Test that integrity checks will find problems by corrupting heap on purpose */
    /* Test regular heap block corruption */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    ptr = NULL;
    ptr2 = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, sizeof(void *), APP_MARK, false));
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr2, sizeof(void *), APP_MARK, false));
    SSFHeapCheck(heapHandle);
    memset(ptr, 0, SSF_HEAP_ALIGNMENT_SIZE + sizeof(uint32_t)); /* Corrupt len of ptr2 block */
    SSF_ASSERT_TEST(SSFHeapDealloc(heapHandle, (void **)&ptr, NULL, false));

    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    ptr = NULL;
    ptr2 = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, sizeof(void *), APP_MARK, false));
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr2, sizeof(void *), APP_MARK, false));
    SSFHeapCheck(heapHandle);
    memset(ptr, 0, SSF_HEAP_ALIGNMENT_SIZE + sizeof(uint32_t)); /* Corrupt len of ptr2 block */
    SSF_ASSERT_TEST(SSFHeapCheck(heapHandle));

    /* Test special end of heap block corruption */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    ptr = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    SSFHeapCheck(heapHandle);
    /* Corrupt end of heap block */
    memset(heap + sizeof(heap) - (SSF_HEAP_ALIGNMENT_SIZE << 1), 0, (SSF_HEAP_ALIGNMENT_SIZE << 1));
    SSF_ASSERT_TEST(SSFHeapDealloc(heapHandle, (void **)&ptr, NULL, false));

    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    ptr = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);
    SSFHeapStatus(heapHandle, &heapStatusOut);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    SSFHeapCheck(heapHandle);
    /* Corrupt end of heap block */
    memset(heap + sizeof(heap) - (SSF_HEAP_ALIGNMENT_SIZE << 1), 0, (SSF_HEAP_ALIGNMENT_SIZE << 1));
    SSF_ASSERT_TEST(SSFHeapCheck(heapHandle));


    /* Test basic behaviors of Init and DeInit */
    heapHandle = NULL;
    memset(heap, 0xDE, sizeof(heap));
    ptr = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr[i] == 0xDE);
    }
    ptr2 = ptr;
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == APP_MARK);
    SSFHeapDeInit(&heapHandle, false);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr2[i] == 0xDE);
    }

    heapHandle = NULL;
    memset(heap, 0xDE, sizeof(heap));
    ptr = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, true);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr[i] == 0);
    }
    memset(ptr, 0xDF, heapStatusOut.maxAllocatableBlockLen);
    ptr2 = ptr;
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == APP_MARK);
    SSFHeapDeInit(&heapHandle, false);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr2[i] == 0xDF);
    }

    heapHandle = NULL;
    memset(heap, 0xDE, sizeof(heap));
    ptr = NULL;
    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, true);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr[i] == 0);
    }
    memset(ptr, 0xDF, heapStatusOut.maxAllocatableBlockLen);
    ptr2 = ptr;
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == APP_MARK);
    SSFHeapDeInit(&heapHandle, true);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr2[i] == 0);
    }

    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);
    /* Test basic behaviors of Alloc */
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen + 1, APP_MARK,
                            false) == false);
    /* Alloc works w/wo/zero */
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    ptr2 = ptr;
    memset(ptr, 0xDF, heapStatusOut.maxAllocatableBlockLen);
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr2[i] == 0xDF);
    }
    SSF_ASSERT(mark == APP_MARK);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr[i] == 0xDF);
    }
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            true));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr[i] == 0);
    }
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);

    /* Test basic behaviors of AllocResize */
    /* Resize new w/wo/zero */
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1, APP_MARK,
                            false));
    ptr2 = ptr;
    memset(ptr, 0xDA, heapStatusOut.maxAllocatableBlockLen >> 1);
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 1; i++)
    {
        SSF_ASSERT(ptr2[i] == 0xDA);
    }
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1,
                                  APP_MARK, false));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 1; i++)
    {
        SSF_ASSERT(ptr[i] == 0xDA);
    }
    ptr2 = ptr;
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1,
                                  APP_MARK, false));
    SSF_ASSERT(ptr2 == ptr);
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == APP_MARK);
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1,
                                  APP_MARK, true));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 1; i++)
    {
        SSF_ASSERT(ptr[i] == 0);
    }
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == APP_MARK);

    /* Resize same w/wo/zero */
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1,
                                  APP_MARK, false));
    ptr2 = ptr;
    memset(ptr, 0xDA, heapStatusOut.maxAllocatableBlockLen >> 1);
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1,
                                  APP_MARK, false));
    SSF_ASSERT(ptr2 == ptr);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 1; i++)
    {
        SSF_ASSERT(ptr[i] == 0xDA);
    }
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1,
                                  APP_MARK + 1, true));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 1; i++)
    {
        SSF_ASSERT(ptr[i] == 0xDA);
    }
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == (APP_MARK + 1));



    /* Resize smaller w/wo/zero */
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1, APP_MARK,
                            false));
    ptr2 = ptr;
    memset(ptr, 0x2A, heapStatusOut.maxAllocatableBlockLen >> 1);
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 2,
                                  APP_MARK, false));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 2; i++)
    {
        SSF_ASSERT(ptr[i] == 0x2A);
    }
    SSF_ASSERT(ptr2 != ptr);
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 4,
                                  APP_MARK + 1, true));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 4; i++)
    {
        SSF_ASSERT(ptr[i] == 0x2A);
    }
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == APP_MARK + 1);

    /* Resize bigger w/wo/zero */
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 4, APP_MARK,
                            false));
    ptr2 = ptr;
    memset(ptr, 0xDA, heapStatusOut.maxAllocatableBlockLen >> 4);
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 2,
                                  APP_MARK, false));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 4; i++)
    {
        SSF_ASSERT(ptr[i] == 0xDA);
    }
    SSF_ASSERT(ptr2 != ptr);
    len = heapStatusOut.maxAllocatableBlockLen >> 2;
    SSF_HEAP_ALIGN_LEN(len);
    memset(ptr, 0x7B, len);
    SSF_ASSERT(SSFHeapAllocResize(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen >> 1,
                                  APP_MARK + 1, true));
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen >> 2; i++)
    {
        SSF_ASSERT(ptr[i] == 0x7B);
    }
    for (i = len; i < heapStatusOut.maxAllocatableBlockLen >> 1; i++)
    {
        SSF_ASSERT(ptr[i] == 0);
    }
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(mark == APP_MARK + 1);

    /* Test basic behaviors of Free */
    /* Alloc Free w/wo/Zero */
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    ptr2 = ptr;
    memset(ptr, 0x45, heapStatusOut.maxAllocatableBlockLen);
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, false);
    SSF_ASSERT(ptr == NULL);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr2[i] == 0x45);
    }
    SSF_ASSERT(SSFHeapAlloc(heapHandle, (void **)&ptr, heapStatusOut.maxAllocatableBlockLen, APP_MARK,
                            false));
    ptr2 = ptr;
    memset(ptr, 0x45, heapStatusOut.maxAllocatableBlockLen);
    SSFHeapDealloc(heapHandle, (void **)&ptr, &mark, true);
    SSF_ASSERT(ptr == NULL);
    for (i = 0; i < heapStatusOut.maxAllocatableBlockLen; i++)
    {
        SSF_ASSERT(ptr2[i] == 0);
    }

    SSFHeapDeInit(&heapHandle, false);

    /* Iterate over every heap memory size and verify correct behavior of all interfaces */
    heapHandle = NULL;
    memset(heap, 0, sizeof(heap));
    for (j = SSFHeapInitMinMemSize(); j <= sizeof(heap); j++)
    {
        SSFHeapInit(&heapHandle, heap, j, 0xff, false);
        SSFHeapCheck(heapHandle);
        SSFHeapStatus(heapHandle, &heapStatusOut);

        ptr = heap;
        SSF_HEAP_ALIGN_PTR(ptr);
        len = j;
        SSF_HEAP_ALIGN_LEN(len);
        size = len - (uint32_t)(ptr - heap) - sizeof(SSFHeapPrivateHandle_t) - 32u;
        SSF_ASSERT(heapStatusOut.allocatableSize >= size);
        SSF_ASSERT(heapStatusOut.allocatableLen == heapStatusOut.allocatableSize);
        SSF_ASSERT(heapStatusOut.numBlocks == 1);
        SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 1);
        SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen == heapStatusOut.allocatableSize);
        SSF_ASSERT(heapStatusOut.numTotalAllocRequests == 0);
        SSF_ASSERT(heapStatusOut.numAllocRequests == 0);
        SSF_ASSERT(heapStatusOut.numFreeRequests == 0);

        allocs = 0;
        allocs1 = 0;
        frees = 0;
        /* Make a series of random allocs and deallocs */
        for (i = 0; i < SSF_MAX(1000u, (j << 1)); i++)
        {
            rindex = rand() % j;
            rsize = rand() % j;

            if (ptrs[rindex] != NULL)
            {
                if (i & 0x01)
                {
                    ptr = ptrs[rindex];
                    if (SSFHeapAllocResize(heapHandle, (void **)&ptr, rsize >> 1, APP_MARK, true) == false)
                    {
                        SSF_ASSERT(ptrs[rindex] == ptr);
                        allocs1++;
                    }
                    else if (ptr != ptrs[rindex])
                    {
                        SSF_ASSERT(ptrs[rindex] != NULL);
                        allocs1++;
                        allocs++;
                        frees++;
                        ptrs[rindex] = ptr;
                        memset(ptrs[rindex], 0x55, rsize >> 1);
                    }
                }
                else
                {
                    SSFHeapFree(heapHandle, &ptrs[rindex], &mark);
                    SSF_ASSERT(ptrs[rindex] == NULL);
                    SSF_ASSERT(mark == APP_MARK);
                    frees++;
                }
            }
            else
            {
                allocs1++;
                SSFHeapMalloc(heapHandle, &ptrs[rindex], rsize, APP_MARK);

                if (ptrs[rindex] != NULL)
                {
                    SSF_ASSERT(ptrs[rindex] != NULL);
                    memset(ptrs[rindex], 0x55, rsize);
                    allocs++;
                }
            }
            SSFHeapCheck(heapHandle);
        }

        /* Free everything */
        for (i = 0; i < MAX_ALLOCS; i++)
        {
            if (ptrs[i] != NULL)
            {
                SSFHeapFree(heapHandle, &ptrs[i], NULL);
                frees++;
                SSFHeapCheck(heapHandle);
            }
        }
        SSFHeapStatus(heapHandle, &heapStatusOut);
        SSF_ASSERT(heapStatusOut.allocatableSize >= size);
        SSF_ASSERT(heapStatusOut.allocatableLen == heapStatusOut.allocatableSize);
        SSF_ASSERT(heapStatusOut.numBlocks >= (allocs - frees));
        SSF_ASSERT(heapStatusOut.numAllocatableBlocks == 1);
        SSF_ASSERT(heapStatusOut.maxAllocatableBlockLen == heapStatusOut.allocatableSize);
        SSF_ASSERT(heapStatusOut.numTotalAllocRequests == allocs1);
        SSF_ASSERT(heapStatusOut.numAllocRequests == allocs);
        SSF_ASSERT(heapStatusOut.numFreeRequests == frees);
        SSFHeapDeInit(&heapHandle, true);
    }
}
#endif /* SSF_CONFIG_HEAP_UNIT_TEST */

