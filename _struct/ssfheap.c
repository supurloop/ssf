/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfheap.c                                                                                     */
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
/*                                                                                               */
/* Note: This heap implementation is not a direct replacement for malloc, realloc, free, etc.    */
/*                                                                                               */
/* This interface has a more pedantic and consistent API designed to prevent common dynamic      */
/* memory allocation mistakes that the standard C library happily permits.                       */
/*                                                                                               */
/* All operations check the heap's integrity and asserts when corruption is found.               */
/* When the time comes to read a heap dump, +/- chars help visually mark the block headers,      */
/* while "dead" headers are zeroed so they never pollute the dump.                               */
/*                                                                                               */
/* Heap                                                                                          */
/* |                                                                                             */
/* Heap Block 1, Heap Block 2,...Heap Block N, End of Heap Fence Block                           */
/* |                                                                                             */
/* Heap Block Header, Heap Block Memory                                                          */
/* |<-Block Len---------------------->|                                                          */
/* |                                                                                             */
/* Block Len, Is Alloced, Mark, Block Header Checksum                                            */
/* |<-Block Header Checksum->|                                                                   */
/*                                                                                               */
/* Immediately preceeding the working heap is the heap handle structure.                         */
/* A Heap is composed of 1 or more Heap Blocks terminated by an End of Heap Fence BLock.         */
/* A Heap Block is composed of a Heap Block Header followed by Heap Block Memory.                */
/* A Heap Block may have a Heap Block Memory of 0 length.                                        */
/* The Heap Block Header Length == the byte size of the Heap Block Header and Heap Block Memory. */
/* A Heap Block may either be allocated (isAlloced == '-') or unallocated (isAlloced == '+').    */
/* A Heap Block Header has a Mark field, which allows app tracking of allocs and frees.          */
/* A Heap Block Header has a Checksum used to verify the integrity of the Heap Block Header.     */
/* Heap Block Headers are checked for validity before being referenced.                          */
/* Heap Block Headers act as a fence to detect apps writing past their allocated region.         */
/* Heap Block Headers are always memory aligned to the machine word size.                        */
/* The size of a Heap Block Header is an exact multiple of the machine word size.                */
/* Heap Block Memory is always memory aligned to the machine word size.                          */
/* The End of Heap Fence Block abuts the end of allocatable heap, detects writes past heap's end.*/
/* App allocations are pointers to Heap Block Memory and machine word size aligned.              */
/* App allocations are from the first set of sequential free Heap Blocks >= requested size.      */
/* App allocations that == free Heap Block Memories len marks the Heap Block Header allocated.   */
/* App allocations that are < free Heap Block Memories len form a new unallocated Heap Block.    */
/* App deallocations mark the Heap Block as unallocated and check next block for overruns.       */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssffcsum.h"
#include "ssfheap.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* Private heap handle structure */
typedef struct
{
    uint8_t *base;                  /* User supplied pointer to start of heap area */
    uint32_t baseSize;              /* User supplied size of heap area */
    uint8_t *start;                 /* Aligned pointer to start of working heap area */
    uint8_t *end;                   /* Aligned pointer to end of working heap area */
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

typedef struct
{
    uint32_t len;
    uint8_t isAlloced;
    uint8_t mark;
    uint8_t spareLen;
    uint8_t checksum;
} SSFHeapBlock_t;

#define SSF_HEAP_MAGIC (0x48454150)
#define SSF_HEAP_BLOCK_ALLOCED ((uint8_t)('-'))
#define SSF_HEAP_BLOCK_UNALLOCED ((uint8_t)('+'))
#define SSF_HEAP_ALIGNMENT_SIZE (uint64_t)(sizeof(void *))
#define SSF_HEAP_ALIGNMENT_MASK (uint64_t)-((int64_t)SSF_HEAP_ALIGNMENT_SIZE)
#define SSF_HEAP_MIN_HEAP_MEM_SIZE ((SSF_HEAP_ALIGNMENT_SIZE << 2) + \
                                    sizeof(SSFHeapPrivateHandle_t) + \
                                    (sizeof(SSFHeapBlock_t) << 1))
#define SSF_HEAP_ALIGN_PTR(p) p = (void *)((uint64_t)(((uint8_t *)p) + \
                                  (SSF_HEAP_ALIGNMENT_SIZE - 1)) & SSF_HEAP_ALIGNMENT_MASK)
#define SSF_HEAP_ALIGN_LEN(l) l = (uint32_t)((uint64_t)(l + (SSF_HEAP_ALIGNMENT_SIZE - 1)) & \
                                  SSF_HEAP_ALIGNMENT_MASK)
#define SSF_HEAP_U8_CAST(p) ((uint8_t *)(p))
#define SSF_HEAP_SET_BLOCK(blk, blkLen, blkIsAlloced, blkMark, sprLen) \
    (blk)->len = blkLen; \
    (blk)->isAlloced = blkIsAlloced; \
    (blk)->mark = blkMark; \
    (blk)->spareLen = (uint8_t)(sprLen); \
    (blk)->checksum = (uint8_t)SSFFCSum16(SSF_HEAP_U8_CAST(blk), \
                                          sizeof(SSFHeapBlock_t) - sizeof(uint8_t), \
                                          SSF_FCSUM_INITIAL);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
SSF_HEAP_SYNC_DECLARATION;
#endif

/* --------------------------------------------------------------------------------------------- */
/* Check heap block integrity.                                                                   */
/* --------------------------------------------------------------------------------------------- */
void _SSFHeapCheckBlock(SSFHeapPrivateHandle_t *handle, SSFHeapBlock_t *hb)
{
    SSF_REQUIRE(handle != NULL);
    SSF_ASSERT(((uint8_t)SSFFCSum16(SSF_HEAP_U8_CAST(hb),
                                    sizeof(SSFHeapBlock_t) - sizeof(uint8_t),
                                    SSF_FCSUM_INITIAL)) == hb->checksum);
    SSF_ASSERT((hb->isAlloced == SSF_HEAP_BLOCK_UNALLOCED) ||
               (hb->isAlloced == SSF_HEAP_BLOCK_ALLOCED));
    SSF_ASSERT((hb->len >= sizeof(SSFHeapBlock_t)) && (hb->len <= handle->len));
    SSF_ASSERT(hb->spareLen <= SSF_HEAP_ALIGNMENT_SIZE);
    SSF_ASSERT((SSF_HEAP_U8_CAST(hb) >= handle->start) &&
               (SSF_HEAP_U8_CAST(hb) <= handle->end));
}

/* --------------------------------------------------------------------------------------------- */
/* Condenses a series of free blocks into one free block.                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHeapBlockCondense(SSFHeapPrivateHandle_t *handle, SSFHeapBlock_t *hb,
                                  uint32_t remainingLen)
{
    uint32_t len;
    uint32_t bmLen = 0;
    uint8_t spareLen;
    uint8_t* start = SSF_HEAP_U8_CAST(hb);

    SSF_REQUIRE(handle != NULL);
    SSF_REQUIRE(hb != NULL);
    SSF_REQUIRE(remainingLen <= handle->len);

    _SSFHeapCheckBlock(handle, hb);
    spareLen = hb->spareLen;
    while (remainingLen != 0)
    {
        /* Accumulate sequential unallocated len, zeroing out condensed block headers */
        len = hb->len;
        remainingLen -= len;
        if (hb->isAlloced == SSF_HEAP_BLOCK_UNALLOCED)
        {
            bmLen += len;
            memset(hb, 0, sizeof(SSFHeapBlock_t));
        }

        /* End of free blocks? */
        if ((hb->isAlloced == SSF_HEAP_BLOCK_ALLOCED) || (remainingLen == 0))
        {
            /* Yes, set the head block to the new condensed length */
            hb = (SSFHeapBlock_t *)(void *)start;
            SSF_HEAP_SET_BLOCK(hb, bmLen, SSF_HEAP_BLOCK_UNALLOCED, handle->mark, spareLen);
            return;
        }
        hb = (SSFHeapBlock_t *)(void *)(SSF_HEAP_U8_CAST(hb) + len);
        _SSFHeapCheckBlock(handle, hb);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns min # bytes to ensure SSFHeapInit successfully creates a heap w/0 allocatable memory. */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFHeapInitMinMemSize(void)
{
    return (uint32_t)SSF_HEAP_MIN_HEAP_MEM_SIZE;
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes a new heap.                                                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFHeapInit(SSFHeapHandle_t *handleOut, uint8_t *heapMem, uint32_t heapMemSize,
                 uint8_t heapMark, bool isZeroed)
{
    SSFHeapBlock_t *hb;
    SSFHeapPrivateHandle_t *ph;

    SSF_REQUIRE(handleOut != NULL);
    SSF_REQUIRE(*handleOut == NULL);
    SSF_REQUIRE(heapMem != NULL);
    SSF_REQUIRE(heapMemSize >= SSF_HEAP_MIN_HEAP_MEM_SIZE);

    /* Compute aligned start of heap handle */
    ph = (SSFHeapPrivateHandle_t *)(void *)heapMem;
    SSF_HEAP_ALIGN_PTR(ph);
    SSF_ASSERT(ph->magic != SSF_HEAP_MAGIC);
    if (isZeroed) memset(heapMem, 0, heapMemSize);
    else memset(ph, 0, sizeof(SSFHeapPrivateHandle_t));

    /* Save the original heap pointer and size, init all memory to the unallocated value */
    ph->base = heapMem;
    ph->baseSize = heapMemSize;
    ph->mark = heapMark;

    /* Compute aligned start of heap */
    ph->start = SSF_HEAP_U8_CAST(ph) + sizeof(SSFHeapPrivateHandle_t);
    SSF_HEAP_ALIGN_PTR(ph->start);
    SSF_ASSERT(ph->start >= ph->base);
    SSF_ASSERT((ph->start - ph->base) <= heapMemSize);

    /* Compute aligned heap length and end */
    ph->len = heapMemSize - (uint32_t)(ph->start - ph->base);
    SSF_ASSERT(ph->len >= SSF_HEAP_ALIGNMENT_SIZE);
    ph->len -= SSF_HEAP_ALIGNMENT_SIZE;
    SSF_HEAP_ALIGN_LEN(ph->len);
    SSF_REQUIRE(ph->len >= (sizeof(SSFHeapBlock_t) << 1));
    ph->len -= sizeof(SSFHeapBlock_t);
    ph->end = SSF_HEAP_U8_CAST(ph->start) + ph->len;

    /* Initialize a single free block for all available memory */
    hb = (SSFHeapBlock_t *)(void *)ph->start;
    SSF_HEAP_SET_BLOCK(hb, ph->len, SSF_HEAP_BLOCK_UNALLOCED, ph->mark, 0);

    /* Initialize the End of Heap Fence Block */
    SSF_HEAP_SET_BLOCK((SSFHeapBlock_t *)(void *)ph->end, sizeof(SSFHeapBlock_t),
                       SSF_HEAP_BLOCK_ALLOCED, ph->mark, 0);

    ph->magic = SSF_HEAP_MAGIC;

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_INIT();
#endif

    *handleOut = ph;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a heap.                                                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFHeapDeInit(SSFHeapHandle_t *handleOut, bool isZeroed)
{
    void *memOut = NULL;
    SSFHeapPrivateHandle_t *ph;

    SSF_REQUIRE(handleOut != NULL);
    SSF_REQUIRE(*handleOut != NULL);
    ph = *handleOut;
    SSF_ASSERT(ph->magic == SSF_HEAP_MAGIC);

    /* No memory may be still allocated by the heap on deinit */
    SSF_ASSERT(SSFHeapMalloc(ph, &memOut, ph->len - sizeof(SSFHeapBlock_t), ph->mark));

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_DEINIT();
#endif

    if (isZeroed) memset(ph->base, 0, ph->baseSize);
    else memset(ph, 0, sizeof(SSFHeapPrivateHandle_t));

    *handleOut = NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if heap allocation succeeds, else false.                                         */
/* --------------------------------------------------------------------------------------------- */
bool SSFHeapAlloc(SSFHeapHandle_t handle, void **memOut, uint32_t memSize, uint8_t mark,
                  bool isZeroed)
{
    SSFHeapBlock_t *hb;
    uint32_t blockMemory;
    uint32_t remainingLen;
    SSFHeapPrivateHandle_t *ph;
    uint32_t requestedSize = memSize;

    SSF_REQUIRE(handle != NULL);
    ph = handle;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_ACQUIRE();
#endif
    SSF_ASSERT(ph->magic == SSF_HEAP_MAGIC);
    SSF_REQUIRE(memOut != NULL);
    SSF_REQUIRE(*memOut == NULL);


    ph->numTotalAllocRequests++;
    remainingLen = ph->len;
    hb = (SSFHeapBlock_t *)(void *)ph->start;

    /* Adjust requested allocation to alignment size */
    if (memSize == 0) memSize = 1;
    SSF_HEAP_ALIGN_LEN(memSize);

    while (true)
    {
        /* Check that block is valid */
        _SSFHeapCheckBlock(ph, hb);

        /* Is block unallocated? */
        if (hb->isAlloced == SSF_HEAP_BLOCK_UNALLOCED)
        {
            /* Yes, condense consecutive free blocks */
            _SSFHeapBlockCondense(ph, hb, remainingLen);

            /* Cache amount of block memory */
            blockMemory = hb->len - sizeof(SSFHeapBlock_t);

            /* Is requested allocation an exact match to the block memory? */
            if (memSize == blockMemory)
            {
                /* Yes, mark block as alloced and set memory ptr */
                SSF_HEAP_SET_BLOCK(hb, hb->len, SSF_HEAP_BLOCK_ALLOCED, mark,
                                   memSize - requestedSize);
                *memOut = SSF_HEAP_U8_CAST(hb) + sizeof(SSFHeapBlock_t);

                /* Zero memory if requested */
                if (isZeroed) memset(*memOut, 0, memSize);

                ph->numAllocRequests++;

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
                SSF_HEAP_SYNC_RELEASE();
#endif
                return true;
            }

            /* Is requested allocation less than the block memory */
            if (memSize < blockMemory)
            {
                /* Yes, save allocated memory pointer */
                *memOut = SSF_HEAP_U8_CAST(hb) + sizeof(SSFHeapBlock_t);

                /* Zero memory if requested */
                if (isZeroed) memset(*memOut, 0, memSize);

                /* Mark block as allocated */
                SSF_HEAP_SET_BLOCK(hb, memSize + sizeof(SSFHeapBlock_t), SSF_HEAP_BLOCK_ALLOCED,
                                   mark, memSize - requestedSize);

                /* Advance to create a new available block */
                hb = (SSFHeapBlock_t*)(void *)(SSF_HEAP_U8_CAST(hb) + hb->len);
                SSF_HEAP_SET_BLOCK(hb, blockMemory - memSize, SSF_HEAP_BLOCK_UNALLOCED, ph->mark, 0);

                ph->numAllocRequests++;

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
                SSF_HEAP_SYNC_RELEASE();
#endif
                return true;
            }
        }

        /* Any more heap left to check? */
        remainingLen -= hb->len;
        if (remainingLen == 0)
        {
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
            SSF_HEAP_SYNC_RELEASE();
#endif
            return false;
        }

        /* Advance to next block */
        hb = (SSFHeapBlock_t *)(void *)(SSF_HEAP_U8_CAST(hb) + hb->len);
    }
    /* Never gets here */
    SSF_ERROR();
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if newMemSize allocation returned with data copied, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFHeapAllocResize(SSFHeapHandle_t handle, void** memOut, uint32_t newMemSize,
                        uint8_t newMark, bool newIsZeroed)
{
    SSFHeapPrivateHandle_t *ph;
    SSFHeapBlock_t *hb;
    uint32_t blockMemory;
    void *newMem = NULL;
    uint32_t newRequestedSize = newMemSize;

    SSF_REQUIRE(handle != NULL);
    ph = handle;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_ACQUIRE();
#endif
    SSF_ASSERT(ph->magic == SSF_HEAP_MAGIC);
    SSF_REQUIRE(memOut != NULL);

    /* Adjust requested allocation to alignment size */
    if (newMemSize == 0) newMemSize = 1;
    SSF_HEAP_ALIGN_LEN(newMemSize);

    /* New allocation? */
    if (*memOut == NULL)
    /* Yes, just alloc the requested block with new mark */
    {
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
        SSF_HEAP_SYNC_RELEASE();
#endif
        return SSFHeapAlloc(handle, memOut, newMemSize, newMark, newIsZeroed);
    }

    /* No, get block pointer and check for integrity */
    hb = (SSFHeapBlock_t*)(void *)(SSF_HEAP_U8_CAST(*memOut) - sizeof(SSFHeapBlock_t));
    _SSFHeapCheckBlock(handle, hb);
    blockMemory = hb->len - sizeof(SSFHeapBlock_t);

    /* Zeroing? */
    if (newIsZeroed)
    {
        /* Yes, make sure spare bytes are cleared properly */
        memset(SSF_HEAP_U8_CAST(*memOut) + blockMemory - hb->spareLen, 0, hb->spareLen);
    }

    /* Requested size same as current size? */
    if (newMemSize == blockMemory)
    {
        /* Yes, just return same memory with new mark */
        SSF_HEAP_SET_BLOCK(hb, hb->len, SSF_HEAP_BLOCK_ALLOCED, newMark,
                           newMemSize - newRequestedSize);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
        SSF_HEAP_SYNC_RELEASE();
#endif
        return true;
    }

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_RELEASE();
#endif

    /* No, can we allocate new memory */
    if (SSFHeapAlloc(handle, &newMem, newRequestedSize, newMark, newIsZeroed) == false)
    {
        /* No, could not handle request, original memory not modified */
        return false;
    }

    /* Yes, copy existing data from old memory to new memory */
    memcpy(newMem, *memOut, SSF_MIN(newMemSize, blockMemory));

    /* Free old memory and return new memory*/
    SSFHeapFree(handle, memOut, NULL);
    *memOut = newMem;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Frees memory from a heap.                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFHeapDealloc(SSFHeapHandle_t handle, void **heapMemOut, uint8_t *markOutOpt, bool isZeroed)
{
    SSFHeapPrivateHandle_t *ph;
    SSFHeapBlock_t *hb;

    SSF_REQUIRE(handle != NULL);
    ph = handle;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_ACQUIRE();
#endif
    SSF_ASSERT(ph->magic == SSF_HEAP_MAGIC);
    SSF_REQUIRE(heapMemOut != NULL);
    SSF_REQUIRE(*heapMemOut != NULL);

    /* Get block pointer and check for integrity */
    hb = (SSFHeapBlock_t*)(void *)(SSF_HEAP_U8_CAST(*heapMemOut) - sizeof(SSFHeapBlock_t));
    _SSFHeapCheckBlock(handle, hb);
    SSF_ASSERT(hb->isAlloced == SSF_HEAP_BLOCK_ALLOCED);

    /* Check next block for potential overrun */
    _SSFHeapCheckBlock(handle, (SSFHeapBlock_t *)(void *)(SSF_HEAP_U8_CAST(hb) + hb->len));

    /* Return debug mark if requested */
    if (markOutOpt != NULL) *markOutOpt = hb->mark;

    /* Free block */
    SSF_HEAP_SET_BLOCK(hb, hb->len, SSF_HEAP_BLOCK_UNALLOCED, ph->mark, 0);
    if (isZeroed) memset(*heapMemOut, 0, hb->len - sizeof(SSFHeapBlock_t));
    *heapMemOut = NULL;
    ph->numFreeRequests++;

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
        SSF_HEAP_SYNC_RELEASE();
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Checks heap integrity, returns if valid else throws assertion.                                */
/* --------------------------------------------------------------------------------------------- */
void SSFHeapCheck(SSFHeapHandle_t handle)
{
    SSFHeapPrivateHandle_t *ph;
    SSFHeapBlock_t* hb;
    uint8_t *mem;
    uint32_t remainingLen;

    SSF_REQUIRE(handle != NULL);
    ph = handle;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_ACQUIRE();
#endif
    SSF_ASSERT(ph->magic == SSF_HEAP_MAGIC);

    hb = (SSFHeapBlock_t*)(void *)ph->start;
    mem = ph->start;
    remainingLen = ph->len;

    while (true)
    {
        /* Check that block is valid and does not go past end of heap */
        _SSFHeapCheckBlock(handle, hb);

        /* Advance to next block */
        SSF_ASSERT(remainingLen >= hb->len);
        remainingLen -= hb->len;
        mem += hb->len;

        /* End of heap? */
        if (remainingLen == 0)
        {
            /* Yes, make sure pointers match and that fence block valid */
            SSF_ASSERT(mem == ph->end);
            _SSFHeapCheckBlock(handle, (SSFHeapBlock_t *)(void *)ph->end);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
            SSF_HEAP_SYNC_RELEASE();
#endif
            return;
        }
        /* No, make sure pointer in range and continue */
        else SSF_ASSERT(mem < ph->end);
        hb = (SSFHeapBlock_t*)(void *)mem;
    }
    SSF_ERROR();
}

/* --------------------------------------------------------------------------------------------- */
/* Reports heap status.                                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFHeapStatus(SSFHeapHandle_t handle, SSFHeapStatus_t *heapStatusOut)
{
    SSFHeapPrivateHandle_t *ph;
    uint32_t remainingLen;
    SSFHeapBlock_t* hb;

    SSF_REQUIRE(handle != NULL);
    ph = handle;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_ACQUIRE();
#endif
    SSF_ASSERT(ph->magic == SSF_HEAP_MAGIC);
    SSF_REQUIRE(heapStatusOut != NULL);

    hb = (SSFHeapBlock_t*)(void *)ph->start;
    remainingLen = ph->len;

    /* These heap status fields are recalculated below */
    memset(heapStatusOut, 0, sizeof(SSFHeapStatus_t));
    heapStatusOut->allocatableSize = ph->len - sizeof(SSFHeapBlock_t);
    heapStatusOut->numTotalAllocRequests = ph->numTotalAllocRequests;
    heapStatusOut->numAllocRequests = ph->numAllocRequests;
    heapStatusOut->numFreeRequests = ph->numFreeRequests;

    /* Condense all heap blocks to properly calculate status */
    while (true)
    {
        /* Check that block is valid */
        _SSFHeapCheckBlock(handle, hb);
        heapStatusOut->numBlocks++;

        /* Is block unallocated? */
        if (hb->isAlloced == SSF_HEAP_BLOCK_UNALLOCED)
        {
            /* Yes, condense consecutive free blocks */
            _SSFHeapBlockCondense(handle, hb, remainingLen);

            /* Update status */
            heapStatusOut->allocatableLen += (hb->len - sizeof(SSFHeapBlock_t));
            heapStatusOut->numAllocatableBlocks++;
            if ((hb->len - sizeof(SSFHeapBlock_t)) > heapStatusOut->maxAllocatableBlockLen)
            { heapStatusOut->maxAllocatableBlockLen = hb->len - sizeof(SSFHeapBlock_t); }
        }

        /* Any more heap left to check? */
        remainingLen -= hb->len;
        if (remainingLen == 0) break;;

        /* Advance to next block */
        hb = (SSFHeapBlock_t*)(void *)(SSF_HEAP_U8_CAST(hb) + hb->len);
    }

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_HEAP_SYNC_RELEASE();
#endif
}

