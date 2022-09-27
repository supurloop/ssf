/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmpool.c                                                                                    */
/* Provides memory pool interface with fixed max block size.                                     */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#include <stdlib.h>
#include <string.h>
#include "ssfll.h"
#include "ssfmpool.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MPOOL_INIT_MAGIC (0x43130817ul)

#if SSF_MPOOL_DEBUG == 1
typedef struct SSFMPoolDebug
{
    SSFLLItem_t item;
    SSFLLItem_t *block;
} SSFMPoolDebug_t;
#endif

/* --------------------------------------------------------------------------------------------- */
/* Initializes a memory pool.                                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFMPoolInit(SSFMPool_t *pool, uint32_t blocks, uint32_t blockSize)
{
    uint32_t memSize = blockSize + sizeof(SSFLLItem_t) + sizeof(uint32_t);
    uint32_t i;
#if SSF_MPOOL_DEBUG == 1
    SSFMPoolDebug_t *w;
#endif /* SSF_MPOOL_DEBUG */

    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(blocks > 0);
    SSF_REQUIRE(blockSize > 0);
    SSF_ASSERT(pool->magic != SSF_MPOOL_INIT_MAGIC);

    SSFLLInit(&(pool->avail), blocks);
#if SSF_MPOOL_DEBUG == 1
    SSFLLInit(&(pool->world), blocks);
#endif /* SSF_MPOOL_DEBUG */

    for (i = 0; i < blocks; i++)
    {
        SSFLLItem_t *mem;
        SSF_ASSERT((mem = (SSFLLItem_t*)malloc(memSize)) != NULL);
        memset(mem, 0, memSize);
        memcpy(((uint8_t *)mem) + blockSize + sizeof(SSFLLItem_t), "\x12\x34\x56\xff", sizeof(uint32_t));
        SSF_LL_FIFO_PUSH(&(pool->avail), mem);
#if SSF_MPOOL_DEBUG == 1
        SSF_ASSERT((w = (SSFMPoolDebug_t *)malloc(sizeof(SSFMPoolDebug_t))) != NULL);
        memset(w, 0, sizeof(SSFMPoolDebug_t));
        w->block = (SSFLLItem_t *)mem;
        SSF_LL_FIFO_PUSH(&(pool->world), w);
#endif /* SSF_MPOOL_DEBUG */
    }
    pool->blocks = blocks;
    pool->blockSize = blockSize;
    pool->magic = SSF_MPOOL_INIT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a memory pool.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFMPoolDeInit(SSFMPool_t *pool)
{
    uint32_t i;
    uint32_t memSize;

    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    memSize = pool->blockSize + sizeof(SSFLLItem_t) + sizeof(uint32_t);
    for (i = 0; i < pool->blocks; i++)
    {
        SSFLLItem_t *mem = NULL;
#if SSF_MPOOL_DEBUG == 1
    SSFMPoolDebug_t *w = NULL;
#endif /* SSF_MPOOL_DEBUG */

        SSF_LL_FIFO_POP(&(pool->avail), &mem);
        SSF_ASSERT(mem != NULL);
        memset(mem, 0, memSize);
        free(mem);
#if SSF_MPOOL_DEBUG == 1
        SSF_LL_FIFO_POP(&(pool->world), &w);
        SSF_ASSERT(w != NULL);
        memset(w, 0, sizeof(SSFMPoolDebug_t));
        free(w);
#endif /* SSF_MPOOL_DEBUG */
    }

#if SSF_MPOOL_DEBUG == 1
    SSFLLDeInit(&(pool->world));
#endif /* SSF_MPOOL_DEBUG */
    SSFLLDeInit(&(pool->avail));
    memset(pool, 0, sizeof(SSFMPool_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Allocates a block from the pool.                                                              */
/* --------------------------------------------------------------------------------------------- */
void* SSFMPoolAlloc(SSFMPool_t *pool, uint32_t size, uint8_t owner)
{
    SSFLLItem_t *mem;
    uint8_t *p;

    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(size <= pool->blockSize);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    SSF_ASSERT(SSF_LL_FIFO_POP(&(pool->avail), &mem) == true);

    p = ((uint8_t *)mem) + sizeof(SSFLLItem_t) + pool->blockSize;
    SSF_ASSERT(memcmp(p, "\x12\x34\x56", sizeof(uint32_t) - 1) == 0);
    p += sizeof(uint32_t) - 1;
    *p = owner;

    return (void *)(((uint8_t *)mem) + sizeof(SSFLLItem_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a block to the pool, always returns NULL.                                             */
/* --------------------------------------------------------------------------------------------- */
void* SSFMPoolFree(SSFMPool_t *pool, void *mpool)
{
    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(mpool != NULL);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    SSF_ASSERT(memcmp(((uint8_t *)mpool) + pool->blockSize, "\x12\x34\x56",
                      sizeof(uint32_t) - 1) == 0);
    SSF_LL_FIFO_PUSH(&(pool->avail), ((SSFLLItem_t *) mpool) - 1);
    return NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns pool block size.                                                                      */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFMPoolBlockSize(const SSFMPool_t *pool)
{
    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    return pool->blockSize;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns pool total number of blocks.                                                          */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFMPoolSize(const SSFMPool_t *pool)
{
    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    return pool->blocks;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns number pool blocks available.                                                         */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFMPoolLen(const SSFMPool_t *pool)
{
    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    return SSFLLLen(&(pool->avail));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pool empty, else false.                                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFMPoolIsEmpty(const SSFMPool_t *pool)
{
    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    return SSFLLIsEmpty(&(pool->avail));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pool full, else false.                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFMPoolIsFull(const SSFMPool_t *pool)
{
    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(pool->magic == SSF_MPOOL_INIT_MAGIC);

    return SSFLLIsFull(&(pool->avail));
}
