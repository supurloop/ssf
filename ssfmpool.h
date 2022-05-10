/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmpool.h                                                                                    */
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
#ifndef SSF_MPOOL_INCLUDE_H
#define SSF_MPOOL_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "ssfport.h"
#include "ssfll.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
typedef struct SSFMPool
{
    SSFLL_t avail;
#if SSF_MPOOL_DEBUG == 1
    SSFLL_t world;
#endif
    uint32_t blocks;
    uint32_t blockSize;
    uint32_t magic;
} SSFMPool_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFMPoolInit(SSFMPool_t *pool, uint32_t blocks, uint32_t blockSize);
void* SSFMPoolAlloc(SSFMPool_t *pool, uint32_t size, uint8_t owner);
void* SSFMPoolFree(SSFMPool_t *pool, void *mpool);
uint32_t SSFMPoolBlockSize(const SSFMPool_t *pool);
uint32_t SSFMPoolSize(const SSFMPool_t *pool);
uint32_t SSFMPoolLen(const SSFMPool_t *pool);
bool SSFMPoolIsEmpty(const SSFMPool_t *pool);
bool SSFMPoolIsFull(const SSFMPool_t *pool);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_MPOOL_UNIT_TEST == 1
void SSFMPoolUnitTest(void);
#endif /* SSF_CONFIG_MPOOL_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_MEMPOOL_INCLUDE_H */

