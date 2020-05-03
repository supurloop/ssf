/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmpool_ut.c                                                                                 */
/* Provides unit tests for ssfmpool's memory pool interface.                                     */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfmpool.h"
#include "ssfport.h"
#include "ssfassert.h"

#if SSF_CONFIG_MPOOL_UNIT_TEST == 1

    #define SMP_TEST_BLOCK_SIZE (42UL)
    #define SMP_TEST_BLOCKS (10UL)

SSFMPool_t smpTestPool;
void *smpTestPtrs[SMP_TEST_BLOCKS];

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfll's external interface.                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFMPoolUnitTest()
{
    uint32_t i;
    void *testPtr;

    SSF_ASSERT_TEST(SSFMPoolInit(NULL, SMP_TEST_BLOCKS, SMP_TEST_BLOCK_SIZE));
    SSF_ASSERT_TEST(SSFMPoolInit(&smpTestPool, 0, SMP_TEST_BLOCK_SIZE));
    SSF_ASSERT_TEST(SSFMPoolInit(&smpTestPool, SMP_TEST_BLOCKS, 0));
    SSF_ASSERT_TEST(SSFMPoolAlloc(&smpTestPool, SMP_TEST_BLOCK_SIZE, 0));
    SSF_ASSERT_TEST(SSFMPoolFree(&smpTestPool, (void *)1));
    SSF_ASSERT_TEST(SSFMPoolBlockSize(&smpTestPool));
    SSF_ASSERT_TEST(SSFMPoolSize(&smpTestPool));
    SSF_ASSERT_TEST(SSFMPoolLen(&smpTestPool));
    SSF_ASSERT_TEST(SSFMPoolIsEmpty(&smpTestPool));
    SSF_ASSERT_TEST(SSFMPoolIsFull(&smpTestPool));

    SSFMPoolInit(&smpTestPool, SMP_TEST_BLOCKS, SMP_TEST_BLOCK_SIZE);
    SSF_ASSERT_TEST(SSFMPoolInit(&smpTestPool, SMP_TEST_BLOCKS, SMP_TEST_BLOCK_SIZE));
    SSF_ASSERT(SSFMPoolBlockSize(&smpTestPool) == SMP_TEST_BLOCK_SIZE);
    SSF_ASSERT(SSFMPoolSize(&smpTestPool) == SMP_TEST_BLOCKS);
    SSF_ASSERT(SSFMPoolLen(&smpTestPool) == SMP_TEST_BLOCKS);
    SSF_ASSERT(SSFMPoolIsEmpty(&smpTestPool) == false);
    SSF_ASSERT(SSFMPoolIsFull(&smpTestPool) == true);

    SSF_ASSERT_TEST(SSFMPoolAlloc(NULL, SMP_TEST_BLOCK_SIZE, 0));
    SSF_ASSERT_TEST(SSFMPoolAlloc(&smpTestPool, SMP_TEST_BLOCK_SIZE + 1, 0));
    SSF_ASSERT_TEST(SSFMPoolFree(NULL, (void *)1));
    SSF_ASSERT_TEST(SSFMPoolFree(&smpTestPool, NULL));
    SSF_ASSERT_TEST(SSFMPoolBlockSize(NULL));
    SSF_ASSERT_TEST(SSFMPoolSize(NULL));
    SSF_ASSERT_TEST(SSFMPoolLen(NULL));
    SSF_ASSERT_TEST(SSFMPoolIsEmpty(NULL));
    SSF_ASSERT_TEST(SSFMPoolIsFull(NULL));

    /* Alloc all the blocks */
    for (i = 0; i < SMP_TEST_BLOCKS - 1; i++)
    {
        smpTestPtrs[i] = SSFMPoolAlloc(&smpTestPool, i % SMP_TEST_BLOCK_SIZE, (uint8_t)i);
        SSF_ASSERT(smpTestPtrs[i] != NULL);
        SSF_ASSERT(SSFMPoolBlockSize(&smpTestPool) == SMP_TEST_BLOCK_SIZE);
        SSF_ASSERT(SSFMPoolSize(&smpTestPool) == SMP_TEST_BLOCKS);
        SSF_ASSERT(SSFMPoolLen(&smpTestPool) == SMP_TEST_BLOCKS - (i + 1));
        SSF_ASSERT(SSFMPoolIsEmpty(&smpTestPool) == false);
        SSF_ASSERT(SSFMPoolIsFull(&smpTestPool) == false);
    }
    smpTestPtrs[i] = SSFMPoolAlloc(&smpTestPool, i % SMP_TEST_BLOCK_SIZE, (uint8_t)i);
    SSF_ASSERT(smpTestPtrs[i] != NULL);
    SSF_ASSERT(SSFMPoolBlockSize(&smpTestPool) == SMP_TEST_BLOCK_SIZE);
    SSF_ASSERT(SSFMPoolSize(&smpTestPool) == SMP_TEST_BLOCKS);
    SSF_ASSERT(SSFMPoolLen(&smpTestPool) == 0);
    SSF_ASSERT(SSFMPoolIsEmpty(&smpTestPool) == true);
    SSF_ASSERT(SSFMPoolIsFull(&smpTestPool) == false);
    SSF_ASSERT_TEST(SSFMPoolAlloc(&smpTestPool, SMP_TEST_BLOCK_SIZE, 0));

    /* Free all the blocks */
    for (i = 0; i < SMP_TEST_BLOCKS - 1; i++)
    {
        smpTestPtrs[i] = SSFMPoolFree(&smpTestPool, smpTestPtrs[i]);
        SSF_ASSERT(smpTestPtrs[i] == NULL);
        SSF_ASSERT(SSFMPoolBlockSize(&smpTestPool) == SMP_TEST_BLOCK_SIZE);
        SSF_ASSERT(SSFMPoolSize(&smpTestPool) == SMP_TEST_BLOCKS);
        SSF_ASSERT(SSFMPoolLen(&smpTestPool) == (i + 1));
        SSF_ASSERT(SSFMPoolIsEmpty(&smpTestPool) == false);
        SSF_ASSERT(SSFMPoolIsFull(&smpTestPool) == false);
    }
    testPtr = smpTestPtrs[i];
    smpTestPtrs[i] = SSFMPoolFree(&smpTestPool, smpTestPtrs[i]);
    SSF_ASSERT(smpTestPtrs[i] == NULL);
    SSF_ASSERT(SSFMPoolBlockSize(&smpTestPool) == SMP_TEST_BLOCK_SIZE);
    SSF_ASSERT(SSFMPoolSize(&smpTestPool) == SMP_TEST_BLOCKS);
    SSF_ASSERT(SSFMPoolLen(&smpTestPool) == SMP_TEST_BLOCKS);
    SSF_ASSERT(SSFMPoolIsEmpty(&smpTestPool) == false);
    SSF_ASSERT(SSFMPoolIsFull(&smpTestPool) == true);
    SSF_ASSERT_TEST(SSFMPoolFree(&smpTestPool, testPtr));
}
#endif /* SSF_CONFIG_MPOOL_UNIT_TEST */

