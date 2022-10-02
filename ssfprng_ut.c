/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfprng_ut.c                                                                                  */
/* Provides unit test for cryptographically secure capable pseudo random number generator (PRNG).*/
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#include <stdio.h>
#include <stdlib.h>
#include "ssfprng.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on PRNG external interface.                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFPRNGUnitTest(void)
{
    SSFPRNGContext_t context;
    SSFPRNGContext_t contextZero;
    uint8_t entropy[SSF_PRNG_ENTROPY_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                                               15 };
    uint8_t random[SSF_PRNG_RANDOM_MAX_SIZE];
    size_t i;
    uint64_t lastCount;

    SSF_ASSERT_TEST(SSFPRNGInitContext(NULL, entropy, sizeof(entropy)));
    SSF_ASSERT_TEST(SSFPRNGInitContext(&context, NULL, sizeof(entropy)));
    SSF_ASSERT_TEST(SSFPRNGInitContext(&context, entropy, sizeof(entropy) - 1));
    SSF_ASSERT_TEST(SSFPRNGInitContext(&context, entropy, sizeof(entropy) + 1));
    SSF_ASSERT_TEST(SSFPRNGInitContext(&context, entropy, 0));

    SSF_ASSERT_TEST(SSFPRNGDeInitContext(NULL));
    memset(&context, 0, sizeof(context));
    SSF_ASSERT_TEST(SSFPRNGDeInitContext(&context));

    SSF_ASSERT_TEST(SSFPRNGGetRandom(NULL, random, sizeof(random)));
    SSF_ASSERT_TEST(SSFPRNGGetRandom(&context, NULL, sizeof(random)));
    SSF_ASSERT_TEST(SSFPRNGGetRandom(&context, random, 0));
    SSF_ASSERT_TEST(SSFPRNGGetRandom(&context, random, sizeof(random) + 1));
    SSF_ASSERT_TEST(SSFPRNGGetRandom(&context, random, sizeof(random)));

    SSFPRNGInitContext(&context, entropy, sizeof(entropy));

    for (i = 1; i <= SSF_PRNG_RANDOM_MAX_SIZE; i++)
    {
        lastCount = context.count;
        SSFPRNGGetRandom(&context, random, i);
        SSF_ASSERT((lastCount + 1) == context.count);
    }

    SSFPRNGDeInitContext(&context);
    memset(&contextZero, 0, sizeof(contextZero));
    SSF_ASSERT(memcmp(&context, &contextZero, sizeof(context)) == 0);
}
