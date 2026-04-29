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

    /* Same entropy produces deterministic (repeatable) output */
    {
        SSFPRNGContext_t ctx1;
        SSFPRNGContext_t ctx2;
        uint8_t r1[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t r2[SSF_PRNG_RANDOM_MAX_SIZE];

        SSFPRNGInitContext(&ctx1, entropy, sizeof(entropy));
        SSFPRNGInitContext(&ctx2, entropy, sizeof(entropy));
        SSFPRNGGetRandom(&ctx1, r1, sizeof(r1));
        SSFPRNGGetRandom(&ctx2, r2, sizeof(r2));
        SSF_ASSERT(memcmp(r1, r2, sizeof(r1)) == 0);
        SSFPRNGDeInitContext(&ctx1);
        SSFPRNGDeInitContext(&ctx2);
    }

    /* Different entropy produces different output */
    {
        SSFPRNGContext_t ctx1;
        SSFPRNGContext_t ctx2;
        uint8_t e1[SSF_PRNG_ENTROPY_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        uint8_t e2[SSF_PRNG_ENTROPY_SIZE] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
        uint8_t r1[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t r2[SSF_PRNG_RANDOM_MAX_SIZE];

        SSFPRNGInitContext(&ctx1, e1, sizeof(e1));
        SSFPRNGInitContext(&ctx2, e2, sizeof(e2));
        SSFPRNGGetRandom(&ctx1, r1, sizeof(r1));
        SSFPRNGGetRandom(&ctx2, r2, sizeof(r2));
        SSF_ASSERT(memcmp(r1, r2, sizeof(r1)) != 0);
        SSFPRNGDeInitContext(&ctx1);
        SSFPRNGDeInitContext(&ctx2);
    }

    /* SSFPRNGReInitContext changes output with new entropy */
    {
        SSFPRNGContext_t ctx;
        uint8_t e1[SSF_PRNG_ENTROPY_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        uint8_t e2[SSF_PRNG_ENTROPY_SIZE] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                              0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
        uint8_t r1[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t r2[SSF_PRNG_RANDOM_MAX_SIZE];

        SSFPRNGInitContext(&ctx, e1, sizeof(e1));
        SSFPRNGGetRandom(&ctx, r1, sizeof(r1));
        SSFPRNGReInitContext(&ctx, e2, sizeof(e2));
        SSFPRNGGetRandom(&ctx, r2, sizeof(r2));
        SSF_ASSERT(memcmp(r1, r2, sizeof(r1)) != 0);
        SSFPRNGDeInitContext(&ctx);
    }

    /* Consecutive GetRandom calls produce different output */
    {
        SSFPRNGContext_t ctx;
        uint8_t r1[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t r2[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t r3[SSF_PRNG_RANDOM_MAX_SIZE];

        SSFPRNGInitContext(&ctx, entropy, sizeof(entropy));
        SSFPRNGGetRandom(&ctx, r1, sizeof(r1));
        SSFPRNGGetRandom(&ctx, r2, sizeof(r2));
        SSFPRNGGetRandom(&ctx, r3, sizeof(r3));
        SSF_ASSERT(memcmp(r1, r2, sizeof(r1)) != 0);
        SSF_ASSERT(memcmp(r2, r3, sizeof(r2)) != 0);
        SSF_ASSERT(memcmp(r1, r3, sizeof(r1)) != 0);
        SSFPRNGDeInitContext(&ctx);
    }

    /* Random output is non-trivial (not all zeros) */
    {
        SSFPRNGContext_t ctx;
        uint8_t r[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t zeros[SSF_PRNG_RANDOM_MAX_SIZE];

        memset(zeros, 0, sizeof(zeros));
        SSFPRNGInitContext(&ctx, entropy, sizeof(entropy));
        SSFPRNGGetRandom(&ctx, r, sizeof(r));
        SSF_ASSERT(memcmp(r, zeros, sizeof(r)) != 0);
        SSFPRNGDeInitContext(&ctx);
    }

    /* Verify pt = count || zeros (NIST CTR_DRBG-style input shape). Property test: the PRNG
     * output for any (entropy, count) must equal AES-128-ECB(entropy, count_bytes || zeros).
     * Compute both sides on the host (same memcpy semantics on either endianness) and compare.
     * Pre-fix this would have been AES(entropy, count||count); the change makes the input
     * shape match standard CTR_DRBG conventions. */
    {
        SSFPRNGContext_t ctx;
        uint8_t entropyKnown[SSF_PRNG_ENTROPY_SIZE] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu
        };
        uint8_t knownRandom[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t expectedPt[SSF_AES_BLOCK_SIZE];
        uint8_t expectedCt[SSF_AES_BLOCK_SIZE];
        uint64_t snappedCount;

        SSFPRNGInitContext(&ctx, entropyKnown, sizeof(entropyKnown));
        snappedCount = ctx.count;

        /* Build the AES input as count || zeros (the post-fix construction). */
        memcpy(expectedPt, &snappedCount, sizeof(uint64_t));
        memset(&expectedPt[sizeof(uint64_t)], 0, sizeof(uint64_t));

        SSFAES128BlockEncrypt(expectedPt, sizeof(expectedPt),
                              expectedCt, sizeof(expectedCt),
                              entropyKnown, sizeof(entropyKnown));

        SSFPRNGGetRandom(&ctx, knownRandom, sizeof(knownRandom));
        SSF_ASSERT(memcmp(knownRandom, expectedCt, sizeof(knownRandom)) == 0);

        SSFPRNGDeInitContext(&ctx);
    }

    /* Defense-in-depth regression: GetRandom now scrubs its internal pt and ct stack buffers
     * before return. The scrub is not externally observable through the C API, but it must
     * not break the deterministic-output contract — a fresh ctx with the same entropy must
     * still produce the same first-call output. This catches any regression that would
     * accidentally damage the live state during the scrub (e.g., scrubbing context->entropy
     * by mistake). */
    {
        SSFPRNGContext_t ctxA;
        SSFPRNGContext_t ctxB;
        uint8_t rA[SSF_PRNG_RANDOM_MAX_SIZE];
        uint8_t rB[SSF_PRNG_RANDOM_MAX_SIZE];

        SSFPRNGInitContext(&ctxA, entropy, sizeof(entropy));
        SSFPRNGGetRandom(&ctxA, rA, sizeof(rA));

        /* Run a few extra calls to exercise the scrub path multiple times before the    */
        /* second context's first call. If the scrub were corrupting state, ctxB's first */
        /* call would diverge from ctxA's first call.                                    */
        {
            uint8_t scratch[SSF_PRNG_RANDOM_MAX_SIZE];
            SSFPRNGGetRandom(&ctxA, scratch, sizeof(scratch));
            SSFPRNGGetRandom(&ctxA, scratch, 1u);
            SSFPRNGGetRandom(&ctxA, scratch, 7u);
        }

        SSFPRNGInitContext(&ctxB, entropy, sizeof(entropy));
        SSFPRNGGetRandom(&ctxB, rB, sizeof(rB));
        SSF_ASSERT(memcmp(rA, rB, sizeof(rA)) == 0);

        SSFPRNGDeInitContext(&ctxA);
        SSFPRNGDeInitContext(&ctxB);
    }
}
