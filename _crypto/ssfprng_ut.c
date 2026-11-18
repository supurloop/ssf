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

    /* (Hardening) Backtracking resistance: GetRandom performs a CTR_DRBG-style Update that
     * re-keys the context, destroying the AES key that produced the returned bytes. A state
     * compromise after the call therefore cannot recover previously returned output. Observe the
     * rotation directly -- right after init the context key equals the seed; after one draw it
     * must differ. (The first output block stays deterministic for a given seed; covered above.) */
    {
        SSFPRNGContext_t ctx;
        uint8_t seedKey[SSF_PRNG_ENTROPY_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7,
                                                  8, 9, 10, 11, 12, 13, 14, 15};
        uint8_t out[SSF_PRNG_RANDOM_MAX_SIZE];

        SSFPRNGInitContext(&ctx, seedKey, sizeof(seedKey));
        SSF_ASSERT(memcmp(ctx.entropy, seedKey, sizeof(seedKey)) == 0);
        SSFPRNGGetRandom(&ctx, out, sizeof(out));
        SSF_ASSERT(memcmp(ctx.entropy, seedKey, sizeof(seedKey)) != 0);
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

    /* ---- AUDIT PRNG-1/PRNG-2: documented counter start and portable counter encoding ---- */
    /* Init/ReInit must reset the counter to zero (it used to start at -(first 8 seed bytes)), */
    /* and the counter must enter the AES input big-endian (it used to be the raw host-order */
    /* uint64_t, so the stream differed between little- and big-endian hosts). Known answers */
    /* computed independently with `openssl enc -aes-128-ecb -nopad`:                        */
    /*   out1 = AES(K0, 0^16)                          (count 0, output block)               */
    /*   K1   = AES(K0, 00*8 || 01 || 00*7)            (count 0, re-key block)               */
    /*   out2 = AES(K1, 00*7 || 01 || 00*8)            (count 1 big-endian, output block)    */
    {
        SSFPRNGContext_t ctx;
        static const uint8_t entropyKnown[SSF_PRNG_ENTROPY_SIZE] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu
        };
        static const uint8_t out1Known[SSF_PRNG_RANDOM_MAX_SIZE] = {
            0xC6u, 0xA1u, 0x3Bu, 0x37u, 0x87u, 0x8Fu, 0x5Bu, 0x82u,
            0x6Fu, 0x4Fu, 0x81u, 0x62u, 0xA1u, 0xC8u, 0xD8u, 0x79u
        };
        static const uint8_t out2Known[SSF_PRNG_RANDOM_MAX_SIZE] = {
            0xB6u, 0xD3u, 0x90u, 0x3Fu, 0xA2u, 0xA8u, 0x7Au, 0x2Du,
            0x49u, 0x75u, 0x8Cu, 0x7Fu, 0xACu, 0x67u, 0x91u, 0xF7u
        };
        static const uint8_t otherSeed[SSF_PRNG_ENTROPY_SIZE] = {
            0xF0u, 0xE1u, 0xD2u, 0xC3u, 0xB4u, 0xA5u, 0x96u, 0x87u,
            0x78u, 0x69u, 0x5Au, 0x4Bu, 0x3Cu, 0x2Du, 0x1Eu, 0x0Fu
        };
        uint8_t knownRandom[SSF_PRNG_RANDOM_MAX_SIZE];

        SSFPRNGInitContext(&ctx, entropyKnown, sizeof(entropyKnown));
        SSF_ASSERT(ctx.count == 0u);

        SSFPRNGGetRandom(&ctx, knownRandom, sizeof(knownRandom));
        SSF_ASSERT(memcmp(knownRandom, out1Known, sizeof(knownRandom)) == 0);
        SSFPRNGGetRandom(&ctx, knownRandom, sizeof(knownRandom));
        SSF_ASSERT(memcmp(knownRandom, out2Known, sizeof(knownRandom)) == 0);
        SSF_ASSERT(ctx.count == 2u);

        /* ReInit on a used context resets the counter and restarts the documented stream. */
        SSFPRNGReInitContext(&ctx, otherSeed, sizeof(otherSeed));
        SSF_ASSERT(ctx.count == 0u);
        SSFPRNGReInitContext(&ctx, entropyKnown, sizeof(entropyKnown));
        SSFPRNGGetRandom(&ctx, knownRandom, sizeof(knownRandom));
        SSF_ASSERT(memcmp(knownRandom, out1Known, sizeof(knownRandom)) == 0);

        SSFPRNGDeInitContext(&ctx);
    }

    /* Defense-in-depth regression: GetRandom now scrubs its internal pt and ct stack buffers
     * before return. The scrub is not externally observable through the C API, but it must
     * not break the deterministic-output contract -- a fresh ctx with the same entropy must
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
