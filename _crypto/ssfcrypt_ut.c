/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcrypt_ut.c                                                                                 */
/* Provides unit tests for the ssfcrypt high-level cryptographic helpers.                        */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
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
#include <string.h>
#include "ssfcrypt.h"
#include "ssfassert.h"
#include "ssfport.h"

#if SSF_CONFIG_CRYPT_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfcrypt external interface.                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFCryptUnitTest(void)
{
    /* ---- SSFCryptCTMemEq ---- */

    /* NULL-argument assertions. The contract requires non-NULL pointers even when n is 0,
       so exercise both n>0 and n==0 to pin the documented behavior. */
    {
        uint8_t buf[4] = {0};
        SSF_ASSERT_TEST(SSFCryptCTMemEq(NULL, buf, 4u));
        SSF_ASSERT_TEST(SSFCryptCTMemEq(buf, NULL, 4u));
        SSF_ASSERT_TEST(SSFCryptCTMemEq(NULL, buf, 0u));
        SSF_ASSERT_TEST(SSFCryptCTMemEq(buf, NULL, 0u));
    }

    /* Zero-length input compares equal regardless of pointer values. */
    {
        uint8_t a[1] = {0xAA};
        uint8_t b[1] = {0x55};
        SSF_ASSERT(SSFCryptCTMemEq(a, b, 0u) == true);
        SSF_ASSERT(SSFCryptCTMemEq(a, a, 0u) == true);
    }

    /* Single-byte equal and single-byte mismatch. */
    {
        uint8_t a = 0xA5;
        uint8_t b = 0xA5;
        uint8_t c = 0xA4;
        SSF_ASSERT(SSFCryptCTMemEq(&a, &b, 1u) == true);
        SSF_ASSERT(SSFCryptCTMemEq(&a, &c, 1u) == false);
    }

    /* Multi-byte equal, and same buffer against itself. */
    {
        const uint8_t a[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        const uint8_t b[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        SSF_ASSERT(SSFCryptCTMemEq(a, b, 6u) == true);
        SSF_ASSERT(SSFCryptCTMemEq(a, a, 6u) == true);
    }

    /* Mismatch at first, middle, and last positions. Each must return false —
       proves the whole-buffer scan behavior by induction. */
    {
        const uint8_t base[6]    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        uint8_t       diffFirst[6] = {0x01, 0x11, 0x22, 0x33, 0x44, 0x55};
        uint8_t       diffMid[6]   = {0x00, 0x11, 0x22, 0x77, 0x44, 0x55};
        uint8_t       diffLast[6]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};
        SSF_ASSERT(SSFCryptCTMemEq(base, diffFirst, 6u) == false);
        SSF_ASSERT(SSFCryptCTMemEq(base, diffMid,   6u) == false);
        SSF_ASSERT(SSFCryptCTMemEq(base, diffLast,  6u) == false);
    }

    /* Typical MAC-length buffers (32 bytes = SHA-256 output). */
    {
        uint8_t zeros[32];
        uint8_t ones[32];
        uint8_t diff0[32];
        uint8_t diff31[32];
        memset(zeros, 0x00, sizeof(zeros));
        memset(ones,  0xFF, sizeof(ones));
        memset(diff0, 0x00, sizeof(diff0));  diff0[0]  = 0x01;
        memset(diff31, 0x00, sizeof(diff31)); diff31[31] = 0x01;

        SSF_ASSERT(SSFCryptCTMemEq(zeros, zeros, 32u) == true);
        SSF_ASSERT(SSFCryptCTMemEq(zeros, ones,  32u) == false);
        SSF_ASSERT(SSFCryptCTMemEq(zeros, diff0, 32u) == false);
        SSF_ASSERT(SSFCryptCTMemEq(zeros, diff31, 32u) == false);
    }

    /* Long buffer (exercise multi-iteration path). */
    {
        uint8_t a[256];
        uint8_t b[256];
        size_t i;
        for (i = 0; i < sizeof(a); i++) { a[i] = (uint8_t)i; b[i] = (uint8_t)i; }
        SSF_ASSERT(SSFCryptCTMemEq(a, b, sizeof(a)) == true);
        b[128] ^= 0x01;
        SSF_ASSERT(SSFCryptCTMemEq(a, b, sizeof(a)) == false);
    }

    /* void * ergonomics: accepts differing pointer types without casts at the call site. */
    {
        const char  *s1 = "hello";
        const char  *s2 = "hello";
        const char  *s3 = "help!";
        SSF_ASSERT(SSFCryptCTMemEq(s1, s2, 5u) == true);
        SSF_ASSERT(SSFCryptCTMemEq(s1, s3, 5u) == false);
    }

    /* Sweep every byte position: a single-bit flip at any index must register false.
       Catches off-by-one errors in the loop bound (e.g., scanning n-1 bytes instead of n). */
    {
        uint8_t a[64];
        uint8_t b[64];
        size_t pos;
        memset(a, 0x33, sizeof(a));
        for (pos = 0; pos < sizeof(a); pos++)
        {
            memcpy(b, a, sizeof(a));
            b[pos] ^= 0x01u;
            SSF_ASSERT(SSFCryptCTMemEq(a, b, sizeof(a)) == false);
        }
    }

    /* Multi-position mismatch: two or more differing bytes must still return false.
       The OR-accumulator is monotonic so no XOR cancellation can mask the mismatch,
       but exercise it explicitly with values whose XOR results overlap. */
    {
        uint8_t a[16];
        uint8_t b[16];
        memset(a, 0x00, sizeof(a));
        memset(b, 0x00, sizeof(b));
        b[3]  = 0x01u;
        b[10] = 0x02u;
        SSF_ASSERT(SSFCryptCTMemEq(a, b, sizeof(a)) == false);
        b[3]  = 0x55u;
        b[10] = 0x55u;
        SSF_ASSERT(SSFCryptCTMemEq(a, b, sizeof(a)) == false);
    }

    /* Misaligned pointers: the byte-by-byte read path must not depend on word alignment.
       Sweep both arguments through every offset 0..7 within a backing array. */
    {
        uint8_t bufA[40];
        uint8_t bufB[40];
        size_t offA;
        size_t offB;
        for (offA = 0; offA < 8u; offA++)
        {
            for (offB = 0; offB < 8u; offB++)
            {
                memset(bufA, 0x77, sizeof(bufA));
                memset(bufB, 0x77, sizeof(bufB));
                SSF_ASSERT(SSFCryptCTMemEq(&bufA[offA], &bufB[offB], 16u) == true);
                bufB[offB + 7u] = 0x88u;
                SSF_ASSERT(SSFCryptCTMemEq(&bufA[offA], &bufB[offB], 16u) == false);
            }
        }
    }

#if SSF_CONFIG_CRYPT_CT_TIMING_TEST == 1
    /* Wall-clock check that runtime is independent of the position of the first differing
       byte. Times CT_ITERS calls of SSFCryptCTMemEq with a mismatch at byte 0 (a non-CT
       memcmp would short-circuit immediately) and another CT_ITERS calls with a mismatch
       at byte n-1 (memcmp would scan the entire buffer). The min-of-trials reduces
       scheduler / cache jitter. The 10x ratio threshold is far above typical wall-clock
       noise (even on QEMU) and far below the >>1000x speedup a memcmp-class regression
       would produce. The +5ms slop guards against ms-quantized "early" measurements. */
    {
        enum { CT_BUF_SIZE = 2048, CT_ITERS = 30000, CT_TRIALS = 3 };
        static uint8_t ctA[CT_BUF_SIZE];
        static uint8_t ctB[CT_BUF_SIZE];
        volatile uint64_t sink = 0;
        uint64_t earlyMs[CT_TRIALS];
        uint64_t lateMs[CT_TRIALS];
        uint64_t earlyMin;
        uint64_t lateMin;
        SSFPortTick_t t0;
        SSFPortTick_t t1;
        uint32_t i;
        uint32_t trial;

        memset(ctA, 0xAA, sizeof(ctA));
        memset(ctB, 0xAA, sizeof(ctB));

        /* Warmup: prime caches and let any one-shot init settle. */
        for (i = 0; i < 1000u; i++)
        {
            sink += (uint64_t)SSFCryptCTMemEq(ctA, ctB, sizeof(ctA));
        }

        for (trial = 0; trial < CT_TRIALS; trial++)
        {
            /* Late mismatch: differs at byte n-1; CT impl must scan the whole buffer. */
            ctB[CT_BUF_SIZE - 1u] = 0x55u;
            t0 = SSFPortGetTick64();
            for (i = 0; i < CT_ITERS; i++)
            {
                sink += (uint64_t)SSFCryptCTMemEq(ctA, ctB, sizeof(ctA));
            }
            t1 = SSFPortGetTick64();
            lateMs[trial] = (uint64_t)(t1 - t0);
            ctB[CT_BUF_SIZE - 1u] = 0xAAu;

            /* Early mismatch: differs at byte 0; a non-CT memcmp would return after one byte. */
            ctB[0] = 0x55u;
            t0 = SSFPortGetTick64();
            for (i = 0; i < CT_ITERS; i++)
            {
                sink += (uint64_t)SSFCryptCTMemEq(ctA, ctB, sizeof(ctA));
            }
            t1 = SSFPortGetTick64();
            earlyMs[trial] = (uint64_t)(t1 - t0);
            ctB[0] = 0xAAu;
        }

        earlyMin = earlyMs[0];
        lateMin = lateMs[0];
        for (trial = 1; trial < CT_TRIALS; trial++)
        {
            if (earlyMs[trial] < earlyMin) earlyMin = earlyMs[trial];
            if (lateMs[trial] < lateMin) lateMin = lateMs[trial];
        }

        printf("ssfcrypt CT timing: early=%llums late=%llums "
               "(min over %u trials, %u iters x %u B)\n",
               (unsigned long long)earlyMin, (unsigned long long)lateMin,
               (unsigned)CT_TRIALS, (unsigned)CT_ITERS, (unsigned)CT_BUF_SIZE);

        /* CT property: late runtime must not exceed 10x the early runtime. */
        SSF_ASSERT(lateMin <= ((10u * earlyMin) + 5u));

        /* Reference the volatile sink so the optimizer cannot drop the timing loops. */
        SSF_ASSERT(sink != UINT64_MAX);
    }
#endif /* SSF_CONFIG_CRYPT_CT_TIMING_TEST */

    /* ---- SSFCryptSecureZero ---- */
    {
        uint8_t buf[37];
        size_t i;

        for (i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i + 1u);
        SSFCryptSecureZero(buf, sizeof(buf));
        for (i = 0; i < sizeof(buf); i++) SSF_ASSERT(buf[i] == 0u);

        /* n == 0 must be a no-op (loop body never executes). */
        buf[0] = 0xA5u;
        SSFCryptSecureZero(buf, 0);
        SSF_ASSERT(buf[0] == 0xA5u);

        /* p == NULL must trip SSF_REQUIRE. */
        SSF_ASSERT_TEST(SSFCryptSecureZero(NULL, 1));
    }

    /* Size sweep: tag-sized, key-sized, block-aligned, off-by-one, and large. Catches any
       length-dependent bug (final-byte, word-aligned-only, capped-at-256, etc.). */
    {
        static const size_t sizes[] = {1u, 7u, 15u, 16u, 17u, 31u, 32u, 64u, 257u, 1024u};
        static uint8_t buf[1024];
        size_t s;
        size_t i;
        for (s = 0; s < (sizeof(sizes) / sizeof(sizes[0])); s++)
        {
            memset(buf, 0xC3, sizes[s]);
            SSFCryptSecureZero(buf, sizes[s]);
            for (i = 0; i < sizes[s]; i++) SSF_ASSERT(buf[i] == 0u);
        }
    }

    /* No out-of-bounds writes: zero a window in the middle of a sentinel-filled buffer
       and verify the bytes outside the window are untouched. Catches any length+1 or
       wraparound bug in the loop bound. */
    {
        uint8_t buf[64];
        size_t i;
        memset(buf, 0xEEu, sizeof(buf));
        SSFCryptSecureZero(&buf[16], 16u);
        for (i = 0;  i < 16u; i++) SSF_ASSERT(buf[i] == 0xEEu);
        for (i = 16u; i < 32u; i++) SSF_ASSERT(buf[i] == 0u);
        for (i = 32u; i < 64u; i++) SSF_ASSERT(buf[i] == 0xEEu);
    }

    /* Misaligned target: odd-offset start, odd length. Verifies the byte-by-byte path
       does not depend on word alignment. */
    {
        uint8_t buf[16];
        size_t i;
        memset(buf, 0xAAu, sizeof(buf));
        SSFCryptSecureZero(&buf[3], 7u);
        SSF_ASSERT(buf[2] == 0xAAu);
        for (i = 3u; i < 10u; i++) SSF_ASSERT(buf[i] == 0u);
        SSF_ASSERT(buf[10] == 0xAAu);
    }
}
#endif /* SSF_CONFIG_CRYPT_UNIT_TEST */
