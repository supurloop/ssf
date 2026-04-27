/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfct_ut.c                                                                                    */
/* Provides constant-time primitives interface unit test.                                        */
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
#include <string.h>
#include "ssfct.h"
#include "ssfassert.h"
#include "ssfport.h"

#if SSF_CONFIG_CT_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on constant-time primitives external interface.                            */
/* --------------------------------------------------------------------------------------------- */
void SSFCTUnitTest(void)
{
    /* NULL-argument assertions. The contract requires non-NULL pointers even when n is 0,
       so exercise both n>0 and n==0 to pin the documented behavior. */
    {
        uint8_t buf[4] = {0};
        SSF_ASSERT_TEST(SSFCTMemEq(NULL, buf, 4u));
        SSF_ASSERT_TEST(SSFCTMemEq(buf, NULL, 4u));
        SSF_ASSERT_TEST(SSFCTMemEq(NULL, buf, 0u));
        SSF_ASSERT_TEST(SSFCTMemEq(buf, NULL, 0u));
    }

    /* Zero-length input compares equal regardless of pointer values. */
    {
        uint8_t a[1] = {0xAA};
        uint8_t b[1] = {0x55};
        SSF_ASSERT(SSFCTMemEq(a, b, 0u) == true);
        SSF_ASSERT(SSFCTMemEq(a, a, 0u) == true);
    }

    /* Single-byte equal and single-byte mismatch. */
    {
        uint8_t a = 0xA5;
        uint8_t b = 0xA5;
        uint8_t c = 0xA4;
        SSF_ASSERT(SSFCTMemEq(&a, &b, 1u) == true);
        SSF_ASSERT(SSFCTMemEq(&a, &c, 1u) == false);
    }

    /* Multi-byte equal, and same buffer against itself. */
    {
        const uint8_t a[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        const uint8_t b[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        SSF_ASSERT(SSFCTMemEq(a, b, 6u) == true);
        SSF_ASSERT(SSFCTMemEq(a, a, 6u) == true);
    }

    /* Mismatch at first, middle, and last positions. Each must return false —
       proves the whole-buffer scan behavior by induction. */
    {
        const uint8_t base[6]    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        uint8_t       diffFirst[6] = {0x01, 0x11, 0x22, 0x33, 0x44, 0x55};
        uint8_t       diffMid[6]   = {0x00, 0x11, 0x22, 0x77, 0x44, 0x55};
        uint8_t       diffLast[6]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};
        SSF_ASSERT(SSFCTMemEq(base, diffFirst, 6u) == false);
        SSF_ASSERT(SSFCTMemEq(base, diffMid,   6u) == false);
        SSF_ASSERT(SSFCTMemEq(base, diffLast,  6u) == false);
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

        SSF_ASSERT(SSFCTMemEq(zeros, zeros, 32u) == true);
        SSF_ASSERT(SSFCTMemEq(zeros, ones,  32u) == false);
        SSF_ASSERT(SSFCTMemEq(zeros, diff0, 32u) == false);
        SSF_ASSERT(SSFCTMemEq(zeros, diff31, 32u) == false);
    }

    /* Long buffer (exercise multi-iteration path). */
    {
        uint8_t a[256];
        uint8_t b[256];
        size_t i;
        for (i = 0; i < sizeof(a); i++) { a[i] = (uint8_t)i; b[i] = (uint8_t)i; }
        SSF_ASSERT(SSFCTMemEq(a, b, sizeof(a)) == true);
        b[128] ^= 0x01;
        SSF_ASSERT(SSFCTMemEq(a, b, sizeof(a)) == false);
    }

    /* void * ergonomics: accepts differing pointer types without casts at the call site. */
    {
        const char  *s1 = "hello";
        const char  *s2 = "hello";
        const char  *s3 = "help!";
        SSF_ASSERT(SSFCTMemEq(s1, s2, 5u) == true);
        SSF_ASSERT(SSFCTMemEq(s1, s3, 5u) == false);
    }
}
#endif /* SSF_CONFIG_CT_UNIT_TEST */
