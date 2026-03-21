/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssffcsum_ut.c                                                                                 */
/* Provides Fletcher checksum interface unit test.                                               */
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
#include <stdio.h>
#include "ssffcsum.h"
#include "ssfassert.h"
#include "ssfport.h"

#if SSF_CONFIG_FCSUM_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on Fletcher checksum external interface.                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFFCSumUnitTest(void)
{
    uint16_t fc;

    SSF_ASSERT_TEST(SSFFCSum16(NULL, 2, SSF_FCSUM_INITIAL));

    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x01\x02", 2, SSF_FCSUM_INITIAL) == 0x0403);
    fc = SSFFCSum16((uint8_t *)"\x01", 1, SSF_FCSUM_INITIAL);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x02", 1, fc) == 0x0403);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"abcde", 5, SSF_FCSUM_INITIAL) == 0xC8F0);
    fc = SSFFCSum16((uint8_t *)"a", 1, SSF_FCSUM_INITIAL);
    fc = SSFFCSum16((uint8_t *)"bcd", 3, fc);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"e", 1, fc) == 0xC8F0);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"abcdef", 6, SSF_FCSUM_INITIAL) == 0x2057);
    fc = SSFFCSum16((uint8_t *)"a", 1, SSF_FCSUM_INITIAL);
    fc = SSFFCSum16((uint8_t *)"bcd", 3, fc);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"ef", 2, fc) == 0x2057);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"abcdefgh", 8, SSF_FCSUM_INITIAL) == 0x0627);
    fc = SSFFCSum16((uint8_t *)"a", 1, SSF_FCSUM_INITIAL);
    fc = SSFFCSum16((uint8_t *)"bcd", 3, fc);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"efgh", 4, fc) == 0x0627);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x01\xfe", 2, SSF_FCSUM_INITIAL) == 0x0100);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\xff", 1, SSF_FCSUM_INITIAL) == 0x0000);

    /* Zero-length input returns initial unchanged */
    SSF_ASSERT(SSFFCSum16((uint8_t *)"x", 0, SSF_FCSUM_INITIAL) == SSF_FCSUM_INITIAL);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"x", 0, 0x1234) == 0x1234);

    /* Non-zero initial value on actual data */
    {
        uint16_t fc1 = SSFFCSum16((uint8_t *)"abcdefgh", 8, SSF_FCSUM_INITIAL);
        uint16_t fc2 = SSFFCSum16((uint8_t *)"abcdefgh", 8, 0x0101);

        SSF_ASSERT(fc1 == 0x0627);
        SSF_ASSERT(fc2 != fc1);
    }

    /* All-zero input: single zero byte → s1=0, s2=0 */
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x00", 1, SSF_FCSUM_INITIAL) == 0x0000);
    /* Multiple zero bytes stay at 0 */
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x00\x00\x00\x00", 4, SSF_FCSUM_INITIAL) == 0x0000);

    /* Single byte explicit values */
    /* 0x01: s1=1, s2=1 → 0x0101 */
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x01", 1, SSF_FCSUM_INITIAL) == 0x0101);
    /* 0x80: s1=128, s2=128 → 0x8080 */
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x80", 1, SSF_FCSUM_INITIAL) == 0x8080);

    /* Byte-by-byte incremental matches single-call */
    {
        uint16_t i;
        uint16_t ref;
        const uint8_t *data = (const uint8_t *)"abcdefgh";

        ref = SSFFCSum16(data, 8, SSF_FCSUM_INITIAL);
        fc = SSF_FCSUM_INITIAL;
        for (i = 0; i < 8; i++)
        {
            fc = SSFFCSum16(&data[i], 1, fc);
        }
        SSF_ASSERT(fc == ref);
    }
    {
        uint16_t i;
        uint16_t ref;
        const uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};

        ref = SSFFCSum16(data, 16, SSF_FCSUM_INITIAL);
        fc = SSF_FCSUM_INITIAL;
        for (i = 0; i < 16; i++)
        {
            fc = SSFFCSum16(&data[i], 1, fc);
        }
        SSF_ASSERT(fc == ref);
        SSF_ASSERT(ref != SSF_FCSUM_INITIAL);
    }
}
#endif /* SSF_CONFIG_FCSUM_UNIT_TEST */
