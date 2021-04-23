/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcrc32_ut.c                                                                                 */
/* Provides 32-bit CCITT-32 0x04C11DB7 Poly CRC interface unit test.                             */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2021 Supurloop Software LLC                                                         */
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
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfcrc32.h"

#if SSF_CONFIG_CRC32_UNIT_TEST == 1

typedef struct SSFCRC32UT
{
    const uint8_t *in;
    uint32_t inLen;
    uint32_t crc;
} SSFCRC32UT_t;

static const SSFCRC32UT_t _SSFCRC32UT[] =
{
    {"helloworldZ", 11, 0xF1226312},
    {"helloworld!", 11, 0x36F5CBA6},
    {"abcde", 5, 0x8587D865},
    {"1", 1, 0x83DCEFB7},
    {"123456789", 9, 0xCBF43926},
    {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10, 0x456CD746},
    {"\xf0\xf1\xf2\xf3\xf4\x05\x00\x30\x41\x65\x07\xf8\xff", 13, 0xFAD52B77},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 100, 0xAF707A64},
    {"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 300, 0xFA2DD4AA}
};

/* --------------------------------------------------------------------------------------------- */
/* Units tests the 32-bit CCITT-32 CRC external interface.                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFCRC32UnitTest(void)
{
    uint16_t i, j;
    uint32_t crc;

    /* Check NULL string case */
    SSF_ASSERT_TEST(SSFCRC32(NULL, 0, SSF_CRC32_INITIAL));

    /* Check 0 length cases */
    SSF_ASSERT(SSFCRC32((uint8_t*)"1", 0, SSF_CRC32_INITIAL) == SSF_CRC32_INITIAL);
    SSF_ASSERT(SSFCRC32((uint8_t*)"1", 0, (0xAA553366ul)) == (0xAA553366ul));

    /* Check single pass cases */
    for (i = 0; i < sizeof(_SSFCRC32UT) / sizeof(SSFCRC32UT_t); i++)
    {
        SSF_ASSERT(SSFCRC32(_SSFCRC32UT[i].in, _SSFCRC32UT[i].inLen, SSF_CRC32_INITIAL) ==
                            _SSFCRC32UT[i].crc);
    }

    /* Check multi pass cases */
    for (i = 0; i < sizeof(_SSFCRC32UT) / sizeof(SSFCRC32UT_t); i++)
    {
        for (j = 1; j <= _SSFCRC32UT[i].inLen; j++)
        {
            crc = SSFCRC32(_SSFCRC32UT[i].in, j, SSF_CRC32_INITIAL);
            SSF_ASSERT(SSFCRC32(_SSFCRC32UT[i].in + j, _SSFCRC32UT[i].inLen - j, crc) ==
                       _SSFCRC32UT[i].crc);
        }
    }
}
#endif /* SSF_CONFIG_CRC32_UNIT_TEST */
