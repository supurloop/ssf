/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcrc16_ut.c                                                                                 */
/* Provides 16-bit XMODEM/CCITT-16 0x1021 CRC interface unit test.                               */
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
#include "ssfcrc16.h"

#if SSF_CONFIG_CRC16_UNIT_TEST == 1

typedef struct SSFCRC16UT
{
    const uint8_t *in;
    uint16_t inLen;
    uint16_t crc;
} SSFCRC16UT_t;

static const SSFCRC16UT_t _SSFCRC16UT[] =
{
    {(uint8_t *)"helloworldZ", 11, 0xA131},
    {(uint8_t *)"helloworld!", 11, 0x6ECD},
    {(uint8_t *)"abcde", 5, 0x3EE1},
    {(uint8_t *)"1", 1, 0x2672},
    {(uint8_t *)"123456789", 9, 0x31C3},
    {(uint8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10, 0x2378},
    {(uint8_t *)"\xf0\xf1\xf2\xf3\xf4\x05\x00\x30\x41\x65\x07\xf8\xff", 13, 0x512B},
    {(uint8_t *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 100, 0xd748},
    {(uint8_t *)
     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
     "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", 300, 0xF099}
};

/* --------------------------------------------------------------------------------------------- */
/* Units tests the 16-bit XMODEM/CCITT-16 CRC external interface.                                */
/* --------------------------------------------------------------------------------------------- */
void SSFCRC16UnitTest(void)
{
    uint16_t i, j;
    uint16_t crc;

    /* Check NULL string case */
    SSF_ASSERT_TEST(SSFCRC16(NULL, 0, SSF_CRC16_INITIAL));

    /* Check 0 length cases */
    SSF_ASSERT(SSFCRC16((uint8_t *)"1", 0, SSF_CRC16_INITIAL) == SSF_CRC16_INITIAL);
    SSF_ASSERT(SSFCRC16((uint8_t *)"1", 0, 0xAA55) == 0xAA55);

    /* Check single pass cases */
    for (i = 0; i < sizeof(_SSFCRC16UT) / sizeof(SSFCRC16UT_t); i++)
    {
        SSF_ASSERT(SSFCRC16(_SSFCRC16UT[i].in, _SSFCRC16UT[i].inLen, SSF_CRC16_INITIAL) ==
                            _SSFCRC16UT[i].crc);
    }

    /* Check multi pass cases */
    for (i = 0; i < sizeof(_SSFCRC16UT) / sizeof(SSFCRC16UT_t); i++)
    {
        for (j = 1; j <= _SSFCRC16UT[i].inLen; j++)
        {
            crc = SSFCRC16(_SSFCRC16UT[i].in, j, SSF_CRC16_INITIAL);
            SSF_ASSERT(SSFCRC16(_SSFCRC16UT[i].in + j, _SSFCRC16UT[i].inLen - j, crc) ==
                       _SSFCRC16UT[i].crc);
        }
    }
}
#endif /* SSF_CONFIG_CRC16_UNIT_TEST */
