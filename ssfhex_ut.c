/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhex_ut.c                                                                                   */
/* Provides ASCII hex encoder/decoder interface unit test.                                       */
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
#include "ssfhex.h"
#include "ssfassert.h"

#if SSF_CONFIG_HEX_UNIT_TEST == 1

typedef struct SSFHex64UT
{
    char *ascii;
    char *asciiup;
    char *asciilow;
    char *asciirevup;
    char *asciirevlow;
    uint8_t *bin;
    uint8_t *binrev;
    size_t binlen;
} SSFHexUT_t;

SSFHexUT_t _hexUTPass[] =
{
    { "", "", "", "", "", "", "", 0 },
    { "a1", "A1", "a1", "A1", "a1", "\xa1", "\xa1", 1 },
    { "A1", "A1", "a1", "A1", "a1", "\xA1", "\xA1", 1 },
    { "A1f5", "A1F5", "a1f5", "F5A1", "f5A1", "\xA1\xF5", "\xF5\xA1", 2 },
    { "A1f51234567890abcdefABCDEF", "A1F51234567890ABCDEFABCDEF", "a1f51234567890abcdefabcdef",
        "EFCDABEFCDAB9078563412F5A1", "efcdabefcdab9078563412f5a1",
        "\xA1\xF5\x12\x34\x56\x78\x90\xab\xcd\xef\xAB\xCD\xEF",
        "\xef\xcd\xab\xef\xcd\xab\x90\x78\x56\x34\x12\xF5\xA1", 13 },
};

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ASCII Hex external interface.                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFHexUnitTest(void)
{
    uint32_t i;
    uint8_t binout[32];
    char hexout[65];
    size_t outlen;

    SSF_ASSERT_TEST(SSFHexBytesToBin(NULL, strlen(_hexUTPass[0].ascii), binout, sizeof(binout),
                                     &outlen, false));
    SSF_ASSERT_TEST(SSFHexBytesToBin(_hexUTPass[0].ascii, strlen(_hexUTPass[0].ascii), NULL,
                                     sizeof(binout), &outlen, false));
    SSF_ASSERT_TEST(SSFHexBytesToBin(_hexUTPass[0].ascii, strlen(_hexUTPass[0].ascii), binout,
                                     sizeof(binout), NULL, false));

    SSF_ASSERT_TEST(SSFHexBinToBytes(NULL, _hexUTPass[0].binlen, hexout, sizeof(hexout), &outlen,
                                     false, SSF_HEX_CASE_LOWER));
    SSF_ASSERT_TEST(SSFHexBinToBytes(_hexUTPass[0].bin, _hexUTPass[0].binlen, NULL,
                                     sizeof(hexout), &outlen, false, SSF_HEX_CASE_LOWER));

    for (i = 0; i <= 1; i++)
    {
        SSF_ASSERT(SSFHexBytesToBin("a", strlen("a"), binout, sizeof(binout), &outlen, (bool)i) ==
                       false);
        SSF_ASSERT(SSFHexBytesToBin("ag", strlen("ag"), binout, sizeof(binout), &outlen,
                                    (bool)i) == false);
        SSF_ASSERT(SSFHexBytesToBin("ga", strlen("ga"), binout, sizeof(binout), &outlen,
                                    (bool)i) == false);
        SSF_ASSERT(SSFHexBytesToBin("111", strlen("111"), binout, sizeof(binout), &outlen,
                                    (bool)i) == false);
        SSF_ASSERT(SSFHexBytesToBin("111x", strlen("111x"), binout, sizeof(binout), &outlen,
                                    (bool)i) == false);

        SSF_ASSERT(SSFHexBytesToBin("1234", strlen("1234"), binout, 1, &outlen, (bool)i) ==
                       false);
        SSF_ASSERT(SSFHexBytesToBin("1234", strlen("1234"), binout, 2, &outlen, (bool)i) == true);

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes("\x12\x34", 2, hexout, 4, &outlen, (bool)i,
                                    SSF_HEX_CASE_UPPER) == false);
        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes("\x12\x34", 2, hexout, 5, &outlen, (bool)i,
                                    SSF_HEX_CASE_UPPER) == true);
        SSF_ASSERT(strlen(hexout) == 4);
    }

    for (i = 0; i < (sizeof(_hexUTPass) / sizeof(SSFHexUT_t)); i++)
    {
        SSF_ASSERT(SSFHexBytesToBin(_hexUTPass[i].ascii, strlen(_hexUTPass[i].ascii), binout,
                                    sizeof(binout), &outlen, false));
        SSF_ASSERT(outlen == _hexUTPass[i].binlen);
        SSF_ASSERT(memcmp(binout, _hexUTPass[i].bin, outlen) == 0);
        SSF_ASSERT(SSFHexBytesToBin(_hexUTPass[i].ascii, strlen(_hexUTPass[i].ascii), binout,
                                    sizeof(binout), &outlen, true));
        SSF_ASSERT(outlen == _hexUTPass[i].binlen);
        SSF_ASSERT(memcmp(binout, _hexUTPass[i].binrev, outlen) == 0);

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes(_hexUTPass[i].bin, _hexUTPass[i].binlen, hexout,
                                    sizeof(hexout), &outlen, false, SSF_HEX_CASE_LOWER));
        SSF_ASSERT(outlen == (_hexUTPass[i].binlen << 1));
        SSF_ASSERT(outlen == strlen(_hexUTPass[i].asciilow));
        SSF_ASSERT(outlen == strlen(hexout));
        SSF_ASSERT(memcpy(hexout, _hexUTPass[i].asciilow, outlen + 1));

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes(_hexUTPass[i].bin, _hexUTPass[i].binlen, hexout,
                                    sizeof(hexout), &outlen, false, SSF_HEX_CASE_UPPER));
        SSF_ASSERT(outlen == (_hexUTPass[i].binlen << 1));
        SSF_ASSERT(outlen == strlen(_hexUTPass[i].asciiup));
        SSF_ASSERT(outlen == strlen(hexout));
        SSF_ASSERT(memcpy(hexout, _hexUTPass[i].asciiup, outlen + 1));

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes(_hexUTPass[i].bin, _hexUTPass[i].binlen, hexout,
                                    sizeof(hexout), &outlen, true, SSF_HEX_CASE_LOWER));
        SSF_ASSERT(outlen == (_hexUTPass[i].binlen << 1));
        SSF_ASSERT(outlen == strlen(_hexUTPass[i].asciirevlow));
        SSF_ASSERT(outlen == strlen(hexout));
        SSF_ASSERT(memcpy(hexout, _hexUTPass[i].asciirevlow, outlen + 1));

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes(_hexUTPass[i].bin, _hexUTPass[i].binlen, hexout,
                                    sizeof(hexout), &outlen, true, SSF_HEX_CASE_UPPER));
        SSF_ASSERT(outlen == (_hexUTPass[i].binlen << 1));
        SSF_ASSERT(outlen == strlen(_hexUTPass[i].asciirevup));
        SSF_ASSERT(outlen == strlen(hexout));
        SSF_ASSERT(memcpy(hexout, _hexUTPass[i].asciirevup, outlen + 1));
    }
}
#endif /* SSF_CONFIG_HEX_UNIT_TEST */

