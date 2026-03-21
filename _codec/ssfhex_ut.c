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
    { "", "", "", "", "", (uint8_t *)"", (uint8_t *)"", 0 },
    { "a1", "A1", "a1", "A1", "a1", (uint8_t *)"\xa1", (uint8_t *)"\xa1", 1 },
    { "A1", "A1", "a1", "A1", "a1", (uint8_t *)"\xA1", (uint8_t *)"\xA1", 1 },
    { "A1f5", "A1F5", "a1f5", "F5A1", "f5a1", (uint8_t *)"\xA1\xF5", (uint8_t *)"\xF5\xA1", 2 },
    { "A1f51234567890abcdefABCDEF", "A1F51234567890ABCDEFABCDEF", "a1f51234567890abcdefabcdef",
        "EFCDABEFCDAB9078563412F5A1", "efcdabefcdab9078563412f5a1",
        (uint8_t *)"\xA1\xF5\x12\x34\x56\x78\x90\xab\xcd\xef\xAB\xCD\xEF",
        (uint8_t *)"\xef\xcd\xab\xef\xcd\xab\x90\x78\x56\x34\x12\xF5\xA1", 13 },
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
    SSF_ASSERT_TEST(SSFHexBinToBytes(_hexUTPass[0].bin, _hexUTPass[0].binlen, hexout,
                                     0, &outlen, false, SSF_HEX_CASE_LOWER));
    SSF_ASSERT_TEST(SSFHexBinToBytes(_hexUTPass[0].bin, _hexUTPass[0].binlen, hexout,
                                     sizeof(hexout), &outlen, false, SSF_HEX_CASE_MIN));
    SSF_ASSERT_TEST(SSFHexBinToBytes(_hexUTPass[0].bin, _hexUTPass[0].binlen, hexout,
                                     sizeof(hexout), &outlen, false, SSF_HEX_CASE_MAX));

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

        SSF_ASSERT(SSFHexBytesToBin("1234", strlen("1234") + 200, binout, sizeof(binout), &outlen, (bool)i) ==
                       false);
        SSF_ASSERT(SSFHexBytesToBin("1234", strlen("1234") + 2, binout, sizeof(binout), &outlen, (bool)i) ==
                       false);
        SSF_ASSERT(SSFHexBytesToBin("123", strlen("1234") + 2, binout, sizeof(binout), &outlen, (bool)i) ==
                       false);
        SSF_ASSERT(SSFHexBytesToBin("123", strlen("1234") + 1, binout, sizeof(binout), &outlen, (bool)i) ==
                       false);
        SSF_ASSERT(SSFHexBytesToBin("1234", strlen("1234"), binout, 1, &outlen, (bool)i) ==
                       false);
        SSF_ASSERT(SSFHexBytesToBin("1234", strlen("1234"), binout, 2, &outlen, (bool)i) == true);

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes((uint8_t *)"\x12\x34", 2, hexout, 4, &outlen, (bool)i,
                                    SSF_HEX_CASE_UPPER) == false);
        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes((uint8_t *)"\x12\x34", 2, hexout, 5, &outlen, (bool)i,
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
        SSF_ASSERT(memcmp(hexout, _hexUTPass[i].asciilow, outlen + 1) == 0);

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes(_hexUTPass[i].bin, _hexUTPass[i].binlen, hexout,
                                    sizeof(hexout), &outlen, false, SSF_HEX_CASE_UPPER));
        SSF_ASSERT(outlen == (_hexUTPass[i].binlen << 1));
        SSF_ASSERT(outlen == strlen(_hexUTPass[i].asciiup));
        SSF_ASSERT(outlen == strlen(hexout));
        SSF_ASSERT(memcmp(hexout, _hexUTPass[i].asciiup, outlen + 1) == 0);

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes(_hexUTPass[i].bin, _hexUTPass[i].binlen, hexout,
                                    sizeof(hexout), &outlen, true, SSF_HEX_CASE_LOWER));
        SSF_ASSERT(outlen == (_hexUTPass[i].binlen << 1));
        SSF_ASSERT(outlen == strlen(_hexUTPass[i].asciirevlow));
        SSF_ASSERT(outlen == strlen(hexout));
        SSF_ASSERT(memcmp(hexout, _hexUTPass[i].asciirevlow, outlen + 1) == 0);

        memset(hexout, 0xff, sizeof(hexout));
        SSF_ASSERT(SSFHexBinToBytes(_hexUTPass[i].bin, _hexUTPass[i].binlen, hexout,
                                    sizeof(hexout), &outlen, true, SSF_HEX_CASE_UPPER));
        SSF_ASSERT(outlen == (_hexUTPass[i].binlen << 1));
        SSF_ASSERT(outlen == strlen(_hexUTPass[i].asciirevup));
        SSF_ASSERT(outlen == strlen(hexout));
        SSF_ASSERT(memcmp(hexout, _hexUTPass[i].asciirevup, outlen + 1) == 0);
    }

    /* SSFHexBinToByte direct tests */
    SSF_ASSERT_TEST(SSFHexBinToByte(0x00, NULL, 3, SSF_HEX_CASE_UPPER));
    SSF_ASSERT(SSFHexBinToByte(0xAB, hexout, 0, SSF_HEX_CASE_UPPER) == false);
    SSF_ASSERT(SSFHexBinToByte(0xAB, hexout, 1, SSF_HEX_CASE_UPPER) == false);
    /* outSize=2: writes 2 hex chars, no null terminator */
    memset(hexout, 0xff, sizeof(hexout));
    SSF_ASSERT(SSFHexBinToByte(0xAB, hexout, 2, SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(hexout[0] == 'A');
    SSF_ASSERT(hexout[1] == 'B');
    SSF_ASSERT((uint8_t)hexout[2] == 0xff);
    /* outSize>=3: writes 2 hex chars + null */
    memset(hexout, 0xff, sizeof(hexout));
    SSF_ASSERT(SSFHexBinToByte(0xAB, hexout, 3, SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(hexout[0] == 'A');
    SSF_ASSERT(hexout[1] == 'B');
    SSF_ASSERT(hexout[2] == 0);
    /* Lower case */
    SSF_ASSERT(SSFHexBinToByte(0xAB, hexout, 3, SSF_HEX_CASE_LOWER) == true);
    SSF_ASSERT(hexout[0] == 'a');
    SSF_ASSERT(hexout[1] == 'b');
    /* Boundary values */
    SSF_ASSERT(SSFHexBinToByte(0x00, hexout, 3, SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(hexout[0] == '0');
    SSF_ASSERT(hexout[1] == '0');
    SSF_ASSERT(SSFHexBinToByte(0xFF, hexout, 3, SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(hexout[0] == 'F');
    SSF_ASSERT(hexout[1] == 'F');
    SSF_ASSERT(SSFHexBinToByte(0x09, hexout, 3, SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(hexout[0] == '0');
    SSF_ASSERT(hexout[1] == '9');
    SSF_ASSERT(SSFHexBinToByte(0x0A, hexout, 3, SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(hexout[0] == '0');
    SSF_ASSERT(hexout[1] == 'A');

    /* SSFHexByteToBin direct tests */
    SSF_ASSERT_TEST(SSFHexByteToBin(NULL, binout));
    SSF_ASSERT_TEST(SSFHexByteToBin("AB", NULL));
    SSF_ASSERT(SSFHexByteToBin("AB", binout) == true);
    SSF_ASSERT(binout[0] == 0xAB);
    SSF_ASSERT(SSFHexByteToBin("ab", binout) == true);
    SSF_ASSERT(binout[0] == 0xAB);
    SSF_ASSERT(SSFHexByteToBin("00", binout) == true);
    SSF_ASSERT(binout[0] == 0x00);
    SSF_ASSERT(SSFHexByteToBin("FF", binout) == true);
    SSF_ASSERT(binout[0] == 0xFF);
    SSF_ASSERT(SSFHexByteToBin("ff", binout) == true);
    SSF_ASSERT(binout[0] == 0xFF);
    SSF_ASSERT(SSFHexByteToBin("0A", binout) == true);
    SSF_ASSERT(binout[0] == 0x0A);
    /* Invalid chars */
    SSF_ASSERT(SSFHexByteToBin("GG", binout) == false);
    SSF_ASSERT(SSFHexByteToBin("0G", binout) == false);
    SSF_ASSERT(SSFHexByteToBin("G0", binout) == false);
    SSF_ASSERT(SSFHexByteToBin("  ", binout) == false);
    SSF_ASSERT(SSFHexByteToBin("0x", binout) == false);

    /* SSFHexBinToBytes with outLen == NULL */
    memset(hexout, 0xff, sizeof(hexout));
    SSF_ASSERT(SSFHexBinToBytes((uint8_t *)"\xAB", 1, hexout, sizeof(hexout), NULL, false,
                                SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(hexout[0] == 'A');
    SSF_ASSERT(hexout[1] == 'B');
    SSF_ASSERT(hexout[2] == 0);

    /* SSFHexBinToBytes exactly-sized output buffer */
    /* 1 binary byte needs 3 bytes output (2 hex + null) */
    memset(hexout, 0xff, sizeof(hexout));
    SSF_ASSERT(SSFHexBinToBytes((uint8_t *)"\x12", 1, hexout, 3, &outlen, false,
                                SSF_HEX_CASE_UPPER) == true);
    SSF_ASSERT(outlen == 2);
    SSF_ASSERT(memcmp(hexout, "12", 3) == 0);
    /* 1 byte short must fail */
    SSF_ASSERT(SSFHexBinToBytes((uint8_t *)"\x12", 1, hexout, 2, &outlen, false,
                                SSF_HEX_CASE_UPPER) == false);
    /* outSize=1 always fails for non-empty input (only room for null) */
    SSF_ASSERT(SSFHexBinToBytes((uint8_t *)"\x12", 1, hexout, 1, &outlen, false,
                                SSF_HEX_CASE_UPPER) == false);

    /* SSFHexBytesToBin with outSize=0 and non-empty input */
    SSF_ASSERT(SSFHexBytesToBin("AABB", 4, binout, 0, &outlen, false) == false);
    /* outSize=0 with empty input succeeds */
    SSF_ASSERT(SSFHexBytesToBin("", 0, binout, 0, &outlen, false) == true);
    SSF_ASSERT(outlen == 0);

    /* Full 256-value round-trip: encode then decode every byte */
    {
        uint16_t v;
        uint8_t binIn;
        uint8_t binDec;
        char hexEnc[3];

        for (v = 0; v <= 255; v++)
        {
            binIn = (uint8_t)v;
            SSF_ASSERT(SSFHexBinToByte(binIn, hexEnc, sizeof(hexEnc), SSF_HEX_CASE_UPPER) == true);
            SSF_ASSERT(SSFHexByteToBin(hexEnc, &binDec) == true);
            SSF_ASSERT(binDec == binIn);
            SSF_ASSERT(SSFHexBinToByte(binIn, hexEnc, sizeof(hexEnc), SSF_HEX_CASE_LOWER) == true);
            SSF_ASSERT(SSFHexByteToBin(hexEnc, &binDec) == true);
            SSF_ASSERT(binDec == binIn);
        }
    }

    /* SSFIsHex macro */
    SSF_ASSERT(SSFIsHex('0'));
    SSF_ASSERT(SSFIsHex('9'));
    SSF_ASSERT(SSFIsHex('a'));
    SSF_ASSERT(SSFIsHex('f'));
    SSF_ASSERT(SSFIsHex('A'));
    SSF_ASSERT(SSFIsHex('F'));
    SSF_ASSERT(!SSFIsHex('g'));
    SSF_ASSERT(!SSFIsHex('G'));
    SSF_ASSERT(!SSFIsHex(' '));
    SSF_ASSERT(!SSFIsHex('\0'));
    SSF_ASSERT(!SSFIsHex('/'));
    SSF_ASSERT(!SSFIsHex(':'));
    SSF_ASSERT(!SSFIsHex('@'));
    SSF_ASSERT(!SSFIsHex('['));
    SSF_ASSERT(!SSFIsHex('`'));
    SSF_ASSERT(!SSFIsHex('{'));
}
#endif /* SSF_CONFIG_HEX_UNIT_TEST */

