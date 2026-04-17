/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbase64_ut.c                                                                                */
/* Provides Base64 encoder/decoder interface unit test.                                          */
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
#include "ssfbase64.h"
#include "ssfassert.h"

#if SSF_CONFIG_BASE64_UNIT_TEST == 1

/* Low level block encode/decode */
uint8_t SSFBase64Dec32To24(const char *b32, uint8_t *b24out, size_t b24outSize);
void SSFBase64Enc24To32(const uint8_t *b24, size_t b24len, char *b32out, size_t b32outSize);

typedef struct SSBase64UT
{
    uint8_t *unencoded;
    uint8_t unencodedLen;
    char *encoded;
} SSBase64UT_t;

SSBase64UT_t _b64BlockUT[] = {
    { (uint8_t *)"", 0, "" },
    { (uint8_t *)"a", 1, "YQ==" },
    { (uint8_t *)"ab", 2, "YWI=" },
    { (uint8_t *)"abc", 3, "YWJj" },
    { (uint8_t *)"\x00", 1, "AA==" },
    { (uint8_t *)"\x00\x00", 2, "AAA=" },
    { (uint8_t *)"\x00\x00\x00", 3, "AAAA" },
    { (uint8_t *)"\x00\x01\x02", 3, "AAEC" },
    { (uint8_t *)"\x80", 1, "gA==" },
    { (uint8_t *)"\xff\x80\x5a", 3, "/4Ba" },
    { (uint8_t *)"\xff", 1, "/w==" },
    { (uint8_t *)"\xff\xff", 2, "//8=" },
    { (uint8_t *)"\xff\xff\xff", 3, "////" },
    { (uint8_t *)"\x55", 1, "VQ==" },
    { (uint8_t *)"\x55\x55", 2, "VVU=" },
    { (uint8_t *)"\x55\x55\x55", 3, "VVVV" },
    { (uint8_t *)"\x66", 1, "Zg==" },
    { (uint8_t *)"\x66\x66", 2, "ZmY=" },
    { (uint8_t *)"\x66\x66\x66", 3, "ZmZm" },
};

SSBase64UT_t _b64StringUT[] = {
    { (uint8_t *)"a", 1, "YQ==" },
    { (uint8_t *)"ab", 2, "YWI=" },
    { (uint8_t *)"abc", 3, "YWJj" },
    { (uint8_t *)"abcd", 4, "YWJjZA==" },
    { (uint8_t *)"abcde", 5, "YWJjZGU=" },
    { (uint8_t *)"abcdef", 6, "YWJjZGVm" },
    { (uint8_t *)
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x12\x13\x14\x15\x16\x17"
        "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed"
        "\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00", 64,
        "AAECAwQFBgcICQoLDA0ODxASExQVFhcYGRobHB0eH+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AA==" },
};

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on Base64 external interface.                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFBase64UnitTest(void)
{
    volatile uint32_t i;
    uint8_t b24[3];
    char b32[4];
    char encodedStr[5];
    uint8_t decodedBin[3];
    char encodedBigStr[128];
    uint8_t decodedBigBin[128];
    size_t outLen;

    /* Check NULL pointer cases */
    SSF_ASSERT_TEST(SSFBase64Dec32To24(NULL, b24, sizeof(b24)));
    SSF_ASSERT_TEST(SSFBase64Dec32To24(_b64BlockUT[1].encoded, NULL, sizeof(b24)));

    SSF_ASSERT_TEST(SSFBase64Enc24To32(NULL, _b64BlockUT[1].unencodedLen, b32, sizeof(b32)));
    SSF_ASSERT_TEST(SSFBase64Enc24To32(_b64BlockUT[1].unencoded, _b64BlockUT[1].unencodedLen, NULL, sizeof(b32)));

    SSF_ASSERT_TEST(SSFBase64Encode(NULL, _b64BlockUT[1].unencodedLen,
                                   _b64BlockUT[1].encoded, sizeof(_b64BlockUT[1].encoded), &outLen));

    SSF_ASSERT_TEST(SSFBase64Decode(NULL, strlen(_b64BlockUT[1].encoded),
                                   decodedBin, sizeof(decodedBin), &outLen));
    SSF_ASSERT_TEST(SSFBase64Decode(_b64BlockUT[1].encoded, strlen(_b64BlockUT[1].encoded),
                                   NULL, sizeof(decodedBin), &outLen));
    SSF_ASSERT_TEST(SSFBase64Decode(_b64BlockUT[1].encoded, strlen(_b64BlockUT[1].encoded),
                                   decodedBin, sizeof(decodedBin), NULL));    

    /* Check length constraints */
    SSF_ASSERT_TEST(SSFBase64Dec32To24(_b64BlockUT[1].encoded, b24, 0));

    SSF_ASSERT_TEST(SSFBase64Enc24To32(_b64BlockUT[1].unencoded, 0, b32, sizeof(b32)));
    SSF_ASSERT_TEST(SSFBase64Enc24To32(_b64BlockUT[1].unencoded, _b64BlockUT[1].unencodedLen, b32, 3));


    for (i = 0; i < (sizeof(_b64BlockUT) / sizeof(SSBase64UT_t)); i++)
    {
        SSF_ASSERT(SSFBase64Dec32To24(_b64BlockUT[i].encoded, b24, sizeof(b24)) ==
                       _b64BlockUT[i].unencodedLen);
        SSF_ASSERT(memcmp(b24, _b64BlockUT[i].unencoded, _b64BlockUT[i].unencodedLen) == 0);
        if (_b64BlockUT[i].unencodedLen == 0)
        {
            SSF_ASSERT_TEST(SSFBase64Enc24To32(_b64BlockUT[i].unencoded,
                                               _b64BlockUT[i].unencodedLen, b32, sizeof(b32)));
        } else
        {
            SSFBase64Enc24To32(_b64BlockUT[i].unencoded, _b64BlockUT[i].unencodedLen, b32,
                               sizeof(b32));
            SSF_ASSERT(memcmp(b32, _b64BlockUT[i].encoded, strlen(_b64BlockUT[i].encoded)) == 0);
        }

        SSF_ASSERT(SSFBase64Encode(_b64BlockUT[i].unencoded, _b64BlockUT[i].unencodedLen,
                                   encodedStr, sizeof(encodedStr), &outLen));
        SSF_ASSERT(outLen == strlen(encodedStr));
        SSF_ASSERT(outLen == strlen(_b64BlockUT[i].encoded));
        SSF_ASSERT(memcmp(_b64BlockUT[i].encoded, encodedStr, outLen + 1) == 0);

        SSF_ASSERT(SSFBase64Decode(_b64BlockUT[i].encoded, strlen(_b64BlockUT[i].encoded),
                                   decodedBin, sizeof(decodedBin), &outLen));
        SSF_ASSERT(outLen == _b64BlockUT[i].unencodedLen);
        SSF_ASSERT(memcmp(_b64BlockUT[i].unencoded, decodedBin, outLen) == 0);
    }

    for (i = 0; i < (sizeof(_b64StringUT) / sizeof(SSBase64UT_t)); i++)
    {
        SSF_ASSERT(SSFBase64Encode(_b64StringUT[i].unencoded, _b64StringUT[i].unencodedLen,
                                   encodedBigStr, sizeof(encodedBigStr), &outLen));
        SSF_ASSERT(outLen == strlen(encodedBigStr));
        SSF_ASSERT(outLen == strlen(_b64StringUT[i].encoded));
        SSF_ASSERT(memcmp(_b64StringUT[i].encoded, encodedBigStr, outLen + 1) == 0);

        SSF_ASSERT(SSFBase64Decode(_b64StringUT[i].encoded, strlen(_b64StringUT[i].encoded),
                                   decodedBigBin, sizeof(decodedBigBin), &outLen));
        SSF_ASSERT(outLen == _b64StringUT[i].unencodedLen);
        SSF_ASSERT(memcmp(_b64StringUT[i].unencoded, decodedBigBin, outLen) == 0);
    }
    SSF_ASSERT_TEST(SSFBase64Encode((uint8_t *)"abc", 0, encodedStr, 0, &outLen));
    SSF_ASSERT(SSFBase64Decode("abcd", 4, decodedBin, 2, &outLen) == false);

    /* Verify decode succeeds with exactly-sized output buffers for padded inputs */
    /* "YQ==" decodes to "a" (1 byte) - outSize=1 must succeed */
    SSF_ASSERT(SSFBase64Decode("YQ==", 4, decodedBigBin, 1, &outLen) == true);
    SSF_ASSERT(outLen == 1);
    SSF_ASSERT(decodedBigBin[0] == 'a');

    /* "YWI=" decodes to "ab" (2 bytes) - outSize=2 must succeed */
    SSF_ASSERT(SSFBase64Decode("YWI=", 4, decodedBigBin, 2, &outLen) == true);
    SSF_ASSERT(outLen == 2);
    SSF_ASSERT(memcmp(decodedBigBin, "ab", 2) == 0);

    /* "YWJjZA==" decodes to "abcd" (4 bytes) - outSize=4 must succeed */
    SSF_ASSERT(SSFBase64Decode("YWJjZA==", 8, decodedBigBin, 4, &outLen) == true);
    SSF_ASSERT(outLen == 4);
    SSF_ASSERT(memcmp(decodedBigBin, "abcd", 4) == 0);

    /* "YWJjZGU=" decodes to "abcde" (5 bytes) - outSize=5 must succeed */
    SSF_ASSERT(SSFBase64Decode("YWJjZGU=", 8, decodedBigBin, 5, &outLen) == true);
    SSF_ASSERT(outLen == 5);
    SSF_ASSERT(memcmp(decodedBigBin, "abcde", 5) == 0);

    /* Verify decode fails when outSize is too small for actual decoded data */
    /* "YWJj" decodes to "abc" (3 bytes) - outSize=2 must fail */
    SSF_ASSERT(SSFBase64Decode("YWJj", 4, decodedBigBin, 2, &outLen) == false);

    /* "YWI=" decodes to "ab" (2 bytes) - outSize=1 must fail */
    SSF_ASSERT(SSFBase64Decode("YWI=", 4, decodedBigBin, 1, &outLen) == false);

    /* SSFBase64Encode with outLen == NULL must not crash */
    SSF_ASSERT(SSFBase64Encode((uint8_t *)"abc", 3, encodedBigStr, sizeof(encodedBigStr), NULL));
    SSF_ASSERT(memcmp(encodedBigStr, "YWJj", 5) == 0);

    /* SSFBase64Encode returns false when output buffer too small (> 0 but insufficient) */
    SSF_ASSERT(SSFBase64Encode((uint8_t *)"a", 1, encodedBigStr, 4, &outLen) == false);
    SSF_ASSERT(SSFBase64Encode((uint8_t *)"a", 1, encodedBigStr, 1, &outLen) == false);
    SSF_ASSERT(SSFBase64Encode((uint8_t *)"abcd", 4, encodedBigStr, 5, &outLen) == false);
    /* Exactly-sized multi-block output buffer must succeed: 4 bytes encodes to 8 chars + null = 9 */
    SSF_ASSERT(SSFBase64Encode((uint8_t *)"abcd", 4, encodedBigStr, 9, &outLen) == true);
    SSF_ASSERT(outLen == 8);
    SSF_ASSERT(memcmp(encodedBigStr, "YWJjZA==", 9) == 0);
    /* One byte short must fail */
    SSF_ASSERT(SSFBase64Encode((uint8_t *)"abcd", 4, encodedBigStr, 8, &outLen) == false);

    /* SSFBase64Decode with non-multiple-of-4 input length must return false */
    SSF_ASSERT(SSFBase64Decode("YWJ", 3, decodedBigBin, sizeof(decodedBigBin), &outLen) == false);
    SSF_ASSERT(SSFBase64Decode("YWJjZ", 5, decodedBigBin, sizeof(decodedBigBin), &outLen) == false);
    SSF_ASSERT(SSFBase64Decode("Y", 1, decodedBigBin, sizeof(decodedBigBin), &outLen) == false);

    /* SSFBase64Decode with invalid base64 characters must return false */
    SSF_ASSERT(SSFBase64Decode("!@#$", 4, decodedBigBin, sizeof(decodedBigBin), &outLen) == false);
    SSF_ASSERT(SSFBase64Decode("YW.j", 4, decodedBigBin, sizeof(decodedBigBin), &outLen) == false);
    SSF_ASSERT(SSFBase64Decode("YWJ ", 4, decodedBigBin, sizeof(decodedBigBin), &outLen) == false);

    /* SSFBase64Dec32To24 with invalid padding pattern "AA=A" (pad c but non-pad d) must return 0 */
    SSF_ASSERT(SSFBase64Dec32To24("AA=A", b24, sizeof(b24)) == 0);
    /* Invalid: pad in first two positions */
    SSF_ASSERT(SSFBase64Dec32To24("=AAA", b24, sizeof(b24)) == 0);
    SSF_ASSERT(SSFBase64Dec32To24("A=AA", b24, sizeof(b24)) == 0);

    /* RFC 4648 §3.5: non-canonical encodings MUST be rejected. When 2 base64 chars +
     * "==" encode 1 output byte, the second char's low 4 bits MUST be zero. When 3
     * chars + "=" encode 2 output bytes, the third char's low 2 bits MUST be zero. */
    /* 1-byte output, non-zero b-low-4 bits. These decode to 0x00 under a loose decoder
     * but are not a canonical encoding of anything. */
    SSF_ASSERT(SSFBase64Dec32To24("AB==", b24, sizeof(b24)) == 0);   /* b = 0b000001 */
    SSF_ASSERT(SSFBase64Dec32To24("AP==", b24, sizeof(b24)) == 0);   /* b = 0b001111 */
    SSF_ASSERT(SSFBase64Dec32To24("/x==", b24, sizeof(b24)) == 0);   /* canonical is /w== */
    /* 2-byte output, non-zero c-low-2 bits. */
    SSF_ASSERT(SSFBase64Dec32To24("AAB=", b24, sizeof(b24)) == 0);   /* c = 0b000001 */
    SSF_ASSERT(SSFBase64Dec32To24("AAD=", b24, sizeof(b24)) == 0);   /* c = 0b000011 */
    SSF_ASSERT(SSFBase64Dec32To24("//9=", b24, sizeof(b24)) == 0);   /* canonical is //8= */

    /* Sanity: the canonical forms still decode successfully. */
    SSF_ASSERT(SSFBase64Dec32To24("AA==", b24, sizeof(b24)) == 1 && b24[0] == 0x00);
    SSF_ASSERT(SSFBase64Dec32To24("/w==", b24, sizeof(b24)) == 1 && b24[0] == 0xFF);
    SSF_ASSERT(SSFBase64Dec32To24("AAA=", b24, sizeof(b24)) == 2 &&
               b24[0] == 0x00 && b24[1] == 0x00);
    SSF_ASSERT(SSFBase64Dec32To24("//8=", b24, sizeof(b24)) == 2 &&
               b24[0] == 0xFF && b24[1] == 0xFF);

    /* SSFBase64Decode must also reject the non-canonical forms end-to-end. */
    SSF_ASSERT(SSFBase64Decode("AB==", 4, decodedBigBin, sizeof(decodedBigBin), &outLen)
               == false);
    SSF_ASSERT(SSFBase64Decode("AAB=", 4, decodedBigBin, sizeof(decodedBigBin), &outLen)
               == false);

    /* SSFBase64Dec32To24 with b24outSize=1 on non-padded 2-byte block must return 0 */
    SSF_ASSERT(SSFBase64Dec32To24("YWI=", b24, 1) == 0);
    /* SSFBase64Dec32To24 with b24outSize=2 on non-padded 3-byte block must return 0 */
    SSF_ASSERT(SSFBase64Dec32To24("YWJj", b24, 2) == 0);
    /* SSFBase64Dec32To24 with b24outSize=1 on padded 1-byte block must succeed */
    SSF_ASSERT(SSFBase64Dec32To24("YQ==", b24, 1) == 1);
    SSF_ASSERT(b24[0] == 'a');
    /* SSFBase64Dec32To24 with b24outSize=2 on padded 2-byte block must succeed */
    SSF_ASSERT(SSFBase64Dec32To24("YWI=", b24, 2) == 2);
    SSF_ASSERT(memcmp(b24, "ab", 2) == 0);

    /* SSFBase64Decode with outSize=0 and empty input must succeed (vacuous decode) */
    outLen = 99;
    SSF_ASSERT(SSFBase64Decode("", 0, decodedBigBin, 0, &outLen) == true);
    SSF_ASSERT(outLen == 0);
}
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */

