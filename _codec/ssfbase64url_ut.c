/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbase64url_ut.c                                                                             */
/* Provides unit tests for Base64URL encoder/decoder.                                            */
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
#include "ssfbase64url.h"
#include "ssfport.h"

#if SSF_CONFIG_BASE64URL_UNIT_TEST == 1

void SSFBase64URLUnitTest(void)
{
    /* ---- Encode: known input ---- */
    {
        char out[64];
        size_t outLen;
        /* "Hello" in standard base64 = "SGVsbG8=" */
        /* In base64url = "SGVsbG8" (no padding) */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"Hello", 5, out, sizeof(out),
                   &outLen) == true);
        SSF_ASSERT(memcmp(out, "SGVsbG8", 7u) == 0);
        SSF_ASSERT(outLen == 7u);
    }

    /* ---- Decode: known input ---- */
    {
        uint8_t out[64];
        size_t outLen;
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8", 7, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 5u);
        SSF_ASSERT(memcmp(out, "Hello", 5u) == 0);
    }

    /* ---- Round-trip ---- */
    {
        const uint8_t data[] = { 0xFB, 0xFF, 0xFE, 0x01, 0x02, 0x03 };
        char encoded[32];
        size_t encodedLen;
        uint8_t decoded[32];
        size_t decodedLen;

        SSF_ASSERT(SSFBase64URLEncode(data, sizeof(data), encoded, sizeof(encoded),
                   &encodedLen) == true);
        SSF_ASSERT(SSFBase64URLDecode(encoded, encodedLen, decoded, sizeof(decoded),
                   &decodedLen) == true);
        SSF_ASSERT(decodedLen == sizeof(data));
        SSF_ASSERT(memcmp(decoded, data, sizeof(data)) == 0);
    }

    /* ---- URL-safe characters: input that produces + and / in standard base64 ---- */
    {
        const uint8_t data[] = { 0x3E, 0xFF, 0x3F };  /* produces +/= chars in std base64 */
        char encoded[32];
        size_t encodedLen;
        size_t i;

        SSF_ASSERT(SSFBase64URLEncode(data, sizeof(data), encoded, sizeof(encoded),
                   &encodedLen) == true);
        /* Verify no +, /, or = in output */
        for (i = 0; i < encodedLen; i++)
        {
            SSF_ASSERT(encoded[i] != '+');
            SSF_ASSERT(encoded[i] != '/');
            SSF_ASSERT(encoded[i] != '=');
        }
    }

    /* ---- Empty input ---- */
    {
        char out[8];
        size_t outLen;
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"", 0, out, sizeof(out),
                   &outLen) == true);
        SSF_ASSERT(outLen == 0u);
    }

    /* ---- RFC 4648 Sec. 3.3: '+' and '/' are Sec. 4 chars outside the Sec. 5 alphabet. ---- */
    {
        uint8_t out[16];
        size_t outLen;

        /* '+' anywhere in input: rejected. */
        SSF_ASSERT(SSFBase64URLDecode("YW+W",   4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("+AAA",   4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAA+",   4u, out, sizeof(out), &outLen) == false);

        /* '/' anywhere in input: rejected. */
        SSF_ASSERT(SSFBase64URLDecode("YW/W",   4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("/AAA",   4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAA/",   4u, out, sizeof(out), &outLen) == false);

        /* Sanity: the URL-safe equivalents ('-' and '_') still decode. */
        SSF_ASSERT(SSFBase64URLDecode("YW-W",   4u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(SSFBase64URLDecode("YW_W",   4u, out, sizeof(out), &outLen) == true);
    }

    /* ---- Round-trip all 256 byte values: Sec. 5 alphabet only, decoded bytes match input. ---- */
    {
        uint8_t in[256];
        char    encoded[512];
        size_t  encodedLen;
        uint8_t decoded[256];
        size_t  decodedLen;
        size_t  i;

        for (i = 0; i < sizeof(in); i++) in[i] = (uint8_t)i;
        SSF_ASSERT(SSFBase64URLEncode(in, sizeof(in), encoded, sizeof(encoded),
                                      &encodedLen) == true);
        for (i = 0; i < encodedLen; i++)
        {
            char ch = encoded[i];
            bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                      (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            SSF_ASSERT(ok);
        }
        SSF_ASSERT(SSFBase64URLDecode(encoded, encodedLen, decoded, sizeof(decoded),
                                      &decodedLen) == true);
        SSF_ASSERT(decodedLen == sizeof(in));
        SSF_ASSERT(memcmp(decoded, in, sizeof(in)) == 0);
    }

    /* ---- Padded input on decode (header contract: accepts padded or unpadded, Sec. 3.2). ---- */
    {
        uint8_t out[8];
        size_t outLen;

        /* "Hello" padded: standard base64 "SGVsbG8=" must also decode per Sec. 3.2. */
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8=", 8u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 5u);
        SSF_ASSERT(memcmp(out, "Hello", 5u) == 0);

        /* 1-byte output, fully padded. */
        SSF_ASSERT(SSFBase64URLDecode("YQ==", 4u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 1u && out[0] == 'a');

        /* 2-byte output, fully padded. */
        SSF_ASSERT(SSFBase64URLDecode("YWI=", 4u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 2u && memcmp(out, "ab", 2u) == 0);

        /* Same content unpadded. */
        SSF_ASSERT(SSFBase64URLDecode("YQ", 2u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 1u && out[0] == 'a');
        SSF_ASSERT(SSFBase64URLDecode("YWI", 3u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 2u && memcmp(out, "ab", 2u) == 0);
    }

    /* ---- Size guard: inLen >= SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 4 rejected. ---- */
    {
        char oversized[SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN];
        uint8_t out[16];
        size_t outLen;

        memset(oversized, 'A', sizeof(oversized));  /* valid Sec. 5 chars */

        /* Exactly the guard threshold: rejected. */
        SSF_ASSERT(SSFBase64URLDecode(oversized,
                                      (size_t)(SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 4u),
                                      out, sizeof(out), &outLen) == false);

        /* Well above the threshold: rejected. */
        SSF_ASSERT(SSFBase64URLDecode(oversized,
                                      (size_t)SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN,
                                      out, sizeof(out), &outLen) == false);
    }

    /* ---- Output buffer too small - decode ---- */
    {
        uint8_t out[4];
        size_t outLen;

        /* "SGVsbG8" decodes to 5 bytes; outSize=4 must fail. */
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8", 7u, out, 4u, &outLen) == false);
        /* Even outSize=1 too small for a 2-byte decode. */
        SSF_ASSERT(SSFBase64URLDecode("YWI", 3u, out, 1u, &outLen) == false);
    }

    /* ---- Output buffer too small - encode ---- */
    {
        char out[8];
        size_t outLen;

        /* "Hello" (5 bytes) encodes to 7 chars + NUL = 8 bytes min. outSize=7 fails. */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"Hello", 5u, out, 7u, &outLen) == false);
        /* 3 bytes encodes to 4 chars + NUL; outSize=4 fails, outSize=5 succeeds. */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"abc", 3u, out, 4u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"abc", 3u, out, 5u, &outLen) == true);
        SSF_ASSERT(outLen == 4u && memcmp(out, "YWJj", 4u) == 0);
    }

    /* ---- Non-canonical input rejected via the wrapper (ssfbase64 Sec. 3.5 check). ---- */
    {
        uint8_t out[8];
        size_t outLen;

        /* "AP==" (padded) - b's low 4 bits non-zero. */
        SSF_ASSERT(SSFBase64URLDecode("AP==", 4u, out, sizeof(out), &outLen) == false);
        /* "AP" (unpadded) - padded to "AP==" internally, same rejection. */
        SSF_ASSERT(SSFBase64URLDecode("AP",   2u, out, sizeof(out), &outLen) == false);
        /* "AAB=" (padded) - c's low 2 bits non-zero. */
        SSF_ASSERT(SSFBase64URLDecode("AAB=", 4u, out, sizeof(out), &outLen) == false);
        /* "AAB" (unpadded). */
        SSF_ASSERT(SSFBase64URLDecode("AAB",  3u, out, sizeof(out), &outLen) == false);
    }

    /* ---- Zero-length decode: vacuous success with outLen=0. ---- */
    {
        uint8_t out[1];
        size_t outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("", 0u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 0u);
    }

    /* ---- RFC 4648 Sec. 3.3 / 4: '=' only at the very end, else decoding is malleable. ---- */
    {
        uint8_t out[16];
        size_t outLen;

        SSF_ASSERT(SSFBase64URLDecode("AA==AAAA", 8u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAA=AAAA", 8u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("YQ==YQ==", 8u, out, sizeof(out), &outLen) == false);
        /* Interior '=' that the re-padding step would otherwise complete into a valid block. */
        SSF_ASSERT(SSFBase64URLDecode("AA=AAAA",  7u, out, sizeof(out), &outLen) == false);
        /* Final-block padding is still accepted. */
        SSF_ASSERT(SSFBase64URLDecode("AAAAAA==", 8u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 4u);
    }

    /* ---- RFC 4648 Sec. 3.2: padding is all-or-nothing, partial padding is rejected. ---- */
    {
        uint8_t out[16];
        size_t outLen;

        SSF_ASSERT(SSFBase64URLDecode("AA=",      3u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAAAA=",  7u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAAA=",   6u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("YWI=YQ=",  7u, out, sizeof(out), &outLen) == false);
        /* Fully padded and fully unpadded forms of the same data both still decode. */
        SSF_ASSERT(SSFBase64URLDecode("AA==",     4u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 1u);
        SSF_ASSERT(SSFBase64URLDecode("AA",       2u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 1u);
        SSF_ASSERT(SSFBase64URLDecode("AAAAAAA=", 8u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 5u);
        SSF_ASSERT(SSFBase64URLDecode("AAAAAAA",  7u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 5u);
    }

    /* ---- Failure contract: false leaves *outLen == 0 and no partial bytes in out. ---- */
    {
        uint8_t out[16];
        size_t outLen;
        char oversized[SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN];

        memset(oversized, 'A', sizeof(oversized));

        memset(out, 0xEE, sizeof(out)); outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AAAA!!!!", 8u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);                              /* bad char after good block */
        SSF_ASSERT(out[0] == 0u && out[1] == 0u && out[2] == 0u);
        SSF_ASSERT(out[5] == 0xEEu);  /* scrub is bounded: 3 decoded + at most 2 partial bytes */

        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AA+A", 4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);                              /* '+' rejected by wrapper */

        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AA=", 3u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);                              /* partial padding */

        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode(oversized, sizeof(oversized), out, sizeof(out), &outLen)
                   == false);
        SSF_ASSERT(outLen == 0u);                              /* size guard */

        memset(out, 0xEE, sizeof(out)); outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8", 7u, out, 4u, &outLen) == false);
        SSF_ASSERT(outLen == 0u);                              /* output buffer too small */
        SSF_ASSERT(out[0] == 0u && out[1] == 0u && out[2] == 0u);
    }

    /* ---- inLen mod 4 == 1: one char cannot encode a byte, "X===" is rejected. ---- */
    {
        uint8_t out[4];
        size_t outLen;
        SSF_ASSERT(SSFBase64URLDecode("A", 1u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAAA", 5u, out, sizeof(out), &outLen) == false);
    }

    /* ---- Decode all 64 Sec. 5 alphabet chars to 48 bytes, re-encode must match input. ---- */
    {
        static const char alpha64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        uint8_t decoded[48];
        size_t decodedLen;
        char reencoded[65];
        size_t reencodedLen;

        SSF_ASSERT(SSFBase64URLDecode(alpha64, 64u, decoded, sizeof(decoded),
                                      &decodedLen) == true);
        SSF_ASSERT(decodedLen == 48u);
        SSF_ASSERT(SSFBase64URLEncode(decoded, decodedLen, reencoded, sizeof(reencoded),
                                      &reencodedLen) == true);
        SSF_ASSERT(reencodedLen == 64u);
        SSF_ASSERT(memcmp(reencoded, alpha64, 64u) == 0);
    }

    /* ---- NULL-pointer SSF_REQUIRE assertions for both encode and decode. ---- */
    {
        uint8_t buf[4];
        size_t outLen;
        SSF_ASSERT_TEST(SSFBase64URLEncode(NULL,  1u, (char *)buf, sizeof(buf), &outLen));
        SSF_ASSERT_TEST(SSFBase64URLEncode(buf,   1u, NULL,        sizeof(buf), &outLen));
        SSF_ASSERT_TEST(SSFBase64URLEncode(buf,   1u, (char *)buf, sizeof(buf), NULL));
        /* outSize == 0 cannot hold even the NUL terminator: a precondition, not a false return. */
        SSF_ASSERT_TEST(SSFBase64URLEncode(buf,   1u, (char *)buf, 0u,          &outLen));
        SSF_ASSERT_TEST(SSFBase64URLEncode(buf,   0u, (char *)buf, 0u,          &outLen));
        SSF_ASSERT_TEST(SSFBase64URLDecode(NULL,  1u, buf,         sizeof(buf), &outLen));
        SSF_ASSERT_TEST(SSFBase64URLDecode("A",   1u, NULL,        sizeof(buf), &outLen));
        SSF_ASSERT_TEST(SSFBase64URLDecode("A",   1u, buf,         sizeof(buf), NULL));
    }

    /* ---- Output-length formula: N bytes -> ceil(4N/3) chars unpadded per RFC 4648 Sec. 5. ---- */
    {
        static const struct { size_t inLen; size_t expectedOutLen; } cases[] = {
            { 0, 0 }, { 1, 2 }, { 2, 3 }, { 3, 4 },
            { 4, 6 }, { 5, 7 }, { 6, 8 }, { 7, 10 }, { 8, 11 }, { 9, 12 },
        };
        uint8_t in[9];
        char out[16];
        size_t outLen;
        size_t k;

        memset(in, 0x5A, sizeof(in));
        for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
        {
            SSF_ASSERT(SSFBase64URLEncode(in, cases[k].inLen, out, sizeof(out),
                                          &outLen) == true);
            SSF_ASSERT(outLen == cases[k].expectedOutLen);
        }
    }

    /* ---- Edge byte patterns: all-zero and all-0xFF inputs, plus single-byte extremes. ---- */
    {
        uint8_t zeros[8];
        uint8_t ones[8];
        uint8_t decoded[8];
        char encoded[16];
        size_t encodedLen;
        size_t decodedLen;

        memset(zeros, 0x00, sizeof(zeros));
        memset(ones,  0xFF, sizeof(ones));

        SSF_ASSERT(SSFBase64URLEncode(zeros, sizeof(zeros), encoded, sizeof(encoded),
                                      &encodedLen) == true);
        SSF_ASSERT(SSFBase64URLDecode(encoded, encodedLen, decoded, sizeof(decoded),
                                      &decodedLen) == true);
        SSF_ASSERT(decodedLen == sizeof(zeros));
        SSF_ASSERT(memcmp(decoded, zeros, sizeof(zeros)) == 0);

        SSF_ASSERT(SSFBase64URLEncode(ones, sizeof(ones), encoded, sizeof(encoded),
                                      &encodedLen) == true);
        SSF_ASSERT(SSFBase64URLDecode(encoded, encodedLen, decoded, sizeof(decoded),
                                      &decodedLen) == true);
        SSF_ASSERT(decodedLen == sizeof(ones));
        SSF_ASSERT(memcmp(decoded, ones, sizeof(ones)) == 0);

        /* Single-byte extremes. */
        {
            uint8_t one = 0x00;
            SSF_ASSERT(SSFBase64URLEncode(&one, 1u, encoded, sizeof(encoded),
                                          &encodedLen) == true);
            SSF_ASSERT(SSFBase64URLDecode(encoded, encodedLen, decoded, sizeof(decoded),
                                          &decodedLen) == true);
            SSF_ASSERT(decodedLen == 1u && decoded[0] == 0x00);

            one = 0xFF;
            SSF_ASSERT(SSFBase64URLEncode(&one, 1u, encoded, sizeof(encoded),
                                          &encodedLen) == true);
            SSF_ASSERT(SSFBase64URLDecode(encoded, encodedLen, decoded, sizeof(decoded),
                                          &decodedLen) == true);
            SSF_ASSERT(decodedLen == 1u && decoded[0] == 0xFF);
        }
    }

    /* ---- Embedded NUL: decoder honors inLen not strlen, NUL is not a Sec. 5 char. ---- */
    {
        static const char nulInMiddle[4] = { 'Y', 'W', '\0', 'j' };
        uint8_t out[4];
        size_t outLen;
        SSF_ASSERT(SSFBase64URLDecode(nulInMiddle, 4u, out, sizeof(out), &outLen) == false);
    }
}
#endif /* SSF_CONFIG_BASE64URL_UNIT_TEST */
