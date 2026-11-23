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
        /* "Hello" is "SGVsbG8=" in standard base64, "SGVsbG8" (no padding) in base64url */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"Hello", 5, out, sizeof(out),
                   &outLen) == true);
        SSF_ASSERT(memcmp(out, "SGVsbG8", 7u) == 0);
        SSF_ASSERT(outLen == 7u);
        /* Null-terminated where the first stripped '=' used to be */
        SSF_ASSERT(out[7] == '\0');
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

    /* ---- URL-safe characters: standard base64 of 3E FF 3F is "Pv8/", so '/' -> '_' ---- */
    {
        const uint8_t data[] = { 0x3E, 0xFF, 0x3F };
        char encoded[32];
        size_t encodedLen;
        size_t i;

        SSF_ASSERT(SSFBase64URLEncode(data, sizeof(data), encoded, sizeof(encoded),
                   &encodedLen) == true);
        SSF_ASSERT(encodedLen == 4u && memcmp(encoded, "Pv8_", 4u) == 0);
        SSF_ASSERT(encoded[4] == '\0');
        /* Verify no +, /, or = in output */
        for (i = 0; i < encodedLen; i++)
        {
            SSF_ASSERT(encoded[i] != '+');
            SSF_ASSERT(encoded[i] != '/');
            SSF_ASSERT(encoded[i] != '=');
        }
    }

    /* ---- Known-answer vectors that pin both substitutions at exact positions. A round ---- */
    /* ---- trip cannot catch '+' and '/' mapped to the wrong URL char if decode swaps too. ---- */
    {
        /* RFC 7515 Appendix C: 03 EC FF E0 C1 <-> "A-z_4ME" (standard "A+z/4ME=") */
        static const uint8_t rfc7515[] = { 0x03u, 0xECu, 0xFFu, 0xE0u, 0xC1u };
        /* ssfbase64url.md example: FB FF <-> "-_8" (standard "+/8=") */
        static const uint8_t mdExample[] = { 0xFBu, 0xFFu };
        char encoded[16];
        size_t encodedLen;
        uint8_t decoded[8];
        size_t decodedLen;

        SSF_ASSERT(SSFBase64URLEncode(rfc7515, sizeof(rfc7515), encoded, sizeof(encoded),
                                      &encodedLen) == true);
        SSF_ASSERT(encodedLen == 7u && memcmp(encoded, "A-z_4ME", 7u) == 0);
        SSF_ASSERT(encoded[7] == '\0');
        SSF_ASSERT(SSFBase64URLDecode("A-z_4ME", 7u, decoded, sizeof(decoded),
                                      &decodedLen) == true);
        SSF_ASSERT(decodedLen == 5u && memcmp(decoded, rfc7515, 5u) == 0);
        SSF_ASSERT(SSFBase64URLDecode("A-z_4ME=", 8u, decoded, sizeof(decoded),
                                      &decodedLen) == true);
        SSF_ASSERT(decodedLen == 5u && memcmp(decoded, rfc7515, 5u) == 0);
        /* The standard-alphabet spelling of the same data is rejected */
        SSF_ASSERT(SSFBase64URLDecode("A+z/4ME", 7u, decoded, sizeof(decoded),
                                      &decodedLen) == false);
        /* Swapped substitutions decode to different bytes, so they must not compare equal */
        SSF_ASSERT(SSFBase64URLDecode("A_z-4ME", 7u, decoded, sizeof(decoded),
                                      &decodedLen) == true);
        SSF_ASSERT(memcmp(decoded, rfc7515, 5u) != 0);

        SSF_ASSERT(SSFBase64URLEncode(mdExample, sizeof(mdExample), encoded, sizeof(encoded),
                                      &encodedLen) == true);
        SSF_ASSERT(encodedLen == 3u && memcmp(encoded, "-_8", 3u) == 0);
        SSF_ASSERT(encoded[3] == '\0');
        SSF_ASSERT(SSFBase64URLDecode("-_8", 3u, decoded, sizeof(decoded), &decodedLen) == true);
        SSF_ASSERT(decodedLen == 2u && decoded[0] == 0xFBu && decoded[1] == 0xFFu);
        SSF_ASSERT(SSFBase64URLDecode("-_8=", 4u, decoded, sizeof(decoded), &decodedLen) == true);
        SSF_ASSERT(decodedLen == 2u && decoded[0] == 0xFBu && decoded[1] == 0xFFu);
        SSF_ASSERT(SSFBase64URLDecode("+/8", 3u, decoded, sizeof(decoded), &decodedLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("+/8=", 4u, decoded, sizeof(decoded), &decodedLen) == false);
    }

    /* ---- Empty input ---- */
    {
        char out[8];
        size_t outLen;
        out[0] = 'X';
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"", 0, out, sizeof(out),
                   &outLen) == true);
        SSF_ASSERT(outLen == 0u);
        SSF_ASSERT(out[0] == '\0');
        /* The smallest legal buffer holds just the terminator */
        out[0] = 'X';
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"", 0, out, 1u, &outLen) == true);
        SSF_ASSERT(outLen == 0u && out[0] == '\0');
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
        size_t encodedLen;
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

    /* ---- Size guard: the longest documented length, MAX - 5, is accepted and decoded ---- */
    {
        char longest[SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN];
        uint8_t big[((SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN / 4u) + 1u) * 3u];
        size_t len = SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 5u;
        size_t expected;
        size_t outLen;
        size_t i;

        /* Length 1 mod 4 is never valid Base64: step down one so only the guard is exercised */
        if ((len % 4u) == 1u) len--;
        expected = ((len / 4u) * 3u) + (((len % 4u) == 0u) ? 0u : ((len % 4u) - 1u));

        memset(longest, 'A', sizeof(longest));
        SSF_ASSERT(SSFBase64URLDecode(longest, len, big, sizeof(big), &outLen) == true);
        SSF_ASSERT(outLen == expected);
        for (i = 0; i < outLen; i++) SSF_ASSERT(big[i] == 0u);
    }

    /* ---- Exact-fit output buffers: outSize equal to the decoded length succeeds ---- */
    {
        uint8_t out[8];
        size_t outLen;

        memset(out, 0xEE, sizeof(out));
        SSF_ASSERT(SSFBase64URLDecode("YQ", 2u, out, 1u, &outLen) == true);
        SSF_ASSERT(outLen == 1u && out[0] == 'a' && out[1] == 0xEEu);
        SSF_ASSERT(SSFBase64URLDecode("YWI", 3u, out, 2u, &outLen) == true);
        SSF_ASSERT(outLen == 2u && memcmp(out, "ab", 2u) == 0 && out[2] == 0xEEu);
        SSF_ASSERT(SSFBase64URLDecode("YWJj", 4u, out, 3u, &outLen) == true);
        SSF_ASSERT(outLen == 3u && memcmp(out, "abc", 3u) == 0 && out[3] == 0xEEu);
        /* Multi-block: the second block's partial-size checks see exactly the bytes left */
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8", 7u, out, 5u, &outLen) == true);
        SSF_ASSERT(outLen == 5u && memcmp(out, "Hello", 5u) == 0 && out[5] == 0xEEu);
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8=", 8u, out, 5u, &outLen) == true);
        SSF_ASSERT(outLen == 5u && memcmp(out, "Hello", 5u) == 0);
        SSF_ASSERT(SSFBase64URLDecode("YWJjZGVm", 8u, out, 6u, &outLen) == true);
        SSF_ASSERT(outLen == 6u && memcmp(out, "abcdef", 6u) == 0 && out[6] == 0xEEu);
        /* One byte short in every position fails */
        SSF_ASSERT(SSFBase64URLDecode("YWJj", 4u, out, 2u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("YWJjZGVm", 8u, out, 5u, &outLen) == false);
    }

    /* ---- outSize == 0 is legal: nothing can be written, so non-empty input fails ---- */
    {
        uint8_t out[4];
        size_t outLen;

        memset(out, 0xEE, sizeof(out));
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AA", 2u, out, 0u, &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        /* Nothing written or scrubbed */
        SSF_ASSERT(out[0] == 0xEEu);
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AAAA", 4u, out, 0u, &outLen) == false);
        SSF_ASSERT(outLen == 0u && out[0] == 0xEEu);
        /* Empty input into a zero-size buffer is the one vacuous success */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("", 0u, out, 0u, &outLen) == true);
        SSF_ASSERT(outLen == 0u && out[0] == 0xEEu);
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

    /* ---- Output buffer too small - encode. The padded form is produced first, so the ---- */
    /* ---- buffer must hold ((inLen + 2) / 3) * 4 + 1 bytes even though the result is shorter. */
    {
        char out[16];
        size_t outLen;

        /* "Hello" (5 bytes): unpadded result "SGVsbG8" is 7 chars but padded is 8, so 9 min. */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"Hello", 5u, out, 7u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"Hello", 5u, out, 8u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"Hello", 5u, out, 9u, &outLen) == true);
        SSF_ASSERT(outLen == 7u && memcmp(out, "SGVsbG8", 7u) == 0 && out[7] == '\0');

        /* 1 byte: unpadded "YQ" + NUL would fit in 3, but padded "YQ==" needs 5. */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"a", 1u, out, 3u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"a", 1u, out, 4u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"a", 1u, out, 5u, &outLen) == true);
        SSF_ASSERT(outLen == 2u && memcmp(out, "YQ", 2u) == 0 && out[2] == '\0');

        /* 2 bytes: unpadded "YWI" + NUL would fit in 4, but padded "YWI=" needs 5. */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"ab", 2u, out, 4u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"ab", 2u, out, 5u, &outLen) == true);
        SSF_ASSERT(outLen == 3u && memcmp(out, "YWI", 3u) == 0 && out[3] == '\0');

        /* 3 bytes encodes to 4 chars with no padding; outSize=4 fails, outSize=5 succeeds. */
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"abc", 3u, out, 4u, &outLen) == false);
        SSF_ASSERT(SSFBase64URLEncode((const uint8_t *)"abc", 3u, out, 5u, &outLen) == true);
        SSF_ASSERT(outLen == 4u && memcmp(out, "YWJj", 4u) == 0 && out[4] == '\0');
    }

    /* ---- Encode failure contract: false leaves *outStrLen == 0 and outStr zeroed, so a ---- */
    /* ---- caller that ignores the return cannot pick up a partial standard-alphabet string. */
    {
        /* FB FF FB FF: standard "+//7/w==" so the partial first block would be "+//7" */
        static const uint8_t data[] = { 0xFBu, 0xFFu, 0xFBu, 0xFFu };
        char out[16];
        size_t outLen;
        size_t i;

        memset(out, 0xEE, sizeof(out));
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLEncode(data, sizeof(data), out, 8u, &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        SSF_ASSERT(out[0] == '\0');
        /* Whole buffer scrubbed and not one byte more */
        for (i = 0; i < 8u; i++) SSF_ASSERT(out[i] == '\0');
        SSF_ASSERT((uint8_t)out[8] == 0xEEu);

        /* Smallest legal buffer with non-empty input */
        memset(out, 0xEE, sizeof(out));
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLEncode(data, 1u, out, 1u, &outLen) == false);
        SSF_ASSERT(outLen == 0u && out[0] == '\0' && (uint8_t)out[1] == 0xEEu);

        /* Success after failure writes the full result */
        SSF_ASSERT(SSFBase64URLEncode(data, sizeof(data), out, 9u, &outLen) == true);
        SSF_ASSERT(outLen == 6u && memcmp(out, "-__7_w", 6u) == 0 && out[6] == '\0');
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

    /* ---- RFC 4648 Sec. 3.2: more than two pad chars can never be valid. ---- */
    {
        uint8_t out[16];
        size_t outLen;

        SSF_ASSERT(SSFBase64URLDecode("A===",     4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("====",     4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAAA===", 8u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAA====", 8u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("=",        1u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("==",       2u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("===",      3u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("A=",       2u, out, sizeof(out), &outLen) == false);
    }

    /* ---- Characters outside the Sec. 5 alphabet are rejected wherever they appear. ---- */
    /* ---- Whitespace is the common real-world case: Base64URL has no line breaks (Sec. 3.1). */
    {
        static const char highBit[] = "\xC3\xA9" "AA";
        uint8_t out[16];
        size_t outLen;

        SSF_ASSERT(SSFBase64URLDecode(" AAA",      4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAA ",     5u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAA AAAA", 9u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAA\r\n",  6u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAAA\n",    5u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AA\tA",     4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AA.A",      4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AA,A",      4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AA:A",      4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AA~A",      4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode(highBit,     4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("{AAA",      4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAA\x7F",   4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(SSFBase64URLDecode("AAA\x01",   4u, out, sizeof(out), &outLen) == false);
    }

    /* ---- inStrLen is honored over any terminator: a prefix of a longer buffer decodes. ---- */
    {
        uint8_t out[16];
        size_t outLen;

        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8XYZ", 7u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 5u && memcmp(out, "Hello", 5u) == 0);
        /* The trailing chars after the prefix may even be invalid and are never looked at */
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8+/= ", 7u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 5u && memcmp(out, "Hello", 5u) == 0);
        /* A shorter prefix that is itself 1 mod 4 fails */
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8", 5u, out, sizeof(out), &outLen) == false);
        /* A 4-char prefix decodes the first block only */
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8", 4u, out, sizeof(out), &outLen) == true);
        SSF_ASSERT(outLen == 3u && memcmp(out, "Hel", 3u) == 0);
    }

    /* ---- Failure contract: false leaves *outLen == 0 and no partial bytes in out. ---- */
    {
        uint8_t out[16];
        size_t outLen;
        char oversized[SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN];

        memset(oversized, 'A', sizeof(oversized));

        /* Bad char after good block */
        memset(out, 0xEE, sizeof(out)); outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AAAA!!!!", 8u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        SSF_ASSERT(out[0] == 0u && out[1] == 0u && out[2] == 0u);
        /* Scrub is bounded: 3 decoded + at most 2 partial bytes */
        SSF_ASSERT(out[5] == 0xEEu);

        /* '+' rejected by wrapper */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AA+A", 4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);

        /* Partial padding */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AA=", 3u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);

        /* Size guard */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode(oversized, sizeof(oversized), out, sizeof(out), &outLen)
                   == false);
        SSF_ASSERT(outLen == 0u);

        /* Output buffer too small */
        memset(out, 0xEE, sizeof(out)); outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("SGVsbG8", 7u, out, 4u, &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        SSF_ASSERT(out[0] == 0u && out[1] == 0u && out[2] == 0u);
        /* Rejected block wrote out[3] before running out of room; scrubbed, not past outSize */
        SSF_ASSERT(out[3] == 0u);
        SSF_ASSERT(out[4] == 0xEEu);

        /* Two partial bytes of the rejected block: 8 chars = 6 bytes into 5 writes out[3..4] */
        memset(out, 0xEE, sizeof(out)); outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("YWJjZGVm", 8u, out, 5u, &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        SSF_ASSERT(out[0] == 0u && out[1] == 0u && out[2] == 0u && out[3] == 0u && out[4] == 0u);
        SSF_ASSERT(out[5] == 0xEEu);

        /* Bad char in the first block: nothing decoded, scrub of (0 + 2) bytes still bounded */
        memset(out, 0xEE, sizeof(out)); outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("A!AA", 4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        SSF_ASSERT(out[0] == 0u && out[1] == 0u);
        SSF_ASSERT(out[2] == 0xEEu);
        memset(out, 0xEE, sizeof(out)); outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("A!AA", 4u, out, 1u, &outLen) == false);
        SSF_ASSERT(outLen == 0u && out[0] == 0u && out[1] == 0xEEu);

        /* Remaining false paths all report zero: length 1 mod 4 */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("A", 1u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        /* Length 1 mod 4, 2nd block */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AAAAA", 5u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        /* Non-canonical */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AP", 2u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        /* Non-canonical, 2nd block */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AAAAAP", 6u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        /* Excess padding */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("A===", 4u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        /* Interior padding */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AA=AAAA", 7u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
        /* Whitespace */
        outLen = 99u;
        SSF_ASSERT(SSFBase64URLDecode("AAAA\n", 5u, out, sizeof(out), &outLen) == false);
        SSF_ASSERT(outLen == 0u);
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
