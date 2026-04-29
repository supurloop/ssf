/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpoly1305_ut.c                                                                              */
/* Provides Poly1305 MAC unit test (RFC 7539).                                                   */
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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfpoly1305.h"

/* Cross-validate Poly1305 against OpenSSL on host builds where libcrypto is linked. Same      */
/* gating pattern as ssfaesctr_ut.c. When disabled (cross builds with                          */
/* -DSSF_CONFIG_HAVE_OPENSSL=0) the RFC 8439 KAT plus internal corner cases are the load-      */
/* bearing correctness coverage.                                                                */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_POLY1305_UNIT_TEST == 1)
#define SSF_POLY1305_OSSL_VERIFY 1
#else
#define SSF_POLY1305_OSSL_VERIFY 0
#endif

#if SSF_POLY1305_OSSL_VERIFY == 1
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#endif

#if SSF_CONFIG_POLY1305_UNIT_TEST == 1

#if SSF_POLY1305_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers.                                                                  */
/* --------------------------------------------------------------------------------------------- */

/* One-shot Poly1305 via OpenSSL's EVP_MAC ("POLY1305" provider). */
static void _OSSLPoly1305(const uint8_t key[SSF_POLY1305_KEY_SIZE],
                          const uint8_t *msg, size_t msgLen,
                          uint8_t tag[SSF_POLY1305_TAG_SIZE])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[2];
    size_t outL = 0;

    SSF_ASSERT(mac != NULL);
    ctx = EVP_MAC_CTX_new(mac);
    SSF_ASSERT(ctx != NULL);

    params[0] = OSSL_PARAM_construct_octet_string("key", (void *)key, SSF_POLY1305_KEY_SIZE);
    params[1] = OSSL_PARAM_construct_end();
    SSF_ASSERT(EVP_MAC_init(ctx, NULL, 0u, params) == 1);
    if (msgLen > 0u) SSF_ASSERT(EVP_MAC_update(ctx, msg, msgLen) == 1);
    SSF_ASSERT(EVP_MAC_final(ctx, tag, &outL, SSF_POLY1305_TAG_SIZE) == 1);
    SSF_ASSERT(outL == SSF_POLY1305_TAG_SIZE);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz across message lengths spanning the 16-byte Poly1305 block boundary plus the    */
/* multi-block / partial-final-block paths. Each cell hashes via SSF one-shot AND incremental   */
/* (mid-message split) and compares both against OpenSSL.                                        */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyPoly1305AgainstOpenSSLRandom(void)
{
    static const size_t lens[] = {0u, 1u, 15u, 16u, 17u, 31u, 32u, 33u, 63u, 64u, 65u, 127u, 128u,
                                  129u, 256u, 1024u, 4096u};
    uint8_t key[SSF_POLY1305_KEY_SIZE];
    uint8_t msg[4096];
    uint8_t tagSSF[SSF_POLY1305_TAG_SIZE];
    uint8_t tagSSFInc[SSF_POLY1305_TAG_SIZE];
    uint8_t tagOSSL[SSF_POLY1305_TAG_SIZE];
    size_t lIdx;
    int iter;

    for (lIdx = 0; lIdx < (sizeof(lens) / sizeof(lens[0])); lIdx++)
    {
        for (iter = 0; iter < 10; iter++)
        {
            size_t len = lens[lIdx];
            SSFPoly1305Context_t ctx = {0};

            SSF_ASSERT(RAND_bytes(key, sizeof(key)) == 1);
            if (len > 0u) SSF_ASSERT(RAND_bytes(msg, (int)len) == 1);

            SSFPoly1305Mac(len ? msg : NULL, len, key, sizeof(key), tagSSF, sizeof(tagSSF));
            _OSSLPoly1305(key, msg, len, tagOSSL);
            SSF_ASSERT(memcmp(tagSSF, tagOSSL, SSF_POLY1305_TAG_SIZE) == 0);

            /* Incremental: feed first half then second half. */
            SSFPoly1305Begin(&ctx, key, sizeof(key));
            if (len > 0u)
            {
                SSFPoly1305Update(&ctx, msg, len / 2u);
                SSFPoly1305Update(&ctx, &msg[len / 2u], len - len / 2u);
            }
            SSFPoly1305End(&ctx, tagSSFInc, sizeof(tagSSFInc));
            SSF_ASSERT(memcmp(tagSSFInc, tagOSSL, SSF_POLY1305_TAG_SIZE) == 0);
        }
    }
}
#endif /* SSF_POLY1305_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* RFC 7539 Section 2.5.2 test vector                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFPoly1305UnitTest(void)
{
    /* RFC 7539 Section 2.5.2 */
    static const uint8_t key[] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    static const uint8_t msg[] = {
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
        0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
        0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
        0x75, 0x70
    };
    static const uint8_t expected_tag[] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };
    uint8_t tag[16];

    /* Test RFC 7539 Section 2.5.2 vector */
    SSFPoly1305Mac(msg, sizeof(msg), key, sizeof(key), tag, sizeof(tag));
    SSF_ASSERT(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0);

    /* Empty message with r=1, s=0 → tag = (h=0) + s = 0. Asserts the empty-message path
     * actually emits the algebraically-required all-zero tag, instead of just "doesn't crash". */
    {
        static const uint8_t zeroKey[32] = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        static const uint8_t expectedZeroTag[16] = {0};
        uint8_t emptyTag[16];

        SSFPoly1305Mac(NULL, 0, zeroKey, sizeof(zeroKey), emptyTag, sizeof(emptyTag));
        SSF_ASSERT(memcmp(emptyTag, expectedZeroTag, sizeof(expectedZeroTag)) == 0);
    }

    /* RFC 8439 §A.3 Test Vector #1: all-zero key + 64-byte all-zero msg → all-zero tag.
     * Catches any path that would fail to emit zero when both r and s are zero (defensive
     * floor for the corner case where the multiply produces no contribution). */
    {
        static const uint8_t tv1Key[32] = {0};
        static const uint8_t tv1Msg[64] = {0};
        static const uint8_t expectedTag[16] = {0};
        uint8_t tv1Tag[16];

        SSFPoly1305Mac(tv1Msg, sizeof(tv1Msg), tv1Key, sizeof(tv1Key), tv1Tag, sizeof(tv1Tag));
        SSF_ASSERT(memcmp(tv1Tag, expectedTag, sizeof(expectedTag)) == 0);
    }

    /* RFC 8439 §A.3 Test Vector #5: r=2 (clamped from `02 00…`), s=0, msg = `ff × 16`.
     * Specifically chosen to exercise the modular reduction near 2^130: the single block
     * `ff × 16 || 01` interpreted as a 130-bit number is 2^128 + (2^128 - 1); multiplying
     * by 2 wraps past 2^130, exercising the `c * 5` carry-propagation path. Expected
     * tag = 0x03 in low byte, rest zero. Cross-build coverage for the carry-edge case
     * that the OpenSSL fuzz catches on host. */
    {
        static const uint8_t tv5Key[32] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        static const uint8_t carryMsg[16] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        static const uint8_t expectedTag[16] = {
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        uint8_t tv5Tag[16];

        SSFPoly1305Mac(carryMsg, sizeof(carryMsg), tv5Key, sizeof(tv5Key), tv5Tag, sizeof(tv5Tag));
        SSF_ASSERT(memcmp(tv5Tag, expectedTag, sizeof(expectedTag)) == 0);
    }

    /* r=0 algebraic edge: with r clamped from `00 × 16` to 0, every multiply yields 0, so
     * the accumulator stays 0 regardless of message content and the final tag is exactly s.
     * Reuses the RFC 8439 §A.3 TV2 key (s = `36 e5 f6 b5 …`) but pairs it with the §2.5.2
     * 34-byte message rather than TV2's 375-byte IETF text -- the result is algebraically
     * determined by r=0 and is independent of message content. Catches a class of bugs
     * where the multiply path leaks state into the output even when r is zero. */
    {
        static const uint8_t r0Key[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x36, 0xE5, 0xF6, 0xB5, 0xC5, 0xE0, 0x60, 0x70,
            0xF0, 0xEF, 0xCA, 0x96, 0x22, 0x7A, 0x86, 0x3E
        };
        static const uint8_t expectedTag[16] = {
            0x36, 0xE5, 0xF6, 0xB5, 0xC5, 0xE0, 0x60, 0x70,
            0xF0, 0xEF, 0xCA, 0x96, 0x22, 0x7A, 0x86, 0x3E
        };
        uint8_t r0Tag[16];

        SSFPoly1305Mac(msg, sizeof(msg), r0Key, sizeof(r0Key), r0Tag, sizeof(r0Tag));
        SSF_ASSERT(memcmp(r0Tag, expectedTag, sizeof(expectedTag)) == 0);
    }

    /* RFC 8439 §A.3 Test Vector #3: r ≠ 0, s = 0, with a 375-byte multi-block IETF text.
     * Complement to the r=0 case above -- exercises the pure-r-mixing path across many MulR
     * iterations. Ensures multi-block reductions converge to the canonical h with no s-add. */
    {
        static const uint8_t tv3Key[] = {
            0x36u, 0xE5u, 0xF6u, 0xB5u, 0xC5u, 0xE0u, 0x60u, 0x70u,
            0xF0u, 0xEFu, 0xCAu, 0x96u, 0x22u, 0x7Au, 0x86u, 0x3Eu,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t text[] = {
            0x41u, 0x6Eu, 0x79u, 0x20u, 0x73u, 0x75u, 0x62u, 0x6Du,
            0x69u, 0x73u, 0x73u, 0x69u, 0x6Fu, 0x6Eu, 0x20u, 0x74u,
            0x6Fu, 0x20u, 0x74u, 0x68u, 0x65u, 0x20u, 0x49u, 0x45u,
            0x54u, 0x46u, 0x20u, 0x69u, 0x6Eu, 0x74u, 0x65u, 0x6Eu,
            0x64u, 0x65u, 0x64u, 0x20u, 0x62u, 0x79u, 0x20u, 0x74u,
            0x68u, 0x65u, 0x20u, 0x43u, 0x6Fu, 0x6Eu, 0x74u, 0x72u,
            0x69u, 0x62u, 0x75u, 0x74u, 0x6Fu, 0x72u, 0x20u, 0x66u,
            0x6Fu, 0x72u, 0x20u, 0x70u, 0x75u, 0x62u, 0x6Cu, 0x69u,
            0x63u, 0x61u, 0x74u, 0x69u, 0x6Fu, 0x6Eu, 0x20u, 0x61u,
            0x73u, 0x20u, 0x61u, 0x6Cu, 0x6Cu, 0x20u, 0x6Fu, 0x72u,
            0x20u, 0x70u, 0x61u, 0x72u, 0x74u, 0x20u, 0x6Fu, 0x66u,
            0x20u, 0x61u, 0x6Eu, 0x20u, 0x49u, 0x45u, 0x54u, 0x46u,
            0x20u, 0x49u, 0x6Eu, 0x74u, 0x65u, 0x72u, 0x6Eu, 0x65u,
            0x74u, 0x2Du, 0x44u, 0x72u, 0x61u, 0x66u, 0x74u, 0x20u,
            0x6Fu, 0x72u, 0x20u, 0x52u, 0x46u, 0x43u, 0x20u, 0x61u,
            0x6Eu, 0x64u, 0x20u, 0x61u, 0x6Eu, 0x79u, 0x20u, 0x73u,
            0x74u, 0x61u, 0x74u, 0x65u, 0x6Du, 0x65u, 0x6Eu, 0x74u,
            0x20u, 0x6Du, 0x61u, 0x64u, 0x65u, 0x20u, 0x77u, 0x69u,
            0x74u, 0x68u, 0x69u, 0x6Eu, 0x20u, 0x74u, 0x68u, 0x65u,
            0x20u, 0x63u, 0x6Fu, 0x6Eu, 0x74u, 0x65u, 0x78u, 0x74u,
            0x20u, 0x6Fu, 0x66u, 0x20u, 0x61u, 0x6Eu, 0x20u, 0x49u,
            0x45u, 0x54u, 0x46u, 0x20u, 0x61u, 0x63u, 0x74u, 0x69u,
            0x76u, 0x69u, 0x74u, 0x79u, 0x20u, 0x69u, 0x73u, 0x20u,
            0x63u, 0x6Fu, 0x6Eu, 0x73u, 0x69u, 0x64u, 0x65u, 0x72u,
            0x65u, 0x64u, 0x20u, 0x61u, 0x6Eu, 0x20u, 0x22u, 0x49u,
            0x45u, 0x54u, 0x46u, 0x20u, 0x43u, 0x6Fu, 0x6Eu, 0x74u,
            0x72u, 0x69u, 0x62u, 0x75u, 0x74u, 0x69u, 0x6Fu, 0x6Eu,
            0x22u, 0x2Eu, 0x20u, 0x53u, 0x75u, 0x63u, 0x68u, 0x20u,
            0x73u, 0x74u, 0x61u, 0x74u, 0x65u, 0x6Du, 0x65u, 0x6Eu,
            0x74u, 0x73u, 0x20u, 0x69u, 0x6Eu, 0x63u, 0x6Cu, 0x75u,
            0x64u, 0x65u, 0x20u, 0x6Fu, 0x72u, 0x61u, 0x6Cu, 0x20u,
            0x73u, 0x74u, 0x61u, 0x74u, 0x65u, 0x6Du, 0x65u, 0x6Eu,
            0x74u, 0x73u, 0x20u, 0x69u, 0x6Eu, 0x20u, 0x49u, 0x45u,
            0x54u, 0x46u, 0x20u, 0x73u, 0x65u, 0x73u, 0x73u, 0x69u,
            0x6Fu, 0x6Eu, 0x73u, 0x2Cu, 0x20u, 0x61u, 0x73u, 0x20u,
            0x77u, 0x65u, 0x6Cu, 0x6Cu, 0x20u, 0x61u, 0x73u, 0x20u,
            0x77u, 0x72u, 0x69u, 0x74u, 0x74u, 0x65u, 0x6Eu, 0x20u,
            0x61u, 0x6Eu, 0x64u, 0x20u, 0x65u, 0x6Cu, 0x65u, 0x63u,
            0x74u, 0x72u, 0x6Fu, 0x6Eu, 0x69u, 0x63u, 0x20u, 0x63u,
            0x6Fu, 0x6Du, 0x6Du, 0x75u, 0x6Eu, 0x69u, 0x63u, 0x61u,
            0x74u, 0x69u, 0x6Fu, 0x6Eu, 0x73u, 0x20u, 0x6Du, 0x61u,
            0x64u, 0x65u, 0x20u, 0x61u, 0x74u, 0x20u, 0x61u, 0x6Eu,
            0x79u, 0x20u, 0x74u, 0x69u, 0x6Du, 0x65u, 0x20u, 0x6Fu,
            0x72u, 0x20u, 0x70u, 0x6Cu, 0x61u, 0x63u, 0x65u, 0x2Cu,
            0x20u, 0x77u, 0x68u, 0x69u, 0x63u, 0x68u, 0x20u, 0x61u,
            0x72u, 0x65u, 0x20u, 0x61u, 0x64u, 0x64u, 0x72u, 0x65u,
            0x73u, 0x73u, 0x65u, 0x64u, 0x20u, 0x74u, 0x6Fu
        };
        static const uint8_t expectedTag[] = {
            0xF3u, 0x47u, 0x7Eu, 0x7Cu, 0xD9u, 0x54u, 0x17u, 0xAFu,
            0x89u, 0xA6u, 0xB8u, 0x79u, 0x4Cu, 0x31u, 0x0Cu, 0xF0u
        };
        uint8_t tv3Tag[16];

        SSFPoly1305Mac(text, sizeof(text), tv3Key, sizeof(tv3Key), tv3Tag, sizeof(tv3Tag));
        SSF_ASSERT(memcmp(tv3Tag, expectedTag, sizeof(expectedTag)) == 0);
    }

    /* RFC 8439 §A.3 Test Vector #6: r=2, s=ff×16, msg=`02 00…00`. Stresses the s-addition
     * carry propagation in the tag-write loop -- adding s=ff×16 to a non-zero h forces the
     * carry to walk through all four 32-bit assembly words. */
    {
        static const uint8_t tv6Key[] = {
            0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
        };
        static const uint8_t text[16] = {
            0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t expectedTag[] = {
            0x03u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        uint8_t tv6Tag[16];

        SSFPoly1305Mac(text, sizeof(text), tv6Key, sizeof(tv6Key), tv6Tag, sizeof(tv6Tag));
        SSF_ASSERT(memcmp(tv6Tag, expectedTag, sizeof(expectedTag)) == 0);
    }

    /* RFC 8439 §A.3 Test Vector #7: r=1, s=0, 48-byte msg crafted to push h to/past p across
     * three blocks. Specifically tests the constant-time `h - p` selection in End -- the
     * mask = (g4 >> 31) - 1u branch where the high-bit underflow distinguishes h<p from h≥p. */
    {
        static const uint8_t tv7Key[] = {
            0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t text[] = {
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xF0u, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0x11u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t expectedTag[] = {
            0x05u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        uint8_t tv7Tag[16];

        SSFPoly1305Mac(text, sizeof(text), tv7Key, sizeof(tv7Key), tv7Tag, sizeof(tv7Tag));
        SSF_ASSERT(memcmp(tv7Tag, expectedTag, sizeof(expectedTag)) == 0);
    }

    /* RFC 8439 §A.3 Test Vector #9: r=2, s=0, msg=`fd ff…ff`. Reduction edge complementary to
     * TV5 -- different upper-boundary pattern through MulR's `c * 5` carry-back-into-h0 path. */
    {
        static const uint8_t tv9Key[] = {
            0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t text[] = {
            0xFDu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
        };
        static const uint8_t expectedTag[] = {
            0xFAu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
        };
        uint8_t tv9Tag[16];

        SSFPoly1305Mac(text, sizeof(text), tv9Key, sizeof(tv9Key), tv9Tag, sizeof(tv9Tag));
        SSF_ASSERT(memcmp(tv9Tag, expectedTag, sizeof(expectedTag)) == 0);
    }

    /* Streaming API: Begin/Update/End over the RFC 7539 vector must produce the same tag
     * as the one-shot Mac. Run it several ways to exercise the partial-block hold-back
     * across the 16-byte block boundary: byte-by-byte, uneven chunks, and chunks that
     * straddle the boundary. */
    {
        SSFPoly1305Context_t ctx = {0};
        uint8_t streamTag[16];
        size_t i;

        /* Single Update over the whole message -- should match Mac exactly. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSFPoly1305Update(&ctx, msg, sizeof(msg));
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Byte-by-byte Update -- exercises the partial-block drain on every single call. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        for (i = 0; i < sizeof(msg); i++) SSFPoly1305Update(&ctx, &msg[i], 1u);
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Boundary-straddling chunks: 1, 15, 17, 1 -- forces drain, then drain+block,
         * then block+partial, then final partial. Total = 34 = sizeof(msg). */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSFPoly1305Update(&ctx, &msg[0],  1u);
        SSFPoly1305Update(&ctx, &msg[1],  15u);
        SSFPoly1305Update(&ctx, &msg[16], 17u);
        SSFPoly1305Update(&ctx, &msg[33], 1u);
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Zero-length Updates mixed with real ones -- must be a no-op. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSFPoly1305Update(&ctx, NULL, 0u);
        SSFPoly1305Update(&ctx, msg, 10u);
        SSFPoly1305Update(&ctx, NULL, 0u);
        SSFPoly1305Update(&ctx, &msg[10], sizeof(msg) - 10u);
        SSFPoly1305Update(&ctx, NULL, 0u);
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Begin/End with no data -- tag should equal s (for this RFC vector, nonzero). */
        {
            uint8_t emptyStreamTag[16];
            uint8_t emptyOneShotTag[16];
            SSFPoly1305Begin(&ctx, key, sizeof(key));
            SSFPoly1305End(&ctx, emptyStreamTag, sizeof(emptyStreamTag));
            SSFPoly1305Mac(NULL, 0u, key, sizeof(key), emptyOneShotTag, sizeof(emptyOneShotTag));
            SSF_ASSERT(memcmp(emptyStreamTag, emptyOneShotTag, sizeof(emptyStreamTag)) == 0);
        }
    }

    /* Tag-buffer write boundary: an oversized tag buffer must leave bytes 16..N-1 untouched.
     * Pins down the .md guarantee "Oversized buffers are not padded -- byte 16 onward is left
     * untouched" -- currently asserted nowhere else. */
    {
        uint8_t oversizedTag[32];
        size_t i;

        memset(oversizedTag, 0xCCu, sizeof(oversizedTag));
        SSFPoly1305Mac(msg, sizeof(msg), key, sizeof(key), oversizedTag, sizeof(oversizedTag));
        SSF_ASSERT(memcmp(oversizedTag, expected_tag, 16u) == 0);
        for (i = 16u; i < sizeof(oversizedTag); i++) SSF_ASSERT(oversizedTag[i] == 0xCCu);
    }

    /* Length walk 0..32: for every msg length, one-shot Mac and byte-by-byte streaming must
     * produce the same tag. Walks bufLen through every 0..15 value across two block boundaries
     * and pins down one-shot/streaming agreement at each length. */
    {
        static const uint8_t walkKey[32] = {
            0xABu, 0xCDu, 0xEFu, 0x01u, 0x23u, 0x45u, 0x67u, 0x89u,
            0xFEu, 0xDCu, 0xBAu, 0x98u, 0x76u, 0x54u, 0x32u, 0x10u,
            0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u,
            0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x00u
        };
        uint8_t walkMsg[33];
        uint8_t macTag[16];
        uint8_t streamTag[16];
        SSFPoly1305Context_t walkCtx = {0};
        size_t len;
        size_t i;

        for (i = 0; i < sizeof(walkMsg); i++) walkMsg[i] = (uint8_t)((i * 7u + 0x5Au) & 0xFFu);

        for (len = 0; len <= 32u; len++)
        {
            SSFPoly1305Mac(len ? walkMsg : NULL, len, walkKey, sizeof(walkKey),
                           macTag, sizeof(macTag));

            SSFPoly1305Begin(&walkCtx, walkKey, sizeof(walkKey));
            for (i = 0; i < len; i++) SSFPoly1305Update(&walkCtx, &walkMsg[i], 1u);
            SSFPoly1305End(&walkCtx, streamTag, sizeof(streamTag));

            SSF_ASSERT(memcmp(macTag, streamTag, 16u) == 0);
        }
    }

    /* Exhaustive 2-chunk split equivalence: for a fixed 64-byte message, every possible split
     * point 0..64 of two Update calls must produce the same tag as one-shot Mac. Catches off-
     * by-one bugs in the partial-block drain at every possible (bufLen, remaining) state pair. */
    {
        static const uint8_t splitKey[32] = {
            0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
            0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu,
            0xF0u, 0xE1u, 0xD2u, 0xC3u, 0xB4u, 0xA5u, 0x96u, 0x87u,
            0x78u, 0x69u, 0x5Au, 0x4Bu, 0x3Cu, 0x2Du, 0x1Eu, 0x0Fu
        };
        uint8_t splitMsg[64];
        uint8_t splitMacTag[16];
        uint8_t splitStreamTag[16];
        SSFPoly1305Context_t splitCtx = {0};
        size_t splitPoint;
        size_t i;

        for (i = 0; i < sizeof(splitMsg); i++) splitMsg[i] = (uint8_t)((i * 13u + 0xA3u) & 0xFFu);

        SSFPoly1305Mac(splitMsg, sizeof(splitMsg), splitKey, sizeof(splitKey),
                       splitMacTag, sizeof(splitMacTag));

        for (splitPoint = 0; splitPoint <= sizeof(splitMsg); splitPoint++)
        {
            SSFPoly1305Begin(&splitCtx, splitKey, sizeof(splitKey));
            SSFPoly1305Update(&splitCtx, splitMsg, splitPoint);
            SSFPoly1305Update(&splitCtx, &splitMsg[splitPoint], sizeof(splitMsg) - splitPoint);
            SSFPoly1305End(&splitCtx, splitStreamTag, sizeof(splitStreamTag));
            SSF_ASSERT(memcmp(splitStreamTag, splitMacTag, 16u) == 0);
        }
    }

    /* SSFPoly1305Verify: positive correctness -- RFC 7539 §2.5.2 vector accepts. */
    {
        SSF_ASSERT(SSFPoly1305Verify(msg, sizeof(msg), key, sizeof(key), expected_tag) == true);
    }

    /* SSFPoly1305Verify: negative correctness -- single-bit flip rejects. Verifies the function
     * actually compares all 16 bytes rather than e.g. always returning true. */
    {
        uint8_t wrongTag[16];
        size_t i;

        memcpy(wrongTag, expected_tag, sizeof(wrongTag));
        wrongTag[0] ^= 0x01u;
        SSF_ASSERT(SSFPoly1305Verify(msg, sizeof(msg), key, sizeof(key), wrongTag) == false);

        /* Flip every byte position once to confirm the compare looks at all 16 bytes. */
        for (i = 0; i < 16u; i++)
        {
            memcpy(wrongTag, expected_tag, sizeof(wrongTag));
            wrongTag[i] ^= 0x80u;
            SSF_ASSERT(SSFPoly1305Verify(msg, sizeof(msg), key, sizeof(key), wrongTag) == false);
        }
    }

    /* SSFPoly1305Verify: round-trip -- Mac followed by Verify of the computed tag accepts. */
    {
        uint8_t computedTag[16];

        /* Empty message round-trip. */
        SSFPoly1305Mac(NULL, 0u, key, sizeof(key), computedTag, sizeof(computedTag));
        SSF_ASSERT(SSFPoly1305Verify(NULL, 0u, key, sizeof(key), computedTag) == true);

        /* Multi-block round-trip with deterministic message content. */
        {
            uint8_t multiBlockMsg[64];
            size_t i;
            for (i = 0; i < sizeof(multiBlockMsg); i++) multiBlockMsg[i] = (uint8_t)(i ^ 0xA5u);
            SSFPoly1305Mac(multiBlockMsg, sizeof(multiBlockMsg), key, sizeof(key),
                           computedTag, sizeof(computedTag));
            SSF_ASSERT(SSFPoly1305Verify(multiBlockMsg, sizeof(multiBlockMsg), key, sizeof(key),
                                         computedTag) == true);
        }
    }

    /* SSFPoly1305Verify: DBC coverage. msg may be NULL only when msgLen == 0; key must be
     * non-NULL with length exactly SSF_POLY1305_KEY_SIZE; expectedTag must be non-NULL. */
    {
        static const uint8_t scratchKey[32] = {0};
        static const uint8_t scratchMsg[16] = {0};
        static const uint8_t scratchTag[16] = {0};

        SSF_ASSERT_TEST(SSFPoly1305Verify(NULL, 1u, scratchKey, sizeof(scratchKey), scratchTag));
        SSF_ASSERT_TEST(SSFPoly1305Verify(scratchMsg, sizeof(scratchMsg), NULL, sizeof(scratchKey),
                                          scratchTag));
        SSF_ASSERT_TEST(SSFPoly1305Verify(scratchMsg, sizeof(scratchMsg), scratchKey, 0u,
                                          scratchTag));
        SSF_ASSERT_TEST(SSFPoly1305Verify(scratchMsg, sizeof(scratchMsg), scratchKey, 31u,
                                          scratchTag));
        SSF_ASSERT_TEST(SSFPoly1305Verify(scratchMsg, sizeof(scratchMsg), scratchKey, 33u,
                                          scratchTag));
        SSF_ASSERT_TEST(SSFPoly1305Verify(scratchMsg, sizeof(scratchMsg), scratchKey,
                                          sizeof(scratchKey), NULL));

        /* msg == NULL with msgLen == 0 is permitted and must not assert. Return value is
         * unconstrained (depends on whether the all-zeros tag matches the all-zeros key's
         * empty-message MAC), but the call must complete. */
        (void)SSFPoly1305Verify(NULL, 0u, scratchKey, sizeof(scratchKey), scratchTag);
    }

    /* Defensive: the context-magic check rejects any call sequence that violates
     * Begin → (Update*) → End. Begin requires `magic == 0` on entry (stricter than
     * HMAC's `!= MAGIC` convention), so a non-zero context -- whether previously
     * initialised or stack residue -- is rejected. */
    {
        SSFPoly1305Context_t ctx = {0};
        uint8_t scratchTag[16];

        /* Begin must refuse a context that is already initialised. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&ctx, key, sizeof(key)));
        SSFPoly1305End(&ctx, scratchTag, sizeof(scratchTag));   /* End wipes ctx → magic == 0. */

        /* Begin must refuse a context filled with non-zero garbage. Stricter than HMAC, where
         * any pattern != MAGIC is accepted; forces callers to use `... ctx = {0};` rather than
         * relying on stack residue happening not to collide with MAGIC. */
        memset(&ctx, 0xC3u, sizeof(ctx));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&ctx, key, sizeof(key)));
        memset(&ctx, 0, sizeof(ctx));   /* restore zero-init for the cases below */

        /* Update / End must refuse an uninitialised context (magic == 0). */
        SSF_ASSERT_TEST(SSFPoly1305Update(&ctx, msg, sizeof(msg)));
        SSF_ASSERT_TEST(SSFPoly1305End(&ctx, scratchTag, sizeof(scratchTag)));

        /* End wipes ctx → Update / End on the wiped context must also assert. Catches the
         * common "Begin once, MAC twice" bug: silently emitting `tag = s = 0` for the second
         * message (since r and s are zero post-wipe) would otherwise be a hard-to-spot
         * MAC-collapse rather than a loud failure. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSFPoly1305End(&ctx, scratchTag, sizeof(scratchTag));
        SSF_ASSERT_TEST(SSFPoly1305Update(&ctx, msg, 1u));
        SSF_ASSERT_TEST(SSFPoly1305End(&ctx, scratchTag, sizeof(scratchTag)));
    }

    /* SSFPoly1305Begin: DBC coverage. ctx must be non-NULL and zero-initialised; key must be
     * non-NULL with length exactly SSF_POLY1305_KEY_SIZE. The magic-field requirement
     * (ctx->magic == 0u) is exercised separately above. */
    {
        SSFPoly1305Context_t scratchCtx = {0};
        static const uint8_t scratchKey[32] = {0};

        SSF_ASSERT_TEST(SSFPoly1305Begin(NULL, scratchKey, sizeof(scratchKey)));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&scratchCtx, NULL, sizeof(scratchKey)));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&scratchCtx, scratchKey, 0u));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&scratchCtx, scratchKey, 1u));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&scratchCtx, scratchKey, 31u));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&scratchCtx, scratchKey, 33u));
        SSF_ASSERT_TEST(SSFPoly1305Begin(&scratchCtx, scratchKey, 64u));
        /* scratchCtx remains zero-init since every assert fires before Begin sets magic. */
    }

    /* SSFPoly1305Update: DBC coverage. ctx must be non-NULL and initialised; msg may only be
     * NULL when msgLen == 0. Magic-required-for-init is exercised above. */
    {
        SSFPoly1305Context_t scratchCtx = {0};
        static const uint8_t scratchKey[32] = {0};
        static const uint8_t scratchMsg[8] = {0};
        uint8_t scratchTag[16];

        SSFPoly1305Begin(&scratchCtx, scratchKey, sizeof(scratchKey));
        SSF_ASSERT_TEST(SSFPoly1305Update(NULL, scratchMsg, sizeof(scratchMsg)));
        SSF_ASSERT_TEST(SSFPoly1305Update(&scratchCtx, NULL, 1u));

        /* Permitted edge: NULL msg with msgLen == 0 must not assert. */
        SSFPoly1305Update(&scratchCtx, NULL, 0u);

        /* Successful End wipes the still-initialised ctx so it goes out of scope clean. */
        SSFPoly1305End(&scratchCtx, scratchTag, sizeof(scratchTag));
    }

    /* SSFPoly1305End: DBC coverage. ctx must be non-NULL and initialised; tag must be non-NULL;
     * tagSize must be >= SSF_POLY1305_TAG_SIZE. Magic-required is exercised above. */
    {
        SSFPoly1305Context_t scratchCtx = {0};
        static const uint8_t scratchKey[32] = {0};
        uint8_t scratchTag[16];

        SSFPoly1305Begin(&scratchCtx, scratchKey, sizeof(scratchKey));
        SSF_ASSERT_TEST(SSFPoly1305End(NULL, scratchTag, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305End(&scratchCtx, NULL, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305End(&scratchCtx, scratchTag, 0u));
        SSF_ASSERT_TEST(SSFPoly1305End(&scratchCtx, scratchTag, 1u));
        SSF_ASSERT_TEST(SSFPoly1305End(&scratchCtx, scratchTag, 15u));

        /* Successful End to clean up the still-initialised ctx. */
        SSFPoly1305End(&scratchCtx, scratchTag, sizeof(scratchTag));
    }

    /* SSFPoly1305Mac: DBC coverage. The one-shot wrapper has no own SSF_REQUIRE -- every
     * contract violation fires inside Begin / Update / End. Mac has no ctx parameter (the
     * context is internally allocated), so no NULL-ctx case applies. */
    {
        static const uint8_t scratchKey[32] = {0};
        static const uint8_t scratchMsg[8] = {0};
        uint8_t scratchTag[16];

        SSF_ASSERT_TEST(SSFPoly1305Mac(NULL, 1u, scratchKey, sizeof(scratchKey),
                                       scratchTag, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305Mac(scratchMsg, sizeof(scratchMsg), NULL, sizeof(scratchKey),
                                       scratchTag, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305Mac(scratchMsg, sizeof(scratchMsg), scratchKey, 0u,
                                       scratchTag, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305Mac(scratchMsg, sizeof(scratchMsg), scratchKey, 31u,
                                       scratchTag, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305Mac(scratchMsg, sizeof(scratchMsg), scratchKey, 33u,
                                       scratchTag, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305Mac(scratchMsg, sizeof(scratchMsg), scratchKey,
                                       sizeof(scratchKey), NULL, sizeof(scratchTag)));
        SSF_ASSERT_TEST(SSFPoly1305Mac(scratchMsg, sizeof(scratchMsg), scratchKey,
                                       sizeof(scratchKey), scratchTag, 0u));
        SSF_ASSERT_TEST(SSFPoly1305Mac(scratchMsg, sizeof(scratchMsg), scratchKey,
                                       sizeof(scratchKey), scratchTag, 15u));

        /* Permitted edge: NULL msg with msgLen == 0 must not assert. */
        SSFPoly1305Mac(NULL, 0u, scratchKey, sizeof(scratchKey), scratchTag, sizeof(scratchTag));
    }

#if SSF_POLY1305_OSSL_VERIFY == 1
    _VerifyPoly1305AgainstOpenSSLRandom();
#endif
}

#endif /* SSF_CONFIG_POLY1305_UNIT_TEST */
