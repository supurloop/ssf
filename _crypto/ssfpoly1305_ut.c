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
            SSFPoly1305Context_t ctx;

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

    /* Test empty message */
    {
        static const uint8_t zeroKey[32] = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        uint8_t emptyTag[16];

        SSFPoly1305Mac(NULL, 0, zeroKey, sizeof(zeroKey), emptyTag, sizeof(emptyTag));
        /* With r=1, s=0, empty message: tag should be s = 0 */
    }

    /* Test single-byte message */
    {
        uint8_t oneByte = 0x01;
        uint8_t oneTag[16];
        SSFPoly1305Mac(&oneByte, 1, key, sizeof(key), oneTag, sizeof(oneTag));
        /* Just verify it doesn't crash; correctness covered by RFC vector above */
    }

    /* Test exactly 16-byte (one block) message */
    {
        uint8_t blockTag[16];
        SSFPoly1305Mac(msg, 16, key, sizeof(key), blockTag, sizeof(blockTag));
        /* Verify doesn't crash with exact block boundary */
    }

    /* Streaming API: Begin/Update/End over the RFC 7539 vector must produce the same tag
     * as the one-shot Mac. Run it several ways to exercise the partial-block hold-back
     * across the 16-byte block boundary: byte-by-byte, uneven chunks, and chunks that
     * straddle the boundary. */
    {
        SSFPoly1305Context_t ctx;
        uint8_t streamTag[16];
        size_t i;

        /* Single Update over the whole message — should match Mac exactly. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSFPoly1305Update(&ctx, msg, sizeof(msg));
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Byte-by-byte Update — exercises the partial-block drain on every single call. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        for (i = 0; i < sizeof(msg); i++) SSFPoly1305Update(&ctx, &msg[i], 1u);
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Boundary-straddling chunks: 1, 15, 17, 1 — forces drain, then drain+block,
         * then block+partial, then final partial. Total = 34 = sizeof(msg). */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSFPoly1305Update(&ctx, &msg[0],  1u);
        SSFPoly1305Update(&ctx, &msg[1],  15u);
        SSFPoly1305Update(&ctx, &msg[16], 17u);
        SSFPoly1305Update(&ctx, &msg[33], 1u);
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Zero-length Updates mixed with real ones — must be a no-op. */
        SSFPoly1305Begin(&ctx, key, sizeof(key));
        SSFPoly1305Update(&ctx, NULL, 0u);
        SSFPoly1305Update(&ctx, msg, 10u);
        SSFPoly1305Update(&ctx, NULL, 0u);
        SSFPoly1305Update(&ctx, &msg[10], sizeof(msg) - 10u);
        SSFPoly1305Update(&ctx, NULL, 0u);
        SSFPoly1305End(&ctx, streamTag, sizeof(streamTag));
        SSF_ASSERT(memcmp(streamTag, expected_tag, sizeof(expected_tag)) == 0);

        /* Begin/End with no data — tag should equal s (for this RFC vector, nonzero). */
        {
            uint8_t emptyStreamTag[16];
            uint8_t emptyOneShotTag[16];
            SSFPoly1305Begin(&ctx, key, sizeof(key));
            SSFPoly1305End(&ctx, emptyStreamTag, sizeof(emptyStreamTag));
            SSFPoly1305Mac(NULL, 0u, key, sizeof(key), emptyOneShotTag, sizeof(emptyOneShotTag));
            SSF_ASSERT(memcmp(emptyStreamTag, emptyOneShotTag, sizeof(emptyStreamTag)) == 0);
        }
    }

#if SSF_POLY1305_OSSL_VERIFY == 1
    _VerifyPoly1305AgainstOpenSSLRandom();
#endif
}

#endif /* SSF_CONFIG_POLY1305_UNIT_TEST */
