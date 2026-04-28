/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaesctr_ut.c                                                                                */
/* Provides unit tests for the ssfaesctr AES-CTR module.                                         */
/* Test vectors from NIST SP 800-38A Appendix F.5 (CTR-AES128/192/256 Encrypt/Decrypt).          */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#include <string.h>
#include "ssfassert.h"
#include "ssfaesctr.h"

#if SSF_CONFIG_AESCTR_UNIT_TEST == 1

/* NIST SP 800-38A F.5 shared test plaintext (4 × 16-byte blocks). */
static const uint8_t _nistPt[64] = {
    0x6Bu, 0xC1u, 0xBEu, 0xE2u, 0x2Eu, 0x40u, 0x9Fu, 0x96u,
    0xE9u, 0x3Du, 0x7Eu, 0x11u, 0x73u, 0x93u, 0x17u, 0x2Au,
    0xAEu, 0x2Du, 0x8Au, 0x57u, 0x1Eu, 0x03u, 0xACu, 0x9Cu,
    0x9Eu, 0xB7u, 0x6Fu, 0xACu, 0x45u, 0xAFu, 0x8Eu, 0x51u,
    0x30u, 0xC8u, 0x1Cu, 0x46u, 0xA3u, 0x5Cu, 0xE4u, 0x11u,
    0xE5u, 0xFBu, 0xC1u, 0x19u, 0x1Au, 0x0Au, 0x52u, 0xEFu,
    0xF6u, 0x9Fu, 0x24u, 0x45u, 0xDFu, 0x4Fu, 0x9Bu, 0x17u,
    0xADu, 0x2Bu, 0x41u, 0x7Bu, 0xE6u, 0x6Cu, 0x37u, 0x10u
};

/* Initial counter for all three NIST CTR examples. */
static const uint8_t _nistIv[16] = {
    0xF0u, 0xF1u, 0xF2u, 0xF3u, 0xF4u, 0xF5u, 0xF6u, 0xF7u,
    0xF8u, 0xF9u, 0xFAu, 0xFBu, 0xFCu, 0xFDu, 0xFEu, 0xFFu
};

void SSFAESCTRUnitTest(void)
{
    uint8_t out[64];
    uint8_t back[64];

    /* ---- NIST SP 800-38A F.5.1 / F.5.2: CTR-AES128 ---- */
    {
        static const uint8_t key[16] = {
            0x2Bu, 0x7Eu, 0x15u, 0x16u, 0x28u, 0xAEu, 0xD2u, 0xA6u,
            0xABu, 0xF7u, 0x15u, 0x88u, 0x09u, 0xCFu, 0x4Fu, 0x3Cu
        };
        static const uint8_t expectedCt[64] = {
            0x87u, 0x4Du, 0x61u, 0x91u, 0xB6u, 0x20u, 0xE3u, 0x26u,
            0x1Bu, 0xEFu, 0x68u, 0x64u, 0x99u, 0x0Du, 0xB6u, 0xCEu,
            0x98u, 0x06u, 0xF6u, 0x6Bu, 0x79u, 0x70u, 0xFDu, 0xFFu,
            0x86u, 0x17u, 0x18u, 0x7Bu, 0xB9u, 0xFFu, 0xFDu, 0xFFu,
            0x5Au, 0xE4u, 0xDFu, 0x3Eu, 0xDBu, 0xD5u, 0xD3u, 0x5Eu,
            0x5Bu, 0x4Fu, 0x09u, 0x02u, 0x0Du, 0xB0u, 0x3Eu, 0xABu,
            0x1Eu, 0x03u, 0x1Du, 0xDAu, 0x2Fu, 0xBEu, 0x03u, 0xD1u,
            0x79u, 0x21u, 0x70u, 0xA0u, 0xF3u, 0x00u, 0x9Cu, 0xEEu
        };

        /* Encrypt path. */
        SSFAESCTR(key, sizeof(key), _nistIv, _nistPt, out, 64u);
        SSF_ASSERT(memcmp(out, expectedCt, 64) == 0);

        /* Decrypt path (CTR is symmetric). */
        SSFAESCTR(key, sizeof(key), _nistIv, expectedCt, back, 64u);
        SSF_ASSERT(memcmp(back, _nistPt, 64) == 0);
    }

    /* ---- NIST SP 800-38A F.5.3 / F.5.4: CTR-AES192 ---- */
    {
        static const uint8_t key[24] = {
            0x8Eu, 0x73u, 0xB0u, 0xF7u, 0xDAu, 0x0Eu, 0x64u, 0x52u,
            0xC8u, 0x10u, 0xF3u, 0x2Bu, 0x80u, 0x90u, 0x79u, 0xE5u,
            0x62u, 0xF8u, 0xEAu, 0xD2u, 0x52u, 0x2Cu, 0x6Bu, 0x7Bu
        };
        static const uint8_t expectedCt[64] = {
            0x1Au, 0xBCu, 0x93u, 0x24u, 0x17u, 0x52u, 0x1Cu, 0xA2u,
            0x4Fu, 0x2Bu, 0x04u, 0x59u, 0xFEu, 0x7Eu, 0x6Eu, 0x0Bu,
            0x09u, 0x03u, 0x39u, 0xECu, 0x0Au, 0xA6u, 0xFAu, 0xEFu,
            0xD5u, 0xCCu, 0xC2u, 0xC6u, 0xF4u, 0xCEu, 0x8Eu, 0x94u,
            0x1Eu, 0x36u, 0xB2u, 0x6Bu, 0xD1u, 0xEBu, 0xC6u, 0x70u,
            0xD1u, 0xBDu, 0x1Du, 0x66u, 0x56u, 0x20u, 0xABu, 0xF7u,
            0x4Fu, 0x78u, 0xA7u, 0xF6u, 0xD2u, 0x98u, 0x09u, 0x58u,
            0x5Au, 0x97u, 0xDAu, 0xECu, 0x58u, 0xC6u, 0xB0u, 0x50u
        };

        SSFAESCTR(key, sizeof(key), _nistIv, _nistPt, out, 64u);
        SSF_ASSERT(memcmp(out, expectedCt, 64) == 0);
        SSFAESCTR(key, sizeof(key), _nistIv, expectedCt, back, 64u);
        SSF_ASSERT(memcmp(back, _nistPt, 64) == 0);
    }

    /* ---- NIST SP 800-38A F.5.5 / F.5.6: CTR-AES256 ---- */
    {
        static const uint8_t key[32] = {
            0x60u, 0x3Du, 0xEBu, 0x10u, 0x15u, 0xCAu, 0x71u, 0xBEu,
            0x2Bu, 0x73u, 0xAEu, 0xF0u, 0x85u, 0x7Du, 0x77u, 0x81u,
            0x1Fu, 0x35u, 0x2Cu, 0x07u, 0x3Bu, 0x61u, 0x08u, 0xD7u,
            0x2Du, 0x98u, 0x10u, 0xA3u, 0x09u, 0x14u, 0xDFu, 0xF4u
        };
        static const uint8_t expectedCt[64] = {
            0x60u, 0x1Eu, 0xC3u, 0x13u, 0x77u, 0x57u, 0x89u, 0xA5u,
            0xB7u, 0xA7u, 0xF5u, 0x04u, 0xBBu, 0xF3u, 0xD2u, 0x28u,
            0xF4u, 0x43u, 0xE3u, 0xCAu, 0x4Du, 0x62u, 0xB5u, 0x9Au,
            0xCAu, 0x84u, 0xE9u, 0x90u, 0xCAu, 0xCAu, 0xF5u, 0xC5u,
            0x2Bu, 0x09u, 0x30u, 0xDAu, 0xA2u, 0x3Du, 0xE9u, 0x4Cu,
            0xE8u, 0x70u, 0x17u, 0xBAu, 0x2Du, 0x84u, 0x98u, 0x8Du,
            0xDFu, 0xC9u, 0xC5u, 0x8Du, 0xB6u, 0x7Au, 0xADu, 0xA6u,
            0x13u, 0xC2u, 0xDDu, 0x08u, 0x45u, 0x79u, 0x41u, 0xA6u
        };

        SSFAESCTR(key, sizeof(key), _nistIv, _nistPt, out, 64u);
        SSF_ASSERT(memcmp(out, expectedCt, 64) == 0);
        SSFAESCTR(key, sizeof(key), _nistIv, expectedCt, back, 64u);
        SSF_ASSERT(memcmp(back, _nistPt, 64) == 0);
    }

    /* Cross-equivalence: one-shot SSFAESCTR == incremental Begin / Crypt / DeInit. */
    {
        static const uint8_t key[16] = {
            0x2Bu, 0x7Eu, 0x15u, 0x16u, 0x28u, 0xAEu, 0xD2u, 0xA6u,
            0xABu, 0xF7u, 0x15u, 0x88u, 0x09u, 0xCFu, 0x4Fu, 0x3Cu
        };
        SSFAESCTRContext_t ctx = {0};
        uint8_t inc[64];

        SSFAESCTR(key, sizeof(key), _nistIv, _nistPt, out, 64u);

        SSFAESCTRBegin(&ctx, key, sizeof(key), _nistIv);
        SSFAESCTRCrypt(&ctx, _nistPt, inc, 64u);
        SSFAESCTRDeInit(&ctx);
        SSF_ASSERT(memcmp(out, inc, 64) == 0);
    }

    /* Block-boundary lengths: feeding the same plaintext as a single Crypt call must produce
       the same output as feeding it in N sub-blocks for any split. Catches keystream-buffer
       carry-over bugs at every boundary inside and across 16-byte blocks. */
    {
        static const uint8_t key[16] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu
        };
        static const size_t lens[] = {0u, 1u, 15u, 16u, 17u, 31u, 32u, 33u, 63u, 64u, 65u, 1024u};
        static uint8_t pt[1024];
        static uint8_t ref[1024];
        static uint8_t inc[1024];
        size_t i;
        size_t k;

        for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i ^ 0x55u);

        for (k = 0; k < (sizeof(lens) / sizeof(lens[0])); k++)
        {
            size_t L = lens[k];
            SSFAESCTRContext_t ctx = {0};

            SSFAESCTR(key, sizeof(key), _nistIv, pt, ref, L);

            /* Same length, but driven through Begin / Crypt / DeInit. */
            SSFAESCTRBegin(&ctx, key, sizeof(key), _nistIv);
            SSFAESCTRCrypt(&ctx, pt, inc, L);
            SSFAESCTRDeInit(&ctx);
            SSF_ASSERT(memcmp(ref, inc, L) == 0);
        }
    }

    /* Many tiny Crypt calls summing to the full plaintext must produce the same output as one
       call of the full length. Specifically exercises the keystream-buffer carry-over across
       Crypt boundaries (the bug class where ksOff is mismanaged between calls). */
    {
        static const uint8_t key[32] = {
            0x60u, 0x3Du, 0xEBu, 0x10u, 0x15u, 0xCAu, 0x71u, 0xBEu,
            0x2Bu, 0x73u, 0xAEu, 0xF0u, 0x85u, 0x7Du, 0x77u, 0x81u,
            0x1Fu, 0x35u, 0x2Cu, 0x07u, 0x3Bu, 0x61u, 0x08u, 0xD7u,
            0x2Du, 0x98u, 0x10u, 0xA3u, 0x09u, 0x14u, 0xDFu, 0xF4u
        };
        static const uint32_t chunkSizes[] = {1u, 3u, 7u, 13u, 15u, 16u, 17u, 33u, 64u, 100u};
        static uint8_t pt[256];
        static uint8_t ref[256];
        static uint8_t inc[256];
        size_t i;
        size_t cs;

        for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)i;
        SSFAESCTR(key, sizeof(key), _nistIv, pt, ref, sizeof(pt));

        for (cs = 0; cs < (sizeof(chunkSizes) / sizeof(chunkSizes[0])); cs++)
        {
            SSFAESCTRContext_t ctx = {0};
            size_t off = 0u;
            size_t step = chunkSizes[cs];

            SSFAESCTRBegin(&ctx, key, sizeof(key), _nistIv);
            while (off < sizeof(pt))
            {
                size_t take = sizeof(pt) - off;
                if (take > step) take = step;
                SSFAESCTRCrypt(&ctx, &pt[off], &inc[off], take);
                off += take;
            }
            SSFAESCTRDeInit(&ctx);
            SSF_ASSERT(memcmp(ref, inc, sizeof(pt)) == 0);
        }
    }

    /* Round-trip: encrypt random-ish plaintext, decrypt with same key/iv, recover plaintext.
       Proves CTR symmetry across all three key sizes. */
    {
        static const uint8_t iv[16] = {
            0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
            0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu
        };
        static const size_t keyLens[] = {16u, 24u, 32u};
        static uint8_t keyBuf[32];
        uint8_t pt[200];
        uint8_t ct[200];
        uint8_t recovered[200];
        size_t k;
        size_t i;

        for (i = 0; i < sizeof(keyBuf); i++) keyBuf[i] = (uint8_t)(i ^ 0xA5u);
        for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i + 1u);

        for (k = 0; k < (sizeof(keyLens) / sizeof(keyLens[0])); k++)
        {
            SSFAESCTR(keyBuf, keyLens[k], iv, pt, ct, sizeof(pt));
            SSFAESCTR(keyBuf, keyLens[k], iv, ct, recovered, sizeof(pt));
            SSF_ASSERT(memcmp(pt, recovered, sizeof(pt)) == 0);
        }
    }

    /* In-place encryption (in == out) must produce identical output to out-of-place. Catches a
       bug where the implementation reads from out[i] before writing the XOR result. */
    {
        static const uint8_t key[16] = {
            0x2Bu, 0x7Eu, 0x15u, 0x16u, 0x28u, 0xAEu, 0xD2u, 0xA6u,
            0xABu, 0xF7u, 0x15u, 0x88u, 0x09u, 0xCFu, 0x4Fu, 0x3Cu
        };
        uint8_t buf[64];
        uint8_t ref[64];

        memcpy(buf, _nistPt, sizeof(buf));
        SSFAESCTR(key, sizeof(key), _nistIv, _nistPt, ref, sizeof(ref));
        SSFAESCTR(key, sizeof(key), _nistIv, buf, buf, sizeof(buf));     /* in == out */
        SSF_ASSERT(memcmp(buf, ref, sizeof(buf)) == 0);
    }

    /* Counter wrap inside the low-order byte: start the counter with byte 15 == 0xFF. After
       the first keystream block, counter[15] wraps to 0x00 and counter[14] increments. Use
       exactly one block (16 bytes) so the post-condition is unambiguous. Catches an off-by-one
       in _SSFAESCTRIncCounter or a wrong-endianness counter increment. */
    {
        static const uint8_t key[16] = {0};
        static const uint8_t iv[16] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0xFFu
        };
        uint8_t pt[16] = {0};
        uint8_t ct[16];
        SSFAESCTRContext_t ctx = {0};

        SSFAESCTRBegin(&ctx, key, sizeof(key), iv);
        SSFAESCTRCrypt(&ctx, pt, ct, sizeof(pt));
        /* After one block the counter must equal {0,...,0, 0x01, 0x00}. */
        SSF_ASSERT(ctx.counter[14] == 0x01u);
        SSF_ASSERT(ctx.counter[15] == 0x00u);
        SSFAESCTRDeInit(&ctx);
    }

    /* Counter wrap that ripples through multiple bytes: counter[14..15] = 0xFF 0xFF. After one
       block, expect {..., 0x01, 0x00, 0x00}. Verifies the carry chain in the BE increment. */
    {
        static const uint8_t key[16] = {0};
        static const uint8_t iv[16] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu
        };
        uint8_t pt[16] = {0};
        uint8_t ct[16];
        SSFAESCTRContext_t ctx = {0};

        SSFAESCTRBegin(&ctx, key, sizeof(key), iv);
        SSFAESCTRCrypt(&ctx, pt, ct, sizeof(pt));
        SSF_ASSERT(ctx.counter[13] == 0x01u);
        SSF_ASSERT(ctx.counter[14] == 0x00u);
        SSF_ASSERT(ctx.counter[15] == 0x00u);
        SSFAESCTRDeInit(&ctx);
    }

    /* Empty input is a no-op: 0-byte Crypt does not advance the counter or touch the keystream
       buffer. */
    {
        static const uint8_t key[16] = {
            0x2Bu, 0x7Eu, 0x15u, 0x16u, 0x28u, 0xAEu, 0xD2u, 0xA6u,
            0xABu, 0xF7u, 0x15u, 0x88u, 0x09u, 0xCFu, 0x4Fu, 0x3Cu
        };
        SSFAESCTRContext_t ctx = {0};
        uint8_t out0[1] = {0};

        SSFAESCTRBegin(&ctx, key, sizeof(key), _nistIv);
        SSFAESCTRCrypt(&ctx, NULL, NULL, 0u);                 /* NULL allowed when len == 0 */
        SSFAESCTRCrypt(&ctx, out0, out0, 0u);                 /* non-NULL, len == 0 */
        /* Counter must still equal _nistIv (no block was generated). */
        SSF_ASSERT(memcmp(ctx.counter, _nistIv, 16) == 0);
        SSFAESCTRDeInit(&ctx);
    }

    /* DBC: SSFAESCTRBegin parameter validation. */
    {
        SSFAESCTRContext_t ctx = {0};
        uint8_t key[16] = {0};
        uint8_t iv[16] = {0};

        SSF_ASSERT_TEST(SSFAESCTRBegin(NULL, key, sizeof(key), iv));
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, NULL, sizeof(key), iv));
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, key, 0u, iv));
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, key, 8u, iv));
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, key, 17u, iv));
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, key, 25u, iv));
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, key, 33u, iv));
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, key, sizeof(key), NULL));
    }

    /* DBC: double-Begin without DeInit must trip (strict zero-init contract). */
    {
        SSFAESCTRContext_t ctx = {0};
        uint8_t key[16] = {0};
        uint8_t iv[16] = {0};

        SSFAESCTRBegin(&ctx, key, sizeof(key), iv);
        SSF_ASSERT_TEST(SSFAESCTRBegin(&ctx, key, sizeof(key), iv));
        SSFAESCTRDeInit(&ctx);
    }

    /* DBC: SSFAESCTRCrypt parameter validation, including magic check. */
    {
        SSFAESCTRContext_t ctx = {0};
        uint8_t key[16] = {0};
        uint8_t iv[16] = {0};
        uint8_t buf[4] = {0};

        /* Uninitialized ctx — magic check trips. */
        SSF_ASSERT_TEST(SSFAESCTRCrypt(&ctx, buf, buf, sizeof(buf)));

        SSFAESCTRBegin(&ctx, key, sizeof(key), iv);
        SSF_ASSERT_TEST(SSFAESCTRCrypt(NULL, buf, buf, sizeof(buf)));
        SSF_ASSERT_TEST(SSFAESCTRCrypt(&ctx, NULL, buf, sizeof(buf)));
        SSF_ASSERT_TEST(SSFAESCTRCrypt(&ctx, buf, NULL, sizeof(buf)));
        SSFAESCTRDeInit(&ctx);

        /* Use after DeInit must trip. */
        SSF_ASSERT_TEST(SSFAESCTRCrypt(&ctx, buf, buf, sizeof(buf)));
    }

    /* DBC: SSFAESCTRDeInit. */
    {
        SSFAESCTRContext_t ctx = {0};

        SSF_ASSERT_TEST(SSFAESCTRDeInit(NULL));
        /* Uninitialized — magic mismatch. */
        SSF_ASSERT_TEST(SSFAESCTRDeInit(&ctx));
    }

    /* DBC: single-call SSFAESCTR parameter validation. */
    {
        uint8_t key[16] = {0};
        uint8_t iv[16] = {0};
        uint8_t buf[4] = {0};

        SSF_ASSERT_TEST(SSFAESCTR(NULL, sizeof(key), iv, buf, buf, sizeof(buf)));
        SSF_ASSERT_TEST(SSFAESCTR(key, 0u, iv, buf, buf, sizeof(buf)));
        SSF_ASSERT_TEST(SSFAESCTR(key, 17u, iv, buf, buf, sizeof(buf)));
        SSF_ASSERT_TEST(SSFAESCTR(key, sizeof(key), NULL, buf, buf, sizeof(buf)));
        SSF_ASSERT_TEST(SSFAESCTR(key, sizeof(key), iv, NULL, buf, sizeof(buf)));
        SSF_ASSERT_TEST(SSFAESCTR(key, sizeof(key), iv, buf, NULL, sizeof(buf)));
        /* len == 0 with NULL pointers is allowed. */
        SSFAESCTR(key, sizeof(key), iv, NULL, NULL, 0u);
    }

    /* DeInit zeros every byte of the context. */
    {
        SSFAESCTRContext_t ctx = {0};
        uint8_t key[16];
        uint8_t iv[16];
        const uint8_t *p;
        size_t i;

        memset(key, 0xC3u, sizeof(key));
        memset(iv,  0xA5u, sizeof(iv));
        SSFAESCTRBegin(&ctx, key, sizeof(key), iv);
        SSFAESCTRCrypt(&ctx, key, key, sizeof(key));
        SSFAESCTRDeInit(&ctx);

        p = (const uint8_t *)&ctx;
        for (i = 0; i < sizeof(ctx); i++) SSF_ASSERT(p[i] == 0u);
    }
}
#endif /* SSF_CONFIG_AESCTR_UNIT_TEST */
