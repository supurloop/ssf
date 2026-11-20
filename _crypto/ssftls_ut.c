/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftls_ut.c                                                                                   */
/* Provides unit tests for the ssftls TLS 1.3 core module.                                       */
/* Key schedule test vectors from RFC 8448 ("Example Handshake Traces for TLS 1.3").             */
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
#include "ssfassert.h"
#include "ssftls.h"
#include "ssfhkdf.h"
#include "ssfaesgcm.h"

#if SSF_CONFIG_TLS_UNIT_TEST == 1

/* Suppress C6262 (large stack frame): the test entry point uses many record buffers. */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
/* Zeroization audit hook: sets *ctx true iff the finished_key buffer is fully zeroed. */
static void _SSFTLSFinishedScrubHook(void *ctx, const uint8_t *finishedKey, size_t len)
{
    bool allZero = true;
    size_t i;
    for (i = 0; i < len; i++) { if (finishedKey[i] != 0u) { allZero = false; break; } }
    *(bool *)ctx = allZero;
}

void SSFTLSUnitTest(void)
{
    /* ---- (Hardening) RecordStateDeInit securely wipes the traffic key / IV ---- */
    {
        SSFTLSRecordState_t st = {0}; /* zero before first Init (magic guard) */
        uint8_t key[16];
        uint8_t iv[SSF_TLS_IV_SIZE];
        uint8_t zeros[sizeof(st)];

        memset(key, 0xC7, sizeof(key));
        memset(iv, 0x39, sizeof(iv));
        memset(zeros, 0, sizeof(zeros));

        SSFTLSRecordStateInit(&st, SSF_TLS_CS_AES_128_GCM_SHA256, key, sizeof(key), iv, sizeof(iv));
        SSF_ASSERT(memcmp(st.key, key, sizeof(key)) == 0);
        SSFTLSRecordStateDeInit(&st); /* DeInit must wipe the whole state */
        SSF_ASSERT(memcmp(&st, zeros, sizeof(st)) == 0);
    }

    /* ---- (Hardening) record-state magic: reject re-init when active and use after DeInit ---- */
    {
        SSFTLSRecordState_t st = {0};
        uint8_t key[16];
        uint8_t iv[SSF_TLS_IV_SIZE];

        memset(key, 0x4E, sizeof(key));
        memset(iv, 0x71, sizeof(iv));

        SSFTLSRecordStateInit(&st, SSF_TLS_CS_AES_128_GCM_SHA256, key, sizeof(key), iv, sizeof(iv));
        /* Re-initializing an already-active state (no DeInit) must be rejected. */
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&st, SSF_TLS_CS_AES_128_GCM_SHA256,
                                              key, sizeof(key), iv, sizeof(iv)));
        SSFTLSRecordStateDeInit(&st);
        /* DeInit again (state now inactive) must be rejected. */
        SSF_ASSERT_TEST(SSFTLSRecordStateDeInit(&st));
    }

    /* AUDIT TLS-5: the key length must match the cipher suite (RFC 8446 App. B.4). */
    {
        static const uint16_t suites[5] = {
            SSF_TLS_CS_AES_128_GCM_SHA256, SSF_TLS_CS_AES_256_GCM_SHA384,
            SSF_TLS_CS_CHACHA20_POLY1305_SHA256, SSF_TLS_CS_AES_128_CCM_SHA256,
            SSF_TLS_CS_AES_128_CCM_8_SHA256
        };
        static const uint8_t keyLens[5] = { 16u, 32u, 32u, 16u, 16u };
        SSFTLSRecordState_t st = {0};
        uint8_t key[32];
        uint8_t iv[SSF_TLS_IV_SIZE];
        uint8_t i;

        memset(key, 0x3Cu, sizeof(key));
        memset(iv, 0x5Au, sizeof(iv));

        /* Mismatched lengths and an unknown suite trap instead of running the wrong cipher. */
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&st, SSF_TLS_CS_AES_256_GCM_SHA384, key, 16u, iv,
                                              sizeof(iv)));
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&st, SSF_TLS_CS_AES_128_GCM_SHA256, key, 32u, iv,
                                              sizeof(iv)));
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&st, SSF_TLS_CS_AES_128_CCM_SHA256, key, 24u, iv,
                                              sizeof(iv)));
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&st, SSF_TLS_CS_CHACHA20_POLY1305_SHA256, key, 16u,
                                              iv, sizeof(iv)));
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&st, 0x1399u, key, 16u, iv, sizeof(iv)));

        /* Every valid pairing initializes. */
        for (i = 0u; i < 5u; i++)
        {
            SSFTLSRecordStateInit(&st, suites[i], key, keyLens[i], iv, sizeof(iv));
            SSFTLSRecordStateDeInit(&st);
        }
    }

    /* ---- (Hardening) ComputeFinished wipes the finished_key before returning ---- */
    {
        uint8_t baseKey[32];
        uint8_t transcript[32];
        uint8_t verifyData[32];
        bool sawZero = false;

        memset(baseKey, 0x5A, sizeof(baseKey));
        memset(transcript, 0x1D, sizeof(transcript));

        _SSFTLSFinishedKeyScrubTestHookCtx = &sawZero;
        _SSFTLSFinishedKeyScrubTestHook = _SSFTLSFinishedScrubHook;
        SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256, baseKey, sizeof(baseKey),
                              transcript, sizeof(transcript), verifyData, sizeof(verifyData));
        _SSFTLSFinishedKeyScrubTestHook = NULL;
        _SSFTLSFinishedKeyScrubTestHookCtx = NULL;

        SSF_ASSERT(sawZero == true);
    }

    /* ---- Transcript hash: SHA-256 of empty string ---- */
    {
        SSFTLSTranscript_t t;
        uint8_t hash[32];
        /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
        static const uint8_t expectedEmpty[] = {
            0xE3u, 0xB0u, 0xC4u, 0x42u, 0x98u, 0xFCu, 0x1Cu, 0x14u,
            0x9Au, 0xFBu, 0xF4u, 0xC8u, 0x99u, 0x6Fu, 0xB9u, 0x24u,
            0x27u, 0xAEu, 0x41u, 0xE4u, 0x64u, 0x9Bu, 0x93u, 0x4Cu,
            0xA4u, 0x95u, 0x99u, 0x1Bu, 0x78u, 0x52u, 0xB8u, 0x55u
        };

        SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA256);
        SSFTLSTranscriptHash(&t, hash, sizeof(hash));
        SSF_ASSERT(memcmp(hash, expectedEmpty, 32) == 0);
    }

    /* ---- Transcript hash: snapshot preserves running state ---- */
    {
        SSFTLSTranscript_t t;
        uint8_t hash1[32];
        uint8_t hash2[32];

        SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA256);
        SSFTLSTranscriptUpdate(&t, (const uint8_t *)"hello", 5);
        SSFTLSTranscriptHash(&t, hash1, sizeof(hash1));

        /* Update more data and take another snapshot */
        SSFTLSTranscriptUpdate(&t, (const uint8_t *)" world", 6);
        SSFTLSTranscriptHash(&t, hash2, sizeof(hash2));

        /* Snapshots should differ */
        SSF_ASSERT(memcmp(hash1, hash2, 32) != 0);
    }

    /* ---- Transcript hash: SHA-384 paths (used by AES_256_GCM_SHA384 cipher suite) ---- */
    {
        SSFTLSTranscript_t t;
        uint8_t hash[SSF_SHA2_384_BYTE_SIZE];
        uint8_t hash2[SSF_SHA2_384_BYTE_SIZE];
        /* SHA-384("") FIPS 180-4 Appendix B. */
        static const uint8_t expectedEmpty384[SSF_SHA2_384_BYTE_SIZE] = {
            0x38u, 0xB0u, 0x60u, 0xA7u, 0x51u, 0xACu, 0x96u, 0x38u,
            0x4Cu, 0xD9u, 0x32u, 0x7Eu, 0xB1u, 0xB1u, 0xE3u, 0x6Au,
            0x21u, 0xFDu, 0xB7u, 0x11u, 0x14u, 0xBEu, 0x07u, 0x43u,
            0x4Cu, 0x0Cu, 0xC7u, 0xBFu, 0x63u, 0xF6u, 0xE1u, 0xDAu,
            0x27u, 0x4Eu, 0xDEu, 0xBFu, 0xE7u, 0x6Fu, 0x65u, 0xFBu,
            0xD5u, 0x1Au, 0xD2u, 0xF1u, 0x48u, 0x98u, 0xB9u, 0x5Bu
        };

        SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA384);
        SSFTLSTranscriptHash(&t, hash, sizeof(hash));
        SSF_ASSERT(memcmp(hash, expectedEmpty384, SSF_SHA2_384_BYTE_SIZE) == 0);

        /* Update + re-snapshot must change the digest while leaving the running state intact. */
        SSFTLSTranscriptUpdate(&t, (const uint8_t *)"abc", 3);
        SSFTLSTranscriptHash(&t, hash2, sizeof(hash2));
        SSF_ASSERT(memcmp(hash, hash2, SSF_SHA2_384_BYTE_SIZE) != 0);
    }

    /* ---- HKDF-Expand-Label basic test: early secret = HKDF-Extract(0, 0) (no PSK) ---- */
    {
        uint8_t earlySecret[32];
        uint8_t zeroPSK[32];
        uint8_t zeroSalt[32];

        memset(zeroPSK, 0, sizeof(zeroPSK));
        memset(zeroSalt, 0, sizeof(zeroSalt));

        /* Early Secret = HKDF-Extract(salt=0, IKM=0) */
        SSF_ASSERT(SSFHKDFExtract(SSF_HMAC_HASH_SHA256, zeroSalt, 32, zeroPSK, 32,
                   earlySecret, sizeof(earlySecret)) == true);

        /* The early secret should be deterministic and non-zero */
        {
            uint8_t i;
            bool nonZero = false;
            for (i = 0; i < 32u; i++) if (earlySecret[i] != 0u) nonZero = true;
            SSF_ASSERT(nonZero == true);
        }

        /* Derive-Secret(early_secret, "derived", Hash("")) */
        {
            uint8_t emptyHash[32];
            uint8_t derived[32];
            SSFTLSTranscript_t t;

            SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA256);
            SSFTLSTranscriptHash(&t, emptyHash, sizeof(emptyHash));

            SSFTLSDeriveSecret(SSF_HMAC_HASH_SHA256, earlySecret, 32,
                               "derived", emptyHash, 32, derived, 32);

            /* derived should be non-zero and different from earlySecret */
            SSF_ASSERT(memcmp(derived, earlySecret, 32) != 0);
        }
    }

    /* ---- Traffic key derivation roundtrip ---- */
    {
        uint8_t secret[32];
        uint8_t key[16];
        uint8_t iv[12];
        uint8_t i;

        /* Use a known secret */
        for (i = 0; i < 32u; i++) secret[i] = i;

        SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256, secret, 32,
                                key, sizeof(key), iv, sizeof(iv));

        /* Key and IV should be non-zero */
        {
            bool nonZero = false;
            for (i = 0; i < 16u; i++) if (key[i] != 0u) nonZero = true;
            SSF_ASSERT(nonZero);
            nonZero = false;
            for (i = 0; i < 12u; i++) if (iv[i] != 0u) nonZero = true;
            SSF_ASSERT(nonZero);
        }
    }

    /* ---- Finished computation ---- */
    {
        uint8_t baseKey[32];
        uint8_t transcriptHash[32];
        uint8_t verifyData[32];
        uint8_t i;

        for (i = 0; i < 32u; i++) { baseKey[i] = i; transcriptHash[i] = (uint8_t)(i + 32u); }
        SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256, baseKey, 32,
                              transcriptHash, 32, verifyData, 32);

        /* Verify data should be deterministic */
        {
            uint8_t verifyData2[32];
            SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256, baseKey, 32,
                                  transcriptHash, 32, verifyData2, 32);
            SSF_ASSERT(memcmp(verifyData, verifyData2, 32) == 0);
        }
    }

    /* ---- RFC 8448 Sec. 3 1-RTT key-schedule KAT: derived, c/s_hs_traffic, traffic key/iv ---- */
    {
        static const uint8_t earlySecret[] = {
            0x33u, 0xADu, 0x0Au, 0x1Cu, 0x60u, 0x7Eu, 0xC0u, 0x3Bu,
            0x09u, 0xE6u, 0xCDu, 0x98u, 0x93u, 0x68u, 0x0Cu, 0xE2u,
            0x10u, 0xADu, 0xF3u, 0x00u, 0xAAu, 0x1Fu, 0x26u, 0x60u,
            0xE1u, 0xB2u, 0x2Eu, 0x10u, 0xF1u, 0x70u, 0xF9u, 0x2Au
        };
        static const uint8_t emptyHash[] = {
            0xE3u, 0xB0u, 0xC4u, 0x42u, 0x98u, 0xFCu, 0x1Cu, 0x14u,
            0x9Au, 0xFBu, 0xF4u, 0xC8u, 0x99u, 0x6Fu, 0xB9u, 0x24u,
            0x27u, 0xAEu, 0x41u, 0xE4u, 0x64u, 0x9Bu, 0x93u, 0x4Cu,
            0xA4u, 0x95u, 0x99u, 0x1Bu, 0x78u, 0x52u, 0xB8u, 0x55u
        };
        static const uint8_t expectedDerived[] = {
            0x6Fu, 0x26u, 0x15u, 0xA1u, 0x08u, 0xC7u, 0x02u, 0xC5u,
            0x67u, 0x8Fu, 0x54u, 0xFCu, 0x9Du, 0xBAu, 0xB6u, 0x97u,
            0x16u, 0xC0u, 0x76u, 0x18u, 0x9Cu, 0x48u, 0x25u, 0x0Cu,
            0xEBu, 0xEAu, 0xC3u, 0x57u, 0x6Cu, 0x36u, 0x11u, 0xBAu
        };
        static const uint8_t handshakeSecret[] = {
            0x1Du, 0xC8u, 0x26u, 0xE9u, 0x36u, 0x06u, 0xAAu, 0x6Fu,
            0xDCu, 0x0Au, 0xADu, 0xC1u, 0x2Fu, 0x74u, 0x1Bu, 0x01u,
            0x04u, 0x6Au, 0xA6u, 0xB9u, 0x9Fu, 0x69u, 0x1Eu, 0xD2u,
            0x21u, 0xA9u, 0xF0u, 0xCAu, 0x04u, 0x3Fu, 0xBEu, 0xACu
        };
        static const uint8_t thashServerHello[] = {
            0x86u, 0x0Cu, 0x06u, 0xEDu, 0xC0u, 0x78u, 0x58u, 0xEEu,
            0x8Eu, 0x78u, 0xF0u, 0xE7u, 0x42u, 0x8Cu, 0x58u, 0xEDu,
            0xD6u, 0xB4u, 0x3Fu, 0x2Cu, 0xA3u, 0xE6u, 0xE9u, 0x5Fu,
            0x02u, 0xEDu, 0x06u, 0x3Cu, 0xF0u, 0xE1u, 0xCAu, 0xD8u
        };
        static const uint8_t expectedCHsTraffic[] = {
            0xB3u, 0xEDu, 0xDBu, 0x12u, 0x6Eu, 0x06u, 0x7Fu, 0x35u,
            0xA7u, 0x80u, 0xB3u, 0xABu, 0xF4u, 0x5Eu, 0x2Du, 0x8Fu,
            0x3Bu, 0x1Au, 0x95u, 0x07u, 0x38u, 0xF5u, 0x2Eu, 0x96u,
            0x00u, 0x74u, 0x6Au, 0x0Eu, 0x27u, 0xA5u, 0x5Au, 0x21u
        };
        static const uint8_t expectedSHsTraffic[] = {
            0xB6u, 0x7Bu, 0x7Du, 0x69u, 0x0Cu, 0xC1u, 0x6Cu, 0x4Eu,
            0x75u, 0xE5u, 0x42u, 0x13u, 0xCBu, 0x2Du, 0x37u, 0xB4u,
            0xE9u, 0xC9u, 0x12u, 0xBCu, 0xDEu, 0xD9u, 0x10u, 0x5Du,
            0x42u, 0xBEu, 0xFDu, 0x59u, 0xD3u, 0x91u, 0xADu, 0x38u
        };
        static const uint8_t expectedClientKey[] = {
            0xDBu, 0xFAu, 0xA6u, 0x93u, 0xD1u, 0x76u, 0x2Cu, 0x5Bu,
            0x66u, 0x6Au, 0xF5u, 0xD9u, 0x50u, 0x25u, 0x8Du, 0x01u
        };
        static const uint8_t expectedClientIv[] = {
            0x5Bu, 0xD3u, 0xC7u, 0x1Bu, 0x83u, 0x6Eu, 0x0Bu, 0x76u,
            0xBBu, 0x73u, 0x26u, 0x5Fu
        };
        uint8_t derived[32];
        uint8_t cHsTraffic[32];
        uint8_t sHsTraffic[32];
        uint8_t clientKey[16];
        uint8_t clientIv[12];

        /* derived = Derive-Secret(early_secret, "derived", empty_hash) */
        SSFTLSDeriveSecret(SSF_HMAC_HASH_SHA256, earlySecret, sizeof(earlySecret),
                           "derived", emptyHash, sizeof(emptyHash),
                           derived, sizeof(derived));
        SSF_ASSERT(memcmp(derived, expectedDerived, sizeof(expectedDerived)) == 0);

        /* c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", thash_ServerHello) */
        SSFTLSDeriveSecret(SSF_HMAC_HASH_SHA256, handshakeSecret, sizeof(handshakeSecret),
                           "c hs traffic", thashServerHello, sizeof(thashServerHello),
                           cHsTraffic, sizeof(cHsTraffic));
        SSF_ASSERT(memcmp(cHsTraffic, expectedCHsTraffic, sizeof(expectedCHsTraffic)) == 0);

        /* s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", thash_ServerHello) */
        SSFTLSDeriveSecret(SSF_HMAC_HASH_SHA256, handshakeSecret, sizeof(handshakeSecret),
                           "s hs traffic", thashServerHello, sizeof(thashServerHello),
                           sHsTraffic, sizeof(sHsTraffic));
        SSF_ASSERT(memcmp(sHsTraffic, expectedSHsTraffic, sizeof(expectedSHsTraffic)) == 0);

        /* (key, iv) = DeriveTrafficKeys(c_hs_traffic): Expand-Label("key", 16), ("iv", 12) */
        SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256, cHsTraffic, sizeof(cHsTraffic),
                                clientKey, sizeof(clientKey),
                                clientIv, sizeof(clientIv));
        SSF_ASSERT(memcmp(clientKey, expectedClientKey, sizeof(expectedClientKey)) == 0);
        SSF_ASSERT(memcmp(clientIv, expectedClientIv, sizeof(expectedClientIv)) == 0);
    }

    /* ---- Record encrypt / decrypt roundtrip (AES-128-GCM) ---- */
    {
        SSFTLSRecordState_t encState = {0};
        SSFTLSRecordState_t decState = {0};
        uint8_t key[16];
        uint8_t iv[12];
        uint8_t plaintext[] = "Hello, TLS 1.3!";
        size_t ptLen = sizeof(plaintext) - 1u;
        uint8_t record[SSF_TLS_RECORD_HEADER_SIZE + 256 + 1 + SSF_TLS_AEAD_TAG_SIZE];
        size_t recordLen;
        uint8_t decrypted[256];
        size_t decLen;
        uint8_t ct;
        uint8_t i;

        /* Use test key and IV */
        for (i = 0; i < 16u; i++) key[i] = (uint8_t)(i + 1u);
        for (i = 0; i < 12u; i++) iv[i] = (uint8_t)(i + 0x10u);

        SSFTLSRecordStateInit(&encState, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));
        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        /* Encrypt */
        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION,
                   plaintext, ptLen, record, sizeof(record), &recordLen) == true);

        /* Record should be larger than plaintext */
        SSF_ASSERT(recordLen == SSF_TLS_RECORD_HEADER_SIZE + ptLen + 1u + SSF_TLS_AEAD_TAG_SIZE);

        /* Outer content type should be application_data (23) */
        SSF_ASSERT(record[0] == SSF_TLS_CT_APPLICATION);

        /* Decrypt */
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == true);

        /* Verify */
        SSF_ASSERT(decLen == ptLen);
        SSF_ASSERT(ct == SSF_TLS_CT_APPLICATION);
        SSF_ASSERT(memcmp(decrypted, plaintext, ptLen) == 0);

        /* Second record with incremented sequence number */
        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_HANDSHAKE,
                   plaintext, ptLen, record, sizeof(record), &recordLen) == true);
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == true);
        SSF_ASSERT(ct == SSF_TLS_CT_HANDSHAKE);
        SSF_ASSERT(memcmp(decrypted, plaintext, ptLen) == 0);
    }

    /* ---- Record: corrupted ciphertext fails decryption ---- */
    {
        SSFTLSRecordState_t encState = {0};
        SSFTLSRecordState_t decState = {0};
        uint8_t key[16];
        uint8_t iv[12];
        uint8_t plaintext[] = "test";
        uint8_t record[128];
        size_t recordLen;
        uint8_t decrypted[128];
        size_t decLen;
        uint8_t ct;
        uint8_t i;

        for (i = 0; i < 16u; i++) key[i] = (uint8_t)i;
        for (i = 0; i < 12u; i++) iv[i] = (uint8_t)i;

        SSFTLSRecordStateInit(&encState, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));
        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION,
                   plaintext, 4, record, sizeof(record), &recordLen) == true);

        /* Corrupt one ciphertext byte */
        record[SSF_TLS_RECORD_HEADER_SIZE] ^= 0x01u;

        /* Decryption should fail due to tag mismatch */
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == false);
    }

    /* ---- Record: AES-256-GCM roundtrip ---- */
    {
        SSFTLSRecordState_t encState = {0};
        SSFTLSRecordState_t decState = {0};
        uint8_t key[32];
        uint8_t iv[12];
        uint8_t plaintext[] = "AES-256-GCM test";
        uint8_t record[128];
        size_t recordLen;
        uint8_t decrypted[128];
        size_t decLen;
        uint8_t ct;
        uint8_t i;

        for (i = 0; i < 32u; i++) key[i] = (uint8_t)(i + 0x40u);
        for (i = 0; i < 12u; i++) iv[i] = (uint8_t)(i + 0x80u);

        SSFTLSRecordStateInit(&encState, SSF_TLS_CS_AES_256_GCM_SHA384,
                              key, sizeof(key), iv, sizeof(iv));
        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_256_GCM_SHA384,
                              key, sizeof(key), iv, sizeof(iv));

        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION,
                   plaintext, 16, record, sizeof(record), &recordLen) == true);
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == true);
        SSF_ASSERT(decLen == 16u);
        SSF_ASSERT(ct == SSF_TLS_CT_APPLICATION);
        SSF_ASSERT(memcmp(decrypted, plaintext, 16) == 0);
    }

    /* AES-128-CCM round trip (16-byte tag). */
    {
        SSFTLSRecordState_t encState = {0};
        SSFTLSRecordState_t decState = {0};
        uint8_t key[16];
        uint8_t iv[12];
        uint8_t plaintext[] = "AES-128-CCM test";
        uint8_t record[128];
        size_t recordLen;
        uint8_t decrypted[128];
        size_t decLen;
        uint8_t ct;
        uint8_t i;

        for (i = 0; i < 16u; i++) key[i] = (uint8_t)(i + 0xA0u);
        for (i = 0; i < 12u; i++) iv[i]  = (uint8_t)(i + 0xB0u);

        SSFTLSRecordStateInit(&encState, SSF_TLS_CS_AES_128_CCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));
        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_128_CCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION,
                   plaintext, 16, record, sizeof(record), &recordLen) == true);
        /* 5 header + 17 inner + 16 tag = 38 bytes on the wire. */
        SSF_ASSERT(recordLen == 38u);
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == true);
        SSF_ASSERT(decLen == 16u);
        SSF_ASSERT(ct == SSF_TLS_CT_APPLICATION);
        SSF_ASSERT(memcmp(decrypted, plaintext, 16) == 0);
    }

    /* AES-128-CCM-8 round trip: the header length must reflect the 8-byte tag. */
    {
        SSFTLSRecordState_t encState = {0};
        SSFTLSRecordState_t decState = {0};
        uint8_t key[16];
        uint8_t iv[12];
        uint8_t plaintext[] = "CCM-8 regression";
        uint8_t record[128];
        size_t recordLen;
        uint8_t decrypted[128];
        size_t decLen;
        uint8_t ct;
        uint8_t i;
        uint16_t hdrCipherLen;

        for (i = 0; i < 16u; i++) key[i] = (uint8_t)(i + 0xC0u);
        for (i = 0; i < 12u; i++) iv[i]  = (uint8_t)(i + 0xD0u);

        SSFTLSRecordStateInit(&encState, SSF_TLS_CS_AES_128_CCM_8_SHA256,
                              key, sizeof(key), iv, sizeof(iv));
        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_128_CCM_8_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION,
                   plaintext, 16, record, sizeof(record), &recordLen) == true);
        /* 5 header + 17 inner + 8 tag = 30 bytes on the wire. */
        SSF_ASSERT(recordLen == 30u);
        /* The header's advertised cipherLen must match innerLen + tagLen = 25. */
        hdrCipherLen = ((uint16_t)record[3] << 8) | (uint16_t)record[4];
        SSF_ASSERT(hdrCipherLen == 25u);

        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == true);
        SSF_ASSERT(decLen == 16u);
        SSF_ASSERT(ct == SSF_TLS_CT_APPLICATION);
        SSF_ASSERT(memcmp(decrypted, plaintext, 16) == 0);
    }
    /* ---- Record: ChaCha20-Poly1305 round-trip ---- */
    {
        SSFTLSRecordState_t encState = {0};
        SSFTLSRecordState_t decState = {0};
        uint8_t key[32];
        uint8_t iv[12];
        uint8_t plaintext[] = "ChaCha20-Poly1305 record test";
        uint8_t record[128];
        size_t recordLen;
        uint8_t decrypted[128];
        size_t decLen;
        uint8_t ct;
        uint8_t i;

        for (i = 0; i < 32u; i++) key[i] = (uint8_t)(i + 0xE0u);
        for (i = 0; i < 12u; i++) iv[i]  = (uint8_t)(i + 0xF0u);

        SSFTLSRecordStateInit(&encState, SSF_TLS_CS_CHACHA20_POLY1305_SHA256,
                              key, sizeof(key), iv, sizeof(iv));
        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_CHACHA20_POLY1305_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION,
                   plaintext, sizeof(plaintext) - 1u, record, sizeof(record), &recordLen) == true);
        SSF_ASSERT(record[0] == SSF_TLS_CT_APPLICATION);
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == true);
        SSF_ASSERT(decLen == sizeof(plaintext) - 1u);
        SSF_ASSERT(ct == SSF_TLS_CT_APPLICATION);
        SSF_ASSERT(memcmp(decrypted, plaintext, sizeof(plaintext) - 1u) == 0);

        /* Tampered ct must reject under ChaCha20-Poly1305 just as under AES-*. */
        record[SSF_TLS_RECORD_HEADER_SIZE] ^= 0x01u;
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, recordLen,
                   decrypted, sizeof(decrypted), &decLen, &ct) == false);
    }

    /* RFC 8446 Sec. 5.5: encrypt and decrypt return false with seqNum at UINT64_MAX. */
    {
        SSFTLSRecordState_t encState = {0};
        SSFTLSRecordState_t decState = {0};
        uint8_t key[16] = {0};
        uint8_t iv[12] = {0};
        uint8_t pt[16] = {0};
        uint8_t record[64];
        size_t recordLen;
        uint8_t decBuf[64];
        size_t decLen;
        uint8_t innerCt;

        SSFTLSRecordStateInit(&encState, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));
        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        encState.seqNum = UINT64_MAX;
        SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION,
                                       pt, sizeof(pt),
                                       record, sizeof(record), &recordLen) == false);

        /* Build a real-looking record header so the seqNum guard is the actual gate. */
        decState.seqNum = UINT64_MAX;
        record[0] = SSF_TLS_CT_APPLICATION;
        record[1] = 0x03u;
        record[2] = 0x03u;
        record[3] = 0x00u;
        record[4] = 0x21u;   /* fragLen = 33 = innerLen(17) + tagLen(16) */
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, record, 5u + 0x21u,
                                       decBuf, sizeof(decBuf),
                                       &decLen, &innerCt) == false);
    }

    /* ---- Encrypt/decrypt reject an unsupported suite (state corrupted after Init) ---- */
    {
        SSFTLSRecordState_t state = {0};
        uint8_t key[16] = {0};
        uint8_t iv[12] = {0};
        uint8_t pt[16] = {0};
        uint8_t record[64];
        size_t outLen;
        uint8_t innerCt;

        SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256, key, sizeof(key), iv,
                              sizeof(iv));
        state.cipherSuite = 0xFFFFu;
        SSF_ASSERT(SSFTLSRecordEncrypt(&state, SSF_TLS_CT_APPLICATION, pt, sizeof(pt),
                                       record, sizeof(record), &outLen) == false);

        /* Build a header that parses cleanly so the tag-size guard is the actual gate. */
        record[0] = SSF_TLS_CT_APPLICATION;
        record[1] = 0x03u;
        record[2] = 0x03u;
        record[3] = 0x00u;
        record[4] = 0x21u;
        SSF_ASSERT(SSFTLSRecordDecrypt(&state, record, 5u + 0x21u,
                                       pt, sizeof(pt), &outLen, &innerCt) == false);
    }

    /* SSFTLSHkdfExpandLabel: full DBC surface. */
    {
        uint8_t scratchSecret[32] = {0};
        uint8_t scratchCtx[100];
        uint8_t scratchOut[32];
        char    longLabel[251];

        memset(scratchCtx, 0xA5u, sizeof(scratchCtx));
        memset(longLabel, 'X', sizeof(longLabel));
        longLabel[sizeof(longLabel) - 1u] = '\0';   /* 250-char label, one past the RFC cap */

        /* secret NULL */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256, NULL, 32u, "key",
                                              NULL, 0u, scratchOut, sizeof(scratchOut)));
        /* label NULL */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), NULL,
                                              NULL, 0u, scratchOut, sizeof(scratchOut)));
        /* out NULL */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), "key",
                                              NULL, 0u, NULL, sizeof(scratchOut)));
        /* outLen > 255 */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), "key",
                                              NULL, 0u, scratchOut, 256u));
        /* ctxLen > SSF_TLS_MAX_HASH_SIZE -- addresses #1 buffer overflow */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), "key",
                                              scratchCtx, 49u,
                                              scratchOut, sizeof(scratchOut)));
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), "key",
                                              scratchCtx, sizeof(scratchCtx),
                                              scratchOut, sizeof(scratchOut)));
        /* labelLen > 249 (RFC 8446 Sec. 7.1: "tls13 " + label must fit opaque label<7..255>) */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), longLabel,
                                              NULL, 0u, scratchOut, sizeof(scratchOut)));
        /* AUDIT TLS-3: context NULL with ctxLen > 0 used to build a malformed HkdfLabel */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), "key",
                                              NULL, 32u, scratchOut, sizeof(scratchOut)));
    }

    /* AUDIT TLS-4: a 249-byte label (the RFC 8446 maximum) is accepted and framed correctly. */
    {
        static const uint8_t expected[32] = {
            0x7Au, 0xDEu, 0x0Du, 0x02u, 0xBBu, 0xFBu, 0x19u, 0x8Eu,
            0xCDu, 0x6Du, 0xF3u, 0x02u, 0x42u, 0x1Eu, 0x30u, 0xAEu,
            0xF3u, 0xF3u, 0x82u, 0xA9u, 0x1Au, 0x36u, 0x58u, 0x97u,
            0x5Bu, 0xA5u, 0xDCu, 0xA2u, 0x17u, 0x18u, 0x1Bu, 0x9Bu
        };
        uint8_t secret[32];
        uint8_t ctx[32];
        uint8_t out[32];
        char maxLabel[250];
        uint8_t i;

        for (i = 0u; i < (uint8_t)sizeof(secret); i++) secret[i] = i;
        memset(ctx, 0xA5u, sizeof(ctx));
        memset(maxLabel, 'X', sizeof(maxLabel));
        maxLabel[sizeof(maxLabel) - 1u] = '\0';

        /* Expected output from an independent Python RFC 5869 / RFC 8446 model. */
        SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256, secret, sizeof(secret), maxLabel, ctx,
                              sizeof(ctx), out, sizeof(out));
        SSF_ASSERT(memcmp(out, expected, sizeof(expected)) == 0);
    }

    /* SSFTLSDeriveSecret: adds transcriptHash NULL on top of HkdfExpandLabel's contracts. */
    {
        uint8_t scratchSecret[32] = {0};
        uint8_t scratchOut[32];

        SSF_ASSERT_TEST(SSFTLSDeriveSecret(SSF_HMAC_HASH_SHA256,
                                           scratchSecret, sizeof(scratchSecret), "derived",
                                           NULL, 0u, scratchOut, sizeof(scratchOut)));
    }

    /* SSFTLSDeriveTrafficKeys: full DBC surface. */
    {
        uint8_t scratchSecret[32] = {0};
        uint8_t scratchKey[16];
        uint8_t scratchIv[12];

        SSF_ASSERT_TEST(SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256,
                                                NULL, sizeof(scratchSecret),
                                                scratchKey, sizeof(scratchKey),
                                                scratchIv, sizeof(scratchIv)));
        SSF_ASSERT_TEST(SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256,
                                                scratchSecret, sizeof(scratchSecret),
                                                NULL, sizeof(scratchKey),
                                                scratchIv, sizeof(scratchIv)));
        SSF_ASSERT_TEST(SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256,
                                                scratchSecret, sizeof(scratchSecret),
                                                scratchKey, sizeof(scratchKey),
                                                NULL, sizeof(scratchIv)));
    }

    /* SSFTLSComputeFinished: full DBC surface. */
    {
        uint8_t scratchKey[32] = {0};
        uint8_t scratchHash[32] = {0};
        uint8_t scratchVerify[100];

        /* baseKey NULL */
        SSF_ASSERT_TEST(SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                                              NULL, sizeof(scratchKey),
                                              scratchHash, sizeof(scratchHash),
                                              scratchVerify, 32u));
        /* transcriptHash NULL */
        SSF_ASSERT_TEST(SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                                              scratchKey, sizeof(scratchKey),
                                              NULL, sizeof(scratchHash),
                                              scratchVerify, 32u));
        /* verifyData NULL */
        SSF_ASSERT_TEST(SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                                              scratchKey, sizeof(scratchKey),
                                              scratchHash, sizeof(scratchHash),
                                              NULL, 32u));
        /* verifyDataLen > SSF_TLS_MAX_HASH_SIZE -- addresses #2 buffer overflow */
        SSF_ASSERT_TEST(SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                                              scratchKey, sizeof(scratchKey),
                                              scratchHash, sizeof(scratchHash),
                                              scratchVerify, 49u));
        SSF_ASSERT_TEST(SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                                              scratchKey, sizeof(scratchKey),
                                              scratchHash, sizeof(scratchHash),
                                              scratchVerify, sizeof(scratchVerify)));
    }

    /* SSFTLSTranscriptInit / Update / Hash: full DBC surface. */
    {
        SSFTLSTranscript_t t;
        uint8_t scratchHash[48];
        uint8_t scratchData[16] = {0};

        /* Init: t NULL */
        SSF_ASSERT_TEST(SSFTLSTranscriptInit(NULL, SSF_HMAC_HASH_SHA256));
        /* Init: invalid hash (SHA-1 is not allowed for the TLS 1.3 transcript) */
        SSF_ASSERT_TEST(SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA1));

        /* Properly init for the rest of the tests. */
        SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA256);

        /* Update: t NULL */
        SSF_ASSERT_TEST(SSFTLSTranscriptUpdate(NULL, scratchData, sizeof(scratchData)));
        /* Update: data NULL with len > 0 */
        SSF_ASSERT_TEST(SSFTLSTranscriptUpdate(&t, NULL, 1u));

        /* Hash: t NULL */
        SSF_ASSERT_TEST(SSFTLSTranscriptHash(NULL, scratchHash, sizeof(scratchHash)));
        /* Hash: out NULL */
        SSF_ASSERT_TEST(SSFTLSTranscriptHash(&t, NULL, sizeof(scratchHash)));
        /* Hash: outSize < hashLen -- SHA-256 needs 32 */
        SSF_ASSERT_TEST(SSFTLSTranscriptHash(&t, scratchHash, 31u));
    }

    /* SSFTLSRecordStateInit: full DBC surface. */
    {
        SSFTLSRecordState_t state = {0};
        uint8_t key[32] = {0};
        uint8_t iv[12] = {0};

        /* state NULL */
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(NULL, SSF_TLS_CS_AES_128_GCM_SHA256,
                                              key, 16u, iv, sizeof(iv)));
        /* key NULL */
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256,
                                              NULL, 16u, iv, sizeof(iv)));
        /* iv NULL */
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256,
                                              key, 16u, NULL, sizeof(iv)));
        /* ivLen != 12 */
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256,
                                              key, 16u, iv, 11u));
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256,
                                              key, 16u, iv, 13u));
        /* keyLen > SSF_TLS_MAX_KEY_SIZE */
        SSF_ASSERT_TEST(SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256,
                                              key, 33u, iv, sizeof(iv)));
    }

    /* SSFTLSRecordEncrypt: full DBC surface. */
    {
        SSFTLSRecordState_t state = {0};
        uint8_t key[16] = {0};
        uint8_t iv[12] = {0};
        uint8_t pt[16] = {0};
        uint8_t record[64];
        size_t recordLen;

        SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        /* state NULL */
        SSF_ASSERT_TEST(SSFTLSRecordEncrypt(NULL, SSF_TLS_CT_APPLICATION,
                                            pt, sizeof(pt), record, sizeof(record), &recordLen));
        /* pt NULL */
        SSF_ASSERT_TEST(SSFTLSRecordEncrypt(&state, SSF_TLS_CT_APPLICATION,
                                            NULL, sizeof(pt), record, sizeof(record), &recordLen));
        /* record NULL */
        SSF_ASSERT_TEST(SSFTLSRecordEncrypt(&state, SSF_TLS_CT_APPLICATION,
                                            pt, sizeof(pt), NULL, sizeof(record), &recordLen));
        /* recordLen NULL */
        SSF_ASSERT_TEST(SSFTLSRecordEncrypt(&state, SSF_TLS_CT_APPLICATION,
                                            pt, sizeof(pt), record, sizeof(record), NULL));
    }

    /* SSFTLSRecordDecrypt: full DBC surface. */
    {
        SSFTLSRecordState_t state = {0};
        uint8_t key[16] = {0};
        uint8_t iv[12] = {0};
        uint8_t record[64] = {0};
        uint8_t pt[64];
        size_t ptLen;
        uint8_t ct;

        SSFTLSRecordStateInit(&state, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));

        /* state NULL */
        SSF_ASSERT_TEST(SSFTLSRecordDecrypt(NULL, record, sizeof(record),
                                            pt, sizeof(pt), &ptLen, &ct));
        /* record NULL */
        SSF_ASSERT_TEST(SSFTLSRecordDecrypt(&state, NULL, sizeof(record),
                                            pt, sizeof(pt), &ptLen, &ct));
        /* pt NULL */
        SSF_ASSERT_TEST(SSFTLSRecordDecrypt(&state, record, sizeof(record),
                                            NULL, sizeof(pt), &ptLen, &ct));
        /* ptLen NULL */
        SSF_ASSERT_TEST(SSFTLSRecordDecrypt(&state, record, sizeof(record),
                                            pt, sizeof(pt), NULL, &ct));
        /* contentType NULL */
        SSF_ASSERT_TEST(SSFTLSRecordDecrypt(&state, record, sizeof(record),
                                            pt, sizeof(pt), &ptLen, NULL));
    }

    /* SSFTLSRecordDecrypt rejects fragLen 0x4101, one past the 2^14 + 256 limit. */
    {
        SSFTLSRecordState_t decState = {0};
        uint8_t key[16] = {0};
        uint8_t iv[12] = {0};
        uint8_t oversizedRecord[0x4106];   /* HEADER + 0x4101 */
        uint8_t scratchPt[0x4101];
        size_t scratchPtLen;
        uint8_t scratchCt;

        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_128_GCM_SHA256,
                              key, sizeof(key), iv, sizeof(iv));
        memset(oversizedRecord, 0, sizeof(oversizedRecord));
        oversizedRecord[0] = SSF_TLS_CT_APPLICATION;
        oversizedRecord[1] = 0x03u;
        oversizedRecord[2] = 0x03u;
        oversizedRecord[3] = 0x41u;        /* fragLen = 0x4101 = 16641, just over the limit */
        oversizedRecord[4] = 0x01u;

        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, oversizedRecord, sizeof(oversizedRecord),
                                       scratchPt, sizeof(scratchPt),
                                       &scratchPtLen, &scratchCt) == false);
    }

    /* ---- AUDIT TLS-1/TLS-6: SSFTLSRecordEncrypt enforces TLSPlaintext.length <= 2^14 ---- */
    {
        static const uint16_t suites[] = { SSF_TLS_CS_AES_128_GCM_SHA256,
                                           SSF_TLS_CS_AES_128_CCM_8_SHA256 };
        static uint8_t bigPt[0x4000u + 1u];
        static uint8_t bigRecord[SSF_TLS_RECORD_HEADER_SIZE + 0x4000u + 256u];
        static uint8_t bigDec[0x4000u + 1u];
        uint8_t key[16];
        uint8_t iv[12];
        size_t bigRecordLen;
        size_t bigDecLen;
        uint8_t bigCt;
        size_t k;

        for (k = 0; k < sizeof(bigPt); k++) bigPt[k] = (uint8_t)(k * 7u);
        for (k = 0; k < sizeof(key); k++) key[k] = (uint8_t)(0x20u + k);
        for (k = 0; k < sizeof(iv); k++) iv[k] = (uint8_t)(0x40u + k);

        for (k = 0; k < (sizeof(suites) / sizeof(suites[0])); k++)
        {
            SSFTLSRecordState_t encState = {0};
            SSFTLSRecordState_t decState = {0};

            SSFTLSRecordStateInit(&encState, suites[k], key, sizeof(key), iv, sizeof(iv));
            SSFTLSRecordStateInit(&decState, suites[k], key, sizeof(key), iv, sizeof(iv));

            /* Exactly 2^14 bytes: allowed, and round-trips. */
            SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION, bigPt, 0x4000u,
                                           bigRecord, sizeof(bigRecord), &bigRecordLen) == true);
            SSF_ASSERT(SSFTLSRecordDecrypt(&decState, bigRecord, bigRecordLen, bigDec,
                                           sizeof(bigDec), &bigDecLen, &bigCt) == true);
            SSF_ASSERT(bigDecLen == 0x4000u);
            SSF_ASSERT(bigCt == SSF_TLS_CT_APPLICATION);
            SSF_ASSERT(memcmp(bigDec, bigPt, 0x4000u) == 0);

            /* 2^14 + 1 bytes: over the TLSPlaintext limit, must be refused. */
            SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION, bigPt, 0x4001u,
                                           bigRecord, sizeof(bigRecord), &bigRecordLen) == false);

            /* SIZE_MAX: must be refused before ptLen + 1 can wrap (TLS-6). */
            SSF_ASSERT(SSFTLSRecordEncrypt(&encState, SSF_TLS_CT_APPLICATION, bigPt, SIZE_MAX,
                                           bigRecord, sizeof(bigRecord), &bigRecordLen) == false);

            SSFTLSRecordStateDeInit(&encState);
            SSFTLSRecordStateDeInit(&decState);
        }
    }

    /* ---- AUDIT TLS-2: Decrypt rejects TLSInnerPlaintext > 2^14 + 1 (built via raw AEAD) ---- */
    {
        static uint8_t ovRecord[SSF_TLS_RECORD_HEADER_SIZE + 0x4002u + 16u];
        static uint8_t ovInner[0x4002u];
        static uint8_t ovDec[0x4002u];
        SSFTLSRecordState_t decState = {0};
        uint8_t key[16];
        uint8_t iv[12];
        size_t innerLen;
        size_t fragLen;
        size_t ovDecLen;
        uint8_t ovCt;
        size_t k;

        for (k = 0; k < sizeof(key); k++) key[k] = (uint8_t)(0x60u + k);
        for (k = 0; k < sizeof(iv); k++) iv[k] = (uint8_t)(0x80u + k);

        /* inner = 2^14 + 1 bytes of data || content type: one byte over the inner limit. */
        innerLen = sizeof(ovInner);
        for (k = 0; k < (innerLen - 1u); k++) ovInner[k] = (uint8_t)(k + 3u);
        ovInner[innerLen - 1u] = SSF_TLS_CT_APPLICATION;
        fragLen = innerLen + 16u;

        ovRecord[0] = SSF_TLS_CT_APPLICATION;
        ovRecord[1] = 0x03u;
        ovRecord[2] = 0x03u;
        ovRecord[3] = (uint8_t)((fragLen >> 8) & 0xFFu);
        ovRecord[4] = (uint8_t)(fragLen & 0xFFu);
        SSFAESGCMEncrypt(ovInner, innerLen, iv, sizeof(iv), ovRecord, SSF_TLS_RECORD_HEADER_SIZE,
                         key, sizeof(key), &ovRecord[SSF_TLS_RECORD_HEADER_SIZE + innerLen], 16u,
                         &ovRecord[SSF_TLS_RECORD_HEADER_SIZE], innerLen);

        SSFTLSRecordStateInit(&decState, SSF_TLS_CS_AES_128_GCM_SHA256, key, sizeof(key), iv,
                              sizeof(iv));
        SSF_ASSERT(SSFTLSRecordDecrypt(&decState, ovRecord, sizeof(ovRecord), ovDec,
                                       sizeof(ovDec), &ovDecLen, &ovCt) == false);
        SSFTLSRecordStateDeInit(&decState);
    }

    /* AUDIT TLS-8: in-place pt, partial overlap traps, content type 0 traps, length cast traps */
    {
        SSFTLSRecordState_t enc = { 0 };
        SSFTLSRecordState_t dec = { 0 };
        SSFTLSTranscript_t t;
        uint8_t key[16];
        uint8_t iv[SSF_TLS_IV_SIZE];
        uint8_t record[5u + 64u + 1u + 16u];
        uint8_t msg[64];
        uint8_t out[80];
        size_t recordLen;
        size_t outLen;
        uint8_t ct;

        memset(key, 0x4E, sizeof(key));
        memset(iv, 0x71, sizeof(iv));
        memset(msg, 0x3C, sizeof(msg));
        SSFTLSRecordStateInit(&enc, SSF_TLS_CS_AES_128_GCM_SHA256, key, sizeof(key), iv,
                              sizeof(iv));
        SSFTLSRecordStateInit(&dec, SSF_TLS_CS_AES_128_GCM_SHA256, key, sizeof(key), iv,
                              sizeof(iv));

        /* (a) In place: the plaintext is already where the record body goes. */
        memcpy(&record[5], msg, sizeof(msg));
        SSF_ASSERT(SSFTLSRecordEncrypt(&enc, SSF_TLS_CT_APPLICATION, &record[5], sizeof(msg),
                                       record, sizeof(record), &recordLen) == true);
        SSF_ASSERT(SSFTLSRecordDecrypt(&dec, record, recordLen, out, sizeof(out), &outLen,
                                       &ct) == true);
        SSF_ASSERT((outLen == sizeof(msg)) && (memcmp(out, msg, sizeof(msg)) == 0));
        SSF_ASSERT(ct == SSF_TLS_CT_APPLICATION);

        /* (a) Partial overlap with the record body. */
        SSF_ASSERT_TEST(SSFTLSRecordEncrypt(&enc, SSF_TLS_CT_APPLICATION, &record[6], 16u,
                                            record, sizeof(record), &recordLen));

        /* (b) Content type 0. */
        SSF_ASSERT_TEST(SSFTLSRecordEncrypt(&enc, 0u, msg, sizeof(msg), record, sizeof(record),
                                            &recordLen));
        SSFTLSRecordStateDeInit(&enc);
        SSFTLSRecordStateDeInit(&dec);

        /* (c) Length that does not fit the SHA update's uint32_t. */
#if SIZE_MAX > UINT32_MAX
        SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA256);
        SSF_ASSERT_TEST(SSFTLSTranscriptUpdate(&t, msg, ((size_t)UINT32_MAX) + 1u));
        SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA384);
        SSF_ASSERT_TEST(SSFTLSTranscriptUpdate(&t, msg, ((size_t)UINT32_MAX) + 1u));
#else
        (void)t;
#endif
    }
}
#ifdef _WIN32
#pragma warning(pop)
#endif
#endif /* SSF_CONFIG_TLS_UNIT_TEST */
