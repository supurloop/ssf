/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftls_ut.c                                                                                   */
/* Provides unit tests for the ssftls TLS 1.3 core module.                                      */
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

#if SSF_CONFIG_TLS_UNIT_TEST == 1

void SSFTLSUnitTest(void)
{
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
        uint8_t hash1[32], hash2[32];

        SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA256);
        SSFTLSTranscriptUpdate(&t, (const uint8_t *)"hello", 5);
        SSFTLSTranscriptHash(&t, hash1, sizeof(hash1));

        /* Update more data and take another snapshot */
        SSFTLSTranscriptUpdate(&t, (const uint8_t *)" world", 6);
        SSFTLSTranscriptHash(&t, hash2, sizeof(hash2));

        /* Snapshots should differ */
        SSF_ASSERT(memcmp(hash1, hash2, 32) != 0);
    }

    /* ---- HKDF-Expand-Label basic test ---- */
    /* Verify the label encoding produces correct output by testing against known values. */
    /* The TLS 1.3 key schedule starts with HKDF-Extract(0, 0) for early secret (no PSK). */
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
        uint8_t key[16], iv[12];
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

    /* ---- RFC 8448 §3 Simple 1-RTT Handshake key-schedule KAT ---- */
    /* Walks four steps of the published worked example with bit-exact reference values:           */
    /*   derived       = Derive-Secret(early_secret, "derived", empty_hash)                         */
    /*   c_hs_traffic  = Derive-Secret(handshake_secret, "c hs traffic", thash_through_ServerHello) */
    /*   s_hs_traffic  = Derive-Secret(handshake_secret, "s hs traffic", thash_through_ServerHello) */
    /*   (key, iv)     = DeriveTrafficKeys(c_hs_traffic) — HKDF-Expand-Label "key" + "iv"           */
    /* Exercises HkdfExpandLabel, DeriveSecret, and DeriveTrafficKeys against published RFC values  */
    /* for the strongest cross-build correctness coverage. The Finished step is not pinned here     */
    /* because the trace doesn't make its transcript-hash input explicit — it remains exercised     */
    /* via the existing deterministic regression test below.                                        */
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

        /* (key, iv) = DeriveTrafficKeys(c_hs_traffic) — HKDF-Expand-Label("key", 16) and ("iv", 12) */
        SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256, cHsTraffic, sizeof(cHsTraffic),
                                clientKey, sizeof(clientKey),
                                clientIv, sizeof(clientIv));
        SSF_ASSERT(memcmp(clientKey, expectedClientKey, sizeof(expectedClientKey)) == 0);
        SSF_ASSERT(memcmp(clientIv, expectedClientIv, sizeof(expectedClientIv)) == 0);
    }

    /* ---- Record encrypt / decrypt roundtrip (AES-128-GCM) ---- */
    {
        SSFTLSRecordState_t encState, decState;
        uint8_t key[16], iv[12];
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
        SSFTLSRecordState_t encState, decState;
        uint8_t key[16], iv[12];
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
        SSFTLSRecordState_t encState, decState;
        uint8_t key[32], iv[12];
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
        SSFTLSRecordState_t encState, decState;
        uint8_t key[16], iv[12];
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

    /* AES-128-CCM-8 round trip (8-byte tag). Regression test for the framing bug where
     * the record header advertised a 16-byte tag length but only 8 tag bytes were written,
     * leaving 8 uninitialised bytes in the wire record and breaking interop with any
     * spec-compliant peer. cipherLen must reflect the 8-byte tag, and Decrypt must
     * dispatch CCM_8 correctly. */
    {
        SSFTLSRecordState_t encState, decState;
        uint8_t key[16], iv[12];
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
        SSFTLSRecordState_t encState, decState;
        uint8_t key[32], iv[12];
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

    /* RFC 8446 §5.5: implementations MUST close the connection when the sequence number
     * wraps. SSF refuses encrypt / decrypt when state->seqNum is already at UINT64_MAX —
     * the next increment would wrap to 0 and reuse the nonce of record 0, breaking the
     * AEAD contract catastrophically. Set state.seqNum to the boundary and confirm both
     * directions return false. */
    {
        SSFTLSRecordState_t encState, decState;
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

        /* Build a real-looking record header so decrypt's framing checks pass and the seqNum
         * guard is the actual gate. */
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

    /* SSFTLSHkdfExpandLabel: full DBC surface. */
    {
        uint8_t scratchSecret[32] = {0};
        uint8_t scratchCtx[100];
        uint8_t scratchOut[32];
        char    longLabel[80];

        memset(scratchCtx, 0xA5u, sizeof(scratchCtx));
        memset(longLabel, 'X', sizeof(longLabel));
        longLabel[sizeof(longLabel) - 1u] = '\0';   /* 79-char label, just past the 64-byte cap */

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
        /* ctxLen > SSF_TLS_MAX_HASH_SIZE — addresses #1 buffer overflow */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), "key",
                                              scratchCtx, 49u,
                                              scratchOut, sizeof(scratchOut)));
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), "key",
                                              scratchCtx, sizeof(scratchCtx),
                                              scratchOut, sizeof(scratchOut)));
        /* labelLen > 64 */
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret), longLabel,
                                              NULL, 0u, scratchOut, sizeof(scratchOut)));
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
        /* verifyDataLen > SSF_TLS_MAX_HASH_SIZE — addresses #2 buffer overflow */
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
        /* Hash: outSize < hashLen — SHA-256 needs 32 */
        SSF_ASSERT_TEST(SSFTLSTranscriptHash(&t, scratchHash, 31u));
    }

    /* SSFTLSRecordStateInit: full DBC surface. */
    {
        SSFTLSRecordState_t state;
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
        SSFTLSRecordState_t state;
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
        SSFTLSRecordState_t state;
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

    /* SSFTLSRecordDecrypt: records claiming a fragLen above 2^14 + 256 (RFC 8446 §5.2 limit)
     * must be rejected. Build a header with fragLen = 0x4101 (one past the limit) and check
     * that decrypt returns false rather than proceeding to the AEAD layer. */
    {
        SSFTLSRecordState_t decState;
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
}
#endif /* SSF_CONFIG_TLS_UNIT_TEST */
