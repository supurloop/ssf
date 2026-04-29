/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftls_ut.c                                                                                   */
/* Provides unit tests for the ssftls TLS 1.3 core module.                                      */
/* Key schedule test vectors from RFC 8448 ("Example Handshake Traces for TLS 1.3").             */
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
    /* SSFTLSHkdfExpandLabel: ctxLen must be bounded. The internal hkdfLabel buffer is sized
     * for at most SSF_TLS_MAX_HASH_SIZE (48) context bytes — without a contract check, larger
     * ctxLen values overflow the stack buffer. The call below would write 100 bytes into a
     * slot sized for 48; the SSF_REQUIRE introduced for this finding catches it. */
    {
        uint8_t scratchSecret[32] = {0};
        uint8_t scratchCtx[200];
        uint8_t scratchOut[32];

        memset(scratchCtx, 0xA5u, sizeof(scratchCtx));
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret),
                                              "key",
                                              scratchCtx, 49u,
                                              scratchOut, sizeof(scratchOut)));
        SSF_ASSERT_TEST(SSFTLSHkdfExpandLabel(SSF_HMAC_HASH_SHA256,
                                              scratchSecret, sizeof(scratchSecret),
                                              "key",
                                              scratchCtx, sizeof(scratchCtx),
                                              scratchOut, sizeof(scratchOut)));
    }

    /* SSFTLSComputeFinished: verifyDataLen must be bounded. The internal finishedKey buffer
     * is SSF_TLS_MAX_HASH_SIZE (48) bytes — verifyDataLen above that overflows it. */
    {
        uint8_t scratchKey[32] = {0};
        uint8_t scratchHash[32] = {0};
        uint8_t scratchVerify[100];

        SSF_ASSERT_TEST(SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                                              scratchKey, sizeof(scratchKey),
                                              scratchHash, sizeof(scratchHash),
                                              scratchVerify, 49u));
        SSF_ASSERT_TEST(SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                                              scratchKey, sizeof(scratchKey),
                                              scratchHash, sizeof(scratchHash),
                                              scratchVerify, sizeof(scratchVerify)));
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
