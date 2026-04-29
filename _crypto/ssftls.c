/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftls.c                                                                                      */
/* Provides TLS 1.3 core: key schedule, record layer, and handshake message codec (RFC 8446).    */
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
#include "ssfaesgcm.h"
#include "ssfaesccm.h"
#include "ssfchacha20poly1305.h"

/* --------------------------------------------------------------------------------------------- */
/* Key schedule: HKDF-Expand-Label (RFC 8446 Section 7.1)                                        */
/*                                                                                               */
/* HkdfLabel = uint16(Length) || uint8(6 + len(Label)) || "tls13 " || Label ||                   */
/*             uint8(len(Context)) || Context                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSHkdfExpandLabel(SSFHMACHash_t hash,
                           const uint8_t *secret, size_t secretLen,
                           const char *label,
                           const uint8_t *context, size_t ctxLen,
                           uint8_t *out, size_t outLen)
{
    uint8_t hkdfLabel[2 + 1 + 6 + 64 + 1 + SSF_TLS_MAX_HASH_SIZE];
    size_t labelLen;
    size_t pos = 0;

    SSF_REQUIRE(secret != NULL);
    SSF_REQUIRE(label != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen <= 255u);
    /* hkdfLabel buffer is sized for at most SSF_TLS_MAX_HASH_SIZE bytes of context. RFC 8446 */
    /* §7.1 permits up to 255 bytes, but real TLS 1.3 only feeds transcript hashes (≤ 48), so */
    /* tightening to the buffer's slot is safe and matches actual usage.                     */
    SSF_REQUIRE(ctxLen <= SSF_TLS_MAX_HASH_SIZE);

    labelLen = strlen(label);
    SSF_REQUIRE(labelLen <= 64u);

    /* uint16 Length */
    hkdfLabel[pos++] = (uint8_t)((outLen >> 8) & 0xFFu);
    hkdfLabel[pos++] = (uint8_t)(outLen & 0xFFu);

    /* uint8 label length (including "tls13 " prefix) */
    hkdfLabel[pos++] = (uint8_t)(6u + labelLen);

    /* "tls13 " prefix + label */
    memcpy(&hkdfLabel[pos], "tls13 ", 6);
    pos += 6;
    memcpy(&hkdfLabel[pos], label, labelLen);
    pos += labelLen;

    /* uint8 context length + context */
    hkdfLabel[pos++] = (uint8_t)ctxLen;
    if ((context != NULL) && (ctxLen > 0u))
    {
        memcpy(&hkdfLabel[pos], context, ctxLen);
        pos += ctxLen;
    }

    SSFHKDFExpand(hash, secret, secretLen, hkdfLabel, pos, out, outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Key schedule: Derive-Secret (RFC 8446 Section 7.1)                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSDeriveSecret(SSFHMACHash_t hash,
                        const uint8_t *secret, size_t secretLen,
                        const char *label,
                        const uint8_t *transcriptHash, size_t transcriptHashLen,
                        uint8_t *out, size_t outLen)
{
    SSF_REQUIRE(transcriptHash != NULL);

    SSFTLSHkdfExpandLabel(hash, secret, secretLen, label,
                          transcriptHash, transcriptHashLen, out, outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Key schedule: derive traffic key and IV from traffic secret (RFC 8446 Section 7.3)            */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSDeriveTrafficKeys(SSFHMACHash_t hash,
                             const uint8_t *trafficSecret, size_t secretLen,
                             uint8_t *key, size_t keyLen,
                             uint8_t *iv, size_t ivLen)
{
    SSF_REQUIRE(trafficSecret != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(iv != NULL);

    SSFTLSHkdfExpandLabel(hash, trafficSecret, secretLen, "key", NULL, 0, key, keyLen);
    SSFTLSHkdfExpandLabel(hash, trafficSecret, secretLen, "iv", NULL, 0, iv, ivLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Key schedule: compute Finished verify_data (RFC 8446 Section 4.4.4)                           */
/*                                                                                               */
/* finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)                        */
/* verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context ...))                      */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSComputeFinished(SSFHMACHash_t hash,
                           const uint8_t *baseKey, size_t baseKeyLen,
                           const uint8_t *transcriptHash, size_t transcriptHashLen,
                           uint8_t *verifyData, size_t verifyDataLen)
{
    uint8_t finishedKey[SSF_TLS_MAX_HASH_SIZE];

    SSF_REQUIRE(baseKey != NULL);
    SSF_REQUIRE(transcriptHash != NULL);
    SSF_REQUIRE(verifyData != NULL);
    /* finishedKey is sized for SSF_TLS_MAX_HASH_SIZE — verifyDataLen above that overflows it. */
    /* RFC 8446 §4.4.4 specifies verify_data length equals the hash output length (32 or 48). */
    SSF_REQUIRE(verifyDataLen <= SSF_TLS_MAX_HASH_SIZE);

    /* finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length) */
    SSFTLSHkdfExpandLabel(hash, baseKey, baseKeyLen, "finished", NULL, 0,
                          finishedKey, verifyDataLen);

    /* verify_data = HMAC(finished_key, transcript_hash) */
    SSFHMAC(hash, finishedKey, verifyDataLen, transcriptHash, transcriptHashLen,
            verifyData, verifyDataLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Transcript hash                                                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSTranscriptInit(SSFTLSTranscript_t *t, SSFHMACHash_t hash)
{
    SSF_REQUIRE(t != NULL);

    t->hmac = hash;
    switch (hash)
    {
    case SSF_HMAC_HASH_SHA256:
        t->hashLen = SSF_SHA2_256_BYTE_SIZE;
        SSFSHA256Begin(&t->ctx.sha256);
        break;
    case SSF_HMAC_HASH_SHA384:
        t->hashLen = SSF_SHA2_384_BYTE_SIZE;
        SSFSHA384Begin(&t->ctx.sha384);
        break;
    default:
        SSF_ASSERT(false);
        break;
    }
}

void SSFTLSTranscriptUpdate(SSFTLSTranscript_t *t, const uint8_t *data, size_t len)
{
    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE((data != NULL) || (len == 0));

    switch (t->hmac)
    {
    case SSF_HMAC_HASH_SHA256:
        SSFSHA256Update(&t->ctx.sha256, data, (uint32_t)len);
        break;
    case SSF_HMAC_HASH_SHA384:
        SSFSHA384Update(&t->ctx.sha384, data, (uint32_t)len);
        break;
    default:
        SSF_ASSERT(false);
        break;
    }
}

void SSFTLSTranscriptHash(const SSFTLSTranscript_t *t, uint8_t *out, size_t outSize)
{
    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outSize >= t->hashLen);

    /* Snapshot: copy context, finalize the copy (leaves original intact) */
    switch (t->hmac)
    {
    case SSF_HMAC_HASH_SHA256:
    {
        SSFSHA2_32Context_t tmp;
        memcpy(&tmp, &t->ctx.sha256, sizeof(tmp));
        SSFSHA256End(&tmp, out, (uint32_t)outSize);
        break;
    }
    case SSF_HMAC_HASH_SHA384:
    {
        SSFSHA2_64Context_t tmp;
        memcpy(&tmp, &t->ctx.sha384, sizeof(tmp));
        SSFSHA384End(&tmp, out, (uint32_t)outSize);
        break;
    }
    default:
        SSF_ASSERT(false);
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Record layer: initialize state                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSRecordStateInit(SSFTLSRecordState_t *state, uint16_t cipherSuite,
                           const uint8_t *key, size_t keyLen,
                           const uint8_t *iv, size_t ivLen)
{
    SSF_REQUIRE(state != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(iv != NULL);
    SSF_REQUIRE(ivLen == SSF_TLS_IV_SIZE);
    SSF_REQUIRE(keyLen <= SSF_TLS_MAX_KEY_SIZE);

    memset(state, 0, sizeof(*state));
    memcpy(state->key, key, keyLen);
    memcpy(state->iv, iv, ivLen);
    state->keyLen = (uint16_t)keyLen;
    state->cipherSuite = cipherSuite;
    state->seqNum = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Record layer: build per-record nonce = IV XOR pad64(sequence_number)                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSBuildNonce(const SSFTLSRecordState_t *state, uint8_t nonce[12])
{
    uint8_t i;

    memcpy(nonce, state->iv, SSF_TLS_IV_SIZE);

    /* XOR sequence number (big-endian) into the rightmost 8 bytes of the IV */
    for (i = 0; i < 8u; i++)
    {
        nonce[SSF_TLS_IV_SIZE - 1u - i] ^= (uint8_t)((state->seqNum >> (i * 8u)) & 0xFFu);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* AEAD tag size per TLS 1.3 cipher suite. Returns 0 for an unsupported suite.                   */
/* All currently supported suites use 16-byte tags except TLS_AES_128_CCM_8_SHA256 (8 bytes).    */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSAeadTagSize(uint16_t cipherSuite)
{
    switch (cipherSuite)
    {
    case SSF_TLS_CS_AES_128_GCM_SHA256:
    case SSF_TLS_CS_AES_256_GCM_SHA384:
    case SSF_TLS_CS_AES_128_CCM_SHA256:
    case SSF_TLS_CS_CHACHA20_POLY1305_SHA256:
        return SSF_TLS_AEAD_TAG_SIZE;    /* 16 */
    case SSF_TLS_CS_AES_128_CCM_8_SHA256:
        return 8u;
    default:
        return 0u;                        /* Unsupported */
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Record layer: encrypt a plaintext into a TLS 1.3 record.                                      */
/* RFC 8446 Section 5.2: inner content type appended before encryption.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFTLSRecordEncrypt(SSFTLSRecordState_t *state, uint8_t contentType,
                         const uint8_t *pt, size_t ptLen,
                         uint8_t *record, size_t recordSize, size_t *recordLen)
{
    size_t tagLen;
    size_t innerLen;
    size_t cipherLen;
    size_t totalLen;
    uint8_t nonce[SSF_TLS_IV_SIZE];
    uint8_t *inner;
    uint8_t *ct;

    SSF_REQUIRE(state != NULL);
    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(record != NULL);
    SSF_REQUIRE(recordLen != NULL);

    /* Per-suite AEAD tag size (16 bytes for all suites except TLS_AES_128_CCM_8_SHA256, which
     * uses 8). Rejecting unsupported suites up front keeps the rest of the function's sizing
     * math straightforward. */
    tagLen = _SSFTLSAeadTagSize(state->cipherSuite);
    if (tagLen == 0u) return false;

    innerLen  = ptLen + 1u;              /* plaintext + inner content type */
    cipherLen = innerLen + tagLen;
    totalLen  = SSF_TLS_RECORD_HEADER_SIZE + cipherLen;

    if (recordSize < totalLen) return false;
    if (cipherLen > 0x4000u + 256u) return false; /* RFC 8446 §5.2 record limit */

    /* Build record header (used as AAD). cipherLen now correctly reflects the tag size. */
    record[0] = SSF_TLS_CT_APPLICATION; /* Outer type is always application_data */
    record[1] = 0x03u;
    record[2] = 0x03u;                   /* Legacy version 0x0303 */
    record[3] = (uint8_t)((cipherLen >> 8) & 0xFFu);
    record[4] = (uint8_t)(cipherLen & 0xFFu);

    /* Build inner plaintext: plaintext || content_type */
    inner = &record[SSF_TLS_RECORD_HEADER_SIZE];
    memcpy(inner, pt, ptLen);
    inner[ptLen] = contentType;

    /* Build nonce */
    _SSFTLSBuildNonce(state, nonce);

    /* AEAD encrypt in-place and place the tag of size `tagLen` immediately after. */
    ct = &record[SSF_TLS_RECORD_HEADER_SIZE];
    {
        uint8_t tag[SSF_TLS_AEAD_TAG_SIZE];

        switch (state->cipherSuite)
        {
        case SSF_TLS_CS_AES_128_GCM_SHA256:
        case SSF_TLS_CS_AES_256_GCM_SHA384:
            SSFAESGCMEncrypt(inner, innerLen, nonce, SSF_TLS_IV_SIZE,
                             record, SSF_TLS_RECORD_HEADER_SIZE,
                             state->key, state->keyLen,
                             tag, tagLen, ct, innerLen);
            break;
        case SSF_TLS_CS_AES_128_CCM_SHA256:
        case SSF_TLS_CS_AES_128_CCM_8_SHA256:
            SSFAESCCMEncrypt(inner, innerLen, nonce, SSF_TLS_IV_SIZE,
                             record, SSF_TLS_RECORD_HEADER_SIZE,
                             state->key, state->keyLen,
                             tag, tagLen, ct, innerLen);
            break;
        case SSF_TLS_CS_CHACHA20_POLY1305_SHA256:
            SSFChaCha20Poly1305Encrypt(inner, innerLen, nonce, SSF_TLS_IV_SIZE,
                                       record, SSF_TLS_RECORD_HEADER_SIZE,
                                       state->key, state->keyLen,
                                       tag, tagLen, ct, innerLen);
            break;
        default:
            /* Unreachable: _SSFTLSAeadTagSize rejected this above. */
            return false;
        }
        memcpy(&ct[innerLen], tag, tagLen);
    }

    state->seqNum++;
    *recordLen = totalLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Record layer: decrypt a TLS 1.3 record.                                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFTLSRecordDecrypt(SSFTLSRecordState_t *state,
                         const uint8_t *record, size_t recordLen,
                         uint8_t *pt, size_t ptSize, size_t *ptLen,
                         uint8_t *contentType)
{
    size_t tagLen;
    uint16_t fragLen;
    size_t innerLen;
    uint8_t nonce[SSF_TLS_IV_SIZE];
    const uint8_t *ct;
    const uint8_t *tag;

    SSF_REQUIRE(state != NULL);
    SSF_REQUIRE(record != NULL);
    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(ptLen != NULL);
    SSF_REQUIRE(contentType != NULL);

    /* Per-suite AEAD tag size — must match what the encrypting peer emitted. */
    tagLen = _SSFTLSAeadTagSize(state->cipherSuite);
    if (tagLen == 0u) return false;

    if (recordLen < SSF_TLS_RECORD_HEADER_SIZE + tagLen + 1u) return false;

    /* Parse record header */
    if (record[0] != SSF_TLS_CT_APPLICATION) return false;

    fragLen = ((uint16_t)record[3] << 8) | (uint16_t)record[4];
    if ((size_t)(SSF_TLS_RECORD_HEADER_SIZE + fragLen) != recordLen) return false;
    if (fragLen < tagLen + 1u) return false;
    /* RFC 8446 §5.2: receivers MUST reject records whose ciphertext exceeds 2^14 + 256. */
    if (fragLen > 0x4000u + 256u) return false;

    innerLen = (size_t)fragLen - tagLen;
    if (ptSize < innerLen) return false;

    ct = &record[SSF_TLS_RECORD_HEADER_SIZE];
    tag = &ct[innerLen];

    /* Build nonce */
    _SSFTLSBuildNonce(state, nonce);

    /* AEAD decrypt */
    {
        bool ok;

        switch (state->cipherSuite)
        {
        case SSF_TLS_CS_AES_128_GCM_SHA256:
        case SSF_TLS_CS_AES_256_GCM_SHA384:
            ok = SSFAESGCMDecrypt(ct, innerLen, nonce, SSF_TLS_IV_SIZE,
                                  record, SSF_TLS_RECORD_HEADER_SIZE,
                                  state->key, state->keyLen,
                                  tag, tagLen, pt, innerLen);
            break;
        case SSF_TLS_CS_AES_128_CCM_SHA256:
        case SSF_TLS_CS_AES_128_CCM_8_SHA256:
            ok = SSFAESCCMDecrypt(ct, innerLen, nonce, SSF_TLS_IV_SIZE,
                                  record, SSF_TLS_RECORD_HEADER_SIZE,
                                  state->key, state->keyLen,
                                  tag, tagLen, pt, innerLen);
            break;
        case SSF_TLS_CS_CHACHA20_POLY1305_SHA256:
            ok = SSFChaCha20Poly1305Decrypt(ct, innerLen, nonce, SSF_TLS_IV_SIZE,
                                             record, SSF_TLS_RECORD_HEADER_SIZE,
                                             state->key, state->keyLen,
                                             tag, tagLen, pt, innerLen);
            break;
        default:
            /* Unreachable: _SSFTLSAeadTagSize rejected this above. */
            return false;
        }
        if (!ok) return false;
    }

    state->seqNum++;

    /* Strip inner content type (last byte of plaintext). Skip zero-padding. */
    {
        size_t i = innerLen;
        while (i > 0u && pt[i - 1u] == 0u) i--;
        if (i == 0u) return false;
        i--;
        *contentType = pt[i];
        *ptLen = i;
    }

    return true;
}
