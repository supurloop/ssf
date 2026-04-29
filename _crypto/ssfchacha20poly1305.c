/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfchacha20poly1305.c                                                                         */
/* Provides ChaCha20-Poly1305 AEAD implementation (RFC 7539).                                    */
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
#include <stdint.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfchacha20.h"
#include "ssfpoly1305.h"
#include "ssfchacha20poly1305.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Streams the Poly1305 AEAD construction `auth || pad16 || ct || pad16 || le64(authLen) ||      */
/* le64(ctLen)` directly into an incremental Poly1305 context — no intermediate buffer.          */
/* Peak stack for this function is ~sizeof(SSFPoly1305Context_t) + ~32 B of locals, independent  */
/* of authLen and ctLen.                                                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFCCPComputeTag(const uint8_t *auth, size_t authLen, const uint8_t *ct, size_t ctLen,
                              const uint8_t *otk, uint8_t *tag, size_t tagSize)
{
    static const uint8_t pad16[15] = { 0 };
    SSFPoly1305Context_t ctx = {0};
    uint8_t lengths[16];

    SSFPoly1305Begin(&ctx, otk, SSF_POLY1305_KEY_SIZE);

    /* AAD + zero pad to 16-byte boundary. */
    if (authLen > 0u) SSFPoly1305Update(&ctx, auth, authLen);
    SSFPoly1305Update(&ctx, pad16, (16u - (authLen & 15u)) & 15u);

    /* Ciphertext + zero pad to 16-byte boundary. */
    if (ctLen > 0u) SSFPoly1305Update(&ctx, ct, ctLen);
    SSFPoly1305Update(&ctx, pad16, (16u - (ctLen & 15u)) & 15u);

    /* le64(authLen) || le64(ctLen). */
    SSF_PUTU64LE(&lengths[0], (uint64_t)authLen);
    SSF_PUTU64LE(&lengths[8], (uint64_t)ctLen);
    SSFPoly1305Update(&ctx, lengths, sizeof(lengths));

    SSFPoly1305End(&ctx, tag, tagSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs ChaCha20-Poly1305 AEAD encryption (RFC 7539 Section 2.8).                            */
/* --------------------------------------------------------------------------------------------- */
void SSFChaCha20Poly1305Encrypt(const uint8_t *pt, size_t ptLen, const uint8_t *iv, size_t ivLen,
                                const uint8_t *auth, size_t authLen, const uint8_t *key,
                                size_t keyLen, uint8_t *tag, size_t tagSize, uint8_t *ct,
                                size_t ctSize)
{
    uint8_t otk[SSF_POLY1305_KEY_SIZE];
    uint8_t zeros[SSF_POLY1305_KEY_SIZE];

    SSF_REQUIRE(iv != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(tag != NULL);
    SSF_REQUIRE(keyLen == SSF_CCP_KEY_SIZE);
    SSF_REQUIRE(ivLen == SSF_CCP_NONCE_SIZE);
    SSF_REQUIRE(tagSize >= SSF_CCP_TAG_SIZE);
    SSF_REQUIRE(ptLen <= ctSize);
    SSF_REQUIRE(ptLen < (512u * 1024u * 1024u));
    SSF_REQUIRE((auth != NULL) || (authLen == 0u));

    /* Generate Poly1305 one-time key using counter=0 */
    memset(zeros, 0, sizeof(zeros));
    SSFChaCha20Encrypt(zeros, sizeof(zeros), key, keyLen, iv, ivLen, 0, otk, sizeof(otk));

    /* Encrypt plaintext using counter=1 */
    if (ptLen > 0)
    {
        SSF_REQUIRE(pt != NULL);
        SSF_REQUIRE(ct != NULL);
        SSFChaCha20Encrypt(pt, ptLen, key, keyLen, iv, ivLen, 1, ct, ctSize);
    }

    /* Compute Poly1305 tag over auth || pad || ct || pad || lengths */
    _SSFCCPComputeTag(auth, authLen, ct, ptLen, otk, tag, SSF_CCP_TAG_SIZE);

    /* Zeroize one-time key */
    SSFCryptSecureZero(otk, sizeof(otk));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if ChaCha20-Poly1305 AEAD decryption/authentication successful else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFChaCha20Poly1305Decrypt(const uint8_t *ct, size_t ctLen, const uint8_t *iv, size_t ivLen,
                                const uint8_t *auth, size_t authLen, const uint8_t *key,
                                size_t keyLen, const uint8_t *tag, size_t tagLen, uint8_t *pt,
                                size_t ptSize)
{
    uint8_t otk[SSF_POLY1305_KEY_SIZE];
    uint8_t zeros[SSF_POLY1305_KEY_SIZE];
    uint8_t computedTag[SSF_CCP_TAG_SIZE];

    SSF_REQUIRE(iv != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(tag != NULL);
    SSF_REQUIRE(keyLen == SSF_CCP_KEY_SIZE);
    SSF_REQUIRE(ivLen == SSF_CCP_NONCE_SIZE);
    SSF_REQUIRE(tagLen == SSF_CCP_TAG_SIZE);
    SSF_REQUIRE(ctLen <= ptSize);
    SSF_REQUIRE(ctLen < (512u * 1024u * 1024u));
    SSF_REQUIRE((auth != NULL) || (authLen == 0u));

    /* Generate Poly1305 one-time key using counter=0 */
    memset(zeros, 0, sizeof(zeros));
    SSFChaCha20Encrypt(zeros, sizeof(zeros), key, keyLen, iv, ivLen, 0, otk, sizeof(otk));

    /* Compute expected tag BEFORE decrypting */
    _SSFCCPComputeTag(auth, authLen, ct, ctLen, otk, computedTag, sizeof(computedTag));

    /* Zeroize one-time key */
    SSFCryptSecureZero(otk, sizeof(otk));

    /* Verify tag in constant time to avoid leaking the position of the first differing byte. */
    if (SSFCryptCTMemEq(computedTag, tag, SSF_CCP_TAG_SIZE) == false)
    {
        /* Scrub computedTag before stack reuse: on the failure path it holds the correct */
        /* expected tag for (key, AAD, ct), the value an attacker submitting forged tags  */
        /* is trying to recover.                                                          */
        SSFCryptSecureZero(computedTag, sizeof(computedTag));
        return false;
    }

    /* Tag verified: decrypt */
    if (ctLen > 0)
    {
        SSF_REQUIRE(ct != NULL);
        SSF_REQUIRE(pt != NULL);
        SSFChaCha20Encrypt(ct, ctLen, key, keyLen, iv, ivLen, 1, pt, ptSize);
    }

    /* Scrub computedTag for symmetry with the failure path. On success it equals the     */
    /* caller's supplied tag (already public), but consistent scrubbing is cheaper than   */
    /* path-dependent reasoning.                                                          */
    SSFCryptSecureZero(computedTag, sizeof(computedTag));
    return true;
}

