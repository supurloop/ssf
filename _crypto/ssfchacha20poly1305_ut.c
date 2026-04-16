/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfchacha20poly1305_ut.c                                                                      */
/* Provides ChaCha20-Poly1305 AEAD unit test (RFC 7539).                                         */
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
#include "ssfchacha20poly1305.h"

#if SSF_CONFIG_CCP_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* RFC 7539 Section 2.8.2 AEAD test vector                                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFChaCha20Poly1305UnitTest(void)
{
    /* RFC 7539 Section 2.8.2 */
    static const uint8_t key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t nonce[] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    static const uint8_t aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    static const uint8_t pt[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    static const uint8_t expected_ct[] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    static const uint8_t expected_tag[] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };

    uint8_t ct[sizeof(pt)];
    uint8_t tag[16];
    uint8_t dec[sizeof(pt)];
    bool ok;

    /* Test RFC 7539 Section 2.8.2 AEAD encrypt */
    SSFChaCha20Poly1305Encrypt(pt, sizeof(pt), nonce, sizeof(nonce),
                               aad, sizeof(aad), key, sizeof(key),
                               tag, sizeof(tag), ct, sizeof(ct));
    SSF_ASSERT(memcmp(ct, expected_ct, sizeof(expected_ct)) == 0);
    SSF_ASSERT(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0);

    /* Test RFC 7539 Section 2.8.2 AEAD decrypt */
    ok = SSFChaCha20Poly1305Decrypt(ct, sizeof(ct), nonce, sizeof(nonce),
                                    aad, sizeof(aad), key, sizeof(key),
                                    tag, sizeof(tag), dec, sizeof(dec));
    SSF_ASSERT(ok);
    SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);

    /* Test wrong tag returns false */
    {
        uint8_t badTag[16];
        memcpy(badTag, tag, sizeof(badTag));
        badTag[0] ^= 0x01;
        ok = SSFChaCha20Poly1305Decrypt(ct, sizeof(ct), nonce, sizeof(nonce),
                                        aad, sizeof(aad), key, sizeof(key),
                                        badTag, sizeof(badTag), dec, sizeof(dec));
        SSF_ASSERT(!ok);
    }

    /* Test encrypt/decrypt round-trip with no AAD */
    {
        uint8_t rtCt[sizeof(pt)];
        uint8_t rtTag[16];
        uint8_t rtDec[sizeof(pt)];

        SSFChaCha20Poly1305Encrypt(pt, sizeof(pt), nonce, sizeof(nonce),
                                   NULL, 0, key, sizeof(key),
                                   rtTag, sizeof(rtTag), rtCt, sizeof(rtCt));
        ok = SSFChaCha20Poly1305Decrypt(rtCt, sizeof(rtCt), nonce, sizeof(nonce),
                                        NULL, 0, key, sizeof(key),
                                        rtTag, sizeof(rtTag), rtDec, sizeof(rtDec));
        SSF_ASSERT(ok);
        SSF_ASSERT(memcmp(rtDec, pt, sizeof(pt)) == 0);
    }

    /* Test empty plaintext (auth-only mode) */
    {
        uint8_t authOnlyTag[16];
        uint8_t authOnlyTag2[16];

        SSFChaCha20Poly1305Encrypt(NULL, 0, nonce, sizeof(nonce),
                                   aad, sizeof(aad), key, sizeof(key),
                                   authOnlyTag, sizeof(authOnlyTag), NULL, 0);
        ok = SSFChaCha20Poly1305Decrypt(NULL, 0, nonce, sizeof(nonce),
                                        aad, sizeof(aad), key, sizeof(key),
                                        authOnlyTag, sizeof(authOnlyTag), NULL, 0);
        SSF_ASSERT(ok);

        /* Verify wrong tag fails for auth-only mode too */
        memset(authOnlyTag2, 0, sizeof(authOnlyTag2));
        ok = SSFChaCha20Poly1305Decrypt(NULL, 0, nonce, sizeof(nonce),
                                        aad, sizeof(aad), key, sizeof(key),
                                        authOnlyTag2, sizeof(authOnlyTag2), NULL, 0);
        SSF_ASSERT(!ok);
    }
}

#endif /* SSF_CONFIG_CCP_UNIT_TEST */
