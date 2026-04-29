/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfchacha20.c                                                                                 */
/* Provides ChaCha20 stream cipher implementation (RFC 7539).                                    */
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

/* --------------------------------------------------------------------------------------------- */
/* Per US export restrictions for open source cryptographic software the Department of Commerce  */
/* has been notified of the inclusion of cryptographic software in the SSF. This is a copy of    */
/* the notice emailed on Nov 11, 2021:                                                           */
/* --------------------------------------------------------------------------------------------- */
/* Unrestricted Encryption Source Code Notification                                              */
/* To : crypt@bis.doc.gov; enc@nsa.gov                                                           */
/* Subject : Addition to SSF Source Code                                                         */
/* Department of Commerce                                                                        */
/* Bureau of Export Administration                                                               */
/* Office of Strategic Trade and Foreign Policy Controls                                         */
/* 14th Street and Pennsylvania Ave., N.W.                                                       */
/* Room 2705                                                                                     */
/* Washington, DC 20230                                                                          */
/* Re: Unrestricted Encryption Source Code Notification Commodity : Addition to SSF Source Code  */
/*                                                                                               */
/* Dear Sir / Madam,                                                                             */
/*                                                                                               */
/* Pursuant to paragraph(e)(1) of Part 740.13 of the U.S.Export Administration Regulations       */
/* ("EAR", 15 CFR Part 730 et seq.), we are providing this written notification of the Internet  */
/* location of the unrestricted, publicly available Source Code being added to the Small System  */
/* Framework (SSF) Source Code. SSF Source Code is a free embedded system application framework  */
/* developed by Supurloop Software LLC in the Public Interest. This notification serves as a     */
/* notification of an addition of new software to the SSF archive. This archive is updated from  */
/* time to time, but its location is constant. Therefore this notification serves as a one-time  */
/* notification for subsequent updates that may occur in the future to the software covered by   */
/* this notification. Such updates may add or enhance cryptographic functionality of the SSF.    */
/* The Internet location for the SSF Source Code is: https://github.com/supurloop/ssf            */
/*                                                                                               */
/* This site may be mirrored to a number of other sites located outside the United States.       */
/*                                                                                               */
/* The following software is being added to the SSF archive:                                     */
/*                                                                                               */
/* ssfchacha20.c, ssfchacha20.h - ChaCha20 stream cipher.                                       */
/* ssfpoly1305.c, ssfpoly1305.h - Poly1305 message authentication code.                         */
/* ssfchacha20poly1305.c, ssfchacha20poly1305.h - ChaCha20-Poly1305 AEAD.                       */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfchacha20.h"
#include "ssfcrypt.h"

/* --------------------------------------------------------------------------------------------- */
/* Module Defines                                                                                */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* ChaCha20 quarter round (RFC 7539 Section 2.1).                                               */
/* --------------------------------------------------------------------------------------------- */
#define QR(a, b, c, d) \
    a += b; d ^= a; d = SSF_ROTL32(d, 16); \
    c += d; b ^= c; b = SSF_ROTL32(b, 12); \
    a += b; d ^= a; d = SSF_ROTL32(d, 8);  \
    c += d; b ^= c; b = SSF_ROTL32(b, 7)

/* --------------------------------------------------------------------------------------------- */
/* Generates one 64-byte ChaCha20 keystream block (RFC 7539 Section 2.3).                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFChaCha20Block(const uint32_t *input, size_t inputLen, uint8_t *out,
                              size_t outSize)
{
    uint32_t x[16];
    uint32_t i;

    SSF_ASSERT(inputLen == sizeof(uint32_t) * 16u);
    SSF_ASSERT(outSize >= SSF_CHACHA20_BLOCK_SIZE);

    memcpy(x, input, sizeof(uint32_t) * 16);

    /* 20 rounds = 10 iterations of double-round */
    for (i = 0; i < 10; i++)
    {
        /* Column rounds */
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    /* Add initial state */
    for (i = 0; i < 16; i++)
    {
        SSF_PUTU32LE(&out[i * 4], x[i] + input[i]);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Encrypts (or decrypts) data with ChaCha20 (RFC 7539 Section 2.4).                             */
/* --------------------------------------------------------------------------------------------- */
void SSFChaCha20Encrypt(const uint8_t *pt, size_t ptLen, const uint8_t *key, size_t keyLen,
                        const uint8_t *nonce, size_t nonceLen, uint32_t counter, uint8_t *ct,
                        size_t ctSize)
{
    uint32_t state[16];
    uint8_t block[SSF_CHACHA20_BLOCK_SIZE];
    size_t pos;
    size_t remaining;
    uint32_t i;

    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(keyLen == SSF_CHACHA20_KEY_SIZE);
    SSF_REQUIRE(nonce != NULL);
    SSF_REQUIRE(nonceLen == SSF_CHACHA20_NONCE_SIZE);
    SSF_REQUIRE(ptLen <= ctSize);
    SSF_REQUIRE(ptLen < (512u * 1024u * 1024u));

    if (ptLen == 0) return;

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(ct != NULL);

    /* Initialize state: constants || key || counter || nonce (RFC 7539 Section 2.3) */
    state[0] = 0x61707865u; /* "expa" */
    state[1] = 0x3320646eu; /* "nd 3" */
    state[2] = 0x79622d32u; /* "2-by" */
    state[3] = 0x6b206574u; /* "te k" */
    state[4] = SSF_GETU32LE(&key[0]);
    state[5] = SSF_GETU32LE(&key[4]);
    state[6] = SSF_GETU32LE(&key[8]);
    state[7] = SSF_GETU32LE(&key[12]);
    state[8] = SSF_GETU32LE(&key[16]);
    state[9] = SSF_GETU32LE(&key[20]);
    state[10] = SSF_GETU32LE(&key[24]);
    state[11] = SSF_GETU32LE(&key[28]);
    state[12] = counter;
    state[13] = SSF_GETU32LE(&nonce[0]);
    state[14] = SSF_GETU32LE(&nonce[4]);
    state[15] = SSF_GETU32LE(&nonce[8]);

    pos = 0;
    while (pos < ptLen)
    {
        _SSFChaCha20Block(state, sizeof(state), block, sizeof(block));

        remaining = ptLen - pos;
        if (remaining > SSF_CHACHA20_BLOCK_SIZE) remaining = SSF_CHACHA20_BLOCK_SIZE;

        for (i = 0; i < (uint32_t)remaining; i++)
        {
            ct[pos + i] = pt[pos + i] ^ block[i];
        }

        state[12]++;
        pos += remaining;
    }

    /* Defense-in-depth: state[4..11] holds the key, block[] holds the most recent keystream. */
    /* Scrub both before stack reuse. SSFCryptSecureZero uses volatile writes to defeat dead- */
    /* store elimination at -O3.                                                              */
    SSFCryptSecureZero(state, sizeof(state));
    SSFCryptSecureZero(block, sizeof(block));
}

