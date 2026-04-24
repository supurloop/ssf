/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpoly1305.c                                                                                 */
/* Provides Poly1305 message authentication code implementation (RFC 7539).                      */
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
#include "ssfpoly1305.h"

/* --------------------------------------------------------------------------------------------- */
/* Poly1305 uses 130-bit arithmetic mod p = 2^130 - 5.                                          */
/* We use 5 limbs of 26 bits each (Donna variant). All intermediate products fit uint64_t.       */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Computes Poly1305 MAC (RFC 7539 Section 2.5).                                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFPoly1305Mac(const uint8_t *msg, size_t msgLen,
                    const uint8_t *key, size_t keyLen,
                    uint8_t *tag, size_t tagSize)
{
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s0, s1, s2, s3;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t rr0, rr1, rr2, rr3;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;
    size_t pos;
    size_t remaining;
    uint32_t hibit;
    uint8_t buf[16];
    uint64_t f;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t mask;

    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(keyLen == SSF_POLY1305_KEY_SIZE);
    SSF_REQUIRE(tag != NULL);
    SSF_REQUIRE(tagSize >= SSF_POLY1305_TAG_SIZE);

    /* Clamp r (RFC 7539 Section 2.5) */
    r0 = (SSF_GETU32LE(&key[0])) & 0x3FFFFFFu;
    r1 = (SSF_GETU32LE(&key[3]) >> 2) & 0x3FFFF03u;
    r2 = (SSF_GETU32LE(&key[6]) >> 4) & 0x3FFC0FFu;
    r3 = (SSF_GETU32LE(&key[9]) >> 6) & 0x3F03FFFu;
    r4 = (SSF_GETU32LE(&key[12]) >> 8) & 0x00FFFFFu;

    /* s = key[16..31] */
    s0 = SSF_GETU32LE(&key[16]);
    s1 = SSF_GETU32LE(&key[20]);
    s2 = SSF_GETU32LE(&key[24]);
    s3 = SSF_GETU32LE(&key[28]);

    /* Precompute r * 5 for reduction */
    rr0 = r1 * 5;
    rr1 = r2 * 5;
    rr2 = r3 * 5;
    rr3 = r4 * 5;

    h0 = 0; h1 = 0; h2 = 0; h3 = 0; h4 = 0;

    pos = 0;
    while (pos < msgLen)
    {
        remaining = msgLen - pos;

        if (remaining >= 16)
        {
            /* Full block: append 0x01 as high bit */
            h0 += SSF_GETU32LE(&msg[pos]) & 0x3FFFFFFu;
            h1 += (SSF_GETU32LE(&msg[pos + 3]) >> 2) & 0x3FFFFFFu;
            h2 += (SSF_GETU32LE(&msg[pos + 6]) >> 4) & 0x3FFFFFFu;
            h3 += (SSF_GETU32LE(&msg[pos + 9]) >> 6) & 0x3FFFFFFu;
            h4 += (SSF_GETU32LE(&msg[pos + 12]) >> 8) | (1u << 24);
            hibit = 0; /* Already added above */
            pos += 16;
        }
        else
        {
            /* Partial block: pad with 0x01 then zeros */
            memset(buf, 0, sizeof(buf));
            memcpy(buf, &msg[pos], remaining);
            buf[remaining] = 0x01;
            hibit = 0;

            h0 += SSF_GETU32LE(&buf[0]) & 0x3FFFFFFu;
            h1 += (SSF_GETU32LE(&buf[3]) >> 2) & 0x3FFFFFFu;
            h2 += (SSF_GETU32LE(&buf[6]) >> 4) & 0x3FFFFFFu;
            h3 += (SSF_GETU32LE(&buf[9]) >> 6) & 0x3FFFFFFu;
            h4 += (SSF_GETU32LE(&buf[12]) >> 8);
            pos += remaining;
        }

        /* h = (h * r) mod p */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * rr3) +
             ((uint64_t)h2 * rr2) + ((uint64_t)h3 * rr1) + ((uint64_t)h4 * rr0);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) +
             ((uint64_t)h2 * rr3) + ((uint64_t)h3 * rr2) + ((uint64_t)h4 * rr1);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) +
             ((uint64_t)h2 * r0) + ((uint64_t)h3 * rr3) + ((uint64_t)h4 * rr2);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) +
             ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * rr3);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) +
             ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        /* Carry propagation */
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3FFFFFFu;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3FFFFFFu;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3FFFFFFu;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3FFFFFFu;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3FFFFFFu;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFFu;
        h1 += c;
    }

    /* Final reduction: fully carry h */
    c = h1 >> 26; h1 &= 0x3FFFFFFu;
    h2 += c; c = h2 >> 26; h2 &= 0x3FFFFFFu;
    h3 += c; c = h3 >> 26; h3 &= 0x3FFFFFFu;
    h4 += c; c = h4 >> 26; h4 &= 0x3FFFFFFu;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFFu;
    h1 += c;

    /* Compute h - p = h - (2^130 - 5) */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3FFFFFFu;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFFu;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFFu;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFFu;
    g4 = h4 + c - (1u << 26);

    /* Select h if h < p, else g = h - p */
    mask = (g4 >> 31) - 1u; /* 0 if g4 bit 31 set (h < p), 0xFFFFFFFF otherwise */
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Assemble h into 4 × 32-bit words and add s */
    f = (uint64_t)(h0 | (h1 << 26)) + s0; tag[0] = (uint8_t)f;
    tag[1] = (uint8_t)(f >> 8); tag[2] = (uint8_t)(f >> 16); tag[3] = (uint8_t)(f >> 24);
    f = (uint64_t)((h1 >> 6) | (h2 << 20)) + s1 + (f >> 32); tag[4] = (uint8_t)f;
    tag[5] = (uint8_t)(f >> 8); tag[6] = (uint8_t)(f >> 16); tag[7] = (uint8_t)(f >> 24);
    f = (uint64_t)((h2 >> 12) | (h3 << 14)) + s2 + (f >> 32); tag[8] = (uint8_t)f;
    tag[9] = (uint8_t)(f >> 8); tag[10] = (uint8_t)(f >> 16); tag[11] = (uint8_t)(f >> 24);
    f = (uint64_t)((h3 >> 18) | (h4 << 8)) + s3 + (f >> 32); tag[12] = (uint8_t)f;
    tag[13] = (uint8_t)(f >> 8); tag[14] = (uint8_t)(f >> 16); tag[15] = (uint8_t)(f >> 24);
}
