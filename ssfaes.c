/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaes.c                                                                                      */
/* Provides AES block interface.                                                                 */
/*                                                                                               */
/* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf                                      */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2021 Supurloop Software LLC                                                         */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Per US export restrictions for open source cryptographic software the Department of Commerce  */
/* has been notified of the inclusion of cryptographic software in the SSF. This is a copy of    */
/* the notice:                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Unrestricted Encryption Source Code Notification                                              */
/* To : crypt@bxa.doc.gov                                                                        */
/* Subject : Addition to SSF Source Code                                                         */
/* Department of Commerce                                                                        */
/* Bureau of Export Administration                                                               */
/* Office of Strategic Tradeand Foreign Policy Controls                                          */
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
/* ssfaes.c, ssfaes.h - AES block encryption.                                                    */
/* ssfaesgcm.c, ssfaesgcm.h - AES-GCM authenticated encryption.                                  */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"

#define FGFM2(x) ((x<<1) ^ (0x1b & -(x>>7)))

#define BOX_STATE(s, b) \
    s[0][0] = b[s[0][0]]; s[0][1] = b[s[0][1]]; s[0][2] = b[s[0][2]]; s[0][3] = b[s[0][3]]; \
    s[1][0] = b[s[1][0]]; s[1][1] = b[s[1][1]]; s[1][2] = b[s[1][2]]; s[1][3] = b[s[1][3]]; \
    s[2][0] = b[s[2][0]]; s[2][1] = b[s[2][1]]; s[2][2] = b[s[2][2]]; s[2][3] = b[s[2][3]]; \
    s[3][0] = b[s[3][0]]; s[3][1] = b[s[3][1]]; s[3][2] = b[s[3][2]]; s[3][3] = b[s[3][3]]

#define SBOX_STATE(s) BOX_STATE(s, sbox)
#define INV_SBOX_STATE(s) BOX_STATE(s, inv_sbox)

#define SBOX_WORD(x) (sbox[(x & 0xff)] ^ (sbox[((x >> 8) & 0xff)] << 8) \
    ^ (sbox[((x >> 16) & 0xff)] << 16) ^ (sbox[((x >> 24) & 0xff)] << 24))

#define SHIFT_ROWS(s, t) \
    t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t; \
    t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t; t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t; \
    t = s[3][0]; s[3][0] = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = t

#define INV_SHIFT_ROWS(s, t) \
    t = s[1][3]; s[1][3] = s[1][2]; s[1][2] = s[1][1]; s[1][1] = s[1][0]; s[1][0] = t; \
    t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t; t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t; \
    t = s[3][0]; s[3][0] = s[3][1]; s[3][1] = s[3][2]; s[3][2] = s[3][3]; s[3][3] = t

#define MIX_COLUMN(s, i, t) \
    t[4] = s[0][i] ^ s[1][i] ^ s[2][i] ^ s[3][i]; \
    t[0] = s[0][i] ^ s[1][i]; \
    t[0] = FGFM2(t[0]) ^ s[0][i] ^ t[4]; \
    t[1] = s[1][i] ^ s[2][i]; \
    t[1] = FGFM2(t[1]) ^ s[1][i] ^ t[4]; \
    t[2] = s[2][i] ^ s[3][i]; \
    t[2] = FGFM2(t[2]) ^ s[2][i] ^ t[4]; \
    t[3] = s[3][i] ^ s[0][i]; \
    t[3] = FGFM2(t[3]) ^ s[3][i] ^ t[4]; \
    s[0][i] = t[0]; s[1][i] = t[1]; s[2][i] = t[2]; s[3][i] = t[3]

#define MIX_COLUMNS(s, t) \
    MIX_COLUMN(s, 0, t); MIX_COLUMN(s, 1, t); \
    MIX_COLUMN(s, 2, t); MIX_COLUMN(s, 3, t)

#define INV_MIX_COLUMNS_PREPROCESS_COLUMN(s, i, t) \
    t[0] = s[0][i] ^ s[2][i]; \
    t[0] = FGFM2(t[0]); \
    t[0] = FGFM2(t[0]); \
    t[1] = s[1][i] ^ s[3][i]; \
    t[1] = FGFM2(t[1]); \
    t[1] = FGFM2(t[1]); \
    s[0][i] ^= t[0]; \
    s[1][i] ^= t[1]; \
    s[2][i] ^= t[0]; \
    s[3][i] ^= t[1]

#define INV_MIX_COLUMNS(s, t) \
    INV_MIX_COLUMNS_PREPROCESS_COLUMN(s, 0, t); INV_MIX_COLUMNS_PREPROCESS_COLUMN(s, 1, t); \
    INV_MIX_COLUMNS_PREPROCESS_COLUMN(s, 2, t); INV_MIX_COLUMNS_PREPROCESS_COLUMN(s, 3, t); \
    MIX_COLUMNS(s, t)


#define ADD_KEY(s, w, i) \
    s[0][0] ^= w[i] & 0xff; \
    s[1][0] ^= (w[i] >> 8) & 0xff; \
    s[2][0] ^= (w[i] >> 16) & 0xff; \
    s[3][0] ^= (w[i] >> 24) & 0xff; \
    s[0][1] ^= w[i + 1] & 0xff; \
    s[1][1] ^= (w[i + 1] >> 8) & 0xff; \
    s[2][1] ^= (w[i + 1] >> 16) & 0xff; \
    s[3][1] ^= (w[i + 1] >> 24) & 0xff; \
    s[0][2] ^= w[i + 2] & 0xff; \
    s[1][2] ^= (w[i + 2] >> 8) & 0xff; \
    s[2][2] ^= (w[i + 2] >> 16) & 0xff; \
    s[3][2] ^= (w[i + 2] >> 24) & 0xff; \
    s[0][3] ^= w[i + 3] & 0xff; \
    s[1][3] ^= (w[i + 3] >> 8) & 0xff; \
    s[2][3] ^= (w[i + 3] >> 16) & 0xff; \
    s[3][3] ^= (w[i + 3] >> 24) & 0xff

#define ARRAY_TO_STATE(s, a) \
    s[0][0] = a[0]; s[0][1] = a[4]; s[0][2] = a[8]; s[0][3] = a[12]; \
    s[1][0] = a[1]; s[1][1] = a[5]; s[1][2] = a[9]; s[1][3] = a[13]; \
    s[2][0] = a[2]; s[2][1] = a[6]; s[2][2] = a[10]; s[2][3] = a[14]; \
    s[3][0] = a[3]; s[3][1] = a[7]; s[3][2] = a[11]; s[3][3] = a[15]

#define STATE_TO_ARRAY(s, a) \
    a[0] = s[0][0]; a[4] = s[0][1]; a[8] = s[0][2]; a[12] = s[0][3]; \
    a[1] = s[1][0]; a[5] = s[1][1]; a[9] = s[1][2]; a[13] = s[1][3]; \
    a[2] = s[2][0]; a[6] = s[2][1]; a[10] = s[2][2]; a[14] = s[2][3]; \
    a[3] = s[3][0]; a[7] = s[3][1]; a[11] = s[3][2]; a[15] = s[3][3]


static const uint8_t sbox[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = 
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* --------------------------------------------------------------------------------------------- */
/* Performs AES key expansion.                                                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESKeyExpansion(uint32_t *w, size_t wSize, const uint8_t *key, size_t keyLen,
                                uint8_t nr, uint8_t nk)
{
    uint32_t i, t;
    uint8_t rcon = 1;

    SSF_ASSERT(w != NULL);
    SSF_ASSERT(key != NULL);

    SSF_ASSERT((uint8_t)wSize == (4 * (nr + 1)));
    SSF_ASSERT(keyLen == (4 * nk));

    SSF_ASSERT(((nr == 10) && (nk == 4)) ||
               ((nr == 12) && (nk == 6)) ||
               ((nr == 14) && (nk == 8)));

    for (i = 0; i < nk; i++)
    {
        t = 4 * i;
        w[i] = (key[t]) ^ (key[t + 1] << 8) ^ (key[t + 2] << 16) ^ (key[t + 3] << 24);
    }

    for (i = nk; i < wSize; i++)
    {
        t = w[i - 1];
        if ((i % nk) == 0)
        {
            t = ((t >> 8) | ((t << (32 - 8)) & 0xffffffff));
            t = SBOX_WORD(t);
            t ^= rcon;
            rcon = FGFM2(rcon);
        } else if ((nk > 6) && ((i % nk) == 4))
        {
            t = SBOX_WORD(t);
        }
        w[i] = w[i - nk] ^ t;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Performs AES block encryption.                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFAESBlockEncrypt(const uint8_t *pt, size_t ptLen, uint8_t *ct, size_t ctSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk)
{
    uint32_t w[60];
    uint8_t t[5];
    uint8_t s[4][4];
    uint8_t i;

    size_t wSize = (nr + 1) * 4;

    SSF_ASSERT(pt != NULL);
    SSF_ASSERT(ct != NULL);
    SSF_ASSERT(key != NULL);

    SSF_ASSERT(ptLen == 16);
    SSF_ASSERT(ctSize == 16);
    SSF_ASSERT(keyLen == (4 * nk));

    SSF_ASSERT(((nr == 10) && (nk == 4)) ||
               ((nr == 12) && (nk == 6)) ||
               ((nr == 14) && (nk == 8)));

    ARRAY_TO_STATE(s, pt);
    _SSFAESKeyExpansion(w, wSize, key, keyLen, nr, nk);
    ADD_KEY(s, w, 0);

    for (i = 1; i < nr; i++)
    {
        SBOX_STATE(s);
        SHIFT_ROWS(s, t[0]);
        MIX_COLUMNS(s, t);
        ADD_KEY(s, w, i * 4);
    }

    SBOX_STATE(s);
    SHIFT_ROWS(s, t[0]);
    ADD_KEY(s, w, nr * 4);

    STATE_TO_ARRAY(s, ct);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs AES block decryption.                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFAESBlockDecrypt(const uint8_t *ct, size_t ctLen, uint8_t *pt, size_t ptSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk)
{
    uint32_t w[60];
    uint8_t t[5];
    uint8_t s[4][4];
    uint8_t i;

    size_t wSize = (nr + 1) * 4;

    SSF_ASSERT(ct != NULL);
    SSF_ASSERT(pt != NULL);
    SSF_ASSERT(key != NULL);

    SSF_ASSERT(ctLen == 16);
    SSF_ASSERT(ptSize == 16);
    SSF_ASSERT(keyLen == (4 * nk));

    SSF_ASSERT(((nr == 10) && (nk == 4)) ||
               ((nr == 12) && (nk == 6)) ||
               ((nr == 14) && (nk == 8)));

    ARRAY_TO_STATE(s, ct);
    _SSFAESKeyExpansion(w, wSize, key, keyLen, nr, nk);
    ADD_KEY(s, w, nr * 4);

    for (i = nr - 1; i > 0; i--)
    {
        INV_SHIFT_ROWS(s, t[0]);
        INV_SBOX_STATE(s);
        ADD_KEY(s, w, i * 4);
        INV_MIX_COLUMNS(s, t);
    }

    INV_SHIFT_ROWS(s, t[0]);
    INV_SBOX_STATE(s);
    ADD_KEY(s, w, 0);

    STATE_TO_ARRAY(s, pt);
}

