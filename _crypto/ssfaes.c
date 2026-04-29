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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfaes.h"
#include "ssfusexport.h"

/* State is four LE-packed u32 columns: c = row0 | (row1<<8) | (row2<<16) | (row3<<24). */
#define FGFM2(x) ((x<<1) ^ (0x1b & -(x>>7)))

#define ROTR8(x)  (((x) >> 8)  | ((x) << 24))
#define ROTR16(x) (((x) >> 16) | ((x) << 16))
#define ROTR24(x) (((x) >> 24) | ((x) << 8))

/* Packed xtime: multiply each byte of x by 2 in GF(2^8) with poly 0x1B. */
#define XTIME32(x) ((((x) << 1) & 0xFEFEFEFEu) ^ ((((x) >> 7) & 0x01010101u) * 0x1Bu))

/* Explicit shift-pack so packing matches the LE state convention on big-endian hosts too;
   gcc/clang collapse this to a single load (+bswap on BE) at -O1+. */
#define ARRAY_TO_STATE(s, a) do { \
    (s)[0] =  (uint32_t)(a)[ 0]        | ((uint32_t)(a)[ 1] <<  8) | \
             ((uint32_t)(a)[ 2] << 16) | ((uint32_t)(a)[ 3] << 24); \
    (s)[1] =  (uint32_t)(a)[ 4]        | ((uint32_t)(a)[ 5] <<  8) | \
             ((uint32_t)(a)[ 6] << 16) | ((uint32_t)(a)[ 7] << 24); \
    (s)[2] =  (uint32_t)(a)[ 8]        | ((uint32_t)(a)[ 9] <<  8) | \
             ((uint32_t)(a)[10] << 16) | ((uint32_t)(a)[11] << 24); \
    (s)[3] =  (uint32_t)(a)[12]        | ((uint32_t)(a)[13] <<  8) | \
             ((uint32_t)(a)[14] << 16) | ((uint32_t)(a)[15] << 24); \
} while (0)

#define STATE_TO_ARRAY(s, a) do { \
    (a)[ 0] = (uint8_t) (s)[0];        (a)[ 1] = (uint8_t)((s)[0] >>  8); \
    (a)[ 2] = (uint8_t)((s)[0] >> 16); (a)[ 3] = (uint8_t)((s)[0] >> 24); \
    (a)[ 4] = (uint8_t) (s)[1];        (a)[ 5] = (uint8_t)((s)[1] >>  8); \
    (a)[ 6] = (uint8_t)((s)[1] >> 16); (a)[ 7] = (uint8_t)((s)[1] >> 24); \
    (a)[ 8] = (uint8_t) (s)[2];        (a)[ 9] = (uint8_t)((s)[2] >>  8); \
    (a)[10] = (uint8_t)((s)[2] >> 16); (a)[11] = (uint8_t)((s)[2] >> 24); \
    (a)[12] = (uint8_t) (s)[3];        (a)[13] = (uint8_t)((s)[3] >>  8); \
    (a)[14] = (uint8_t)((s)[3] >> 16); (a)[15] = (uint8_t)((s)[3] >> 24); \
} while (0)

#define ADD_KEY(s, w, i) do { \
    (s)[0] ^= (w)[(i) + 0]; \
    (s)[1] ^= (w)[(i) + 1]; \
    (s)[2] ^= (w)[(i) + 2]; \
    (s)[3] ^= (w)[(i) + 3]; \
} while (0)

/* SubBytes + ShiftRows fused: byte at row r col c gathered from col (c+r) mod 4. */
#define SBOX_SHIFT_ROWS(s, b) do { \
    uint32_t _c0 = (s)[0], _c1 = (s)[1], _c2 = (s)[2], _c3 = (s)[3]; \
    (s)[0] = ((uint32_t)(b)[ _c0        & 0xFFu])        | \
             ((uint32_t)(b)[(_c1 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c2 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c3 >> 24) & 0xFFu] << 24); \
    (s)[1] = ((uint32_t)(b)[ _c1        & 0xFFu])        | \
             ((uint32_t)(b)[(_c2 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c3 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c0 >> 24) & 0xFFu] << 24); \
    (s)[2] = ((uint32_t)(b)[ _c2        & 0xFFu])        | \
             ((uint32_t)(b)[(_c3 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c0 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c1 >> 24) & 0xFFu] << 24); \
    (s)[3] = ((uint32_t)(b)[ _c3        & 0xFFu])        | \
             ((uint32_t)(b)[(_c0 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c1 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c2 >> 24) & 0xFFu] << 24); \
} while (0)

/* InvSubBytes + InvShiftRows fused: gather from col (c-r) mod 4 (gather pattern reverses). */
#define INV_SBOX_SHIFT_ROWS(s, b) do { \
    uint32_t _c0 = (s)[0], _c1 = (s)[1], _c2 = (s)[2], _c3 = (s)[3]; \
    (s)[0] = ((uint32_t)(b)[ _c0        & 0xFFu])        | \
             ((uint32_t)(b)[(_c3 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c2 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c1 >> 24) & 0xFFu] << 24); \
    (s)[1] = ((uint32_t)(b)[ _c1        & 0xFFu])        | \
             ((uint32_t)(b)[(_c0 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c3 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c2 >> 24) & 0xFFu] << 24); \
    (s)[2] = ((uint32_t)(b)[ _c2        & 0xFFu])        | \
             ((uint32_t)(b)[(_c1 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c0 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c3 >> 24) & 0xFFu] << 24); \
    (s)[3] = ((uint32_t)(b)[ _c3        & 0xFFu])        | \
             ((uint32_t)(b)[(_c2 >>  8) & 0xFFu] <<  8)  | \
             ((uint32_t)(b)[(_c1 >> 16) & 0xFFu] << 16)  | \
             ((uint32_t)(b)[(_c0 >> 24) & 0xFFu] << 24); \
} while (0)

#define SBOX_STATE(s)     SBOX_SHIFT_ROWS((s), sbox)
#define INV_SBOX_STATE(s) INV_SBOX_SHIFT_ROWS((s), inv_sbox)

/* Word-form MixColumns: 2 rotates + 3 XORs + 1 packed xtime per column. */
#define MIX_COL_WORD(c) do { \
    uint32_t _E = (c) ^ ROTR8(c); \
    uint32_t _T = _E ^ ROTR16(_E); \
    (c) = (c) ^ _T ^ XTIME32(_E); \
} while (0)

#define MIX_COLUMNS(s) do { \
    MIX_COL_WORD((s)[0]); MIX_COL_WORD((s)[1]); \
    MIX_COL_WORD((s)[2]); MIX_COL_WORD((s)[3]); \
} while (0)

/* Inverse MixColumns via Gladman's preprocess-then-MixColumns identity. */
#define INV_MIX_PRE(c) do { \
    uint32_t _e = (c) ^ ROTR16(c); \
    (c) ^= XTIME32(XTIME32(_e)); \
} while (0)

#define INV_MIX_COLUMNS(s) do { \
    INV_MIX_PRE((s)[0]); INV_MIX_PRE((s)[1]); \
    INV_MIX_PRE((s)[2]); INV_MIX_PRE((s)[3]); \
    MIX_COLUMNS(s); \
} while (0)

/* Used by key expansion: byte-wise SBOX over a u32 (no row shift). */
#define SBOX_WORD(x) ((uint32_t)sbox[(x) & 0xFFu] \
    | ((uint32_t)sbox[((x) >> 8)  & 0xFFu] << 8) \
    | ((uint32_t)sbox[((x) >> 16) & 0xFFu] << 16) \
    | ((uint32_t)sbox[((x) >> 24) & 0xFFu] << 24))


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

    SSF_REQUIRE(w != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(wSize == ((((size_t) nr) + 1) << 2));
    SSF_REQUIRE(keyLen == (((size_t) nk) << 2));
    SSF_REQUIRE(((nr == 10) && (nk == 4)) || ((nr == 12) && (nk == 6)) ||
                ((nr == 14) && (nk == 8)));

    for (i = 0; i < nk; i++)
    {
        t = i << 2;
        w[i] = ((uint32_t)key[t])              ^ ((uint32_t)key[t + 1] <<  8) ^
               ((uint32_t)key[t + 2] << 16)    ^ ((uint32_t)key[t + 3] << 24);
    }

    for (i = nk; i < wSize; i++)
    {
        t = w[i - 1];
        /* Is this word at the start of a new Nk-word group? */
        if ((i % nk) == 0)
        {
            /* Yes, apply the round-key transform: RotWord, SubWord, then XOR Rcon. */
            t = ((t >> 8) | ((t << 24) & 0xffffffff));
            t = SBOX_WORD(t);
            t ^= rcon;
            rcon = FGFM2(rcon);
        }
        /* No, but for AES-256 only, is this the mid-group SubWord position? */
        else if ((nk > 6) && ((i % nk) == 4))
        {
            /* Yes, apply SubWord (no rotate, no Rcon). */
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
    uint32_t s[4];
    uint8_t i;

    size_t wSize = (((size_t) nr) + 1) << 2;

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(ct != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(ptLen == SSF_AES_BLOCK_SIZE);
    SSF_REQUIRE(ctSize == SSF_AES_BLOCK_SIZE);
    SSF_REQUIRE(keyLen == (((size_t) nk) << 2));
    SSF_REQUIRE(((nr == 10) && (nk == 4)) || ((nr == 12) && (nk == 6)) ||
                ((nr == 14) && (nk == 8)));

    ARRAY_TO_STATE(s, pt);
    _SSFAESKeyExpansion(w, wSize, key, keyLen, nr, nk);
    ADD_KEY(s, w, 0);

    for (i = 1; i < nr; i++)
    {
        SBOX_STATE(s);
        MIX_COLUMNS(s);
        ADD_KEY(s, w, (i << 2));
    }

    SBOX_STATE(s);
    ADD_KEY(s, w, (nr << 2));

    STATE_TO_ARRAY(s, ct);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs AES block decryption.                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFAESBlockDecrypt(const uint8_t *ct, size_t ctLen, uint8_t *pt, size_t ptSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk)
{
    uint32_t w[60];
    uint32_t s[4];
    uint8_t i;

    size_t wSize = (((size_t) nr) + 1) << 2;

    SSF_REQUIRE(ct != NULL);
    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(ctLen == SSF_AES_BLOCK_SIZE);
    SSF_REQUIRE(ptSize == SSF_AES_BLOCK_SIZE);
    SSF_REQUIRE(keyLen == (((size_t) nk) << 2));
    SSF_REQUIRE(((nr == 10) && (nk == 4)) || ((nr == 12) && (nk == 6)) ||
                ((nr == 14) && (nk == 8)));

    ARRAY_TO_STATE(s, ct);
    _SSFAESKeyExpansion(w, wSize, key, keyLen, nr, nk);
    ADD_KEY(s, w, (nr << 2));

    for (i = nr - 1; i > 0; i--)
    {
        INV_SBOX_STATE(s);
        ADD_KEY(s, w, (i << 2));
        INV_MIX_COLUMNS(s);
    }

    INV_SBOX_STATE(s);
    ADD_KEY(s, w, 0);

    STATE_TO_ARRAY(s, pt);
}

