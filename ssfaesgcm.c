/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaesgcm.c                                                                                   */
/* Provides AES-GCM authenticated encryption interface.                                          */
/*                                                                                               */
/* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf                                      */
/* https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf                 */
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
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfaes.h"

/* --------------------------------------------------------------------------------------------- */
/* Local Helper Functions and Macros                                                             */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline void PUT_32_LE(uint8_t *buf, uint32_t val)
{
    buf[0] = (val >> 24) & 0xff;
    buf[1] = (val >> 16) & 0xff;
    buf[2] = (val >> 8) & 0xff;
    buf[3] = val & 0xff;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline void PUT_64_LE(uint8_t *buf, uint64_t val)
{
    buf[0] = (val >> 56) & 0xff;
    buf[1] = (val >> 48) & 0xff;
    buf[2] = (val >> 40) & 0xff;
    buf[3] = (val >> 32) & 0xff;
    buf[4] = (val >> 24) & 0xff;
    buf[5] = (val >> 16) & 0xff;
    buf[6] = (val >> 8) & 0xff;
    buf[7] = val & 0xff;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline uint32_t GET_32_BE(const uint8_t *buf)
{
    uint32_t res;
    res = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
    return res;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline uint32_t GET_32_LE(const uint8_t *buf)
{
    uint32_t res;
    res = buf[3] | (buf[2] << 8) | (buf[1] << 16) | (buf[0] << 24);
    return res;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
#define BLOCK_XOR(x, y) \
    (x)[0] ^= (y)[0]; (x)[1] ^= (y)[1]; (x)[2] ^= (y)[2]; (x)[3] ^= (y)[3]; \
    (x)[4] ^= (y)[4]; (x)[5] ^= (y)[5]; (x)[6] ^= (y)[6]; (x)[7] ^= (y)[7]; \
    (x)[8] ^= (y)[8]; (x)[9] ^= (y)[9]; (x)[10] ^= (y)[10]; (x)[11] ^= (y)[11]; \
    (x)[12] ^= (y)[12]; (x)[13] ^= (y)[13]; (x)[14] ^= (y)[14]; (x)[15] ^= (y)[15]

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline void _SSFAESGCMBlockInc32(uint8_t *in)
{
    uint32_t x;

    x = GET_32_LE(in + 12);
    x += 1;
    PUT_32_LE(in + 12, x);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline void _SSFAESGCMCarryless32Mult(uint32_t a, uint32_t b, uint32_t *l, uint32_t *r)
{
    uint32_t x[4];
    uint32_t y[4];
    uint64_t z[4];
    uint64_t res;

    x[0] = a & 0x11111111;
    x[1] = a & 0x22222222;
    x[2] = a & 0x44444444;
    x[3] = a & 0x88888888;

    y[0] = b & 0x11111111;
    y[1] = b & 0x22222222;
    y[2] = b & 0x44444444;
    y[3] = b & 0x88888888;

    z[0] = ((uint64_t)x[0] * (uint64_t)y[0]) ^ ((uint64_t)x[1] * (uint64_t)y[3]) 
         ^ ((uint64_t)x[2] * (uint64_t)y[2]) ^ ((uint64_t)x[3] * (uint64_t)y[1]);
    z[1] = ((uint64_t)x[0] * (uint64_t)y[1]) ^ ((uint64_t)x[1] * (uint64_t)y[0]) 
         ^ ((uint64_t)x[2] * (uint64_t)y[3]) ^ ((uint64_t)x[3] * (uint64_t)y[2]);
    z[2] = ((uint64_t)x[0] * (uint64_t)y[2]) ^ ((uint64_t)x[1] * (uint64_t)y[1]) 
         ^ ((uint64_t)x[2] * (uint64_t)y[0]) ^ ((uint64_t)x[3] * (uint64_t)y[3]);
    z[3] = ((uint64_t)x[0] * (uint64_t)y[3]) ^ ((uint64_t)x[1] * (uint64_t)y[2]) 
         ^ ((uint64_t)x[2] * (uint64_t)y[1]) ^ ((uint64_t)x[3] * (uint64_t)y[0]);

    z[0] &= 0x1111111111111111;
    z[1] &= 0x2222222222222222;
    z[2] &= 0x4444444444444444;
    z[3] &= 0x8888888888888888;

    res = z[0] ^ z[1] ^ z[2] ^ z[3];

    *l = (uint32_t)res;
    *r = (uint32_t)(res >> 32);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline void _SSFAESGCMCarrylessReduce(uint32_t *in)
{
    uint64_t x0, x1, x2, x3;
    uint64_t a, b, c, d;
    uint64_t t[2], e[2], f[2], g[2];
    uint64_t r[2];

    x0 = ((uint64_t)in[6] << 32) ^ ((uint64_t)in[7]);
    x1 = ((uint64_t)in[4] << 32) ^ ((uint64_t)in[5]);
    x2 = ((uint64_t)in[2] << 32) ^ ((uint64_t)in[3]);
    x3 = ((uint64_t)in[0] << 32) ^ ((uint64_t)in[1]);

    a = x3 >> 63;
    b = x3 >> 62;
    c = x3 >> 57;
    d = x2 ^ a ^ b ^ c;

    t[0] = d;
    t[1] = x3;
    e[0] = (t[0] << 1);
    e[1] = (t[1] << 1) ^ (t[0] >> 63);
    f[0] = (t[0] << 2);
    f[1] = (t[1] << 2) ^ (t[0] >> 62);
    g[0] = (t[0] << 7);
    g[1] = (t[1] << 7) ^ (t[0] >> 57);

    r[0] = d ^ e[0] ^ f[0] ^ g[0] ^ x0;
    r[1] = x3 ^ e[1] ^ f[1] ^ g[1] ^ x1;

    memcpy(in, r, 16);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline uint32_t _SSFAESGCMReverseByte(uint8_t x)
{
    x = (x & 0xf0) >> 4 | (x & 0x0f) << 4;
    x = (x & 0xcc) >> 2 | (x & 0x33) << 2;
    x = (x & 0xaa) >> 1 | (x & 0x55) << 1;
    return x;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static inline uint32_t _SSFAESGCMReverseBytes(uint32_t x)
{
    return (_SSFAESGCMReverseByte(x & 0xff) 
           ^ (_SSFAESGCMReverseByte((x >> 8) & 0xff) << 8)
           ^ (_SSFAESGCMReverseByte((x >> 16) & 0xff) << 16) 
           ^ (_SSFAESGCMReverseByte((x >> 24) & 0xff) << 24));
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESGCMBlockMult(uint8_t *in, size_t inSize, const uint8_t *con, size_t conLen)
{
    uint32_t ac64[2];
    uint32_t bd64[2];
    uint32_t ab_cd64[2];

    uint32_t ac128[4];
    uint32_t bd128[4];
    uint32_t ab_cd128[4];

    uint32_t x[4];
    uint32_t y[4];

    uint32_t res[8];

    SSF_ASSERT(in != NULL);
    SSF_ASSERT(con != NULL);

    SSF_ASSERT(inSize == 16);
    SSF_ASSERT(conLen == 16);

    x[3] = GET_32_BE(in);
    x[2] = GET_32_BE(&in[4]);
    x[1] = GET_32_BE(&in[8]);
    x[0] = GET_32_BE(&in[12]);

    x[0] = _SSFAESGCMReverseBytes(x[0]);
    x[1] = _SSFAESGCMReverseBytes(x[1]);
    x[2] = _SSFAESGCMReverseBytes(x[2]);
    x[3] = _SSFAESGCMReverseBytes(x[3]);

    y[3] = GET_32_BE(con);
    y[2] = GET_32_BE(&con[4]);
    y[1] = GET_32_BE(&con[8]);
    y[0] = GET_32_BE(&con[12]);

    y[0] = _SSFAESGCMReverseBytes(y[0]);
    y[1] = _SSFAESGCMReverseBytes(y[1]);
    y[2] = _SSFAESGCMReverseBytes(y[2]);
    y[3] = _SSFAESGCMReverseBytes(y[3]);

    _SSFAESGCMCarryless32Mult(x[0], y[0], &ac64[1], &ac64[0]);
    _SSFAESGCMCarryless32Mult(x[1], y[1], &bd64[1], &bd64[0]);
    _SSFAESGCMCarryless32Mult((x[0] ^ x[1]), (y[0] ^ y[1]), &ab_cd64[1], &ab_cd64[0]);
    ab_cd64[0] ^= ac64[0] ^ bd64[0];
    ab_cd64[1] ^= ac64[1] ^ bd64[1];

    ac128[0] = ac64[0];
    ac128[1] = ac64[1] ^ ab_cd64[0];
    ac128[2] = ab_cd64[1] ^ bd64[0];
    ac128[3] = bd64[1];

    _SSFAESGCMCarryless32Mult(x[2], y[2], &ac64[1], &ac64[0]);
    _SSFAESGCMCarryless32Mult(x[3], y[3], &bd64[1], &bd64[0]);
    _SSFAESGCMCarryless32Mult((x[2] ^ x[3]), (y[2] ^ y[3]), &ab_cd64[1], &ab_cd64[0]);
    ab_cd64[0] ^= ac64[0] ^ bd64[0];
    ab_cd64[1] ^= ac64[1] ^ bd64[1];

    bd128[0] = ac64[0];
    bd128[1] = ac64[1] ^ ab_cd64[0];
    bd128[2] = ab_cd64[1] ^ bd64[0];
    bd128[3] = bd64[1];

    _SSFAESGCMCarryless32Mult((x[0] ^ x[2]), (y[0] ^ y[2]), &ac64[1], &ac64[0]);
    _SSFAESGCMCarryless32Mult((x[1] ^ x[3]), (y[1] ^ y[3]), &bd64[1], &bd64[0]);
    _SSFAESGCMCarryless32Mult((x[0] ^ x[1] ^ x[2] ^ x[3]), 
                              (y[0] ^ y[1] ^ y[2] ^ y[3]), &ab_cd64[1], &ab_cd64[0]);
    ab_cd64[0] ^= ac64[0] ^ bd64[0];
    ab_cd64[1] ^= ac64[1] ^ bd64[1];

    ab_cd128[0] = ac64[0];
    ab_cd128[1] = ac64[1] ^ ab_cd64[0];
    ab_cd128[2] = ab_cd64[1] ^ bd64[0];
    ab_cd128[3] = bd64[1];

    ab_cd128[0] ^= ac128[0] ^ bd128[0];
    ab_cd128[1] ^= ac128[1] ^ bd128[1];
    ab_cd128[2] ^= ac128[2] ^ bd128[2];
    ab_cd128[3] ^= ac128[3] ^ bd128[3];

    res[0] = ac128[0];
    res[1] = ac128[1];
    res[2] = ac128[2] ^ ab_cd128[0];
    res[3] = ac128[3] ^ ab_cd128[1];
    res[4] = ab_cd128[2] ^ bd128[0];
    res[5] = ab_cd128[3] ^ bd128[1];
    res[6] = bd128[2];
    res[7] = bd128[3];

    _SSFAESGCMCarrylessReduce(res);

    res[0] = _SSFAESGCMReverseBytes(res[0]);
    res[1] = _SSFAESGCMReverseBytes(res[1]);
    res[2] = _SSFAESGCMReverseBytes(res[2]);
    res[3] = _SSFAESGCMReverseBytes(res[3]);

    memcpy(in, res, 16);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESGCMGHASH(const uint8_t *in, size_t inLen, const uint8_t *h, size_t hLen,
                            uint8_t *out, size_t outSize)
{
    uint8_t buf[16] = {0};
    uint32_t i, pos, iters;

    if ((in == NULL) || (out == NULL) || (inLen == 0)) { return; }

    SSF_ASSERT(in != NULL);
    SSF_ASSERT(h != NULL);
    SSF_ASSERT(out != NULL);

    SSF_ASSERT(inLen > 0);
    SSF_ASSERT(hLen == 16);
    SSF_ASSERT(outSize == 16);

    memset(buf, 0, 16);

    pos = 0;
    iters = (uint32_t)inLen / 16;

    for (i = 0; i < iters; i++)
    {
        BLOCK_XOR(out, &in[pos]);
        _SSFAESGCMBlockMult(out, outSize, h, hLen);
        pos += 16;
    }

    if (pos < inLen)
    {
        memset(buf, 0, sizeof(buf));
        memcpy(buf, &in[pos], inLen - pos);
        BLOCK_XOR(out, buf);
        _SSFAESGCMBlockMult(out, outSize, h, hLen);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESGCMGCTR(const uint8_t *in, size_t inLen, const uint8_t *key, size_t keyLen,
                           const uint8_t *icb, size_t icbLen, uint8_t *out, size_t outSize)
{
    uint8_t cb[16];
    uint8_t buf[16];
    uint32_t i, n;

    if ((in == NULL) || (out == NULL)) { return; }

    SSF_ASSERT(in != NULL);
    SSF_ASSERT(key != NULL);
    SSF_ASSERT(icb != NULL);
    SSF_ASSERT(out != NULL);

    SSF_ASSERT((keyLen == 16) || (keyLen == 24) || (keyLen == 32));
    SSF_ASSERT(icbLen == 16);
    SSF_ASSERT(inLen == outSize);

    memcpy(cb, icb, sizeof(cb));
    memcpy(out, in, outSize);

    n = outSize & 0xfffffff0;
    for (i = 0; i < n; i += 16)
    {
        SSFAESXXXBlockEncrypt(cb, sizeof(cb), buf, sizeof(buf), key, keyLen);
        BLOCK_XOR(&out[i], buf);
        _SSFAESGCMBlockInc32(cb);
    }

    if (i < outSize)
    {
        SSFAESXXXBlockEncrypt(cb, sizeof(cb), buf, sizeof(buf), key, keyLen);

        for (i = 0; i < (outSize & 0xf); i++)
        {
            out[n + i] ^= buf[i];
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Performs AES-GCM encryption.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFAESGCMEncrypt(const uint8_t *pt, size_t ptLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *auth, size_t authLen, const uint8_t *key, size_t keyLen,
                      uint8_t *tag, size_t tagSize, uint8_t *ct, size_t ctSize)
{
    uint8_t h[16] = {0};
    uint8_t s[16] = {0};
    uint8_t j0[16] = {0};
    uint8_t j1[16] = {0};
    uint8_t buf[16] = {0};

    uint32_t t;

    SSF_ASSERT(iv != NULL);
    SSF_ASSERT(key != NULL);
    SSF_ASSERT(tag != NULL);

    SSF_ASSERT(ptLen == ctSize);
    SSF_ASSERT(ivLen > 0);
    SSF_ASSERT((keyLen == 16) || (keyLen == 24) || (keyLen == 32));
    SSF_ASSERT(((tagSize >= 12) && (tagSize <= 16)) || (tagSize == 8) || (tagSize == 4));

    SSFAESXXXBlockEncrypt(h, sizeof(h), h, sizeof(h), key, keyLen);

    if (ivLen == 12)
    {
        memcpy(j0, iv, ivLen);
        PUT_32_LE(&j0[12], 1);
    }
    else
    {
        _SSFAESGCMGHASH(iv, ivLen, h, sizeof(h), j0, sizeof(j0));
        t = ((uint32_t)ivLen << 3);
        PUT_64_LE(&buf[8], t);
        _SSFAESGCMGHASH(buf, sizeof(buf), h, sizeof(h), j0, sizeof(j0));
    }

    memcpy(j1, j0, sizeof(j1));
    _SSFAESGCMBlockInc32(j1);

    _SSFAESGCMGCTR(pt, ptLen, key, keyLen, j1, sizeof(j1), ct, ctSize);

    t = ((uint32_t)authLen << 3);
    PUT_64_LE(buf, t);
    t = ((uint32_t)ctSize << 3);
    PUT_64_LE(&buf[8], t);

    _SSFAESGCMGHASH(auth, authLen, h, sizeof(h), s, sizeof(s));
    _SSFAESGCMGHASH(ct, ctSize, h, sizeof(h), s, sizeof(s));
    _SSFAESGCMGHASH(buf, sizeof(buf), h, sizeof(h), s, sizeof(s));

    _SSFAESGCMGCTR(s, sizeof(s), key, keyLen, j0, sizeof(j0), s, sizeof(s));

    memcpy(tag, s, sizeof(s));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if AES-GCM decryption/authentication successful else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFAESGCMDecrypt(const uint8_t* ct, size_t ctLen, const uint8_t* iv, size_t ivLen,
                      const uint8_t* auth, size_t authLen, const uint8_t* key, size_t keyLen,
                      const uint8_t* tag, size_t tagLen, uint8_t* pt, size_t ptSize)
{
    uint8_t h[16] = { 0 };
    uint8_t s[16] = { 0 };
    uint8_t j0[16] = { 0 };
    uint8_t j1[16] = { 0 };
    uint8_t buf[16] = { 0 };

    uint32_t t;

    SSF_ASSERT(iv != NULL);
    SSF_ASSERT(key != NULL);
    SSF_ASSERT(tag != NULL);

    SSF_ASSERT(ctLen == ptSize);
    SSF_ASSERT(ivLen > 0);
    SSF_ASSERT((keyLen == 16) || (keyLen == 24) || (keyLen == 32));
    SSF_ASSERT(((tagLen >= 12) && (tagLen <= 16)) || (tagLen == 8) || (tagLen == 4));

    SSFAESXXXBlockEncrypt(h, sizeof(h), h, sizeof(h), key, keyLen);

    if (ivLen == 12)
    {
        memcpy(j0, iv, ivLen);
        PUT_32_LE(&j0[12], 1);
    }
    else
    {
        _SSFAESGCMGHASH(iv, ivLen, h, sizeof(h), j0, sizeof(j0));
        t = ((uint32_t)ivLen << 3);
        PUT_64_LE(&buf[8], t);
        _SSFAESGCMGHASH(buf, sizeof(buf), h, sizeof(h), j0, sizeof(j0));
    }

    memcpy(j1, j0, sizeof(j1));
    _SSFAESGCMBlockInc32(j1);

    _SSFAESGCMGCTR(ct, ctLen, key, keyLen, j1, sizeof(j1), pt, ptSize);

    t = ((uint32_t)authLen << 3);
    PUT_64_LE(buf, t);
    t = ((uint32_t)ctLen << 3);
    PUT_64_LE(&buf[8], t);

    _SSFAESGCMGHASH(auth, authLen, h, sizeof(h), s, sizeof(s));
    _SSFAESGCMGHASH(ct, ctLen, h, sizeof(h), s, sizeof(s));
    _SSFAESGCMGHASH(buf, sizeof(buf), h, sizeof(h), s, sizeof(s));

    _SSFAESGCMGCTR(s, sizeof(s), key, keyLen, j0, sizeof(j0), s, sizeof(s));

    return memcmp(s, tag, tagLen) != 0;
}

