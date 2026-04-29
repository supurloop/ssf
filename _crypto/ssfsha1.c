/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsha1.c                                                                                     */
/* Provides SHA-1 (RFC 3174) hash implementation.                                                */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#include "ssfsha1.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* SHA-1 constants (RFC 3174 section 5)                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_SHA1_K0 (0x5A827999ul)
#define SSF_SHA1_K1 (0x6ED9EBA1ul)
#define SSF_SHA1_K2 (0x8F1BBCDCul)
#define SSF_SHA1_K3 (0xCA62C1D6ul)

#define SSF_SHA1_H0 (0x67452301ul)
#define SSF_SHA1_H1 (0xEFCDAB89ul)
#define SSF_SHA1_H2 (0x98BADCFEul)
#define SSF_SHA1_H3 (0x10325476ul)
#define SSF_SHA1_H4 (0xC3D2E1F0ul)

/* --------------------------------------------------------------------------------------------- */
/* Processes a single 512-bit (64-byte) block.                                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSHA1ProcessBlock(SSFSHA1Context_t *ctx, const uint8_t block[SSF_SHA1_BLOCK_SIZE])
{
    uint32_t w[80];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t temp;
    uint32_t t;

    /* Step a: prepare the message schedule W[0..79] */
    for (t = 0; t < 16u; t++)
    {
        w[t] = SSF_GETU32BE(&block[t * 4u]);
    }
    for (t = 16; t < 80u; t++)
    {
        w[t] = SSF_ROTL32(w[t - 3u] ^ w[t - 8u] ^ w[t - 14u] ^ w[t - 16u], 1);
    }

    /* Step b: initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    /* Step c: 80 rounds */
    for (t = 0; t < 80u; t++)
    {
        uint32_t f;
        uint32_t k;

        if (t < 20u)
        {
            f = (b & c) | ((~b) & d);
            k = SSF_SHA1_K0;
        }
        else if (t < 40u)
        {
            f = b ^ c ^ d;
            k = SSF_SHA1_K1;
        }
        else if (t < 60u)
        {
            f = (b & c) | (b & d) | (c & d);
            k = SSF_SHA1_K2;
        }
        else
        {
            f = b ^ c ^ d;
            k = SSF_SHA1_K3;
        }

        temp = SSF_ROTL32(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = SSF_ROTL32(b, 30);
        b = a;
        a = temp;
    }

    /* Step d: update hash values */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes a SHA-1 context for incremental hashing.                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA1Begin(SSFSHA1Context_t *ctx)
{
    SSF_REQUIRE(ctx != NULL);

    ctx->state[0] = SSF_SHA1_H0;
    ctx->state[1] = SSF_SHA1_H1;
    ctx->state[2] = SSF_SHA1_H2;
    ctx->state[3] = SSF_SHA1_H3;
    ctx->state[4] = SSF_SHA1_H4;
    ctx->totalLen = 0;
    ctx->blockLen = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds data into the SHA-1 context.                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA1Update(SSFSHA1Context_t *ctx, const uint8_t *in, uint32_t inLen)
{
    uint32_t i;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE((in != NULL) || (inLen == 0));

    for (i = 0; i < inLen; i++)
    {
        ctx->block[ctx->blockLen] = in[i];
        ctx->blockLen++;
        ctx->totalLen++;

        if (ctx->blockLen == SSF_SHA1_BLOCK_SIZE)
        {
            _SSFSHA1ProcessBlock(ctx, ctx->block);
            ctx->blockLen = 0;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Finalizes the SHA-1 hash (FIPS 180-1 padding) and writes the 20-byte result.                  */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA1End(SSFSHA1Context_t *ctx, uint8_t out[SSF_SHA1_HASH_SIZE])
{
    uint64_t totalBits;
    uint32_t i;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(out != NULL);

    totalBits = ctx->totalLen * 8ull;

    /* Append the '1' bit (0x80 byte) */
    ctx->block[ctx->blockLen] = 0x80u;
    ctx->blockLen++;

    /* If there isn't room for the 8-byte length field, pad and process */
    if (ctx->blockLen > 56u)
    {
        while (ctx->blockLen < SSF_SHA1_BLOCK_SIZE)
        {
            ctx->block[ctx->blockLen] = 0x00u;
            ctx->blockLen++;
        }
        _SSFSHA1ProcessBlock(ctx, ctx->block);
        ctx->blockLen = 0;
    }

    /* Pad with zeros up to byte 56 */
    while (ctx->blockLen < 56u)
    {
        ctx->block[ctx->blockLen] = 0x00u;
        ctx->blockLen++;
    }

    /* Append the total length in bits as a 64-bit big-endian value */
    SSF_PUTU64BE(&ctx->block[56], totalBits);

    _SSFSHA1ProcessBlock(ctx, ctx->block);

    /* Write the hash output (big-endian) */
    for (i = 0; i < 5u; i++)
    {
        SSF_PUTU32BE(&out[i * 4u], ctx->state[i]);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Single-call SHA-1 hash.                                                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA1(const uint8_t *in, uint32_t inLen, uint8_t out[SSF_SHA1_HASH_SIZE])
{
    SSFSHA1Context_t ctx;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE((in != NULL) || (inLen == 0));

    SSFSHA1Begin(&ctx);
    SSFSHA1Update(&ctx, in, inLen);
    SSFSHA1End(&ctx, out);
}

