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
#include <stdint.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfpoly1305.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Poly1305 uses 130-bit arithmetic mod p = 2^130 - 5.                                          */
/* We use 5 limbs of 26 bits each (Donna variant). All intermediate products fit uint64_t.       */
/* --------------------------------------------------------------------------------------------- */

#define SSF_POLY1305_CONTEXT_MAGIC (0x504F4C59ul) /* 'POLY' — set by Begin, cleared by End. */

/* --------------------------------------------------------------------------------------------- */
/* Internal: h = h * r mod (2^130 - 5), using 5 × 26-bit limbs and precomputed r[1..4] * 5.      */
/* Shared between full-block (Update) and final-partial-block (End) paths.                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFPoly1305MulR(SSFPoly1305Context_t *ctx)
{
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    d0 = ((uint64_t)ctx->h0 * ctx->r0) + ((uint64_t)ctx->h1 * ctx->rr3) +
         ((uint64_t)ctx->h2 * ctx->rr2) + ((uint64_t)ctx->h3 * ctx->rr1) +
         ((uint64_t)ctx->h4 * ctx->rr0);
    d1 = ((uint64_t)ctx->h0 * ctx->r1) + ((uint64_t)ctx->h1 * ctx->r0) +
         ((uint64_t)ctx->h2 * ctx->rr3) + ((uint64_t)ctx->h3 * ctx->rr2) +
         ((uint64_t)ctx->h4 * ctx->rr1);
    d2 = ((uint64_t)ctx->h0 * ctx->r2) + ((uint64_t)ctx->h1 * ctx->r1) +
         ((uint64_t)ctx->h2 * ctx->r0) + ((uint64_t)ctx->h3 * ctx->rr3) +
         ((uint64_t)ctx->h4 * ctx->rr2);
    d3 = ((uint64_t)ctx->h0 * ctx->r3) + ((uint64_t)ctx->h1 * ctx->r2) +
         ((uint64_t)ctx->h2 * ctx->r1) + ((uint64_t)ctx->h3 * ctx->r0) +
         ((uint64_t)ctx->h4 * ctx->rr3);
    d4 = ((uint64_t)ctx->h0 * ctx->r4) + ((uint64_t)ctx->h1 * ctx->r3) +
         ((uint64_t)ctx->h2 * ctx->r2) + ((uint64_t)ctx->h3 * ctx->r1) +
         ((uint64_t)ctx->h4 * ctx->r0);

    /* Carry propagation */
    c = (uint32_t)(d0 >> 26); ctx->h0 = (uint32_t)d0 & 0x3FFFFFFu;
    d1 += c; c = (uint32_t)(d1 >> 26); ctx->h1 = (uint32_t)d1 & 0x3FFFFFFu;
    d2 += c; c = (uint32_t)(d2 >> 26); ctx->h2 = (uint32_t)d2 & 0x3FFFFFFu;
    d3 += c; c = (uint32_t)(d3 >> 26); ctx->h3 = (uint32_t)d3 & 0x3FFFFFFu;
    d4 += c; c = (uint32_t)(d4 >> 26); ctx->h4 = (uint32_t)d4 & 0x3FFFFFFu;
    ctx->h0 += c * 5u; c = ctx->h0 >> 26; ctx->h0 &= 0x3FFFFFFu;
    ctx->h1 += c;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: process one complete 16-byte block (adds implicit high bit 2^128 per RFC 7539 §2.5) */
/* --------------------------------------------------------------------------------------------- */
static void _SSFPoly1305ProcessFullBlock(SSFPoly1305Context_t *ctx, const uint8_t block[16])
{
    ctx->h0 += SSF_GETU32LE(&block[0])  & 0x3FFFFFFu;
    ctx->h1 += (SSF_GETU32LE(&block[3])  >> 2) & 0x3FFFFFFu;
    ctx->h2 += (SSF_GETU32LE(&block[6])  >> 4) & 0x3FFFFFFu;
    ctx->h3 += (SSF_GETU32LE(&block[9])  >> 6) & 0x3FFFFFFu;
    ctx->h4 += (SSF_GETU32LE(&block[12]) >> 8) | (1u << 24);
    _SSFPoly1305MulR(ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Incremental API: initialize context from a 32-byte one-time key.                              */
/* RFC 7539 §2.5: clamp the low half of the key as r, take the high half verbatim as s, and      */
/* precompute r[1..4] * 5 for the modular reduction inner loop. Accumulator starts at zero.       */
/* --------------------------------------------------------------------------------------------- */
void SSFPoly1305Begin(SSFPoly1305Context_t *ctx,
                      const uint8_t *key, size_t keyLen)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == 0u);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(keyLen == SSF_POLY1305_KEY_SIZE);

    /* Clamp r (RFC 7539 §2.5) */
    ctx->r0 = (SSF_GETU32LE(&key[0]))        & 0x3FFFFFFu;
    ctx->r1 = (SSF_GETU32LE(&key[3])  >> 2)  & 0x3FFFF03u;
    ctx->r2 = (SSF_GETU32LE(&key[6])  >> 4)  & 0x3FFC0FFu;
    ctx->r3 = (SSF_GETU32LE(&key[9])  >> 6)  & 0x3F03FFFu;
    ctx->r4 = (SSF_GETU32LE(&key[12]) >> 8)  & 0x00FFFFFu;

    /* s = key[16..31] as four little-endian 32-bit words */
    ctx->s0 = SSF_GETU32LE(&key[16]);
    ctx->s1 = SSF_GETU32LE(&key[20]);
    ctx->s2 = SSF_GETU32LE(&key[24]);
    ctx->s3 = SSF_GETU32LE(&key[28]);

    /* Precompute r[1..4] * 5 for the reduction-inner multiply */
    ctx->rr0 = ctx->r1 * 5u;
    ctx->rr1 = ctx->r2 * 5u;
    ctx->rr2 = ctx->r3 * 5u;
    ctx->rr3 = ctx->r4 * 5u;

    /* Accumulator = 0, partial-block buffer empty */
    ctx->h0 = ctx->h1 = ctx->h2 = ctx->h3 = ctx->h4 = 0u;
    ctx->bufLen = 0u;

    /* Mark the context valid last so any earlier assert leaves magic clear. */
    ctx->magic = SSF_POLY1305_CONTEXT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Incremental API: feed msgLen bytes. Drains any partial-block hold-back from a previous call   */
/* first, then processes complete 16-byte blocks directly from msg, then stashes any trailing    */
/* < 16-byte tail back into ctx->buf for the next Update or End. Produces bit-identical output   */
/* to a single Mac call over the concatenation of all Update inputs.                              */
/* --------------------------------------------------------------------------------------------- */
void SSFPoly1305Update(SSFPoly1305Context_t *ctx,
                       const uint8_t *msg, size_t msgLen)
{
    size_t pos = 0;
    size_t take;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_POLY1305_CONTEXT_MAGIC);
    SSF_REQUIRE((msg != NULL) || (msgLen == 0u));

    /* Drain the partial buffer first if it holds anything. */
    if ((ctx->bufLen > 0u) && (msgLen > 0u))
    {
        take = (size_t)(16u - ctx->bufLen);
        if (take > msgLen) take = msgLen;
        memcpy(&ctx->buf[ctx->bufLen], msg, take);
        ctx->bufLen = (uint8_t)(ctx->bufLen + take);
        pos += take;

        if (ctx->bufLen == 16u)
        {
            _SSFPoly1305ProcessFullBlock(ctx, ctx->buf);
            ctx->bufLen = 0u;
        }
    }

    /* Process full blocks directly from the caller's buffer. */
    while ((msgLen - pos) >= 16u)
    {
        _SSFPoly1305ProcessFullBlock(ctx, &msg[pos]);
        pos += 16u;
    }

    /* Stash the < 16-byte tail. */
    if (pos < msgLen)
    {
        take = msgLen - pos;
        memcpy(&ctx->buf[ctx->bufLen], &msg[pos], take);
        ctx->bufLen = (uint8_t)(ctx->bufLen + take);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Incremental API: finalize, emit the 16-byte tag, zeroise the context.                         */
/* Processes any remaining partial block with the RFC 7539 0x01 high-bit marker (no 2^128 bit),  */
/* runs the final reduction, selects h mod p, adds s, writes the LE tag, and memsets ctx to 0.   */
/* --------------------------------------------------------------------------------------------- */
void SSFPoly1305End(SSFPoly1305Context_t *ctx,
                    uint8_t *tag, size_t tagSize)
{
    uint32_t c;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t mask;
    uint64_t f;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_POLY1305_CONTEXT_MAGIC);
    SSF_REQUIRE(tag != NULL);
    SSF_REQUIRE(tagSize >= SSF_POLY1305_TAG_SIZE);

    /* Final partial block (if any): pad with 0x01 then zeros, then multiply by r. */
    if (ctx->bufLen > 0u)
    {
        uint8_t partial[16];

        memset(partial, 0, sizeof(partial));
        memcpy(partial, ctx->buf, ctx->bufLen);
        partial[ctx->bufLen] = 0x01u;

        ctx->h0 += SSF_GETU32LE(&partial[0])  & 0x3FFFFFFu;
        ctx->h1 += (SSF_GETU32LE(&partial[3])  >> 2) & 0x3FFFFFFu;
        ctx->h2 += (SSF_GETU32LE(&partial[6])  >> 4) & 0x3FFFFFFu;
        ctx->h3 += (SSF_GETU32LE(&partial[9])  >> 6) & 0x3FFFFFFu;
        ctx->h4 += (SSF_GETU32LE(&partial[12]) >> 8);  /* no 2^128 bit for partial */
        _SSFPoly1305MulR(ctx);
        ctx->bufLen = 0u;

        SSFCryptSecureZero(partial, sizeof(partial));
    }

    /* Fully carry h. */
    c = ctx->h1 >> 26; ctx->h1 &= 0x3FFFFFFu;
    ctx->h2 += c; c = ctx->h2 >> 26; ctx->h2 &= 0x3FFFFFFu;
    ctx->h3 += c; c = ctx->h3 >> 26; ctx->h3 &= 0x3FFFFFFu;
    ctx->h4 += c; c = ctx->h4 >> 26; ctx->h4 &= 0x3FFFFFFu;
    ctx->h0 += c * 5u; c = ctx->h0 >> 26; ctx->h0 &= 0x3FFFFFFu;
    ctx->h1 += c;

    /* h - p = h - (2^130 - 5). */
    g0 = ctx->h0 + 5u; c = g0 >> 26; g0 &= 0x3FFFFFFu;
    g1 = ctx->h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFFu;
    g2 = ctx->h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFFu;
    g3 = ctx->h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFFu;
    g4 = ctx->h4 + c - (1u << 26);

    /* Select h if h < p, else h - p. */
    mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    ctx->h0 = (ctx->h0 & mask) | g0;
    ctx->h1 = (ctx->h1 & mask) | g1;
    ctx->h2 = (ctx->h2 & mask) | g2;
    ctx->h3 = (ctx->h3 & mask) | g3;
    ctx->h4 = (ctx->h4 & mask) | g4;

    /* Assemble h into 4 × 32-bit LE words and add s, writing the tag as 16 bytes LE. */
    f = (uint64_t)(ctx->h0 | (ctx->h1 << 26)) + ctx->s0;
    tag[0]  = (uint8_t)f;       tag[1]  = (uint8_t)(f >> 8);
    tag[2]  = (uint8_t)(f >> 16); tag[3]  = (uint8_t)(f >> 24);
    f = (uint64_t)((ctx->h1 >> 6) | (ctx->h2 << 20)) + ctx->s1 + (f >> 32);
    tag[4]  = (uint8_t)f;       tag[5]  = (uint8_t)(f >> 8);
    tag[6]  = (uint8_t)(f >> 16); tag[7]  = (uint8_t)(f >> 24);
    f = (uint64_t)((ctx->h2 >> 12) | (ctx->h3 << 14)) + ctx->s2 + (f >> 32);
    tag[8]  = (uint8_t)f;       tag[9]  = (uint8_t)(f >> 8);
    tag[10] = (uint8_t)(f >> 16); tag[11] = (uint8_t)(f >> 24);
    f = (uint64_t)((ctx->h3 >> 18) | (ctx->h4 << 8)) + ctx->s3 + (f >> 32);
    tag[12] = (uint8_t)f;       tag[13] = (uint8_t)(f >> 8);
    tag[14] = (uint8_t)(f >> 16); tag[15] = (uint8_t)(f >> 24);

    /* Zeroise key-derived state. Poly1305 is a one-time MAC — the context must not be reused. */
    SSFCryptSecureZero(ctx, sizeof(*ctx));
}

/* --------------------------------------------------------------------------------------------- */
/* Computes Poly1305 MAC (RFC 7539 §2.5). One-shot convenience wrapper over Begin/Update/End.    */
/* --------------------------------------------------------------------------------------------- */
void SSFPoly1305Mac(const uint8_t *msg, size_t msgLen,
                    const uint8_t *key, size_t keyLen,
                    uint8_t *tag, size_t tagSize)
{
    SSFPoly1305Context_t ctx = {0};

    SSFPoly1305Begin(&ctx, key, keyLen);
    SSFPoly1305Update(&ctx, msg, msgLen);
    SSFPoly1305End(&ctx, tag, tagSize);
}

/* --------------------------------------------------------------------------------------------- */
/* If the computed Poly1305 tag over msg with key matches expectedTag exactly returns true,      */
/* else false. Compare is constant-time. Bundles compute + CT-compare so callers cannot pair Mac */
/* with a non-CT memcmp() and open a tag-recovery timing side channel.                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFPoly1305Verify(const uint8_t *msg, size_t msgLen,
                       const uint8_t *key, size_t keyLen,
                       const uint8_t *expectedTag)
{
    uint8_t computedTag[SSF_POLY1305_TAG_SIZE];
    bool ok;

    SSF_REQUIRE((msg != NULL) || (msgLen == 0u));
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(keyLen == SSF_POLY1305_KEY_SIZE);
    SSF_REQUIRE(expectedTag != NULL);

    SSFPoly1305Mac(msg, msgLen, key, keyLen, computedTag, sizeof(computedTag));
    ok = SSFCryptCTMemEq(computedTag, expectedTag, SSF_POLY1305_TAG_SIZE);

    /* On a verify failure, computedTag holds the valid tag for (msg, key) — exactly the */
    /* secret an attacker is trying to forge. Scrub before stack residue can leak it.    */
    SSFCryptSecureZero(computedTag, sizeof(computedTag));
    return ok;
}
