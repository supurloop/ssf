/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpoly1305.h                                                                                 */
/* Provides Poly1305 message authentication code interface (RFC 7539).                           */
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
#ifndef SSFPOLY1305_H_INCLUDE
#define SSFPOLY1305_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_POLY1305_KEY_SIZE (32u)
#define SSF_POLY1305_TAG_SIZE (16u)

/* Opaque incremental Poly1305 context; zero it before the first Begin (see ssfpoly1305.md). */
typedef struct SSFPoly1305Context
{
    uint32_t r0; /* clamped r limbs */
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r4;
    uint32_t s0; /* s = key[16..31] as 4 LE words */
    uint32_t s1;
    uint32_t s2;
    uint32_t s3;
    uint32_t rr0; /* r1..r4 * 5 (precomputed reduction operands) */
    uint32_t rr1;
    uint32_t rr2;
    uint32_t rr3;
    uint32_t h0; /* 130-bit accumulator */
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t h4;
    uint8_t buf[16]; /* partial-block accumulator */
    uint8_t bufLen; /* 0..15 -- bytes currently in buf[] */
    uint32_t magic; /* context validity marker -- 0 => uninitialised */
} SSFPoly1305Context_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* One-shot: compute the Poly1305 tag over msg using the 32-byte one-time key. */
void SSFPoly1305Mac(const uint8_t *msg, size_t msgLen, const uint8_t *key, size_t keyLen,
                    uint8_t *tag, size_t tagSize);

/* One-shot: true iff the tag over msg equals the 16-byte expectedTag (constant-time). */
bool SSFPoly1305Verify(const uint8_t *msg, size_t msgLen, const uint8_t *key, size_t keyLen,
                       const uint8_t *expectedTag);

/* Incremental: initialize ctx with a 32-byte one-time key. */
void SSFPoly1305Begin(SSFPoly1305Context_t *ctx, const uint8_t *key, size_t keyLen);

/* Incremental: feed msgLen bytes; any chunking gives the same tag as one-shot. */
void SSFPoly1305Update(SSFPoly1305Context_t *ctx, const uint8_t *msg, size_t msgLen);

/* Incremental: finalize, write the 16-byte tag and zeroise ctx (Begin again before reuse). */
void SSFPoly1305End(SSFPoly1305Context_t *ctx, uint8_t *tag, size_t tagSize);

#if SSF_CONFIG_POLY1305_UNIT_TEST == 1
void SSFPoly1305UnitTest(void);
#endif /* SSF_CONFIG_POLY1305_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSFPOLY1305_H_INCLUDE */
