/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsha2.h                                                                                     */
/* Provides SHA2 interface: SHA256, SHA224, SHA512, SHA384, SHA512/224, or SHA512/256            */
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
#ifndef SSF_SHA2_H_INCLUDE
#define SSF_SHA2_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "ssfport.h"

#define SSF_SHA2_224_BYTE_SIZE (28u)
#define SSF_SHA2_256_BYTE_SIZE (32u)
#define SSF_SHA2_512_BYTE_SIZE (64u)
#define SSF_SHA2_384_BYTE_SIZE (48u)
#define SSF_SHA2_512_224_BYTE_SIZE (28u)
#define SSF_SHA2_512_256_BYTE_SIZE (32u)

#define SSF_SHA2_32_BLOCK_BYTE_SIZE (64u)
#define SSF_SHA2_64_BLOCK_BYTE_SIZE (128u)

/* --------------------------------------------------------------------------------------------- */
/* Incremental hash context types                                                                */
/* --------------------------------------------------------------------------------------------- */
typedef struct
{
    uint32_t h[8];                              /* Running hash state */
    uint8_t  buf[SSF_SHA2_32_BLOCK_BYTE_SIZE];  /* Partial block buffer */
    uint32_t bufLen;                            /* Bytes currently held in buf */
    uint64_t totalBits;                         /* Total bits fed so far */
    uint16_t hashBitSize;                       /* 256 or 224 */
    uint32_t magic;                             /* Context validity marker */
} SSFSHA2_32Context_t;

typedef struct
{
    uint64_t h[8];                              /* Running hash state */
    uint8_t  buf[SSF_SHA2_64_BLOCK_BYTE_SIZE];  /* Partial block buffer */
    uint32_t bufLen;                            /* Bytes currently held in buf */
    uint64_t totalBits;                         /* Total bits fed so far */
    uint16_t hashBitSize;                       /* 512 or 384 */
    uint16_t truncationBitSize;                 /* 0, 256, or 224 */
    uint32_t magic;                             /* Context validity marker */
} SSFSHA2_64Context_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_32(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize);
#define SSFSHA256(in, inLen, out, outSize) SSFSHA2_32(in, inLen, out, outSize, 256)
#define SSFSHA224(in, inLen, out, outSize) SSFSHA2_32(in, inLen, out, outSize, 224)

void SSFSHA2_64(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize, uint16_t truncationBitSize);

#define SSFSHA512(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 0)
#define SSFSHA512_256(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 256)
#define SSFSHA512_224(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 224)
#define SSFSHA384(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 384, 0)

void SSFSHA2_32Begin(SSFSHA2_32Context_t *context, uint16_t hashBitSize);
void SSFSHA2_32Update(SSFSHA2_32Context_t *context, const uint8_t *in, uint32_t inLen);
void SSFSHA2_32End(SSFSHA2_32Context_t *context, uint8_t *out, uint32_t outSize);

#define SSFSHA256Begin(context)                       SSFSHA2_32Begin(context, 256)
#define SSFSHA256Update(context, in, inLen)           SSFSHA2_32Update(context, in, inLen)
#define SSFSHA256End(context, out, outSize)           SSFSHA2_32End(context, out, outSize)

#define SSFSHA224Begin(context)                       SSFSHA2_32Begin(context, 224)
#define SSFSHA224Update(context, in, inLen)           SSFSHA2_32Update(context, in, inLen)
#define SSFSHA224End(context, out, outSize)           SSFSHA2_32End(context, out, outSize)

void SSFSHA2_64Begin(SSFSHA2_64Context_t *context, uint16_t hashBitSize, uint16_t truncationBitSize);
void SSFSHA2_64Update(SSFSHA2_64Context_t *context, const uint8_t *in, uint32_t inLen);
void SSFSHA2_64End(SSFSHA2_64Context_t *context, uint8_t *out, uint32_t outSize);

#define SSFSHA512Begin(context)                       SSFSHA2_64Begin(context, 512, 0)
#define SSFSHA512Update(context, in, inLen)           SSFSHA2_64Update(context, in, inLen)
#define SSFSHA512End(context, out, outSize)           SSFSHA2_64End(context, out, outSize)

#define SSFSHA512_256Begin(context)                   SSFSHA2_64Begin(context, 512, 256)
#define SSFSHA512_256Update(context, in, inLen)       SSFSHA2_64Update(context, in, inLen)
#define SSFSHA512_256End(context, out, outSize)       SSFSHA2_64End(context, out, outSize)

#define SSFSHA512_224Begin(context)                   SSFSHA2_64Begin(context, 512, 224)
#define SSFSHA512_224Update(context, in, inLen)       SSFSHA2_64Update(context, in, inLen)
#define SSFSHA512_224End(context, out, outSize)       SSFSHA2_64End(context, out, outSize)

#define SSFSHA384Begin(context)                       SSFSHA2_64Begin(context, 384, 0)
#define SSFSHA384Update(context, in, inLen)           SSFSHA2_64Update(context, in, inLen)
#define SSFSHA384End(context, out, outSize)           SSFSHA2_64End(context, out, outSize)

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_SHA2_UNIT_TEST == 1
void SSFSHA2UnitTest(void);
#endif /* SSF_CONFIG_SHA2_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_SHA2_H_INCLUDE */

