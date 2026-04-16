/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsha1.h                                                                                     */
/* Provides SHA-1 (RFC 3174) hash interface. Required by the WebSocket handshake (RFC 6455).     */
/*                                                                                               */
/* Note: SHA-1 is cryptographically deprecated for collision resistance. It is included in SSF    */
/* solely because RFC 6455 mandates it for the Sec-WebSocket-Accept computation. Do not use       */
/* SHA-1 for new cryptographic purposes; use ssfsha2 (SHA-256/512) instead.                      */
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
#ifndef SSF_SHA1_H_INCLUDE
#define SSF_SHA1_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_SHA1_HASH_SIZE  (20u)  /* 160-bit hash output */
#define SSF_SHA1_BLOCK_SIZE (64u)  /* 512-bit block size */

/* Incremental hash context */
typedef struct SSFSHA1Context
{
    uint32_t state[5];                          /* H0..H4 */
    uint64_t totalLen;                          /* Total bytes processed */
    uint8_t block[SSF_SHA1_BLOCK_SIZE];         /* Partial block accumulator */
    uint32_t blockLen;                          /* Bytes in partial block */
} SSFSHA1Context_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Single-call hash: computes SHA-1 of in[0..inLen-1] into out[0..19]. */
void SSFSHA1(const uint8_t *in, uint32_t inLen, uint8_t out[SSF_SHA1_HASH_SIZE]);

/* Incremental hash: Begin/Update/End pattern for hashing data in chunks. */
void SSFSHA1Begin(SSFSHA1Context_t *ctx);
void SSFSHA1Update(SSFSHA1Context_t *ctx, const uint8_t *in, uint32_t inLen);
void SSFSHA1End(SSFSHA1Context_t *ctx, uint8_t out[SSF_SHA1_HASH_SIZE]);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_SHA1_UNIT_TEST == 1
void SSFSHA1UnitTest(void);
#endif /* SSF_CONFIG_SHA1_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_SHA1_H_INCLUDE */
