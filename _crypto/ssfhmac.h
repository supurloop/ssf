/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhmac.h                                                                                     */
/* Provides HMAC (RFC 2104) keyed-hash message authentication code interface.                    */
/* Supports SHA-1, SHA-256, SHA-384, and SHA-512 hash functions.                                 */
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
#ifndef SSF_HMAC_H_INCLUDE
#define SSF_HMAC_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfsha1.h"
#include "ssfsha2.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_HMAC_MAX_HASH_SIZE  (64u)  /* SHA-512 output size */
#define SSF_HMAC_MAX_BLOCK_SIZE (128u) /* SHA-384/512 block size */

/* Hash algorithm selection */
typedef enum
{
    SSF_HMAC_HASH_MIN = -1,
    SSF_HMAC_HASH_SHA1,     /* HMAC-SHA-1 (hash=20, block=64) */
    SSF_HMAC_HASH_SHA256,   /* HMAC-SHA-256 (hash=32, block=64) */
    SSF_HMAC_HASH_SHA384,   /* HMAC-SHA-384 (hash=48, block=128) */
    SSF_HMAC_HASH_SHA512,   /* HMAC-SHA-512 (hash=64, block=128) */
    SSF_HMAC_HASH_MAX,
} SSFHMACHash_t;

/* Incremental HMAC context */
typedef struct SSFHMACContext
{
    SSFHMACHash_t hash;
    uint8_t oKeyPad[SSF_HMAC_MAX_BLOCK_SIZE];
    union
    {
        SSFSHA1Context_t sha1;
        SSFSHA2_32Context_t sha2_32;
        SSFSHA2_64Context_t sha2_64;
    } hashCtx;
} SSFHMACContext_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Single-call HMAC: computes the MAC in one call. */
bool SSFHMAC(SSFHMACHash_t hash, const uint8_t *key, size_t keyLen,
             const uint8_t *msg, size_t msgLen,
             uint8_t *macOut, size_t macOutSize);

/* Incremental HMAC: Begin/Update/End for streaming messages. */
void SSFHMACBegin(SSFHMACContext_t *ctx, SSFHMACHash_t hash,
                  const uint8_t *key, size_t keyLen);
void SSFHMACUpdate(SSFHMACContext_t *ctx, const uint8_t *data, size_t dataLen);
void SSFHMACEnd(SSFHMACContext_t *ctx, uint8_t *macOut, size_t macOutSize);

/* Helper: returns the output size in bytes for a given hash. */
size_t SSFHMACGetHashSize(SSFHMACHash_t hash);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_HMAC_UNIT_TEST == 1
void SSFHMACUnitTest(void);
#endif /* SSF_CONFIG_HMAC_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_HMAC_H_INCLUDE */
