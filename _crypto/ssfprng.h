/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfprng.h                                                                                     */
/* Provides a cryptographically secure capable pseudo random number generator (PRNG).            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#ifndef SSF_PRNG_H_INCLUDE
#define SSF_PRNG_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfaes.h"
#include "ssfport.h"

#if (SSF_PRNG_CONFIG_KEY_BITS != 128u) && (SSF_PRNG_CONFIG_KEY_BITS != 256u)
#error SSF_PRNG_CONFIG_KEY_BITS must be 128 or 256.
#endif

/* Effective key size: P-384 or RSA-4096 forces 256 bits */
#if (SSF_EC_CONFIG_ENABLE_P384 == 1) || (SSF_RSA_CONFIG_ENABLE_4096 == 1) || \
    (SSF_PRNG_CONFIG_KEY_BITS == 256u)
#define SSF_PRNG_KEY_BITS (256u)
#else
#define SSF_PRNG_KEY_BITS (128u)
#endif

/* Seed (= AES key) size in bytes: 16 or 32. Always size seed buffers with this macro. */
#define SSF_PRNG_ENTROPY_SIZE (SSF_PRNG_KEY_BITS / 8u)
#define SSF_PRNG_RANDOM_MAX_SIZE (SSF_AES_BLOCK_SIZE)

typedef struct
{
    uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
    uint64_t count;
    uint32_t magic;
} SSFPRNGContext_t;

/* --------------------------------------------------------------------------------------------- */
/* External Interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFPRNGInitContext(SSFPRNGContext_t *context, const uint8_t *entropy, size_t entropyLen);
#define SSFPRNGReInitContext SSFPRNGInitContext
void SSFPRNGDeInitContext(SSFPRNGContext_t *context);
void SSFPRNGGetRandom(SSFPRNGContext_t *context, uint8_t *random, size_t randomSize);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_PRNG_UNIT_TEST == 1
void SSFPRNGUnitTest(void);
#endif /* SSF_CONFIG_PRNG_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_PRNG_H_INCLUDE */

