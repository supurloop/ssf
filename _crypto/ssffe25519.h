/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssffe25519.h                                                                                  */
/* GF(2^255 - 19) field arithmetic shared by ssfx25519 and ssfed25519 (internal).                */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#ifndef SSF_FE25519_H_INCLUDE
#define SSF_FE25519_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* Field element: 8 x 32-bit limbs, little-endian limb order; any value below 2^256 is accepted  */
typedef struct { uint32_t v[8]; } SSFFE25519_t;

/* p = 2^255 - 19 */
extern const SSFFE25519_t SSF_FE25519_P;

/* --------------------------------------------------------------------------------------------- */
/* External interface (internal to ssfx25519 / ssfed25519; not a public API)                     */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519Mul(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b);
void SSFFE25519Sqr(SSFFE25519_t *r, const SSFFE25519_t *a);
void SSFFE25519Reduce(SSFFE25519_t *a);
void SSFFE25519Inv(SSFFE25519_t *r, const SSFFE25519_t *a);
void SSFFE25519ToBytes(uint8_t *b, const SSFFE25519_t *a);
void SSFFE25519CSwap(SSFFE25519_t *a, SSFFE25519_t *b, uint32_t swap);

/* --------------------------------------------------------------------------------------------- */
/* r = 0.                                                                                        */
/* --------------------------------------------------------------------------------------------- */
static inline void SSFFE25519SetZero(SSFFE25519_t *r)
{
    SSF_REQUIRE(r != NULL);

    memset(r->v, 0, sizeof(r->v));
}

/* --------------------------------------------------------------------------------------------- */
/* r = 1.                                                                                        */
/* --------------------------------------------------------------------------------------------- */
static inline void SSFFE25519SetOne(SSFFE25519_t *r)
{
    SSF_REQUIRE(r != NULL);

    memset(r->v, 0, sizeof(r->v));
    r->v[0] = 1u;
}

/* --------------------------------------------------------------------------------------------- */
/* r = a.                                                                                        */
/* --------------------------------------------------------------------------------------------- */
static inline void SSFFE25519Copy(SSFFE25519_t *r, const SSFFE25519_t *a)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);

    memcpy(r->v, a->v, sizeof(r->v));
}

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_FE25519_UNIT_TEST == 1
void SSFFE25519UnitTest(void);
#endif /* SSF_CONFIG_FE25519_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_FE25519_H_INCLUDE */
