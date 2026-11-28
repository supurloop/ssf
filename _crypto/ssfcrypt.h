/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcrypt.h                                                                                    */
/* Provides high-level cryptographic helpers (constant-time compare, secure zeroize).            */
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
#ifndef SSF_CRYPT_H_INCLUDE
#define SSF_CRYPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFCryptCTMemEq(const void *a, const void *b, size_t n);

/* Constant-time predicates on uint32_t values: 1 or 0, with no comparison operator. Value     */
/* barriers sit on the intermediate whose top bit is the answer and on the returned bit, so   */
/* the optimizer can neither match the expression back to a compare (clang turns (x | -x) >> */
/* 31 into x != 0, and 1 ^ (t >> 31) into t >= 0) nor learn that the result is 0 or 1. On    */
/* ARMv6-M either lets it branch on the secret. 0u - result is a mask it cannot reason about. */
static inline uint32_t SSFCryptCTNonZero(uint32_t x)
{
    uint32_t t = x | (0u - x);

    SSF_CT_VALUE_BARRIER(t);
    t >>= 31;
    SSF_CT_VALUE_BARRIER(t);
    return t;
}

static inline uint32_t SSFCryptCTIsZero(uint32_t x)
{
    uint32_t t = 1u ^ SSFCryptCTNonZero(x);

    SSF_CT_VALUE_BARRIER(t);
    return t;
}

static inline uint32_t SSFCryptCTEq(uint32_t a, uint32_t b)
{
    return SSFCryptCTIsZero(a ^ b);
}

/* 1 if a < b (unsigned), else 0 */
static inline uint32_t SSFCryptCTLt(uint32_t a, uint32_t b)
{
    uint32_t t = ((~a) & b) | (((~a) | b) & (a - b));

    SSF_CT_VALUE_BARRIER(t);
    t >>= 31;
    SSF_CT_VALUE_BARRIER(t);
    return t;
}
void SSFCryptSecureZero(void *p, size_t n);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_CRYPT_UNIT_TEST == 1
void SSFCryptUnitTest(void);
#endif /* SSF_CONFIG_CRYPT_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_CRYPT_H_INCLUDE */

