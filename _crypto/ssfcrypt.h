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

/* Unsigned 32 x 32 -> 64 multiply from four 32-bit products of 16-bit halves. The middle     */
/* terms are summed in 16-bit pieces (t < 3 * 2^16), so no carry ever needs a compare: there  */
/* is nothing for a compiler to branch on. For cores whose only multiply is 32 x 32 -> 32.    */
/* The 16-bit halves pass through value barriers: clang otherwise recognizes the whole as a  */
/* 64-bit multiply and calls __aeabi_lmul again. (Barriers on the four partial products also */
/* stop that, but cost clang spills on ARMv6-M: P-256 sign +4% instead of -0.2% here.)        */
static inline uint64_t SSFCryptCTMul32(uint32_t a, uint32_t b)
{
    uint32_t al = a & 0xFFFFu;
    uint32_t ah = a >> 16;
    uint32_t bl = b & 0xFFFFu;
    uint32_t bh = b >> 16;
    uint32_t lo;
    uint32_t m1;
    uint32_t m2;
    uint32_t hi;
    uint32_t t;

    SSF_CT_VALUE_BARRIER(al);
    SSF_CT_VALUE_BARRIER(ah);
    SSF_CT_VALUE_BARRIER(bl);
    SSF_CT_VALUE_BARRIER(bh);
    lo = al * bl;
    m1 = al * bh;
    m2 = ah * bl;
    hi = ah * bh;

    t = ((lo >> 16) + (m1 & 0xFFFFu)) + (m2 & 0xFFFFu);

    hi += ((m1 >> 16) + (m2 >> 16)) + (t >> 16);
    lo = (lo & 0xFFFFu) | (t << 16);
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

/* Signed 32 x 32 -> 64 multiply: the unsigned product of the two's-complement bit patterns,  */
/* minus b * 2^32 when a < 0 and minus a * 2^32 when b < 0, with the sign masks barriered.    */
static inline int64_t SSFCryptCTSMul32(int32_t a, int32_t b)
{
    uint32_t ua = (uint32_t)a;
    uint32_t ub = (uint32_t)b;
    uint64_t p = SSFCryptCTMul32(ua, ub);
    uint32_t ma = 0u - (ua >> 31);
    uint32_t mb = 0u - (ub >> 31);
    uint32_t hi;

    SSF_CT_VALUE_BARRIER(ma);
    SSF_CT_VALUE_BARRIER(mb);
    hi = ((uint32_t)(p >> 32) - (ub & ma)) - (ua & mb);
    /* uint64_t -> int64_t of a value above INT64_MAX is two's complement on every target */
    return (int64_t)(((uint64_t)hi << 32) | (p & 0xFFFFFFFFu));
}

/* SSF_CT_MUL32(a, b) / SSF_CT_SMUL32(a, b): the full 64-bit product of two 32-bit values for */
/* constant-time code. Cores with no 32 x 32 -> 64 multiply instruction (ARMv6-M: Cortex-M0 / */
/* M0+; ARMv8-M Baseline: M23) would otherwise call libgcc's __aeabi_lmul / __muldi3, which   */
/* branches on the operands; there the branch-free helpers above are used. Everywhere else    */
/* the plain C product is kept, which compiles to the native widening multiply.               */
#if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__)
#define SSF_CT_MUL32(a, b) SSFCryptCTMul32((uint32_t)(a), (uint32_t)(b))
#define SSF_CT_SMUL32(a, b) SSFCryptCTSMul32((int32_t)(a), (int32_t)(b))
#else
#define SSF_CT_MUL32(a, b) ((uint64_t)(uint32_t)(a) * (uint64_t)(uint32_t)(b))
#define SSF_CT_SMUL32(a, b) ((int64_t)(int32_t)(a) * (int64_t)(int32_t)(b))
#endif
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

