/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn.h                                                                                       */
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
#ifndef SSF_BN_H_INCLUDE
#define SSF_BN_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfprng.h"

/* --------------------------------------------------------------------------------------------- */
/* Auto-derive SSF_BN_CONFIG_MAX_BITS as 2x the widest enabled operand (see ssfbn.md).           */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_BN_CONFIG_MAX_BITS

#if (defined(SSF_RSA_CONFIG_ENABLE_4096) && (SSF_RSA_CONFIG_ENABLE_4096 == 1))
#define SSF_BN_CONFIG_MAX_BITS (8192u)
#elif (defined(SSF_RSA_CONFIG_ENABLE_3072) && (SSF_RSA_CONFIG_ENABLE_3072 == 1))
#define SSF_BN_CONFIG_MAX_BITS (6144u)
#elif (defined(SSF_RSA_CONFIG_ENABLE_2048) && (SSF_RSA_CONFIG_ENABLE_2048 == 1))
#define SSF_BN_CONFIG_MAX_BITS (4096u)
#elif (defined(SSF_EC_CONFIG_ENABLE_P384) && (SSF_EC_CONFIG_ENABLE_P384 == 1))
#define SSF_BN_CONFIG_MAX_BITS  (768u)
#elif (defined(SSF_EC_CONFIG_ENABLE_P256) && (SSF_EC_CONFIG_ENABLE_P256 == 1))
#define SSF_BN_CONFIG_MAX_BITS  (512u)
#else
#define SSF_BN_CONFIG_MAX_BITS  (256u)
#endif

#endif /* !defined(SSF_BN_CONFIG_MAX_BITS) */

/* --------------------------------------------------------------------------------------------- */
/* Defines.                                                                                      */
/* --------------------------------------------------------------------------------------------- */
typedef uint32_t SSFBNLimb_t;
typedef uint64_t SSFBNDLimb_t;

#define SSF_BN_LIMB_BITS           (32u)
#define SSF_BN_LIMB_MAX            (0xFFFFFFFFul)
#define SSF_BN_BITS_TO_LIMBS(bits) ((((bits) + SSF_BN_LIMB_BITS) - 1u) / SSF_BN_LIMB_BITS)
#define SSF_BN_MAX_LIMBS           SSF_BN_BITS_TO_LIMBS(SSF_BN_CONFIG_MAX_BITS)
#define SSF_BN_MAX_BYTES           (((SSF_BN_CONFIG_MAX_BITS) + 7u) / 8u)

/* Upper bound on SSFBNMont_t::len. Override only for non-2N MAX_BITS pins. See ssfbn.md. */
#ifndef SSF_BN_MAX_MOD_LIMBS
#define SSF_BN_MAX_MOD_LIMBS       (((SSF_BN_MAX_LIMBS) + 1u) / 2u)
#endif

/* Largest modulus SSFBNModInvSmall / SSFBNModMulSmall accept: P-384 size, or the whole cap */
#if SSF_BN_MAX_LIMBS >= 12u
#define SSF_BN_SMALL_MAX_LIMBS     (12u)
#else
#define SSF_BN_SMALL_MAX_LIMBS     (SSF_BN_MAX_LIMBS)
#endif

/* Largest modulus SSFBNModExpHalf accepts: half of SSF_BN_MAX_MOD_LIMBS, an RSA CRT prime.     */
#define SSF_BN_HALF_MOD_LIMBS      (((SSF_BN_MAX_MOD_LIMBS) + 1u) / 2u)

/* --------------------------------------------------------------------------------------------- */
/* Compile-time checks that an SSF_BN_CONFIG_MAX_BITS override fits every enabled algorithm.     */
/* --------------------------------------------------------------------------------------------- */

/* SSF_BN_CONFIG_MAX_BITS must be a whole number of limbs */
typedef char _ssf_bn_sa_max_bits_aligned[
    (((SSF_BN_CONFIG_MAX_BITS) % SSF_BN_LIMB_BITS) == 0u) ? 1 : -1];

/* MAX_LIMBS <= 32767 keeps a checked Mul / Square result len in uint16_t */
typedef char _ssf_bn_sa_max_limbs_fits_int16[
    ((SSF_BN_MAX_LIMBS) <= 32767u) ? 1 : -1];

/* Per-algorithm: the cap must hold a 2N-limb intermediate from SSFBNMul. */
#if (defined(SSF_EC_CONFIG_ENABLE_P256) && (SSF_EC_CONFIG_ENABLE_P256 == 1))
typedef char _ssf_bn_sa_cap_supports_p256[
    ((SSF_BN_CONFIG_MAX_BITS) >= 512u) ? 1 : -1];
#endif
#if (defined(SSF_EC_CONFIG_ENABLE_P384) && (SSF_EC_CONFIG_ENABLE_P384 == 1))
typedef char _ssf_bn_sa_cap_supports_p384[
    ((SSF_BN_CONFIG_MAX_BITS) >= 768u) ? 1 : -1];
#endif
#if (defined(SSF_RSA_CONFIG_ENABLE_2048) && (SSF_RSA_CONFIG_ENABLE_2048 == 1))
typedef char _ssf_bn_sa_cap_supports_rsa2048[
    ((SSF_BN_CONFIG_MAX_BITS) >= 4096u) ? 1 : -1];
#endif
#if (defined(SSF_RSA_CONFIG_ENABLE_3072) && (SSF_RSA_CONFIG_ENABLE_3072 == 1))
typedef char _ssf_bn_sa_cap_supports_rsa3072[
    ((SSF_BN_CONFIG_MAX_BITS) >= 6144u) ? 1 : -1];
#endif
#if (defined(SSF_RSA_CONFIG_ENABLE_4096) && (SSF_RSA_CONFIG_ENABLE_4096 == 1))
typedef char _ssf_bn_sa_cap_supports_rsa4096[
    ((SSF_BN_CONFIG_MAX_BITS) >= 8192u) ? 1 : -1];
#endif

/* Per-algorithm: SSF_BN_MAX_MOD_LIMBS must hold the modulus, and must not exceed MAX_LIMBS. */
typedef char _ssf_bn_sa_mod_limbs_cap[
    ((SSF_BN_MAX_MOD_LIMBS) <= (SSF_BN_MAX_LIMBS)) ? 1 : -1];
#if (defined(SSF_EC_CONFIG_ENABLE_P256) && (SSF_EC_CONFIG_ENABLE_P256 == 1))
typedef char _ssf_bn_sa_mod_supports_p256[
    ((SSF_BN_MAX_MOD_LIMBS) >= 8u) ? 1 : -1];
#endif
#if (defined(SSF_EC_CONFIG_ENABLE_P384) && (SSF_EC_CONFIG_ENABLE_P384 == 1))
typedef char _ssf_bn_sa_mod_supports_p384[
    ((SSF_BN_MAX_MOD_LIMBS) >= 12u) ? 1 : -1];
#endif
#if (defined(SSF_RSA_CONFIG_ENABLE_2048) && (SSF_RSA_CONFIG_ENABLE_2048 == 1))
typedef char _ssf_bn_sa_mod_supports_rsa2048[
    ((SSF_BN_MAX_MOD_LIMBS) >= 64u) ? 1 : -1];
#endif
#if (defined(SSF_RSA_CONFIG_ENABLE_3072) && (SSF_RSA_CONFIG_ENABLE_3072 == 1))
typedef char _ssf_bn_sa_mod_supports_rsa3072[
    ((SSF_BN_MAX_MOD_LIMBS) >= 96u) ? 1 : -1];
#endif
#if (defined(SSF_RSA_CONFIG_ENABLE_4096) && (SSF_RSA_CONFIG_ENABLE_4096 == 1))
typedef char _ssf_bn_sa_mod_supports_rsa4096[
    ((SSF_BN_MAX_MOD_LIMBS) >= 128u) ? 1 : -1];
#endif

typedef struct SSFBN
{
    SSFBNLimb_t *limbs;
    uint16_t len;
    uint16_t cap;
} SSFBN_t;

#define SSFBN_DEFINE(name, nlimbs) \
    SSFBNLimb_t name##_storage[(nlimbs)] = {0u}; \
    SSFBN_t name = { name##_storage, 0u, (uint16_t)(nlimbs) }

typedef struct SSFBNMont
{
    SSFBN_t mod;
    SSFBN_t rr;
    SSFBNLimb_t mp;
    uint16_t len;
} SSFBNMont_t;

#define SSFBNMONT_DEFINE(name, nlimbs) \
    SSFBNLimb_t name##_mod_storage[(nlimbs)] = {0u}; \
    SSFBNLimb_t name##_rr_storage[(nlimbs)] = {0u}; \
    SSFBNMont_t name = { \
        { name##_mod_storage, 0u, (uint16_t)(nlimbs) }, \
        { name##_rr_storage,  0u, (uint16_t)(nlimbs) }, \
        0u, 0u \
    }

/* --------------------------------------------------------------------------------------------- */
/* Initialization and conversion                                                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFBNSetZero(SSFBN_t *a, uint16_t numLimbs);
void SSFBNSetUint32(SSFBN_t *a, uint32_t val, uint16_t numLimbs);
void SSFBNSetOne(SSFBN_t *a, uint16_t numLimbs);
void SSFBNCopy(SSFBN_t *dst, const SSFBN_t *src);
bool SSFBNFromBytes(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs);
bool SSFBNToBytes(const SSFBN_t *a, uint8_t *out, size_t outSize);
bool SSFBNFromBytesLE(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs);
bool SSFBNToBytesLE(const SSFBN_t *a, uint8_t *out, size_t outSize);

/* --------------------------------------------------------------------------------------------- */
/* Comparison                                                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNIsZero(const SSFBN_t *a);
bool SSFBNIsOne(const SSFBN_t *a);
#define SSFBNIsEven(a)  (((a)->limbs[0] & 1u) == 0u)
#define SSFBNIsOdd(a)   (((a)->limbs[0] & 1u) != 0u)
int8_t SSFBNCmp(const SSFBN_t *a, const SSFBN_t *b);
int8_t SSFBNCmpUint32(const SSFBN_t *a, uint32_t val);

/* --------------------------------------------------------------------------------------------- */
/* Bit operations                                                                                */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFBNBitLen(const SSFBN_t *a);
uint32_t SSFBNTrailingZeros(const SSFBN_t *a);
#define SSFBNGetBit(a, pos) \
    ((((uint32_t)(pos) >> 5u) >= (uint32_t)(a)->len) ? (uint8_t)0u : \
     (uint8_t)(((a)->limbs[(uint32_t)(pos) >> 5u] >> ((uint32_t)(pos) & 0x1Fu)) & 1u))
#define SSFBNSetBit(a, pos) \
    do { (a)->limbs[(uint32_t)(pos) >> 5u] |= \
         ((SSFBNLimb_t)1u << ((uint32_t)(pos) & 0x1Fu)); } while (0)
#define SSFBNClearBit(a, pos) \
    do { (a)->limbs[(uint32_t)(pos) >> 5u] &= \
         ~((SSFBNLimb_t)1u << ((uint32_t)(pos) & 0x1Fu)); } while (0)
void SSFBNShiftLeft1(SSFBN_t *a);
void SSFBNShiftRight1(SSFBN_t *a);
void SSFBNShiftLeft(SSFBN_t *a, uint32_t nBits);
void SSFBNShiftRight(SSFBN_t *a, uint32_t nBits);

/* --------------------------------------------------------------------------------------------- */
/* Basic arithmetic                                                                              */
/* --------------------------------------------------------------------------------------------- */
SSFBNLimb_t SSFBNAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
SSFBNLimb_t SSFBNSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
SSFBNLimb_t SSFBNAddUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b);
SSFBNLimb_t SSFBNSubUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b);
void SSFBNMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
void SSFBNMulUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b);
void SSFBNSquare(SSFBN_t *r, const SSFBN_t *a);

/* --------------------------------------------------------------------------------------------- */
/* Modular arithmetic                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModMulCT(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModMulCTOdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
bool SSFBNModInv(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
bool SSFBNModInvSmall(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
void SSFBNModMulSmall(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModMulNIST(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModMulNISTPrime(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
void SSFBNDivMod(SSFBN_t *q, SSFBN_t *rem, const SSFBN_t *a, const SSFBN_t *b);
void SSFBNGcd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
bool SSFBNModInvExt(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
bool SSFBNModInvOdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);

/* --------------------------------------------------------------------------------------------- */
/* Montgomery multiplication                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontInit(SSFBNMont_t *ctx, const SSFBN_t *m);
void SSFBNMontMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBNMont_t *ctx);
void SSFBNMontSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBNMont_t *ctx);
void SSFBNMontConvertIn(SSFBN_t *aR, const SSFBN_t *a, const SSFBNMont_t *ctx);
void SSFBNMontConvertOut(SSFBN_t *a, const SSFBN_t *aR, const SSFBNMont_t *ctx);

/* --------------------------------------------------------------------------------------------- */
/* Modular exponentiation                                                                        */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExp(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m);
void SSFBNModExpMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx);
void SSFBNModExpHalf(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m);
void SSFBNModExpPub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m);
void SSFBNModExpMontPub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx);

/* --------------------------------------------------------------------------------------------- */
/* Utility                                                                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFBNCondSwap(SSFBN_t *a, SSFBN_t *b, SSFBNLimb_t swap);
void SSFBNCondCopy(SSFBN_t *dst, const SSFBN_t *src, SSFBNLimb_t sel);
void SSFBNZeroize(SSFBN_t *a);

/* --------------------------------------------------------------------------------------------- */
/* Primality and random                                                                          */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFBNModUint32(const SSFBN_t *a, uint32_t d);
void SSFBNRandom(SSFBN_t *a, uint16_t numLimbs, SSFPRNGContext_t *prng);
bool SSFBNRandomBelow(SSFBN_t *a, const SSFBN_t *bound, SSFPRNGContext_t *prng);
bool SSFBNIsProbablePrime(const SSFBN_t *n, uint16_t rounds, SSFPRNGContext_t *prng);
bool SSFBNGenPrime(SSFBN_t *p, uint16_t bitLen, uint16_t rounds, SSFPRNGContext_t *prng);

/* --------------------------------------------------------------------------------------------- */
/* NIST curve prime constants                                                                    */
/* --------------------------------------------------------------------------------------------- */
extern const SSFBN_t SSF_BN_NIST_P256;
extern const SSFBN_t SSF_BN_NIST_P384;

/* Their limbs; ssfec's curve parameters point at these so the prime is stored once */
extern const SSFBNLimb_t SSF_BN_NIST_P256_LIMBS[8];
extern const SSFBNLimb_t SSF_BN_NIST_P384_LIMBS[12];

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_BN_UNIT_TEST == 1
void SSFBNUnitTest(void);

/* Test-only count of SSFBNMod calls. */
extern uint32_t _SSFBNModCallCount;

/* Test-only hook fired after each secret local is wiped. */
extern void (*_SSFBNScrubTestHook)(const void *buf, size_t len);

/* Test-only counters: Karatsuba propagation iterations, exporter scans. */
extern uint32_t _SSFBNKaratsubaPropIters;
extern uint32_t _SSFBNToBytesScans;

/* Test-only count of the modular doublings SSFBNMontInit runs. */
extern uint32_t _SSFBNMontInitDoublings;

/* Test-only counts: MontMul inner-loop and MontSquare carry-loop iterations. */
extern uint32_t _SSFBNMontMulIters;
extern uint32_t _SSFBNMontSqrCarryIters;

/* Test-only count of SSFBNSquare's diagonal carry steps, fixed at a->len */
extern uint32_t _SSFBNSquareCarryIters;

/* Test-only count of the P-256 / P-384 reductions' correction passes */
extern uint32_t _SSFBNNistCorrPasses;

/* Test-only count of full NIST prime comparisons in SSFBNModMulNIST */
extern uint32_t _SSFBNNistPrimeCmps;

/* Test-only wrapper: r = t mod m through the P-256 / P-384 fast reduction (m must be one) */
void _SSFBNReduceNISTForTest(SSFBN_t *r, const SSFBN_t *t, const SSFBN_t *m);

/* Test-only count of full-width entry points (ModExpMont[Pub], ModMulCT, ModInvExt, ModMul). */
extern uint32_t _SSFBNFullWidthCalls;

/* Test-only count of the slow ModMulCT / ModInvExt algorithms (shift-subtract, Euclid) */
extern uint32_t _SSFBNSlowPathCalls;

/* Test-only count of SSFBNMod's variable-time shift-and-subtract reductions */
extern uint32_t _SSFBNModShiftCalls;
#endif /* SSF_CONFIG_BN_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_H_INCLUDE */
