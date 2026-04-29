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
/* Auto-derive SSF_BN_CONFIG_MAX_BITS from enabled algorithm flags.                              */
/*                                                                                               */
/* The cap must hold a 2N-limb intermediate for any consumer module: SSFBNMul produces a 2N-limb */
/* product, and SSFBNModMul / SSFBNModMulNIST / SSFBNModInvExt all gate on 2N <= MAX_LIMBS. The  */
/* derivation picks the largest operand width across enabled algorithms and doubles it:          */
/*                                                                                               */
/*   ECC P-256                  → 2 × 256  =  512                                                 */
/*   ECC P-384                  → 2 × 384  =  768                                                 */
/*   RSA-2048 (sign / keygen)   → 2 × 2048 = 4096                                                 */
/*   RSA-3072                   → 2 × 3072 = 6144                                                 */
/*   RSA-4096                   → 2 × 4096 = 8192                                                 */
/*                                                                                               */
/* If no consumer is enabled the cap defaults to 256 — ssfbn still compiles but its working      */
/* state is irrelevant. Users can override via SSF_BN_CONFIG_MAX_BITS in ssfbn_opt.h to size the */
/* cap up for an out-of-tree consumer.                                                            */
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
#define SSF_BN_BITS_TO_LIMBS(bits) (((bits) + SSF_BN_LIMB_BITS - 1u) / SSF_BN_LIMB_BITS)
#define SSF_BN_MAX_LIMBS           SSF_BN_BITS_TO_LIMBS(SSF_BN_CONFIG_MAX_BITS)
#define SSF_BN_MAX_BYTES           (((SSF_BN_CONFIG_MAX_BITS) + 7u) / 8u)

/* --------------------------------------------------------------------------------------------- */
/* Static-assert defense-in-depth on the derived width.                                          */
/*                                                                                                */
/* These typedef-array tautologies are guaranteed by the auto-derivation above, but they catch   */
/* user overrides of SSF_BN_CONFIG_MAX_BITS in ssfbn_opt.h that drop below an enabled algorithm's */
/* minimum. The pre-C11 typedef-array idiom is used because the cross-test toolchain matrix     */
/* predates universal _Static_assert support.                                                     */
/* --------------------------------------------------------------------------------------------- */

/* SSF_BN_CONFIG_MAX_BITS must be a whole-limb multiple so SSF_BN_BITS_TO_LIMBS doesn't pick up */
/* a fractional-limb residue.                                                                   */
typedef char _ssf_bn_sa_max_bits_aligned[
    ((SSF_BN_CONFIG_MAX_BITS) % SSF_BN_LIMB_BITS == 0u) ? 1 : -1];

/* SSF_BN_MAX_LIMBS must fit in int16_t so a->len + b->len cannot wrap uint16_t in SSFBNMul /  */
/* SSFBNSquare. Same property as the matching #error in ssfbn.c, but visible at every include. */
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
void SSFBNModSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
bool SSFBNModInv(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
void SSFBNModMulNIST(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
void SSFBNDivMod(SSFBN_t *q, SSFBN_t *rem, const SSFBN_t *a, const SSFBN_t *b);
void SSFBNGcd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
bool SSFBNModInvExt(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);

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

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_BN_UNIT_TEST == 1
void SSFBNUnitTest(void);
#endif /* SSF_CONFIG_BN_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_H_INCLUDE */
