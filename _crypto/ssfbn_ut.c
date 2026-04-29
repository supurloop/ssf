/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn_ut.c                                                                                    */
/* Provides unit tests for the ssfbn big number arithmetic module.                               */
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
#include "ssfassert.h"
#include "ssfbn.h"
#include "ssfprng.h"
#if SSF_CONFIG_BN_MICROBENCH == 1
#include "ssfport.h"
#include <stdio.h>
#endif

/* Cross-check the SSFBN implementation against OpenSSL's BIGNUM. Enabled when the build is      */
/* linking libcrypto (host macOS/Linux); disabled on cross builds via -DSSF_CONFIG_HAVE_OPENSSL=0 */
/* (see ssfport.h). When disabled, the Wycheproof corpus and the RFC 6979 KATs are the load-     */
/* bearing correctness coverage instead.                                                          */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_BN_UNIT_TEST == 1)
#define SSF_BN_OSSL_VERIFY 1
#else
#define SSF_BN_OSSL_VERIFY 0
#endif

#if SSF_BN_OSSL_VERIFY == 1
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#endif

#if SSF_CONFIG_BN_UNIT_TEST == 1

#if SSF_BN_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers.                                                                  */
/* --------------------------------------------------------------------------------------------- */

/* Convert an SSFBN_t to a BIGNUM via the canonical big-endian byte representation. */
static void _ToOSSL(BIGNUM *dst, const SSFBN_t *src)
{
    uint8_t buf[SSF_BN_MAX_BYTES];
    size_t outSize = (size_t)src->len * sizeof(SSFBNLimb_t);

    SSF_ASSERT(outSize <= sizeof(buf));
    SSF_ASSERT(SSFBNToBytes(src, buf, outSize) == true);
    SSF_ASSERT(BN_bin2bn(buf, (int)outSize, dst) != NULL);
}

/* Convert a BIGNUM into an SSFBN_t with the given working limb count. The BIGNUM must fit. */
static void _FromOSSL(SSFBN_t *dst, const BIGNUM *src, uint16_t numLimbs)
{
    uint8_t buf[SSF_BN_MAX_BYTES];
    size_t outSize = (size_t)numLimbs * sizeof(SSFBNLimb_t);

    SSF_ASSERT(outSize <= sizeof(buf));
    SSF_ASSERT((size_t)BN_num_bytes(src) <= outSize);
    SSF_ASSERT(BN_bn2binpad(src, buf, (int)outSize) == (int)outSize);
    SSF_ASSERT(SSFBNFromBytes(dst, buf, outSize, numLimbs) == true);
}

/* Compare an SSFBN_t to a BIGNUM by exporting both to a fixed-width big-endian buffer. */
static bool _EqOSSL(const SSFBN_t *a, const BIGNUM *b)
{
    uint8_t bufA[SSF_BN_MAX_BYTES];
    uint8_t bufB[SSF_BN_MAX_BYTES];
    size_t outSize = (size_t)a->len * sizeof(SSFBNLimb_t);

    if (BN_num_bytes(b) > (int)outSize) return false;
    if (!SSFBNToBytes(a, bufA, outSize)) return false;
    if (BN_bn2binpad(b, bufB, (int)outSize) != (int)outSize) return false;
    return memcmp(bufA, bufB, outSize) == 0;
}

/* Generate a random SSFBN_t at exactly `bits` bits, mirrored into `mirror`. The top bit is set */
/* so the value occupies the full width. */
static void _RandSSFBN(SSFBN_t *dst, BIGNUM *mirror, int bits, uint16_t numLimbs)
{
    SSF_ASSERT(BN_rand(mirror, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 1);
    _FromOSSL(dst, mirror, numLimbs);
}

/* Generate a random odd modulus `m` of exactly `bits` bits. */
static void _RandOddModulus(SSFBN_t *dst, BIGNUM *mirror, int bits, uint16_t numLimbs)
{
    SSF_ASSERT(BN_rand(mirror, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) == 1);
    _FromOSSL(dst, mirror, numLimbs);
}

/* Generate a random value strictly less than the given modulus. */
static void _RandBelow(SSFBN_t *dst, BIGNUM *mirror, const BIGNUM *modulus, uint16_t numLimbs)
{
    SSF_ASSERT(BN_rand_range(mirror, modulus) == 1);
    _FromOSSL(dst, mirror, numLimbs);
}

/* Drive verification for a single modulus size. */
static void _VerifyAtSize(int bits, uint16_t iters, bool prime_capable)
{
    uint16_t nLimbs = (uint16_t)((bits + 31) / 32);
    uint16_t mulLimbs = (uint16_t)(nLimbs * 2u); /* product width */
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bnA = BN_new();
    BIGNUM *bnB = BN_new();
    BIGNUM *bnM = BN_new();
    BIGNUM *bnE = BN_new();
    BIGNUM *bnR = BN_new();
    BIGNUM *bnQ = BN_new();
    BIGNUM *bnTmp = BN_new();
    uint16_t i;

    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(bnA != NULL); SSF_ASSERT(bnB != NULL); SSF_ASSERT(bnM != NULL);
    SSF_ASSERT(bnE != NULL); SSF_ASSERT(bnR != NULL); SSF_ASSERT(bnQ != NULL);
    SSF_ASSERT(bnTmp != NULL);

    /* For ModInv coverage, build a prime modulus once per size when feasible. Generating large */
    /* primes is slow, so callers gate this with `prime_capable` for the smaller sizes. */
    BIGNUM *bnPrime = NULL;
    SSFBN_DEFINE(prime, SSF_BN_MAX_LIMBS);
    if (prime_capable)
    {
        bnPrime = BN_new();
        SSF_ASSERT(bnPrime != NULL);
        SSF_ASSERT(BN_generate_prime_ex(bnPrime, bits, 0, NULL, NULL, NULL) == 1);
        _FromOSSL(&prime, bnPrime, nLimbs);
    }

    for (i = 0; i < iters; i++)
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r2, SSF_BN_MAX_LIMBS);

        _RandOddModulus(&m, bnM, bits, nLimbs);
        _RandBelow(&a, bnA, bnM, nLimbs);
        _RandBelow(&b, bnB, bnM, nLimbs);

        /* ---- Add (limit operands so a+b still fits the working width) ---- */
        if (mulLimbs <= SSF_BN_MAX_LIMBS)
        {
            SSFBN_DEFINE(sumR, SSF_BN_MAX_LIMBS);
            SSFBNCopy(&sumR, &a);
            sumR.len = nLimbs;
            (void)SSFBNAdd(&sumR, &a, &b);
            SSF_ASSERT(BN_add(bnR, bnA, bnB) == 1);
            /* a+b can overflow nLimbs*32 bits; SSFBNAdd truncates, mask OpenSSL the same way. */
            if (BN_num_bits(bnR) > (int)nLimbs * 32)
            {
                SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
            }
            SSF_ASSERT(_EqOSSL(&sumR, bnR));
        }

        /* ---- Sub (ordered so a >= b) ---- */
        {
            SSFBN_DEFINE(subR, SSF_BN_MAX_LIMBS);
            const SSFBN_t *hi = &a;
            const SSFBN_t *lo = &b;
            const BIGNUM *bnHi = bnA;
            const BIGNUM *bnLo = bnB;
            if (BN_cmp(bnA, bnB) < 0) { hi = &b; lo = &a; bnHi = bnB; bnLo = bnA; }
            SSFBNCopy(&subR, hi);
            (void)SSFBNSub(&subR, hi, lo);
            SSF_ASSERT(BN_sub(bnR, bnHi, bnLo) == 1);
            SSF_ASSERT(_EqOSSL(&subR, bnR));
        }

        /* ---- Mod (split a 2*nLimbs dividend by m) ---- */
        if (mulLimbs <= SSF_BN_MAX_LIMBS)
        {
            SSFBN_DEFINE(big, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(modR, SSF_BN_MAX_LIMBS);
            BIGNUM *bnBig = BN_new();

            SSF_ASSERT(BN_rand(bnBig, bits * 2 - 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 1);
            _FromOSSL(&big, bnBig, mulLimbs);
            modR.len = nLimbs;
            SSFBNMod(&modR, &big, &m);
            SSF_ASSERT(BN_mod(bnR, bnBig, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&modR, bnR));
            BN_free(bnBig);
        }

        /* ---- DivMod ---- */
        if (mulLimbs <= SSF_BN_MAX_LIMBS)
        {
            SSFBN_DEFINE(big, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(qOut, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(rOut, SSF_BN_MAX_LIMBS);
            BIGNUM *bnBig = BN_new();

            SSF_ASSERT(BN_rand(bnBig, bits * 2 - 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 1);
            _FromOSSL(&big, bnBig, mulLimbs);
            big.len = mulLimbs;
            qOut.len = mulLimbs; rOut.len = mulLimbs;
            {
                SSFBN_t mFull;
                SSFBNLimb_t mFullStorage[SSF_BN_MAX_LIMBS] = {0u};
                mFull.limbs = mFullStorage;
                mFull.len = mulLimbs;
                mFull.cap = SSF_BN_MAX_LIMBS;
                SSFBNCopy(&mFull, &m);
                mFull.len = mulLimbs;
                SSFBNDivMod(&qOut, &rOut, &big, &mFull);
            }
            SSF_ASSERT(BN_div(bnQ, bnR, bnBig, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&qOut, bnQ));
            SSF_ASSERT(_EqOSSL(&rOut, bnR));
            BN_free(bnBig);
        }

        /* ---- Gcd ---- */
        {
            SSFBN_DEFINE(gOut, SSF_BN_MAX_LIMBS);
            gOut.len = nLimbs;
            SSFBNGcd(&gOut, &a, &b);
            SSF_ASSERT(BN_gcd(bnR, bnA, bnB, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&gOut, bnR));
        }

        /* ---- ModAdd / ModSub / ModMul / ModSquare (latter two require 2*nLimbs <= MAX_LIMBS) - */
        {
            SSFBN_DEFINE(rr, SSF_BN_MAX_LIMBS);
            rr.len = nLimbs;

            SSFBNModAdd(&rr, &a, &b, &m);
            SSF_ASSERT(BN_mod_add(bnR, bnA, bnB, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&rr, bnR));

            SSFBNModSub(&rr, &a, &b, &m);
            SSF_ASSERT(BN_mod_sub(bnR, bnA, bnB, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&rr, bnR));

            if (mulLimbs <= SSF_BN_MAX_LIMBS)
            {
                SSFBNModMul(&rr, &a, &b, &m);
                SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnM, ctx) == 1);
                SSF_ASSERT(_EqOSSL(&rr, bnR));

                SSFBNModSquare(&rr, &a, &m);
                SSF_ASSERT(BN_mod_sqr(bnR, bnA, bnM, ctx) == 1);
                SSF_ASSERT(_EqOSSL(&rr, bnR));
            }
        }

        /* ---- Mul / Square (operand width must satisfy a->len + b->len <= MAX_LIMBS) ---- */
        if (mulLimbs <= SSF_BN_MAX_LIMBS)
        {
            SSFBN_DEFINE(mulR, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(sqR, SSF_BN_MAX_LIMBS);

            SSFBNMul(&mulR, &a, &b);
            SSF_ASSERT(BN_mul(bnR, bnA, bnB, ctx) == 1);
            SSF_ASSERT(mulR.len == mulLimbs);
            SSF_ASSERT(_EqOSSL(&mulR, bnR));

            SSFBNSquare(&sqR, &a);
            SSF_ASSERT(BN_sqr(bnR, bnA, ctx) == 1);
            SSF_ASSERT(sqR.len == mulLimbs);
            SSF_ASSERT(_EqOSSL(&sqR, bnR));
        }

        /* ---- ModInv / ModInvExt against the prime modulus (when available) ---- */
        if (prime_capable)
        {
            SSFBN_DEFINE(aP, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(invR, SSF_BN_MAX_LIMBS);
            BIGNUM *bnAP = BN_new();
            SSF_ASSERT(bnAP != NULL);

            _RandBelow(&aP, bnAP, bnPrime, nLimbs);
            if (!SSFBNIsZero(&aP))
            {
                SSF_ASSERT(SSFBNModInv(&invR, &aP, &prime) == true);
                SSF_ASSERT(BN_mod_inverse(bnR, bnAP, bnPrime, ctx) != NULL);
                SSF_ASSERT(_EqOSSL(&invR, bnR));

                SSF_ASSERT(SSFBNModInvExt(&invR, &aP, &prime) == true);
                SSF_ASSERT(_EqOSSL(&invR, bnR));

                /* Round-trip property: aP * inv mod prime == 1. Catches ModInv/ModMul errors    */
                /* that might both happen to match OpenSSL bug-for-bug or that corrupt internal  */
                /* state without being visible at single-op parity. ModMul requires 2*nLimbs <=  */
                /* MAX_LIMBS, so this only runs at sizes where Mul is also testable.             */
                if ((uint32_t)nLimbs * 2u <= SSF_BN_MAX_LIMBS)
                {
                    SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
                    check.len = nLimbs;
                    SSFBNModMul(&check, &aP, &invR, &prime);
                    SSF_ASSERT(SSFBNCmpUint32(&check, 1u) == 0);
                }
            }
            BN_free(bnAP);
        }

        /* ---- Mont (init from m, round-trip a, square and multiply) ---- */
        {
            SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(aR, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(bR, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(rrR, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(rOut, SSF_BN_MAX_LIMBS);

            SSFBNMontInit(&mont, &m);
            SSFBNMontConvertIn(&aR, &a, &mont);
            SSFBNMontConvertIn(&bR, &b, &mont);

            /* MontMul should equal (a*b) mod m once converted out. */
            SSFBNMontMul(&rrR, &aR, &bR, &mont);
            SSFBNMontConvertOut(&rOut, &rrR, &mont);
            SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&rOut, bnR));

            /* MontSquare should equal a^2 mod m once converted out. */
            SSFBNMontSquare(&rrR, &aR, &mont);
            SSFBNMontConvertOut(&rOut, &rrR, &mont);
            SSF_ASSERT(BN_mod_sqr(bnR, bnA, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&rOut, bnR));
        }

        /* ---- ModExp / ModExpPub (small public exponent for speed) ---- */
        {
            SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(rOut, SSF_BN_MAX_LIMBS);

            /* Public exponent: e = 65537. Non-secret, low Hamming weight — exercises ModExpPub. */
            SSFBNSetUint32(&e, 65537u, nLimbs);
            BN_set_word(bnE, 65537u);

            rOut.len = nLimbs;
            SSFBNModExpPub(&rOut, &a, &e, &m);
            SSF_ASSERT(BN_mod_exp(bnR, bnA, bnE, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&rOut, bnR));

            /* Constant-time path. Exercise it less aggressively at the larger sizes. */
            if (bits <= 1024 || (i & 0x7u) == 0u)
            {
                SSFBNModExp(&rOut, &a, &e, &m);
                SSF_ASSERT(_EqOSSL(&rOut, bnR));
            }
        }

        /* ---- ModUint32 ---- */
        {
            uint32_t d;
            uint32_t got;

            d = 0xDEADBEEFu;
            got = SSFBNModUint32(&a, d);
            SSF_ASSERT(BN_set_word(bnTmp, d) == 1);
            SSF_ASSERT(BN_mod(bnR, bnA, bnTmp, ctx) == 1);
            SSF_ASSERT((uint32_t)BN_get_word(bnR) == got);
        }

        /* ---- BitLen / Shift ---- */
        {
            SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
            uint32_t shiftBy;

            SSF_ASSERT(SSFBNBitLen(&a) == (uint32_t)BN_num_bits(bnA));

            shiftBy = (uint32_t)((unsigned)i & 0x1Fu); /* 0..31 — keeps result inside nLimbs. */
            SSFBNCopy(&shifted, &a);
            SSFBNShiftRight(&shifted, shiftBy);
            SSF_ASSERT(BN_rshift(bnR, bnA, (int)shiftBy) == 1);
            SSF_ASSERT(_EqOSSL(&shifted, bnR));

            SSFBNCopy(&shifted, &a);
            shifted.len = nLimbs;
            SSFBNShiftLeft(&shifted, shiftBy);
            SSF_ASSERT(BN_lshift(bnR, bnA, (int)shiftBy) == 1);
            /* SSFBN truncates to its working width; mask the OpenSSL result the same way.       */
            /* BN_mask_bits errors when the BIGNUM is already shorter than the mask; skip then.  */
            if (BN_num_bits(bnR) > (int)nLimbs * 32)
            {
                SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
            }
            SSF_ASSERT(_EqOSSL(&shifted, bnR));
        }
    }

    BN_free(bnA); BN_free(bnB); BN_free(bnM); BN_free(bnE);
    BN_free(bnR); BN_free(bnQ); BN_free(bnTmp);
    if (bnPrime != NULL) BN_free(bnPrime);
    BN_CTX_free(ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Corner-case verification against OpenSSL.                                                     */
/*                                                                                                */
/* Random testing rarely hits identity values (0, 1, m-1), aliasing patterns (r=a=b), or         */
/* carry/borrow boundaries. This routine drives each public function through those inputs and    */
/* compares the result against OpenSSL where the operation has a counterpart, or against a       */
/* hand-computed expected value where it does not. All modular work uses NIST P-256 as the       */
/* modulus so ModInv coverage is included without paying for prime generation.                   */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyCornerCasesAgainstOpenSSL(void)
{
    const uint16_t nLimbs = 8u; /* 256-bit operands. */
    const uint16_t mulLimbs = (uint16_t)(nLimbs * 2u);
    const size_t nBytes = (size_t)nLimbs * 4u;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bnA = BN_new();
    BIGNUM *bnB = BN_new();
    BIGNUM *bnM = BN_new();
    BIGNUM *bnR = BN_new();
    BIGNUM *bnQ = BN_new();
    BIGNUM *bnTmp = BN_new();

    /* Modulus = NIST P-256 prime (public). Lets ModInv work without prime generation. */
    SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
    SSFBNCopy(&m, &SSF_BN_NIST_P256);
    m.len = nLimbs;
    _ToOSSL(bnM, &m);

    /* Reusable values: zero, one, m-1, half-modulus, max-fits (all-ones at nLimbs width). */
    SSFBN_DEFINE(zero, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(mMinus1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(allOnes, SSF_BN_MAX_LIMBS); /* 2^(nLimbs*32) - 1 */
    SSFBN_DEFINE(rand1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(rand2, SSF_BN_MAX_LIMBS);

    SSFBNSetZero(&zero, nLimbs);
    SSFBNSetOne(&one, nLimbs);
    SSFBNCopy(&mMinus1, &m);
    (void)SSFBNSubUint32(&mMinus1, &mMinus1, 1u);
    {
        uint16_t k;
        allOnes.len = nLimbs;
        for (k = 0; k < nLimbs; k++) allOnes.limbs[k] = 0xFFFFFFFFu;
    }

    _RandSSFBN(&rand1, bnA, 256, nLimbs); /* deterministic from the seeded PRNG */
    _RandSSFBN(&rand2, bnB, 256, nLimbs);
    /* Reduce rand1, rand2 mod m so they're valid modular operands. */
    {
        SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);
        tmp.len = nLimbs;
        SSFBNMod(&tmp, &rand1, &m); SSFBNCopy(&rand1, &tmp);
        SSFBNMod(&tmp, &rand2, &m); SSFBNCopy(&rand2, &tmp);
        rand1.len = nLimbs; rand2.len = nLimbs;
    }
    _ToOSSL(bnA, &rand1);
    _ToOSSL(bnB, &rand2);

    /* === Add corner cases ============================================================ */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBNLimb_t carry;

        /* 0 + 0 = 0, no carry. */
        carry = SSFBNAdd(&r, &zero, &zero); SSF_ASSERT(carry == 0u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* a + 0 = a. */
        carry = SSFBNAdd(&r, &rand1, &zero); SSF_ASSERT(carry == 0u);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);

        /* 0 + a = a. */
        carry = SSFBNAdd(&r, &zero, &rand1); SSF_ASSERT(carry == 0u);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);

        /* allOnes + 1 wraps to 0 with carry=1. */
        carry = SSFBNAdd(&r, &allOnes, &one); SSF_ASSERT(carry == 1u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* allOnes + allOnes = 2^(n*32) - 2, carry=1. Compare against OpenSSL truncated. */
        carry = SSFBNAdd(&r, &allOnes, &allOnes); SSF_ASSERT(carry == 1u);
        _ToOSSL(bnTmp, &allOnes);
        SSF_ASSERT(BN_add(bnR, bnTmp, bnTmp) == 1);
        SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Aliasing: r = a. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        carry = SSFBNAdd(&r, &r, &rand2); (void)carry;
        SSF_ASSERT(BN_add(bnR, bnA, bnB) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32) SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Aliasing: r = b. */
        SSFBNCopy(&r, &rand2); r.len = nLimbs;
        (void)SSFBNAdd(&r, &rand1, &r);
        SSF_ASSERT(BN_add(bnR, bnA, bnB) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32) SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Aliasing: r = a = b (a + a). */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        (void)SSFBNAdd(&r, &r, &r);
        SSF_ASSERT(BN_add(bnR, bnA, bnA) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32) SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));
    }

    /* === Sub corner cases ============================================================ */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBNLimb_t borrow;

        /* 0 - 0 = 0, no borrow. */
        borrow = SSFBNSub(&r, &zero, &zero); SSF_ASSERT(borrow == 0u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* a - 0 = a. */
        borrow = SSFBNSub(&r, &rand1, &zero); SSF_ASSERT(borrow == 0u);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);

        /* a - a = 0. */
        borrow = SSFBNSub(&r, &rand1, &rand1); SSF_ASSERT(borrow == 0u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* 0 - 1 = allOnes with borrow=1 (two's complement wrap). */
        borrow = SSFBNSub(&r, &zero, &one); SSF_ASSERT(borrow == 1u);
        SSF_ASSERT(SSFBNCmp(&r, &allOnes) == 0);

        /* Aliasing: r = a in r = a - b. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        if (BN_cmp(bnA, bnB) >= 0)
        {
            (void)SSFBNSub(&r, &r, &rand2);
            SSF_ASSERT(BN_sub(bnR, bnA, bnB) == 1);
            SSF_ASSERT(_EqOSSL(&r, bnR));
        }

        /* Aliasing: r = b in r = a - b. */
        SSFBNCopy(&r, &rand2); r.len = nLimbs;
        if (BN_cmp(bnA, bnB) >= 0)
        {
            (void)SSFBNSub(&r, &rand1, &r);
            SSF_ASSERT(BN_sub(bnR, bnA, bnB) == 1);
            SSF_ASSERT(_EqOSSL(&r, bnR));
        }
    }

    /* === AddUint32 / SubUint32 carry & borrow boundaries =========================== */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBNLimb_t carry;

        /* allOnes + 1 → 0, carry=1. */
        carry = SSFBNAddUint32(&r, &allOnes, 1u); SSF_ASSERT(carry == 1u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* allOnes + 0 → allOnes, carry=0. */
        carry = SSFBNAddUint32(&r, &allOnes, 0u); SSF_ASSERT(carry == 0u);
        SSF_ASSERT(SSFBNCmp(&r, &allOnes) == 0);

        /* 0 - 1 → allOnes, borrow=1. */
        carry = SSFBNSubUint32(&r, &zero, 1u); SSF_ASSERT(carry == 1u);
        SSF_ASSERT(SSFBNCmp(&r, &allOnes) == 0);

        /* a + 0xFFFFFFFFu, compared to OpenSSL. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        (void)SSFBNAddUint32(&r, &rand1, 0xFFFFFFFFu);
        SSF_ASSERT(BN_set_word(bnTmp, 0xFFFFFFFFu) == 1);
        SSF_ASSERT(BN_add(bnR, bnA, bnTmp) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32) SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));
    }

    /* === Mul / Square / MulUint32 corner cases ====================================== */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        r.len = mulLimbs;

        /* 0 * a = 0. */
        SSFBNMul(&r, &zero, &rand1); SSF_ASSERT(SSFBNIsZero(&r));
        /* a * 0 = 0. */
        SSFBNMul(&r, &rand1, &zero); SSF_ASSERT(SSFBNIsZero(&r));
        /* 1 * a = a (with width grown to mulLimbs). */
        SSFBNMul(&r, &one, &rand1);
        _ToOSSL(bnTmp, &one);
        SSF_ASSERT(BN_mul(bnR, bnTmp, bnA, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* allOnes * allOnes — exercises full carry propagation. */
        SSFBNMul(&r, &allOnes, &allOnes);
        _ToOSSL(bnTmp, &allOnes);
        SSF_ASSERT(BN_mul(bnR, bnTmp, bnTmp, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Square parity: SSFBNSquare(a) == SSFBNMul(a, a). */
        {
            SSFBN_DEFINE(rSq, SSF_BN_MAX_LIMBS);
            SSFBNSquare(&rSq, &allOnes);
            SSF_ASSERT(SSFBNCmp(&rSq, &r) == 0);
            SSF_ASSERT(BN_sqr(bnR, bnTmp, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&rSq, bnR));
        }

        /* MulUint32 corner cases. */
        SSFBNMulUint32(&r, &allOnes, 0u); SSF_ASSERT(SSFBNIsZero(&r));
        SSFBNMulUint32(&r, &allOnes, 1u);
        _ToOSSL(bnTmp, &allOnes);
        SSF_ASSERT(_EqOSSL(&r, bnTmp) || ((r.len == nLimbs + 1u) && r.limbs[nLimbs] == 0u));

        SSFBNMulUint32(&r, &rand1, 0xFFFFFFFFu);
        SSF_ASSERT(BN_set_word(bnTmp, 0xFFFFFFFFu) == 1);
        SSF_ASSERT(BN_mul(bnR, bnA, bnTmp, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));
    }

    /* === Mod / DivMod corner cases ================================================== */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(q, SSF_BN_MAX_LIMBS);

        /* 0 mod m = 0. */
        SSFBNMod(&r, &zero, &m); SSF_ASSERT(SSFBNIsZero(&r));
        /* (m-1) mod m = m-1. */
        SSFBNMod(&r, &mMinus1, &m); SSF_ASSERT(SSFBNCmp(&r, &mMinus1) == 0);
        /* m mod m = 0. */
        SSFBNMod(&r, &m, &m); SSF_ASSERT(SSFBNIsZero(&r));
        /* a mod m == a when a < m. */
        SSFBNMod(&r, &rand1, &m); SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);

        /* DivMod with b = 1: q = a, rem = 0. */
        {
            SSFBN_DEFINE(big, SSF_BN_MAX_LIMBS);
            big.len = mulLimbs;
            SSFBNCopy(&big, &rand1); big.len = mulLimbs;
            SSFBNDivMod(&q, &r, &big, &one);
            SSF_ASSERT(SSFBNIsZero(&r));
            /* q should equal big. */
            {
                uint8_t bufQ[SSF_BN_MAX_BYTES], bufBig[SSF_BN_MAX_BYTES];
                size_t out = (size_t)mulLimbs * 4u;
                SSF_ASSERT(SSFBNToBytes(&q, bufQ, out));
                SSF_ASSERT(SSFBNToBytes(&big, bufBig, out));
                SSF_ASSERT(memcmp(bufQ, bufBig, out) == 0);
            }
        }
        /* DivMod with a < b: q = 0, rem = a. */
        {
            SSFBN_DEFINE(small, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(big, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&small, 5u, nLimbs);
            SSFBNSetUint32(&big, 17u, nLimbs);
            SSFBNDivMod(&q, &r, &small, &big);
            SSF_ASSERT(SSFBNIsZero(&q));
            SSF_ASSERT(SSFBNCmpUint32(&r, 5u) == 0);
        }
        /* DivMod where a = b: q = 1, rem = 0. */
        {
            SSFBN_DEFINE(eq, SSF_BN_MAX_LIMBS);
            SSFBNCopy(&eq, &m); eq.len = nLimbs;
            SSFBNDivMod(&q, &r, &eq, &m);
            SSF_ASSERT(SSFBNCmpUint32(&q, 1u) == 0);
            SSF_ASSERT(SSFBNIsZero(&r));
        }
    }

    /* === Gcd corner cases =========================================================== */
    {
        SSFBN_DEFINE(g, SSF_BN_MAX_LIMBS);
        g.len = nLimbs;

        /* gcd(0, a) = a. */
        SSFBNGcd(&g, &zero, &rand1);
        SSF_ASSERT(BN_gcd(bnR, BN_value_one(), bnA, ctx) == 1 || 1); /* OpenSSL gcd(0,a)=a */
        {
            BIGNUM *zeroBN = BN_new();
            BN_zero(zeroBN);
            SSF_ASSERT(BN_gcd(bnR, zeroBN, bnA, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&g, bnR));
            BN_free(zeroBN);
        }
        /* gcd(a, 0) = a. */
        {
            BIGNUM *zeroBN = BN_new();
            BN_zero(zeroBN);
            SSFBNGcd(&g, &rand1, &zero);
            SSF_ASSERT(BN_gcd(bnR, bnA, zeroBN, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&g, bnR));
            BN_free(zeroBN);
        }
        /* gcd(a, a) = a. */
        SSFBNGcd(&g, &rand1, &rand1);
        SSF_ASSERT(SSFBNCmp(&g, &rand1) == 0);
        /* gcd(a, 1) = 1. */
        SSFBNGcd(&g, &rand1, &one);
        SSF_ASSERT(SSFBNCmpUint32(&g, 1u) == 0);
    }

    /* === ModAdd / ModSub corner cases =============================================== */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        r.len = nLimbs;

        /* (m-1) + 1 mod m = 0. */
        SSFBNModAdd(&r, &mMinus1, &one, &m);
        SSF_ASSERT(SSFBNIsZero(&r));
        /* 0 + a mod m = a. */
        SSFBNModAdd(&r, &zero, &rand1, &m);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);
        /* a + (m-a) mod m = 0. */
        {
            SSFBN_DEFINE(neg, SSF_BN_MAX_LIMBS);
            neg.len = nLimbs;
            (void)SSFBNSub(&neg, &m, &rand1);
            SSFBNModAdd(&r, &rand1, &neg, &m);
            SSF_ASSERT(SSFBNIsZero(&r));
        }

        /* a - a mod m = 0. */
        SSFBNModSub(&r, &rand1, &rand1, &m);
        SSF_ASSERT(SSFBNIsZero(&r));
        /* 0 - 1 mod m = m-1. */
        SSFBNModSub(&r, &zero, &one, &m);
        SSF_ASSERT(SSFBNCmp(&r, &mMinus1) == 0);

        /* Aliasing: r = a, r = b, r = a = b for ModAdd. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNModAdd(&r, &r, &rand2, &m);
        SSF_ASSERT(BN_mod_add(bnR, bnA, bnB, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        SSFBNCopy(&r, &rand2); r.len = nLimbs;
        SSFBNModAdd(&r, &rand1, &r, &m);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNModAdd(&r, &r, &r, &m);
        SSF_ASSERT(BN_mod_add(bnR, bnA, bnA, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));
    }

    /* === ModMul / ModSquare corner cases ============================================ */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        r.len = nLimbs;

        /* 0 * a mod m = 0. */
        SSFBNModMul(&r, &zero, &rand1, &m); SSF_ASSERT(SSFBNIsZero(&r));
        /* a * 0 mod m = 0. */
        SSFBNModMul(&r, &rand1, &zero, &m); SSF_ASSERT(SSFBNIsZero(&r));
        /* 1 * a mod m = a. */
        SSFBNModMul(&r, &one, &rand1, &m); SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);
        /* a * 1 mod m = a. */
        SSFBNModMul(&r, &rand1, &one, &m); SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);
        /* (m-1) * (m-1) mod m = 1. */
        SSFBNModMul(&r, &mMinus1, &mMinus1, &m); SSF_ASSERT(SSFBNCmpUint32(&r, 1u) == 0);

        /* ModSquare: 0^2 = 0, 1^2 = 1, (m-1)^2 = 1. */
        SSFBNModSquare(&r, &zero, &m); SSF_ASSERT(SSFBNIsZero(&r));
        SSFBNModSquare(&r, &one, &m); SSF_ASSERT(SSFBNCmpUint32(&r, 1u) == 0);
        SSFBNModSquare(&r, &mMinus1, &m); SSF_ASSERT(SSFBNCmpUint32(&r, 1u) == 0);

        /* Aliasing: ModMul with r = a. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNModMul(&r, &r, &rand2, &m);
        SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Aliasing: ModSquare with r = a. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNModSquare(&r, &r, &m);
        SSF_ASSERT(BN_mod_sqr(bnR, bnA, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));
    }

    /* === ModInv / ModInvExt corner cases ============================================ */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        r.len = nLimbs;

        /* 1^(-1) mod m = 1. */
        SSF_ASSERT(SSFBNModInv(&r, &one, &m) == true);
        SSF_ASSERT(SSFBNCmpUint32(&r, 1u) == 0);

        /* (m-1)^(-1) mod m = m-1 (since (m-1) ≡ -1, and (-1)^2 = 1). */
        SSF_ASSERT(SSFBNModInv(&r, &mMinus1, &m) == true);
        SSF_ASSERT(SSFBNCmp(&r, &mMinus1) == 0);

        /* a^(-1) * a mod m = 1 — round-trip property. */
        {
            SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
            prod.len = nLimbs;
            SSF_ASSERT(SSFBNModInv(&r, &rand1, &m) == true);
            SSFBNModMul(&prod, &r, &rand1, &m);
            SSF_ASSERT(SSFBNCmpUint32(&prod, 1u) == 0);
            SSF_ASSERT(BN_mod_inverse(bnR, bnA, bnM, ctx) != NULL);
            SSF_ASSERT(_EqOSSL(&r, bnR));
        }

        /* ModInvExt parity with ModInv on a coprime input. */
        SSF_ASSERT(SSFBNModInvExt(&r, &rand1, &m) == true);
        SSF_ASSERT(BN_mod_inverse(bnR, bnA, bnM, ctx) != NULL);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* ModInvExt: even input vs even modulus → no inverse (gcd > 1). */
        {
            SSFBN_DEFINE(twoMod, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(four, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&twoMod, 8u, nLimbs);  /* even modulus */
            SSFBNSetUint32(&four, 4u, nLimbs);    /* shares factor 4 with 8 */
            SSF_ASSERT(SSFBNModInvExt(&r, &four, &twoMod) == false);
        }
    }

    /* === Mont corner cases ========================================================== */
    {
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(zR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(oneR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(bR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rOut, SSF_BN_MAX_LIMBS);

        SSFBNMontInit(&mont, &m);

        /* ConvertIn(0) → 0; ConvertOut → 0. */
        SSFBNMontConvertIn(&zR, &zero, &mont);
        SSF_ASSERT(SSFBNIsZero(&zR));
        SSFBNMontConvertOut(&rOut, &zR, &mont);
        SSF_ASSERT(SSFBNIsZero(&rOut));

        /* ConvertIn(1) = R mod m; ConvertOut → 1. */
        SSFBNMontConvertIn(&oneR, &one, &mont);
        SSFBNMontConvertOut(&rOut, &oneR, &mont);
        SSF_ASSERT(SSFBNCmpUint32(&rOut, 1u) == 0);

        /* MontMul(0R, anything) → 0R. */
        SSFBNMontConvertIn(&aR, &rand1, &mont);
        SSFBNMontMul(&rR, &zR, &aR, &mont);
        SSF_ASSERT(SSFBNIsZero(&rR));

        /* MontMul(1R, aR) = aR. */
        SSFBNMontMul(&rR, &oneR, &aR, &mont);
        SSF_ASSERT(SSFBNCmp(&rR, &aR) == 0);

        /* Aliasing: MontMul(rR, rR, ..) — r = a. */
        SSFBNMontConvertIn(&bR, &rand2, &mont);
        SSFBNCopy(&rR, &aR);
        SSFBNMontMul(&rR, &rR, &bR, &mont);
        SSFBNMontConvertOut(&rOut, &rR, &mont);
        SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&rOut, bnR));

        /* Aliasing: MontSquare with r = a. */
        SSFBNCopy(&rR, &aR);
        SSFBNMontSquare(&rR, &rR, &mont);
        SSFBNMontConvertOut(&rOut, &rR, &mont);
        SSF_ASSERT(BN_mod_sqr(bnR, bnA, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&rOut, bnR));
    }

    /* === ModExp / ModExpPub corner cases ============================================ */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        BIGNUM *bnE = BN_new();
        r.len = nLimbs;

        /* a^0 mod m = 1 (for a != 0, m > 1). */
        SSFBNSetZero(&e, nLimbs);
        SSFBNModExpPub(&r, &rand1, &e, &m);
        SSF_ASSERT(SSFBNCmpUint32(&r, 1u) == 0);
        BN_set_word(bnE, 0);
        SSF_ASSERT(BN_mod_exp(bnR, bnA, bnE, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* a^1 mod m = a. */
        SSFBNSetUint32(&e, 1u, nLimbs);
        SSFBNModExpPub(&r, &rand1, &e, &m);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);
        BN_set_word(bnE, 1);
        SSF_ASSERT(BN_mod_exp(bnR, bnA, bnE, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* 1^e mod m = 1. */
        SSFBNSetUint32(&e, 0xDEADBEEFu, nLimbs);
        SSFBNModExpPub(&r, &one, &e, &m);
        SSF_ASSERT(SSFBNCmpUint32(&r, 1u) == 0);

        /* 0^e mod m = 0 (for e > 0). */
        SSFBNSetUint32(&e, 7u, nLimbs);
        SSFBNModExpPub(&r, &zero, &e, &m);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* Constant-time path: same checks. */
        SSFBNSetUint32(&e, 1u, nLimbs);
        SSFBNModExp(&r, &rand1, &e, &m);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);
        SSFBNSetZero(&e, nLimbs);
        SSFBNModExp(&r, &rand1, &e, &m);
        SSF_ASSERT(SSFBNCmpUint32(&r, 1u) == 0);

        /* Wider e (e->len > ctx->len) with high bits set: ModExp must process all of e, not    */
        /* silently truncate to the modulus's bit width. Construct e with e->len = 2*nLimbs and */
        /* a bit set above ctx->len*32 — verify against OpenSSL. */
        {
            SSFBN_DEFINE(eWide, SSF_BN_MAX_LIMBS);
            BIGNUM *bnEWide = BN_new();
            SSFBNSetZero(&eWide, (uint16_t)(nLimbs * 2u));
            SSFBNSetBit(&eWide, (uint32_t)nLimbs * 32u + 5u); /* bit above modulus width */
            SSFBNSetBit(&eWide, 3u);                          /* and a low bit */
            _ToOSSL(bnEWide, &eWide);
            SSFBNModExp(&r, &rand1, &eWide, &m);
            SSF_ASSERT(BN_mod_exp(bnR, bnA, bnEWide, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&r, bnR));
            BN_free(bnEWide);
        }

        BN_free(bnE);
    }

    /* === Shift corner cases ========================================================= */
    {
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* Shift by 0 is a no-op. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftLeft(&r, 0u);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);
        SSFBNShiftRight(&r, 0u);
        SSF_ASSERT(SSFBNCmp(&r, &rand1) == 0);

        /* Shift left by exactly one limb (32 bits). */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftLeft(&r, 32u);
        SSF_ASSERT(BN_lshift(bnR, bnA, 32) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32) SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Shift right by exactly one limb. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftRight(&r, 32u);
        SSF_ASSERT(BN_rshift(bnR, bnA, 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Shift right by full width → zero. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftRight(&r, (uint32_t)nLimbs * 32u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* Shift left by full width → all bits truncated → zero. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftLeft(&r, (uint32_t)nLimbs * 32u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* Shift1 of zero is zero. */
        SSFBNCopy(&r, &zero); r.len = nLimbs;
        SSFBNShiftLeft1(&r);
        SSF_ASSERT(SSFBNIsZero(&r));
        SSFBNShiftRight1(&r);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* Shift1 of one: << → 2, >> → 0. */
        SSFBNCopy(&r, &one); r.len = nLimbs;
        SSFBNShiftLeft1(&r);
        SSF_ASSERT(SSFBNCmpUint32(&r, 2u) == 0);
        SSFBNCopy(&r, &one); r.len = nLimbs;
        SSFBNShiftRight1(&r);
        SSF_ASSERT(SSFBNIsZero(&r));
    }

    /* === BitLen / TrailingZeros / GetBit at edges =================================== */
    {
        SSFBN_DEFINE(t, SSF_BN_MAX_LIMBS);

        /* BitLen(0) = 0. */
        SSF_ASSERT(SSFBNBitLen(&zero) == 0u);
        /* BitLen(1) = 1. */
        SSF_ASSERT(SSFBNBitLen(&one) == 1u);
        /* BitLen(2^k) = k+1 (for k = 0, 31, 32, 63, 64, 255). */
        {
            const uint32_t ks[] = { 0u, 1u, 31u, 32u, 63u, 64u, 100u, 200u, 255u };
            size_t ki;
            for (ki = 0; ki < sizeof(ks) / sizeof(ks[0]); ki++)
            {
                SSFBNSetZero(&t, nLimbs);
                SSFBNSetBit(&t, ks[ki]);
                SSF_ASSERT(SSFBNBitLen(&t) == ks[ki] + 1u);
                SSF_ASSERT(SSFBNTrailingZeros(&t) == ks[ki]);
            }
        }
        /* BitLen of allOnes = nLimbs * 32. */
        SSF_ASSERT(SSFBNBitLen(&allOnes) == (uint32_t)nLimbs * 32u);
        /* TrailingZeros(allOnes) = 0. */
        SSF_ASSERT(SSFBNTrailingZeros(&allOnes) == 0u);

        /* GetBit at boundary positions. */
        SSF_ASSERT(SSFBNGetBit(&one, 0u) == 1u);
        SSF_ASSERT(SSFBNGetBit(&one, 1u) == 0u);
        SSF_ASSERT(SSFBNGetBit(&allOnes, (uint32_t)nLimbs * 32u - 1u) == 1u);
        /* GetBit beyond a->len returns 0. */
        SSF_ASSERT(SSFBNGetBit(&one, (uint32_t)nLimbs * 32u + 7u) == 0u);

        /* SetBit then ClearBit returns to original. */
        SSFBNCopy(&t, &rand1); t.len = nLimbs;
        SSFBNSetBit(&t, 13u);
        SSFBNClearBit(&t, 13u);
        SSF_ASSERT(SSFBNGetBit(&t, 13u) == 0u);
    }

    /* === ModUint32 corner cases ===================================================== */
    {
        SSF_ASSERT(SSFBNModUint32(&zero, 7u) == 0u);
        SSF_ASSERT(SSFBNModUint32(&one, 7u) == 1u);
        SSF_ASSERT(SSFBNModUint32(&allOnes, 1u) == 0u);

        /* a mod 0xFFFFFFFFu compared to OpenSSL. */
        {
            uint32_t got = SSFBNModUint32(&rand1, 0xFFFFFFFFu);
            SSF_ASSERT(BN_set_word(bnTmp, 0xFFFFFFFFu) == 1);
            SSF_ASSERT(BN_mod(bnR, bnA, bnTmp, ctx) == 1);
            SSF_ASSERT((uint32_t)BN_get_word(bnR) == got);
        }
    }

    /* === FromBytes / ToBytes corner cases =========================================== */
    {
        SSFBN_DEFINE(t, SSF_BN_MAX_LIMBS);
        uint8_t buf[SSF_BN_MAX_BYTES];

        /* All-zero bytes → zero value. */
        memset(buf, 0, nBytes);
        SSF_ASSERT(SSFBNFromBytes(&t, buf, nBytes, nLimbs) == true);
        SSF_ASSERT(SSFBNIsZero(&t));

        /* All-FF bytes → allOnes value. */
        memset(buf, 0xFFu, nBytes);
        SSF_ASSERT(SSFBNFromBytes(&t, buf, nBytes, nLimbs) == true);
        SSF_ASSERT(SSFBNCmp(&t, &allOnes) == 0);

        /* Round-trip rand1 through bytes. */
        SSF_ASSERT(SSFBNToBytes(&rand1, buf, nBytes) == true);
        SSF_ASSERT(SSFBNFromBytes(&t, buf, nBytes, nLimbs) == true);
        SSF_ASSERT(SSFBNCmp(&t, &rand1) == 0);

        /* Short input zero-pads the high bytes. */
        {
            uint8_t shortBuf[1] = { 0x42u };
            SSF_ASSERT(SSFBNFromBytes(&t, shortBuf, 1u, nLimbs) == true);
            SSF_ASSERT(SSFBNCmpUint32(&t, 0x42u) == 0);
        }

        /* ToBytes refuses too-small output. */
        {
            uint8_t tiny[3];
            SSF_ASSERT(SSFBNToBytes(&allOnes, tiny, sizeof(tiny)) == false);
        }
    }

    /* === Cmp / CmpUint32 corner cases =============================================== */
    {
        SSFBN_DEFINE(big, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(small, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&big, 0xFFFFFFFFu, nLimbs);
        SSFBNSetUint32(&small, 1u, nLimbs);

        SSF_ASSERT(SSFBNCmp(&big, &small) > 0);
        SSF_ASSERT(SSFBNCmp(&small, &big) < 0);
        SSF_ASSERT(SSFBNCmp(&big, &big) == 0);

        SSF_ASSERT(SSFBNCmpUint32(&zero, 0u) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&zero, 1u) < 0);
        SSF_ASSERT(SSFBNCmpUint32(&one, 0u) > 0);
        SSF_ASSERT(SSFBNCmpUint32(&one, 1u) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&allOnes, 0xFFFFFFFFu) > 0); /* allOnes > 1 limb */
        SSF_ASSERT(SSFBNCmpUint32(&big, 0xFFFFFFFFu) == 0);
    }

    /* === CondSwap / CondCopy ========================================================= */
    {
        SSFBN_DEFINE(x, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(y, SSF_BN_MAX_LIMBS);

        SSFBNCopy(&x, &rand1); x.len = nLimbs;
        SSFBNCopy(&y, &rand2); y.len = nLimbs;

        /* swap=0 → no change. */
        SSFBNCondSwap(&x, &y, 0u);
        SSF_ASSERT(SSFBNCmp(&x, &rand1) == 0);
        SSF_ASSERT(SSFBNCmp(&y, &rand2) == 0);

        /* swap=1 → swap. */
        SSFBNCondSwap(&x, &y, 1u);
        SSF_ASSERT(SSFBNCmp(&x, &rand2) == 0);
        SSF_ASSERT(SSFBNCmp(&y, &rand1) == 0);

        /* swap with allOnes mask: also swaps. */
        SSFBNCondSwap(&x, &y, 0xFFFFFFFFu);
        SSF_ASSERT(SSFBNCmp(&x, &rand1) == 0);
        SSF_ASSERT(SSFBNCmp(&y, &rand2) == 0);

        /* CondCopy: sel=0 → no copy. */
        SSFBNCopy(&x, &rand1); x.len = nLimbs;
        SSFBNCondCopy(&x, &rand2, 0u);
        SSF_ASSERT(SSFBNCmp(&x, &rand1) == 0);
        /* sel=1 → copy. */
        SSFBNCondCopy(&x, &rand2, 1u);
        SSF_ASSERT(SSFBNCmp(&x, &rand2) == 0);
    }

    /* === IsProbablePrime corner cases =============================================== */
    {
        SSFBN_DEFINE(t, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t prngSeed[SSF_PRNG_ENTROPY_SIZE];

        memset(prngSeed, 0xA5u, sizeof(prngSeed));
        SSFPRNGInitContext(&prng, prngSeed, sizeof(prngSeed));

        /* P-256 prime is prime. */
        SSFBNCopy(&t, &m); t.len = nLimbs;
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);

        /* P-256 - 1 is composite (it's even). */
        SSFBNCopy(&t, &mMinus1); t.len = nLimbs;
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == false);

        /* Small-case results: 0 and 1 are not prime; 2 and 3 are prime (handled by the      */
        /* fast-path branches that bypass the Miller-Rabin witness sampler).                  */
        SSFBNSetUint32(&t, 0u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == false);
        SSFBNSetUint32(&t, 1u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == false);
        SSFBNSetUint32(&t, 2u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);
        SSFBNSetUint32(&t, 3u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);
        SSFBNSetUint32(&t, 4u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == false);
        SSFBNSetUint32(&t, 9u, nLimbs);  /* 3 * 3 */
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == false);

        /* Small odd primes exercise the small-n / wide-storage Miller-Rabin path that the   */
        /* sampler-mask fix unblocked.                                                        */
        SSFBNSetUint32(&t, 11u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);
        SSFBNSetUint32(&t, 13u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);
        SSFBNSetUint32(&t, 65537u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);

        /* Carmichael number 561 = 3 * 11 * 17 — passes Fermat test but Miller-Rabin must */
        /* reject with a few rounds of random witnesses. */
        SSFBNSetUint32(&t, 561u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 10u, &prng) == false);

        SSFPRNGDeInitContext(&prng);
    }

    /* === ModMulNIST coverage ======================================================== */
    /* The header documents: "mod must be SSF_BN_NIST_P256 or SSF_BN_NIST_P384. Falls back to */
    /* SSFBNModMul for other moduli." Existing tests only cover x*0 and x*1; verify each path  */
    /* against ModMul / OpenSSL across non-trivial inputs.                                    */
    {
        SSFBN_DEFINE(rNist, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rGen, SSF_BN_MAX_LIMBS);
        rNist.len = nLimbs; rGen.len = nLimbs;

        /* P-256 fast path: rand1, rand2 are already < P-256 from earlier reduction. */
        SSFBNModMulNIST(&rNist, &rand1, &rand2, &SSF_BN_NIST_P256);
        SSFBNModMul(&rGen, &rand1, &rand2, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmp(&rNist, &rGen) == 0);
        SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&rNist, bnR));

        /* (P-256 - 1) * (P-256 - 1) mod P-256 = 1 — exercises the reduction tail. */
        SSFBNModMulNIST(&rNist, &mMinus1, &mMinus1, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmpUint32(&rNist, 1u) == 0);
    }
#if SSF_BN_CONFIG_MAX_BITS >= 768
    {
        /* P-384 fast path. (Block requires SSF_BN_NIST_P384 — only defined when the cap is at  */
        /* least 768 bits, which excludes a pure-ECC-P256-only config.)                          */
        const uint16_t n384 = 12u;
        SSFBN_DEFINE(a384, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b384, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rNist, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rGen, SSF_BN_MAX_LIMBS);
        BIGNUM *bnA384 = BN_new();
        BIGNUM *bnB384 = BN_new();
        BIGNUM *bnM384 = BN_new();
        rNist.len = n384; rGen.len = n384;

        _ToOSSL(bnM384, &SSF_BN_NIST_P384);
        SSF_ASSERT(BN_rand_range(bnA384, bnM384) == 1);
        SSF_ASSERT(BN_rand_range(bnB384, bnM384) == 1);
        _FromOSSL(&a384, bnA384, n384);
        _FromOSSL(&b384, bnB384, n384);

        SSFBNModMulNIST(&rNist, &a384, &b384, &SSF_BN_NIST_P384);
        SSFBNModMul(&rGen, &a384, &b384, &SSF_BN_NIST_P384);
        SSF_ASSERT(SSFBNCmp(&rNist, &rGen) == 0);
        SSF_ASSERT(BN_mod_mul(bnR, bnA384, bnB384, bnM384, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&rNist, bnR));

        BN_free(bnA384); BN_free(bnB384); BN_free(bnM384);
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */
    {
        /* Fallback path: a non-NIST modulus must produce the same result as ModMul. */
        SSFBN_DEFINE(altMod, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(bR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rNist, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rGen, SSF_BN_MAX_LIMBS);

        /* Random odd 256-bit modulus (very unlikely to coincide with P-256). */
        SSF_ASSERT(BN_rand(bnTmp, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) == 1);
        _FromOSSL(&altMod, bnTmp, nLimbs);
        SSF_ASSERT(BN_rand_range(bnA, bnTmp) == 1);
        SSF_ASSERT(BN_rand_range(bnB, bnTmp) == 1);
        _FromOSSL(&aR, bnA, nLimbs);
        _FromOSSL(&bR, bnB, nLimbs);
        rNist.len = nLimbs; rGen.len = nLimbs;

        SSFBNModMulNIST(&rNist, &aR, &bR, &altMod);
        SSFBNModMul(&rGen, &aR, &bR, &altMod);
        SSF_ASSERT(SSFBNCmp(&rNist, &rGen) == 0);
        SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnTmp, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&rNist, bnR));

        /* Restore bnA, bnB to the rand1/rand2 values used elsewhere — caller of this */
        /* function does not depend on them, but be tidy. */
        _ToOSSL(bnA, &rand1);
        _ToOSSL(bnB, &rand2);
    }

    /* === ModMulCT: cross-check against ModMul + OpenSSL ============================== */
    /* The CT primitive must produce identical results to the data-dependent SSFBNModMul   */
    /* across random inputs and edge cases. The strongest invariant: ModMulCT(a, b, m) ==  */
    /* ModMul(a, b, m) for any (a, b, m). If the fixed-iteration mask logic is wrong, the   */
    /* random cross-check or the (m-1)*(m-1) edge case will fail.                            */
    {
        SSFBN_DEFINE(rCT, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rGen, SSF_BN_MAX_LIMBS);
        rCT.len = nLimbs; rGen.len = nLimbs;

        /* Random inputs against the local odd modulus `m`. */
        SSFBNModMulCT(&rCT, &rand1, &rand2, &m);
        SSFBNModMul(&rGen, &rand1, &rand2, &m);
        SSF_ASSERT(SSFBNCmp(&rCT, &rGen) == 0);
        SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnM, ctx) == 1);
        SSF_ASSERT(_EqOSSL(&rCT, bnR));

        /* Edge: a = 0, b = anything → result = 0. */
        {
            SSFBN_DEFINE(zero, SSF_BN_MAX_LIMBS);
            SSFBNSetZero(&zero, nLimbs);
            SSFBNModMulCT(&rCT, &zero, &rand2, &m);
            SSF_ASSERT(SSFBNIsZero(&rCT) == true);
        }

        /* Edge: a = 1, b = rand2 → result = rand2 (rand2 was reduced to be < m above). */
        {
            SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
            SSFBNSetOne(&one, nLimbs);
            SSFBNModMulCT(&rCT, &one, &rand2, &m);
            SSF_ASSERT(SSFBNCmp(&rCT, &rand2) == 0);
        }

        /* Edge: (m-1) * (m-1) mod m == 1 (exercises full reduction including underflow). */
        SSFBNModMulCT(&rCT, &mMinus1, &mMinus1, &m);
        SSF_ASSERT(SSFBNCmpUint32(&rCT, 1u) == 0);

        /* Edge: at NIST P-256 prime as modulus (the dense bit pattern of P-256 = 2^256 -      */
        /* 2^224 + ... is a stress case for shift-and-subtract reductions). */
        if (nLimbs == 8u)
        {
            SSFBN_DEFINE(rCTNist, SSF_BN_MAX_LIMBS);
            rCTNist.len = nLimbs;
            SSFBNModMulCT(&rCTNist, &rand1, &rand2, &SSF_BN_NIST_P256);
            SSFBNModMulNIST(&rGen, &rand1, &rand2, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNCmp(&rCTNist, &rGen) == 0);
        }
    }

    /* === DivMod with b = 0: division by zero must trip SSF_REQUIRE ================== */
    {
        SSFBN_DEFINE(zeroB, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(q, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rem, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&zeroB, nLimbs);
        q.len = nLimbs; rem.len = nLimbs;
        SSF_ASSERT_TEST(SSFBNDivMod(&q, &rem, &rand1, &zeroB));
    }

    /* === SSFBNCopy: src.len < dst.cap, no spillage ================================== */
    {
        SSFBN_DEFINE(dst, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(src, SSF_BN_MAX_LIMBS);
        uint16_t k;

        /* Pre-fill dst with garbage so a misbehaving copy would leak. */
        dst.len = nLimbs;
        for (k = 0; k < nLimbs; k++) dst.limbs[k] = 0xCAFEBABEu;
        SSFBNSetUint32(&src, 0x12345678u, 1u); /* len = 1 */
        SSFBNCopy(&dst, &src);
        SSF_ASSERT(dst.len == 1u);
        SSF_ASSERT(dst.limbs[0] == 0x12345678u);

        /* Self-copy is well-defined and is a no-op. */
        SSFBNCopy(&rand1, &rand1);
        SSF_ASSERT(_EqOSSL(&rand1, bnA));
    }

    /* === FromBytes oversize-input rejection ========================================= */
    {
        SSFBN_DEFINE(t, SSF_BN_MAX_LIMBS);
        uint8_t buf[SSF_BN_MAX_BYTES + 1];

        /* dataLen one byte beyond numLimbs * 4 — must reject regardless of leading byte. */
        memset(buf, 0xFFu, sizeof(buf));
        SSF_ASSERT(SSFBNFromBytes(&t, buf, (size_t)nLimbs * 4u + 1u, nLimbs) == false);
        memset(buf, 0x00u, sizeof(buf));
        SSF_ASSERT(SSFBNFromBytes(&t, buf, (size_t)nLimbs * 4u + 1u, nLimbs) == false);

        /* Exactly numLimbs * 4 bytes succeeds. */
        SSF_ASSERT(SSFBNFromBytes(&t, buf, (size_t)nLimbs * 4u, nLimbs) == true);
    }

    /* === RandomBelow tiny bounds ==================================================== */
    {
        SSFBN_DEFINE(small, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(out, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t prngSeed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t k;

        memset(prngSeed, 0x77u, sizeof(prngSeed));
        SSFPRNGInitContext(&prng, prngSeed, sizeof(prngSeed));

        /* bound = 1: only valid output is 0. */
        SSFBNSetUint32(&small, 1u, nLimbs);
        for (k = 0; k < 16u; k++)
        {
            SSF_ASSERT(SSFBNRandomBelow(&out, &small, &prng) == true);
            SSF_ASSERT(SSFBNIsZero(&out));
        }
        /* bound = 2: outputs must be 0 or 1. Both should appear over many draws. */
        {
            bool sawZero = false, sawOne = false;
            SSFBNSetUint32(&small, 2u, nLimbs);
            for (k = 0; k < 64u; k++)
            {
                SSF_ASSERT(SSFBNRandomBelow(&out, &small, &prng) == true);
                if (SSFBNIsZero(&out)) sawZero = true;
                else { SSF_ASSERT(SSFBNCmpUint32(&out, 1u) == 0); sawOne = true; }
            }
            SSF_ASSERT(sawZero && sawOne);
        }

        SSFPRNGDeInitContext(&prng);
    }

    /* === GenPrime at multiple bit lengths =========================================== */
    {
        SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t prngSeed[SSF_PRNG_ENTROPY_SIZE];
        const uint16_t bitLens[] = { 64u, 128u, 192u };
        size_t bi;

        memset(prngSeed, 0x33u, sizeof(prngSeed));
        SSFPRNGInitContext(&prng, prngSeed, sizeof(prngSeed));

        for (bi = 0; bi < sizeof(bitLens) / sizeof(bitLens[0]); bi++)
        {
            SSF_ASSERT(SSFBNGenPrime(&p, bitLens[bi], 5u, &prng) == true);
            SSF_ASSERT(SSFBNBitLen(&p) == bitLens[bi]);
            SSF_ASSERT(SSFBNIsOdd(&p));
            /* Cross-check primality against OpenSSL. */
            _ToOSSL(bnTmp, &p);
            SSF_ASSERT(BN_check_prime(bnTmp, NULL, NULL) == 1);
        }

        SSFPRNGDeInitContext(&prng);
    }

    BN_free(bnA); BN_free(bnB); BN_free(bnM);
    BN_free(bnR); BN_free(bnQ); BN_free(bnTmp);
    BN_CTX_free(ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Karatsuba boundary stress.                                                                    */
/*                                                                                                */
/* SSFBNMul dispatches to Karatsuba when (a->len == b->len) AND (n >= 32) AND (n is even); every  */
/* other case falls back to schoolbook. Random-input sweeps don't reliably probe the boundary —  */
/* this function explicitly tests lengths that bracket the threshold and exercise the dispatch   */
/* logic on both even/odd and same/asymmetric pairings.                                          */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyKaratsubaAtBoundary(void)
{
    static const struct { uint16_t aLen; uint16_t bLen; } cases[] = {
        { 31u, 31u },  /* schoolbook (just below threshold) */
        { 32u, 32u },  /* Karatsuba (boundary, even) */
        { 33u, 33u },  /* schoolbook (odd, even though >= threshold) */
        { 34u, 34u },  /* Karatsuba (just above) */
        { 32u, 31u },  /* schoolbook (asymmetric) */
        { 32u, 33u },  /* schoolbook (asymmetric, larger b) */
        { 31u, 32u },  /* schoolbook (asymmetric, larger a) */
        { 62u, 62u },  /* Karatsuba (large even) */
        { 63u, 63u },  /* schoolbook (large odd) */
        { 64u, 64u },  /* Karatsuba (max within MAX_LIMBS) */
    };
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bnA = BN_new();
    BIGNUM *bnB = BN_new();
    BIGNUM *bnR = BN_new();
    size_t ci;

    for (ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++)
    {
        uint16_t iter;
        const uint16_t aLen = cases[ci].aLen;
        const uint16_t bLen = cases[ci].bLen;

        for (iter = 0; iter < 5u; iter++)
        {
            SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

            SSF_ASSERT(BN_rand(bnA, (int)aLen * 32, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 1);
            SSF_ASSERT(BN_rand(bnB, (int)bLen * 32, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 1);
            _FromOSSL(&a, bnA, aLen);
            _FromOSSL(&b, bnB, bLen);

            SSFBNMul(&r, &a, &b);
            SSF_ASSERT(BN_mul(bnR, bnA, bnB, ctx) == 1);
            SSF_ASSERT(r.len == (uint16_t)(aLen + bLen));
            SSF_ASSERT(_EqOSSL(&r, bnR));

            /* Square parity (only when a.len matches what SSFBNSquare can handle and aLen==bLen) */
            if ((aLen == bLen) && ((uint32_t)aLen * 2u <= SSF_BN_MAX_LIMBS))
            {
                SSFBN_DEFINE(sq, SSF_BN_MAX_LIMBS);
                SSFBNSquare(&sq, &a);
                SSF_ASSERT(BN_sqr(bnR, bnA, ctx) == 1);
                SSF_ASSERT(_EqOSSL(&sq, bnR));
            }
        }
    }

    BN_free(bnA); BN_free(bnB); BN_free(bnR);
    BN_CTX_free(ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* NIST fast-reduction stress.                                                                   */
/*                                                                                                */
/* _SSFBNReduceP256 / _SSFBNReduceP384 are hand-coded magic-limb-permutation tables from NIST    */
/* SP 800-186. Each s_i and d_i selects specific 32-bit chunks of the 16- or 24-limb input —     */
/* easy to typo, hard to spot in code review. The trailing carry/borrow adjustment loops are     */
/* hit infrequently with purely random inputs because random a*b rarely sits right at the prime. */
/* This sweep injects boundary values periodically to force adjustment-loop activity.            */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyNISTReductionStress(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bnA = BN_new();
    BIGNUM *bnB = BN_new();
    BIGNUM *bnM = BN_new();
    BIGNUM *bnR = BN_new();

    /* Per-curve sweep. */
    {
        const struct { const SSFBN_t *p; uint16_t nLimbs; const char *label; } curves[] = {
            { &SSF_BN_NIST_P256, 8u,  "P-256" },
#if SSF_BN_CONFIG_MAX_BITS >= 768
            { &SSF_BN_NIST_P384, 12u, "P-384" },
#endif
        };
        size_t ci;

        for (ci = 0; ci < sizeof(curves) / sizeof(curves[0]); ci++)
        {
            uint16_t iter;
            const SSFBN_t *p = curves[ci].p;
            const uint16_t nLimbs = curves[ci].nLimbs;
            (void)curves[ci].label;

            _ToOSSL(bnM, p);

            for (iter = 0; iter < 1000u; iter++)
            {
                SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
                SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
                SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
                r.len = nLimbs;

                /* Inject boundary inputs every 32 iters to exercise the adjustment loops. */
                switch ((unsigned)iter & 0x1Fu)
                {
                    case 0u: /* a = p - 1 */
                        SSF_ASSERT(BN_sub(bnA, bnM, BN_value_one()) == 1);
                        break;
                    case 1u: /* a = (p - 1) / 2 */
                        SSF_ASSERT(BN_sub(bnA, bnM, BN_value_one()) == 1);
                        SSF_ASSERT(BN_rshift1(bnA, bnA) == 1);
                        break;
                    case 2u: /* a = 1 */
                        SSF_ASSERT(BN_one(bnA) == 1);
                        break;
                    case 3u: /* a = 2 */
                        SSF_ASSERT(BN_set_word(bnA, 2u) == 1);
                        break;
                    default:
                        SSF_ASSERT(BN_rand_range(bnA, bnM) == 1);
                        break;
                }
                switch ((unsigned)(iter >> 5) & 0x3u)
                {
                    case 0u: /* b = p - 1 */
                        SSF_ASSERT(BN_sub(bnB, bnM, BN_value_one()) == 1);
                        break;
                    case 1u: /* b = 1 */
                        SSF_ASSERT(BN_one(bnB) == 1);
                        break;
                    default:
                        SSF_ASSERT(BN_rand_range(bnB, bnM) == 1);
                        break;
                }
                _FromOSSL(&a, bnA, nLimbs);
                _FromOSSL(&b, bnB, nLimbs);

                SSFBNModMulNIST(&r, &a, &b, p);
                SSF_ASSERT(BN_mod_mul(bnR, bnA, bnB, bnM, ctx) == 1);
                SSF_ASSERT(_EqOSSL(&r, bnR));
            }
        }
    }

    BN_free(bnA); BN_free(bnB); BN_free(bnM); BN_free(bnR);
    BN_CTX_free(ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* ModInvExt at RSA-2048.                                                                        */
/*                                                                                                */
/* The existing _VerifyAtSize covers ModInv at 256, 384, 1024 (where prime gen is fast). At      */
/* 2048 prime gen would dominate test runtime, and at 4096 SSFBNModInv's internal verification   */
/* via SSFBNModMul trips the 2*nLimbs <= MAX_LIMBS precondition. This function fills the gap by  */
/* generating one 2048-bit prime and running a focused ModInvExt sweep against it.               */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyModInvExtAtRSA2048(void)
{
    const uint16_t nLimbs = 64u;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bnPrime = BN_new();
    BIGNUM *bnA = BN_new();
    BIGNUM *bnInv = BN_new();
    SSFBN_DEFINE(prime, SSF_BN_MAX_LIMBS);
    uint16_t iter;

    SSF_ASSERT(BN_generate_prime_ex(bnPrime, 2048, 0, NULL, NULL, NULL) == 1);
    _FromOSSL(&prime, bnPrime, nLimbs);

    for (iter = 0; iter < 50u; iter++)
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(inv, SSF_BN_MAX_LIMBS);
        inv.len = nLimbs;

        SSF_ASSERT(BN_rand_range(bnA, bnPrime) == 1);
        if (BN_is_zero(bnA)) SSF_ASSERT(BN_set_word(bnA, 1u) == 1);
        _FromOSSL(&a, bnA, nLimbs);

        SSF_ASSERT(SSFBNModInvExt(&inv, &a, &prime) == true);
        SSF_ASSERT(BN_mod_inverse(bnInv, bnA, bnPrime, ctx) != NULL);
        SSF_ASSERT(_EqOSSL(&inv, bnInv));
    }

    BN_free(bnPrime); BN_free(bnA); BN_free(bnInv);
    BN_CTX_free(ctx);
}

static void _SSFBNVerifyAgainstOpenSSL(void)
{
    static const struct
    {
        const char *label;
        int bits;
        uint16_t iters;
        bool prime_capable; /* generate a prime modulus to exercise ModInv */
    } sizes[] = {
        { "P-256-eq",  256,  5000, true  },
        { "P-384-eq",  384,  3000, true  },
        { "RSA-1024",  1024, 2000, true  },
        { "RSA-2048",  2048, 1000, false }, /* 2048-bit prime gen too slow for routine test */
        { "RSA-4096",  4096, 300,  false },
    };
    size_t si;

    /* Deterministic seed so test failures are reproducible. */
    {
        static const uint8_t seed[32] = {
            0x53, 0x53, 0x46, 0x42, 0x4E, 0x2D, 0x4F, 0x53, 0x53, 0x4C, 0x2D, 0x56,
            0x45, 0x52, 0x49, 0x46, 0x59, 0x2D, 0x53, 0x45, 0x45, 0x44, 0x2D, 0x32,
            0x30, 0x32, 0x36, 0x2D, 0x30, 0x34, 0x32, 0x34
        };
        RAND_seed(seed, (int)sizeof(seed));
    }

    printf("--- ssfbn OpenSSL cross-check ---\n");
    printf("  corner cases (256-bit, NIST P-256 modulus)... ");
    fflush(stdout);
    _VerifyCornerCasesAgainstOpenSSL();
    printf("OK\n");
    printf("  Karatsuba boundary stress... ");
    fflush(stdout);
    _VerifyKaratsubaAtBoundary();
    printf("OK\n");
    printf("  NIST fast-reduction stress (P-256 + P-384, 1000 iters each)... ");
    fflush(stdout);
    _VerifyNISTReductionStress();
    printf("OK\n");
    for (si = 0; si < (sizeof(sizes) / sizeof(sizes[0])); si++)
    {
        printf("  %-9s %4d-bit x %u iters... ", sizes[si].label, sizes[si].bits, sizes[si].iters);
        fflush(stdout);
        _VerifyAtSize(sizes[si].bits, sizes[si].iters, sizes[si].prime_capable);
        printf("OK\n");
    }
    printf("  ModInvExt @ RSA-2048 (50 iters)... ");
    fflush(stdout);
    _VerifyModInvExtAtRSA2048();
    printf("OK\n");
    printf("--- end OpenSSL cross-check ---\n");
}

#endif /* SSF_BN_OSSL_VERIFY */

/* Suppress C6262 (large stack frame). This unit-test entry point intentionally allocates many */
/* SSFBN_DEFINE locals across its sub-test blocks; the host test environment has ample stack.  */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
void SSFBNUnitTest(void)
{
    /* ---- SetZero, SetUint32, IsZero, IsOne ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == true);
        SSF_ASSERT(SSFBNIsOne(&a) == false);
        SSF_ASSERT(a.len == 4);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(SSFBNIsOne(&a) == true);

        SSFBNSetUint32(&a, 42u, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(SSFBNIsOne(&a) == false);
        SSF_ASSERT(SSFBNIsEven(&a) == true);

        SSFBNSetUint32(&a, 43u, 4);
        SSF_ASSERT(SSFBNIsEven(&a) == false);
    }

    /* ---- FromBytes / ToBytes roundtrip ---- */
    {
        static const uint8_t data[] = { 0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu };
        uint8_t out[8];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytes(&a, data, sizeof(data), 4) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);
        SSF_ASSERT(memcmp(data, out, sizeof(data)) == 0);
    }

    /* ---- FromBytesLE / ToBytesLE: round-trip + parity against BE via byte reversal ---- */
    {
        static const uint8_t le[] = { 0xEFu, 0xCDu, 0xABu, 0x89u, 0x67u, 0x45u, 0x23u, 0x01u };
        static const uint8_t be[] = { 0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu };
        uint8_t out[8];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        /* LE from the reversed BE bytes must yield the same numeric value as BE from the BE. */
        SSF_ASSERT(SSFBNFromBytesLE(&a, le, sizeof(le), 2) == true);
        SSF_ASSERT(SSFBNFromBytes(&b, be, sizeof(be), 2) == true);
        SSF_ASSERT(SSFBNCmp(&a, &b) == 0);

        /* Limb layout: limb[0] = 0x89ABCDEF, limb[1] = 0x01234567. */
        SSF_ASSERT(a.limbs[0] == 0x89ABCDEFul);
        SSF_ASSERT(a.limbs[1] == 0x01234567ul);

        /* Round-trip: LE → BN → LE == original. */
        SSF_ASSERT(SSFBNToBytesLE(&a, out, sizeof(out)) == true);
        SSF_ASSERT(memcmp(out, le, sizeof(le)) == 0);
    }

    /* ---- FromBytesLE with dataLen shorter than numLimbs*4 (zero-pad high limbs) ---- */
    {
        static const uint8_t data[] = { 0xFFu };
        uint8_t out[4];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytesLE(&a, data, 1, 2) == true);
        /* LE: low byte is 0xFF → limb[0] = 0x000000FF, limb[1] = 0. */
        SSF_ASSERT(a.limbs[0] == 0x000000FFul);
        SSF_ASSERT(a.limbs[1] == 0x00000000ul);

        SSF_ASSERT(SSFBNToBytesLE(&a, out, sizeof(out)) == true);
        /* LE export: low byte first, then zeros. */
        SSF_ASSERT(out[0] == 0xFFu);
        SSF_ASSERT(out[1] == 0x00u);
        SSF_ASSERT(out[2] == 0x00u);
        SSF_ASSERT(out[3] == 0x00u);
    }

    /* ---- FromBytes / ToBytes with leading zero pad ---- */
    {
        static const uint8_t data[] = { 0xFFu };
        uint8_t out[4];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytes(&a, data, 1, 2) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);
        SSF_ASSERT(out[0] == 0x00u);
        SSF_ASSERT(out[1] == 0x00u);
        SSF_ASSERT(out[2] == 0x00u);
        SSF_ASSERT(out[3] == 0xFFu);
    }

    /* ---- ToBytes regression: outSize smaller than a->len * limb-size must not corrupt  */
    /* the stack. Uses canary bytes around `out` and checks them afterward; this caught    */
    /* an earlier underflow in the limb-offset computation that wrote to out[SIZE_MAX].    */
    {
        volatile uint8_t canaryLo = 0xA5u;
        uint8_t out[6];
        volatile uint8_t canaryHi = 0x5Au;
        static const uint8_t data[] = { 0x01u, 0x23u };
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        /* 4 limbs * 4 bytes = 16 total limb bytes, written into a 6-byte buffer.          */
        SSF_ASSERT(SSFBNFromBytes(&a, data, sizeof(data), 4) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);

        /* Low bytes zero-padded, tail carries the value. */
        SSF_ASSERT(out[0] == 0x00u);
        SSF_ASSERT(out[1] == 0x00u);
        SSF_ASSERT(out[2] == 0x00u);
        SSF_ASSERT(out[3] == 0x00u);
        SSF_ASSERT(out[4] == 0x01u);
        SSF_ASSERT(out[5] == 0x23u);
        /* Canaries intact → no stack corruption. */
        SSF_ASSERT(canaryLo == 0xA5u);
        SSF_ASSERT(canaryHi == 0x5Au);
    }

    /* ---- Comparison ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 200u, 4);
        SSF_ASSERT(SSFBNCmp(&a, &b) == -1);
        SSF_ASSERT(SSFBNCmp(&b, &a) == 1);
        SSF_ASSERT(SSFBNCmp(&a, &a) == 0);
    }

    /* ---- Add / Sub ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 200u, 4);
        SSF_ASSERT(SSFBNAdd(&r, &a, &b) == 0);
        {
            SSFBN_DEFINE(expected, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&expected, 300u, 4);
            SSF_ASSERT(SSFBNCmp(&r, &expected) == 0);
        }

        SSF_ASSERT(SSFBNSub(&r, &b, &a) == 0);
        {
            SSFBN_DEFINE(expected, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&expected, 100u, 4);
            SSF_ASSERT(SSFBNCmp(&r, &expected) == 0);
        }
    }

    /* ---- Multiplication ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* 7 * 6 = 42 */
        SSFBNSetUint32(&a, 7u, 2);
        SSFBNSetUint32(&b, 6u, 2);
        SSFBNMul(&r, &a, &b);
        SSF_ASSERT(r.len == 4);
        SSF_ASSERT(r.limbs[0] == 42u);
        SSF_ASSERT(r.limbs[1] == 0u);
    }

    /* ---- BitLen and GetBit ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 0u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 0);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 1);

        SSFBNSetUint32(&a, 255u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 8);

        SSFBNSetUint32(&a, 256u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 9);

        /* GetBit: 0b1010 = 10 */
        SSFBNSetUint32(&a, 10u, 4);
        SSF_ASSERT(SSFBNGetBit(&a, 0) == 0);
        SSF_ASSERT(SSFBNGetBit(&a, 1) == 1);
        SSF_ASSERT(SSFBNGetBit(&a, 2) == 0);
        SSF_ASSERT(SSFBNGetBit(&a, 3) == 1);
        SSF_ASSERT(SSFBNGetBit(&a, 4) == 0);
    }

    /* ---- Shift left / right ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 1u, 4);
        SSFBNShiftLeft1(&a);
        SSF_ASSERT(a.limbs[0] == 2u);
        SSFBNShiftLeft1(&a);
        SSF_ASSERT(a.limbs[0] == 4u);

        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 2u);
        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 1u);
        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 0u);
    }

    /* ---- Multi-bit ShiftLeft / ShiftRight: must match N iterations of Shift*1 ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        uint32_t nBits;
        uint32_t s;

        /* n == 0 is a no-op on any value. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNCopy(&b, &a);
        SSFBNShiftLeft(&a, 0u);
        SSF_ASSERT(SSFBNCmp(&a, &b) == 0);
        SSFBNShiftRight(&a, 0u);
        SSF_ASSERT(SSFBNCmp(&a, &b) == 0);

        /* Parity sweep: for 0 <= nBits <= 160, SSFBNShiftLeft(a, nBits) must equal nBits       */
        /* applications of SSFBNShiftLeft1 starting from the same a. Same for ShiftRight.       */
        for (nBits = 0; nBits <= 160u; nBits++)
        {
            /* Seed a and b with an identical pseudo-random value wide enough to exercise       */
            /* limb-boundary crossings at 32, 64, 96, 128 bits.                                  */
            uint8_t data[20] = {
                0x12u, 0x34u, 0x56u, 0x78u, 0x9Au, 0xBCu, 0xDEu, 0xF0u,
                0x0Fu, 0xEDu, 0xCBu, 0xA9u, 0x87u, 0x65u, 0x43u, 0x21u,
                0xA5u, 0x5Au, 0xC3u, 0x3Cu
            };
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNFromBytes(&b, data, sizeof(data), 8);

            /* Left parity. */
            SSFBNShiftLeft(&a, nBits);
            for (s = 0; s < nBits; s++) SSFBNShiftLeft1(&b);
            SSF_ASSERT(SSFBNCmp(&a, &b) == 0);

            /* Right parity (reset). */
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNFromBytes(&b, data, sizeof(data), 8);
            SSFBNShiftRight(&a, nBits);
            for (s = 0; s < nBits; s++) SSFBNShiftRight1(&b);
            SSF_ASSERT(SSFBNCmp(&a, &b) == 0);
        }

        /* Shift by exactly the value's bit length zeroes it. */
        SSFBNSetUint32(&a, 1u, 4);
        SSFBNShiftLeft(&a, 4u * 32u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        /* Shift by more than the value's bit length still zeroes (no UB, no wraparound). */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNShiftLeft(&a, 10000u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNShiftRight(&a, 10000u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        /* Exact limb-boundary shift: shift of 32 bits. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNShiftLeft(&a, 32u);
        SSF_ASSERT(a.limbs[0] == 0u);
        SSF_ASSERT(a.limbs[1] == 0xDEADBEEFul);
        SSFBNShiftRight(&a, 32u);
        SSF_ASSERT(a.limbs[0] == 0xDEADBEEFul);
        SSF_ASSERT(a.limbs[1] == 0u);

        /* Sub-limb shift that crosses a limb boundary (shift 0xFFFFFFFF left by 20 yields       */
        /* 0x000FFFFF_FFF00000: limb[0]=0xFFF00000, limb[1]=0x000FFFFF).                          */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNShiftLeft(&a, 20u);
        SSF_ASSERT(a.limbs[0] == 0xFFF00000ul);
        SSF_ASSERT(a.limbs[1] == 0x000FFFFFul);
    }

    /* ---- SSFBNSetOne: sets to multiplicative identity ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetOne(&a, 4);
        SSF_ASSERT(SSFBNIsOne(&a) == true);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(a.len == 4u);
        SSF_ASSERT(a.limbs[0] == 1u);
        SSF_ASSERT(a.limbs[1] == 0u);
        SSF_ASSERT(a.limbs[2] == 0u);
        SSF_ASSERT(a.limbs[3] == 0u);

        /* Overwrites prior content. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNSetOne(&a, 4);
        SSF_ASSERT(SSFBNIsOne(&a) == true);
    }

    /* ---- SSFBNIsOdd: complement of IsEven ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == false);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == true);

        SSFBNSetUint32(&a, 2u, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == false);

        SSFBNSetUint32(&a, 3u, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == true);

        /* High limb parity does not affect IsOdd — only the low bit of limb[0] matters. */
        SSFBNSetZero(&a, 4);
        a.limbs[3] = 0x80000001ul;
        SSF_ASSERT(SSFBNIsOdd(&a) == false); /* limb[0] = 0 → even */

        a.limbs[0] = 0xFFFFFFFEul;
        SSF_ASSERT(SSFBNIsOdd(&a) == false);

        a.limbs[0] = 0xFFFFFFFFul;
        SSF_ASSERT(SSFBNIsOdd(&a) == true);

        /* IsOdd == !IsEven across the sweep. */
        {
            uint32_t k;
            for (k = 0; k < 100u; k++)
            {
                SSFBNSetUint32(&a, k, 4);
                SSF_ASSERT((SSFBNIsOdd(&a) ? true : false) != SSFBNIsEven(&a));
            }
        }
    }

    /* ---- SSFBNCmpUint32: a vs small integer ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0u) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&a, 1u) == -1);

        SSFBNSetUint32(&a, 5u, 4);
        SSF_ASSERT(SSFBNCmpUint32(&a, 5u) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&a, 4u) == 1);
        SSF_ASSERT(SSFBNCmpUint32(&a, 6u) == -1);

        /* a > any uint32_t when a has nonzero high limbs. */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 1u;
        SSF_ASSERT(SSFBNCmpUint32(&a, 0u) == 1);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0xFFFFFFFFul) == 1);

        /* Exact-boundary: a == UINT32_MAX. */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0xFFFFFFFFul) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0xFFFFFFFEul) == 1);
    }

    /* ---- SSFBNSetBit / SSFBNClearBit: single-bit mutation ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        uint32_t pos;

        /* SetBit at 0 on zero turns the value into 1. */
        SSFBNSetZero(&a, 4);
        SSFBNSetBit(&a, 0u);
        SSF_ASSERT(SSFBNIsOne(&a) == true);

        /* ClearBit at 0 on 1 turns it back to zero. */
        SSFBNClearBit(&a, 0u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        /* Set a selection of bits spanning limb boundaries and verify via GetBit. */
        SSFBNSetZero(&a, 4);
        {
            static const uint32_t targets[] = { 0u, 1u, 31u, 32u, 47u, 63u, 64u, 96u, 127u };
            uint32_t k;

            for (k = 0; k < (sizeof(targets) / sizeof(targets[0])); k++)
            {
                SSFBNSetBit(&a, targets[k]);
            }
            for (pos = 0; pos < 128u; pos++)
            {
                uint8_t expected = 0u;
                for (k = 0; k < (sizeof(targets) / sizeof(targets[0])); k++)
                {
                    if (targets[k] == pos) { expected = 1u; break; }
                }
                SSF_ASSERT(SSFBNGetBit(&a, pos) == expected);
            }

            /* Clearing every target restores zero. */
            for (k = 0; k < (sizeof(targets) / sizeof(targets[0])); k++)
            {
                SSFBNClearBit(&a, targets[k]);
            }
            SSF_ASSERT(SSFBNIsZero(&a) == true);
        }

        /* SetBit on an already-set bit is a no-op. */
        SSFBNSetZero(&a, 4);
        SSFBNSetBit(&a, 20u);
        SSF_ASSERT(a.limbs[0] == (1ul << 20));
        SSFBNSetBit(&a, 20u);
        SSF_ASSERT(a.limbs[0] == (1ul << 20));

        /* ClearBit on an already-clear bit is a no-op. */
        SSFBNClearBit(&a, 5u);
        SSF_ASSERT(a.limbs[0] == (1ul << 20));

        /* Setting the top bit of a non-empty value doesn't clobber other bits. */
        SSFBNSetUint32(&a, 0x12345678ul, 4);
        SSFBNSetBit(&a, 127u);
        SSF_ASSERT(a.limbs[0] == 0x12345678ul);
        SSF_ASSERT(a.limbs[3] == 0x80000000ul);
    }

    /* ---- SSFBNTrailingZeros: count low-order zero bits ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        /* a = 1 → tz = 0 */
        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 0u);

        /* a = 2 → tz = 1 */
        SSFBNSetUint32(&a, 2u, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 1u);

        /* a = 0x80000000 (bit 31) → tz = 31 (top of limb 0) */
        SSFBNSetUint32(&a, 0x80000000ul, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 31u);

        /* a = 2^32 (bit 32, start of limb 1) → tz = 32 */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 1u;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 32u);

        /* a = 2^47 (mid-limb 1) → tz = 47 */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 0x00008000ul;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 47u);

        /* a = 2^96 (start of limb 3) → tz = 96 */
        SSFBNSetZero(&a, 4);
        a.limbs[3] = 1u;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 96u);

        /* Mixed value: low limb zero, limb[1] has a low set bit and other high bits — must      */
        /* return the position of the lowest set bit only.                                       */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 0xFF00FF10ul; /* lowest set bit is bit 4 of limb 1 → global bit 36 */
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 36u);

        /* After a left shift by k, tz grows by k. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 0u); /* 0xDEADBEEF has bit 0 set */
        SSFBNShiftLeft(&a, 17u);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 17u);
    }

    /* ---- ModAdd / ModSub with small modulus ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* (5 + 6) mod 7 = 4 */
        SSFBNSetUint32(&a, 5u, 4);
        SSFBNSetUint32(&b, 6u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModAdd(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 4u);

        /* (2 - 5) mod 7 = 4 */
        SSFBNSetUint32(&a, 2u, 4);
        SSFBNSetUint32(&b, 5u, 4);
        SSFBNModSub(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModMul with small modulus ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* (5 * 6) mod 7 = 30 mod 7 = 2 */
        SSFBNSetUint32(&a, 5u, 4);
        SSFBNSetUint32(&b, 6u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModMul(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 2u);
    }

    /* ---- ModExp: 3^10 mod 7 = 59049 mod 7 = 4 ---- */
    {
        SSFBN_DEFINE(base, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(exp, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&base, 3u, 4);
        SSFBNSetUint32(&exp, 10u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModExp(&r, &base, &exp, &m);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModInv: 2^(-1) mod 7 = 4 (since 2*4 = 8 = 1 mod 7) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 2u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == true);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModInv: 0 has no inverse ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 0u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);
    }

    /* ---- CondSwap ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 10u, 4);
        SSFBNSetUint32(&b, 20u, 4);
        SSFBNCondSwap(&a, &b, 0u);
        SSF_ASSERT(a.limbs[0] == 10u);
        SSF_ASSERT(b.limbs[0] == 20u);
        SSFBNCondSwap(&a, &b, 1u);
        SSF_ASSERT(a.limbs[0] == 20u);
        SSF_ASSERT(b.limbs[0] == 10u);
    }

    /* ---- Zeroize ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&a, 0xDEADBEEFu, 4);
        SSFBNZeroize(&a);
        SSF_ASSERT(a.limbs[0] == 0u);
        SSF_ASSERT(a.len == 0);
    }

    /* ---- NIST P-256: verify p is consistent with SSF_BN_NIST_P256 ---- */
    {
        SSF_ASSERT(SSFBNCmp(&SSF_BN_NIST_P256, &SSF_BN_NIST_P256) == 0);
        SSF_ASSERT(SSFBNIsZero(&SSF_BN_NIST_P256) == false);
        SSF_ASSERT(SSFBNBitLen(&SSF_BN_NIST_P256) == 256u);
    }

    /* ---- ModMulNIST: a * 1 mod p = a ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetUint32(&one, 1u, 8);
        SSFBNModMulNIST(&r, &a, &one, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmp(&r, &a) == 0);
    }

    /* ---- ModMulNIST: a * 0 mod p = 0 ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(zero, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetZero(&zero, 8);
        SSFBNModMulNIST(&r, &a, &zero, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsZero(&r) == true);
    }

    /* ---- Montgomery: roundtrip convert in/out ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aBack, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 12345u, 8);
        SSFBNMontInit(&mont, &SSF_BN_NIST_P256);
        SSFBNMontConvertIn(&aM, &a, &mont);
        SSFBNMontConvertOut(&aBack, &aM, &mont);
        SSF_ASSERT(SSFBNCmp(&a, &aBack) == 0);
    }

    /* ====================================================================================== */
    /* Primality-related API (hoisted from ssfrsa)                                              */
    /* ====================================================================================== */

    /* ---- SSFBNModUint32: basic reductions ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        /* 123456789 mod 7 = 1 */
        SSFBNSetUint32(&a, 123456789u, 4);
        SSF_ASSERT(SSFBNModUint32(&a, 7u) == 1u);

        /* A large BN: (2^64) mod 3 == 1 since 2^64 = 4 * 2^62, and 2 mod 3 == 2, 4 mod 3 == 1  */
        /* Build 2^64 via FromBytes: big-endian 0x00..01 0x00..00. */
        {
            static const uint8_t data[9] = { 0x01u, 0,0,0,0, 0,0,0,0 };
            SSFBNFromBytes(&a, data, sizeof(data), 4);
            SSF_ASSERT(SSFBNModUint32(&a, 3u) == 1u);
        }

        /* Zero mod anything == 0. */
        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNModUint32(&a, 17u) == 0u);

        /* Dividing by the value itself gives 0. */
        SSFBNSetUint32(&a, 42u, 4);
        SSF_ASSERT(SSFBNModUint32(&a, 42u) == 0u);
    }

    /* ---- SSFBNRandom: populates without corrupting beyond numLimbs ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;
        bool sawNonZero = false;

        /* Deterministic seed so the test is reproducible. */
        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)i;
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* Fill 4 limbs of a that has capacity SSF_BN_MAX_LIMBS. */
        SSFBNSetZero(&a, SSF_BN_MAX_LIMBS);
        SSFBNRandom(&a, 4u, &prng);
        SSF_ASSERT(a.len == 4u);

        /* At least one limb should be non-zero (vanishingly unlikely to be all zero). */
        for (i = 0; i < 4u; i++)
        {
            if (a.limbs[i] != 0u) { sawNonZero = true; break; }
        }
        SSF_ASSERT(sawNonZero);

        /* Limbs past numLimbs must not have been touched. */
        for (i = 4u; i < SSF_BN_MAX_LIMBS; i++)
        {
            SSF_ASSERT(a.limbs[i] == 0u);
        }

        SSFPRNGDeInitContext(&prng);
    }

    /* ---- SSFBNRandomBelow: uniform draw in [0, bound) ---- */
    {
        SSFBN_DEFINE(bound, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x71u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* Small bound: 100 draws all land in [0, 1000). */
        SSFBNSetUint32(&bound, 1000u, 4);
        for (i = 0; i < 100u; i++)
        {
            SSF_ASSERT(SSFBNRandomBelow(&r, &bound, &prng) == true);
            SSF_ASSERT(SSFBNCmp(&r, &bound) < 0);
        }

        /* Large bound (P-256 prime): draws are well-distributed and always < bound. */
        for (i = 0; i < 16u; i++)
        {
            SSF_ASSERT(SSFBNRandomBelow(&r, &SSF_BN_NIST_P256, &prng) == true);
            SSF_ASSERT(SSFBNCmp(&r, &SSF_BN_NIST_P256) < 0);
        }

        /* Bound = 1: the only valid draw is 0. */
        SSFBNSetOne(&bound, 4);
        SSF_ASSERT(SSFBNRandomBelow(&r, &bound, &prng) == true);
        SSF_ASSERT(SSFBNIsZero(&r) == true);

        /* Bound = 2: draws are 0 or 1. Check we see both in a few hundred draws. */
        {
            SSFBNSetUint32(&bound, 2u, 4);
            bool sawZero = false;
            bool sawOne = false;
            for (i = 0; i < 200u; i++)
            {
                SSF_ASSERT(SSFBNRandomBelow(&r, &bound, &prng) == true);
                SSF_ASSERT(SSFBNCmp(&r, &bound) < 0);
                if (SSFBNIsZero(&r)) sawZero = true;
                else sawOne = true;
            }
            SSF_ASSERT(sawZero);
            SSF_ASSERT(sawOne);
        }

        SSFPRNGDeInitContext(&prng);
    }

    /* ---- SSFBNIsProbablePrime: known prime accepted, composite rejected ---- */
    {
        SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0xA5u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* 2^31 - 1 = 2147483647 is a Mersenne prime. */
        SSFBNSetUint32(&n, 2147483647u, 4);
        SSF_ASSERT(SSFBNIsProbablePrime(&n, 5u, &prng) == true);

        /* 2^31 - 3 = 2147483645 = 5 * 429496729, composite. */
        SSFBNSetUint32(&n, 2147483645u, 4);
        SSF_ASSERT(SSFBNIsProbablePrime(&n, 5u, &prng) == false);

        /* 91 = 7 * 13 — small composite that fools Fermat base-3 test but not MR. */
        SSFBNSetUint32(&n, 91u, 4);
        SSF_ASSERT(SSFBNIsProbablePrime(&n, 5u, &prng) == false);

        SSFPRNGDeInitContext(&prng);
    }

    /* ====================================================================================== */
    /* Squaring API — must agree bit-for-bit with the general multiply on every input.          */
    /* ====================================================================================== */

    /* ---- SSFBNSquare: parity with SSFBNMul(a, a) across small, mid, and large operands ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(sq, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mul, SSF_BN_MAX_LIMBS);
        uint16_t k;

        /* 0^2 = 0 */
        SSFBNSetZero(&a, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(SSFBNIsZero(&sq) == true);
        SSF_ASSERT(sq.len == 8u);

        /* 1^2 = 1 */
        SSFBNSetUint32(&a, 1u, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 1u);
        SSF_ASSERT(sq.limbs[1] == 0u);
        SSF_ASSERT(sq.limbs[2] == 0u);

        /* 7^2 = 49 */
        SSFBNSetUint32(&a, 7u, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 49u);

        /* 65536^2 = 2^32 (crosses limb boundary) */
        SSFBNSetUint32(&a, 65536u, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 0u);
        SSF_ASSERT(sq.limbs[1] == 1u);

        /* 0xFFFFFFFF^2 = 0xFFFFFFFE00000001 (largest single limb) */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 0x00000001ul);
        SSF_ASSERT(sq.limbs[1] == 0xFFFFFFFEul);

        /* Parity against generic multiply for a range of multi-limb values. Build a from a      */
        /* pseudo-random byte sequence; the test is deterministic (no PRNG dependency).          */
        for (k = 1; k <= 8u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x5Au + (uint8_t)i * (uint8_t)k);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNSquare(&sq, &a);
            SSFBNMul(&mul, &a, &a);
            SSF_ASSERT(sq.len == mul.len);
            SSF_ASSERT(memcmp(sq.limbs, mul.limbs, (size_t)sq.len * sizeof(SSFBNLimb_t)) == 0);
        }
    }

    /* ---- SSFBNModSquare: parity with SSFBNModMul(a, a, m) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(modSq, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(modMul, SSF_BN_MAX_LIMBS);
        uint16_t k;

        for (k = 1; k <= 4u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0xA5u + (uint8_t)i * (uint8_t)k);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            /* Ensure a < p256 so the modular contract holds. */
            SSFBNMod(&a, &a, &SSF_BN_NIST_P256);

            SSFBNModSquare(&modSq, &a, &SSF_BN_NIST_P256);
            SSFBNModMul(&modMul, &a, &a, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNCmp(&modSq, &modMul) == 0);
        }

        /* ModSquare supports aliasing r == a. */
        SSFBNSetUint32(&a, 12345u, 8);
        SSFBNMod(&a, &a, &SSF_BN_NIST_P256);
        SSFBNModMul(&modMul, &a, &a, &SSF_BN_NIST_P256);
        SSFBNModSquare(&a, &a, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmp(&a, &modMul) == 0);
    }

    /* ---- SSFBNMontSquare: parity with SSFBNMontMul(a, a, ctx) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(sqM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mulM, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        uint16_t k;

        SSFBNMontInit(&mont, &SSF_BN_NIST_P256);

        for (k = 1; k <= 4u; k++)
        {
            SSFBNSetUint32(&a, 1000u * (uint32_t)k + (uint32_t)k, 8);
            SSFBNMontConvertIn(&aM, &a, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontMul(&mulM, &aM, &aM, &mont);
            SSF_ASSERT(SSFBNCmp(&sqM, &mulM) == 0);
        }

        /* MontSquare supports aliasing r == a. */
        SSFBNSetUint32(&a, 7777u, 8);
        SSFBNMontConvertIn(&aM, &a, &mont);
        SSFBNMontMul(&mulM, &aM, &aM, &mont);
        SSFBNMontSquare(&aM, &aM, &mont);
        SSF_ASSERT(SSFBNCmp(&aM, &mulM) == 0);

        /* Boundary: 0 in Montgomery form squared is 0. */
        SSFBNSetZero(&a, 8);
        SSFBNMontConvertIn(&aM, &a, &mont);
        SSFBNMontSquare(&sqM, &aM, &mont);
        SSF_ASSERT(SSFBNIsZero(&sqM) == true);

        /* Boundary: (p-1)^2 mod p = 1. Test through MontSquare + ConvertOut. */
        {
            SSFBN_DEFINE(pm1, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(result, SSF_BN_MAX_LIMBS);

            SSFBNSetUint32(&one, 1u, 8);
            SSFBNSub(&pm1, &SSF_BN_NIST_P256, &one);  /* pm1 = p - 1 */
            SSFBNMontConvertIn(&aM, &pm1, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontConvertOut(&result, &sqM, &mont);
            SSF_ASSERT(SSFBNIsOne(&result) == true);
        }

        /* Full sweep: 16 random-ish values, verify MontSquare == MontMul(a, a) bit-for-bit. */
        for (k = 0; k < 16u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x3Cu + (uint8_t)i * 7u + (uint8_t)k * 11u);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNMod(&a, &a, &SSF_BN_NIST_P256);
            SSFBNMontConvertIn(&aM, &a, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontMul(&mulM, &aM, &aM, &mont);
            SSF_ASSERT(SSFBNCmp(&sqM, &mulM) == 0);
        }
    }

    /* ====================================================================================== */
    /* Uint32 small-operand arithmetic — parity with matched 1-limb BN operand                  */
    /* ====================================================================================== */

    /* ---- SSFBNAddUint32: parity + carry return ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aCopy, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rSum, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rRef, SSF_BN_MAX_LIMBS);
        SSFBNLimb_t carrySum;
        SSFBNLimb_t carryRef;

        /* Simple: 100 + 25 == 125 */
        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 25u, 4);
        carryRef = SSFBNAdd(&rRef, &a, &b);
        carrySum = SSFBNAddUint32(&rSum, &a, 25u);
        SSF_ASSERT(carrySum == carryRef);
        SSF_ASSERT(SSFBNCmp(&rSum, &rRef) == 0);

        /* Carry propagates across limbs: 0xFFFFFFFF + 1 = 0x100000000 */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNAddUint32(&rSum, &a, 1u);
        SSF_ASSERT(rSum.limbs[0] == 0u);
        SSF_ASSERT(rSum.limbs[1] == 1u);

        /* Top-limb carry-out returned. */
        SSFBNSetZero(&a, 2);
        a.limbs[0] = 0xFFFFFFFFul;
        a.limbs[1] = 0xFFFFFFFFul;
        carrySum = SSFBNAddUint32(&rSum, &a, 1u);
        SSF_ASSERT(carrySum == 1u);
        SSF_ASSERT(rSum.limbs[0] == 0u);
        SSF_ASSERT(rSum.limbs[1] == 0u);

        /* Aliasing r == a works in place. */
        SSFBNSetUint32(&aCopy, 0x123456u, 4);
        SSFBNAddUint32(&aCopy, &aCopy, 0xFFFFu);
        SSF_ASSERT(aCopy.limbs[0] == 0x133455ul);

        /* Adding zero is a copy. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        carrySum = SSFBNAddUint32(&rSum, &a, 0u);
        SSF_ASSERT(carrySum == 0u);
        SSF_ASSERT(SSFBNCmp(&rSum, &a) == 0);
    }

    /* ---- SSFBNSubUint32: parity + borrow return ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aCopy, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rSub, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rRef, SSF_BN_MAX_LIMBS);
        SSFBNLimb_t borrowSub;
        SSFBNLimb_t borrowRef;

        /* 100 - 25 == 75 */
        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 25u, 4);
        borrowRef = SSFBNSub(&rRef, &a, &b);
        borrowSub = SSFBNSubUint32(&rSub, &a, 25u);
        SSF_ASSERT(borrowSub == borrowRef);
        SSF_ASSERT(SSFBNCmp(&rSub, &rRef) == 0);

        /* Borrow crosses limb boundary: 0x100000000 - 1 = 0xFFFFFFFF. */
        SSFBNSetZero(&a, 2);
        a.limbs[1] = 1u;
        SSFBNSubUint32(&rSub, &a, 1u);
        SSF_ASSERT(rSub.limbs[0] == 0xFFFFFFFFul);
        SSF_ASSERT(rSub.limbs[1] == 0u);

        /* Underflow returns borrow=1, result is two's-complement. */
        SSFBNSetZero(&a, 2);
        borrowSub = SSFBNSubUint32(&rSub, &a, 5u);
        SSF_ASSERT(borrowSub == 1u);
        SSF_ASSERT(rSub.limbs[0] == 0xFFFFFFFBul);
        SSF_ASSERT(rSub.limbs[1] == 0xFFFFFFFFul);

        /* Aliasing r == a. */
        SSFBNSetUint32(&aCopy, 0x12345678ul, 4);
        SSFBNSubUint32(&aCopy, &aCopy, 0x12340000ul);
        SSF_ASSERT(aCopy.limbs[0] == 0x5678u);
    }

    /* ---- SSFBNMulUint32: parity with full-width Mul against a 1-limb BN ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rProd, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rRef, SSF_BN_MAX_LIMBS);

        /* 7 * 6 = 42 */
        SSFBNSetUint32(&a, 7u, 4);
        SSFBNSetUint32(&b, 6u, 1);
        SSFBNMul(&rRef, &a, &b);
        SSFBNMulUint32(&rProd, &a, 6u);
        SSF_ASSERT(rProd.len == 5u);
        SSF_ASSERT(rProd.limbs[0] == 42u);

        /* Across limb boundary: 0xFFFFFFFF * 2 = 0x1_FFFFFFFE */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNMulUint32(&rProd, &a, 2u);
        SSF_ASSERT(rProd.limbs[0] == 0xFFFFFFFEul);
        SSF_ASSERT(rProd.limbs[1] == 1u);

        /* Parity sweep against SSFBNMul(a, b-as-BN) for multi-limb a, small b. */
        {
            static const uint8_t data[8] = { 0x01u, 0x23u, 0x45u, 0x67u,
                                             0x89u, 0xABu, 0xCDu, 0xEFu };
            uint32_t k;
            SSFBNFromBytes(&a, data, sizeof(data), 4);
            for (k = 1u; k <= 100u; k += 7u)
            {
                SSFBNSetUint32(&b, k, 1);
                SSFBNMul(&rRef, &a, &b);
                SSFBNMulUint32(&rProd, &a, k);
                /* rRef is 5 limbs (4 + 1); rProd is also 5 limbs. */
                SSF_ASSERT(rProd.len == rRef.len);
                SSF_ASSERT(memcmp(rProd.limbs, rRef.limbs,
                                  (size_t)rProd.len * sizeof(SSFBNLimb_t)) == 0);
            }
        }

        /* Multiplying by zero yields zero. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNMulUint32(&rProd, &a, 0u);
        SSF_ASSERT(SSFBNIsZero(&rProd) == true);
    }

    /* ====================================================================================== */
    /* Variable-time ModExp (public-exponent-only) — must match constant-time ModExp exactly    */
    /* ====================================================================================== */

    /* ---- SSFBNModExpPub: parity with SSFBNModExp across typical RSA public exponents ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rCT, SSF_BN_MAX_LIMBS); /* constant-time reference */
        SSFBN_DEFINE(rVT, SSF_BN_MAX_LIMBS); /* variable-time candidate */
        static const uint32_t pubExponents[] = { 0u, 1u, 2u, 3u, 17u, 65537u, 0xFFFFFFFFul };
        uint16_t k;

        /* Use P-256 as a convenient prime modulus for the parity sweep. */
        SSFBNSetUint32(&a, 12345u, 8);

        for (k = 0; k < (uint16_t)(sizeof(pubExponents) / sizeof(pubExponents[0])); k++)
        {
            SSFBNSetUint32(&e, pubExponents[k], 8);
            SSFBNModExp(&rCT, &a, &e, &SSF_BN_NIST_P256);
            SSFBNModExpPub(&rVT, &a, &e, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNCmp(&rCT, &rVT) == 0);
        }
    }

    /* ---- SSFBNModExpPub: parity across random bases for e = 65537 ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rCT, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rVT, SSF_BN_MAX_LIMBS);
        uint16_t k;

        SSFBNSetUint32(&e, 65537u, 8);

        for (k = 0; k < 8u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x2Bu + (uint8_t)i * 11u + (uint8_t)k * 19u);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNMod(&a, &a, &SSF_BN_NIST_P256);

            SSFBNModExp(&rCT, &a, &e, &SSF_BN_NIST_P256);
            SSFBNModExpPub(&rVT, &a, &e, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNCmp(&rCT, &rVT) == 0);
        }
    }

    /* ---- SSFBNModExpPub: edge cases ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* a^0 = 1 for any a. */
        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetUint32(&e, 0u, 8);
        SSFBNModExpPub(&r, &a, &e, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsOne(&r) == true);

        /* 0^e = 0 for e >= 1. */
        SSFBNSetZero(&a, 8);
        SSFBNSetUint32(&e, 7u, 8);
        SSFBNModExpPub(&r, &a, &e, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsZero(&r) == true);

        /* 1^e = 1. */
        SSFBNSetUint32(&a, 1u, 8);
        SSFBNSetUint32(&e, 0x12345678ul, 8);
        SSFBNModExpPub(&r, &a, &e, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsOne(&r) == true);
    }

    /* ---- SSFBNModExpMontPub: parity with SSFBNModExpMont (precomputed ctx path) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rCT, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rVT, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(ctx, SSF_BN_MAX_LIMBS);

        SSFBNMontInit(&ctx, &SSF_BN_NIST_P256);
        SSFBNSetUint32(&a, 99999u, 8);
        SSFBNSetUint32(&e, 65537u, 8);

        SSFBNModExpMont(&rCT, &a, &e, &ctx);
        SSFBNModExpMontPub(&rVT, &a, &e, &ctx);
        SSF_ASSERT(SSFBNCmp(&rCT, &rVT) == 0);
    }

#if SSF_BN_CONFIG_MAX_BITS >= 768
    /* ---- SSFBNMontSquare on P-384 (larger modulus exercises more carry propagation) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(sqM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mulM, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        uint16_t k;

        SSFBNMontInit(&mont, &SSF_BN_NIST_P384);

        for (k = 0; k < 8u; k++)
        {
            uint8_t data[48];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x71u + (uint8_t)i * 13u + (uint8_t)k * 17u);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 12);
            SSFBNMod(&a, &a, &SSF_BN_NIST_P384);
            SSFBNMontConvertIn(&aM, &a, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontMul(&mulM, &aM, &aM, &mont);
            SSF_ASSERT(SSFBNCmp(&sqM, &mulM) == 0);
        }
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */

    /* ---- SSFBNGenPrime: produces a prime of the requested size ---- */
    {
        SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x5Au ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* Small bit size keeps the test fast but still exercises the loop. */
        SSF_ASSERT(SSFBNGenPrime(&p, 64u, 5u, &prng) == true);
        SSF_ASSERT(SSFBNBitLen(&p) == 64u); /* Top two bits forced set → bit length exact. */
        SSF_ASSERT(SSFBNIsProbablePrime(&p, 5u, &prng) == true);

        SSFPRNGDeInitContext(&prng);
    }

    /* ---- Precondition assertions (SSF_REQUIRE) — make sure the documented contracts trip ---- */
    {
        SSFBN_DEFINE(z, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(a8, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b4, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(evenMod, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&z, 8u);
        SSFBNSetUint32(&a8, 1u, 8u);
        SSFBNSetUint32(&b4, 1u, 4u);
        SSFBNSetUint32(&evenMod, 6u, 8u); /* even modulus must be rejected by MontInit */

        /* TrailingZeros requires nonzero input. */
        SSF_ASSERT_TEST(SSFBNTrailingZeros(&z));

        /* Cmp requires matching working widths. */
        SSF_ASSERT_TEST(SSFBNCmp(&a8, &b4));

        /* MontInit requires odd modulus. */
        SSF_ASSERT_TEST(SSFBNMontInit(&mont, &evenMod));

        /* NULL pointer rejection on a representative selection. */
        SSF_ASSERT_TEST(SSFBNZeroize(NULL));
        SSF_ASSERT_TEST(SSFBNIsZero(NULL));
        SSF_ASSERT_TEST(SSFBNCmp(NULL, &a8));
        SSF_ASSERT_TEST(SSFBNAdd(NULL, &a8, &a8));
        SSF_ASSERT_TEST(SSFBNMod(NULL, &a8, &a8));

        /* DivMod forbids q == rem aliasing — should assert. */
        {
            SSFBN_DEFINE(qr, SSF_BN_MAX_LIMBS);
            qr.len = 8u;
            SSF_ASSERT_TEST(SSFBNDivMod(&qr, &qr, &a8, &a8));
        }

        /* MontMul / MontSquare must reject operands whose cap is smaller than the modulus's   */
        /* working width. Without this trap the inner loop reads past the operand's allocated  */
        /* limb storage. Construct a "narrow" operand via SSFBN_DEFINE with a small nlimbs so  */
        /* its cap < ctx->len after MontInit at the P-256 modulus.                              */
        {
            SSFBNMONT_DEFINE(montP256, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(narrow, 4u); /* cap = 4, less than mont.len = 8 */
            SSFBN_DEFINE(wide, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(result, SSF_BN_MAX_LIMBS);

            SSFBNMontInit(&montP256, &SSF_BN_NIST_P256);
            SSFBNSetUint32(&narrow, 1u, 4u);
            SSFBNMontConvertIn(&wide, &SSF_BN_NIST_P256, &montP256); /* arbitrary valid value */

            SSF_ASSERT_TEST(SSFBNMontMul(&result, &narrow, &wide, &montP256));
            SSF_ASSERT_TEST(SSFBNMontMul(&result, &wide, &narrow, &montP256));
            SSF_ASSERT_TEST(SSFBNMontSquare(&result, &narrow, &montP256));
        }
    }

#if SSF_BN_OSSL_VERIFY == 1
    _SSFBNVerifyAgainstOpenSSL();
#endif

#if SSF_CONFIG_BN_MICROBENCH == 1
    /* ====================================================================================== */
    /* Microbenchmark — MontMul / MontSquare (CIOS-based) and raw Mul / Square (schoolbook /    */
    /* triangular) throughput at representative operand sizes. Gated by SSF_CONFIG_BN_MICROBENCH*/
    /* so the normal test run stays quick; flip the macro in ssfport.h to 1 before measuring    */
    /* perf changes, then back to 0 after.                                                      */
    /*                                                                                          */
    /* Raw Mul/Square require 2*nLimbs <= SSF_BN_MAX_LIMBS, so n=128 is skipped for those.      */
    /* ====================================================================================== */
    {
        /* Drop bench entries whose 2*nLimbs would exceed SSF_BN_MAX_LIMBS at the configured BN  */
        /* cap. With auto-derivation in ssfbn.h the cap tracks the largest enabled algorithm;   */
        /* an ECC-only build (cap = 768 → MAX_LIMBS = 24) cannot run the RSA-1024+ rows because */
        /* the schoolbook product would overflow the SSF_REQUIRE in SSFBNSetZero / SSFBNMul.    */
        struct { uint16_t nLimbs; uint32_t mIters; uint32_t mulIters; const char *label; } bench[] = {
            {   8u, 4000000u, 20000000u, "P-256 (n= 8, RSA-256-eq) " },
#if (2u * 32u) <= SSF_BN_MAX_LIMBS
            {  32u,  400000u,  5000000u, "RSA-1024     (n=32)      " },
#endif
#if (2u * 64u) <= SSF_BN_MAX_LIMBS
            {  64u,  100000u,  1500000u, "RSA-2048     (n=64)      " },
#endif
#if (2u * 128u) <= SSF_BN_MAX_LIMBS
            { 128u,   30000u,        0u, "RSA-4096     (n=128)     " },
#endif
        };
        uint16_t bi;

        printf("\n--- ssfbn microbenchmark (ms for iter count shown) ---\n");
        for (bi = 0; bi < (uint16_t)(sizeof(bench) / sizeof(bench[0])); bi++)
        {
            uint16_t n = bench[bi].nLimbs;
            uint32_t mIters = bench[bi].mIters;
            uint32_t mulIters = bench[bi].mulIters;
            uint32_t i;

            /* Build a Mont context with an odd, prime-ish modulus (use P-256 / P-384 constants  */
            /* where they fit; else synthesize an odd modulus with the high bit set and low bit  */
            /* set so MontInit accepts it).                                                      */
            SSFBN_DEFINE(mod, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(rWide, SSF_BN_MAX_LIMBS); /* Width for raw Mul/Square (2n limbs). */
            SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
            SSFPortTick_t t0, t1;

            if (n == 8u)
            {
                SSFBNCopy(&mod, &SSF_BN_NIST_P256);
            }
            else
            {
                SSFBNSetZero(&mod, n);
                for (i = 0; i < n; i++) mod.limbs[i] = 0xFFFFFFFFul;
                mod.limbs[0] ^= 0x58ul;              /* random-ish low bits, still odd */
                mod.limbs[n - 1u] = 0xFFFFFF00ul | 1u;
            }

            /* Fill every limb with pseudo-random non-zero data so SSFBNMul's `if (a[i]==0)` */
            /* shortcut does not artificially speed the baseline. Use a cheap LCG-style seed   */
            /* keyed on the limb index.                                                        */
            SSFBNSetZero(&a, n);
            SSFBNSetZero(&b, n);
            for (i = 0; i < n; i++)
            {
                a.limbs[i] = 0xA5A5A5A5ul ^ (i * 0x9E3779B9ul);
                b.limbs[i] = 0x5A5A5A5Aul ^ (i * 0x7F4A7C15ul);
            }
            a.len = n;
            b.len = n;
            SSFBNMod(&a, &a, &mod);
            SSFBNMod(&b, &b, &mod);

            SSFBNMontInit(&mont, &mod);

            /* --- Raw SSFBNMul / SSFBNSquare (non-Mont) at 2n-limb output. --- */
            if (mulIters > 0u)
            {
                t0 = SSFPortGetTick64();
                for (i = 0; i < mulIters; i++)
                {
                    SSFBNMul(&rWide, &a, &b);
                }
                t1 = SSFPortGetTick64();
                printf("  Mul        %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)mulIters,
                       (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < mulIters; i++)
                {
                    SSFBNSquare(&rWide, &a);
                }
                t1 = SSFPortGetTick64();
                printf("  Square     %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)mulIters,
                       (unsigned long long)(t1 - t0));
            }

            /* --- ModExpMont (constant-time, dense full-Hamming exponent — worst case for the    */
            /* binary ladder) and ModExpMontPub (variable-time, e = 65537 = F4, the realistic     */
            /* RSA verify exponent). a is still in plain (non-Mont) form here.                    */
            {
                SSFBN_DEFINE(expPriv, SSF_BN_MAX_LIMBS);
                SSFBN_DEFINE(expPub, SSF_BN_MAX_LIMBS);
                SSFBN_DEFINE(rE, SSF_BN_MAX_LIMBS);
                uint32_t expIters = 0u;
                uint32_t expPubIters = 0u;

                /* Dense pseudo-random private-style exponent: full bit-width, both ends set. */
                SSFBNSetZero(&expPriv, n);
                for (i = 0; i < n; i++)
                {
                    expPriv.limbs[i] = 0xC9F1A8B7ul ^ (i * 0x517CC1B7ul);
                }
                expPriv.limbs[n - 1u] |= 0x80000000ul;   /* force full bit-length */
                expPriv.limbs[0] |= 1u;                  /* force odd */
                expPriv.len = n;

                /* Public exponent F4 = 65537. */
                SSFBNSetUint32(&expPub, 65537u, 1u);

                /* Iter counts tuned for ~0.5–2 s per measurement (Mont ladder is ~2*eBits ops). */
                if (n == 8u)        { expIters = 20000u;  expPubIters = 500000u; }
                else if (n == 32u)  { expIters = 400u;    expPubIters = 40000u;  }
                else if (n == 64u)  { expIters = 50u;     expPubIters = 10000u;  }
                else                { expIters = 10u;     expPubIters = 2000u;   }

                t0 = SSFPortGetTick64();
                for (i = 0; i < expIters; i++)
                {
                    SSFBNModExpMont(&rE, &a, &expPriv, &mont);
                }
                t1 = SSFPortGetTick64();
                printf("  ModExpMont %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)expIters,
                       (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < expPubIters; i++)
                {
                    SSFBNModExpMontPub(&rE, &a, &expPub, &mont);
                }
                t1 = SSFPortGetTick64();
                printf("  ModExpPub  %s %u iter: %llu ms (e=F4)\n",
                       bench[bi].label, (unsigned)expPubIters,
                       (unsigned long long)(t1 - t0));
            }

            /* --- ModInv (Fermat via ModExp) vs ModInvExt (binary EEA, non-CT) at P-256 size. */
            /* Used to validate that EEA actually beats Fermat in this codebase before routing  */
            /* public-input ECDSA Verify ModInv calls to the EEA path.                          */
            if (n == 8u)
            {
                SSFBN_DEFINE(rInv, SSF_BN_MAX_LIMBS);
                rInv.len = n;
                t0 = SSFPortGetTick64();
                for (i = 0; i < 2000u; i++)
                {
                    (void)SSFBNModInv(&rInv, &a, &mod);
                }
                t1 = SSFPortGetTick64();
                printf("  ModInv     %s %u iter: %llu ms (Fermat)\n",
                       bench[bi].label, 2000u, (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < 2000u; i++)
                {
                    (void)SSFBNModInvExt(&rInv, &a, &mod);
                }
                t1 = SSFPortGetTick64();
                printf("  ModInvExt  %s %u iter: %llu ms (binary EEA)\n",
                       bench[bi].label, 2000u, (unsigned long long)(t1 - t0));
            }

            /* --- Mont-form MontMul / MontSquare (CIOS / SOS). --- */
            SSFBNMontConvertIn(&a, &a, &mont);
            SSFBNMontConvertIn(&b, &b, &mont);

            t0 = SSFPortGetTick64();
            for (i = 0; i < mIters; i++)
            {
                SSFBNMontMul(&r, &a, &b, &mont);
            }
            t1 = SSFPortGetTick64();
            printf("  MontMul    %s %u iter: %llu ms\n",
                   bench[bi].label, (unsigned)mIters,
                   (unsigned long long)(t1 - t0));

            t0 = SSFPortGetTick64();
            for (i = 0; i < mIters; i++)
            {
                SSFBNMontSquare(&r, &a, &mont);
            }
            t1 = SSFPortGetTick64();
            printf("  MontSquare %s %u iter: %llu ms\n",
                   bench[bi].label, (unsigned)mIters,
                   (unsigned long long)(t1 - t0));
        }
        printf("--- end microbenchmark ---\n");
    }
#endif /* SSF_CONFIG_BN_MICROBENCH */
}
#ifdef _WIN32
#pragma warning(pop)
#endif
#endif /* SSF_CONFIG_BN_UNIT_TEST */
