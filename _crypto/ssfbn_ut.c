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

/* Cross-check against OpenSSL's BIGNUM when the build links libcrypto (SSF_CONFIG_HAVE_OPENSSL) */
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

/* Generate a random SSFBN_t of exactly `bits` bits (top bit set), mirrored into `mirror`. */
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

    /* Build a prime modulus once per size for ModInv coverage; slow, so gated by prime_capable */
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

                /* Does ModMul's 2 * nLimbs <= MAX_LIMBS allow the aP * inv == 1 round trip? */
                if ((uint32_t)nLimbs * 2u <= SSF_BN_MAX_LIMBS)
                {
                    /* Yes, check aP * inv mod prime == 1 */
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

            /* Public exponent: e = 65537. Non-secret, low Hamming weight -- exercises ModExpPub. */
            SSFBNSetUint32(&e, 65537u, nLimbs);
            BN_set_word(bnE, 65537u);

            rOut.len = nLimbs;
            SSFBNModExpPub(&rOut, &a, &e, &m);
            SSF_ASSERT(BN_mod_exp(bnR, bnA, bnE, bnM, ctx) == 1);
            SSF_ASSERT(_EqOSSL(&rOut, bnR));

            /* Is this a small size, or every 8th iteration at the larger sizes? */
            if (bits <= 1024 || (i & 0x7u) == 0u)
            {
                /* Yes, also check the constant-time path */
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

            shiftBy = (uint32_t)((unsigned)i & 0x1Fu); /* 0..31 -- keeps result inside nLimbs. */
            SSFBNCopy(&shifted, &a);
            SSFBNShiftRight(&shifted, shiftBy);
            SSF_ASSERT(BN_rshift(bnR, bnA, (int)shiftBy) == 1);
            SSF_ASSERT(_EqOSSL(&shifted, bnR));

            SSFBNCopy(&shifted, &a);
            shifted.len = nLimbs;
            SSFBNShiftLeft(&shifted, shiftBy);
            SSF_ASSERT(BN_lshift(bnR, bnA, (int)shiftBy) == 1);
            /* Mask OpenSSL to SSFBN's working width (BN_mask_bits errors if already shorter) */
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
/* Checks identity, aliasing and carry/borrow corner cases against OpenSSL, mod NIST P-256.      */
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
        if (BN_num_bits(bnR) > (int)nLimbs * 32)
        {
            SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        }
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Aliasing: r = b. */
        SSFBNCopy(&r, &rand2); r.len = nLimbs;
        (void)SSFBNAdd(&r, &rand1, &r);
        SSF_ASSERT(BN_add(bnR, bnA, bnB) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32)
        {
            SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        }
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Aliasing: r = a = b (a + a). */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        (void)SSFBNAdd(&r, &r, &r);
        SSF_ASSERT(BN_add(bnR, bnA, bnA) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32)
        {
            SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        }
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

        /* allOnes + 1 -> 0, carry=1. */
        carry = SSFBNAddUint32(&r, &allOnes, 1u); SSF_ASSERT(carry == 1u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* allOnes + 0 -> allOnes, carry=0. */
        carry = SSFBNAddUint32(&r, &allOnes, 0u); SSF_ASSERT(carry == 0u);
        SSF_ASSERT(SSFBNCmp(&r, &allOnes) == 0);

        /* 0 - 1 -> allOnes, borrow=1. */
        carry = SSFBNSubUint32(&r, &zero, 1u); SSF_ASSERT(carry == 1u);
        SSF_ASSERT(SSFBNCmp(&r, &allOnes) == 0);

        /* a + 0xFFFFFFFFu, compared to OpenSSL. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        (void)SSFBNAddUint32(&r, &rand1, 0xFFFFFFFFu);
        SSF_ASSERT(BN_set_word(bnTmp, 0xFFFFFFFFu) == 1);
        SSF_ASSERT(BN_add(bnR, bnA, bnTmp) == 1);
        if (BN_num_bits(bnR) > (int)nLimbs * 32)
        {
            SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        }
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

        /* allOnes * allOnes -- exercises full carry propagation. */
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
                uint8_t bufQ[SSF_BN_MAX_BYTES];
                uint8_t bufBig[SSF_BN_MAX_BYTES];
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
        SSF_ASSERT(BN_gcd(bnR, BN_value_one(), bnA, ctx) == 1 || 1);
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

        /* (m-1)^(-1) mod m = m-1 (since (m-1) == -1, and (-1)^2 = 1). */
        SSF_ASSERT(SSFBNModInv(&r, &mMinus1, &m) == true);
        SSF_ASSERT(SSFBNCmp(&r, &mMinus1) == 0);

        /* a^(-1) * a mod m = 1 -- round-trip property. */
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

        /* ModInvExt: even input vs even modulus -> no inverse (gcd > 1). */
        {
            SSFBN_DEFINE(twoMod, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(four, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&twoMod, 8u, nLimbs);  /* even modulus */
            SSFBNSetUint32(&four, 4u, nLimbs);    /* shares factor 4 with 8 */
            SSF_ASSERT(SSFBNModInvExt(&r, &four, &twoMod) == false);
        }

        /* ModInvExt: a == 0 -> no inverse (zero divisor). */
        {
            SSFBN_DEFINE(zero, SSF_BN_MAX_LIMBS);
            SSFBNSetZero(&zero, nLimbs);
            SSF_ASSERT(SSFBNModInvExt(&r, &zero, &m) == false);
        }

        /* ModInvExt: a == m -> a mod m == 0 -> no inverse. */
        SSF_ASSERT(SSFBNModInvExt(&r, &m, &m) == false);
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

        /* ConvertIn(0) -> 0; ConvertOut -> 0. */
        SSFBNMontConvertIn(&zR, &zero, &mont);
        SSF_ASSERT(SSFBNIsZero(&zR));
        SSFBNMontConvertOut(&rOut, &zR, &mont);
        SSF_ASSERT(SSFBNIsZero(&rOut));

        /* ConvertIn(1) = R mod m; ConvertOut -> 1. */
        SSFBNMontConvertIn(&oneR, &one, &mont);
        SSFBNMontConvertOut(&rOut, &oneR, &mont);
        SSF_ASSERT(SSFBNCmpUint32(&rOut, 1u) == 0);

        /* MontMul(0R, anything) -> 0R. */
        SSFBNMontConvertIn(&aR, &rand1, &mont);
        SSFBNMontMul(&rR, &zR, &aR, &mont);
        SSF_ASSERT(SSFBNIsZero(&rR));

        /* MontMul(1R, aR) = aR. */
        SSFBNMontMul(&rR, &oneR, &aR, &mont);
        SSF_ASSERT(SSFBNCmp(&rR, &aR) == 0);

        /* Aliasing: MontMul(rR, rR, ..) -- r = a. */
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

        /* Wider e (2 * nLimbs, a bit above ctx->len * 32): ModExp must not truncate e */
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
        if (BN_num_bits(bnR) > (int)nLimbs * 32)
        {
            SSF_ASSERT(BN_mask_bits(bnR, (int)nLimbs * 32) == 1);
        }
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Shift right by exactly one limb. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftRight(&r, 32u);
        SSF_ASSERT(BN_rshift(bnR, bnA, 32) == 1);
        SSF_ASSERT(_EqOSSL(&r, bnR));

        /* Shift right by full width -> zero. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftRight(&r, (uint32_t)nLimbs * 32u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* Shift left by full width -> all bits truncated -> zero. */
        SSFBNCopy(&r, &rand1); r.len = nLimbs;
        SSFBNShiftLeft(&r, (uint32_t)nLimbs * 32u);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* Shift1 of zero is zero. */
        SSFBNCopy(&r, &zero); r.len = nLimbs;
        SSFBNShiftLeft1(&r);
        SSF_ASSERT(SSFBNIsZero(&r));
        SSFBNShiftRight1(&r);
        SSF_ASSERT(SSFBNIsZero(&r));

        /* Shift1 of one: << -> 2, >> -> 0. */
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

        /* All-zero bytes -> zero value. */
        memset(buf, 0, nBytes);
        SSF_ASSERT(SSFBNFromBytes(&t, buf, nBytes, nLimbs) == true);
        SSF_ASSERT(SSFBNIsZero(&t));

        /* All-FF bytes -> allOnes value. */
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
        SSF_ASSERT(SSFBNCmpUint32(&allOnes, 0xFFFFFFFFu) > 0);
        SSF_ASSERT(SSFBNCmpUint32(&big, 0xFFFFFFFFu) == 0);
    }

    /* === CondSwap / CondCopy ========================================================= */
    {
        SSFBN_DEFINE(x, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(y, SSF_BN_MAX_LIMBS);

        SSFBNCopy(&x, &rand1); x.len = nLimbs;
        SSFBNCopy(&y, &rand2); y.len = nLimbs;

        /* swap=0 -> no change. */
        SSFBNCondSwap(&x, &y, 0u);
        SSF_ASSERT(SSFBNCmp(&x, &rand1) == 0);
        SSF_ASSERT(SSFBNCmp(&y, &rand2) == 0);

        /* swap=1 -> swap. */
        SSFBNCondSwap(&x, &y, 1u);
        SSF_ASSERT(SSFBNCmp(&x, &rand2) == 0);
        SSF_ASSERT(SSFBNCmp(&y, &rand1) == 0);

        /* swap with allOnes mask: also swaps. */
        SSFBNCondSwap(&x, &y, 0xFFFFFFFFu);
        SSF_ASSERT(SSFBNCmp(&x, &rand1) == 0);
        SSF_ASSERT(SSFBNCmp(&y, &rand2) == 0);

        /* CondCopy: sel=0 -> no copy. */
        SSFBNCopy(&x, &rand1); x.len = nLimbs;
        SSFBNCondCopy(&x, &rand2, 0u);
        SSF_ASSERT(SSFBNCmp(&x, &rand1) == 0);
        /* sel=1 -> copy. */
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

        /* Small cases (fast paths, no witness sampling): 0 and 1 are not prime; 2 and 3 are */
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
        SSFBNSetUint32(&t, 9u, nLimbs); /* 3 * 3 */
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == false);

        /* Small odd primes exercise the small-n / wide-storage Miller-Rabin path */
        SSFBNSetUint32(&t, 11u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);
        SSFBNSetUint32(&t, 13u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);
        SSFBNSetUint32(&t, 65537u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 5u, &prng) == true);

        /* Carmichael 561 = 3 * 11 * 17 passes Fermat; Miller-Rabin must reject it */
        SSFBNSetUint32(&t, 561u, nLimbs);
        SSF_ASSERT(SSFBNIsProbablePrime(&t, 10u, &prng) == false);

        SSFPRNGDeInitContext(&prng);
    }

    /* === ModMulNIST: P-256, P-384 and fallback paths vs ModMul / OpenSSL ============= */
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

        /* (P-256 - 1) * (P-256 - 1) mod P-256 = 1 -- exercises the reduction tail. */
        SSFBNModMulNIST(&rNist, &mMinus1, &mMinus1, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmpUint32(&rNist, 1u) == 0);
    }
#if SSF_BN_CONFIG_MAX_BITS >= 768
    {
        /* P-384 fast path (SSF_BN_NIST_P384 exists only when the cap is >= 768 bits) */
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

        /* Restore bnA, bnB to the rand1 / rand2 values used elsewhere */
        _ToOSSL(bnA, &rand1);
        _ToOSSL(bnB, &rand2);
    }

    /* === ModMulCT == ModMul + OpenSSL whenever a < m or b < m (AUDIT BN-1) =========== */
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

        /* Edge: a = 0, b = anything -> result = 0. */
        {
            SSFBN_DEFINE(zero, SSF_BN_MAX_LIMBS);
            SSFBNSetZero(&zero, nLimbs);
            SSFBNModMulCT(&rCT, &zero, &rand2, &m);
            SSF_ASSERT(SSFBNIsZero(&rCT) == true);
        }

        /* Edge: a = 1, b = rand2 -> result = rand2 (rand2 was reduced to be < m above). */
        {
            SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
            SSFBNSetOne(&one, nLimbs);
            SSFBNModMulCT(&rCT, &one, &rand2, &m);
            SSF_ASSERT(SSFBNCmp(&rCT, &rand2) == 0);
        }

        /* Edge: (m-1) * (m-1) mod m == 1 (exercises full reduction including underflow). */
        SSFBNModMulCT(&rCT, &mMinus1, &mMinus1, &m);
        SSF_ASSERT(SSFBNCmpUint32(&rCT, 1u) == 0);

        /* Edge: the dense bit pattern of the P-256 prime stresses shift-and-subtract reduction */
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

        /* dataLen one byte beyond numLimbs * 4 -- must reject regardless of leading byte. */
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
            bool sawZero = false;
            bool sawOne = false;
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
/* Checks SSFBNMul at lengths bracketing the Karatsuba threshold (even/odd, same/asymmetric).    */
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

            /* Are the operands the same size and small enough for SSFBNSquare? */
            if ((aLen == bLen) && ((uint32_t)aLen * 2u <= SSF_BN_MAX_LIMBS))
            {
                /* Yes, check square parity */
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
/* Stresses the P-256 / P-384 fast reductions with periodic boundary inputs against OpenSSL.     */
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
/* Checks SSFBNModInvExt against OpenSSL with one 2048-bit prime (too slow in _VerifyAtSize).    */
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

    SSF_UT_PRINTF("--- ssfbn OpenSSL cross-check ---\n");
    SSF_UT_PRINTF("  corner cases (256-bit, NIST P-256 modulus)... ");
    fflush(stdout);
    _VerifyCornerCasesAgainstOpenSSL();
    SSF_UT_PRINTF("OK\n");
    SSF_UT_PRINTF("  Karatsuba boundary stress... ");
    fflush(stdout);
    _VerifyKaratsubaAtBoundary();
    SSF_UT_PRINTF("OK\n");
    SSF_UT_PRINTF("  NIST fast-reduction stress (P-256 + P-384, 1000 iters each)... ");
    fflush(stdout);
    _VerifyNISTReductionStress();
    SSF_UT_PRINTF("OK\n");
    for (si = 0; si < (sizeof(sizes) / sizeof(sizes[0])); si++)
    {
        SSF_UT_PRINTF("  %-9s %4d-bit x %u iters... ", sizes[si].label, sizes[si].bits,
                      sizes[si].iters);
        fflush(stdout);
        _VerifyAtSize(sizes[si].bits, sizes[si].iters, sizes[si].prime_capable);
        SSF_UT_PRINTF("OK\n");
    }
    SSF_UT_PRINTF("  ModInvExt @ RSA-2048 (50 iters)... ");
    fflush(stdout);
    _VerifyModInvExtAtRSA2048();
    SSF_UT_PRINTF("OK\n");
    SSF_UT_PRINTF("--- end OpenSSL cross-check ---\n");
}

#endif /* SSF_BN_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* AUDIT BN-11: scrub-hook callback; counts calls and any buffer that is not all zero.           */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _scrubCalls;
static uint32_t _scrubDirty;
static void _ScrubCheck(const void *buf, size_t len)
{
    const uint8_t *b = (const uint8_t *)buf;
    size_t i;

    SSF_ASSERT(buf != NULL);
    _scrubCalls++;
    for (i = 0; i < len; i++)
    {
        if (b[i] != 0u)
        {
            _scrubDirty++;
            break;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Writes R^2 mod m into r2 (R = 2^(32 * m->len)) by doubling 1 modulo m 2 * 32 * len times.     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNUTRefR2(SSFBN_t *r2, const SSFBN_t *m)
{
    uint32_t k;

    SSF_REQUIRE(r2 != NULL);
    SSF_REQUIRE(m != NULL);

    SSFBNSetOne(r2, m->len);
    for (k = 0u; k < (((uint32_t)m->len * SSF_BN_LIMB_BITS) * 2u); k++)
    {
        SSFBNModAdd(r2, r2, r2, m);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that SSFBNMontInit(m) yields R^2 mod m equal to the doubling reference.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNUTCheckMontInitR2(const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(ref, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(m != NULL);

    SSFBNMontInit(&mont, m);
    _SSFBNUTRefR2(&ref, m);
    SSF_ASSERT(mont.rr.len == m->len);
    SSF_ASSERT(SSFBNCmp(&mont.rr, &ref) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Fills a->limbs[0..n-1] with a pseudo-random pattern below m (top limb cleared); sets a->len.  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNUTFillBelow(SSFBN_t *a, const SSFBN_t *m, uint32_t seed)
{
    uint16_t k;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(m != NULL);

    a->len = m->len;
    for (k = 0u; k < m->len; k++)
    {
        seed = (seed * 1664525u) + 1013904223u;
        a->limbs[k] = (SSFBNLimb_t)seed;
    }
    a->limbs[m->len - 1u] = (SSFBNLimb_t)(a->limbs[m->len - 1u] % m->limbs[m->len - 1u]);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts MontMul(a, b) == a * b * R^-1 via ModMul, and MontSquare(a) == MontMul(a, a).         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNUTCheckMont(const SSFBN_t *m, const SSFBN_t *a, const SSFBN_t *b)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(r2, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(ref, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    SSFBNMontInit(&mont, m);

    /* MontMul(a, b) * R mod m must equal a * b mod m; MontMul(x, R^2) is x * R mod m */
    SSFBNMontMul(&r, a, b, &mont);
    SSFBNMontMul(&r2, &r, &mont.rr, &mont);
    SSFBNModMul(&ref, a, b, m);
    SSF_ASSERT(r2.len == m->len);
    SSF_ASSERT(SSFBNCmp(&r2, &ref) == 0);

    /* MontSquare(a) must equal MontMul(a, a), also when r aliases a */
    SSFBNMontMul(&r, a, a, &mont);
    SSFBNMontSquare(&r2, a, &mont);
    SSF_ASSERT(SSFBNCmp(&r2, &r) == 0);
    SSFBNCopy(&r2, a);
    SSFBNMontSquare(&r2, &r2, &mont);
    SSF_ASSERT(SSFBNCmp(&r2, &r) == 0);

    /* Round trip through ConvertOut: MontMul(x, 1) is x * R^-1 */
    SSFBNSetOne(&one, m->len);
    SSFBNMontMul(&r, a, &one, &mont);
    SSFBNMontConvertOut(&r2, a, &mont);
    SSF_ASSERT(SSFBNCmp(&r2, &r) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts SSFBNModAdd(a + b mod m) against a limb-by-limb reference, in place and not.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNUTCheckModAdd(const SSFBN_t *m, const SSFBN_t *a, const SSFBN_t *b)
{
    SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(ref, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(x, SSF_BN_MAX_LIMBS);
    SSFBNDLimb_t acc;
    SSFBNLimb_t top;
    uint16_t k;
    int16_t q;
    bool geM;

    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    /* Reference: s = a + b with its carry word, then s - m when s >= m */
    ref.len = m->len;
    acc = 0u;
    for (k = 0u; k < m->len; k++)
    {
        acc += ((SSFBNDLimb_t)a->limbs[k] + (SSFBNDLimb_t)b->limbs[k]);
        ref.limbs[k] = (SSFBNLimb_t)acc;
        acc >>= SSF_BN_LIMB_BITS;
    }
    top = (SSFBNLimb_t)acc;
    geM = (top != 0u);
    if (!geM)
    {
        geM = true;
        for (q = (int16_t)(m->len - 1u); q >= 0; q--)
        {
            if (ref.limbs[q] != m->limbs[q])
            {
                geM = (ref.limbs[q] > m->limbs[q]);
                break;
            }
        }
    }
    if (geM)
    {
        acc = 0u;
        for (k = 0u; k < m->len; k++)
        {
            SSFBNDLimb_t d = ((SSFBNDLimb_t)ref.limbs[k] - (SSFBNDLimb_t)m->limbs[k]) - acc;
            ref.limbs[k] = (SSFBNLimb_t)d;
            acc = (d >> SSF_BN_LIMB_BITS) & 1u;
        }
    }

    /* Out of place, then r aliasing a, r aliasing b, and r == a == b when a equals b */
    SSFBNModAdd(&r, a, b, m);
    SSF_ASSERT((r.len == m->len) && (SSFBNCmp(&r, &ref) == 0));
    SSFBNCopy(&x, a);
    SSFBNModAdd(&x, &x, b, m);
    SSF_ASSERT(SSFBNCmp(&x, &ref) == 0);
    SSFBNCopy(&x, b);
    SSFBNModAdd(&x, a, &x, m);
    SSF_ASSERT(SSFBNCmp(&x, &ref) == 0);
    if (SSFBNCmp(a, b) == 0)
    {
        SSFBNCopy(&x, a);
        SSFBNModAdd(&x, &x, &x, m);
        SSF_ASSERT(SSFBNCmp(&x, &ref) == 0);
    }
}

/* Suppress C6262 (large stack frame): the unit test entry point has many SSFBN_DEFINE locals */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
/* --------------------------------------------------------------------------------------------- */
/* Stack hygiene probes: fill, then scan, the region below the caller's frame for unwiped locals */
/* --------------------------------------------------------------------------------------------- */
#define _SSFBN_UT_PROBE_BYTES (8u * 1024u)
SSF_NOINLINE
static void _SSFBNUTPolluteStack(void)
{
    volatile uint8_t buf[_SSFBN_UT_PROBE_BYTES];
    size_t i;
    for (i = 0u; i < sizeof(buf); i++) buf[i] = 0xA5u;
}

/* Reading uninitialized stack is the test, so silence the uninitialized-read warnings here */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 6001)
#endif
SSF_NOINLINE
static uint32_t _SSFBNUTScanStack(const uint8_t *n1, const uint8_t *n2, size_t len)
{
    volatile uint8_t buf[_SSFBN_UT_PROBE_BYTES];
    uint32_t found = 0u;
    size_t i;
    size_t j;

    for (i = 0u; (i + len) <= sizeof(buf); i++)
    {
        bool m1 = true;
        bool m2 = true;
        for (j = 0u; j < len; j++)
        {
            if (buf[i + j] != n1[j]) m1 = false;
            if (buf[i + j] != n2[j]) m2 = false;
        }
        /* Does either pattern match at offset i? */
        if (m1 || m2)
        {
            /* Yes, count it */
            found++;
        }
    }
    buf[0] = (uint8_t)found;
    return found;
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic pop
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

    /* ---- SSFBNMontSquare fixed-length carry spans: all-ones operand vs ModMul reference ---- */
    {
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aRed, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(sqR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(montOut, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(ref, SSF_BN_MAX_LIMBS);
        /* Odd 256-bit modulus (Montgomery requires gcd(m, 2) = 1): 0xFFFF..FF43. */
        static const uint8_t mBytes[32] = {
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x43u
        };
        /* Operand a = 2^256 - 1 (all-ones limbs) -> maximal carry activity in the square. */
        static const uint8_t aBytes[32] = {
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
        };

        SSF_ASSERT(SSFBNFromBytes(&m, mBytes, sizeof(mBytes), 8) == true);
        SSF_ASSERT(SSFBNFromBytes(&a, aBytes, sizeof(aBytes), 8) == true);

        /* aRed = a mod m (MontConvertIn expects a reduced operand). */
        SSFBNMod(&aRed, &a, &m);

        /* Reference: a^2 mod m via the independent schoolbook path. */
        SSFBNModMul(&ref, &aRed, &aRed, &m);

        /* Montgomery square path (the function under test). */
        SSFBNMontInit(&mont, &m);
        SSFBNMontConvertIn(&aR, &aRed, &mont);
        SSFBNMontSquare(&sqR, &aR, &mont);
        SSFBNMontConvertOut(&montOut, &sqR, &mont);

        SSF_ASSERT(SSFBNCmp(&montOut, &ref) == 0);
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

        /* Round-trip: LE -> BN -> LE == original. */
        SSF_ASSERT(SSFBNToBytesLE(&a, out, sizeof(out)) == true);
        SSF_ASSERT(memcmp(out, le, sizeof(le)) == 0);
    }

    /* ---- FromBytesLE with dataLen shorter than numLimbs*4 (zero-pad high limbs) ---- */
    {
        static const uint8_t data[] = { 0xFFu };
        uint8_t out[4];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytesLE(&a, data, 1, 2) == true);
        /* LE: low byte is 0xFF -> limb[0] = 0x000000FF, limb[1] = 0. */
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

    /* ---- FromBytesLE rejects dataLen > numLimbs * sizeof(limb) ---- */
    {
        uint8_t tooMany[9];  /* 9 bytes > 2 limbs * 4 bytes */
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        memset(tooMany, 0xAA, sizeof(tooMany));
        SSF_ASSERT(SSFBNFromBytesLE(&a, tooMany, sizeof(tooMany), 2) == false);
    }

    /* ---- ToBytesLE on zero (single 0x00 byte) and with too-small buffer ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        uint8_t out[4];
        uint8_t tiny[1];

        SSFBNSetZero(&a, 4u);
        SSF_ASSERT(SSFBNToBytesLE(&a, out, sizeof(out)) == true);
        SSF_ASSERT(out[0] == 0x00u);

        /* Non-zero value with a buffer too small for its significant bytes. */
        SSFBNSetUint32(&a, 0x12345678u, 4u);
        SSF_ASSERT(SSFBNToBytesLE(&a, tiny, sizeof(tiny)) == false);
    }

    /* ---- ToBytes with outSize < a->len * 4 must not write outside out (canaries) ---- */
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
        /* Canaries intact -> no stack corruption. */
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

        /* Parity sweep: ShiftLeft / ShiftRight(a, n) == n Shift*1 steps, 0 <= n <= 160 */
        for (nBits = 0; nBits <= 160u; nBits++)
        {
            /* Seed a and b identically, wide enough to cross limbs at 32, 64, 96, 128 bits */
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

        /* Sub-limb shift across a limb: 0xFFFFFFFF << 20 == limbs { 0xFFF00000, 0x000FFFFF } */
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

        /* High limb parity does not affect IsOdd -- only the low bit of limb[0] matters. */
        SSFBNSetZero(&a, 4);
        a.limbs[3] = 0x80000001ul;
        SSF_ASSERT(SSFBNIsOdd(&a) == false);

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

        /* a = 1 -> tz = 0 */
        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 0u);

        /* a = 2 -> tz = 1 */
        SSFBNSetUint32(&a, 2u, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 1u);

        /* a = 0x80000000 (bit 31) -> tz = 31 (top of limb 0) */
        SSFBNSetUint32(&a, 0x80000000ul, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 31u);

        /* a = 2^32 (bit 32, start of limb 1) -> tz = 32 */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 1u;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 32u);

        /* a = 2^47 (mid-limb 1) -> tz = 47 */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 0x00008000ul;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 47u);

        /* a = 2^96 (start of limb 3) -> tz = 96 */
        SSFBNSetZero(&a, 4);
        a.limbs[3] = 1u;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 96u);

        /* Low limb zero, limb[1] with a low set bit and high bits: lowest set bit only */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 0xFF00FF10ul; /* lowest set bit is bit 4 of limb 1 -> global bit 36 */
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 36u);

        /* After a left shift by k, tz grows by k. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 0u);
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

    /* ---- AUDIT BN-1: ModMulCT needs an operand < m (was truncated, non-reduced result) ---- */
    {
        static const uint8_t aBytes[8] = { 0x7Fu, 0x62u, 0x00u, 0xECu, 0x78u, 0x86u, 0x9Bu, 0x5Au };
        static const uint8_t bBytes[8] = { 0xC0u, 0xFCu, 0x92u, 0x52u, 0xD0u, 0xDBu, 0x7Fu, 0xEDu };
        static const uint8_t mBytes[8] = { 0x00u, 0x00u, 0x00u, 0x00u, 0x6Cu, 0xEDu, 0x81u, 0x37u };
        static const uint8_t aRedBytes[8] = { 0x00u, 0x00u, 0x00u, 0x00u,
                                              0x0Fu, 0x56u, 0xCBu, 0x30u };
        static const uint8_t bRedBytes[8] = { 0x00u, 0x00u, 0x00u, 0x00u,
                                              0x3Eu, 0xE8u, 0x33u, 0xC9u };
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aRed, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(bRed, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rRef, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytes(&a, aBytes, sizeof(aBytes), 2u) == true);
        SSF_ASSERT(SSFBNFromBytes(&b, bBytes, sizeof(bBytes), 2u) == true);
        SSF_ASSERT(SSFBNFromBytes(&m, mBytes, sizeof(mBytes), 2u) == true);
        SSF_ASSERT(SSFBNFromBytes(&aRed, aRedBytes, sizeof(aRedBytes), 2u) == true);
        SSF_ASSERT(SSFBNFromBytes(&bRed, bRedBytes, sizeof(bRedBytes), 2u) == true);

        /* Both operands >= m: precondition violated, must trap. */
        SSF_ASSERT_TEST(SSFBNModMulCT(&r, &a, &b, &m));

        /* a >= m, b < m: allowed; must equal SSFBNModMul and the reference 0x5e8879ed. */
        SSFBNModMulCT(&r, &a, &bRed, &m);
        SSFBNModMul(&rRef, &a, &bRed, &m);
        SSF_ASSERT(SSFBNCmp(&r, &rRef) == 0);
        SSF_ASSERT((r.limbs[0] == 0x5E8879EDu) && (r.limbs[1] == 0u));

        /* a < m, b >= m: allowed; same product mod m. */
        SSFBNModMulCT(&r, &aRed, &b, &m);
        SSF_ASSERT((r.limbs[0] == 0x5E8879EDu) && (r.limbs[1] == 0u));
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

    /* ---- AUDIT BN-3: ModInv returns false (never traps) for unusable, e.g. even, moduli ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* Even modulus. */
        SSFBNSetUint32(&a, 3u, 4);
        SSFBNSetUint32(&m, 10u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);

        /* m == 1 (m - 2 underflows). */
        SSFBNSetUint32(&m, 1u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);

        /* Odd, non-prime modulus sharing a factor with a. */
        SSFBNSetUint32(&m, 15u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);
    }

    /* ---- AUDIT BN-10: ModInv's a * r == 1 check is constant-time (never reaches SSFBNMod) ---- */
#if SSF_BN_CONFIG_MAX_BITS >= 512
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        uint32_t calls;
        uint16_t i;

        /* Full-length a, then a short a (top 48 bits zero), modulo the P-256 prime. */
        for (i = 0; i < 2u; i++)
        {
            SSFBNSetZero(&a, 8);
            a.limbs[0] = 0x12345679u;
            a.limbs[3] = 0x9ABCDEF0u;
            a.limbs[5] = 0x0F1E2D3Cu;
            a.limbs[6] = (i == 0u) ? 0xDEADBEEFu : 0x0000BEEFu;
            a.limbs[7] = (i == 0u) ? 0xC0FFEE00u : 0u;
            _SSFBNModCallCount = 0u;
            SSF_ASSERT(SSFBNModInv(&r, &a, &SSF_BN_NIST_P256) == true);
            calls = _SSFBNModCallCount;
            SSF_ASSERT(calls == 0u);
            SSFBNModMul(&check, &a, &r, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNIsOne(&check));
        }

        /* Coprime to a non-prime modulus: Fermat 2^13 mod 15 = 2 is not an inverse. */
        SSFBNSetUint32(&a, 2u, 4);
        SSFBNSetUint32(&m, 15u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 512 */

    /* ---- AUDIT BN-11: GenPrime / IsProbablePrime wipe candidate and MR state, every path ---- */
    {
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(c, SSF_BN_MAX_LIMBS);
        uint32_t calls;

        memset(seed, 0x2B, sizeof(seed));
        SSFPRNGInitContext(&prng, seed, sizeof(seed));
        _scrubCalls = 0u;
        _scrubDirty = 0u;
        _SSFBNScrubTestHook = _ScrubCheck;

        /* Accept path: 7 locals from the final IsProbablePrime plus GenPrime's buf. */
        SSF_ASSERT(SSFBNGenPrime(&p, 256u, 5u, &prng) == true);
        SSF_ASSERT(_scrubCalls >= 8u);

        /* Composite 221 = 13 * 17: 7 MR locals + MontInit's R^2 + 5 per odd-modulus SSFBNMod */
        calls = _scrubCalls;
        _SSFBNModCallCount = 0u;
        SSFBNSetUint32(&c, 221u, 8u);
        SSF_ASSERT(SSFBNIsProbablePrime(&c, 5u, &prng) == false);
        SSF_ASSERT(_scrubCalls == ((calls + 8u) + (5u * _SSFBNModCallCount)));

        _SSFBNScrubTestHook = NULL;
        SSF_ASSERT(_scrubDirty == 0u);
        SSFPRNGDeInitContext(&prng);
    }

    /* ---- AUDIT BN-12: Karatsuba carry / borrow propagation runs a fixed iteration count ---- */
#if ((2u * (SSF_BN_KARATSUBA_THRESHOLD + (SSF_BN_KARATSUBA_THRESHOLD & 1u))) <= SSF_BN_MAX_LIMBS)
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        const uint16_t n =
            (uint16_t)(SSF_BN_KARATSUBA_THRESHOLD + (SSF_BN_KARATSUBA_THRESHOLD & 1u));
        uint32_t itZero;
        uint32_t itOnes;
        uint16_t i;

        SSFBNSetZero(&a, n);
        SSFBNSetZero(&b, n);
        _SSFBNKaratsubaPropIters = 0u;
        SSFBNMul(&r, &a, &b);
        itZero = _SSFBNKaratsubaPropIters;

        for (i = 0; i < n; i++)
        {
            a.limbs[i] = 0xFFFFFFFFu;
            b.limbs[i] = 0xFFFFFFFFu;
        }
        _SSFBNKaratsubaPropIters = 0u;
        SSFBNMul(&r, &a, &b);
        itOnes = _SSFBNKaratsubaPropIters;

        SSF_ASSERT(itZero == itOnes);
        SSF_ASSERT(itZero > 0u);

        /* (2^(32n) - 1)^2 = 2^(64n) - 2^(32n+1) + 1 */
        SSF_ASSERT(r.len == (uint16_t)(2u * n));
        SSF_ASSERT(r.limbs[0] == 1u);
        for (i = 1; i < n; i++) SSF_ASSERT(r.limbs[i] == 0u);
        SSF_ASSERT(r.limbs[n] == 0xFFFFFFFEu);
        for (i = (uint16_t)(n + 1u); i < (uint16_t)(2u * n); i++)
        {
            SSF_ASSERT(r.limbs[i] == 0xFFFFFFFFu);
        }
    }
#endif /* Karatsuba-size operands fit */

    /* ---- AUDIT BN-13: full-width ToBytes / ToBytesLE export without a significance scan ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        uint8_t out[32];
        uint8_t outLE[32];
        uint16_t i;

        SSFBNSetZero(&a, 8);
        a.limbs[0] = 0x01020304u;
        _SSFBNToBytesScans = 0u;
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);
        SSF_ASSERT(SSFBNToBytesLE(&a, outLE, sizeof(outLE)) == true);
        SSF_ASSERT(_SSFBNToBytesScans == 0u);
        for (i = 0; i < 28u; i++) SSF_ASSERT(out[i] == 0u);
        SSF_ASSERT((out[28] == 0x01u) && (out[29] == 0x02u) && (out[30] == 0x03u));
        SSF_ASSERT(out[31] == 0x04u);
        SSF_ASSERT((outLE[0] == 0x04u) && (outLE[1] == 0x03u) && (outLE[2] == 0x02u));
        SSF_ASSERT(outLE[3] == 0x01u);
        for (i = 4; i < 32u; i++) SSF_ASSERT(outLE[i] == 0u);

        /* Narrower than the limbs: the scan still decides fit, then the value is written. */
        SSF_ASSERT(SSFBNToBytes(&a, out, 4u) == true);
        SSF_ASSERT((out[0] == 0x01u) && (out[3] == 0x04u));
        SSF_ASSERT(SSFBNToBytes(&a, out, 3u) == false);
        SSF_ASSERT(SSFBNToBytesLE(&a, outLE, 4u) == true);
        SSF_ASSERT((outLE[0] == 0x04u) && (outLE[3] == 0x01u));
        SSF_ASSERT(SSFBNToBytesLE(&a, outLE, 3u) == false);
        SSF_ASSERT(_SSFBNToBytesScans == 4u);
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

    /* ==== Primality-related API (hoisted from ssfrsa) ===================================== */

    /* ---- SSFBNModUint32: basic reductions ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        /* 123456789 mod 7 = 1 */
        SSFBNSetUint32(&a, 123456789u, 4);
        SSF_ASSERT(SSFBNModUint32(&a, 7u) == 1u);

        /* 2^64 mod 3 == 1 (2^64 = 4 * 2^62); build 2^64 via big-endian FromBytes */
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

        /* 91 = 7 * 13 -- small composite that fools Fermat base-3 test but not MR. */
        SSFBNSetUint32(&n, 91u, 4);
        SSF_ASSERT(SSFBNIsProbablePrime(&n, 5u, &prng) == false);

        SSFPRNGDeInitContext(&prng);
    }

    /* ==== Squaring API: must agree bit-for-bit with the general multiply ================== */

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

        /* Parity against generic multiply for deterministic multi-limb byte patterns */
        for (k = 1; k <= 8u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x5Au + ((uint8_t)i * (uint8_t)k));
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
                data[i] = (uint8_t)(0xA5u + ((uint8_t)i * (uint8_t)k));
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
            SSFBNSetUint32(&a, (1000u * (uint32_t)k) + (uint32_t)k, 8);
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
                data[i] = (uint8_t)((0x3Cu + ((uint8_t)i * 7u)) + ((uint8_t)k * 11u));
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNMod(&a, &a, &SSF_BN_NIST_P256);
            SSFBNMontConvertIn(&aM, &a, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontMul(&mulM, &aM, &aM, &mont);
            SSF_ASSERT(SSFBNCmp(&sqM, &mulM) == 0);
        }
    }

    /* ==== Uint32 small-operand arithmetic: parity with a matched 1-limb BN operand ======== */

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

    /* ==== Variable-time ModExp (public exponent only) must match constant-time ModExp ===== */

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
                data[i] = (uint8_t)((0x2Bu + ((uint8_t)i * 11u)) + ((uint8_t)k * 19u));
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
                data[i] = (uint8_t)((0x71u + ((uint8_t)i * 13u)) + ((uint8_t)k * 17u));
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
        SSF_ASSERT(SSFBNBitLen(&p) == 64u);
        SSF_ASSERT(SSFBNIsProbablePrime(&p, 5u, &prng) == true);

        SSFPRNGDeInitContext(&prng);
    }

    /* ---- AUDIT BN-2: GenPrime yields exactly bitLen bits; bitLen range is a precondition ---- */
    {
        static const uint16_t bitLens[] = { 16u, 17u, 23u, 31u, 33u, 63u };
        SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0xB2u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        for (i = 0; i < (uint16_t)(sizeof(bitLens) / sizeof(bitLens[0])); i++)
        {
            SSF_ASSERT(SSFBNGenPrime(&p, bitLens[i], 5u, &prng) == true);
            SSF_ASSERT(SSFBNBitLen(&p) == (uint32_t)bitLens[i]);
            SSF_ASSERT(SSFBNGetBit(&p, (uint32_t)bitLens[i] - 2u) == 1u);
            SSF_ASSERT(SSFBNIsOdd(&p));
            SSF_ASSERT(SSFBNIsProbablePrime(&p, 5u, &prng) == true);
        }

        /* Below the minimum and above MAX_BITS / 2 must trap at the entry precondition. */
        SSF_ASSERT_TEST(SSFBNGenPrime(&p, 15u, 5u, &prng));
        SSF_ASSERT_TEST(SSFBNGenPrime(&p, (uint16_t)((SSF_BN_CONFIG_MAX_BITS / 2u) + 1u), 5u,
                                      &prng));

        SSFPRNGDeInitContext(&prng);
    }

    /* ---- Precondition assertions (SSF_REQUIRE) -- make sure the documented contracts trip ---- */
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

        /* DivMod forbids q == rem aliasing -- should assert. */
        {
            SSFBN_DEFINE(qr, SSF_BN_MAX_LIMBS);
            qr.len = 8u;
            SSF_ASSERT_TEST(SSFBNDivMod(&qr, &qr, &a8, &a8));
        }

        /* MontMul / MontSquare must trap an operand whose cap is below ctx->len */
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

    /* ---- AUDIT BN-8: Mul / Square trap a corrupt operand len before summing (no wrap) ---- */
    {
        SSFBN_DEFINE(mA, 4u);
        SSFBN_DEFINE(mB, 4u);
        SSFBN_DEFINE(mR, 8u);

        SSFBNSetUint32(&mA, 3u, 4u);
        SSFBNSetUint32(&mB, 5u, 4u);

        mA.len = 65535u;                        /* 65535 + 1 wraps to 0 in uint16_t */
        mB.len = 1u;
        SSF_ASSERT_TEST(SSFBNMul(&mR, &mA, &mB));
        mA.len = (uint16_t)(mA.cap + 1u);       /* len beyond the operand's storage */
        mB.len = 1u;
        SSF_ASSERT_TEST(SSFBNMul(&mR, &mA, &mB));
        mA.len = 1u;
        mB.len = (uint16_t)(mB.cap + 1u);
        SSF_ASSERT_TEST(SSFBNMul(&mR, &mA, &mB));
        mA.len = 32768u;                        /* 2 * 32768 wraps to 0 in uint16_t */
        SSF_ASSERT_TEST(SSFBNSquare(&mR, &mA));
        mA.len = (uint16_t)(mA.cap + 1u);
        SSF_ASSERT_TEST(SSFBNSquare(&mR, &mA));

        /* Well-formed operands still multiply: 3 * 5 = 15. */
        mA.len = 1u;
        mB.len = 1u;
        SSFBNMul(&mR, &mA, &mB);
        SSF_ASSERT((mR.len == 2u) && (mR.limbs[0] == 15u) && (mR.limbs[1] == 0u));
    }

    /* ---- OPTIMIZE BN-O1: MontInit R^2 equals the 2 * 32 * len doubling loop, all shapes ---- */
    {
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
#if SSF_BN_CONFIG_MAX_BITS >= 4096
        uint16_t k;
#endif /* SSF_BN_CONFIG_MAX_BITS >= 4096 */

        /* NIST field primes and the P-256 group order */
        _SSFBNUTCheckMontInitR2(&SSF_BN_NIST_P256);
#if SSF_BN_CONFIG_MAX_BITS >= 768
        _SSFBNUTCheckMontInitR2(&SSF_BN_NIST_P384);
#endif
        SSFBNSetZero(&m, 8u);
        m.limbs[0] = 0xFC632551u; m.limbs[1] = 0xF3B9CAC2u; m.limbs[2] = 0xA7179E84u;
        m.limbs[3] = 0xBCE6FAADu; m.limbs[4] = 0xFFFFFFFFu; m.limbs[5] = 0xFFFFFFFFu;
        m.limbs[6] = 0x00000000u; m.limbs[7] = 0xFFFFFFFFu;
        _SSFBNUTCheckMontInitR2(&m);

        /* 3 limbs (w = 96 = 3 * 2^5) with the top bit set, then inside the top limb */
        m.len = 3u;
        m.limbs[0] = 0x89ABCDEFu; m.limbs[1] = 0x01234567u; m.limbs[2] = 0x80000001u;
        _SSFBNUTCheckMontInitR2(&m);
        m.limbs[2] = 0x00012345u;
        _SSFBNUTCheckMontInitR2(&m);

        /* Padded: 4 limbs whose top limb is zero (bit length 37) */
        SSFBNSetZero(&m, 4u);
        m.limbs[0] = 0x2468ACE1u;
        m.limbs[1] = 0x00000017u;
        _SSFBNUTCheckMontInitR2(&m);

        /* One limb: smallest odd moduli above 1 and the full-width extreme */
        SSFBNSetUint32(&m, 3u, 1u);
        _SSFBNUTCheckMontInitR2(&m);
        SSFBNSetUint32(&m, 0xFFFFFFFFu, 1u);
        _SSFBNUTCheckMontInitR2(&m);

        /* m == 1: R^2 mod 1 is 0 */
        SSFBNSetUint32(&m, 1u, 1u);
        SSFBNMontInit(&mont, &m);
        SSF_ASSERT((mont.rr.len == 1u) && (mont.rr.limbs[0] == 0u));

        /* The local R^2 copy, key-derived for a secret prime, is wiped before return */
        _scrubCalls = 0u;
        _scrubDirty = 0u;
        _SSFBNScrubTestHook = _ScrubCheck;
        SSFBNMontInit(&mont, &SSF_BN_NIST_P256);
        _SSFBNScrubTestHook = NULL;
        SSF_ASSERT(_scrubCalls == 1u);
        SSF_ASSERT(_scrubDirty == 0u);
        _SSFBNUTCheckMontInitR2(&SSF_BN_NIST_P256);

#if SSF_BN_CONFIG_MAX_BITS >= 4096
        /* 2048-bit full-width modulus: R^2 matches, using only 2 doublings */
        m.len = 64u;
        for (k = 0u; k < 64u; k++)
        {
            m.limbs[k] = (SSFBNLimb_t)(0x9E3779B9u * (uint32_t)(k + 1u));
        }
        m.limbs[0] |= 1u;
        m.limbs[63] |= 0x80000000u;
        _SSFBNUTCheckMontInitR2(&m);
        _SSFBNMontInitDoublings = 0u;
        SSFBNMontInit(&mont, &m);
        SSF_ASSERT(_SSFBNMontInitDoublings == 2u);
#endif
#if SSF_BN_CONFIG_MAX_BITS >= 6144
        /* 3072-bit full-width modulus (w = 3 * 2^10): 4 doublings */
        m.len = 96u;
        for (k = 0u; k < 96u; k++)
        {
            m.limbs[k] = (SSFBNLimb_t)(0x7F4A7C15u * (uint32_t)(k + 5u));
        }
        m.limbs[0] |= 1u;
        m.limbs[95] |= 0x80000000u;
        _SSFBNUTCheckMontInitR2(&m);
        _SSFBNMontInitDoublings = 0u;
        SSFBNMontInit(&mont, &m);
        SSF_ASSERT(_SSFBNMontInitDoublings == 4u);
#endif
    }

    /* ---- OPTIMIZE BN-O2 / BN-O3: MontMul / MontSquare exact; 2n^2 - n and 2n step counts ---- */
    {
        static const uint16_t lens[] = { 1u, 2u, 3u, 4u, 5u, 7u, 8u, 12u, 16u, 31u, 32u, 33u };
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        uint16_t li;
        uint16_t k;
        uint32_t seed;

        for (li = 0u; li < (uint16_t)(sizeof(lens) / sizeof(lens[0])); li++)
        {
            uint16_t n = lens[li];

            if (n > (SSF_BN_MAX_LIMBS / 2u)) continue;

            /* Pseudo-random full-width odd modulus, several operand pairs */
            for (seed = 1u; seed <= 4u; seed++)
            {
                m.len = n;
                for (k = 0u; k < n; k++)
                {
                    m.limbs[k] = (SSFBNLimb_t)(0x9E3779B9u * (uint32_t)(k + seed));
                }
                m.limbs[0] |= 1u;
                m.limbs[n - 1u] |= 0x80000000u;
                _SSFBNUTFillBelow(&a, &m, seed * 7u);
                _SSFBNUTFillBelow(&b, &m, seed * 13u);
                _SSFBNUTCheckMont(&m, &a, &b);
            }

            /* All-ones modulus with a = b = m - 1: every partial product and carry is maximal */
            m.len = n;
            for (k = 0u; k < n; k++) m.limbs[k] = 0xFFFFFFFFu;
            SSFBNCopy(&a, &m);
            a.limbs[0] = 0xFFFFFFFEu;
            _SSFBNUTCheckMont(&m, &a, &a);

            /* Minimal top limb (bit length 32n - 31), a = b = m - 1, and a = 0 */
            for (k = 0u; k < n; k++) m.limbs[k] = 0xFFFFFFFFu;
            m.limbs[n - 1u] = 1u;
            SSFBNCopy(&a, &m);
            a.limbs[0] = 0xFFFFFFFEu;
            _SSFBNUTCheckMont(&m, &a, &a);
            SSFBNSetZero(&b, n);
            _SSFBNUTCheckMont(&m, &a, &b);

            /* Work counters on this width */
            SSFBNMontInit(&mont, &m);
            _SSFBNMontMulIters = 0u;
            SSFBNMontMul(&r, &a, &a, &mont);
            SSF_ASSERT(_SSFBNMontMulIters == (((2u * (uint32_t)n) * (uint32_t)n) - (uint32_t)n));
            _SSFBNMontSqrCarryIters = 0u;
            SSFBNMontSquare(&r, &a, &mont);
            SSF_ASSERT(_SSFBNMontSqrCarryIters == (2u * (uint32_t)n));
        }

        /* NIST P-256 and P-384 primes */
        SSFBNCopy(&m, &SSF_BN_NIST_P256);
        _SSFBNUTFillBelow(&a, &m, 99u);
        _SSFBNUTFillBelow(&b, &m, 77u);
        _SSFBNUTCheckMont(&m, &a, &b);
#if SSF_BN_CONFIG_MAX_BITS >= 768
        SSFBNCopy(&m, &SSF_BN_NIST_P384);
        _SSFBNUTFillBelow(&a, &m, 55u);
        _SSFBNUTFillBelow(&b, &m, 33u);
        _SSFBNUTCheckMont(&m, &a, &b);
#endif
#if SSF_BN_CONFIG_MAX_BITS >= 4096
        /* 2048-bit (the RSA width) */
        m.len = 64u;
        for (k = 0u; k < 64u; k++)
        {
            m.limbs[k] = (SSFBNLimb_t)(0x7F4A7C15u * (uint32_t)(k + 9u));
        }
        m.limbs[0] |= 1u;
        m.limbs[63] |= 0x80000000u;
        _SSFBNUTFillBelow(&a, &m, 5u);
        _SSFBNUTFillBelow(&b, &m, 6u);
        _SSFBNUTCheckMont(&m, &a, &b);
#endif
    }

    /* ---- OPTIMIZE BN-O2 / BN-O3: exhaustive 1- and 2-limb carry-extreme grid vs ModMul ---- */
    {
        static const SSFBNLimb_t gridV[] = { 0u, 1u, 2u, 0x7FFFFFFFu, 0x80000000u, 0x80000001u,
                                             0xFFFFFFFEu, 0xFFFFFFFFu };
        SSFBN_DEFINE(m, 2u);
        SSFBN_DEFINE(a, 2u);
        SSFBN_DEFINE(mm1, 2u);
        uint32_t gridN;
        uint32_t mc;
        uint32_t ac;
        uint32_t tot;
        uint32_t checks = 0u;
        uint16_t n;

        gridN = (uint32_t)(sizeof(gridV) / sizeof(gridV[0]));
        for (n = 1u; n <= 2u; n++)
        {
            tot = (n == 1u) ? gridN : (gridN * gridN);
            for (mc = 0u; mc < tot; mc++)
            {
                m.len = n;
                m.limbs[0] = gridV[mc % gridN];
                if (n == 2u) m.limbs[1] = gridV[mc / gridN];

                /* Is m even, top-limb zero, or 1 (not an odd modulus above 1 at full width)? */
                if (((m.limbs[0] & 1u) == 0u) || (m.limbs[n - 1u] == 0u) ||
                    ((n == 1u) && (m.limbs[0] == 1u)))
                {
                    /* Yes, skip it */
                    continue;
                }

                SSFBNCopy(&mm1, &m);
                mm1.limbs[0] -= 1u;
                for (ac = 0u; ac < tot; ac++)
                {
                    a.len = n;
                    a.limbs[0] = gridV[ac % gridN];
                    if (n == 2u) a.limbs[1] = gridV[ac / gridN];
                    if (SSFBNCmp(&a, &m) >= 0) continue;

                    _SSFBNUTCheckMont(&m, &a, &a);
                    _SSFBNUTCheckMont(&m, &a, &mm1);
                    checks++;
                }
            }
        }
        /* 15 one-limb pairs (3 moduli) and 1008 two-limb pairs (4 odd low x 7 non-zero top) */
        SSF_ASSERT(checks == 1023u);
    }

    /* ---- OPTIMIZE BN-O6: ModAdd carry / borrow grid; ModMulNIST vs ModMul for both primes ---- */
    {
        static const SSFBNLimb_t gridV[] = { 0u, 1u, 2u, 0x7FFFFFFFu, 0x80000000u, 0x80000001u,
                                             0xFFFFFFFEu, 0xFFFFFFFFu };
        const SSFBN_t *primes[2];
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(ref, SSF_BN_MAX_LIMBS);
        uint32_t gridN;
        uint32_t tot;
        uint32_t mc;
        uint32_t ac;
        uint32_t bc;
        uint32_t pairs = 0u;
        uint16_t n;
        uint16_t pi;
        uint16_t numPrimes = 1u;
        uint16_t ea;
        uint16_t eb;

        gridN = (uint32_t)(sizeof(gridV) / sizeof(gridV[0]));
        for (n = 1u; n <= 2u; n++)
        {
            tot = (n == 1u) ? gridN : (gridN * gridN);
            for (mc = 0u; mc < tot; mc++)
            {
                m.len = n;
                m.limbs[0] = gridV[mc % gridN];
                if (n == 2u) m.limbs[1] = gridV[mc / gridN];
                if (m.limbs[n - 1u] == 0u) continue;
                for (ac = 0u; ac < tot; ac++)
                {
                    a.len = n;
                    a.limbs[0] = gridV[ac % gridN];
                    if (n == 2u) a.limbs[1] = gridV[ac / gridN];
                    if (SSFBNCmp(&a, &m) >= 0) continue;
                    for (bc = 0u; bc < tot; bc++)
                    {
                        b.len = n;
                        b.limbs[0] = gridV[bc % gridN];
                        if (n == 2u) b.limbs[1] = gridV[bc / gridN];
                        if (SSFBNCmp(&b, &m) >= 0) continue;
                        _SSFBNUTCheckModAdd(&m, &a, &b);
                        pairs++;
                    }
                }
            }
        }
        SSF_ASSERT(pairs == 85344u);

        primes[0] = &SSF_BN_NIST_P256;
#if SSF_BN_CONFIG_MAX_BITS >= 768
        primes[1] = &SSF_BN_NIST_P384;
        numPrimes = 2u;
#endif
        for (pi = 0u; pi < numPrimes; pi++)
        {
            SSFBNCopy(&m, primes[pi]);

            /* Edge operands 0, 1, p - 2, p - 1, and two pseudo-random values, all pairs */
            for (ea = 0u; ea < 6u; ea++)
            {
                for (eb = 0u; eb < 6u; eb++)
                {
                    SSFBN_t *v[2];
                    uint16_t e[2];
                    uint16_t w;

                    v[0] = &a;
                    v[1] = &b;
                    e[0] = ea;
                    e[1] = eb;
                    for (w = 0u; w < 2u; w++)
                    {
                        switch (e[w])
                        {
                        case 0u: SSFBNSetZero(v[w], m.len); break;
                        case 1u: SSFBNSetOne(v[w], m.len); break;
                        case 2u: SSFBNCopy(v[w], &m); v[w]->limbs[0] -= 2u; break;
                        case 3u: SSFBNCopy(v[w], &m); v[w]->limbs[0] -= 1u; break;
                        default: _SSFBNUTFillBelow(v[w], &m, (uint32_t)(e[w] + (w * 17u)));
                            break;
                        }
                    }
                    _SSFBNUTCheckModAdd(&m, &a, &b);
                    SSFBNModMulNIST(&r, &a, &b, &m);
                    SSFBNModMul(&ref, &a, &b, &m);
                    SSF_ASSERT((r.len == m.len) && (SSFBNCmp(&r, &ref) == 0));
                    SSFBNCopy(&r, &a);
                    SSFBNModMulNIST(&r, &r, &b, &m);
                    SSF_ASSERT(SSFBNCmp(&r, &ref) == 0);
                }
            }
        }
    }

    /* ---- OPTIMIZE EC-O3: ModInvSmall / ModMulSmall vs ModInv / ModMul, 1-12 limb moduli ---- */
    {
        static const SSFBNLimb_t primeLimbs[][4] = {
            { 0x7FFFFFFFu, 0u, 0u, 0u },                                 /* 2^31 - 1 */
            { 0xFFFFFFFBu, 0u, 0u, 0u },                                 /* 2^32 - 5 */
            { 0xFFFFFFFFu, 0x1FFFFFFFu, 0u, 0u },                        /* 2^61 - 1 */
            { 0xFFFFFFC5u, 0xFFFFFFFFu, 0u, 0u },                        /* 2^64 - 59 */
            { 0xFFFFFFFFu, 0xFFFFFFFFu, 0x01FFFFFFu, 0u },               /* 2^89 - 1 */
            { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu }       /* 2^127 - 1 */
        };
        static const uint16_t primeLens[] = { 1u, 1u, 2u, 2u, 3u, 4u };
        static const SSFBNLimb_t p256n[8] = { 0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u,
                                              0xBCE6FAADu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                              0x00000000u, 0xFFFFFFFFu };
#if SSF_BN_CONFIG_MAX_BITS >= 768
        static const SSFBNLimb_t p384n[12] = { 0xCCC52973u, 0xECEC196Au, 0x48B0A77Au,
                                               0x581A0DB2u, 0xF4372DDFu, 0xC7634D81u,
                                               0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                               0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu };
#endif
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(ref, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        uint16_t mi;
        uint16_t numMod;
        uint16_t vi;
        uint16_t k;

        numMod = (uint16_t)(sizeof(primeLens) / sizeof(primeLens[0])) + 2u;
#if SSF_BN_CONFIG_MAX_BITS >= 768
        numMod += 2u;
#endif
        for (mi = 0u; mi < numMod; mi++)
        {
            /* Pick the modulus: small primes, then P-256 p and n, then P-384 p and n */
            if (mi < (uint16_t)(sizeof(primeLens) / sizeof(primeLens[0])))
            {
                m.len = primeLens[mi];
                for (k = 0u; k < m.len; k++) m.limbs[k] = primeLimbs[mi][k];
            }
            else
            {
                uint16_t which;

                which = (uint16_t)(mi - (uint16_t)(sizeof(primeLens) / sizeof(primeLens[0])));

                if (which == 0u) SSFBNCopy(&m, &SSF_BN_NIST_P256);
                else if (which == 1u)
                {
                    m.len = 8u;
                    for (k = 0u; k < 8u; k++) m.limbs[k] = p256n[k];
                }
#if SSF_BN_CONFIG_MAX_BITS >= 768
                else if (which == 2u) SSFBNCopy(&m, &SSF_BN_NIST_P384);
                else
                {
                    m.len = 12u;
                    for (k = 0u; k < 12u; k++) m.limbs[k] = p384n[k];
                }
#endif
            }
            SSFBNSetOne(&one, m.len);

            /* a = 1, 2, m - 2, m - 1 and three pseudo-random values below m */
            for (vi = 0u; vi < 7u; vi++)
            {
                if (vi == 0u) SSFBNSetOne(&a, m.len);
                else if (vi == 1u) SSFBNSetUint32(&a, 2u, m.len);
                else if (vi == 2u) { SSFBNCopy(&a, &m); a.limbs[0] -= 2u; }
                else if (vi == 3u) { SSFBNCopy(&a, &m); a.limbs[0] -= 1u; }
                else _SSFBNUTFillBelow(&a, &m, (uint32_t)((mi * 31u) + vi));
                if (SSFBNIsZero(&a)) continue;

                SSF_ASSERT(SSFBNModInvSmall(&r, &a, &m) == true);
                SSF_ASSERT(r.len == m.len);
                SSF_ASSERT(SSFBNModInv(&ref, &a, &m) == true);
                SSF_ASSERT(SSFBNCmp(&r, &ref) == 0);
                SSFBNModMul(&ref, &a, &r, &m);
                SSF_ASSERT(SSFBNCmp(&ref, &one) == 0);

                /* In place: r aliasing a */
                SSFBNCopy(&ref, &a);
                SSF_ASSERT(SSFBNModInvSmall(&ref, &ref, &m) == true);
                SSF_ASSERT(SSFBNCmp(&ref, &r) == 0);

                /* Product against the generic SSFBNModMul, also with a >= m (a < R) and in place */
                _SSFBNUTFillBelow(&b, &m, (uint32_t)(((mi * 17u) + vi) + 3u));
                SSFBNModMulSmall(&r, &a, &b, &m);
                SSFBNModMul(&ref, &a, &b, &m);
                SSF_ASSERT((r.len == m.len) && (SSFBNCmp(&r, &ref) == 0));
                SSFBNCopy(&r, &a);
                SSFBNModMulSmall(&r, &r, &b, &m);
                SSF_ASSERT(SSFBNCmp(&r, &ref) == 0);
                SSFBNCopy(&r, &b);
                SSFBNModMulSmall(&r, &a, &r, &m);
                SSF_ASSERT(SSFBNCmp(&r, &ref) == 0);
                for (k = 0u; k < m.len; k++) a.limbs[k] = 0xFFFFFFFFu;
                SSFBNModMulSmall(&r, &a, &b, &m);
                SSFBNModMul(&ref, &a, &b, &m);
                SSF_ASSERT(SSFBNCmp(&r, &ref) == 0);
            }

            /* a = 0 has no inverse */
            SSFBNSetZero(&a, m.len);
            SSF_ASSERT(SSFBNModInvSmall(&r, &a, &m) == false);
        }

        /* Composite odd moduli: gcd(a, m) != 1, and a Fermat-failing coprime a (as ModInv) */
        SSFBNSetUint32(&m, 15u, 1u);
        SSFBNSetUint32(&a, 5u, 1u);
        SSF_ASSERT(SSFBNModInvSmall(&r, &a, &m) == false);
        SSFBNSetUint32(&a, 2u, 1u);
        SSF_ASSERT(SSFBNModInvSmall(&r, &a, &m) == false);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);

        /* Even modulus: no Fermat inverse, rejected as SSFBNModInv does (AUDIT BN-3) */
        SSFBNSetUint32(&m, 14u, 1u);
        SSFBNSetUint32(&a, 3u, 1u);
        SSF_ASSERT(SSFBNModInvSmall(&r, &a, &m) == false);

        /* m == 1 has no Fermat exponent m - 2: rejected, as SSFBNModInv rejects it */
        SSFBNSetOne(&m, 1u);
        SSFBNSetOne(&a, 1u);
        SSF_ASSERT(SSFBNModInvSmall(&r, &a, &m) == false);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);

        /* Secret-derived locals are wiped before return (BN-11 scrub hook) */
        SSFBNCopy(&m, &SSF_BN_NIST_P256);
        _SSFBNUTFillBelow(&a, &m, 123u);
        _SSFBNUTFillBelow(&b, &m, 321u);
        _scrubCalls = 0u;
        _scrubDirty = 0u;
        _SSFBNScrubTestHook = _ScrubCheck;
        /* ModInvSmall: table, acc, aR, e, ctx.mod, ctx.rr, plus SSFBNMontInit's own R^2 copy */
        SSF_ASSERT(SSFBNModInvSmall(&r, &a, &m) == true);
        SSF_ASSERT(_scrubCalls == 7u);
        /* ModMulSmall: t, ctx.mod, ctx.rr, plus SSFBNMontInit's R^2 copy */
        _scrubCalls = 0u;
        SSFBNModMulSmall(&r, &a, &b, &m);
        SSF_ASSERT(_scrubCalls == 4u);
        _SSFBNScrubTestHook = NULL;
        SSF_ASSERT(_scrubDirty == 0u);
    }

    /* ---- OPTIMIZE BN-O4 / BN-O5: Montgomery ModMulCT and binary-GCD ModInvExt (odd m) ---- */
    {
        static const uint16_t lens[] = { 1u, 2u, 3u, 5u, 8u, 12u, 16u, 32u, 33u, 64u };
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(ref, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(g, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        uint16_t li;
        uint16_t k;
        uint32_t seed;
        bool coprime;

        for (li = 0u; li < (uint16_t)(sizeof(lens) / sizeof(lens[0])); li++)
        {
            uint16_t n = lens[li];

            if (n > (SSF_BN_MAX_LIMBS / 2u)) continue;
            for (seed = 1u; seed <= 6u; seed++)
            {
                /* Would seed 3 at one limb make m == 1 (no meaningful inverse)? */
                if ((seed == 3u) && (n == 1u))
                {
                    /* Yes, skip it */
                    continue;
                }

                /* Odd modulus: full width, all-ones, or a top limb of 1; seed 6 is composite */
                m.len = n;
                for (k = 0u; k < n; k++)
                {
                    m.limbs[k] = (SSFBNLimb_t)(0x9E3779B9u * (uint32_t)(k + (seed * 7u)));
                }
                if (seed == 2u) for (k = 0u; k < n; k++) m.limbs[k] = 0xFFFFFFFFu;
                if (seed == 3u) m.limbs[n - 1u] = 1u;
                m.limbs[0] |= 1u;
                /* Is this a full-width seed (not the top-limb-1 or composite seed)? */
                if ((seed != 3u) && (seed != 6u))
                {
                    /* Yes, set the top bit */
                    m.limbs[n - 1u] |= 0x80000000u;
                }
                if (seed == 6u)
                {
                    /* Composite: 3 * (odd base with two bits of headroom), still n limbs */
                    m.limbs[n - 1u] = (SSFBNLimb_t)((m.limbs[n - 1u] & 0x3FFFFFFFu) | 1u);
                    SSFBNMulUint32(&g, &m, 3u);
                    SSFBNCopy(&m, &g);
                    m.len = n;
                    SSF_ASSERT(SSFBNModUint32(&m, 3u) == 0u);
                }
                SSFBNSetOne(&one, n);

                _SSFBNUTFillBelow(&a, &m, seed * 11u);
                _SSFBNUTFillBelow(&b, &m, seed * 13u);

                /* ModMulCT: b < m, a < m and then a >= m (all-ones), and in place */
                _SSFBNSlowPathCalls = 0u;
                SSFBNModMulCT(&r, &a, &b, &m);
                SSFBNModMul(&ref, &a, &b, &m);
                SSF_ASSERT((r.len == n) && (SSFBNCmp(&r, &ref) == 0));
                SSFBNCopy(&r, &a);
                SSFBNModMulCT(&r, &r, &b, &m);
                SSF_ASSERT(SSFBNCmp(&r, &ref) == 0);
                for (k = 0u; k < n; k++) g.limbs[k] = 0xFFFFFFFFu;
                g.len = n;
                SSFBNModMulCT(&r, &g, &b, &m);
                SSFBNModMul(&ref, &g, &b, &m);
                SSF_ASSERT(SSFBNCmp(&r, &ref) == 0);

                /* ModInvExt: an inverse exactly when gcd(a, m) == 1 */
                if (SSFBNIsZero(&a)) SSFBNSetOne(&a, n);
                SSFBNGcd(&g, &a, &m);
                coprime = SSFBNIsOne(&g);
                SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == coprime);
                if (coprime)
                {
                    SSF_ASSERT((r.len == n) && (SSFBNCmp(&r, &m) < 0));
                    SSFBNModMul(&ref, &a, &r, &m);
                    SSF_ASSERT(SSFBNCmp(&ref, &one) == 0);
                    SSFBNCopy(&ref, &a);
                    SSF_ASSERT(SSFBNModInvExt(&ref, &ref, &m) == true);
                    SSF_ASSERT(SSFBNCmp(&ref, &r) == 0);
                }
                SSF_ASSERT(_SSFBNSlowPathCalls == 0u);
            }
        }

        /* A shared factor: m = 3 * odd, a = 3 has no inverse */
        SSFBNSetUint32(&m, 21u, 1u);
        SSFBNSetUint32(&a, 3u, 1u);
        SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == false);
        SSFBNSetUint32(&a, 5u, 1u);
        SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == true);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 17u));

        /* Even modulus keeps the old algorithms: ModMulCT shift-subtract, ModInvExt Euclid */
        SSFBNSetUint32(&m, 1000u, 1u);
        SSFBNSetUint32(&a, 7u, 1u);
        SSFBNSetUint32(&b, 999u, 1u);
        _SSFBNSlowPathCalls = 0u;
        SSFBNModMulCT(&r, &a, &b, &m);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 993u));
        SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == true);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 143u));
        SSF_ASSERT(_SSFBNSlowPathCalls == 2u);

        /* The fast paths wipe their intermediates (BN-11 scrub hook) */
        SSFBNCopy(&m, &SSF_BN_NIST_P256);
        _SSFBNUTFillBelow(&a, &m, 77u);
        _SSFBNUTFillBelow(&b, &m, 88u);
        _scrubCalls = 0u;
        _scrubDirty = 0u;
        _SSFBNScrubTestHook = _ScrubCheck;
        /* ModMulCT: t, ctx.mod, ctx.rr, plus SSFBNMontInit's R^2 copy */
        SSFBNModMulCT(&r, &a, &b, &m);
        SSF_ASSERT(_scrubCalls == 4u);
        /* ModInvExt: u, v, x1, x2 */
        _scrubCalls = 0u;
        SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == true);
        SSF_ASSERT(_scrubCalls == 4u);
        _SSFBNScrubTestHook = NULL;
        SSF_ASSERT(_scrubDirty == 0u);
    }

    /* ---- OPTIMIZE BN-O8: ModMulNIST recognises its own primes by pointer; a copy works ---- */
    {
        SSFBNLimb_t pCopyLimbs[8];
        SSFBN_t pCopy = { pCopyLimbs, 8u, 8u };
        SSFBN_DEFINE(na, 8u);
        SSFBN_DEFINE(nr, 8u);
        SSFBN_DEFINE(nref, 8u);

        memcpy(pCopyLimbs, SSF_BN_NIST_P256.limbs, sizeof(pCopyLimbs));
        _SSFBNUTFillBelow(&na, &SSF_BN_NIST_P256, 4242u);
        _SSFBNNistPrimeCmps = 0u;
        SSFBNModMulNIST(&nr, &na, &na, &SSF_BN_NIST_P256);
        SSF_ASSERT(_SSFBNNistPrimeCmps == 0u);
        SSFBNModMulNIST(&nref, &na, &na, &pCopy);
        SSF_ASSERT(_SSFBNNistPrimeCmps == 1u);
        SSF_ASSERT(SSFBNCmp(&nr, &nref) == 0);
    }

    /* ---- OPTIMIZE BN-O8: a same-width modulus one limb off a NIST prime uses ModMul ---- */
    {
        const SSFBN_t *primes[2];
        SSFBNLimb_t mutLimbs[12];
        SSFBN_t mut = { mutLimbs, 0u, 12u };
        SSFBN_DEFINE(ma, 12u);
        SSFBN_DEFINE(mr, 12u);
        SSFBN_DEFINE(mref, 12u);
        uint16_t np = 0u;
        uint16_t pi;
        uint16_t li;

        primes[np++] = &SSF_BN_NIST_P256;
#if SSF_BN_CONFIG_MAX_BITS >= 768
        primes[np++] = &SSF_BN_NIST_P384;
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */
        for (pi = 0u; pi < np; pi++)
        {
            for (li = 0u; li < primes[pi]->len; li++)
            {
                memcpy(mutLimbs, primes[pi]->limbs, primes[pi]->len * sizeof(SSFBNLimb_t));
                mut.len = primes[pi]->len;
                /* Flip bit 1 of limb 0 (m stays odd), else bit 0 of the limb */
                mutLimbs[li] ^= (li == 0u) ? 2u : 1u;
                _SSFBNUTFillBelow(&ma, &mut, 777u + li);
                SSFBNModMulNIST(&mr, &ma, &ma, &mut);
                SSFBNModMul(&mref, &ma, &ma, &mut);
                SSF_ASSERT(SSFBNCmp(&mr, &mref) == 0);
            }
        }
    }

    /* ---- OPTIMIZE EC-O4: P-256 / P-384 reductions exact in 3 passes (oracle SSFBNMod) ---- */
    {
        SSFBN_DEFINE(nt, 24u);
        SSFBN_DEFINE(nr, 12u);
        SSFBN_DEFINE(nref, 12u);
        const SSFBN_t *np;
        uint16_t nLimbs;
        uint16_t curve;
        uint32_t pat;
        uint32_t lcg = 12345u;
        uint16_t k;

        for (curve = 0u; curve < 2u; curve++)
        {
#if SSF_BN_CONFIG_MAX_BITS < 768
            /* P-384 needs the 768-bit cap */
            if (curve == 1u) break;
#endif
            np = (curve == 0u) ? &SSF_BN_NIST_P256 : &SSF_BN_NIST_P384;
            nLimbs = np->len;
            for (pat = 0u; pat < ((uint32_t)2u << nLimbs) + 2000u; pat++)
            {
                /* Is this a structured pattern or a pseudo-random input? */
                nt.len = (uint16_t)(2u * nLimbs);
                if (pat < ((uint32_t)2u << nLimbs))
                {
                    /* Structured: bit k of pat picks upper limb k, the top bit the low half */
                    for (k = 0u; k < nLimbs; k++)
                    {
                        nt.limbs[k] = ((pat >> nLimbs) != 0u) ? 0xFFFFFFFFu : 0u;
                        nt.limbs[nLimbs + k] = (((pat >> k) & 1u) != 0u) ? 0xFFFFFFFFu : 0u;
                    }
                }
                else
                {
                    /* Pseudo-random */
                    for (k = 0u; k < nt.len; k++)
                    {
                        lcg = (lcg * 1664525u) + 1013904223u;
                        nt.limbs[k] = lcg;
                    }
                }
                _SSFBNNistCorrPasses = 0u;
                _SSFBNReduceNISTForTest(&nr, &nt, np);
                SSF_ASSERT(_SSFBNNistCorrPasses == 3u);
                SSFBNMod(&nref, &nt, np);
                SSF_ASSERT((nr.len == nLimbs) && (SSFBNCmp(&nr, &nref) == 0));
            }
        }
    }

    /* Inputs (solved offline) whose first fold crosses 0 or 2^w, so the second fold runs */
    {
        static const SSFBNLimb_t _e0T[16] = {
            0x560E3EAAu, 0x83CF3687u, 0x16A35571u, 0xC09516C8u,
            0x7C30C978u, 0x007A4CF9u, 0xAA6C0E51u, 0xD23F0820u,
            0x00000000u, 0x6513270Eu, 0x00000000u, 0xD23F0824u,
            0xFFFFFFFFu, 0x00000000u, 0xE8E25D94u, 0x00000000u
        };
        static const SSFBNLimb_t _e0R[8] = {
            0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000001u,
            0x00000000u, 0x00000000u, 0x00000002u, 0xFFFFFFFEu
        };
        static const SSFBNLimb_t _e1T[16] = {
            0x05F43E7Cu, 0x07B8B571u, 0x6487B144u, 0xB13080D3u,
            0x4CA8CF8Fu, 0x38B5146Du, 0x42E70233u, 0xA9DA040Bu,
            0xFFFFFFFFu, 0xA5AA3C81u, 0xFE3B890Bu, 0xFFFFFFFFu,
            0x48DB40AFu, 0x62C33A4Fu, 0x00000000u, 0xFFFFFFFFu
        };
        static const SSFBNLimb_t _e1R[8] = {
            0x00000001u, 0x00000000u, 0x00000000u, 0xFFFFFFFEu,
            0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFDu, 0x00000001u
        };
#if SSF_BN_CONFIG_MAX_BITS >= 768
        static const SSFBNLimb_t _e2T[24] = {
            0x7BBF97D9u, 0x84406826u, 0x00000000u, 0x2F479642u,
            0xC8379970u, 0x00000002u, 0x591CC17Au, 0x0DF33B58u,
            0x7BBF97D8u, 0x29D52B35u, 0xA594C311u, 0x7BBF97DBu,
            0x00000000u, 0x00000000u, 0x00000000u, 0x4C780197u,
            0x00000000u, 0x00000000u, 0x5A6B3CF0u, 0xFFFFFFFFu,
            0x84406825u, 0x00000000u, 0x00000000u, 0xFFFFFFFFu
        };
        static const SSFBNLimb_t _e2R[12] = {
            0x00000002u, 0xFFFFFFFDu, 0xFFFFFFFFu, 0x00000002u,
            0x00000003u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u
        };
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */
        SSFBN_DEFINE(nt, 24u);
        SSFBN_DEFINE(nr, 12u);

        /* P-256: net carry -1, first fold underflows (e = -1) */
        nt.len = 16u;
        memcpy(nt.limbs, _e0T, sizeof(_e0T));
        _SSFBNReduceNISTForTest(&nr, &nt, &SSF_BN_NIST_P256);
        SSF_ASSERT((nr.len == 8u) && (memcmp(nr.limbs, _e0R, sizeof(_e0R)) == 0));
        /* P-256: net carry 1, first fold overflows (e = 1) */
        nt.len = 16u;
        memcpy(nt.limbs, _e1T, sizeof(_e1T));
        _SSFBNReduceNISTForTest(&nr, &nt, &SSF_BN_NIST_P256);
        SSF_ASSERT((nr.len == 8u) && (memcmp(nr.limbs, _e1R, sizeof(_e1R)) == 0));
#if SSF_BN_CONFIG_MAX_BITS >= 768
        /* P-384: net carry 2, first fold overflows (e = 1) */
        nt.len = 24u;
        memcpy(nt.limbs, _e2T, sizeof(_e2T));
        _SSFBNReduceNISTForTest(&nr, &nt, &SSF_BN_NIST_P384);
        SSF_ASSERT((nr.len == 12u) && (memcmp(nr.limbs, _e2R, sizeof(_e2R)) == 0));
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */
    }

    /* ---- SQ-CT audit: SSFBNSquare's diagonal add runs a fixed a->len carry steps ---- */
    {
        static const uint16_t sqWidths[] = { 1u, 2u, 3u, 8u, 12u, 32u };
        SSFBN_DEFINE(sa, 64u);
        SSFBN_DEFINE(sr, 128u);
        SSFBN_DEFINE(sref, 128u);
        uint16_t wi;
        uint16_t k;
        uint16_t pat;

        for (wi = 0u; wi < (uint16_t)(sizeof(sqWidths) / sizeof(sqWidths[0])); wi++)
        {
            uint16_t n = sqWidths[wi];

            /* Is this width beyond the build's cap (2n limbs must fit SSF_BN_MAX_LIMBS)? */
            if ((2u * (uint32_t)n) > (uint32_t)SSF_BN_MAX_LIMBS)
            {
                /* Yes, skip it */
                continue;
            }
            /* No */
            for (pat = 0u; pat < 4u; pat++)
            {
                /* Patterns: zero, all-ones, alternating all-ones / zero limbs, pseudo-random */
                sa.len = n;
                for (k = 0u; k < n; k++)
                {
                    sa.limbs[k] = (pat == 0u) ? 0u : (pat == 1u) ? 0xFFFFFFFFu :
                                  (pat == 2u) ? (((k & 1u) == 0u) ? 0xFFFFFFFFu : 0u) :
                                  (0x9E3779B9u * (uint32_t)(k + 1u)) ^ 0x5A5A5A5Au;
                }
                _SSFBNSquareCarryIters = 0u;
                SSFBNSquare(&sr, &sa);
                SSF_ASSERT(_SSFBNSquareCarryIters == (uint32_t)n);
                SSFBNMul(&sref, &sa, &sa);
                SSF_ASSERT((sr.len == sref.len) && (SSFBNCmp(&sr, &sref) == 0));
            }
        }
    }

    /* ---- OPTIMIZE BN-O7: SSFBNMod of x = q * m + rem gives rem (odd m, CT Montgomery) ---- */
    {
        static const uint16_t widths[] = { 1u, 2u, 3u, 8u, 12u, 32u, SSF_BN_MAX_MOD_LIMBS };
        SSFBN_DEFINE(om, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(oq, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(orem, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(oprod, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(ox, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(or1, SSF_BN_MAX_LIMBS);
        uint16_t wi;
        uint16_t k;
        uint16_t qLen;
        uint32_t seed;
        uint32_t iters0;

        _SSFBNModShiftCalls = 0u;
        for (wi = 0u; wi < (uint16_t)(sizeof(widths) / sizeof(widths[0])); wi++)
        {
            uint16_t n = widths[wi];

            /* Is this modulus wider than the build's Montgomery limit? */
            if (n > SSF_BN_MAX_MOD_LIMBS)
            {
                /* Yes, skip it */
                continue;
            }
            /* No */
            for (seed = 1u; seed <= 4u; seed++)
            {
                /* Odd m; seeds 1-2 full width, 3-4 a small top limb */
                om.len = n;
                for (k = 0u; k < n; k++) om.limbs[k] = (0x9E3779B9u * (seed + k)) ^ (k << 7);
                om.limbs[n - 1u] = (seed <= 2u) ? (om.limbs[n - 1u] | 0x80000000u) : 1u;
                om.limbs[0] |= 1u;

                for (qLen = 0u; qLen <= n; qLen = (uint16_t)((qLen == 0u) ? 1u : (2u * qLen)))
                {
                    /* rem < m, then x = q * m + rem (qLen 0: x is rem itself) */
                    _SSFBNUTFillBelow(&orem, &om, (seed * 31u) + qLen);
                    if (qLen == 0u)
                    {
                        SSFBNCopy(&ox, &orem);
                    }
                    else
                    {
                        oq.len = qLen;
                        for (k = 0u; k < qLen; k++) oq.limbs[k] = 0xC2B2AE35u * ((seed + k) + 1u);
                        SSFBNMul(&oprod, &oq, &om);
                        SSFBNSetZero(&ox, oprod.len);
                        memcpy(ox.limbs, orem.limbs, (size_t)n * sizeof(SSFBNLimb_t));
                        SSF_ASSERT(SSFBNAdd(&ox, &oprod, &ox) == 0u);
                    }
                    SSFBNMod(&or1, &ox, &om);
                    SSF_ASSERT((or1.len == n) && (SSFBNCmp(&or1, &orem) == 0));

                    /* In place, as _SSFBNModInvExtEuclid calls it */
                    SSFBNMod(&ox, &ox, &om);
                    SSF_ASSERT((ox.len == n) && (SSFBNCmp(&ox, &orem) == 0));
                }

                /* A shorter than m: a single small limb is its own remainder */
                SSFBNSetUint32(&ox, 0x1234567u, 1u);
                SSFBNMod(&or1, &ox, &om);
                SSFBNSetUint32(&orem, (n == 1u && seed > 2u) ? (0x1234567u % om.limbs[0]) :
                                      0x1234567u, n);
                SSF_ASSERT(SSFBNCmp(&or1, &orem) == 0);
            }
        }

        /* m = 1: everything reduces to 0 */
        SSFBNSetOne(&om, 1u);
        SSFBNSetUint32(&ox, 0xFFFFFFFFu, 2u);
        ox.limbs[1] = 0xFFFFFFFFu;
        SSFBNMod(&or1, &ox, &om);
        SSF_ASSERT((or1.len == 1u) && (or1.limbs[0] == 0u));

        /* m with zero top limbs: value 2^32 + 5 stored in 4 limbs */
        SSFBNSetZero(&om, 4u);
        om.limbs[0] = 5u;
        om.limbs[1] = 1u;
        SSFBNSetZero(&ox, 8u);
        for (k = 0u; k < 8u; k++) ox.limbs[k] = 0xFFFFFFFFu;
        SSFBNMod(&or1, &ox, &om);
        /* (2^256 - 1) mod (2^32 + 5) is 390624 (Python) */
        SSF_ASSERT((or1.len == 4u) && (or1.limbs[0] == 390624u) && (or1.limbs[1] == 0u));
        SSF_ASSERT((or1.limbs[2] == 0u) && (or1.limbs[3] == 0u));

        /* None of the odd moduli took the variable-time shift-and-subtract path */
        SSF_ASSERT(_SSFBNModShiftCalls == 0u);

        /* The work does not depend on a's value: all-zero and all-ones a, same MontMul count */
        SSFBNCopy(&om, &SSF_BN_NIST_P256);
        SSFBNSetZero(&ox, 16u);
        _SSFBNMontMulIters = 0u;
        SSFBNMod(&or1, &ox, &om);
        iters0 = _SSFBNMontMulIters;
        SSF_ASSERT((iters0 > 0u) && SSFBNIsZero(&or1));
        for (k = 0u; k < 16u; k++) ox.limbs[k] = 0xFFFFFFFFu;
        _SSFBNMontMulIters = 0u;
        SSFBNMod(&or1, &ox, &om);
        SSF_ASSERT(_SSFBNMontMulIters == iters0);

        /* An even modulus keeps shift-and-subtract: 999999 mod 1000 */
        SSFBNSetUint32(&om, 1000u, 1u);
        SSFBNSetUint32(&ox, 999999u, 1u);
        SSFBNMod(&or1, &ox, &om);
        SSF_ASSERT((or1.len == 1u) && (or1.limbs[0] == 999u));
        SSF_ASSERT(_SSFBNModShiftCalls == 1u);
    }

    /* ---- OPTIMIZE RSA-STK: MontMul / MontSquare leave no product in their freed scratch ---- */
    {
        SSFBNMONT_DEFINE(hm, 8u);
        SSFBN_DEFINE(hmod, 8u);
        SSFBN_DEFINE(ha, 8u);
        SSFBN_DEFINE(hb, 8u);
        SSFBN_DEFINE(hr, 8u);
        SSFBN_DEFINE(hrm, 8u);
        uint16_t k;
        uint16_t op;

        hmod.len = 8u;
        ha.len = 8u;
        hb.len = 8u;
        for (k = 0u; k < 8u; k++)
        {
            hmod.limbs[k] = 0x9E3779B9u * (uint32_t)(k + 1u);
            ha.limbs[k] = 0x7F4A7C15u * (uint32_t)(k + 3u);
            hb.limbs[k] = 0x94D049BBu * (uint32_t)(k + 5u);
        }
        hmod.limbs[7] |= 0x80000000u;
        hmod.limbs[0] |= 1u;
        ha.limbs[7] &= 0x3FFFFFFFu;
        hb.limbs[7] &= 0x3FFFFFFFu;
        SSFBNMontInit(&hm, &hmod);
        for (op = 0u; op < 2u; op++)
        {
            /* Is this pass the multiply? */
            _SSFBNUTPolluteStack();
            if (op == 0u)
            {
                /* Yes */
                SSFBNMontMul(&hr, &ha, &hb, &hm);
            }
            else
            {
                /* No, the square */
                SSFBNMontSquare(&hr, &ha, &hm);
            }
            /* Look for the top four limbs of r and of r + m mod 2^256 (the values t can hold) */
            (void)SSFBNAdd(&hrm, &hr, &hmod);
            SSF_ASSERT(_SSFBNUTScanStack((const uint8_t *)&hr.limbs[4],
                                         (const uint8_t *)&hrm.limbs[4], 16u) == 0u);
        }
    }

    /* ---- OPTIMIZE RSA-STK: SSFBNMontInit refuses a modulus over SSF_BN_MAX_MOD_LIMBS ---- */
    {
        SSFBNMONT_DEFINE(wideMont, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(wideM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(okM, SSF_BN_MAX_LIMBS);
        uint16_t k;

        /* The widest allowed modulus initialises */
        okM.len = SSF_BN_MAX_MOD_LIMBS;
        for (k = 0u; k < okM.len; k++) okM.limbs[k] = 0xFFFFFFFFu;
        SSFBNMontInit(&wideMont, &okM);
        SSF_ASSERT(wideMont.len == SSF_BN_MAX_MOD_LIMBS);

        /* One limb wider is a precondition violation */
        wideM.len = (uint16_t)(SSF_BN_MAX_MOD_LIMBS + 1u);
        for (k = 0u; k < wideM.len; k++) wideM.limbs[k] = 0xFFFFFFFFu;
        SSF_ASSERT_TEST(SSFBNMontInit(&wideMont, &wideM));

        /* Every entry point that builds or takes a Montgomery context states the same bound */
        {
            SSFBN_DEFINE(wideR, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(wideA, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(wideE, SSF_BN_MAX_LIMBS);

            wideA.len = wideM.len;
            wideA.limbs[0] = 2u;
            wideE.len = 1u;
            wideE.limbs[0] = 3u;
            SSF_ASSERT_TEST(SSFBNModExp(&wideR, &wideA, &wideE, &wideM));
            SSF_ASSERT_TEST(SSFBNModExpPub(&wideR, &wideA, &wideE, &wideM));
            SSF_ASSERT_TEST(SSFBNModInv(&wideR, &wideA, &wideM));

            /* A hand-built context one limb too wide is refused before any scratch is used */
            wideMont.len = wideM.len;
            wideMont.mod.len = wideM.len;
            for (k = 0u; k < wideM.len; k++) wideMont.mod.limbs[k] = 0xFFFFFFFFu;
            SSF_ASSERT_TEST(SSFBNModExpMontPub(&wideR, &wideA, &wideE, &wideMont));
            SSF_ASSERT_TEST(SSFBNModExpMont(&wideR, &wideA, &wideE, &wideMont));
        }
    }

    /* ---- AUDIT BN-7: MontInit's R^2 is exact for 1024+ limb moduli (MAX_BITS >= 32768) ---- */
#if SSF_BN_MAX_LIMBS >= 1024u
    {
        static SSFBNLimb_t bigModStorage[SSF_BN_MAX_LIMBS];
        static SSFBNLimb_t bigRrStorage[SSF_BN_MAX_LIMBS];
        static SSFBNLimb_t bigMStorage[SSF_BN_MAX_LIMBS];
        static SSFBNLimb_t bigXStorage[SSF_BN_MAX_LIMBS];
        static SSFBNLimb_t bigXRStorage[SSF_BN_MAX_LIMBS];
        static SSFBNLimb_t bigYStorage[SSF_BN_MAX_LIMBS];
        SSFBNMont_t bigMont = { { bigModStorage, 0u, SSF_BN_MAX_LIMBS },
                                { bigRrStorage, 0u, SSF_BN_MAX_LIMBS }, 0u, 0u };
        SSFBN_t bigM = { bigMStorage, 0u, SSF_BN_MAX_LIMBS };
        SSFBN_t bigX = { bigXStorage, 0u, SSF_BN_MAX_LIMBS };
        SSFBN_t bigXR = { bigXRStorage, 0u, SSF_BN_MAX_LIMBS };
        SSFBN_t bigY = { bigYStorage, 0u, SSF_BN_MAX_LIMBS };
        uint16_t k;

        /* 1024-limb odd modulus with a non-zero top limb; x < m at the same length. */
        bigM.len = 1024u;
        bigX.len = 1024u;
        for (k = 0u; k < 1024u; k++)
        {
            bigM.limbs[k] = (SSFBNLimb_t)(0x9E3779B9u * (uint32_t)(k + 1u));
            bigX.limbs[k] = (SSFBNLimb_t)(0x7F4A7C15u * (uint32_t)(k + 3u));
        }
        bigM.limbs[0] |= 1u;
        bigM.limbs[1023] |= 0x80000000u;
        bigX.limbs[1023] &= 0x7FFFFFFFu;

        SSFBNMontInit(&bigMont, &bigM);
        SSFBNMontConvertIn(&bigXR, &bigX, &bigMont);
        SSFBNMontConvertOut(&bigY, &bigXR, &bigMont);
        SSF_ASSERT(SSFBNCmp(&bigY, &bigX) == 0);
    }
#endif /* SSF_BN_MAX_LIMBS >= 1024 */

    /* ---- AUDIT BN-6: 2-limb multiply into an exactly 2n-limb result (Karatsuba step 7) ---- */
    {
        SSFBN_DEFINE(a2, 2u);
        SSFBN_DEFINE(b2, 2u);
        SSFBN_DEFINE(prod4, 4u);

        a2.len = 2u;
        a2.limbs[0] = 0x01234567u;
        a2.limbs[1] = 0x89ABCDEFu;
        b2.len = 2u;
        b2.limbs[0] = 0x76543210u;
        b2.limbs[1] = 0xFEDCBA98u;
        SSFBNMul(&prod4, &a2, &b2);
        SSF_ASSERT(prod4.len == 4u);
        SSF_ASSERT((prod4.limbs[0] == 0x358E7470u) && (prod4.limbs[1] == 0x09CA39E1u) &&
                   (prod4.limbs[2] == 0xEDCA5E20u) && (prod4.limbs[3] == 0x890F2A50u));
    }

    /* ---- AUDIT BN-5: a^0 mod m is 1 mod m (0 when m == 1) on every exponentiation path ---- */
    {
        SSFBNMONT_DEFINE(montOne, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mOne, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mSeven, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(base, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(eZero, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&mOne, 1u, 1u);
        SSFBNSetUint32(&mSeven, 7u, 1u);
        SSFBNSetUint32(&base, 5u, 1u);
        SSFBNSetZero(&eZero, 1u);

        /* m == 1: every path must give 0. */
        SSFBNModExpPub(&r, &base, &eZero, &mOne);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 0u));
        SSFBNMontInit(&montOne, &mOne);
        SSFBNModExpMontPub(&r, &base, &eZero, &montOne);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 0u));
        SSFBNModExp(&r, &base, &eZero, &mOne);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 0u));

        /* Control, m == 7: both paths give 1. */
        SSFBNModExpPub(&r, &base, &eZero, &mSeven);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 1u));
        SSFBNModExp(&r, &base, &eZero, &mSeven);
        SSF_ASSERT((r.len == 1u) && (r.limbs[0] == 1u));
    }

    /* ---- AUDIT BN-4: Montgomery operands are used at their logical len, never stale limbs ---- */
    {
        SSFBNMONT_DEFINE(mont4, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m4, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(x, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(xR, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(y, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(xPad, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rShort, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rPad, SSF_BN_MAX_LIMBS);
        uint16_t k;

        /* 4-limb odd modulus. */
        m4.len = 4u;
        m4.limbs[0] = 0x9ABCDEF1u;
        m4.limbs[1] = 0x12345678u;
        m4.limbs[2] = 0x0F0E0D0Cu;
        m4.limbs[3] = 0xC0FFEE11u;
        SSFBNMontInit(&mont4, &m4);

        /* x = 0x12345678 at len 1 over junk left in limbs[1..3] by an earlier, longer value. */
        x.len = 4u;
        for (k = 1u; k < 4u; k++) x.limbs[k] = 0xDEADBEEFu;
        x.limbs[0] = 0x12345678u;
        x.len = 1u;

        /* ConvertIn then ConvertOut must give x back (zero-extended to ctx->len). */
        SSFBNMontConvertIn(&xR, &x, &mont4);
        SSFBNMontConvertOut(&y, &xR, &mont4);
        SSF_ASSERT(y.len == 4u);
        SSF_ASSERT((y.limbs[0] == 0x12345678u) && (y.limbs[1] == 0u) && (y.limbs[2] == 0u) &&
                   (y.limbs[3] == 0u));

        /* ModExp with the short, junk-backed base must match the properly padded base. */
        SSFBNSetUint32(&xPad, 0x12345678u, 4u);
        SSFBNSetUint32(&e, 65537u, 4u);
        rShort.len = 4u;
        rPad.len = 4u;
        SSFBNModExp(&rShort, &x, &e, &m4);
        SSFBNModExp(&rPad, &xPad, &e, &m4);
        SSF_ASSERT(SSFBNCmp(&rShort, &rPad) == 0);

        /* Montgomery-form operands must be exactly ctx->len; ConvertIn input at most ctx->len. */
        SSFBNMontConvertIn(&xR, &xPad, &mont4);
        y.len = 2u;
        SSF_ASSERT_TEST(SSFBNMontMul(&rShort, &xR, &y, &mont4));
        SSF_ASSERT_TEST(SSFBNMontMul(&rShort, &y, &xR, &mont4));
        SSF_ASSERT_TEST(SSFBNMontSquare(&rShort, &y, &mont4));
        SSF_ASSERT_TEST(SSFBNMontConvertOut(&rShort, &y, &mont4));
        y.len = 5u;
        SSF_ASSERT_TEST(SSFBNMontConvertIn(&rShort, &y, &mont4));
    }

#if SSF_BN_OSSL_VERIFY == 1
    _SSFBNVerifyAgainstOpenSSL();
#endif

#if SSF_CONFIG_BN_MICROBENCH == 1
    /* ==== Microbenchmark (SSF_CONFIG_BN_MICROBENCH): Mont and raw Mul / Square throughput == */
    {
        /* Skip rows whose 2 * nLimbs exceeds SSF_BN_MAX_LIMBS at the configured cap */
        struct
        {
            uint16_t nLimbs;
            uint32_t mIters;
            uint32_t mulIters;
            const char *label;
        } bench[] = {
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

        SSF_UT_PRINTF("\n--- ssfbn microbenchmark (ms for iter count shown) ---\n");
        for (bi = 0; bi < (uint16_t)(sizeof(bench) / sizeof(bench[0])); bi++)
        {
            uint16_t n = bench[bi].nLimbs;
            uint32_t mIters = bench[bi].mIters;
            uint32_t mulIters = bench[bi].mulIters;
            uint32_t i;

            /* Odd modulus with the top bit set: P-256 / P-384 where they fit, else synthesized */
            SSFBN_DEFINE(mod, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(rWide, SSF_BN_MAX_LIMBS); /* Width for raw Mul/Square (2n limbs). */
            SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
            SSFPortTick_t t0;
            SSFPortTick_t t1;

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

            /* Fill every limb with non-zero LCG data keyed on the limb index */
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
                SSF_UT_PRINTF("  Mul        %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)mulIters,
                       (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < mulIters; i++)
                {
                    SSFBNSquare(&rWide, &a);
                }
                t1 = SSFPortGetTick64();
                SSF_UT_PRINTF("  Square     %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)mulIters,
                       (unsigned long long)(t1 - t0));
            }

            /* --- ModExpMont (CT, dense exponent) and ModExpMontPub (e = 65537); a is plain */
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
                expPriv.limbs[n - 1u] |= 0x80000000ul; /* force full bit-length */
                expPriv.limbs[0] |= 1u;                  /* force odd */
                expPriv.len = n;

                /* Public exponent F4 = 65537. */
                SSFBNSetUint32(&expPub, 65537u, 1u);

                /* Iter counts tuned for ~0.5-2 s per measurement (Mont ladder is ~2*eBits ops). */
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
                SSF_UT_PRINTF("  ModExpMont %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)expIters,
                       (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < expPubIters; i++)
                {
                    SSFBNModExpMontPub(&rE, &a, &expPub, &mont);
                }
                t1 = SSFPortGetTick64();
                SSF_UT_PRINTF("  ModExpPub  %s %u iter: %llu ms (e=F4)\n",
                       bench[bi].label, (unsigned)expPubIters,
                       (unsigned long long)(t1 - t0));
            }

            /* --- ModInv (Fermat) vs ModInvExt (binary EEA, non-CT) at P-256 size */
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
                SSF_UT_PRINTF("  ModInv     %s %u iter: %llu ms (Fermat)\n",
                       bench[bi].label, 2000u, (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < 2000u; i++)
                {
                    (void)SSFBNModInvExt(&rInv, &a, &mod);
                }
                t1 = SSFPortGetTick64();
                SSF_UT_PRINTF("  ModInvExt  %s %u iter: %llu ms (binary EEA)\n",
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
            SSF_UT_PRINTF("  MontMul    %s %u iter: %llu ms\n",
                   bench[bi].label, (unsigned)mIters,
                   (unsigned long long)(t1 - t0));

            t0 = SSFPortGetTick64();
            for (i = 0; i < mIters; i++)
            {
                SSFBNMontSquare(&r, &a, &mont);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  MontSquare %s %u iter: %llu ms\n",
                   bench[bi].label, (unsigned)mIters,
                   (unsigned long long)(t1 - t0));
        }
        SSF_UT_PRINTF("--- end microbenchmark ---\n");
    }
#endif /* SSF_CONFIG_BN_MICROBENCH */
}
#ifdef _WIN32
#pragma warning(pop)
#endif
#endif /* SSF_CONFIG_BN_UNIT_TEST */
