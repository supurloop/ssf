/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfed25519.c                                                                                  */
/* Provides Ed25519 digital signature implementation (RFC 8032).                                 */
/* GF(2^255-19) arithmetic from ssffe25519 (shared with ssfx25519); extended Edwards coords.     */
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
#include <string.h>
#include <stdio.h>
#include "ssfassert.h"
#include "ssffe25519.h"
#include "ssfed25519.h"
#include "ssfsha2.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Field arithmetic: GF(2^255 - 19); lazy add / sub and Ed25519 extras (rest in ssffe25519)      */
/* --------------------------------------------------------------------------------------------- */
/* r = a + b. Result may be up to 2p if both inputs < p. */
static void _fe_add(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b)
{
    uint64_t carry = 0;
    uint8_t i;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i] + (uint64_t)b->v[i];
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }
    /* Fold the overflow past 2^256 back in unconditionally (constant time) */
    {
        uint64_t c = (uint64_t)carry * 38u;
        for (i = 0; i < 8u; i++)
        {
            c += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c;
            c >>= 32;
        }
    }
}

/* r = a - b mod p. Reduces inputs first, then subtracts. Adds 2p on borrow. */
static void _fe_sub(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b)
{
    uint64_t borrow = 0;
    uint8_t i;
    SSFFE25519_t ar, br;

    /* Reduce inputs to [0, p) so that a - b + 2p is in [0, 2p + p) = [0, 3p) < 2^257 */
    SSFFE25519Copy(&ar, a);
    SSFFE25519Copy(&br, b);
    SSFFE25519Reduce(&ar);
    SSFFE25519Reduce(&br);

    /* r = a - b */
    for (i = 0; i < 8u; i++)
    {
        uint64_t diff = (uint64_t)ar.v[i] - (uint64_t)br.v[i] - borrow;
        r->v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }

    /* Add 2p on borrow, masked and unconditional (constant time) */
    {
        uint32_t mask = (uint32_t)(0u - (uint32_t)borrow);
        uint64_t carry = 0;
        for (i = 0; i < 8u; i++)
        {
            carry += (uint64_t)r->v[i] + 2u * (uint64_t)(SSF_FE25519_P.v[i] & mask);
            r->v[i] = (uint32_t)carry;
            carry >>= 32;
        }
    }
}

/* Import from 32 little-endian bytes (caller handles any pre-import bit clearing). */
static void _fe_from_bytes(SSFFE25519_t *a, const uint8_t *b)
{
    uint8_t i;
    for (i = 0; i < 8u; i++)
    {
        a->v[i] = ((uint32_t)b[i * 4u]) |
                  ((uint32_t)b[i * 4u + 1u] << 8) |
                  ((uint32_t)b[i * 4u + 2u] << 16) |
                  ((uint32_t)b[i * 4u + 3u] << 24);
    }
}

/* r = a^((p-5)/8) mod p. Used by _ge_decode's square-root step (the candidate-x formula        */
/*   x = u * v^3 * (u * v^7)^((p-5)/8)).                                                        */
/* (p-5)/8 = (2^255 - 19 - 5)/8 = (2^255 - 24)/8 = 2^252 - 3. The function name (_fe_pow2523)   */
/* records that exponent in shorthand. Addition chain mirrors _fe_inv, with five fewer trailing */
/* squarings and a multiply-by-`a` instead of the multiply-by-`a^11` _fe_inv ends with.         */
static void _fe_pow2523(SSFFE25519_t *r, const SSFFE25519_t *a)
{
    SSFFE25519_t t0, t1, t2, t3;
    uint16_t i;

    /* a^2 */
    SSFFE25519Sqr(&t0, a);
    /* a^9 = ((a^2)^2)^2 * a */
    SSFFE25519Sqr(&t1, &t0);
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Mul(&t1, &t1, a);
    /* a^11 = a^9 * a^2 */
    SSFFE25519Mul(&t0, &t1, &t0);
    /* a^22 = (a^11)^2 */
    SSFFE25519Sqr(&t2, &t0);
    /* a^(2^5 - 1) = a^31 = a^22 * a^9 */
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^10 - 1) */
    SSFFE25519Sqr(&t2, &t1);
    for (i = 1; i < 5u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^20 - 1) */
    SSFFE25519Sqr(&t2, &t1);
    for (i = 1; i < 10u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t2, &t2, &t1);
    /* a^(2^40 - 1) */
    SSFFE25519Sqr(&t3, &t2);
    for (i = 1; i < 20u; i++) SSFFE25519Sqr(&t3, &t3);
    SSFFE25519Mul(&t2, &t3, &t2);
    /* a^(2^50 - 1) */
    SSFFE25519Sqr(&t2, &t2);
    for (i = 1; i < 10u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^100 - 1) */
    SSFFE25519Sqr(&t2, &t1);
    for (i = 1; i < 50u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t2, &t2, &t1);
    /* a^(2^200 - 1) */
    SSFFE25519Sqr(&t3, &t2);
    for (i = 1; i < 100u; i++) SSFFE25519Sqr(&t3, &t3);
    SSFFE25519Mul(&t2, &t3, &t2);
    /* a^(2^250 - 1) */
    SSFFE25519Sqr(&t2, &t2);
    for (i = 1; i < 50u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^252 - 4) */
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Sqr(&t1, &t1);
    /* a^(2^252 - 3) = a^((p-5)/8) */
    SSFFE25519Mul(r, &t1, a);
}

/* Return 1 if a is negative (odd), 0 if non-negative (even). Fully reduces first. */
static uint8_t _fe_isneg(const SSFFE25519_t *a)
{
    SSFFE25519_t t;
    SSFFE25519Copy(&t, a);
    SSFFE25519Reduce(&t);
    return (uint8_t)(t.v[0] & 1u);
}

/* Return 1 if a is zero, 0 otherwise. Fully reduces first. */
static uint8_t _fe_iszero(const SSFFE25519_t *a)
{
    SSFFE25519_t t;
    uint32_t bits;
    uint8_t i;
    SSFFE25519Copy(&t, a);
    SSFFE25519Reduce(&t);
    bits = 0;
    for (i = 0; i < 8u; i++) bits |= t.v[i];
    /* (bits | -bits) has bit 31 set iff bits != 0; unsigned negate (AUDIT E-3) */
    return (uint8_t)(1u ^ (((bits | ((uint32_t)0u - bits)) >> 31) & 1u));
}

/* r = -a mod p */
static void _fe_neg(SSFFE25519_t *r, const SSFFE25519_t *a)
{
    SSFFE25519_t zero;
    SSFFE25519SetZero(&zero);
    _fe_sub(r, &zero, a);
}

/* --------------------------------------------------------------------------------------------- */
/* Edwards point in extended coords (X:Y:Z:T): x=X/Z, y=Y/Z, T=X*Y/Z; curve a = -1.              */
/* --------------------------------------------------------------------------------------------- */
typedef struct { SSFFE25519_t X, Y, Z, T; } _ge_t;

/* d = -121665/121666 mod p                                                                      */
/* d = 37095705934669439343138083508754565189542113879843219016388785533085940283555         */
static const SSFFE25519_t _ed_d = {{ 0x135978A3u, 0x75EB4DCAu, 0x4141D8ABu, 0x00700A4Du,
                              0x7779E898u, 0x8CC74079u, 0x2B6FFE73u, 0x52036CEEu }};

/* 2*d mod p */
static const SSFFE25519_t _ed_2d = {{ 0x26B2F159u, 0xEBD69B94u, 0x8283B156u, 0x00E0149Au,
                               0xEEF3D130u, 0x198E80F2u, 0x56DFFCE7u, 0x2406D9DCu }};

/* sqrt(-1) mod p = 2^((p-1)/4) mod p                                                           */
static const SSFFE25519_t _fe_sqrtm1 = {{ 0x4A0EA0B0u, 0xC4EE1B27u, 0xAD2FE478u, 0x2F431806u,
                                   0x3DFBD7A7u, 0x2B4D0099u, 0x4FC1DF0Bu, 0x2B832480u }};

/* Base point B in extended-Edwards coords (X:Y:Z:T), X=B_x, Y=B_y=4/5 mod p, Z=1, T=B_x*B_y.    */
/* Y is the bytes 0x58 0x66x31 reinterpreted as 8 little-endian 32-bit limbs (sign bit clear).   */
/* X and T values are derived from the curve equation -x^2 + y^2 = 1 + d*x^2*y^2 with the        */
/* positive (even) root for x, then encoded as 8 limbs little-endian. Hardcoded here to skip the */
/* per-call _ge_decode the previous design did at every Sign / Verify / PubKeyFromSeed entry.    */
/* Correctness of these constants is enforced end-to-end by the RFC 8032 Sec. 7.1 test vectors and*/
/* the OpenSSL cross-check below -- any wrong byte makes every signature deviate.                 */
static const _ge_t _ed_basepoint = {
    /* X */ {{ 0x8F25D51Au, 0xC9562D60u, 0x9525A7B2u, 0x692CC760u,
               0xFDD6DC5Cu, 0xC0A4E231u, 0xCD6E53FEu, 0x216936D3u }},
    /* Y */ {{ 0x66666658u, 0x66666666u, 0x66666666u, 0x66666666u,
               0x66666666u, 0x66666666u, 0x66666666u, 0x66666666u }},
    /* Z = 1 */ {{ 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u }},
    /* T = X*Y mod p */ {{ 0xA5B7DDA3u, 0x6DDE8AB3u, 0x775152F5u, 0x20F09F80u,
                           0x64ABE37Du, 0x66EA4E8Eu, 0xD78B7665u, 0x67875F0Fu }}
};

/* Group order L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t _ed_L[32] = {
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
    0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* --------------------------------------------------------------------------------------------- */
/* Edwards curve point operations                                                                */
/* --------------------------------------------------------------------------------------------- */

/* Set point to the identity (neutral element): (0:1:1:0) */
static void _ge_identity(_ge_t *r)
{
    SSFFE25519SetZero(&r->X);
    SSFFE25519SetOne(&r->Y);
    SSFFE25519SetOne(&r->Z);
    SSFFE25519SetZero(&r->T);
}

/* Point doubling in extended coordinates (a = -1 twisted Edwards).                              */
/* From: Hisil, Wong, Carter, Dawson "Twisted Edwards Curves Revisited", 2008.                   */
static void _ge_double(_ge_t *r, const _ge_t *p)
{
    SSFFE25519_t A, B, C, D, E, F, G, H;

    SSFFE25519Sqr(&A, &p->X);           /* A = X1^2 */
    SSFFE25519Sqr(&B, &p->Y);           /* B = Y1^2 */
    SSFFE25519Sqr(&C, &p->Z);           /* C = Z1^2 */
    _fe_add(&C, &C, &C);          /* C = 2*Z1^2 */
    _fe_neg(&D, &A);              /* D = -A (since a = -1) */
    _fe_add(&E, &p->X, &p->Y);   /* E = (X1+Y1) */
    SSFFE25519Sqr(&E, &E);              /* E = (X1+Y1)^2 */
    _fe_sub(&E, &E, &A);          /* E = (X1+Y1)^2 - A */
    _fe_sub(&E, &E, &B);          /* E = (X1+Y1)^2 - A - B */
    _fe_add(&F, &D, &B);          /* F = D + B */
    _fe_sub(&G, &F, &C);          /* G = F - C */
    _fe_sub(&H, &D, &B);          /* H = D - B */
    SSFFE25519Mul(&r->X, &E, &G);       /* X3 = E*G */
    SSFFE25519Mul(&r->Y, &F, &H);       /* Y3 = F*H */
    SSFFE25519Mul(&r->T, &E, &H);       /* T3 = E*H */
    SSFFE25519Mul(&r->Z, &F, &G);       /* Z3 = F*G */
}

/* Unified point addition in extended coordinates.                                               */
/* p3 = p1 + p2, using the formula from the Ed25519 paper.                                      */
static void _ge_add(_ge_t *r, const _ge_t *p1, const _ge_t *p2)
{
    SSFFE25519_t A, B, C, D, E, F, G, H;

    _fe_sub(&A, &p1->Y, &p1->X);  /* A = Y1-X1 */
    _fe_sub(&H, &p2->Y, &p2->X);  /* tmp = Y2-X2 */
    SSFFE25519Mul(&A, &A, &H);          /* A = (Y1-X1)*(Y2-X2) */
    _fe_add(&B, &p1->Y, &p1->X);  /* B = Y1+X1 */
    _fe_add(&H, &p2->Y, &p2->X);  /* tmp = Y2+X2 */
    SSFFE25519Mul(&B, &B, &H);          /* B = (Y1+X1)*(Y2+X2) */
    SSFFE25519Mul(&C, &p1->T, &p2->T);  /* C = T1*T2 */
    SSFFE25519Mul(&C, &C, &_ed_2d);     /* C = T1*2*d*T2 */
    SSFFE25519Mul(&D, &p1->Z, &p2->Z);  /* D = Z1*Z2 */
    _fe_add(&D, &D, &D);          /* D = 2*Z1*Z2 */
    _fe_sub(&E, &B, &A);          /* E = B-A */
    _fe_sub(&F, &D, &C);          /* F = D-C */
    _fe_add(&G, &D, &C);          /* G = D+C */
    _fe_add(&H, &B, &A);          /* H = B+A */
    SSFFE25519Mul(&r->X, &E, &F);       /* X3 = E*F */
    SSFFE25519Mul(&r->Y, &G, &H);       /* Y3 = G*H */
    SSFFE25519Mul(&r->T, &E, &H);       /* T3 = E*H */
    SSFFE25519Mul(&r->Z, &F, &G);       /* Z3 = F*G */
}

/* Encode a point to 32 bytes (Edwards compressed format).                                       */
/* The y-coordinate is encoded in LE; the high bit of byte 31 is the sign of x.                 */
static void _ge_encode(uint8_t out[32], const _ge_t *p)
{
    SSFFE25519_t recip, x, y;
    SSFFE25519Inv(&recip, &p->Z);
    SSFFE25519Mul(&x, &p->X, &recip);
    SSFFE25519Mul(&y, &p->Y, &recip);
    SSFFE25519ToBytes(out, &y);
    out[31] ^= (uint8_t)(_fe_isneg(&x) << 7);
}

/* Decode a 32-byte compressed point. Returns false if invalid. */
static bool _ge_decode(_ge_t *p, const uint8_t in[32])
{
    SSFFE25519_t u, v, v3, vxx, check;
    uint8_t sign;
    uint8_t tmp[32];

    sign = (in[31] >> 7) & 1u;

    memcpy(tmp, in, 32);
    tmp[31] &= 0x7Fu; /* clear sign bit */
    _fe_from_bytes(&p->Y, tmp);

    /* Reject non-canonical y per RFC 8032 Sec. 5.1.3 (must satisfy y < p). */
    {
        uint64_t borrow = 0;
        uint8_t i;
        for (i = 0; i < 8u; i++)
        {
            uint64_t diff = (uint64_t)p->Y.v[i] - (uint64_t)SSF_FE25519_P.v[i] - borrow;
            borrow = (diff >> 63) & 1u;
        }
        if (borrow == 0u) return false;
    }

    /* u = y^2 - 1 */
    SSFFE25519Sqr(&u, &p->Y);
    SSFFE25519Mul(&v, &u, &_ed_d);      /* v = d*y^2 */
    {
        SSFFE25519_t one;
        SSFFE25519SetOne(&one);
        _fe_sub(&u, &u, &one);    /* u = y^2 - 1 */
        _fe_add(&v, &v, &one);    /* v = d*y^2 + 1 */
    }

    /* Compute x = sqrt(u/v) via x = u * v^3 * (u * v^7)^((p-5)/8). */
    SSFFE25519Sqr(&v3, &v);             /* v^2 */
    SSFFE25519Mul(&v3, &v3, &v);        /* v^3 */
    SSFFE25519Sqr(&p->X, &v3);          /* v^6 */
    SSFFE25519Mul(&p->X, &p->X, &v);    /* v^7 */
    SSFFE25519Mul(&p->X, &p->X, &u);    /* u * v^7 */
    _fe_pow2523(&p->X, &p->X);    /* (u * v^7)^((p-5)/8) */
    SSFFE25519Mul(&p->X, &p->X, &v3);   /* * v^3 */
    SSFFE25519Mul(&p->X, &p->X, &u);    /* * u => candidate x */

    /* Check: v * x^2 == u ? */
    SSFFE25519Sqr(&vxx, &p->X);
    SSFFE25519Mul(&vxx, &vxx, &v);
    _fe_sub(&check, &vxx, &u);

    if (!_fe_iszero(&check))
    {
        /* Try x * sqrt(-1) */
        _fe_add(&check, &vxx, &u);
        if (!_fe_iszero(&check))
        {
            return false; /* No square root exists */
        }
        SSFFE25519Mul(&p->X, &p->X, &_fe_sqrtm1);
    }

    /* Adjust sign */
    if (_fe_isneg(&p->X) != sign)
    {
        _fe_neg(&p->X, &p->X);
    }

    /* If x == 0 and sign == 1, invalid */
    if (_fe_iszero(&p->X) && (sign != 0u))
    {
        return false;
    }

    SSFFE25519Mul(&p->T, &p->X, &p->Y);
    SSFFE25519SetOne(&p->Z);

    return true;
}

/* Low-order subgroup check: returns true if [8]p is the identity, i.e., p has order in        */
/* {1,2,4,8}. Per Chalkias et al. "Taming the many EdDSAs" Sec. 5, signatures under low-order  */
/* public keys can be forged for arbitrary messages by setting (R, S) so that the verify        */
/* equation reduces to identity = identity, regardless of the message. RFC 8032 doesn't         */
/* mandate the check, but every modern Ed25519 implementation (libsodium >=1.0.16, BoringSSL)  */
/* enforces it; we match that posture. Three doublings is cheaper than the alternative          */
/* hardcoded byte-blocklist and generalises to any future torsion case.                          */
/* Identity in projective extended coords has X = 0 and Y = Z (and T = 0); checking those two   */
/* conditions on [8]p is sufficient because the doubling formula preserves the invariant T*Z = */
/* X*Y (and Y == Z combined with X == 0 implies that invariant trivially).                      */
static bool _ge_is_low_order(const _ge_t *p)
{
    _ge_t t;
    SSFFE25519_t diff;

    _ge_double(&t, p);     /* [2]p */
    _ge_double(&t, &t);    /* [4]p */
    _ge_double(&t, &t);    /* [8]p */

    if (_fe_iszero(&t.X) == 0u) return false;
    _fe_sub(&diff, &t.Y, &t.Z);
    return (_fe_iszero(&diff) != 0u);
}

/* Constant-time conditional swap of two group elements: if swap != 0, exchange a and b.        */
/* Implemented as four _fe_cswap calls over the four coordinate field-elements; the underlying   */
/* mask-XOR pattern has no secret-dependent branch or memory access.                             */
static void _ge_cswap(_ge_t *a, _ge_t *b, uint32_t swap)
{
    SSFFE25519CSwap(&a->X, &b->X, swap);
    SSFFE25519CSwap(&a->Y, &b->Y, swap);
    SSFFE25519CSwap(&a->Z, &b->Z, swap);
    SSFFE25519CSwap(&a->T, &b->T, swap);
}

/* Constant-time scalar multiplication: r = [scalar]p.                                           */
/* Double-and-add-always pattern: on every bit we compute both `Q' = 2Q` and `Q' + p`, then      */
/* constant-time-swap to keep `Q = 2Q + p` when the bit is 1 and `Q = 2Q` when it is 0. Every   */
/* iteration does exactly one double, one add, and one cswap regardless of bit value, so the    */
/* wall-clock runtime does not depend on the scalar bits. Roughly 2x slower than the            */
/* variable-time double-and-add above; use for any call site where `scalar` is a secret.        */
static void _ge_scalarmult_ct(_ge_t *r, const uint8_t scalar[32], const _ge_t *p)
{
    _ge_t Q;
    _ge_t QplusP;
    int16_t i;

    _ge_identity(&Q);
    for (i = 255; i >= 0; i--)
    {
        uint32_t bit = ((uint32_t)scalar[i >> 3] >> (i & 7)) & 1u;

        _ge_double(&Q, &Q);
        _ge_add(&QplusP, &Q, p);
        /* After the cswap:
         *   bit == 1 -> Q holds (Q + p)  (and QplusP holds the old Q, discarded)
         *   bit == 0 -> Q is unchanged   (and QplusP holds (Q + p), discarded)
         * Either way the next iteration reads only Q, so the discard is harmless. */
        _ge_cswap(&Q, &QplusP, bit);
    }
    *r = Q;
}

/* Base point scalar multiplication: r = [scalar]B. Sign-path entry point -- scalar here is the  */
/* RFC 8032 deterministic nonce, which is derived from the long-term seed and must not leak      */
/* via timing. Routes through the constant-time variant.                                         */
static void _ge_scalarmult_base(_ge_t *r, const uint8_t scalar[32])
{
    _ge_scalarmult_ct(r, scalar, &_ed_basepoint);
}

/* Double scalar multiplication: r = [a]A + [b]B (Straus/interleaved). */
static void _ge_double_scalarmult(_ge_t *r, const uint8_t a[32], const _ge_t *A,
                                  const uint8_t b[32])
{
    _ge_t Q;
    int16_t i;

    _ge_identity(&Q);
    for (i = 255; i >= 0; i--)
    {
        uint8_t aBit = (a[i >> 3] >> (i & 7)) & 1u;
        uint8_t bBit = (b[i >> 3] >> (i & 7)) & 1u;

        _ge_double(&Q, &Q);
        if (aBit != 0u)
        {
            _ge_add(&Q, &Q, A);
        }
        if (bBit != 0u)
        {
            _ge_add(&Q, &Q, &_ed_basepoint);
        }
    }
    *r = Q;
}

/* --------------------------------------------------------------------------------------------- */
/* Scalar arithmetic modulo L (group order, SUPERCOP ref10 24-limb signed representation).       */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Writes x mod L to r (32 bytes LE) and wipes x; x is 64 signed byte limbs (OPTIMIZE ED-O1).    */
/* --------------------------------------------------------------------------------------------- */
static void _sc_modL(uint8_t r[32], int64_t x[64])
{
    int64_t carry;
    int64_t q;
    uint16_t i;
    uint16_t j;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(x != NULL);

    /* Fold limbs 63..32 down: 2^252 == -(L - 2^252) mod L, so 2^(8i) folds into limbs i - 32.. */
    for (i = 63u; i >= 32u; i--)
    {
        carry = 0;
        for (j = (uint16_t)(i - 32u); j < (uint16_t)(i - 12u); j++)
        {
            x[j] += carry - (16 * x[i] * (int64_t)_ed_L[j - (i - 32u)]);
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }

    /* Subtract (x >> 252) * L; L > 2^252, so x may go negative (carry -1); limbs to 8 bits */
    q = x[31] >> 4;
    carry = 0;
    for (j = 0u; j < 32u; j++)
    {
        x[j] += carry - (q * (int64_t)_ed_L[j]);
        carry = x[j] >> 8;
        x[j] &= 255;
    }

    /* The final carry is 0 or -1: subtracting it times L adds L back if x went negative */
    for (j = 0u; j < 32u; j++) x[j] -= carry * (int64_t)_ed_L[j];
    for (i = 0u; i < 32u; i++)
    {
        x[i + 1u] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }

    /* x held the secret nonce or h * a + r */
    SSFCryptSecureZero(x, 64u * sizeof(int64_t));
}

#if SSF_CONFIG_ED25519_UNIT_TEST == 1
/* Test-only wrapper exposing _fe_mul so a unit test can pin carry-fold edge inputs (AUDIT E-1). */
void _SSFEd25519FeMulForTest(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    SSFFE25519_t fa;
    SSFFE25519_t fb;
    SSFFE25519_t fr;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    _fe_from_bytes(&fa, a);
    _fe_from_bytes(&fb, b);
    SSFFE25519Mul(&fr, &fa, &fb);
    SSFFE25519ToBytes(out, &fr);
}

/* Test-only wrapper exposing _ge_decode and returning the affine x of the decoded point. */
bool _SSFEd25519GeDecodeForTest(uint8_t xOut[32], const uint8_t in[32])
{
    _ge_t pt;
    SSFFE25519_t zInv;
    SSFFE25519_t x;

    SSF_REQUIRE(xOut != NULL);
    SSF_REQUIRE(in != NULL);

    /* Did the encoding decode to a curve point? */
    if (!_ge_decode(&pt, in))
    {
        /* No, report failure */
        return false;
    }
    /* Yes, convert X to affine */
    SSFFE25519Inv(&zInv, &pt.Z);
    SSFFE25519Mul(&x, &pt.X, &zInv);
    SSFFE25519ToBytes(xOut, &x);
    return true;
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Reduces the 64-byte LE integer in s mod L into s[0..31]; clears s[32..63] (OPTIMIZE ED-O1).   */
/* --------------------------------------------------------------------------------------------- */
static void _sc_reduce(uint8_t s[64])
{
    int64_t x[64];
    uint16_t i;

    SSF_REQUIRE(s != NULL);

    for (i = 0u; i < 64u; i++) x[i] = (int64_t)s[i];
    memset(s, 0, 64u);
    _sc_modL(s, x);
}

#if SSF_CONFIG_ED25519_UNIT_TEST == 1
/* Test-only wrapper exposing _sc_reduce: 64-byte LE in, s mod L in the low 32 bytes. */
void _SSFEd25519ScReduceForTest(uint8_t s[64])
{
    SSF_REQUIRE(s != NULL);

    _sc_reduce(s);
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* s = (a * b + c) mod L, 32-byte LE operands of any value; s may alias any (OPTIMIZE ED-O1).    */
/* --------------------------------------------------------------------------------------------- */
/* Not inlined: its 512-byte x stays off Sign's verify-after-sign chain, the stack peak          */
SSF_NOINLINE
static void _sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
    int64_t x[64];
    uint16_t i;
    uint16_t j;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(c != NULL);

    /* Schoolbook a * b + c in byte limbs: each limb stays below 32 * 255^2 + 255 */
    for (i = 0u; i < 64u; i++) x[i] = (i < 32u) ? (int64_t)c[i] : 0;
    for (i = 0u; i < 32u; i++)
    {
        for (j = 0u; j < 32u; j++) x[i + j] += (int64_t)a[i] * (int64_t)b[j];
    }
    _sc_modL(s, x);
}

#if SSF_CONFIG_ED25519_UNIT_TEST == 1
/* Test-only wrapper exposing _sc_muladd: s = (a * b + c) mod L, 32-byte LE operands. */
void _SSFEd25519ScMulAddForTest(uint8_t s[32], const uint8_t a[32], const uint8_t b[32],
                                const uint8_t c[32])
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(c != NULL);

    _sc_muladd(s, a, b, c);
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */

/* Check if a 32-byte scalar is less than L. Returns true if s < L. */
static bool _sc_is_lt_L(const uint8_t s[32])
{
    int16_t i;
    /* Compare from high byte to low byte */
    for (i = 31; i >= 0; i--)
    {
        if (s[i] < _ed_L[i]) return true;
        if (s[i] > _ed_L[i]) return false;
    }
    return false; /* Equal to L, not less than */
}

#if (SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB != 0u) && (SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB != 1u)
#error SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB must be 0 or 1.
#endif

#if SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB == 1
#if SSF_ED25519_CONFIG_STACK_SCRUB_SIZE < 1
#error SSF_ED25519_CONFIG_STACK_SCRUB_SIZE must be > 0 when the stack scrub is enabled.
#endif

/* --------------------------------------------------------------------------------------------- */
/* Zeroes SSF_ED25519_CONFIG_STACK_SCRUB_SIZE bytes of stack below Sign (freed intermediates).   */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static void _ed25519_stack_scrub(void)
{
    volatile uint8_t scratch[SSF_ED25519_CONFIG_STACK_SCRUB_SIZE];
    size_t i;
    for (i = 0; i < sizeof(scratch); i++) scratch[i] = 0u;
    SSF_OPTIMIZER_BARRIER(scratch);
}
#else /* SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB */
/* Stack scrub disabled by configuration; call sites compile to nothing. */
#define _ed25519_stack_scrub() do { } while (0)
#endif /* SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB */

/* --------------------------------------------------------------------------------------------- */
/* Feeds an arbitrary-size buffer to a SHA-512 context, looping in UINT32_MAX-sized chunks.      */
/* --------------------------------------------------------------------------------------------- */
static void _sha512_update_sized(SSFSHA2_64Context_t *ctx, const uint8_t *buf, size_t len)
{
    while (len > 0u)
    {
        uint32_t chunk = (len > (size_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)len;
        SSFSHA512Update(ctx, buf, chunk);
        buf += chunk;
        len -= chunk;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Public API                                                                                    */
/* --------------------------------------------------------------------------------------------- */

/* Generate an Ed25519 key pair. */
bool SSFEd25519KeyGen(uint8_t seed[SSF_ED25519_SEED_SIZE], uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE])
{
    SSF_REQUIRE(seed != NULL);
    SSF_REQUIRE(pubKey != NULL);

    if (!SSFPortGetEntropy(seed, (uint16_t)SSF_ED25519_SEED_SIZE)) return false;
    SSFEd25519PubKeyFromSeed(seed, pubKey);
    return true;
}

/* Derive public key from a 32-byte seed. */
void SSFEd25519PubKeyFromSeed(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                              uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE])
{
    uint8_t h[64];
    uint8_t a[32];
    _ge_t A;

    SSF_REQUIRE(seed != NULL);
    SSF_REQUIRE(pubKey != NULL);

    SSFSHA512(seed, 32, h, 64);

    /* Clamp scalar */
    memcpy(a, h, 32);
    a[0]  &= 248u;
    a[31] &= 127u;
    a[31] |= 64u;

    /* A = [a]B */
    _ge_scalarmult_base(&A, a);
    _ge_encode(pubKey, &A);

    /* Zeroize sensitive data */
    SSFCryptSecureZero(h, sizeof(h));
    SSFCryptSecureZero(a, sizeof(a));
}

/* Sign a message. */
bool SSFEd25519Sign(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                    const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE], const uint8_t *msg,
                    size_t msgLen, uint8_t sig[SSF_ED25519_SIG_SIZE])
{
    uint8_t h[64], r_hash[64], hram[64];
    uint8_t a[32], nonce[32];
    _ge_t R;
    SSFSHA2_64Context_t ctx;

    SSF_REQUIRE(seed != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE((msg != NULL) || (msgLen == 0u));
    SSF_REQUIRE(sig != NULL);

    /* Derive scalar and prefix from seed */
    SSFSHA512(seed, 32, h, 64);
    memcpy(a, h, 32);
    a[0]  &= 248u;
    a[31] &= 127u;
    a[31] |= 64u;

    /* r = SHA-512(prefix || msg) mod L */
    SSFSHA512Begin(&ctx);
    SSFSHA512Update(&ctx, &h[32], 32);  /* prefix = upper 32 bytes of SHA-512(seed) */
    _sha512_update_sized(&ctx, msg, msgLen);
    SSFSHA512End(&ctx, r_hash, 64);
    _sc_reduce(r_hash);
    memcpy(nonce, r_hash, 32);

    /* R = [r]B */
    _ge_scalarmult_base(&R, nonce);
    _ge_encode(sig, &R);  /* first 32 bytes of sig = encoded R */

    /* S = (r + SHA-512(R || pubKey || msg) * a) mod L */
    SSFSHA512Begin(&ctx);
    SSFSHA512Update(&ctx, sig, 32);     /* R */
    SSFSHA512Update(&ctx, pubKey, 32);  /* A */
    _sha512_update_sized(&ctx, msg, msgLen);
    SSFSHA512End(&ctx, hram, 64);
    _sc_reduce(hram);

    _sc_muladd(&sig[32], hram, a, nonce);  /* S = h*a + r mod L */

    /* Verify-after-sign defeats differential-fault attacks and catches seed/pubKey mismatch. */
    if (!SSFEd25519Verify(pubKey, msg, msgLen, sig))
    {
        SSFCryptSecureZero(sig, SSF_ED25519_SIG_SIZE);
        SSFCryptSecureZero(h, sizeof(h));
        SSFCryptSecureZero(a, sizeof(a));
        SSFCryptSecureZero(nonce, sizeof(nonce));
        SSFCryptSecureZero(r_hash, sizeof(r_hash));
        SSFCryptSecureZero(hram, sizeof(hram));
        SSFCryptSecureZero(&R, sizeof(R));
        SSFCryptSecureZero(&ctx, sizeof(ctx));
        _ed25519_stack_scrub();
        return false;
    }

    /* Zeroize sensitive data */
    SSFCryptSecureZero(h, sizeof(h));
    SSFCryptSecureZero(a, sizeof(a));
    SSFCryptSecureZero(nonce, sizeof(nonce));
    SSFCryptSecureZero(r_hash, sizeof(r_hash));
    SSFCryptSecureZero(hram, sizeof(hram));
    SSFCryptSecureZero(&R, sizeof(R));
    SSFCryptSecureZero(&ctx, sizeof(ctx));
    _ed25519_stack_scrub();

    return true;
}

/* Verify a signature. Returns true if valid. */
bool SSFEd25519Verify(const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE], const uint8_t *msg,
                      size_t msgLen, const uint8_t sig[SSF_ED25519_SIG_SIZE])
{
    _ge_t A, negA, check;
    uint8_t hram[64];
    SSFSHA2_64Context_t ctx;
    uint8_t rcheck[32];

    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE((msg != NULL) || (msgLen == 0u));
    SSF_REQUIRE(sig != NULL);

    /* Check S < L */
    if (!_sc_is_lt_L(&sig[32])) return false;

    /* Decode public key */
    if (!_ge_decode(&A, pubKey)) return false;

    /* Reject low-order pubkeys ([8]A = identity -> trivial forgery for any message). */
    if (_ge_is_low_order(&A)) return false;

    /* Negate A: -A has coordinates (-X, Y, Z, -T) */
    _fe_neg(&negA.X, &A.X);
    SSFFE25519Copy(&negA.Y, &A.Y);
    SSFFE25519Copy(&negA.Z, &A.Z);
    _fe_neg(&negA.T, &A.T);

    /* h = SHA-512(R || A || msg) mod L */
    SSFSHA512Begin(&ctx);
    SSFSHA512Update(&ctx, sig, 32);     /* R (first 32 bytes of sig) */
    SSFSHA512Update(&ctx, pubKey, 32);  /* A */
    _sha512_update_sized(&ctx, msg, msgLen);
    SSFSHA512End(&ctx, hram, 64);
    _sc_reduce(hram);

    /* check = [S]B + [h](-A) = [S]B - [h]A */
    _ge_double_scalarmult(&check, hram, &negA, &sig[32]);

    _ge_encode(rcheck, &check);

    /* Compare the recomputed R against the signature in constant time. */
    return SSFCryptCTMemEq(rcheck, sig, 32);
}

