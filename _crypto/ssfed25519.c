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

/* --------------------------------------------------------------------------------------------- */
/* r = a + b, lazily reduced below 2^256 (up to 2p if both inputs < p).                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519FeAdd(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b)
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
        uint64_t c = SSF_CT_MUL32(carry, 38u);
        for (i = 0; i < 8u; i++)
        {
            c += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c;
            c >>= 32;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a - b mod p: reduces both inputs, subtracts, then adds 2p on borrow (constant time).      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519FeSub(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b)
{
    uint64_t borrow = 0;
    uint8_t i;
    SSFFE25519_t ar;
    SSFFE25519_t br;

    /* Reduce inputs to [0, p) so that a - b + 2p is in [0, 2p + p) = [0, 3p) < 2^257 */
    SSFFE25519Copy(&ar, a);
    SSFFE25519Copy(&br, b);
    SSFFE25519Reduce(&ar);
    SSFFE25519Reduce(&br);

    /* r = a - b */
    for (i = 0; i < 8u; i++)
    {
        uint64_t diff = ((uint64_t)ar.v[i] - (uint64_t)br.v[i]) - borrow;
        r->v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }

    /* Add 2p on borrow, masked and unconditional (constant time) */
    {
        uint32_t mask = (uint32_t)(0u - (uint32_t)borrow);
        uint64_t carry = 0;
        SSF_CT_VALUE_BARRIER(mask);
        for (i = 0; i < 8u; i++)
        {
            carry += (uint64_t)r->v[i] + (2u * (uint64_t)(SSF_FE25519_P.v[i] & mask));
            r->v[i] = (uint32_t)carry;
            carry >>= 32;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Imports a from 32 little-endian bytes at b; the caller clears any bits beforehand.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519FeFromBytes(SSFFE25519_t *a, const uint8_t *b)
{
    uint8_t i;

    for (i = 0; i < 8u; i++)
    {
        a->v[i] = ((uint32_t)b[i * 4u]) |
                  ((uint32_t)b[(i * 4u) + 1u] << 8) |
                  ((uint32_t)b[(i * 4u) + 2u] << 16) |
                  ((uint32_t)b[(i * 4u) + 3u] << 24);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^((p - 5) / 8) = a^(2^252 - 3) mod p, the exponent of the decode square-root step.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519FePow2523(SSFFE25519_t *r, const SSFFE25519_t *a)
{
    SSFFE25519_t t0;
    SSFFE25519_t t1;
    SSFFE25519_t t2;
    SSFFE25519_t t3;
    uint16_t i;

    /* a^2 (SSFFE25519Inv() chain to a^(2^250 - 1), then 2 squarings and a multiply by a) */

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

/* --------------------------------------------------------------------------------------------- */
/* Returns 1 if a, fully reduced, is negative (odd), else 0.                                     */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFEd25519FeIsNeg(const SSFFE25519_t *a)
{
    SSFFE25519_t t;

    SSFFE25519Copy(&t, a);
    SSFFE25519Reduce(&t);
    return (uint8_t)(t.v[0] & 1u);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 1 if a, fully reduced, is zero, else 0 (constant time).                               */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFEd25519FeIsZero(const SSFFE25519_t *a)
{
    SSFFE25519_t t;
    uint32_t bits;
    uint8_t i;

    SSFFE25519Copy(&t, a);
    SSFFE25519Reduce(&t);
    bits = 0;
    for (i = 0; i < 8u; i++) bits |= t.v[i];
    /* (bits | -bits) has bit 31 set iff bits != 0; the negate is unsigned to avoid overflow */
    return (uint8_t)(1u ^ (((bits | ((uint32_t)0u - bits)) >> 31) & 1u));
}

/* --------------------------------------------------------------------------------------------- */
/* r = -a mod p.                                                                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519FeNeg(SSFFE25519_t *r, const SSFFE25519_t *a)
{
    SSFFE25519_t zero;

    SSFFE25519SetZero(&zero);
    _SSFEd25519FeSub(r, &zero, a);
}

/* --------------------------------------------------------------------------------------------- */
/* Edwards point in extended coords (X:Y:Z:T): x=X/Z, y=Y/Z, T=X*Y/Z; curve a = -1.              */
/* --------------------------------------------------------------------------------------------- */
typedef struct
{
    SSFFE25519_t X;
    SSFFE25519_t Y;
    SSFFE25519_t Z;
    SSFFE25519_t T;
} _ge_t;

/* d = -121665/121666 mod p */
static const SSFFE25519_t _ed_d = {{ 0x135978A3u, 0x75EB4DCAu, 0x4141D8ABu, 0x00700A4Du,
                              0x7779E898u, 0x8CC74079u, 0x2B6FFE73u, 0x52036CEEu }};

/* 2*d mod p */
static const SSFFE25519_t _ed_2d = {{ 0x26B2F159u, 0xEBD69B94u, 0x8283B156u, 0x00E0149Au,
                               0xEEF3D130u, 0x198E80F2u, 0x56DFFCE7u, 0x2406D9DCu }};

/* sqrt(-1) mod p = 2^((p-1)/4) mod p */
static const SSFFE25519_t _fe_sqrtm1 = {{ 0x4A0EA0B0u, 0xC4EE1B27u, 0xAD2FE478u, 0x2F431806u,
                                   0x3DFBD7A7u, 0x2B4D0099u, 0x4FC1DF0Bu, 0x2B832480u }};

/* Base point B (X:Y:Z:T): Y = 4/5 mod p, X its even root, Z = 1, T = X * Y; RFC 8032 Sec. 5.1 */
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

/* --------------------------------------------------------------------------------------------- */
/* Sets r to the identity (neutral element) (0:1:1:0).                                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeIdentity(_ge_t *r)
{
    SSFFE25519SetZero(&r->X);
    SSFFE25519SetOne(&r->Y);
    SSFFE25519SetOne(&r->Z);
    SSFFE25519SetZero(&r->T);
}

/* --------------------------------------------------------------------------------------------- */
/* r = 2p in extended coords, a = -1 (Hisil, Wong, Carter, Dawson, "Twisted Edwards...", 2008).  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeDouble(_ge_t *r, const _ge_t *p)
{
    SSFFE25519_t A;
    SSFFE25519_t B;
    SSFFE25519_t C;
    SSFFE25519_t D;
    SSFFE25519_t E;
    SSFFE25519_t F;
    SSFFE25519_t G;
    SSFFE25519_t H;

    SSFFE25519Sqr(&A, &p->X); /* A = X1^2 */
    SSFFE25519Sqr(&B, &p->Y); /* B = Y1^2 */
    SSFFE25519Sqr(&C, &p->Z); /* C = Z1^2 */
    _SSFEd25519FeAdd(&C, &C, &C); /* C = 2*Z1^2 */
    _SSFEd25519FeNeg(&D, &A); /* D = -A (since a = -1) */
    _SSFEd25519FeAdd(&E, &p->X, &p->Y); /* E = (X1+Y1) */
    SSFFE25519Sqr(&E, &E); /* E = (X1+Y1)^2 */
    _SSFEd25519FeSub(&E, &E, &A); /* E = (X1+Y1)^2 - A */
    _SSFEd25519FeSub(&E, &E, &B); /* E = (X1+Y1)^2 - A - B */
    _SSFEd25519FeAdd(&F, &D, &B); /* F = D + B */
    _SSFEd25519FeSub(&G, &F, &C); /* G = F - C */
    _SSFEd25519FeSub(&H, &D, &B); /* H = D - B */
    SSFFE25519Mul(&r->X, &E, &G); /* X3 = E*G */
    SSFFE25519Mul(&r->Y, &F, &H); /* Y3 = F*H */
    SSFFE25519Mul(&r->T, &E, &H); /* T3 = E*H */
    SSFFE25519Mul(&r->Z, &F, &G); /* Z3 = F*G */
}

/* --------------------------------------------------------------------------------------------- */
/* r = p1 + p2 by the unified extended-coordinates addition of the Ed25519 paper.                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeAdd(_ge_t *r, const _ge_t *p1, const _ge_t *p2)
{
    SSFFE25519_t A;
    SSFFE25519_t B;
    SSFFE25519_t C;
    SSFFE25519_t D;
    SSFFE25519_t E;
    SSFFE25519_t F;
    SSFFE25519_t G;
    SSFFE25519_t H;

    _SSFEd25519FeSub(&A, &p1->Y, &p1->X); /* A = Y1-X1 */
    _SSFEd25519FeSub(&H, &p2->Y, &p2->X); /* tmp = Y2-X2 */
    SSFFE25519Mul(&A, &A, &H); /* A = (Y1-X1)*(Y2-X2) */
    _SSFEd25519FeAdd(&B, &p1->Y, &p1->X); /* B = Y1+X1 */
    _SSFEd25519FeAdd(&H, &p2->Y, &p2->X); /* tmp = Y2+X2 */
    SSFFE25519Mul(&B, &B, &H); /* B = (Y1+X1)*(Y2+X2) */
    SSFFE25519Mul(&C, &p1->T, &p2->T); /* C = T1*T2 */
    SSFFE25519Mul(&C, &C, &_ed_2d); /* C = T1*2*d*T2 */
    SSFFE25519Mul(&D, &p1->Z, &p2->Z); /* D = Z1*Z2 */
    _SSFEd25519FeAdd(&D, &D, &D); /* D = 2*Z1*Z2 */
    _SSFEd25519FeSub(&E, &B, &A); /* E = B-A */
    _SSFEd25519FeSub(&F, &D, &C); /* F = D-C */
    _SSFEd25519FeAdd(&G, &D, &C); /* G = D+C */
    _SSFEd25519FeAdd(&H, &B, &A); /* H = B+A */
    SSFFE25519Mul(&r->X, &E, &F); /* X3 = E*F */
    SSFFE25519Mul(&r->Y, &G, &H); /* Y3 = G*H */
    SSFFE25519Mul(&r->T, &E, &H); /* T3 = E*H */
    SSFFE25519Mul(&r->Z, &F, &G); /* Z3 = F*G */
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes p to 32 bytes: y little-endian with the sign of x in the high bit of byte 31.         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeEncode(uint8_t out[32], const _ge_t *p)
{
    SSFFE25519_t recip;
    SSFFE25519_t x;
    SSFFE25519_t y;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(p != NULL);

    SSFFE25519Inv(&recip, &p->Z);
    SSFFE25519Mul(&x, &p->X, &recip);
    SSFFE25519Mul(&y, &p->Y, &recip);
    SSFFE25519ToBytes(out, &y);
    out[31] ^= (uint8_t)(_SSFEd25519FeIsNeg(&x) << 7);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in decodes to a curve point p (RFC 8032 Sec. 5.1.3), else false.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFEd25519GeDecode(_ge_t *p, const uint8_t in[32])
{
    SSFFE25519_t u;
    SSFFE25519_t v;
    SSFFE25519_t v3;
    SSFFE25519_t vxx;
    SSFFE25519_t check;
    uint8_t sign;
    uint8_t tmp[32];

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(in != NULL);

    sign = (in[31] >> 7) & 1u;

    memcpy(tmp, in, 32);
    tmp[31] &= 0x7Fu; /* clear sign bit */
    _SSFEd25519FeFromBytes(&p->Y, tmp);

    /* Reject non-canonical y per RFC 8032 Sec. 5.1.3 (must satisfy y < p). */
    {
        uint64_t borrow = 0;
        uint8_t i;
        for (i = 0; i < 8u; i++)
        {
            uint64_t diff = ((uint64_t)p->Y.v[i] - (uint64_t)SSF_FE25519_P.v[i]) - borrow;
            borrow = (diff >> 63) & 1u;
        }
        if (borrow == 0u) return false;
    }

    /* u = y^2 - 1 */
    SSFFE25519Sqr(&u, &p->Y);
    SSFFE25519Mul(&v, &u, &_ed_d); /* v = d*y^2 */
    {
        SSFFE25519_t one;
        SSFFE25519SetOne(&one);
        _SSFEd25519FeSub(&u, &u, &one); /* u = y^2 - 1 */
        _SSFEd25519FeAdd(&v, &v, &one); /* v = d*y^2 + 1 */
    }

    /* Compute x = sqrt(u/v) via x = u * v^3 * (u * v^7)^((p-5)/8). */
    SSFFE25519Sqr(&v3, &v); /* v^2 */
    SSFFE25519Mul(&v3, &v3, &v); /* v^3 */
    SSFFE25519Sqr(&p->X, &v3); /* v^6 */
    SSFFE25519Mul(&p->X, &p->X, &v); /* v^7 */
    SSFFE25519Mul(&p->X, &p->X, &u); /* u * v^7 */
    _SSFEd25519FePow2523(&p->X, &p->X); /* (u * v^7)^((p-5)/8) */
    SSFFE25519Mul(&p->X, &p->X, &v3); /* * v^3 */
    SSFFE25519Mul(&p->X, &p->X, &u); /* * u => candidate x */

    SSFFE25519Sqr(&vxx, &p->X);
    SSFFE25519Mul(&vxx, &vxx, &v);
    _SSFEd25519FeSub(&check, &vxx, &u);

    /* Is v * x^2 != u? */
    if (!_SSFEd25519FeIsZero(&check))
    {
        /* Yes, x * sqrt(-1) is the root if v * x^2 == -u */
        _SSFEd25519FeAdd(&check, &vxx, &u);
        if (!_SSFEd25519FeIsZero(&check))
        {
            return false; /* No square root exists */
        }
        SSFFE25519Mul(&p->X, &p->X, &_fe_sqrtm1);
    }

    /* Does the sign of x differ from the encoded sign bit? */
    if (_SSFEd25519FeIsNeg(&p->X) != sign)
    {
        /* Yes, negate x */
        _SSFEd25519FeNeg(&p->X, &p->X);
    }

    /* Is x zero with the sign bit set (no such point)? */
    if (_SSFEd25519FeIsZero(&p->X) && (sign != 0u))
    {
        /* Yes, invalid encoding */
        return false;
    }

    SSFFE25519Mul(&p->T, &p->X, &p->Y);
    SSFFE25519SetOne(&p->Z);

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if [8]p is the identity (p has order 1, 2, 4 or 8), else false.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFEd25519GeIsLowOrder(const _ge_t *p)
{
    _ge_t t;
    SSFFE25519_t diff;

    SSF_REQUIRE(p != NULL);

    _SSFEd25519GeDouble(&t, p); /* [2]p */
    _SSFEd25519GeDouble(&t, &t); /* [4]p */
    _SSFEd25519GeDouble(&t, &t); /* [8]p */

    /* Identity has X = 0 and Y = Z; doubling keeps T * Z = X * Y, so T needs no check */
    if (_SSFEd25519FeIsZero(&t.X) == 0u) return false;
    _SSFEd25519FeSub(&diff, &t.Y, &t.Z);
    return (_SSFEd25519FeIsZero(&diff) != 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Swaps points a and b if the low bit of swap is set, in constant time (mask-XOR per field).    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeCSwap(_ge_t *a, _ge_t *b, uint32_t swap)
{
    SSFFE25519CSwap(&a->X, &b->X, swap);
    SSFFE25519CSwap(&a->Y, &b->Y, swap);
    SSFFE25519CSwap(&a->Z, &b->Z, swap);
    SSFFE25519CSwap(&a->T, &b->T, swap);
}

/* --------------------------------------------------------------------------------------------- */
/* r = [scalar]p by constant-time double-and-add-always; use wherever scalar is secret.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeScalarMultCT(_ge_t *r, const uint8_t scalar[32], const _ge_t *p)
{
    _ge_t Q;
    _ge_t QplusP;
    int16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(scalar != NULL);
    SSF_REQUIRE(p != NULL);

    _SSFEd25519GeIdentity(&Q);
    for (i = 255; i >= 0; i--)
    {
        uint32_t bit = ((uint32_t)scalar[i >> 3] >> (i & 7)) & 1u;

        _SSFEd25519GeDouble(&Q, &Q);
        _SSFEd25519GeAdd(&QplusP, &Q, p);
        /* Q = Q + p if bit is 1, else Q unchanged; QplusP is discarded either way */
        _SSFEd25519GeCSwap(&Q, &QplusP, bit);
    }
    *r = Q;
}

/* --------------------------------------------------------------------------------------------- */
/* r = [scalar]B in constant time; scalar is the secret clamped key or nonce.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeScalarMultBase(_ge_t *r, const uint8_t scalar[32])
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(scalar != NULL);

    _SSFEd25519GeScalarMultCT(r, scalar, &_ed_basepoint);
}

/* --------------------------------------------------------------------------------------------- */
/* r = [a]A + [b]B by interleaved (Straus) double-and-add; variable time, public scalars only.   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519GeDoubleScalarMult(_ge_t *r, const uint8_t a[32], const _ge_t *A,
                                  const uint8_t b[32])
{
    _ge_t Q;
    int16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(A != NULL);
    SSF_REQUIRE(b != NULL);

    _SSFEd25519GeIdentity(&Q);
    for (i = 255; i >= 0; i--)
    {
        uint8_t aBit = (a[i >> 3] >> (i & 7)) & 1u;
        uint8_t bBit = (b[i >> 3] >> (i & 7)) & 1u;

        _SSFEd25519GeDouble(&Q, &Q);
        if (aBit != 0u)
        {
            _SSFEd25519GeAdd(&Q, &Q, A);
        }
        if (bBit != 0u)
        {
            _SSFEd25519GeAdd(&Q, &Q, &_ed_basepoint);
        }
    }
    *r = Q;
}

/* --------------------------------------------------------------------------------------------- */
/* Scalar arithmetic modulo L (group order, SUPERCOP ref10 24-limb signed representation).       */
/* --------------------------------------------------------------------------------------------- */

/* Multiply operands in the scalar arithmetic are int64 but fit int32 (checked under unit test). */
/* Interval bound over the code below, from inputs of at most 32 * 255^2 + 255 per limb          */
/* (ScMulAdd; ScReduce's bytes are smaller): |16 * x[i]| <= 33,427,456 (2^25), q <= 9, the final  */
/* carry is 0 or -1. Products are formed in full 64 bits by SSF_CT_SMUL32.                       */
#if SSF_CONFIG_ED25519_UNIT_TEST == 1
#define _SSF_ED_FITS32(v) SSF_ASSERT(((v) >= (int64_t)INT32_MIN) && ((v) <= (int64_t)INT32_MAX))
#else
#define _SSF_ED_FITS32(v) do { } while (0)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Writes x mod L to r (32 bytes LE) and wipes x; x is 64 signed byte limbs.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519ScModL(uint8_t r[32], int64_t x[64])
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
            _SSF_ED_FITS32(16 * x[i]);
            x[j] += carry - SSF_CT_SMUL32(16 * x[i], _ed_L[j - (i - 32u)]);
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
        _SSF_ED_FITS32(q);
        x[j] += carry - SSF_CT_SMUL32(q, _ed_L[j]);
        carry = x[j] >> 8;
        x[j] &= 255;
    }

    /* The final carry is 0 or -1: subtracting it times L adds L back if x went negative */
    _SSF_ED_FITS32(carry);
    for (j = 0u; j < 32u; j++) x[j] -= SSF_CT_SMUL32(carry, _ed_L[j]);
    for (i = 0u; i < 32u; i++)
    {
        x[i + 1u] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }

    /* x held the secret nonce or h * a + r */
    SSFCryptSecureZero(x, 64u * sizeof(int64_t));
}

#if SSF_CONFIG_ED25519_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Test-only wrapper: out = a * b mod p for 32-byte LE a and b (pins carry-fold edge inputs).    */
/* --------------------------------------------------------------------------------------------- */
void _SSFEd25519FeMulForTest(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    SSFFE25519_t fa;
    SSFFE25519_t fb;
    SSFFE25519_t fr;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    _SSFEd25519FeFromBytes(&fa, a);
    _SSFEd25519FeFromBytes(&fb, b);
    SSFFE25519Mul(&fr, &fa, &fb);
    SSFFE25519ToBytes(out, &fr);
}

/* --------------------------------------------------------------------------------------------- */
/* Test-only wrapper: returns true if in decodes to a point, with its affine x in xOut.          */
/* --------------------------------------------------------------------------------------------- */
bool _SSFEd25519GeDecodeForTest(uint8_t xOut[32], const uint8_t in[32])
{
    _ge_t pt;
    SSFFE25519_t zInv;
    SSFFE25519_t x;

    SSF_REQUIRE(xOut != NULL);
    SSF_REQUIRE(in != NULL);

    /* Did the encoding decode to a curve point? */
    if (!_SSFEd25519GeDecode(&pt, in))
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
/* Reduces the 64-byte LE integer in s mod L into s[0..31]; clears s[32..63].                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519ScReduce(uint8_t s[64])
{
    int64_t x[64];
    uint16_t i;

    SSF_REQUIRE(s != NULL);

    for (i = 0u; i < 64u; i++) x[i] = (int64_t)s[i];
    memset(s, 0, 64u);
    _SSFEd25519ScModL(s, x);
}

#if SSF_CONFIG_ED25519_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Test-only wrapper: reduces 64-byte LE s mod L into its low 32 bytes.                          */
/* --------------------------------------------------------------------------------------------- */
void _SSFEd25519ScReduceForTest(uint8_t s[64])
{
    SSF_REQUIRE(s != NULL);

    _SSFEd25519ScReduce(s);
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* s = (a * b + c) mod L, 32-byte LE operands of any value; s may alias any.                     */
/* --------------------------------------------------------------------------------------------- */
/* Not inlined so its 512-byte x stays off Sign's verify-after-sign chain (the stack peak) */
SSF_NOINLINE
static void _SSFEd25519ScMulAdd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32],
                                const uint8_t c[32])

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
        for (j = 0u; j < 32u; j++) x[i + j] += SSF_CT_SMUL32(a[i], b[j]);
    }
    _SSFEd25519ScModL(s, x);
}

#if SSF_CONFIG_ED25519_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Test-only wrapper: s = (a * b + c) mod L for 32-byte LE operands.                             */
/* --------------------------------------------------------------------------------------------- */
void _SSFEd25519ScMulAddForTest(uint8_t s[32], const uint8_t a[32], const uint8_t b[32],
                                const uint8_t c[32])
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(c != NULL);

    _SSFEd25519ScMulAdd(s, a, b, c);
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the 32-byte LE scalar s is less than L, else false.                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFEd25519ScIsLtL(const uint8_t s[32])
{
    int16_t i;

    SSF_REQUIRE(s != NULL);

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
static void _SSFEd25519StackScrub(void)
{
    volatile uint8_t scratch[SSF_ED25519_CONFIG_STACK_SCRUB_SIZE];
    size_t i;
    for (i = 0; i < sizeof(scratch); i++) scratch[i] = 0u;
    SSF_OPTIMIZER_BARRIER(scratch);
}
#else /* SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB */
/* Stack scrub disabled by configuration; call sites compile to nothing. */
#define _SSFEd25519StackScrub() do { } while (0)
#endif /* SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB */

/* --------------------------------------------------------------------------------------------- */
/* Feeds an arbitrary-size buffer to a SHA-512 context, looping in UINT32_MAX-sized chunks.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFEd25519SHA512UpdateSized(SSFSHA2_64Context_t *ctx, const uint8_t *buf, size_t len)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE((buf != NULL) || (len == 0u));

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

/* --------------------------------------------------------------------------------------------- */
/* Returns true if an Ed25519 key pair was generated from platform entropy, else false.          */
/* --------------------------------------------------------------------------------------------- */
bool SSFEd25519KeyGen(uint8_t seed[SSF_ED25519_SEED_SIZE], uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE])
{
    SSF_REQUIRE(seed != NULL);
    SSF_REQUIRE(pubKey != NULL);

    if (!SSFPortGetEntropy(seed, (uint16_t)SSF_ED25519_SEED_SIZE)) return false;
    SSFEd25519PubKeyFromSeed(seed, pubKey);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Derives the public key from a 32-byte seed.                                                   */
/* --------------------------------------------------------------------------------------------- */
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
    _SSFEd25519GeScalarMultBase(&A, a);
    _SSFEd25519GeEncode(pubKey, &A);

    /* Zeroize sensitive data */
    SSFCryptSecureZero(h, sizeof(h));
    SSFCryptSecureZero(a, sizeof(a));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if msg was signed into sig (verified after signing), else false.                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFEd25519Sign(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                    const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE], const uint8_t *msg,
                    size_t msgLen, uint8_t sig[SSF_ED25519_SIG_SIZE])
{
    uint8_t h[64];
    uint8_t r_hash[64];
    uint8_t hram[64];
    uint8_t a[32];
    uint8_t nonce[32];
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
    SSFSHA512Update(&ctx, &h[32], 32); /* prefix = upper 32 bytes of SHA-512(seed) */
    _SSFEd25519SHA512UpdateSized(&ctx, msg, msgLen);
    SSFSHA512End(&ctx, r_hash, 64);
    _SSFEd25519ScReduce(r_hash);
    memcpy(nonce, r_hash, 32);

    /* R = [r]B */
    _SSFEd25519GeScalarMultBase(&R, nonce);
    _SSFEd25519GeEncode(sig, &R); /* first 32 bytes of sig = encoded R */

    /* S = (r + SHA-512(R || pubKey || msg) * a) mod L */
    SSFSHA512Begin(&ctx);
    SSFSHA512Update(&ctx, sig, 32); /* R */
    SSFSHA512Update(&ctx, pubKey, 32); /* A */
    _SSFEd25519SHA512UpdateSized(&ctx, msg, msgLen);
    SSFSHA512End(&ctx, hram, 64);
    _SSFEd25519ScReduce(hram);

    _SSFEd25519ScMulAdd(&sig[32], hram, a, nonce); /* S = h*a + r mod L */

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
        _SSFEd25519StackScrub();
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
    _SSFEd25519StackScrub();

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sig is a valid signature of msg under pubKey, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFEd25519Verify(const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE], const uint8_t *msg,
                      size_t msgLen, const uint8_t sig[SSF_ED25519_SIG_SIZE])
{
    _ge_t A;
    _ge_t negA;
    _ge_t check;

    uint8_t hram[64];
    SSFSHA2_64Context_t ctx;
    uint8_t rcheck[32];

    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE((msg != NULL) || (msgLen == 0u));
    SSF_REQUIRE(sig != NULL);

    /* Check S < L */
    if (!_SSFEd25519ScIsLtL(&sig[32])) return false;

    /* Decode public key */
    if (!_SSFEd25519GeDecode(&A, pubKey)) return false;

    /* Reject low-order pubkeys ([8]A = identity -> trivial forgery for any message). */
    if (_SSFEd25519GeIsLowOrder(&A)) return false;

    /* Negate A: -A has coordinates (-X, Y, Z, -T) */
    _SSFEd25519FeNeg(&negA.X, &A.X);
    SSFFE25519Copy(&negA.Y, &A.Y);
    SSFFE25519Copy(&negA.Z, &A.Z);
    _SSFEd25519FeNeg(&negA.T, &A.T);

    /* h = SHA-512(R || A || msg) mod L */
    SSFSHA512Begin(&ctx);
    SSFSHA512Update(&ctx, sig, 32); /* R (first 32 bytes of sig) */
    SSFSHA512Update(&ctx, pubKey, 32); /* A */
    _SSFEd25519SHA512UpdateSized(&ctx, msg, msgLen);
    SSFSHA512End(&ctx, hram, 64);
    _SSFEd25519ScReduce(hram);

    /* check = [S]B + [h](-A) = [S]B - [h]A */
    _SSFEd25519GeDoubleScalarMult(&check, hram, &negA, &sig[32]);

    _SSFEd25519GeEncode(rcheck, &check);

    /* Compare the recomputed R against the signature in constant time. */
    return SSFCryptCTMemEq(rcheck, sig, 32);
}

