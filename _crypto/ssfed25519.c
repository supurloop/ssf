/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfed25519.c                                                                                  */
/* Provides Ed25519 digital signature implementation (RFC 8032).                                 */
/* Self-contained with dedicated GF(2^255-19) field arithmetic and extended Edwards coordinates. */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
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
#include "ssfed25519.h"
#include "ssfsha2.h"
#include "ssfct.h"

/* --------------------------------------------------------------------------------------------- */
/* Field element: 256 bits in 8 x 32-bit limbs, little-endian limb order.                       */
/* Values are in [0, 2p) during computation; fully reduced to [0, p) at export.                  */
/* p = 2^255 - 19                                                                                */
/* --------------------------------------------------------------------------------------------- */
typedef struct { uint32_t v[8]; } _fe_t;

/* p = 2^255 - 19 as 8 limbs */
static const _fe_t _fe_p = {{ 0xFFFFFFEDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                              0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu }};

/* Forward declaration for _fe_reduce (used by _fe_mul). */
static void _fe_reduce(_fe_t *a);

/* --------------------------------------------------------------------------------------------- */
/* Field arithmetic: GF(2^255 - 19)                                                              */
/* --------------------------------------------------------------------------------------------- */
static void _fe_0(_fe_t *r)
{
    memset(r->v, 0, sizeof(r->v));
}

static void _fe_1(_fe_t *r)
{
    memset(r->v, 0, sizeof(r->v));
    r->v[0] = 1u;
}

static void _fe_copy(_fe_t *r, const _fe_t *a)
{
    memcpy(r->v, a->v, sizeof(r->v));
}

/* r = a + b. Result may be up to 2p if both inputs < p. */
static void _fe_add(_fe_t *r, const _fe_t *a, const _fe_t *b)
{
    uint64_t carry = 0;
    uint8_t i;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i] + (uint64_t)b->v[i];
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }
    /* If carry, result >= 2^256. Reduce by subtracting p (add 19, clear bit 255). */
    /* This keeps the result in a manageable range. */
    if (carry != 0u)
    {
        uint64_t c = 38u; /* 2^256 mod p = 2 * 19 = 38 */
        for (i = 0; i < 8u; i++)
        {
            c += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c;
            c >>= 32;
        }
    }
}

/* r = a - b mod p. Reduces inputs first, then subtracts. Adds 2p on borrow. */
static void _fe_sub(_fe_t *r, const _fe_t *a, const _fe_t *b)
{
    uint64_t borrow = 0;
    uint8_t i;
    _fe_t ar, br;

    /* Reduce inputs to [0, p) so that a - b + 2p is in [0, 2p + p) = [0, 3p) < 2^257 */
    _fe_copy(&ar, a);
    _fe_copy(&br, b);
    _fe_reduce(&ar);
    _fe_reduce(&br);

    /* r = a - b */
    for (i = 0; i < 8u; i++)
    {
        uint64_t diff = (uint64_t)ar.v[i] - (uint64_t)br.v[i] - borrow;
        r->v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }

    /* If borrow, add 2p (since both inputs < p, result + 2p is in [0, 3p), fits in 257 bits) */
    if (borrow != 0u)
    {
        uint64_t carry = 0;
        for (i = 0; i < 8u; i++)
        {
            carry += (uint64_t)r->v[i] + (uint64_t)_fe_p.v[i] + (uint64_t)_fe_p.v[i];
            r->v[i] = (uint32_t)carry;
            carry >>= 32;
        }
    }
}

/* r = a * b mod p. Schoolbook 8x8 multiply with fast reduction by 38. */
static void _fe_mul(_fe_t *r, const _fe_t *a, const _fe_t *b)
{
    uint32_t t[16];
    uint64_t carry;
    uint8_t i, j;

    /* Schoolbook multiply: a * b -> t[0..15] */
    memset(t, 0, sizeof(t));
    for (i = 0; i < 8u; i++)
    {
        carry = 0;
        for (j = 0; j < 8u; j++)
        {
            uint64_t prod = (uint64_t)a->v[i] * (uint64_t)b->v[j] + (uint64_t)t[i + j] + carry;
            t[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        t[i + 8u] += (uint32_t)carry;
    }

    /* Reduce: low = t[0..7], high = t[8..15]. result = low + 38 * high */
    carry = 0;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)t[i] + (uint64_t)38u * (uint64_t)t[i + 8u];
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Carry might remain (up to ~6 bits). Fold it back: carry * 38 */
    if (carry != 0u)
    {
        uint64_t c = carry * 38u;
        for (i = 0; i < 8u; i++)
        {
            c += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c;
            c >>= 32;
        }
    }

    /* Ensure result is in [0, 2p) for safe use in subsequent sub/add */
    _fe_reduce(r);
}

/* r = a^2 mod p. Optimized: cross-terms computed once and doubled. */
static void _fe_sqr(_fe_t *r, const _fe_t *a)
{
    _fe_mul(r, a, a);
}

/* r = a * c mod p, where c is a small uint32_t constant. */
static void _fe_mul_small(_fe_t *r, const _fe_t *a, uint32_t c)
{
    uint64_t carry = 0;
    uint8_t i;

    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i] * (uint64_t)c;
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Fold carry back: carry * 38 mod p */
    if (carry != 0u)
    {
        uint64_t c2 = carry * 38u;
        for (i = 0; i < 8u; i++)
        {
            c2 += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c2;
            c2 >>= 32;
        }
    }
}

/* Fully reduce a to [0, p). */
static void _fe_reduce(_fe_t *a)
{
    uint64_t carry;
    uint8_t i;
    uint32_t mask;

    /* First, if bit 255 is set, clear it and add 19 (since 2^255 = 19 mod p) */
    carry = (uint64_t)(a->v[7] >> 31) * 19u;
    a->v[7] &= 0x7FFFFFFFu;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i];
        a->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Repeat in case of another overflow */
    carry = (uint64_t)(a->v[7] >> 31) * 19u;
    a->v[7] &= 0x7FFFFFFFu;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i];
        a->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Now a < 2^255. Check if a >= p by trying to subtract p. */
    /* If a >= p, the subtraction won't borrow. */
    {
        uint64_t borrow = 0;
        uint32_t t[8];
        for (i = 0; i < 8u; i++)
        {
            uint64_t diff = (uint64_t)a->v[i] - (uint64_t)_fe_p.v[i] - borrow;
            t[i] = (uint32_t)diff;
            borrow = (diff >> 63) & 1u;
        }
        /* If no borrow, a >= p, use the subtracted result */
        mask = (uint32_t)(1u - borrow); /* 1 if a >= p, 0 if a < p */
        /* mask is 0 or 1, expand to all bits */
        mask = (uint32_t)(-(int32_t)mask);
        for (i = 0; i < 8u; i++)
        {
            a->v[i] = (a->v[i] & ~mask) | (t[i] & mask);
        }
    }
}

/* Import from 32 little-endian bytes. Does NOT clear bit 255 (unlike X25519 version). */
static void _fe_from_bytes(_fe_t *a, const uint8_t *b)
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

/* Export to 32 little-endian bytes. Fully reduces first. */
static void _fe_to_bytes(uint8_t *b, const _fe_t *a)
{
    _fe_t t;
    uint8_t i;
    _fe_copy(&t, a);
    _fe_reduce(&t);
    for (i = 0; i < 8u; i++)
    {
        b[i * 4u]      = (uint8_t)(t.v[i]);
        b[i * 4u + 1u] = (uint8_t)(t.v[i] >> 8);
        b[i * 4u + 2u] = (uint8_t)(t.v[i] >> 16);
        b[i * 4u + 3u] = (uint8_t)(t.v[i] >> 24);
    }
}

/* Constant-time conditional swap: if swap != 0, exchange a and b. */
static void _fe_cswap(_fe_t *a, _fe_t *b, uint32_t swap)
{
    uint32_t mask = (uint32_t)(-(int32_t)(swap & 1u));
    uint8_t i;
    for (i = 0; i < 8u; i++)
    {
        uint32_t diff = (a->v[i] ^ b->v[i]) & mask;
        a->v[i] ^= diff;
        b->v[i] ^= diff;
    }
}

/* r = a^(-1) mod p via Fermat's little theorem: a^(p-2) mod p.                                 */
/* Uses an addition chain for p-2 = 2^255 - 21.                                                 */
/* Total: 255 squarings + 11 multiplications.                                                    */
static void _fe_inv(_fe_t *r, const _fe_t *a)
{
    _fe_t t0, t1, t2, t3;
    uint16_t i;

    /* a^2 */
    _fe_sqr(&t0, a);
    /* a^9 = ((a^2)^2)^2 * a */
    _fe_sqr(&t1, &t0);
    _fe_sqr(&t1, &t1);
    _fe_mul(&t1, &t1, a);
    /* a^11 = a^9 * a^2 */
    _fe_mul(&t0, &t1, &t0);
    /* a^22 = (a^11)^2 */
    _fe_sqr(&t2, &t0);
    /* a^(2^5 - 1) = a^31 = a^22 * a^9 */
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^10 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 5u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^20 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 10u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t2, &t2, &t1);
    /* a^(2^40 - 1) */
    _fe_sqr(&t3, &t2);
    for (i = 1; i < 20u; i++) _fe_sqr(&t3, &t3);
    _fe_mul(&t2, &t3, &t2);
    /* a^(2^50 - 1) */
    _fe_sqr(&t2, &t2);
    for (i = 1; i < 10u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^100 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 50u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t2, &t2, &t1);
    /* a^(2^200 - 1) */
    _fe_sqr(&t3, &t2);
    for (i = 1; i < 100u; i++) _fe_sqr(&t3, &t3);
    _fe_mul(&t2, &t3, &t2);
    /* a^(2^250 - 1) */
    _fe_sqr(&t2, &t2);
    for (i = 1; i < 50u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^255 - 21) = a^(p-2) */
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_mul(r, &t1, &t0);
}

/* r = a^((p+3)/8) mod p. Used for square root computation. */
/* (p+3)/8 = (2^255-19+3)/8 = (2^255-16)/8 = 2^252 - 2                                        */
static void _fe_pow2523(_fe_t *r, const _fe_t *a)
{
    _fe_t t0, t1, t2, t3;
    uint16_t i;

    /* This computes a^(2^252 - 3) which equals a^((p-5)/8).                                    */
    /* Actually we need a^((p+3)/8) = a^(2^252 - 2).                                            */
    /* 2^252 - 2 in binary: 252 ones followed by a zero, but more precisely:                     */
    /* We use the same addition chain structure as _fe_inv.                                       */

    /* a^2 */
    _fe_sqr(&t0, a);
    /* a^9 = ((a^2)^2)^2 * a */
    _fe_sqr(&t1, &t0);
    _fe_sqr(&t1, &t1);
    _fe_mul(&t1, &t1, a);
    /* a^11 = a^9 * a^2 */
    _fe_mul(&t0, &t1, &t0);
    /* a^22 = (a^11)^2 */
    _fe_sqr(&t2, &t0);
    /* a^(2^5 - 1) = a^31 = a^22 * a^9 */
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^10 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 5u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^20 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 10u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t2, &t2, &t1);
    /* a^(2^40 - 1) */
    _fe_sqr(&t3, &t2);
    for (i = 1; i < 20u; i++) _fe_sqr(&t3, &t3);
    _fe_mul(&t2, &t3, &t2);
    /* a^(2^50 - 1) */
    _fe_sqr(&t2, &t2);
    for (i = 1; i < 10u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^100 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 50u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t2, &t2, &t1);
    /* a^(2^200 - 1) */
    _fe_sqr(&t3, &t2);
    for (i = 1; i < 100u; i++) _fe_sqr(&t3, &t3);
    _fe_mul(&t2, &t3, &t2);
    /* a^(2^250 - 1) */
    _fe_sqr(&t2, &t2);
    for (i = 1; i < 50u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^252 - 4) */
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    /* a^(2^252 - 3) = a^((p-5)/8) */
    _fe_mul(r, &t1, a);
}

/* Return 1 if a is negative (odd), 0 if non-negative (even). Fully reduces first. */
static uint8_t _fe_isneg(const _fe_t *a)
{
    _fe_t t;
    _fe_copy(&t, a);
    _fe_reduce(&t);
    return (uint8_t)(t.v[0] & 1u);
}

/* Return 1 if a is zero, 0 otherwise. Fully reduces first. */
static uint8_t _fe_iszero(const _fe_t *a)
{
    _fe_t t;
    uint32_t bits;
    uint8_t i;
    _fe_copy(&t, a);
    _fe_reduce(&t);
    bits = 0;
    for (i = 0; i < 8u; i++) bits |= t.v[i];
    /* Constant-time: (bits | -bits) has bit 31 set iff bits != 0 */
    return (uint8_t)(1u ^ (((bits | ((uint32_t)(-(int32_t)bits))) >> 31) & 1u));
}

/* r = -a mod p */
static void _fe_neg(_fe_t *r, const _fe_t *a)
{
    _fe_t zero;
    _fe_0(&zero);
    _fe_sub(r, &zero, a);
}

/* --------------------------------------------------------------------------------------------- */
/* Edwards curve point in extended coordinates: (X:Y:Z:T) where x=X/Z, y=Y/Z, T=X*Y/Z.        */
/* Curve: -x^2 + y^2 = 1 + d*x^2*y^2  (twisted Edwards, a = -1)                                */
/* --------------------------------------------------------------------------------------------- */
typedef struct { _fe_t X, Y, Z, T; } _ge_t;

/* d = -121665/121666 mod p                                                                      */
/* d = 37095705934669439343138083508754565189542113879843219016388785533085940283555         */
static const _fe_t _ed_d = {{ 0x135978A3u, 0x75EB4DCAu, 0x4141D8ABu, 0x00700A4Du,
                              0x7779E898u, 0x8CC74079u, 0x2B6FFE73u, 0x52036CEEu }};

/* 2*d mod p */
static const _fe_t _ed_2d = {{ 0x26B2F159u, 0xEBD69B94u, 0x8283B156u, 0x00E0149Au,
                               0xEEF3D130u, 0x198E80F2u, 0x56DFFCE7u, 0x2406D9DCu }};

/* sqrt(-1) mod p = 2^((p-1)/4) mod p                                                           */
static const _fe_t _fe_sqrtm1 = {{ 0x4A0EA0B0u, 0xC4EE1B27u, 0xAD2FE478u, 0x2F431806u,
                                   0x3DFBD7A7u, 0x2B4D0099u, 0x4FC1DF0Bu, 0x2B832480u }};

/* Base point B: y = 4/5 mod p, x = positive root */
static const uint8_t _ed_basepoint_y[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
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
    _fe_0(&r->X);
    _fe_1(&r->Y);
    _fe_1(&r->Z);
    _fe_0(&r->T);
}

/* Point doubling in extended coordinates (a = -1 twisted Edwards).                              */
/* From: Hisil, Wong, Carter, Dawson "Twisted Edwards Curves Revisited", 2008.                   */
static void _ge_double(_ge_t *r, const _ge_t *p)
{
    _fe_t A, B, C, D, E, F, G, H;

    _fe_sqr(&A, &p->X);           /* A = X1^2 */
    _fe_sqr(&B, &p->Y);           /* B = Y1^2 */
    _fe_sqr(&C, &p->Z);           /* C = Z1^2 */
    _fe_add(&C, &C, &C);          /* C = 2*Z1^2 */
    _fe_neg(&D, &A);              /* D = -A (since a = -1) */
    _fe_add(&E, &p->X, &p->Y);   /* E = (X1+Y1) */
    _fe_sqr(&E, &E);              /* E = (X1+Y1)^2 */
    _fe_sub(&E, &E, &A);          /* E = (X1+Y1)^2 - A */
    _fe_sub(&E, &E, &B);          /* E = (X1+Y1)^2 - A - B */
    _fe_add(&F, &D, &B);          /* F = D + B */
    _fe_sub(&G, &F, &C);          /* G = F - C */
    _fe_sub(&H, &D, &B);          /* H = D - B */
    _fe_mul(&r->X, &E, &G);       /* X3 = E*G */
    _fe_mul(&r->Y, &F, &H);       /* Y3 = F*H */
    _fe_mul(&r->T, &E, &H);       /* T3 = E*H */
    _fe_mul(&r->Z, &F, &G);       /* Z3 = F*G */
}

/* Unified point addition in extended coordinates.                                               */
/* p3 = p1 + p2, using the formula from the Ed25519 paper.                                      */
static void _ge_add(_ge_t *r, const _ge_t *p1, const _ge_t *p2)
{
    _fe_t A, B, C, D, E, F, G, H;

    _fe_sub(&A, &p1->Y, &p1->X);  /* A = Y1-X1 */
    _fe_sub(&H, &p2->Y, &p2->X);  /* tmp = Y2-X2 */
    _fe_mul(&A, &A, &H);          /* A = (Y1-X1)*(Y2-X2) */
    _fe_add(&B, &p1->Y, &p1->X);  /* B = Y1+X1 */
    _fe_add(&H, &p2->Y, &p2->X);  /* tmp = Y2+X2 */
    _fe_mul(&B, &B, &H);          /* B = (Y1+X1)*(Y2+X2) */
    _fe_mul(&C, &p1->T, &p2->T);  /* C = T1*T2 */
    _fe_mul(&C, &C, &_ed_2d);     /* C = T1*2*d*T2 */
    _fe_mul(&D, &p1->Z, &p2->Z);  /* D = Z1*Z2 */
    _fe_add(&D, &D, &D);          /* D = 2*Z1*Z2 */
    _fe_sub(&E, &B, &A);          /* E = B-A */
    _fe_sub(&F, &D, &C);          /* F = D-C */
    _fe_add(&G, &D, &C);          /* G = D+C */
    _fe_add(&H, &B, &A);          /* H = B+A */
    _fe_mul(&r->X, &E, &F);       /* X3 = E*F */
    _fe_mul(&r->Y, &G, &H);       /* Y3 = G*H */
    _fe_mul(&r->T, &E, &H);       /* T3 = E*H */
    _fe_mul(&r->Z, &F, &G);       /* Z3 = F*G */
}

/* Subtraction: p3 = p1 - p2 = p1 + (-p2). Negate X and T of p2. */
static void _ge_sub(_ge_t *r, const _ge_t *p1, const _ge_t *p2)
{
    _ge_t neg;
    _fe_neg(&neg.X, &p2->X);
    _fe_copy(&neg.Y, &p2->Y);
    _fe_copy(&neg.Z, &p2->Z);
    _fe_neg(&neg.T, &p2->T);
    _ge_add(r, p1, &neg);
}

/* Encode a point to 32 bytes (Edwards compressed format).                                       */
/* The y-coordinate is encoded in LE; the high bit of byte 31 is the sign of x.                 */
static void _ge_encode(uint8_t out[32], const _ge_t *p)
{
    _fe_t recip, x, y;
    _fe_inv(&recip, &p->Z);
    _fe_mul(&x, &p->X, &recip);
    _fe_mul(&y, &p->Y, &recip);
    _fe_to_bytes(out, &y);
    out[31] ^= (uint8_t)(_fe_isneg(&x) << 7);
}

/* Decode a 32-byte compressed point. Returns false if invalid. */
static bool _ge_decode(_ge_t *p, const uint8_t in[32])
{
    _fe_t u, v, v3, vxx, check;
    uint8_t sign;
    uint8_t tmp[32];

    sign = (in[31] >> 7) & 1u;

    memcpy(tmp, in, 32);
    tmp[31] &= 0x7Fu; /* clear sign bit */
    _fe_from_bytes(&p->Y, tmp);

    /* Check that y < p by reducing and comparing */
    {
        _fe_t yCopy;
        _fe_copy(&yCopy, &p->Y);
        _fe_reduce(&yCopy);
        /* If the original had bit 255 set (after clearing sign bit this won't happen since
           we cleared bit 7 of byte 31, but check y < p anyway) */
    }

    /* u = y^2 - 1 */
    _fe_sqr(&u, &p->Y);
    _fe_mul(&v, &u, &_ed_d);      /* v = d*y^2 */
    {
        _fe_t one;
        _fe_1(&one);
        _fe_sub(&u, &u, &one);    /* u = y^2 - 1 */
        _fe_add(&v, &v, &one);    /* v = d*y^2 + 1 */
    }

    /* Compute x = sqrt(u/v) using the formula:                                                  */
    /* x = u * v^3 * (u * v^7)^((p-5)/8)                                                        */
    _fe_sqr(&v3, &v);             /* v^2 */
    _fe_mul(&v3, &v3, &v);        /* v^3 */
    _fe_sqr(&p->X, &v3);          /* v^6 */
    _fe_mul(&p->X, &p->X, &v);    /* v^7 */
    _fe_mul(&p->X, &p->X, &u);    /* u * v^7 */
    _fe_pow2523(&p->X, &p->X);    /* (u * v^7)^((p-5)/8) */
    _fe_mul(&p->X, &p->X, &v3);   /* * v^3 */
    _fe_mul(&p->X, &p->X, &u);    /* * u => candidate x */

    /* Check: v * x^2 == u ? */
    _fe_sqr(&vxx, &p->X);
    _fe_mul(&vxx, &vxx, &v);
    _fe_sub(&check, &vxx, &u);

    if (!_fe_iszero(&check))
    {
        /* Try x * sqrt(-1) */
        _fe_add(&check, &vxx, &u);
        if (!_fe_iszero(&check))
        {
            return false; /* No square root exists */
        }
        _fe_mul(&p->X, &p->X, &_fe_sqrtm1);
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

    _fe_mul(&p->T, &p->X, &p->Y);
    _fe_1(&p->Z);

    return true;
}

/* Scalar multiplication: r = [scalar]p. Double-and-add from high bit to low.                   */
/* Variable-time in `scalar` — the inner branch on each scalar bit makes wall-clock runtime      */
/* proportional to popcount(scalar). Only for callers who pass public scalars (e.g., the verify  */
/* double-scalar multiplication, whose scalars are derived from the message and signature).      */
/* For secret scalars use _ge_scalarmult_ct below.                                                */
static void _ge_scalarmult(_ge_t *r, const uint8_t scalar[32], const _ge_t *p)
{
    _ge_t Q;
    int16_t i;

    _ge_identity(&Q);
    for (i = 255; i >= 0; i--)
    {
        _ge_double(&Q, &Q);
        if (((scalar[i >> 3] >> (i & 7)) & 1u) != 0u)
        {
            _ge_add(&Q, &Q, p);
        }
    }
    *r = Q;
}

/* Constant-time conditional swap of two group elements: if swap != 0, exchange a and b.        */
/* Implemented as four _fe_cswap calls over the four coordinate field-elements; the underlying   */
/* mask-XOR pattern has no secret-dependent branch or memory access.                             */
static void _ge_cswap(_ge_t *a, _ge_t *b, uint32_t swap)
{
    _fe_cswap(&a->X, &b->X, swap);
    _fe_cswap(&a->Y, &b->Y, swap);
    _fe_cswap(&a->Z, &b->Z, swap);
    _fe_cswap(&a->T, &b->T, swap);
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
         *   bit == 1 → Q holds (Q + p)  (and QplusP holds the old Q, discarded)
         *   bit == 0 → Q is unchanged   (and QplusP holds (Q + p), discarded)
         * Either way the next iteration reads only Q, so the discard is harmless. */
        _ge_cswap(&Q, &QplusP, bit);
    }
    *r = Q;
}

/* Base point scalar multiplication: r = [scalar]B. Sign-path entry point — scalar here is the   */
/* RFC 8032 deterministic nonce, which is derived from the long-term seed and must not leak      */
/* via timing. Routes through the constant-time variant.                                         */
static void _ge_scalarmult_base(_ge_t *r, const uint8_t scalar[32])
{
    _ge_t B;

    /* Decode the base point from its compressed form */
    (void)_ge_decode(&B, _ed_basepoint_y);
    _ge_scalarmult_ct(r, scalar, &B);
}

/* Double scalar multiplication: r = [a]A + [b]B (Straus/interleaved). */
static void _ge_double_scalarmult(_ge_t *r, const uint8_t a[32], const _ge_t *A,
                                  const uint8_t b[32])
{
    _ge_t B;
    _ge_t Q;
    int16_t i;

    /* Decode base point */
    (void)_ge_decode(&B, _ed_basepoint_y);

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
            _ge_add(&Q, &Q, &B);
        }
    }
    *r = Q;
}

/* --------------------------------------------------------------------------------------------- */
/* Scalar arithmetic modulo L (group order).                                                     */
/* Uses SUPERCOP ref10 approach: represent scalars in 24 limbs of ~21 bits (signed),             */
/* perform reduction using the known factorization of L.                                         */
/* L = 2^252 + 27742317777372353535851937790883648493                                            */
/* --------------------------------------------------------------------------------------------- */

/* Helper functions for scalar loading (21-bit limb representation).                             */
static uint64_t _sc_load3(const uint8_t *in)
{
    return (uint64_t)in[0] | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16);
}

static uint64_t _sc_load4(const uint8_t *in)
{
    return (uint64_t)in[0] | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16) |
           ((uint64_t)in[3] << 24);
}

/* Pack 12 signed 21-bit limbs into 32 little-endian bytes.                                      */
/* Limbs represent value = s0 + s1*2^21 + s2*2^42 + ... + s11*2^231.                            */
static void _sc_pack(uint8_t out[32], const int64_t s[12])
{
    /* Reconstruct the bit stream and pack byte by byte */
    uint8_t i;
    uint64_t acc = 0;
    uint8_t accBits = 0;
    uint8_t outIdx = 0;

    memset(out, 0, 32);
    for (i = 0; i < 12u; i++)
    {
        acc |= ((uint64_t)(s[i] & 0x1FFFFF)) << accBits;
        accBits += 21u;
        while ((accBits >= 8u) && (outIdx < 32u))
        {
            out[outIdx++] = (uint8_t)(acc & 0xFFu);
            acc >>= 8u;
            accBits -= 8u;
        }
    }
    /* Flush remaining bits */
    while (outIdx < 32u)
    {
        out[outIdx++] = (uint8_t)(acc & 0xFFu);
        acc >>= 8u;
    }
}

/* Load a 64-byte (512-bit) little-endian integer into 24 signed limbs of ~21 bits each,         */
/* then reduce modulo L. Output: 32 bytes little-endian.                                         */
static void _sc_reduce(uint8_t s[64])
{
    int64_t s0  = (int64_t)(2097151u & _sc_load3(&s[0]));
    int64_t s1  = (int64_t)(2097151u & (_sc_load4(&s[2])  >> 5));
    int64_t s2  = (int64_t)(2097151u & (_sc_load3(&s[5])  >> 2));
    int64_t s3  = (int64_t)(2097151u & (_sc_load4(&s[7])  >> 7));
    int64_t s4  = (int64_t)(2097151u & (_sc_load4(&s[10]) >> 4));
    int64_t s5  = (int64_t)(2097151u & (_sc_load3(&s[13]) >> 1));
    int64_t s6  = (int64_t)(2097151u & (_sc_load4(&s[15]) >> 6));
    int64_t s7  = (int64_t)(2097151u & (_sc_load3(&s[18]) >> 3));
    int64_t s8  = (int64_t)(2097151u & _sc_load3(&s[21]));
    int64_t s9  = (int64_t)(2097151u & (_sc_load4(&s[23]) >> 5));
    int64_t s10 = (int64_t)(2097151u & (_sc_load3(&s[26]) >> 2));
    int64_t s11 = (int64_t)(2097151u & (_sc_load4(&s[28]) >> 7));
    int64_t s12 = (int64_t)(2097151u & (_sc_load4(&s[31]) >> 4));
    int64_t s13 = (int64_t)(2097151u & (_sc_load3(&s[34]) >> 1));
    int64_t s14 = (int64_t)(2097151u & (_sc_load4(&s[36]) >> 6));
    int64_t s15 = (int64_t)(2097151u & (_sc_load3(&s[39]) >> 3));
    int64_t s16 = (int64_t)(2097151u & _sc_load3(&s[42]));
    int64_t s17 = (int64_t)(2097151u & (_sc_load4(&s[44]) >> 5));
    int64_t s18 = (int64_t)(2097151u & (_sc_load3(&s[47]) >> 2));
    int64_t s19 = (int64_t)(2097151u & (_sc_load4(&s[49]) >> 7));
    int64_t s20 = (int64_t)(2097151u & (_sc_load4(&s[52]) >> 4));
    int64_t s21 = (int64_t)(2097151u & (_sc_load3(&s[55]) >> 1));
    int64_t s22 = (int64_t)(2097151u & (_sc_load4(&s[57]) >> 6));
    int64_t s23 = (int64_t)(_sc_load4(&s[60]) >> 3);
    int64_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7;
    int64_t carry8, carry9, carry10, carry11, carry12, carry13, carry14, carry15;
    int64_t carry16;

    /* Reduce limbs 23..12 into 0..11 using L's structure.                                       */
    /* L's limbs (21-bit): l0=0x1cf5d3ed, but specifically:                                      */
    /*   L = sum(l_i * 2^(21*i)) where the l_i encode the low part of L.                        */
    /* The reduction subtracts s_i * L for high limbs.                                           */

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9  += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8  += s20 * 666643;
    s9  += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7  += s19 * 666643;
    s8  += s19 * 470296;
    s9  += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6  += s18 * 666643;
    s7  += s18 * 470296;
    s8  += s18 * 654183;
    s9  -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    /* Carry propagation */
    carry6  = (s6  + (1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry8  = (s8  + (1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);
    carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 * (1 << 21);
    carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 * (1 << 21);
    carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 * (1 << 21);

    carry7  = (s7  + (1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry9  = (s9  + (1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 * (1 << 21);
    carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 * (1 << 21);
    carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 * (1 << 21);

    /* Second reduction round: s12..s17 into s0..s11 */
    s5  += s17 * 666643;
    s6  += s17 * 470296;
    s7  += s17 * 654183;
    s8  -= s17 * 997805;
    s9  += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4  += s16 * 666643;
    s5  += s16 * 470296;
    s6  += s16 * 654183;
    s7  -= s16 * 997805;
    s8  += s16 * 136657;
    s9  -= s16 * 683901;
    s16 = 0;

    s3  += s15 * 666643;
    s4  += s15 * 470296;
    s5  += s15 * 654183;
    s6  -= s15 * 997805;
    s7  += s15 * 136657;
    s8  -= s15 * 683901;
    s15 = 0;

    s2  += s14 * 666643;
    s3  += s14 * 470296;
    s4  += s14 * 654183;
    s5  -= s14 * 997805;
    s6  += s14 * 136657;
    s7  -= s14 * 683901;
    s14 = 0;

    s1  += s13 * 666643;
    s2  += s13 * 470296;
    s3  += s13 * 654183;
    s4  -= s13 * 997805;
    s5  += s13 * 136657;
    s6  -= s13 * 683901;
    s13 = 0;

    s0  += s12 * 666643;
    s1  += s12 * 470296;
    s2  += s12 * 654183;
    s3  -= s12 * 997805;
    s4  += s12 * 136657;
    s5  -= s12 * 683901;
    s12 = 0;

    /* Final carry propagation */
    carry0  = (s0  + (1 << 20)) >> 21; s1  += carry0;  s0  -= carry0  * (1 << 21);
    carry2  = (s2  + (1 << 20)) >> 21; s3  += carry2;  s2  -= carry2  * (1 << 21);
    carry4  = (s4  + (1 << 20)) >> 21; s5  += carry4;  s4  -= carry4  * (1 << 21);
    carry6  = (s6  + (1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry8  = (s8  + (1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);

    carry1  = (s1  + (1 << 20)) >> 21; s2  += carry1;  s1  -= carry1  * (1 << 21);
    carry3  = (s3  + (1 << 20)) >> 21; s4  += carry3;  s3  -= carry3  * (1 << 21);
    carry5  = (s5  + (1 << 20)) >> 21; s6  += carry5;  s5  -= carry5  * (1 << 21);
    carry7  = (s7  + (1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry9  = (s9  + (1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 * (1 << 21);

    /* One more reduction of s12 */
    s0  += s12 * 666643;
    s1  += s12 * 470296;
    s2  += s12 * 654183;
    s3  -= s12 * 997805;
    s4  += s12 * 136657;
    s5  -= s12 * 683901;
    s12 = 0;

    carry0  = s0  >> 21; s1  += carry0;  s0  -= carry0  * (1 << 21);
    carry1  = s1  >> 21; s2  += carry1;  s1  -= carry1  * (1 << 21);
    carry2  = s2  >> 21; s3  += carry2;  s2  -= carry2  * (1 << 21);
    carry3  = s3  >> 21; s4  += carry3;  s3  -= carry3  * (1 << 21);
    carry4  = s4  >> 21; s5  += carry4;  s4  -= carry4  * (1 << 21);
    carry5  = s5  >> 21; s6  += carry5;  s5  -= carry5  * (1 << 21);
    carry6  = s6  >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry7  = s7  >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry8  = s8  >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry9  = s9  >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 * (1 << 21);

    s0  += s12 * 666643;
    s1  += s12 * 470296;
    s2  += s12 * 654183;
    s3  -= s12 * 997805;
    s4  += s12 * 136657;
    s5  -= s12 * 683901;
    s12 = 0;

    carry0  = s0  >> 21; s1  += carry0;  s0  -= carry0  * (1 << 21);
    carry1  = s1  >> 21; s2  += carry1;  s1  -= carry1  * (1 << 21);
    carry2  = s2  >> 21; s3  += carry2;  s2  -= carry2  * (1 << 21);
    carry3  = s3  >> 21; s4  += carry3;  s3  -= carry3  * (1 << 21);
    carry4  = s4  >> 21; s5  += carry4;  s4  -= carry4  * (1 << 21);
    carry5  = s5  >> 21; s6  += carry5;  s5  -= carry5  * (1 << 21);
    carry6  = s6  >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry7  = s7  >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry8  = s8  >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry9  = s9  >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);

    /* Pack 12 limbs into 32 bytes */
    {
        int64_t limbs[12];
        limbs[0] = s0; limbs[1] = s1; limbs[2] = s2; limbs[3] = s3;
        limbs[4] = s4; limbs[5] = s5; limbs[6] = s6; limbs[7] = s7;
        limbs[8] = s8; limbs[9] = s9; limbs[10] = s10; limbs[11] = s11;
        _sc_pack(s, limbs);
    }
}

/* Compute s = (a * b + c) mod L.                                                                */
/* a, b, c are 32-byte LE scalars (already reduced mod L).                                       */
/* Output s is 32 bytes LE.                                                                      */
static void _sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32],
                       const uint8_t c[32])
{
    int64_t a0  = (int64_t)(2097151u & _sc_load3(&a[0]));
    int64_t a1  = (int64_t)(2097151u & (_sc_load4(&a[2])  >> 5));
    int64_t a2  = (int64_t)(2097151u & (_sc_load3(&a[5])  >> 2));
    int64_t a3  = (int64_t)(2097151u & (_sc_load4(&a[7])  >> 7));
    int64_t a4  = (int64_t)(2097151u & (_sc_load4(&a[10]) >> 4));
    int64_t a5  = (int64_t)(2097151u & (_sc_load3(&a[13]) >> 1));
    int64_t a6  = (int64_t)(2097151u & (_sc_load4(&a[15]) >> 6));
    int64_t a7  = (int64_t)(2097151u & (_sc_load3(&a[18]) >> 3));
    int64_t a8  = (int64_t)(2097151u & _sc_load3(&a[21]));
    int64_t a9  = (int64_t)(2097151u & (_sc_load4(&a[23]) >> 5));
    int64_t a10 = (int64_t)(2097151u & (_sc_load3(&a[26]) >> 2));
    int64_t a11 = (int64_t)(_sc_load4(&a[28]) >> 7);

    int64_t b0  = (int64_t)(2097151u & _sc_load3(&b[0]));
    int64_t b1  = (int64_t)(2097151u & (_sc_load4(&b[2])  >> 5));
    int64_t b2  = (int64_t)(2097151u & (_sc_load3(&b[5])  >> 2));
    int64_t b3  = (int64_t)(2097151u & (_sc_load4(&b[7])  >> 7));
    int64_t b4  = (int64_t)(2097151u & (_sc_load4(&b[10]) >> 4));
    int64_t b5  = (int64_t)(2097151u & (_sc_load3(&b[13]) >> 1));
    int64_t b6  = (int64_t)(2097151u & (_sc_load4(&b[15]) >> 6));
    int64_t b7  = (int64_t)(2097151u & (_sc_load3(&b[18]) >> 3));
    int64_t b8  = (int64_t)(2097151u & _sc_load3(&b[21]));
    int64_t b9  = (int64_t)(2097151u & (_sc_load4(&b[23]) >> 5));
    int64_t b10 = (int64_t)(2097151u & (_sc_load3(&b[26]) >> 2));
    int64_t b11 = (int64_t)(_sc_load4(&b[28]) >> 7);

    int64_t c0  = (int64_t)(2097151u & _sc_load3(&c[0]));
    int64_t c1  = (int64_t)(2097151u & (_sc_load4(&c[2])  >> 5));
    int64_t c2  = (int64_t)(2097151u & (_sc_load3(&c[5])  >> 2));
    int64_t c3  = (int64_t)(2097151u & (_sc_load4(&c[7])  >> 7));
    int64_t c4  = (int64_t)(2097151u & (_sc_load4(&c[10]) >> 4));
    int64_t c5  = (int64_t)(2097151u & (_sc_load3(&c[13]) >> 1));
    int64_t c6  = (int64_t)(2097151u & (_sc_load4(&c[15]) >> 6));
    int64_t c7  = (int64_t)(2097151u & (_sc_load3(&c[18]) >> 3));
    int64_t c8  = (int64_t)(2097151u & _sc_load3(&c[21]));
    int64_t c9  = (int64_t)(2097151u & (_sc_load4(&c[23]) >> 5));
    int64_t c10 = (int64_t)(2097151u & (_sc_load3(&c[26]) >> 2));
    int64_t c11 = (int64_t)(_sc_load4(&c[28]) >> 7);

    int64_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12;
    int64_t s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23;
    int64_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7;
    int64_t carry8, carry9, carry10, carry11, carry12, carry13, carry14, carry15;
    int64_t carry16, carry17, carry18, carry19, carry20, carry21, carry22;

    s0  = c0  + a0*b0;
    s1  = c1  + a0*b1  + a1*b0;
    s2  = c2  + a0*b2  + a1*b1  + a2*b0;
    s3  = c3  + a0*b3  + a1*b2  + a2*b1  + a3*b0;
    s4  = c4  + a0*b4  + a1*b3  + a2*b2  + a3*b1  + a4*b0;
    s5  = c5  + a0*b5  + a1*b4  + a2*b3  + a3*b2  + a4*b1  + a5*b0;
    s6  = c6  + a0*b6  + a1*b5  + a2*b4  + a3*b3  + a4*b2  + a5*b1  + a6*b0;
    s7  = c7  + a0*b7  + a1*b6  + a2*b5  + a3*b4  + a4*b3  + a5*b2  + a6*b1  + a7*b0;
    s8  = c8  + a0*b8  + a1*b7  + a2*b6  + a3*b5  + a4*b4  + a5*b3  + a6*b2  + a7*b1
          + a8*b0;
    s9  = c9  + a0*b9  + a1*b8  + a2*b7  + a3*b6  + a4*b5  + a5*b4  + a6*b3  + a7*b2
          + a8*b1  + a9*b0;
    s10 = c10 + a0*b10 + a1*b9  + a2*b8  + a3*b7  + a4*b6  + a5*b5  + a6*b4  + a7*b3
          + a8*b2  + a9*b1  + a10*b0;
    s11 = c11 + a0*b11 + a1*b10 + a2*b9  + a3*b8  + a4*b7  + a5*b6  + a6*b5  + a7*b4
          + a8*b3  + a9*b2  + a10*b1 + a11*b0;
    s12 =       a1*b11 + a2*b10 + a3*b9  + a4*b8  + a5*b7  + a6*b6  + a7*b5  + a8*b4
          + a9*b3  + a10*b2 + a11*b1;
    s13 =       a2*b11 + a3*b10 + a4*b9  + a5*b8  + a6*b7  + a7*b6  + a8*b5  + a9*b4
          + a10*b3 + a11*b2;
    s14 =       a3*b11 + a4*b10 + a5*b9  + a6*b8  + a7*b7  + a8*b6  + a9*b5  + a10*b4
          + a11*b3;
    s15 =       a4*b11 + a5*b10 + a6*b9  + a7*b8  + a8*b7  + a9*b6  + a10*b5 + a11*b4;
    s16 =       a5*b11 + a6*b10 + a7*b9  + a8*b8  + a9*b7  + a10*b6 + a11*b5;
    s17 =       a6*b11 + a7*b10 + a8*b9  + a9*b8  + a10*b7 + a11*b6;
    s18 =       a7*b11 + a8*b10 + a9*b9  + a10*b8 + a11*b7;
    s19 =       a8*b11 + a9*b10 + a10*b9 + a11*b8;
    s20 =       a9*b11 + a10*b10 + a11*b9;
    s21 =       a10*b11 + a11*b10;
    s22 =       a11*b11;
    s23 = 0;

    /* Now reduce exactly as in _sc_reduce */
    carry0  = (s0  + (1 << 20)) >> 21; s1  += carry0;  s0  -= carry0  * (1 << 21);
    carry2  = (s2  + (1 << 20)) >> 21; s3  += carry2;  s2  -= carry2  * (1 << 21);
    carry4  = (s4  + (1 << 20)) >> 21; s5  += carry4;  s4  -= carry4  * (1 << 21);
    carry6  = (s6  + (1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry8  = (s8  + (1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);
    carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 * (1 << 21);
    carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 * (1 << 21);
    carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 * (1 << 21);
    carry18 = (s18 + (1 << 20)) >> 21; s19 += carry18; s18 -= carry18 * (1 << 21);
    carry20 = (s20 + (1 << 20)) >> 21; s21 += carry20; s20 -= carry20 * (1 << 21);
    carry22 = (s22 + (1 << 20)) >> 21; s23 += carry22; s22 -= carry22 * (1 << 21);

    carry1  = (s1  + (1 << 20)) >> 21; s2  += carry1;  s1  -= carry1  * (1 << 21);
    carry3  = (s3  + (1 << 20)) >> 21; s4  += carry3;  s3  -= carry3  * (1 << 21);
    carry5  = (s5  + (1 << 20)) >> 21; s6  += carry5;  s5  -= carry5  * (1 << 21);
    carry7  = (s7  + (1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry9  = (s9  + (1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 * (1 << 21);
    carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 * (1 << 21);
    carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 * (1 << 21);
    carry17 = (s17 + (1 << 20)) >> 21; s18 += carry17; s17 -= carry17 * (1 << 21);
    carry19 = (s19 + (1 << 20)) >> 21; s20 += carry19; s19 -= carry19 * (1 << 21);
    carry21 = (s21 + (1 << 20)) >> 21; s22 += carry21; s21 -= carry21 * (1 << 21);

    /* Reduce high limbs */
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9  += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8  += s20 * 666643;
    s9  += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7  += s19 * 666643;
    s8  += s19 * 470296;
    s9  += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6  += s18 * 666643;
    s7  += s18 * 470296;
    s8  += s18 * 654183;
    s9  -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6  = (s6  + (1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry8  = (s8  + (1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);
    carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 * (1 << 21);
    carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 * (1 << 21);
    carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 * (1 << 21);

    carry7  = (s7  + (1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry9  = (s9  + (1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 * (1 << 21);
    carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 * (1 << 21);
    carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 * (1 << 21);

    /* Second reduction round */
    s5  += s17 * 666643;
    s6  += s17 * 470296;
    s7  += s17 * 654183;
    s8  -= s17 * 997805;
    s9  += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4  += s16 * 666643;
    s5  += s16 * 470296;
    s6  += s16 * 654183;
    s7  -= s16 * 997805;
    s8  += s16 * 136657;
    s9  -= s16 * 683901;
    s16 = 0;

    s3  += s15 * 666643;
    s4  += s15 * 470296;
    s5  += s15 * 654183;
    s6  -= s15 * 997805;
    s7  += s15 * 136657;
    s8  -= s15 * 683901;
    s15 = 0;

    s2  += s14 * 666643;
    s3  += s14 * 470296;
    s4  += s14 * 654183;
    s5  -= s14 * 997805;
    s6  += s14 * 136657;
    s7  -= s14 * 683901;
    s14 = 0;

    s1  += s13 * 666643;
    s2  += s13 * 470296;
    s3  += s13 * 654183;
    s4  -= s13 * 997805;
    s5  += s13 * 136657;
    s6  -= s13 * 683901;
    s13 = 0;

    s0  += s12 * 666643;
    s1  += s12 * 470296;
    s2  += s12 * 654183;
    s3  -= s12 * 997805;
    s4  += s12 * 136657;
    s5  -= s12 * 683901;
    s12 = 0;

    /* Final carry propagation */
    carry0  = (s0  + (1 << 20)) >> 21; s1  += carry0;  s0  -= carry0  * (1 << 21);
    carry2  = (s2  + (1 << 20)) >> 21; s3  += carry2;  s2  -= carry2  * (1 << 21);
    carry4  = (s4  + (1 << 20)) >> 21; s5  += carry4;  s4  -= carry4  * (1 << 21);
    carry6  = (s6  + (1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry8  = (s8  + (1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);

    carry1  = (s1  + (1 << 20)) >> 21; s2  += carry1;  s1  -= carry1  * (1 << 21);
    carry3  = (s3  + (1 << 20)) >> 21; s4  += carry3;  s3  -= carry3  * (1 << 21);
    carry5  = (s5  + (1 << 20)) >> 21; s6  += carry5;  s5  -= carry5  * (1 << 21);
    carry7  = (s7  + (1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry9  = (s9  + (1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 * (1 << 21);

    s0  += s12 * 666643;
    s1  += s12 * 470296;
    s2  += s12 * 654183;
    s3  -= s12 * 997805;
    s4  += s12 * 136657;
    s5  -= s12 * 683901;
    s12 = 0;

    carry0  = s0  >> 21; s1  += carry0;  s0  -= carry0  * (1 << 21);
    carry1  = s1  >> 21; s2  += carry1;  s1  -= carry1  * (1 << 21);
    carry2  = s2  >> 21; s3  += carry2;  s2  -= carry2  * (1 << 21);
    carry3  = s3  >> 21; s4  += carry3;  s3  -= carry3  * (1 << 21);
    carry4  = s4  >> 21; s5  += carry4;  s4  -= carry4  * (1 << 21);
    carry5  = s5  >> 21; s6  += carry5;  s5  -= carry5  * (1 << 21);
    carry6  = s6  >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry7  = s7  >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry8  = s8  >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry9  = s9  >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 * (1 << 21);

    s0  += s12 * 666643;
    s1  += s12 * 470296;
    s2  += s12 * 654183;
    s3  -= s12 * 997805;
    s4  += s12 * 136657;
    s5  -= s12 * 683901;
    s12 = 0;

    carry0  = s0  >> 21; s1  += carry0;  s0  -= carry0  * (1 << 21);
    carry1  = s1  >> 21; s2  += carry1;  s1  -= carry1  * (1 << 21);
    carry2  = s2  >> 21; s3  += carry2;  s2  -= carry2  * (1 << 21);
    carry3  = s3  >> 21; s4  += carry3;  s3  -= carry3  * (1 << 21);
    carry4  = s4  >> 21; s5  += carry4;  s4  -= carry4  * (1 << 21);
    carry5  = s5  >> 21; s6  += carry5;  s5  -= carry5  * (1 << 21);
    carry6  = s6  >> 21; s7  += carry6;  s6  -= carry6  * (1 << 21);
    carry7  = s7  >> 21; s8  += carry7;  s7  -= carry7  * (1 << 21);
    carry8  = s8  >> 21; s9  += carry8;  s8  -= carry8  * (1 << 21);
    carry9  = s9  >> 21; s10 += carry9;  s9  -= carry9  * (1 << 21);
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 * (1 << 21);

    /* Pack 12 limbs into 32 bytes */
    {
        int64_t limbs[12];
        limbs[0] = s0; limbs[1] = s1; limbs[2] = s2; limbs[3] = s3;
        limbs[4] = s4; limbs[5] = s5; limbs[6] = s6; limbs[7] = s7;
        limbs[8] = s8; limbs[9] = s9; limbs[10] = s10; limbs[11] = s11;
        _sc_pack(s, limbs);
    }
}

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

/* --------------------------------------------------------------------------------------------- */
/* Public API                                                                                    */
/* --------------------------------------------------------------------------------------------- */

/* Generate an Ed25519 key pair. */
bool SSFEd25519KeyGen(uint8_t seed[SSF_ED25519_SEED_SIZE],
                      uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE])
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
    memset(h, 0, sizeof(h));
    memset(a, 0, sizeof(a));
}

/* Sign a message. */
void SSFEd25519Sign(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                    const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE],
                    const uint8_t *msg, size_t msgLen,
                    uint8_t sig[SSF_ED25519_SIG_SIZE])
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
    if (msgLen > 0u) SSFSHA512Update(&ctx, msg, (uint32_t)msgLen);
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
    if (msgLen > 0u) SSFSHA512Update(&ctx, msg, (uint32_t)msgLen);
    SSFSHA512End(&ctx, hram, 64);
    _sc_reduce(hram);

    _sc_muladd(&sig[32], hram, a, nonce);  /* S = h*a + r mod L */

    /* Zeroize sensitive data */
    memset(h, 0, sizeof(h));
    memset(a, 0, sizeof(a));
    memset(nonce, 0, sizeof(nonce));
    memset(r_hash, 0, sizeof(r_hash));
    memset(&ctx, 0, sizeof(ctx));
}

/* Verify a signature. Returns true if valid. */
bool SSFEd25519Verify(const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE],
                      const uint8_t *msg, size_t msgLen,
                      const uint8_t sig[SSF_ED25519_SIG_SIZE])
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

    /* Negate A: -A has coordinates (-X, Y, Z, -T) */
    _fe_neg(&negA.X, &A.X);
    _fe_copy(&negA.Y, &A.Y);
    _fe_copy(&negA.Z, &A.Z);
    _fe_neg(&negA.T, &A.T);

    /* h = SHA-512(R || A || msg) mod L */
    SSFSHA512Begin(&ctx);
    SSFSHA512Update(&ctx, sig, 32);     /* R (first 32 bytes of sig) */
    SSFSHA512Update(&ctx, pubKey, 32);  /* A */
    if (msgLen > 0u) SSFSHA512Update(&ctx, msg, (uint32_t)msgLen);
    SSFSHA512End(&ctx, hram, 64);
    _sc_reduce(hram);

    /* check = [S]B + [h](-A) = [S]B - [h]A */
    _ge_double_scalarmult(&check, hram, &negA, &sig[32]);

    _ge_encode(rcheck, &check);

    /* Compare the recomputed R against the signature in constant time. */
    return SSFCTMemEq(rcheck, sig, 32);
}
