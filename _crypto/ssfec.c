/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfec.c                                                                                       */
/* Provides elliptic curve point arithmetic over NIST prime curves P-256 and P-384.              */
/*                                                                                               */
/* FIPS 186-4: Digital Signature Standard (DSS)                                                  */
/* NIST SP 800-186: Recommendations for Discrete Logarithm-based Cryptography                   */
/* SEC 1 v2: Elliptic Curve Cryptography                                                        */
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
#include "ssfassert.h"
#include "ssfec.h"

/* --------------------------------------------------------------------------------------------- */
/* NIST curve parameters (FIPS 186-4, little-endian limb order)                                  */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* P-256 / secp256r1 parameters                                                                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
/* p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF */
static SSFBNLimb_t _ssfECP256_p[8] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
    0x00000000ul, 0x00000000ul, 0x00000001ul, 0xFFFFFFFFul
};
/* a = p - 3 */
static SSFBNLimb_t _ssfECP256_a[8] = {
    0xFFFFFFFCul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
    0x00000000ul, 0x00000000ul, 0x00000001ul, 0xFFFFFFFFul
};
/* b = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B */
static SSFBNLimb_t _ssfECP256_b[8] = {
    0x27D2604Bul, 0x3BCE3C3Eul, 0xCC53B0F6ul, 0x651D06B0ul,
    0x769886BCul, 0xB3EBBD55ul, 0xAA3A93E7ul, 0x5AC635D8ul
};
/* Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 */
static SSFBNLimb_t _ssfECP256_gx[8] = {
    0xD898C296ul, 0xF4A13945ul, 0x2DEB33A0ul, 0x77037D81ul,
    0x63A440F2ul, 0xF8BCE6E5ul, 0xE12C4247ul, 0x6B17D1F2ul
};
/* Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 */
static SSFBNLimb_t _ssfECP256_gy[8] = {
    0x37BF51F5ul, 0xCBB64068ul, 0x6B315ECEul, 0x2BCE3357ul,
    0x7C0F9E16ul, 0x8EE7EB4Aul, 0xFE1A7F9Bul, 0x4FE342E2ul
};
/* n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 */
static SSFBNLimb_t _ssfECP256_n[8] = {
    0xFC632551ul, 0xF3B9CAC2ul, 0xA7179E84ul, 0xBCE6FAADul,
    0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul, 0xFFFFFFFFul
};
static const SSFECCurveParams_t _ssfECP256 =
{
    { _ssfECP256_p,  8, 8 },
    { _ssfECP256_a,  8, 8 },
    { _ssfECP256_b,  8, 8 },
    { _ssfECP256_gx, 8, 8 },
    { _ssfECP256_gy, 8, 8 },
    { _ssfECP256_n,  8, 8 },
    8,   /* limbs */
    32   /* bytes */
};
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

/* --------------------------------------------------------------------------------------------- */
/* P-384 / secp384r1 parameters                                                                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
/* p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE */
/*     FFFFFFFF0000000000000000FFFFFFFF                                   */
static SSFBNLimb_t _ssfECP384_p[12] = {
    0xFFFFFFFFul, 0x00000000ul, 0x00000000ul, 0xFFFFFFFFul,
    0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul
};
/* a = p - 3 */
static SSFBNLimb_t _ssfECP384_a[12] = {
    0xFFFFFFFCul, 0x00000000ul, 0x00000000ul, 0xFFFFFFFFul,
    0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul
};
/* b = B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A */
/*     C656398D8A2ED19D2A85C8EDD3EC2AEF                                   */
static SSFBNLimb_t _ssfECP384_b[12] = {
    0xD3EC2AEFul, 0x2A85C8EDul, 0x8A2ED19Dul, 0xC656398Dul,
    0x5013875Aul, 0x0314088Ful, 0xFE814112ul, 0x181D9C6Eul,
    0xE3F82D19ul, 0x988E056Bul, 0xE23EE7E4ul, 0xB3312FA7ul
};
/* Gx = AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38 */
/*      5502F25DBF55296C3A545E3872760AB7                                   */
static SSFBNLimb_t _ssfECP384_gx[12] = {
    0x72760AB7ul, 0x3A545E38ul, 0xBF55296Cul, 0x5502F25Dul,
    0x82542A38ul, 0x59F741E0ul, 0x8BA79B98ul, 0x6E1D3B62ul,
    0xF320AD74ul, 0x8EB1C71Eul, 0xBE8B0537ul, 0xAA87CA22ul
};
/* Gy = 3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0 */
/*      0A60B1CE1D7E819D7A431D7C90EA0E5F                                   */
static SSFBNLimb_t _ssfECP384_gy[12] = {
    0x90EA0E5Ful, 0x7A431D7Cul, 0x1D7E819Dul, 0x0A60B1CEul,
    0xB5F0B8C0ul, 0xE9DA3113ul, 0x289A147Cul, 0xF8F41DBDul,
    0x9292DC29ul, 0x5D9E98BFul, 0x96262C6Ful, 0x3617DE4Aul
};
/* n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB2 */
/*     48B0A77AECEC196ACCC52973                                           */
static SSFBNLimb_t _ssfECP384_n[12] = {
    0xCCC52973ul, 0xECEC196Aul, 0x48B0A77Aul, 0x581A0DB2ul,
    0xF4372DDFul, 0xC7634D81ul, 0xFFFFFFFFul, 0xFFFFFFFFul,
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul
};
static const SSFECCurveParams_t _ssfECP384 =
{
    { _ssfECP384_p,  12, 12 },
    { _ssfECP384_a,  12, 12 },
    { _ssfECP384_b,  12, 12 },
    { _ssfECP384_gx, 12, 12 },
    { _ssfECP384_gy, 12, 12 },
    { _ssfECP384_n,  12, 12 },
    12,  /* limbs */
    48   /* bytes */
};
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

/* --------------------------------------------------------------------------------------------- */
/* Returns curve parameters for the given curve.                                                 */
/* --------------------------------------------------------------------------------------------- */
const SSFECCurveParams_t *SSFECGetCurveParams(SSFECCurve_t curve)
{
    switch (curve)
    {
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    case SSF_EC_CURVE_P256: return &_ssfECP256;
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    case SSF_EC_CURVE_P384: return &_ssfECP384;
#endif
    default: return NULL;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: point doubling in Jacobian coordinates with a = -3 optimization.                    */
/* Uses EFD "dbl-2001-b" formula: 3M + 5S.                                                      */
/* r may alias p.                                                                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECPointDouble(SSFECPoint_t *r, const SSFECPoint_t *p,
                              const SSFECCurveParams_t *c)
{
    SSFBN_DEFINE(delta, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(gamma, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(beta, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(alpha, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    /* No identity early-exit. When p->z == 0, the formulas below produce r->z == (Y1+0)^2 - */
    /* Y1^2 - 0 == 0, so the identity is preserved. The X3, Y3 values become arithmetic       */
    /* "garbage" but are don't-care once Z3 == 0 — every consumer detects identity by Z.      */
    /* Removing the branch is what makes scalar mul constant-time at the first ladder step.   */

    /* delta = Z1^2 */
    SSFBNModMulNIST(&delta, &p->z, &p->z, &c->p);

    /* gamma = Y1^2 */
    SSFBNModMulNIST(&gamma, &p->y, &p->y, &c->p);

    /* beta = X1 * gamma = X1 * Y1^2 */
    SSFBNModMulNIST(&beta, &p->x, &gamma, &c->p);

    /* alpha = 3 * (X1 - delta) * (X1 + delta)  [a = -3 optimization] */
    SSFBNModSub(&tmp, &p->x, &delta, &c->p);
    SSFBNModAdd(&alpha, &p->x, &delta, &c->p);
    SSFBNModMulNIST(&alpha, &tmp, &alpha, &c->p);
    SSFBNModAdd(&tmp, &alpha, &alpha, &c->p);
    SSFBNModAdd(&alpha, &tmp, &alpha, &c->p);

    /* Z3 = (Y1 + Z1)^2 - gamma - delta  [saves one mul vs 2*Y1*Z1] */
    /* Must compute before overwriting r->x or r->y in case r aliases p */
    SSFBNModAdd(&tmp, &p->y, &p->z, &c->p);
    SSFBNModMulNIST(&r->z, &tmp, &tmp, &c->p);
    SSFBNModSub(&r->z, &r->z, &gamma, &c->p);
    SSFBNModSub(&r->z, &r->z, &delta, &c->p);

    /* X3 = alpha^2 - 8 * beta */
    SSFBNModMulNIST(&r->x, &alpha, &alpha, &c->p);
    SSFBNModAdd(&tmp, &beta, &beta, &c->p);
    SSFBNModAdd(&tmp, &tmp, &tmp, &c->p);         /* 4 * beta */
    SSFBNModAdd(&delta, &tmp, &tmp, &c->p);       /* 8 * beta (reuse delta) */
    SSFBNModSub(&r->x, &r->x, &delta, &c->p);

    /* Y3 = alpha * (4 * beta - X3) - 8 * gamma^2 */
    SSFBNModSub(&tmp, &tmp, &r->x, &c->p);        /* 4*beta - X3 (tmp was 4*beta) */
    SSFBNModMulNIST(&tmp, &alpha, &tmp, &c->p);
    SSFBNModMulNIST(&gamma, &gamma, &gamma, &c->p); /* gamma^2 = Y1^4 */
    SSFBNModAdd(&gamma, &gamma, &gamma, &c->p);   /* 2 * Y1^4 */
    SSFBNModAdd(&gamma, &gamma, &gamma, &c->p);   /* 4 * Y1^4 */
    SSFBNModAdd(&gamma, &gamma, &gamma, &c->p);   /* 8 * Y1^4 */
    SSFBNModSub(&r->y, &tmp, &gamma, &c->p);

    /* Zeroize scratch — these contain values derived from the secret scalar during the     */
    /* Montgomery ladder. Stack reuse would otherwise leak intermediate point coordinates.   */
    SSFBNZeroize(&delta);
    SSFBNZeroize(&gamma);
    SSFBNZeroize(&beta);
    SSFBNZeroize(&alpha);
    SSFBNZeroize(&tmp);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: point addition in full Jacobian coordinates.                                        */
/* Standard formulas: 12M + 4S.                                                                  */
/* r may alias p or q.                                                                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECPointAddFull(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                               const SSFECCurveParams_t *c)
{
    SSFBN_DEFINE(t1, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t2, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t3, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t4, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t5, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t6, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->x.limbs != NULL);
    SSF_REQUIRE(q->y.limbs != NULL);
    SSF_REQUIRE(q->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);
    /* Saved copies of the inputs let us run all selection branches without losing p or q to */
    /* aliasing — r may alias either or both. */
    SSFECPOINT_DEFINE(P, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    /* Doubling result for the "P == Q" special case, and an identity point for "P == -Q".   */
    SSFECPOINT_DEFINE(dblP, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(zeroPt, SSF_EC_MAX_LIMBS);
    SSFBNLimb_t z1z, z2z, hz, rz, hzAndRz, hzAndNotRz;

    /* Save p and q so the general formulas can run unconditionally even when r aliases p    */
    /* or q — every read after this point goes through P / Q.                                */
    SSFBNCopy(&P.x, &p->x); SSFBNCopy(&P.y, &p->y); SSFBNCopy(&P.z, &p->z);
    SSFBNCopy(&Q.x, &q->x); SSFBNCopy(&Q.y, &q->y); SSFBNCopy(&Q.z, &q->z);

    /* Pre-compute Double(P) for the P==Q select branch. Done before we touch r so the      */
    /* ScalarMul aliasing pattern (r == &R0 or &R1) doesn't poison the input.                */
    _SSFECPointDouble(&dblP, &P, c);

    /* zeroPt = identity (X=0, Y=1, Z=0) — used for the P == -Q branch.                      */
    SSFBNSetZero(&zeroPt.x, c->limbs);
    SSFBNSetOne(&zeroPt.y, c->limbs);
    SSFBNSetZero(&zeroPt.z, c->limbs);

    /* General Jacobian addition formulas. Read from saved P / Q only.                       */
    /* z1_sq = Z1^2, z2_sq = Z2^2 */
    SSFBNModMulNIST(&t1, &P.z, &P.z, &c->p);     /* t1 = Z1^2 */
    SSFBNModMulNIST(&t2, &Q.z, &Q.z, &c->p);     /* t2 = Z2^2 */

    /* z1_cu = Z1 * Z1^2, z2_cu = Z2 * Z2^2 */
    SSFBNModMulNIST(&t3, &P.z, &t1, &c->p);      /* t3 = Z1^3 */
    SSFBNModMulNIST(&t4, &Q.z, &t2, &c->p);      /* t4 = Z2^3 */

    /* U1 = X1 * Z2^2, U2 = X2 * Z1^2 */
    SSFBNModMulNIST(&t5, &P.x, &t2, &c->p);      /* t5 = U1 = X1*Z2^2 */
    SSFBNModMulNIST(&t2, &Q.x, &t1, &c->p);      /* t2 = U2 = X2*Z1^2 (reuse t2) */

    /* S1 = Y1 * Z2^3, S2 = Y2 * Z1^3 */
    SSFBNModMulNIST(&t1, &P.y, &t4, &c->p);      /* t1 = S1 = Y1*Z2^3 (reuse t1) */
    SSFBNModMulNIST(&t4, &Q.y, &t3, &c->p);      /* t4 = S2 = Y2*Z1^3 (reuse t4) */

    /* H = U2 - U1, R = S2 - S1 */
    SSFBNModSub(&t3, &t2, &t5, &c->p);           /* t3 = H = U2 - U1 (reuse t3) */
    SSFBNModSub(&t2, &t4, &t1, &c->p);           /* t2 = R = S2 - S1 (reuse t2) */

    /* Capture special-case flags BEFORE the formulas continue overwriting things. All four  */
    /* are derived via constant-time IsZero (OR-accumulator).                                 */
    z1z = (SSFBNLimb_t)SSFBNIsZero(&P.z);
    z2z = (SSFBNLimb_t)SSFBNIsZero(&Q.z);
    hz  = (SSFBNLimb_t)SSFBNIsZero(&t3);         /* H == 0 */
    rz  = (SSFBNLimb_t)SSFBNIsZero(&t2);         /* R == 0 */

    /* Continue the general formulas unconditionally. When inputs hit a special case the     */
    /* general result is mathematically wrong, but every wrong-case is overridden by the      */
    /* cascaded conditional copies below.                                                    */

    /* t4 = H^2 */
    SSFBNModMulNIST(&t4, &t3, &t3, &c->p);
    /* t6 = H^3 */
    SSFBNModMulNIST(&t6, &t3, &t4, &c->p);
    /* U1H2 = U1 * H^2 */
    SSFBNModMulNIST(&t5, &t5, &t4, &c->p);

    /* Z3 = Z1 * Z2 * H */
    SSFBNModMulNIST(&r->z, &P.z, &Q.z, &c->p);
    SSFBNModMulNIST(&r->z, &r->z, &t3, &c->p);

    /* X3 = R^2 - H^3 - 2 * U1H2 */
    SSFBNModMulNIST(&r->x, &t2, &t2, &c->p);
    SSFBNModSub(&r->x, &r->x, &t6, &c->p);
    SSFBNModAdd(&t4, &t5, &t5, &c->p);
    SSFBNModSub(&r->x, &r->x, &t4, &c->p);

    /* Y3 = R * (U1H2 - X3) - S1 * H^3 */
    SSFBNModSub(&t5, &t5, &r->x, &c->p);
    SSFBNModMulNIST(&t5, &t2, &t5, &c->p);
    SSFBNModMulNIST(&t1, &t1, &t6, &c->p);
    SSFBNModSub(&r->y, &t5, &t1, &c->p);

    /* Cascaded constant-time conditional copy. Each later override has higher priority      */
    /* than earlier ones (later writes on top of earlier writes).                            */
    /*   default       : r = general add result (already in r)                               */
    /*   hz & !rz      : P == -Q, result is identity                                          */
    /*   hz &  rz      : P ==  Q, result is 2*P                                               */
    /*   z2z           : Q is identity, result is P                                           */
    /*   z1z           : P is identity, result is Q (highest priority)                       */
    hzAndRz    = hz & rz;
    hzAndNotRz = hz & ((SSFBNLimb_t)1u ^ rz);

    SSFBNCondCopy(&r->x, &zeroPt.x, hzAndNotRz);
    SSFBNCondCopy(&r->y, &zeroPt.y, hzAndNotRz);
    SSFBNCondCopy(&r->z, &zeroPt.z, hzAndNotRz);

    SSFBNCondCopy(&r->x, &dblP.x, hzAndRz);
    SSFBNCondCopy(&r->y, &dblP.y, hzAndRz);
    SSFBNCondCopy(&r->z, &dblP.z, hzAndRz);

    SSFBNCondCopy(&r->x, &P.x, z2z);
    SSFBNCondCopy(&r->y, &P.y, z2z);
    SSFBNCondCopy(&r->z, &P.z, z2z);

    SSFBNCondCopy(&r->x, &Q.x, z1z);
    SSFBNCondCopy(&r->y, &Q.y, z1z);
    SSFBNCondCopy(&r->z, &Q.z, z1z);

    /* Zeroize scratch — every t* and the saved point copies hold values derived from the   */
    /* secret scalar during the Montgomery ladder.                                          */
    SSFBNZeroize(&t1); SSFBNZeroize(&t2); SSFBNZeroize(&t3);
    SSFBNZeroize(&t4); SSFBNZeroize(&t5); SSFBNZeroize(&t6);
    SSFBNZeroize(&P.x); SSFBNZeroize(&P.y); SSFBNZeroize(&P.z);
    SSFBNZeroize(&Q.x); SSFBNZeroize(&Q.y); SSFBNZeroize(&Q.z);
    SSFBNZeroize(&dblP.x); SSFBNZeroize(&dblP.y); SSFBNZeroize(&dblP.z);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: mixed-coordinate addition. q is required to satisfy q->z == 1 (affine) OR q->z == 0 */
/* (identity); the simplifications below assume q->z == 1 for the general case, and the CT       */
/* cascade handles q->z == 0 correctly. Saves 3 muls + 1 square per call vs full Jacobian add by */
/* dropping Z2², Z2³, and Z1*Z2.                                                                  */
/* r may alias p or q.                                                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECPointAddMixed(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                                const SSFECCurveParams_t *c)
{
    SSFBN_DEFINE(t1, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t2, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t3, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t4, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t5, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t6, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(P, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(dblP, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(zeroPt, SSF_EC_MAX_LIMBS);
    SSFBNLimb_t z1z, z2z, hz, rz, hzAndRz, hzAndNotRz;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->x.limbs != NULL);
    SSF_REQUIRE(q->y.limbs != NULL);
    SSF_REQUIRE(q->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    /* Save p, q so the formulas can run safely even when r aliases either. */
    SSFBNCopy(&P.x, &p->x); SSFBNCopy(&P.y, &p->y); SSFBNCopy(&P.z, &p->z);
    SSFBNCopy(&Q.x, &q->x); SSFBNCopy(&Q.y, &q->y); SSFBNCopy(&Q.z, &q->z);

    /* Pre-compute Double(P) for the P==Q case. */
    _SSFECPointDouble(&dblP, &P, c);

    /* zeroPt = identity */
    SSFBNSetZero(&zeroPt.x, c->limbs);
    SSFBNSetOne(&zeroPt.y, c->limbs);
    SSFBNSetZero(&zeroPt.z, c->limbs);

    /* General mixed-coordinate add (assume Z2 = 1):                                              */
    /*   Z1Z1 = Z1²            Z1ZZZ1 = Z1 * Z1Z1                                                  */
    /*   U1 = X1               U2 = X2 * Z1Z1                                                     */
    /*   S1 = Y1               S2 = Y2 * Z1ZZZ1                                                   */
    /*   H = U2 - U1           R = S2 - S1                                                        */
    /*   X3 = R² - H³ - 2 * U1 * H²                                                               */
    /*   Y3 = R * (U1*H² - X3) - S1 * H³                                                          */
    /*   Z3 = Z1 * H                                                                              */
    SSFBNModMulNIST(&t1, &P.z, &P.z, &c->p);          /* t1 = Z1²                       */
    SSFBNModMulNIST(&t3, &P.z, &t1, &c->p);            /* t3 = Z1³                       */
    SSFBNModMulNIST(&t2, &Q.x, &t1, &c->p);            /* t2 = U2 = X2 * Z1²            */
    SSFBNModMulNIST(&t4, &Q.y, &t3, &c->p);            /* t4 = S2 = Y2 * Z1³            */
    SSFBNModSub(&t3, &t2, &P.x, &c->p);                /* t3 = H = U2 - X1 (U1 = X1)    */
    SSFBNModSub(&t2, &t4, &P.y, &c->p);                /* t2 = R = S2 - Y1 (S1 = Y1)    */

    /* Capture flags before continuing.                                                          */
    z1z = (SSFBNLimb_t)SSFBNIsZero(&P.z);
    z2z = (SSFBNLimb_t)SSFBNIsZero(&Q.z);
    hz  = (SSFBNLimb_t)SSFBNIsZero(&t3);
    rz  = (SSFBNLimb_t)SSFBNIsZero(&t2);

    SSFBNModMulNIST(&t4, &t3, &t3, &c->p);             /* t4 = H²                       */
    SSFBNModMulNIST(&t6, &t3, &t4, &c->p);             /* t6 = H³                       */
    SSFBNModMulNIST(&t5, &P.x, &t4, &c->p);            /* t5 = U1*H² = X1*H²            */

    /* Z3 = Z1 * H (skipping the Z1*Z2 step from the full add). */
    SSFBNModMulNIST(&r->z, &P.z, &t3, &c->p);

    /* X3 = R² - H³ - 2 * U1*H² */
    SSFBNModMulNIST(&r->x, &t2, &t2, &c->p);
    SSFBNModSub(&r->x, &r->x, &t6, &c->p);
    SSFBNModAdd(&t4, &t5, &t5, &c->p);
    SSFBNModSub(&r->x, &r->x, &t4, &c->p);

    /* Y3 = R * (U1*H² - X3) - S1 * H³ = R * (X1*H² - X3) - Y1 * H³ */
    SSFBNModSub(&t5, &t5, &r->x, &c->p);
    SSFBNModMulNIST(&t5, &t2, &t5, &c->p);
    SSFBNModMulNIST(&t1, &P.y, &t6, &c->p);            /* t1 = Y1 * H³ (reuse t1)       */
    SSFBNModSub(&r->y, &t5, &t1, &c->p);

    /* CT cascade — same priority order as the full add. */
    hzAndRz    = hz & rz;
    hzAndNotRz = hz & ((SSFBNLimb_t)1u ^ rz);

    SSFBNCondCopy(&r->x, &zeroPt.x, hzAndNotRz);
    SSFBNCondCopy(&r->y, &zeroPt.y, hzAndNotRz);
    SSFBNCondCopy(&r->z, &zeroPt.z, hzAndNotRz);

    SSFBNCondCopy(&r->x, &dblP.x, hzAndRz);
    SSFBNCondCopy(&r->y, &dblP.y, hzAndRz);
    SSFBNCondCopy(&r->z, &dblP.z, hzAndRz);

    SSFBNCondCopy(&r->x, &P.x, z2z);
    SSFBNCondCopy(&r->y, &P.y, z2z);
    SSFBNCondCopy(&r->z, &P.z, z2z);

    SSFBNCondCopy(&r->x, &Q.x, z1z);
    SSFBNCondCopy(&r->y, &Q.y, z1z);
    SSFBNCondCopy(&r->z, &Q.z, z1z);

    /* Zeroize scratch. */
    SSFBNZeroize(&t1); SSFBNZeroize(&t2); SSFBNZeroize(&t3);
    SSFBNZeroize(&t4); SSFBNZeroize(&t5); SSFBNZeroize(&t6);
    SSFBNZeroize(&P.x); SSFBNZeroize(&P.y); SSFBNZeroize(&P.z);
    SSFBNZeroize(&Q.x); SSFBNZeroize(&Q.y); SSFBNZeroize(&Q.z);
    SSFBNZeroize(&dblP.x); SSFBNZeroize(&dblP.y); SSFBNZeroize(&dblP.z);
}

#if SSF_CONFIG_EC_UNIT_TEST == 1
void _SSFECPointAddMixedForTest(SSFECPoint_t *r, const SSFECPoint_t *p,
                                const SSFECPoint_t *q, SSFECCurve_t curve)
{
    _SSFECPointAddMixed(r, p, q, SSFECGetCurveParams(curve));
}
#endif

/* --------------------------------------------------------------------------------------------- */
/* Internal: comb-runtime variant of mixed addition. Same as _SSFECPointAddMixed with one      */
/* difference — it does NOT precompute Double(P), saving one full doubling per call.           */
/* Caller MUST guarantee P != Q (the P == Q case is otherwise mathematically required to dispatch */
/* into doubling). For the comb-runtime use case, R is the running accumulator and Q is a fixed  */
/* table entry; the probability of R coinciding with table[mask] is ~2^-bits, statistically zero. */
/* All other special cases (P == identity, Q == identity, P == -Q) are still handled correctly.  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECPointAddMixedNoDouble(SSFECPoint_t *r, const SSFECPoint_t *p,
                                        const SSFECPoint_t *q, const SSFECCurveParams_t *c)
{
    SSFBN_DEFINE(t1, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t2, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t3, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t4, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t5, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t6, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(P, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(zeroPt, SSF_EC_MAX_LIMBS);
    SSFBNLimb_t z1z, z2z, hz, rz, hzAndNotRz;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->x.limbs != NULL);
    SSF_REQUIRE(q->y.limbs != NULL);
    SSF_REQUIRE(q->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    /* Save p, q for safe aliasing of r. */
    SSFBNCopy(&P.x, &p->x); SSFBNCopy(&P.y, &p->y); SSFBNCopy(&P.z, &p->z);
    SSFBNCopy(&Q.x, &q->x); SSFBNCopy(&Q.y, &q->y); SSFBNCopy(&Q.z, &q->z);

    SSFBNSetZero(&zeroPt.x, c->limbs);
    SSFBNSetOne(&zeroPt.y, c->limbs);
    SSFBNSetZero(&zeroPt.z, c->limbs);

    /* General mixed-coordinate add (assume Z2 = 1) — same formulas as _SSFECPointAddMixed. */
    SSFBNModMulNIST(&t1, &P.z, &P.z, &c->p);
    SSFBNModMulNIST(&t3, &P.z, &t1, &c->p);
    SSFBNModMulNIST(&t2, &Q.x, &t1, &c->p);
    SSFBNModMulNIST(&t4, &Q.y, &t3, &c->p);
    SSFBNModSub(&t3, &t2, &P.x, &c->p);
    SSFBNModSub(&t2, &t4, &P.y, &c->p);

    z1z = (SSFBNLimb_t)SSFBNIsZero(&P.z);
    z2z = (SSFBNLimb_t)SSFBNIsZero(&Q.z);
    hz  = (SSFBNLimb_t)SSFBNIsZero(&t3);
    rz  = (SSFBNLimb_t)SSFBNIsZero(&t2);

    SSFBNModMulNIST(&t4, &t3, &t3, &c->p);
    SSFBNModMulNIST(&t6, &t3, &t4, &c->p);
    SSFBNModMulNIST(&t5, &P.x, &t4, &c->p);

    SSFBNModMulNIST(&r->z, &P.z, &t3, &c->p);

    SSFBNModMulNIST(&r->x, &t2, &t2, &c->p);
    SSFBNModSub(&r->x, &r->x, &t6, &c->p);
    SSFBNModAdd(&t4, &t5, &t5, &c->p);
    SSFBNModSub(&r->x, &r->x, &t4, &c->p);

    SSFBNModSub(&t5, &t5, &r->x, &c->p);
    SSFBNModMulNIST(&t5, &t2, &t5, &c->p);
    SSFBNModMulNIST(&t1, &P.y, &t6, &c->p);
    SSFBNModSub(&r->y, &t5, &t1, &c->p);

    /* Cascade — three overrides only (no P == Q case):                                          */
    /*   default       : r = general add result                                                  */
    /*   hz & !rz      : P == -Q, result is identity                                             */
    /*   z2z           : Q is identity, result is P                                              */
    /*   z1z           : P is identity, result is Q (highest priority)                           */
    /* If P == Q (hz & rz both true), the result is wrong — but the caller guarantees P != Q.    */
    hzAndNotRz = hz & ((SSFBNLimb_t)1u ^ rz);

    SSFBNCondCopy(&r->x, &zeroPt.x, hzAndNotRz);
    SSFBNCondCopy(&r->y, &zeroPt.y, hzAndNotRz);
    SSFBNCondCopy(&r->z, &zeroPt.z, hzAndNotRz);

    SSFBNCondCopy(&r->x, &P.x, z2z);
    SSFBNCondCopy(&r->y, &P.y, z2z);
    SSFBNCondCopy(&r->z, &P.z, z2z);

    SSFBNCondCopy(&r->x, &Q.x, z1z);
    SSFBNCondCopy(&r->y, &Q.y, z1z);
    SSFBNCondCopy(&r->z, &Q.z, z1z);

    /* Zeroize scratch. */
    SSFBNZeroize(&t1); SSFBNZeroize(&t2); SSFBNZeroize(&t3);
    SSFBNZeroize(&t4); SSFBNZeroize(&t5); SSFBNZeroize(&t6);
    SSFBNZeroize(&P.x); SSFBNZeroize(&P.y); SSFBNZeroize(&P.z);
    SSFBNZeroize(&Q.x); SSFBNZeroize(&Q.y); SSFBNZeroize(&Q.z);
}

#if SSF_CONFIG_EC_UNIT_TEST == 1
void _SSFECPointAddMixedNoDoubleForTest(SSFECPoint_t *r, const SSFECPoint_t *p,
                                        const SSFECPoint_t *q, SSFECCurve_t curve)
{
    _SSFECPointAddMixedNoDouble(r, p, q, SSFECGetCurveParams(curve));
}
#endif

/* --------------------------------------------------------------------------------------------- */
/* Set point to identity.                                                                        */
/* --------------------------------------------------------------------------------------------- */
void SSFECPointSetIdentity(SSFECPoint_t *pt, SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->x.limbs != NULL);
    SSF_REQUIRE(pt->y.limbs != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(pt->x.cap >= c->limbs);
    SSF_REQUIRE(pt->y.cap >= c->limbs);
    SSF_REQUIRE(pt->z.cap >= c->limbs);

    SSFBNSetZero(&pt->x, c->limbs);
    SSFBNSetOne(&pt->y, c->limbs);
    SSFBNSetZero(&pt->z, c->limbs);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if point is identity (Z == 0).                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointIsIdentity(const SSFECPoint_t *pt)
{
    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);

    return SSFBNIsZero(&pt->z);
}

/* --------------------------------------------------------------------------------------------- */
/* Set Jacobian point from affine coordinates.                                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFECPointFromAffine(SSFECPoint_t *pt, const SSFBN_t *x, const SSFBN_t *y,
                          SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->x.limbs != NULL);
    SSF_REQUIRE(pt->y.limbs != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);
    SSF_REQUIRE(x != NULL);
    SSF_REQUIRE(x->limbs != NULL);
    SSF_REQUIRE(y != NULL);
    SSF_REQUIRE(y->limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(pt->x.cap >= x->len);
    SSF_REQUIRE(pt->y.cap >= y->len);
    SSF_REQUIRE(pt->z.cap >= c->limbs);

    SSFBNCopy(&pt->x, x);
    SSFBNCopy(&pt->y, y);
    SSFBNSetOne(&pt->z, c->limbs);
}

/* --------------------------------------------------------------------------------------------- */
/* Convert Jacobian point to affine: x = X/Z^2, y = Y/Z^3.                                      */
/* Returns false if point is identity (no finite affine representation).                         */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointToAffine(SSFBN_t *x, SSFBN_t *y, const SSFECPoint_t *pt, SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(zInv, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(zInv2, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(zInv3, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(x != NULL);
    SSF_REQUIRE(x->limbs != NULL);
    SSF_REQUIRE(y != NULL);
    SSF_REQUIRE(y->limbs != NULL);
    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->x.limbs != NULL);
    SSF_REQUIRE(pt->y.limbs != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(x->cap >= c->limbs);
    SSF_REQUIRE(y->cap >= c->limbs);

    /* Reject identity (Z=0) — undefined affine coordinate. The early return is data-dependent  */
    /* on a single bit of pt->z, but for prime-order curves (P-256/P-384) with scalars in       */
    /* [1, n-1] the scalar-mul output is never the identity, so this case only triggers on       */
    /* malformed or error inputs and leaks no information about secret operations.               */
    if (SSFBNIsZero(&pt->z)) return false;

    /* No Z==1 fast-path: removed in favor of unconditional inversion. The fast-path branched   */
    /* on the (potentially secret) Z value, and Jacobian scalar-mul outputs have Z = 1 only      */
    /* with probability ~2^-256, so skipping the inversion saved nothing in real workloads while */
    /* leaking 1 bit per call when callers happened to pass an already-affine point.             */

    /* zInv = Z^(-1) mod p */
    if (!SSFBNModInv(&zInv, &pt->z, &c->p)) return false;

    /* zInv2 = Z^(-2), zInv3 = Z^(-3) */
    SSFBNModMulNIST(&zInv2, &zInv, &zInv, &c->p);
    SSFBNModMulNIST(&zInv3, &zInv2, &zInv, &c->p);

    /* x = X * Z^(-2), y = Y * Z^(-3) */
    SSFBNModMulNIST(x, &pt->x, &zInv2, &c->p);
    SSFBNModMulNIST(y, &pt->y, &zInv3, &c->p);

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if point lies on the curve y^2 = x^3 + ax + b (mod p).                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointOnCurve(const SSFECPoint_t *pt, SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->x.limbs != NULL);
    SSF_REQUIRE(pt->y.limbs != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSFBN_DEFINE(lhs, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(rhs, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(c != NULL);

    if (SSFBNIsZero(&pt->z)) return false;

    /* Get affine coordinates */
    if (SSFBNIsOne(&pt->z))
    {
        SSFBNCopy(&ax, &pt->x);
        SSFBNCopy(&ay, &pt->y);
    }
    else
    {
        if (!SSFECPointToAffine(&ax, &ay, pt, curve)) return false;
    }

    /* lhs = y^2 mod p */
    SSFBNModMulNIST(&lhs, &ay, &ay, &c->p);

    /* rhs = x^3 + a*x + b mod p */
    SSFBNModMulNIST(&rhs, &ax, &ax, &c->p);       /* x^2 */
    SSFBNModMulNIST(&rhs, &rhs, &ax, &c->p);      /* x^3 */
    SSFBNModMulNIST(&tmp, &c->a, &ax, &c->p);     /* a*x */
    SSFBNModAdd(&rhs, &rhs, &tmp, &c->p);          /* x^3 + a*x */
    SSFBNModAdd(&rhs, &rhs, &c->b, &c->p);         /* x^3 + a*x + b */

    return (SSFBNCmp(&lhs, &rhs) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Full point validation for untrusted input.                                                    */
/* Checks: coordinates in [0, p-1], on curve, not identity.                                      */
/* For P-256 and P-384 (cofactor 1), on-curve implies correct subgroup.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointValidate(const SSFECPoint_t *pt, SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->x.limbs != NULL);
    SSF_REQUIRE(pt->y.limbs != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);

    /* Must not be identity */
    if (SSFBNIsZero(&pt->z)) return false;

    /* Get affine coordinates */
    if (SSFBNIsOne(&pt->z))
    {
        SSFBNCopy(&ax, &pt->x);
        SSFBNCopy(&ay, &pt->y);
    }
    else
    {
        if (!SSFECPointToAffine(&ax, &ay, pt, curve)) return false;
    }

    /* Check x in [0, p-1] */
    if (SSFBNCmp(&ax, &c->p) >= 0) return false;

    /* Check y in [0, p-1] */
    if (SSFBNCmp(&ay, &c->p) >= 0) return false;

    /* Check on curve */
    return SSFECPointOnCurve(pt, curve);
}

/* --------------------------------------------------------------------------------------------- */
/* Encode point in SEC 1 uncompressed format: 0x04 || X || Y.                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointEncode(const SSFECPoint_t *pt, SSFECCurve_t curve,
                      uint8_t *out, size_t outSize, size_t *outLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    size_t encLen;
    SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->x.limbs != NULL);
    SSF_REQUIRE(pt->y.limbs != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);
    SSF_REQUIRE(c != NULL);

    encLen = 1u + 2u * (size_t)c->bytes;
    if (outSize < encLen) return false;

    /* Convert to affine */
    if (!SSFECPointToAffine(&ax, &ay, pt, curve)) return false;

    /* Write format byte */
    out[0] = 0x04u;

    /* Write X and Y as big-endian, zero-padded to coordinate length */
    if (!SSFBNToBytes(&ax, &out[1], c->bytes)) return false;
    if (!SSFBNToBytes(&ay, &out[1u + c->bytes], c->bytes)) return false;

    *outLen = encLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Decode SEC 1 uncompressed point. Validates the decoded point.                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointDecode(SSFECPoint_t *pt, SSFECCurve_t curve,
                      const uint8_t *data, size_t dataLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    size_t encLen;

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(pt->x.limbs != NULL);
    SSF_REQUIRE(pt->y.limbs != NULL);
    SSF_REQUIRE(pt->z.limbs != NULL);
    SSF_REQUIRE(data != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(pt->x.cap >= c->limbs);
    SSF_REQUIRE(pt->y.cap >= c->limbs);
    SSF_REQUIRE(pt->z.cap >= c->limbs);

    encLen = 1u + 2u * (size_t)c->bytes;
    if (dataLen != encLen) return false;

    /* Must be uncompressed format */
    if (data[0] != 0x04u) return false;

    /* Import X and Y */
    if (!SSFBNFromBytes(&pt->x, &data[1], c->bytes, c->limbs)) return false;
    if (!SSFBNFromBytes(&pt->y, &data[1u + c->bytes], c->bytes, c->limbs)) return false;

    /* Z = 1 (affine) */
    SSFBNSetOne(&pt->z, c->limbs);

    /* Validate the point */
    if (!SSFECPointValidate(pt, curve)) return false;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Point addition: r = p + q (Jacobian).                                                         */
/* Affine fast path: when either operand has Z = 1 (e.g. freshly built via SSFECPointFromAffine  */
/* or freshly decoded from SEC1), dispatch to the cheaper mixed-coordinate addition. The Z-value */
/* check leaks the Z attribute of the inputs, which is a property of the caller's setup, not of  */
/* any secret scalar — so this remains safe to use from public-input callers.                    */
/* --------------------------------------------------------------------------------------------- */
void SSFECPointAdd(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                   SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->x.limbs != NULL);
    SSF_REQUIRE(q->y.limbs != NULL);
    SSF_REQUIRE(q->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    if ((q->z.len >= 1u) && SSFBNIsOne(&q->z))
    {
        _SSFECPointAddMixed(r, p, q, c);
        return;
    }
    if ((p->z.len >= 1u) && SSFBNIsOne(&p->z))
    {
        /* Symmetric: swap operands so the Z=1 one is q in the mixed-add contract. */
        _SSFECPointAddMixed(r, q, p, c);
        return;
    }
    _SSFECPointAddFull(r, p, q, c);
}

/* --------------------------------------------------------------------------------------------- */
/* Constant-time scalar multiplication via Montgomery ladder: r = k * p.                         */
/* k must be in [1, n-1]. Iterates over all bits of the curve's limb width for constant time.    */
/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
/* Constant-time variable-base scalar multiplication via 4-bit windowed scan.                    */
/*                                                                                                */
/* Algorithm:                                                                                     */
/*   1. Precompute table[i] = [i] * P  for i in 0..15 (table[0] = identity).                      */
/*   2. Initialize R = identity.                                                                  */
/*   3. For each 4-bit window of k from MSB to LSB:                                               */
/*        R = 16 * R                                  (4 doublings)                               */
/*        w = decoded window value (0..15)                                                         */
/*        R = R + table[w]                            (CT table lookup + 1 addition)              */
/*                                                                                                */
/* Correctness: R = sum_{j=0}^{nWindows-1} w_j * P * 2^(j*4) = k * P.                             */
/*                                                                                                */
/* Cost (P-256, 256 bits):                                                                        */
/*   - Precompute: 14 additions building [2..15] * P (table[i] = table[i-1] + P).                 */
/*   - Main loop: 64 windows × (4 doublings + 1 addition) = 256 doublings + 64 additions.         */
/*   - vs Montgomery ladder: 256 additions + 256 doublings.                                       */
/* Net win: ~192 fewer additions per call (≈1.8-2x speedup), at the cost of ~2.5 KB more stack.   */
/*                                                                                                */
/* Constant-time: timing and memory access pattern are independent of k's bit pattern. The table  */
/* lookup scans all 16 entries with masked SSFBNCondCopy; the per-window doubling and addition    */
/* run unconditionally.                                                                            */
/* --------------------------------------------------------------------------------------------- */
#define _SSF_EC_VAR_WINDOW_K (4u)
#define _SSF_EC_VAR_TABLE_N  ((uint32_t)1u << _SSF_EC_VAR_WINDOW_K) /* 16 */

void SSFECScalarMul(SSFECPoint_t *r, const SSFBN_t *k, const SSFECPoint_t *p,
                    SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBNLimb_t tableStorage[_SSF_EC_VAR_TABLE_N][3][SSF_EC_MAX_LIMBS];
    SSFECPoint_t table[_SSF_EC_VAR_TABLE_N];
    SSFECPOINT_DEFINE(picked, SSF_EC_MAX_LIMBS);
    uint32_t bits;
    uint32_t nWindows;
    uint32_t winIdx;
    uint32_t w;
    uint32_t bp;
    uint32_t bitOffset;
    int32_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(k != NULL);
    SSF_REQUIRE(k->limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    bits = (uint32_t)c->limbs * SSF_BN_LIMB_BITS;

    /* Wire up SSFECPoint_t descriptors over the local backing storage. */
    for (i = 0; i < (int32_t)_SSF_EC_VAR_TABLE_N; i++)
    {
        table[i].x.limbs = tableStorage[i][0];
        table[i].x.cap = SSF_EC_MAX_LIMBS;
        table[i].x.len = 0u;
        table[i].y.limbs = tableStorage[i][1];
        table[i].y.cap = SSF_EC_MAX_LIMBS;
        table[i].y.len = 0u;
        table[i].z.limbs = tableStorage[i][2];
        table[i].z.cap = SSF_EC_MAX_LIMBS;
        table[i].z.len = 0u;
    }

    /* table[0] = identity */
    SSFBNSetZero(&table[0].x, c->limbs);
    SSFBNSetOne(&table[0].y, c->limbs);
    SSFBNSetZero(&table[0].z, c->limbs);

    /* table[1] = P */
    SSFBNCopy(&table[1].x, &p->x);
    SSFBNCopy(&table[1].y, &p->y);
    SSFBNCopy(&table[1].z, &p->z);

    /* table[i] = table[i-1] + P for i = 2..15. Note table[2] = P+P = 2P (the AddFull cascade   */
    /* handles P==Q via the precomputed Double).                                                 */
    for (w = 2u; w < _SSF_EC_VAR_TABLE_N; w++)
    {
        _SSFECPointAddFull(&table[w], &table[w - 1u], &table[1], c);
    }

    /* R = identity */
    SSFBNSetZero(&r->x, c->limbs);
    SSFBNSetOne(&r->y, c->limbs);
    SSFBNSetZero(&r->z, c->limbs);

    /* nWindows = bits / 4. For P-256 / P-384, bits is divisible by 4 so we cover k exactly.    */
    nWindows = bits / _SSF_EC_VAR_WINDOW_K;

    for (winIdx = 0; winIdx < nWindows; winIdx++)
    {
        uint32_t step;

        /* R = 16 * R: four consecutive doublings. */
        for (step = 0; step < _SSF_EC_VAR_WINDOW_K; step++)
        {
            _SSFECPointDouble(r, r, c);
        }

        /* Decode this window's value (MSB first within k). */
        bitOffset = (nWindows - 1u - winIdx) * _SSF_EC_VAR_WINDOW_K;
        w = 0u;
        for (step = 0; step < _SSF_EC_VAR_WINDOW_K; step++)
        {
            bp = bitOffset + (_SSF_EC_VAR_WINDOW_K - 1u - step);
            w = (w << 1) | (uint32_t)SSFBNGetBit(k, bp);
        }

        /* Constant-time table lookup: scan all 16 entries, mask-select the one matching w.    */
        SSFBNSetZero(&picked.x, c->limbs);
        SSFBNSetOne(&picked.y, c->limbs);
        SSFBNSetZero(&picked.z, c->limbs);
        for (i = 0; i < (int32_t)_SSF_EC_VAR_TABLE_N; i++)
        {
            SSFBNLimb_t sel = (SSFBNLimb_t)((uint32_t)i == w);
            SSFBNCondCopy(&picked.x, &table[i].x, sel);
            SSFBNCondCopy(&picked.y, &table[i].y, sel);
            SSFBNCondCopy(&picked.z, &table[i].z, sel);
        }

        /* R = R + table[w] (full Jacobian add — table entries have arbitrary Z). */
        _SSFECPointAddFull(r, r, &picked, c);
    }

    /* Zeroize all scratch — the precomputed table holds [i]*P for the (potentially secret) P, */
    /* and `picked` carried table contents indexed by secret window values.                     */
    for (i = 0; i < (int32_t)_SSF_EC_VAR_TABLE_N; i++)
    {
        SSFBNZeroize(&table[i].x);
        SSFBNZeroize(&table[i].y);
        SSFBNZeroize(&table[i].z);
    }
    SSFBNZeroize(&picked.x);
    SSFBNZeroize(&picked.y);
    SSFBNZeroize(&picked.z);
}

/* --------------------------------------------------------------------------------------------- */
/* Dual scalar multiplication via Shamir's trick: r = u1 * p + u2 * q.                          */
/* NOT constant-time. Intended for ECDSA verify where u1, u2 are public.                         */
/* --------------------------------------------------------------------------------------------- */
void SSFECScalarMulDual(SSFECPoint_t *r,
                        const SSFBN_t *u1, const SSFECPoint_t *p,
                        const SSFBN_t *u2, const SSFECPoint_t *q,
                        SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    /* Precomputation table: [0]=identity, [1]=P, [2]=Q, [3]=P+Q. Backed by four separately-     */
    /* declared SSFECPoint_t locals (each with its own limb storage via SSFECPOINT_DEFINE),       */
    /* indexed through a pointer array so the runtime `idx` lookup still works.                  */
    SSFECPOINT_DEFINE(table0, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(table1, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(table2, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(table3, SSF_EC_MAX_LIMBS);
    SSFECPoint_t *table[4] = { &table0, &table1, &table2, &table3 };
    uint32_t bits;
    int32_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(u1 != NULL);
    SSF_REQUIRE(u1->limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(u2 != NULL);
    SSF_REQUIRE(u2->limbs != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->x.limbs != NULL);
    SSF_REQUIRE(q->y.limbs != NULL);
    SSF_REQUIRE(q->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    bits = (uint32_t)c->limbs * SSF_BN_LIMB_BITS;

    /* Build precomputation table */
    /* table[0] = identity */
    SSFBNSetZero(&table[0]->x, c->limbs);
    SSFBNSetOne(&table[0]->y, c->limbs);
    SSFBNSetZero(&table[0]->z, c->limbs);

    /* table[1] = P */
    SSFBNCopy(&table[1]->x, &p->x);
    SSFBNCopy(&table[1]->y, &p->y);
    SSFBNCopy(&table[1]->z, &p->z);

    /* table[2] = Q */
    SSFBNCopy(&table[2]->x, &q->x);
    SSFBNCopy(&table[2]->y, &q->y);
    SSFBNCopy(&table[2]->z, &q->z);

    /* table[3] = P + Q */
    _SSFECPointAddFull(table[3], table[1], table[2], c);

    /* R = identity */
    SSFBNCopy(&r->x, &table[0]->x);
    SSFBNCopy(&r->y, &table[0]->y);
    SSFBNCopy(&r->z, &table[0]->z);

    /* Interleaved double-and-add */
    for (i = (int32_t)(bits - 1u); i >= 0; i--)
    {
        uint8_t b1 = SSFBNGetBit(u1, (uint32_t)i);
        uint8_t b2 = SSFBNGetBit(u2, (uint32_t)i);
        uint8_t idx = (uint8_t)((b2 << 1) | b1);

        /* R = 2 * R */
        _SSFECPointDouble(r, r, c);

        /* R = R + table[idx] (skip if identity) */
        if (idx != 0u)
        {
            _SSFECPointAddFull(r, r, table[idx], c);
        }
    }
}

#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)

/* --------------------------------------------------------------------------------------------- */
/* Fixed-base scalar multiplication via the Lim-Lee 4-bit comb.                                  */
/*                                                                                                */
/* Decomposition: k (b bits) is split into h=4 strips of d=b/4 bits each. Let G_j = [2^(j*d)] G   */
/* for j in {0, 1, 2, 3}. table[mask] = sum_{j: bit j of mask is set} G_j  for mask in 0..15.    */
/*                                                                                                */
/* Runtime: for j = d-1 down to 0:                                                                */
/*   R = 2 * R                                                                                    */
/*   bits = (k_bit[j] << 0) | (k_bit[j+d] << 1) | (k_bit[j+2d] << 2) | (k_bit[j+3d] << 3)        */
/*   R = R + table[bits]                                                                          */
/* After d iterations R = [k]G. Cost: d doublings + d additions = 2d point ops vs. ~4d in the    */
/* Montgomery ladder — about 2x in raw ops, ~4x end-to-end after constants amortize.             */
/* --------------------------------------------------------------------------------------------- */

#if (SSF_EC_FIXED_BASE_COMB_H != 4u) && (SSF_EC_FIXED_BASE_COMB_H != 5u) && (SSF_EC_FIXED_BASE_COMB_H != 6u)
#error "SSF_EC_FIXED_BASE_COMB_H must be 4, 5, or 6"
#endif

#define _SSF_EC_COMB_H      (SSF_EC_FIXED_BASE_COMB_H)
#define _SSF_EC_COMB_NTABLE (1u << _SSF_EC_COMB_H)

/* Affine-only comb table descriptor: just X and Y (Z is implicitly 1 for the precomputed       */
/* multiples of G; entry 0 is encoded as (0, 1) and treated as the identity by the runtime via  */
/* a CT mask-on-zero override). Dropping Z saves 33% of the comb-table Flash footprint and ~16  */
/* CondCopy operations per comb iteration.                                                       */
typedef struct
{
    SSFBN_t x;
    SSFBN_t y;
} _SSFECCombAffine_t;

/* Common comb runtime. Per-curve wrappers below pass the curve params, the precomputed table,  */
/* and the strip width d.                                                                         */
static void _SSFECScalarMulComb(SSFECPoint_t *r, const SSFBN_t *k,
                                const SSFECCurveParams_t *c,
                                const _SSFECCombAffine_t *table,
                                uint32_t dBits)
{
    SSFECPOINT_DEFINE(picked, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(rSaved, SSF_EC_MAX_LIMBS);
    int32_t j;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(k != NULL);
    SSF_REQUIRE(k->limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(table != NULL);
    SSF_REQUIRE(dBits >= 1u);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    /* R = identity */
    SSFBNSetZero(&r->x, c->limbs);
    SSFBNSetOne(&r->y, c->limbs);
    SSFBNSetZero(&r->z, c->limbs);

    for (j = (int32_t)(dBits - 1u); j >= 0; j--)
    {
        uint8_t mask;
        uint8_t i;
        SSFBNLimb_t maskIsZero;

        _SSFECPointDouble(r, r, c);

        /* Decode the comb mask: bit i of mask = bit (j + i*dBits) of k. j is public.            */
        mask = 0u;
        for (i = 0u; i < (uint8_t)_SSF_EC_COMB_H; i++)
        {
            mask |= (uint8_t)((uint8_t)SSFBNGetBit(k, (uint32_t)j + (uint32_t)i * dBits) << i);
        }

        /* Constant-time table lookup: scan only X and Y (Z is implicitly 1, set below). */
        SSFBNSetZero(&picked.x, c->limbs);
        SSFBNSetZero(&picked.y, c->limbs);
        SSFBNSetOne(&picked.z, c->limbs);
        for (i = 0; i < _SSF_EC_COMB_NTABLE; i++)
        {
            SSFBNLimb_t sel = (SSFBNLimb_t)((uint32_t)i == (uint32_t)mask);
            SSFBNCondCopy(&picked.x, &table[i].x, sel);
            SSFBNCondCopy(&picked.y, &table[i].y, sel);
        }

        /* Save r before the add so we can restore it CT when mask == 0 (the table[0] entry is  */
        /* a sentinel; the mixed-add result is garbage in that case and must be discarded).      */
        SSFBNCopy(&rSaved.x, &r->x);
        SSFBNCopy(&rSaved.y, &r->y);
        SSFBNCopy(&rSaved.z, &r->z);

        /* Mixed-coordinate add (no-double variant): saves an extra full doubling per call vs */
        /* _SSFECPointAddMixed by skipping the precomputed Double(P) used for the P==Q case.  */
        /* The comb-runtime guarantees R != table[mask] statistically (~2^-bits collision      */
        /* probability), so we never need the doubling fallback here.                          */
        _SSFECPointAddMixedNoDouble(r, r, &picked, c);

        /* Restore r when mask == 0 — the add was operating on the (0, 0/1, 1) sentinel and    */
        /* produced garbage. Done CT via the same SSFBNCondCopy primitive used elsewhere.       */
        maskIsZero = (SSFBNLimb_t)((mask == 0u) ? 1u : 0u);
        SSFBNCondCopy(&r->x, &rSaved.x, maskIsZero);
        SSFBNCondCopy(&r->y, &rSaved.y, maskIsZero);
        SSFBNCondCopy(&r->z, &rSaved.z, maskIsZero);
    }

    /* Zeroize scratch — picked carried table contents indexed by secret bits, and rSaved      */
    /* mirrored intermediate r values.                                                           */
    SSFBNZeroize(&picked.x);
    SSFBNZeroize(&picked.y);
    SSFBNZeroize(&picked.z);
    SSFBNZeroize(&rSaved.x);
    SSFBNZeroize(&rSaved.y);
    SSFBNZeroize(&rSaved.z);
}

#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 || SSF_EC_CONFIG_FIXED_BASE_P384 */

/* Per-curve strip width d = ceil(nbits / h). Multiplied by h it covers >= nbits.                */
#define _SSF_EC_P256_COMB_D ((256u + _SSF_EC_COMB_H - 1u) / _SSF_EC_COMB_H)
#define _SSF_EC_P384_COMB_D ((384u + _SSF_EC_COMB_H - 1u) / _SSF_EC_COMB_H)

/* Initializer-list helpers: expand M(0)..M(N-1) inside an aggregate initializer. Used to wire   */
/* up the comb-table descriptors from the storage arrays without writing 16/32/64 lines by hand. */
#define _SSF_EC_LIST_16(M) \
    M( 0),M( 1),M( 2),M( 3),M( 4),M( 5),M( 6),M( 7), \
    M( 8),M( 9),M(10),M(11),M(12),M(13),M(14),M(15)
#define _SSF_EC_LIST_32(M) _SSF_EC_LIST_16(M), \
    M(16),M(17),M(18),M(19),M(20),M(21),M(22),M(23), \
    M(24),M(25),M(26),M(27),M(28),M(29),M(30),M(31)
#define _SSF_EC_LIST_64(M) _SSF_EC_LIST_32(M), \
    M(32),M(33),M(34),M(35),M(36),M(37),M(38),M(39), \
    M(40),M(41),M(42),M(43),M(44),M(45),M(46),M(47), \
    M(48),M(49),M(50),M(51),M(52),M(53),M(54),M(55), \
    M(56),M(57),M(58),M(59),M(60),M(61),M(62),M(63)

#if _SSF_EC_COMB_H == 4u
#define _SSF_EC_LIST_NTABLE(M) _SSF_EC_LIST_16(M)
#elif _SSF_EC_COMB_H == 5u
#define _SSF_EC_LIST_NTABLE(M) _SSF_EC_LIST_32(M)
#elif _SSF_EC_COMB_H == 6u
#define _SSF_EC_LIST_NTABLE(M) _SSF_EC_LIST_64(M)
#endif

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1

#if _SSF_EC_COMB_H == 4u
#  include "ssfec_p256_comb_table_h4.h"
#elif _SSF_EC_COMB_H == 5u
#  include "ssfec_p256_comb_table_h5.h"
#elif _SSF_EC_COMB_H == 6u
#  include "ssfec_p256_comb_table_h6.h"
#endif

#define _SSF_EC_P256_COMB_ENTRY(idx)                                              \
    {                                                                             \
        { (SSFBNLimb_t *)_ssfECP256CombStorage[(idx)][0], 8u, 8u },               \
        { (SSFBNLimb_t *)_ssfECP256CombStorage[(idx)][1], 8u, 8u },               \
    }

/* Descriptor table — const, lives in .rodata next to the storage. The const-cast on .limbs is */
/* safe because every consumer of these descriptors only READS through them.                    */
static const _SSFECCombAffine_t _ssfECP256CombTable[_SSF_EC_COMB_NTABLE] = {
    _SSF_EC_LIST_NTABLE(_SSF_EC_P256_COMB_ENTRY)
};

void SSFECScalarMulBaseP256(SSFECPoint_t *r, const SSFBN_t *k)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(k != NULL);
    SSF_REQUIRE(k->limbs != NULL);
    SSF_REQUIRE(r->x.cap >= 8u);
    SSF_REQUIRE(r->y.cap >= 8u);
    SSF_REQUIRE(r->z.cap >= 8u);
    _SSFECScalarMulComb(r, k, SSFECGetCurveParams(SSF_EC_CURVE_P256),
                        _ssfECP256CombTable, _SSF_EC_P256_COMB_D);
}

#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1

#if _SSF_EC_COMB_H == 4u
#  include "ssfec_p384_comb_table_h4.h"
#elif _SSF_EC_COMB_H == 5u
#  include "ssfec_p384_comb_table_h5.h"
#elif _SSF_EC_COMB_H == 6u
#  include "ssfec_p384_comb_table_h6.h"
#endif

#define _SSF_EC_P384_COMB_ENTRY(idx)                                                \
    {                                                                               \
        { (SSFBNLimb_t *)_ssfECP384CombStorage[(idx)][0], 12u, 12u },               \
        { (SSFBNLimb_t *)_ssfECP384CombStorage[(idx)][1], 12u, 12u },               \
    }

static const _SSFECCombAffine_t _ssfECP384CombTable[_SSF_EC_COMB_NTABLE] = {
    _SSF_EC_LIST_NTABLE(_SSF_EC_P384_COMB_ENTRY)
};

void SSFECScalarMulBaseP384(SSFECPoint_t *r, const SSFBN_t *k)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(k != NULL);
    SSF_REQUIRE(k->limbs != NULL);
    SSF_REQUIRE(r->x.cap >= 12u);
    SSF_REQUIRE(r->y.cap >= 12u);
    SSF_REQUIRE(r->z.cap >= 12u);
    _SSFECScalarMulComb(r, k, SSFECGetCurveParams(SSF_EC_CURVE_P384),
                        _ssfECP384CombTable, _SSF_EC_P384_COMB_D);
}

#endif /* SSF_EC_CONFIG_FIXED_BASE_P384 */

#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)

/* --------------------------------------------------------------------------------------------- */
/* Internal: variable-time scalar multiplication via 5-bit signed-digit wNAF.                    */
/*                                                                                                */
/* PUBLIC-INPUT ONLY — timing depends on the bit pattern of k. Faster than the constant-time     */
/* windowed SSFECScalarMul because:                                                              */
/*   - wNAF density is ~1/(w+1) = 1/6 nonzero digits (vs every 4-bit window in the CT path).     */
/*   - Only odd multiples are precomputed: [1]P, [3]P, ..., [15]P (8 entries vs 15).             */
/*   - No constant-time table scan — direct indexed access.                                      */
/*   - Skips the add entirely when the digit is 0.                                                */
/*                                                                                                */
/* Total: ~bits doublings + ~bits/6 additions vs the CT path's ~bits doublings + ~bits/4 adds    */
/* with full table scans. Roughly 2x faster on the variable-base half.                            */
/* --------------------------------------------------------------------------------------------- */
#define _SSF_EC_VTWNAF_W            (5u)
#define _SSF_EC_VTWNAF_TABLE_SIZE   (1u << (_SSF_EC_VTWNAF_W - 2u)) /* 8 odd multiples */
#define _SSF_EC_VTWNAF_MAX_DIGITS   ((SSF_EC_MAX_COORD_BYTES * 8u) + 1u)

static void _SSFECScalarMulVTwNAF(SSFECPoint_t *r, const SSFBN_t *k,
                                  const SSFECPoint_t *p, const SSFECCurveParams_t *c)
{
    SSFBNLimb_t tableStorage[_SSF_EC_VTWNAF_TABLE_SIZE][3][SSF_EC_MAX_LIMBS];
    SSFECPoint_t table[_SSF_EC_VTWNAF_TABLE_SIZE]; /* table[i] = [(2i+1)] P */
    SSFECPOINT_DEFINE(twoP, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(neg, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(kCopy, SSF_EC_MAX_LIMBS);
    int8_t digits[_SSF_EC_VTWNAF_MAX_DIGITS];
    int32_t nDigits = 0;
    int32_t i;
    bool inputAffine; /* true when caller's P has Z = 1 (e.g. from PointDecode / PointFromAffine) */

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(k != NULL);
    SSF_REQUIRE(k->limbs != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->x.limbs != NULL);
    SSF_REQUIRE(p->y.limbs != NULL);
    SSF_REQUIRE(p->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

    /* Wire up table descriptors. */
    for (i = 0; i < (int32_t)_SSF_EC_VTWNAF_TABLE_SIZE; i++)
    {
        table[i].x.limbs = tableStorage[i][0]; table[i].x.cap = SSF_EC_MAX_LIMBS; table[i].x.len = 0u;
        table[i].y.limbs = tableStorage[i][1]; table[i].y.cap = SSF_EC_MAX_LIMBS; table[i].y.len = 0u;
        table[i].z.limbs = tableStorage[i][2]; table[i].z.cap = SSF_EC_MAX_LIMBS; table[i].z.len = 0u;
    }

    /* Precompute table[0] = P, twoP = 2P, table[i] = table[i-1] + 2P  for i = 1..7.            */
    SSFBNCopy(&table[0].x, &p->x);
    SSFBNCopy(&table[0].y, &p->y);
    SSFBNCopy(&table[0].z, &p->z);
    inputAffine = (table[0].z.len >= 1u) && SSFBNIsOne(&table[0].z);
    _SSFECPointDouble(&twoP, p, c);
    /* First add: table[1] = table[0] + twoP. If P is affine, mixed-add saves 3 muls + 1 sq.    */
    if (inputAffine)
    {
        _SSFECPointAddMixed(&table[1], &twoP, &table[0], c);
    }
    else
    {
        _SSFECPointAddFull(&table[1], &table[0], &twoP, c);
    }
    /* Subsequent table[i] for i >= 2: both operands are Jacobian (twoP and table[i-1]). */
    for (i = 2; i < (int32_t)_SSF_EC_VTWNAF_TABLE_SIZE; i++)
    {
        _SSFECPointAddFull(&table[i], &table[i - 1], &twoP, c);
    }

    /* Compute wNAF digits. Digits are emitted LSB-first, processed MSB-first below.            */
    SSFBNCopy(&kCopy, k);
    kCopy.len = c->limbs;
    while (!SSFBNIsZero(&kCopy))
    {
        int8_t d;
        if ((kCopy.limbs[0] & 1u) != 0u)
        {
            uint32_t lo = kCopy.limbs[0] & ((1u << _SSF_EC_VTWNAF_W) - 1u); /* low 5 bits */
            if (lo >= (1u << (_SSF_EC_VTWNAF_W - 1u)))
            {
                /* Map to negative: lo - 32 */
                d = (int8_t)((int32_t)lo - (1 << _SSF_EC_VTWNAF_W));
                /* kCopy -= d  ==  kCopy += |d| */
                (void)SSFBNAddUint32(&kCopy, &kCopy, (uint32_t)(-(int32_t)d));
            }
            else
            {
                d = (int8_t)lo;
                /* kCopy -= d */
                (void)SSFBNSubUint32(&kCopy, &kCopy, (uint32_t)d);
            }
        }
        else
        {
            d = 0;
        }
        if (nDigits < (int32_t)_SSF_EC_VTWNAF_MAX_DIGITS)
        {
            digits[nDigits++] = d;
        }
        SSFBNShiftRight1(&kCopy);
    }

    /* R = identity */
    SSFBNSetZero(&r->x, c->limbs);
    SSFBNSetOne(&r->y, c->limbs);
    SSFBNSetZero(&r->z, c->limbs);

    /* Process digits MSB-first. table[0] = P; if P was affine (Z=1), use mixed-add when this  */
    /* digit selects ±table[0]. All other table entries are Jacobian (built via PointAddFull). */
    for (i = nDigits - 1; i >= 0; i--)
    {
        int8_t d = digits[i];
        _SSFECPointDouble(r, r, c);
        if (d > 0)
        {
            int32_t idx = (d - 1) / 2;
            if ((idx == 0) && inputAffine)
            {
                _SSFECPointAddMixed(r, r, &table[0], c);
            }
            else
            {
                _SSFECPointAddFull(r, r, &table[idx], c);
            }
        }
        else if (d < 0)
        {
            int32_t idx = (-d - 1) / 2;
            /* neg = -table[idx] = (X, p - Y, Z) */
            SSFBNCopy(&neg.x, &table[idx].x);
            SSFBNSub(&neg.y, &c->p, &table[idx].y);
            SSFBNCopy(&neg.z, &table[idx].z);
            if ((idx == 0) && inputAffine)
            {
                _SSFECPointAddMixed(r, r, &neg, c);
            }
            else
            {
                _SSFECPointAddFull(r, r, &neg, c);
            }
        }
    }
}

#if SSF_CONFIG_EC_UNIT_TEST == 1
void _SSFECScalarMulVTwNAFForTest(SSFECPoint_t *r, const SSFBN_t *k,
                                  const SSFECPoint_t *p, SSFECCurve_t curve)
{
    _SSFECScalarMulVTwNAF(r, k, p, SSFECGetCurveParams(curve));
}
#endif

/* --------------------------------------------------------------------------------------------- */
/* Specialized dual scalar mul for ECDSA verify: r = u1 * G + u2 * q.                            */
/*                                                                                                */
/* Strategy: split the work into two single-scalar muls and a final point add. The first half    */
/* uses the fixed-base comb table for [u1]G (when configured for the curve), and the second half */
/* uses variable-time wNAF for [u2]q (~2x faster than the CT windowed routine). Both inputs are  */
/* derived from public ECDSA verify data, so leaking timing on u2 is safe by construction.        */
/* --------------------------------------------------------------------------------------------- */
void SSFECScalarMulDualBase(SSFECPoint_t *r,
                            const SSFBN_t *u1,
                            const SSFBN_t *u2, const SSFECPoint_t *q,
                            SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFECPOINT_DEFINE(R1, SSF_EC_MAX_LIMBS); /* [u1] G          */
    SSFECPOINT_DEFINE(R2, SSF_EC_MAX_LIMBS); /* [u2] q          */
    bool didFixedBase = false;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->x.limbs != NULL);
    SSF_REQUIRE(r->y.limbs != NULL);
    SSF_REQUIRE(r->z.limbs != NULL);
    SSF_REQUIRE(u1 != NULL);
    SSF_REQUIRE(u1->limbs != NULL);
    SSF_REQUIRE(u2 != NULL);
    SSF_REQUIRE(u2->limbs != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->x.limbs != NULL);
    SSF_REQUIRE(q->y.limbs != NULL);
    SSF_REQUIRE(q->z.limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r->x.cap >= c->limbs);
    SSF_REQUIRE(r->y.cap >= c->limbs);
    SSF_REQUIRE(r->z.cap >= c->limbs);

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    if (curve == SSF_EC_CURVE_P256)
    {
        SSFECScalarMulBaseP256(&R1, u1);
        didFixedBase = true;
    }
#endif
#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
    if (curve == SSF_EC_CURVE_P384)
    {
        SSFECScalarMulBaseP384(&R1, u1);
        didFixedBase = true;
    }
#endif

    if (!didFixedBase)
    {
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, curve);
        SSFECScalarMul(&R1, u1, &G, curve);
    }

    /* [u2] q via the variable-time wNAF (faster than the CT path; safe because u2 is public). */
    _SSFECScalarMulVTwNAF(&R2, u2, q, c);

    /* r = R1 + R2 */
    SSFECPointAdd(r, &R1, &R2, curve);

    /* Inputs are public, but zeroizing is cheap and consistent with the rest of the module. */
    SSFBNZeroize(&R1.x); SSFBNZeroize(&R1.y); SSFBNZeroize(&R1.z);
    SSFBNZeroize(&R2.x); SSFBNZeroize(&R2.y); SSFBNZeroize(&R2.z);
}

#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 || SSF_EC_CONFIG_FIXED_BASE_P384 */
