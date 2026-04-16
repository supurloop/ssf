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
static const SSFECCurveParams_t _ssfECP256 =
{
    /* p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF */
    { { 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
        0x00000000ul, 0x00000000ul, 0x00000001ul, 0xFFFFFFFFul }, 8 },
    /* a = p - 3 */
    { { 0xFFFFFFFCul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
        0x00000000ul, 0x00000000ul, 0x00000001ul, 0xFFFFFFFFul }, 8 },
    /* b = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B */
    { { 0x27D2604Bul, 0x3BCE3C3Eul, 0xCC53B0F6ul, 0x651D06B0ul,
        0x769886BCul, 0xB3EBBD55ul, 0xAA3A93E7ul, 0x5AC635D8ul }, 8 },
    /* Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 */
    { { 0xD898C296ul, 0xF4A13945ul, 0x2DEB33A0ul, 0x77037D81ul,
        0x63A440F2ul, 0xF8BCE6E5ul, 0xE12C4247ul, 0x6B17D1F2ul }, 8 },
    /* Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 */
    { { 0x37BF51F5ul, 0xCBB64068ul, 0x6B315ECEul, 0x2BCE3357ul,
        0x7C0F9E16ul, 0x8EE7EB4Aul, 0xFE1A7F9Bul, 0x4FE342E2ul }, 8 },
    /* n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 */
    { { 0xFC632551ul, 0xF3B9CAC2ul, 0xA7179E84ul, 0xBCE6FAADul,
        0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul, 0xFFFFFFFFul }, 8 },
    8,   /* limbs */
    32   /* bytes */
};
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

/* --------------------------------------------------------------------------------------------- */
/* P-384 / secp384r1 parameters                                                                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
static const SSFECCurveParams_t _ssfECP384 =
{
    /* p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE */
    /*     FFFFFFFF0000000000000000FFFFFFFF                                   */
    { { 0xFFFFFFFFul, 0x00000000ul, 0x00000000ul, 0xFFFFFFFFul,
        0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
        0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul }, 12 },
    /* a = p - 3 */
    { { 0xFFFFFFFCul, 0x00000000ul, 0x00000000ul, 0xFFFFFFFFul,
        0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
        0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul }, 12 },
    /* b = B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A */
    /*     C656398D8A2ED19D2A85C8EDD3EC2AEF                                   */
    { { 0xD3EC2AEFul, 0x2A85C8EDul, 0x8A2ED19Dul, 0xC656398Dul,
        0x5013875Aul, 0x0314088Ful, 0xFE814112ul, 0x181D9C6Eul,
        0xE3F82D19ul, 0x988E056Bul, 0xE23EE7E4ul, 0xB3312FA7ul }, 12 },
    /* Gx = AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38 */
    /*      5502F25DBF55296C3A545E3872760AB7                                   */
    { { 0x72760AB7ul, 0x3A545E38ul, 0xBF55296Cul, 0x5502F25Dul,
        0x82542A38ul, 0x59F741E0ul, 0x8BA79B98ul, 0x6E1D3B62ul,
        0xF320AD74ul, 0x8EB1C71Eul, 0xBE8B0537ul, 0xAA87CA22ul }, 12 },
    /* Gy = 3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0 */
    /*      0A60B1CE1D7E819D7A431D7C90EA0E5F                                   */
    { { 0x90EA0E5Ful, 0x7A431D7Cul, 0x1D7E819Dul, 0x0A60B1CEul,
        0xB5F0B8C0ul, 0xE9DA3113ul, 0x289A147Cul, 0xF8F41DBDul,
        0x9292DC29ul, 0x5D9E98BFul, 0x96262C6Ful, 0x3617DE4Aul }, 12 },
    /* n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB2 */
    /*     48B0A77AECEC196ACCC52973                                           */
    { { 0xCCC52973ul, 0xECEC196Aul, 0x48B0A77Aul, 0x581A0DB2ul,
        0xF4372DDFul, 0xC7634D81ul, 0xFFFFFFFFul, 0xFFFFFFFFul,
        0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul }, 12 },
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
    SSFBN_t delta, gamma, beta, alpha, tmp;

    /* Identity doubles to identity */
    if (SSFBNIsZero(&p->z))
    {
        SSFBNSetZero(&r->x, c->limbs);
        SSFBNSetUint32(&r->y, 1u, c->limbs);
        SSFBNSetZero(&r->z, c->limbs);
        return;
    }

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
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: point addition in full Jacobian coordinates.                                        */
/* Standard formulas: 12M + 4S.                                                                  */
/* r may alias p or q.                                                                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECPointAddFull(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                               const SSFECCurveParams_t *c)
{
    SSFBN_t t1, t2, t3, t4, t5, t6;

    /* P = identity: return Q */
    if (SSFBNIsZero(&p->z))
    {
        SSFBNCopy(&r->x, &q->x);
        SSFBNCopy(&r->y, &q->y);
        SSFBNCopy(&r->z, &q->z);
        return;
    }

    /* Q = identity: return P */
    if (SSFBNIsZero(&q->z))
    {
        SSFBNCopy(&r->x, &p->x);
        SSFBNCopy(&r->y, &p->y);
        SSFBNCopy(&r->z, &p->z);
        return;
    }

    /* z1_sq = Z1^2, z2_sq = Z2^2 */
    SSFBNModMulNIST(&t1, &p->z, &p->z, &c->p);   /* t1 = Z1^2 */
    SSFBNModMulNIST(&t2, &q->z, &q->z, &c->p);   /* t2 = Z2^2 */

    /* z1_cu = Z1 * Z1^2, z2_cu = Z2 * Z2^2 */
    SSFBNModMulNIST(&t3, &p->z, &t1, &c->p);     /* t3 = Z1^3 */
    SSFBNModMulNIST(&t4, &q->z, &t2, &c->p);     /* t4 = Z2^3 */

    /* U1 = X1 * Z2^2, U2 = X2 * Z1^2 */
    SSFBNModMulNIST(&t5, &p->x, &t2, &c->p);     /* t5 = U1 = X1*Z2^2 */
    SSFBNModMulNIST(&t2, &q->x, &t1, &c->p);     /* t2 = U2 = X2*Z1^2 (reuse t2) */

    /* S1 = Y1 * Z2^3, S2 = Y2 * Z1^3 */
    SSFBNModMulNIST(&t1, &p->y, &t4, &c->p);     /* t1 = S1 = Y1*Z2^3 (reuse t1) */
    SSFBNModMulNIST(&t4, &q->y, &t3, &c->p);     /* t4 = S2 = Y2*Z1^3 (reuse t4) */

    /* H = U2 - U1, R = S2 - S1 */
    SSFBNModSub(&t3, &t2, &t5, &c->p);            /* t3 = H = U2 - U1 (reuse t3) */
    SSFBNModSub(&t2, &t4, &t1, &c->p);            /* t2 = R = S2 - S1 (reuse t2) */

    /* Check for special cases: H == 0 means X coordinates match */
    if (SSFBNIsZero(&t3))
    {
        if (SSFBNIsZero(&t2))
        {
            /* P == Q: use doubling */
            _SSFECPointDouble(r, p, c);
            return;
        }
        /* P == -Q: result is identity */
        SSFBNSetZero(&r->x, c->limbs);
        SSFBNSetUint32(&r->y, 1u, c->limbs);
        SSFBNSetZero(&r->z, c->limbs);
        return;
    }

    /* t4 = H^2 */
    SSFBNModMulNIST(&t4, &t3, &t3, &c->p);       /* t4 = H^2 */

    /* t6 = H^3 = H * H^2 */
    SSFBNModMulNIST(&t6, &t3, &t4, &c->p);        /* t6 = H^3 */

    /* U1H2 = U1 * H^2 */
    SSFBNModMulNIST(&t5, &t5, &t4, &c->p);        /* t5 = U1*H^2 (reuse t5, was U1) */

    /* Z3 = Z1 * Z2 * H */
    /* Compute before writing r->x, r->y in case r aliases p or q */
    SSFBNModMulNIST(&r->z, &p->z, &q->z, &c->p); /* Z1 * Z2 */
    SSFBNModMulNIST(&r->z, &r->z, &t3, &c->p);   /* Z1 * Z2 * H */

    /* X3 = R^2 - H^3 - 2 * U1H2 */
    SSFBNModMulNIST(&r->x, &t2, &t2, &c->p);     /* R^2 */
    SSFBNModSub(&r->x, &r->x, &t6, &c->p);       /* R^2 - H^3 */
    SSFBNModAdd(&t4, &t5, &t5, &c->p);            /* 2 * U1H2 (reuse t4) */
    SSFBNModSub(&r->x, &r->x, &t4, &c->p);       /* X3 */

    /* Y3 = R * (U1H2 - X3) - S1 * H^3 */
    SSFBNModSub(&t5, &t5, &r->x, &c->p);          /* U1H2 - X3 */
    SSFBNModMulNIST(&t5, &t2, &t5, &c->p);        /* R * (U1H2 - X3) */
    SSFBNModMulNIST(&t1, &t1, &t6, &c->p);        /* S1 * H^3 (t1 was S1) */
    SSFBNModSub(&r->y, &t5, &t1, &c->p);          /* Y3 */
}

/* --------------------------------------------------------------------------------------------- */
/* Set point to identity.                                                                        */
/* --------------------------------------------------------------------------------------------- */
void SSFECPointSetIdentity(SSFECPoint_t *pt, SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);

    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(c != NULL);

    SSFBNSetZero(&pt->x, c->limbs);
    SSFBNSetUint32(&pt->y, 1u, c->limbs);
    SSFBNSetZero(&pt->z, c->limbs);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if point is identity (Z == 0).                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointIsIdentity(const SSFECPoint_t *pt)
{
    SSF_REQUIRE(pt != NULL);

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
    SSF_REQUIRE(x != NULL);
    SSF_REQUIRE(y != NULL);
    SSF_REQUIRE(c != NULL);

    SSFBNCopy(&pt->x, x);
    SSFBNCopy(&pt->y, y);
    SSFBNSetUint32(&pt->z, 1u, c->limbs);
}

/* --------------------------------------------------------------------------------------------- */
/* Convert Jacobian point to affine: x = X/Z^2, y = Y/Z^3.                                      */
/* Returns false if point is identity (no finite affine representation).                         */
/* --------------------------------------------------------------------------------------------- */
bool SSFECPointToAffine(SSFBN_t *x, SSFBN_t *y, const SSFECPoint_t *pt, SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_t zInv, zInv2, zInv3;

    SSF_REQUIRE(x != NULL);
    SSF_REQUIRE(y != NULL);
    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(c != NULL);

    if (SSFBNIsZero(&pt->z)) return false;

    /* Fast path: Z == 1 (already affine) */
    if (SSFBNIsOne(&pt->z))
    {
        SSFBNCopy(x, &pt->x);
        SSFBNCopy(y, &pt->y);
        return true;
    }

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
    SSFBN_t ax, ay, lhs, rhs, tmp;

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
    SSFBN_t ax, ay;

    SSF_REQUIRE(pt != NULL);
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
    SSFBN_t ax, ay;

    SSF_REQUIRE(pt != NULL);
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
    SSF_REQUIRE(data != NULL);
    SSF_REQUIRE(c != NULL);

    encLen = 1u + 2u * (size_t)c->bytes;
    if (dataLen != encLen) return false;

    /* Must be uncompressed format */
    if (data[0] != 0x04u) return false;

    /* Import X and Y */
    if (!SSFBNFromBytes(&pt->x, &data[1], c->bytes, c->limbs)) return false;
    if (!SSFBNFromBytes(&pt->y, &data[1u + c->bytes], c->bytes, c->limbs)) return false;

    /* Z = 1 (affine) */
    SSFBNSetUint32(&pt->z, 1u, c->limbs);

    /* Validate the point */
    if (!SSFECPointValidate(pt, curve)) return false;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Point addition: r = p + q (Jacobian).                                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFECPointAdd(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                   SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(c != NULL);

    _SSFECPointAddFull(r, p, q, c);
}

/* --------------------------------------------------------------------------------------------- */
/* Constant-time scalar multiplication via Montgomery ladder: r = k * p.                         */
/* k must be in [1, n-1]. Iterates over all bits of the curve's limb width for constant time.    */
/* --------------------------------------------------------------------------------------------- */
void SSFECScalarMul(SSFECPoint_t *r, const SSFBN_t *k, const SSFECPoint_t *p,
                    SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFECPoint_t R0, R1;
    uint32_t bits;
    int32_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(k != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(c != NULL);

    bits = (uint32_t)c->limbs * SSF_BN_LIMB_BITS;

    /* R0 = identity, R1 = P */
    SSFBNSetZero(&R0.x, c->limbs);
    SSFBNSetUint32(&R0.y, 1u, c->limbs);
    SSFBNSetZero(&R0.z, c->limbs);
    SSFBNCopy(&R1.x, &p->x);
    SSFBNCopy(&R1.y, &p->y);
    SSFBNCopy(&R1.z, &p->z);

    /* Montgomery ladder: process every bit for constant time */
    for (i = (int32_t)(bits - 1u); i >= 0; i--)
    {
        SSFBNLimb_t bit = (SSFBNLimb_t)SSFBNGetBit(k, (uint32_t)i);

        /* Conditional swap based on current bit */
        SSFBNCondSwap(&R0.x, &R1.x, bit);
        SSFBNCondSwap(&R0.y, &R1.y, bit);
        SSFBNCondSwap(&R0.z, &R1.z, bit);

        /* R1 = R0 + R1, R0 = 2 * R0 */
        _SSFECPointAddFull(&R1, &R0, &R1, c);
        _SSFECPointDouble(&R0, &R0, c);

        /* Swap back */
        SSFBNCondSwap(&R0.x, &R1.x, bit);
        SSFBNCondSwap(&R0.y, &R1.y, bit);
        SSFBNCondSwap(&R0.z, &R1.z, bit);
    }

    /* Copy result */
    SSFBNCopy(&r->x, &R0.x);
    SSFBNCopy(&r->y, &R0.y);
    SSFBNCopy(&r->z, &R0.z);

    /* Zeroize temporaries that may contain key-derived data */
    SSFBNZeroize(&R0.x); SSFBNZeroize(&R0.y); SSFBNZeroize(&R0.z);
    SSFBNZeroize(&R1.x); SSFBNZeroize(&R1.y); SSFBNZeroize(&R1.z);
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
    SSFECPoint_t table[4]; /* [0]=identity, [1]=P, [2]=Q, [3]=P+Q */
    uint32_t bits;
    int32_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(u1 != NULL);
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(u2 != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(c != NULL);

    bits = (uint32_t)c->limbs * SSF_BN_LIMB_BITS;

    /* Build precomputation table */
    /* table[0] = identity */
    SSFBNSetZero(&table[0].x, c->limbs);
    SSFBNSetUint32(&table[0].y, 1u, c->limbs);
    SSFBNSetZero(&table[0].z, c->limbs);

    /* table[1] = P */
    SSFBNCopy(&table[1].x, &p->x);
    SSFBNCopy(&table[1].y, &p->y);
    SSFBNCopy(&table[1].z, &p->z);

    /* table[2] = Q */
    SSFBNCopy(&table[2].x, &q->x);
    SSFBNCopy(&table[2].y, &q->y);
    SSFBNCopy(&table[2].z, &q->z);

    /* table[3] = P + Q */
    _SSFECPointAddFull(&table[3], &table[1], &table[2], c);

    /* R = identity */
    SSFBNCopy(&r->x, &table[0].x);
    SSFBNCopy(&r->y, &table[0].y);
    SSFBNCopy(&r->z, &table[0].z);

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
            _SSFECPointAddFull(r, r, &table[idx], c);
        }
    }
}
