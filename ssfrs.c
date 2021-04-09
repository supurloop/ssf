/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrs.c                                                                                       */
/* Provides Reed-Solomon FEC encoder/decoder interface.                                          */
/*                                                                                               */
/* Limitations:                                                                                  */
/*     Decode interface does not support erasure corrections, only error corrections.            */
/*     Eraseure corrections are only useful if the location of an error is known.                */
/*                                                                                               */
/* Reed-Solomon algorithms and code inspired and adapted from:                                   */
/*     https://en.wikiversity.org/wiki/Reed-Solomon_codes_for_coders                             */
/*                                                                                               */
/* MOD255 macro algorithm inspired and adapted from:                                             */
/*     http://homepage.cs.uiowa.edu/~jones/bcd/mod.shtml                                         */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2021 Supurloop Software LLC                                                         */
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
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "ssfrs.h"
#include "ssfassert.h"
#include "ssf.h"

/* --------------------------------------------------------------------------------------------- */
/* Galois Field GF(2^8) Base Operations */
/* --------------------------------------------------------------------------------------------- */

/* GF(2^8) logorithm lookup table */
static const uint8_t _gfLog[256] =
{
    0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1A, 0xC6, 0x03, 0xDF, 0x33, 0xEE, 0x1B, 0x68, 0xC7, 0x4B,
    0x04, 0x64, 0xE0, 0x0E, 0x34, 0x8D, 0xEF, 0x81, 0x1C, 0xC1, 0x69, 0xF8, 0xC8, 0x08, 0x4C, 0x71,
    0x05, 0x8A, 0x65, 0x2F, 0xE1, 0x24, 0x0F, 0x21, 0x35, 0x93, 0x8E, 0xDA, 0xF0, 0x12, 0x82, 0x45,
    0x1D, 0xB5, 0xC2, 0x7D, 0x6A, 0x27, 0xF9, 0xB9, 0xC9, 0x9A, 0x09, 0x78, 0x4D, 0xE4, 0x72, 0xA6,
    0x06, 0xBF, 0x8B, 0x62, 0x66, 0xDD, 0x30, 0xFD, 0xE2, 0x98, 0x25, 0xB3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xD0, 0x94, 0xCE, 0x8F, 0x96, 0xDB, 0xBD, 0xF1, 0xD2, 0x13, 0x5C, 0x83, 0x38, 0x46, 0x40,
    0x1E, 0x42, 0xB6, 0xA3, 0xC3, 0x48, 0x7E, 0x6E, 0x6B, 0x3A, 0x28, 0x54, 0xFA, 0x85, 0xBA, 0x3D,
    0xCA, 0x5E, 0x9B, 0x9F, 0x0A, 0x15, 0x79, 0x2B, 0x4E, 0xD4, 0xE5, 0xAC, 0x73, 0xF3, 0xA7, 0x57,
    0x07, 0x70, 0xC0, 0xF7, 0x8C, 0x80, 0x63, 0x0D, 0x67, 0x4A, 0xDE, 0xED, 0x31, 0xC5, 0xFE, 0x18,
    0xE3, 0xA5, 0x99, 0x77, 0x26, 0xB8, 0xB4, 0x7C, 0x11, 0x44, 0x92, 0xD9, 0x23, 0x20, 0x89, 0x2E,
    0x37, 0x3F, 0xD1, 0x5B, 0x95, 0xBC, 0xCF, 0xCD, 0x90, 0x87, 0x97, 0xB2, 0xDC, 0xFC, 0xBE, 0x61,
    0xF2, 0x56, 0xD3, 0xAB, 0x14, 0x2A, 0x5D, 0x9E, 0x84, 0x3C, 0x39, 0x53, 0x47, 0x6D, 0x41, 0xA2,
    0x1F, 0x2D, 0x43, 0xD8, 0xB7, 0x7B, 0xA4, 0x76, 0xC4, 0x17, 0x49, 0xEC, 0x7F, 0x0C, 0x6F, 0xF6,
    0x6C, 0xA1, 0x3B, 0x52, 0x29, 0x9D, 0x55, 0xAA, 0xFB, 0x60, 0x86, 0xB1, 0xBB, 0xCC, 0x3E, 0x5A,
    0xCB, 0x59, 0x5F, 0xB0, 0x9C, 0xA9, 0xA0, 0x51, 0x0B, 0xF5, 0x16, 0xEB, 0x7A, 0x75, 0x2C, 0xD7,
    0x4F, 0xAE, 0xD5, 0xE9, 0xE6, 0xE7, 0xAD, 0xE8, 0x74, 0xD6, 0xF4, 0xEA, 0xA8, 0x50, 0x58, 0xAF
};

/* GF(2^8) exponent lookup table */
static const uint8_t _gfExp[512] =
{
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1D, 0x3A, 0x74, 0xE8, 0xCD, 0x87, 0x13, 0x26,
    0x4C, 0x98, 0x2D, 0x5A, 0xB4, 0x75, 0xEA, 0xC9, 0x8F, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0,
    0x9D, 0x27, 0x4E, 0x9C, 0x25, 0x4A, 0x94, 0x35, 0x6A, 0xD4, 0xB5, 0x77, 0xEE, 0xC1, 0x9F, 0x23,
    0x46, 0x8C, 0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x5D, 0xBA, 0x69, 0xD2, 0xB9, 0x6F, 0xDE, 0xA1,
    0x5F, 0xBE, 0x61, 0xC2, 0x99, 0x2F, 0x5E, 0xBC, 0x65, 0xCA, 0x89, 0x0F, 0x1E, 0x3C, 0x78, 0xF0,
    0xFD, 0xE7, 0xD3, 0xBB, 0x6B, 0xD6, 0xB1, 0x7F, 0xFE, 0xE1, 0xDF, 0xA3, 0x5B, 0xB6, 0x71, 0xE2,
    0xD9, 0xAF, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBD, 0x67, 0xCE,
    0x81, 0x1F, 0x3E, 0x7C, 0xF8, 0xED, 0xC7, 0x93, 0x3B, 0x76, 0xEC, 0xC5, 0x97, 0x33, 0x66, 0xCC,
    0x85, 0x17, 0x2E, 0x5C, 0xB8, 0x6D, 0xDA, 0xA9, 0x4F, 0x9E, 0x21, 0x42, 0x84, 0x15, 0x2A, 0x54,
    0xA8, 0x4D, 0x9A, 0x29, 0x52, 0xA4, 0x55, 0xAA, 0x49, 0x92, 0x39, 0x72, 0xE4, 0xD5, 0xB7, 0x73,
    0xE6, 0xD1, 0xBF, 0x63, 0xC6, 0x91, 0x3F, 0x7E, 0xFC, 0xE5, 0xD7, 0xB3, 0x7B, 0xF6, 0xF1, 0xFF,
    0xE3, 0xDB, 0xAB, 0x4B, 0x96, 0x31, 0x62, 0xC4, 0x95, 0x37, 0x6E, 0xDC, 0xA5, 0x57, 0xAE, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xC8, 0x8D, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDD, 0xA7, 0x53, 0xA6,
    0x51, 0xA2, 0x59, 0xB2, 0x79, 0xF2, 0xF9, 0xEF, 0xC3, 0x9B, 0x2B, 0x56, 0xAC, 0x45, 0x8A, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3D, 0x7A, 0xF4, 0xF5, 0xF7, 0xF3, 0xFB, 0xEB, 0xCB, 0x8B, 0x0B, 0x16,
    0x2C, 0x58, 0xB0, 0x7D, 0xFA, 0xE9, 0xCF, 0x83, 0x1B, 0x36, 0x6C, 0xD8, 0xAD, 0x47, 0x8E, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1D, 0x3A, 0x74, 0xE8, 0xCD, 0x87, 0x13, 0x26, 0x4C,
    0x98, 0x2D, 0x5A, 0xB4, 0x75, 0xEA, 0xC9, 0x8F, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x9D,
    0x27, 0x4E, 0x9C, 0x25, 0x4A, 0x94, 0x35, 0x6A, 0xD4, 0xB5, 0x77, 0xEE, 0xC1, 0x9F, 0x23, 0x46,
    0x8C, 0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x5D, 0xBA, 0x69, 0xD2, 0xB9, 0x6F, 0xDE, 0xA1, 0x5F,
    0xBE, 0x61, 0xC2, 0x99, 0x2F, 0x5E, 0xBC, 0x65, 0xCA, 0x89, 0x0F, 0x1E, 0x3C, 0x78, 0xF0, 0xFD,
    0xE7, 0xD3, 0xBB, 0x6B, 0xD6, 0xB1, 0x7F, 0xFE, 0xE1, 0xDF, 0xA3, 0x5B, 0xB6, 0x71, 0xE2, 0xD9,
    0xAF, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBD, 0x67, 0xCE, 0x81,
    0x1F, 0x3E, 0x7C, 0xF8, 0xED, 0xC7, 0x93, 0x3B, 0x76, 0xEC, 0xC5, 0x97, 0x33, 0x66, 0xCC, 0x85,
    0x17, 0x2E, 0x5C, 0xB8, 0x6D, 0xDA, 0xA9, 0x4F, 0x9E, 0x21, 0x42, 0x84, 0x15, 0x2A, 0x54, 0xA8,
    0x4D, 0x9A, 0x29, 0x52, 0xA4, 0x55, 0xAA, 0x49, 0x92, 0x39, 0x72, 0xE4, 0xD5, 0xB7, 0x73, 0xE6,
    0xD1, 0xBF, 0x63, 0xC6, 0x91, 0x3F, 0x7E, 0xFC, 0xE5, 0xD7, 0xB3, 0x7B, 0xF6, 0xF1, 0xFF, 0xE3,
    0xDB, 0xAB, 0x4B, 0x96, 0x31, 0x62, 0xC4, 0x95, 0x37, 0x6E, 0xDC, 0xA5, 0x57, 0xAE, 0x41, 0x82,
    0x19, 0x32, 0x64, 0xC8, 0x8D, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDD, 0xA7, 0x53, 0xA6, 0x51,
    0xA2, 0x59, 0xB2, 0x79, 0xF2, 0xF9, 0xEF, 0xC3, 0x9B, 0x2B, 0x56, 0xAC, 0x45, 0x8A, 0x09, 0x12,
    0x24, 0x48, 0x90, 0x3D, 0x7A, 0xF4, 0xF5, 0xF7, 0xF3, 0xFB, 0xEB, 0xCB, 0x8B, 0x0B, 0x16, 0x2C,
    0x58, 0xB0, 0x7D, 0xFA, 0xE9, 0xCF, 0x83, 0x1B, 0x36, 0x6C, 0xD8, 0xAD, 0x47, 0x8E, 0x01, 0x02
};

#define GF_ADD(x, y) (((uint8_t) x) ^ ((uint8_t) y))
#define GF_SUB(x, y) GF_ADD(x, y)
#define GF_MUL(x, y) ((x == 0) || (y == 0) ? 0 : _gfExp[_gfLog[x] + _gfLog[y]])
#define MOD255(m) ((((m) >> 8) + ((m) & 0xFF)) < 255 ? (((m) >> 8) + ((m) & 0xFF)) : ((((m) >> 8) + ((m) & 0xFF)) < (2 * 255)) ? ((((m) >> 8) + ((m) & 0xFF)) - 255): (((m) >> 8) + ((m) & 0xFF)) - (2 * 255))
#define GF_DIV(x, y) ((x == 0) ? 0 : _gfExp[MOD255(_gfLog[x] + 255 - _gfLog[y])])
#define GF_POW(x, p) (_gfExp[MOD255(_gfLog[x] * p)])
#define GF_INV(x) (_gfExp[255 - _gfLog[x]])

/* --------------------------------------------------------------------------------------------- */
/* Galois Field GF(2^8) Base Polynomial Operations                                               */
/* --------------------------------------------------------------------------------------------- */
typedef struct GFPoly
{
    uint8_t array[SSF_RS_MAX_CHUNK_SIZE + SSF_RS_MAX_SYMBOLS];
    size_t len; 
} GFPoly_t;

/* --------------------------------------------------------------------------------------------- */
/* Make a copy of a GF polynomial.                                                               */
/* --------------------------------------------------------------------------------------------- */
static void _GFPolyCopy(const GFPoly_t* src, GFPoly_t* dst)
{
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(dst != NULL);

    memcpy(dst, src, sizeof(GFPoly_t));
}

#if SSF_RS_ENABLE_DECODING == 1
/* --------------------------------------------------------------------------------------------- */
/* Make a reversed copy of a GF polynomial.                                                      */
/* --------------------------------------------------------------------------------------------- */
static void _GFPolyCopyRev(const GFPoly_t* src, GFPoly_t* dst)
{
    uint16_t i;

    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(dst != NULL);

    for (i = 0; i < src->len; i++)
    {
        dst->array[src->len - i - 1] = src->array[i];
    }
    dst->len = src->len;
}

/* --------------------------------------------------------------------------------------------- */
/* Scale a GF polynomial.                                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _GFPolyScale(const GFPoly_t *p, uint8_t s, GFPoly_t* d)
{
    size_t len;
    const uint8_t* pptr;
    uint8_t* dptr;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(d != NULL);

    len = d->len = p->len;
    pptr = p->array;
    dptr = d->array;

    while (len)
    {
        *dptr = GF_MUL(*pptr, s);
        dptr++;
        pptr++;
        len--;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Add two polynomials.                                                                          */
/* --------------------------------------------------------------------------------------------- */
static void _GFPolyAdd(const GFPoly_t *p, const GFPoly_t *q, GFPoly_t *d)
{
    uint16_t i;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(d != NULL);

    /* Initialize d with zeros */
    d->len = SSF_MAX(p->len, q->len);
    memset(d->array, 0, d->len);

    /* Copy p into new array */
    for (i = 0; i < p->len; i++)
    {
        d->array[i + d->len - p->len] = p->array[i];
    }

    /* Add q to new array */
    for (i = 0; i < q->len; i++)
    {
#ifdef _WIN32
#pragma warning(disable:6385) /* Should never index beyond array bounds. */
#endif /* _WIN32 */
        d->array[i + d->len - q->len] ^= q->array[i];
#ifdef _WIN32
#pragma warning(default:6385)
#endif /* _WIN32 */
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the evaluation of the polynomial.                                                     */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _GFPolyEval(const GFPoly_t* p, uint8_t x)
{
    uint16_t i;
    uint8_t y;

    SSF_REQUIRE(p != NULL);

    y = p->array[0];
    for (i = 1; i < p->len; i++)
        y = GF_MUL(y, x) ^ p->array[i];
    return y;
}
#endif /* SSF_RS_ENABLE_DECODING */

/* --------------------------------------------------------------------------------------------- */
/* Multiply two polynomials.                                                                     */
/* --------------------------------------------------------------------------------------------- */
static void _GFPolyMul(const GFPoly_t *p, const GFPoly_t *q, GFPoly_t *d)
{
    uint16_t j;
    uint8_t i;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(d != NULL);

    /* Initialize d with zeros */
    d->len = p->len + q->len - 1;
    SSF_ASSERT(d->len <= sizeof(d->array));
    memset(d->array, 0, d->len);

    for (j = 0; j < q->len; j++)
        for (i = 0; i < p->len; i++)
            d->array[i + j] ^= GF_MUL(p->array[i], q->array[j]);
}

/* --------------------------------------------------------------------------------------------- */
/* Divide two polynomials.                                                                       */
/* --------------------------------------------------------------------------------------------- */
static void _GFPolyDiv(const GFPoly_t *dividend, const GFPoly_t *divisor, GFPoly_t *quotient,
                       GFPoly_t *remainder)
{
    uint8_t coef;
    GFPoly_t msg_out;
    uint16_t i;
    uint16_t j;

    _GFPolyCopy(dividend, &msg_out);

    for (i = 0; i <= (dividend->len - divisor->len); i++)
    {
        coef = msg_out.array[i];
        if (coef != 0)
        {
            for (j = 1; j < divisor->len; j++)
            {
                if (divisor->array[j] != 0)
                {
                    msg_out.array[i + j] ^= GF_MUL(divisor->array[j], coef);
                }
            }
        }
    }

    quotient->len = msg_out.len - (divisor->len - 1);
    for (i = 0; i < (divisor->len - 1); i++)
    {
        remainder->array[i] = msg_out.array[i + quotient->len];
    }
    remainder->len = (divisor->len - 1);
}

/* --------------------------------------------------------------------------------------------- */
/* Reed-Solomon Galois Field GF(2^8) Encoding Operations                                         */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RS_ENABLE_ENCODING == 1
/* --------------------------------------------------------------------------------------------- */
/* Build Reed-Solomon generator polynomial                                                       */
/* --------------------------------------------------------------------------------------------- */
static void _RSGeneratorPoly(uint8_t nsym, GFPoly_t *g)
{
    uint16_t i;
    GFPoly_t c;
    GFPoly_t q;

    SSF_REQUIRE(g != NULL);

    g->len = 1;
    g->array[0] = 1;
    q.len = 2;
    q.array[0] = 1;

    for (i = 0; i < nsym; i++)
    {
        _GFPolyCopy(g, &c);
        q.array[1] = GF_POW(2, i);
        _GFPolyMul(&c, &q, g);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a message by returning the "checksum" to attach to the message                        */
/* --------------------------------------------------------------------------------------------- */
void _RSEncodeMsg(GFPoly_t *msg_in, uint8_t nsym, GFPoly_t *msg_out)
{
    uint16_t i;
    GFPoly_t gen;
    GFPoly_t quot;

    _RSGeneratorPoly(nsym, &gen);

    for (i = 0; i < gen.len - 1; i++)
    {
        msg_in->array[msg_in->len + i] = 0;
    }
    msg_in->len += gen.len - 1;

    _GFPolyDiv(msg_in, &gen, &quot, msg_out);
}
#endif /* SSF_RS_ENABLE_ENCODING */

/* --------------------------------------------------------------------------------------------- */
/* Reed-Solomon Galois Field GF(2^8) Decoding Operations                                         */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RS_ENABLE_DECODING == 1
/* --------------------------------------------------------------------------------------------- */
/* Calculate syndromes.                                                                          */
/* --------------------------------------------------------------------------------------------- */
static void _RSCalcSyndromes(const GFPoly_t *msg, uint8_t nsym, GFPoly_t *synd)
{
    uint16_t i;

    memset(synd->array, 0, ((size_t) nsym) + 1);
    synd->len = ((size_t) nsym) + 1;

    for (i = 0; i < nsym; i++)
    {
        synd->array[i + 1] = _GFPolyEval(msg, GF_POW(2, i));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if message syndromes match, else false.                                          */
/* --------------------------------------------------------------------------------------------- */
static bool _RSCheck(const GFPoly_t *msg, uint8_t nsym)
{
    GFPoly_t synd;
    uint16_t i;

    _RSCalcSyndromes(msg, nsym, &synd);
    for(i = 1; i <= nsym; i++)
    {
        if (synd.array[i] != 0) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if syndromes match, else false.                                                  */
/* --------------------------------------------------------------------------------------------- */
static bool _RSCheckSynd(const GFPoly_t* msg, uint8_t nsym, GFPoly_t *synd)
{
    uint16_t i;

    _RSCalcSyndromes(msg, nsym, synd);
    for (i = 1; i <= nsym; i++)
    {
        if (synd->array[i] != 0) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Evaluates for errors.                                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _RSFindErrorEvaluator(GFPoly_t *synd, GFPoly_t *err_loc, uint8_t nsym,
                                 GFPoly_t *remainder)
{
    GFPoly_t tmp;
    GFPoly_t tmp2;
    GFPoly_t quotient;

    _GFPolyMul(synd, err_loc, &tmp);
    tmp2.len = ((size_t) nsym) + 2;
    tmp2.array[0] = 1;
    memset(&tmp2.array[1], 0, tmp2.len - 1);    
    _GFPolyDiv(&tmp, &tmp2, &quotient, remainder);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if errors located and fixed, else false.                                         */
/* --------------------------------------------------------------------------------------------- */
static bool _RSFindErrorLocator(const GFPoly_t *synd, uint8_t nsym, GFPoly_t *err_loc)
{
    GFPoly_t old_loc;
    GFPoly_t new_loc;
    GFPoly_t tmp;
    GFPoly_t tmp2;
    size_t synd_shift;
    uint16_t i;
    uint16_t j;
    uint16_t K;
    uint8_t delta;
    size_t errs;

    err_loc->array[0] = 1;
    err_loc->len = 1;
    old_loc.array[0] = 1;
    old_loc.len = 1;

    synd_shift = synd->len - nsym;

    for (i = 0; i < nsym; i++)
    {
        K = (uint16_t) (i + synd_shift);

        delta = synd->array[K];
        for (j = 1; j < err_loc->len; j++)
        {
            delta ^= GF_MUL(err_loc->array[err_loc->len - 1 - j], synd->array[K - j]);
        }
        
        /* Shift polynomials to compute the next degree */
        old_loc.array[old_loc.len] = 0;
        old_loc.len++;

        /* Iteratively estimate the errata locator and evaluator polynomials */
        if (delta != 0)
        {
            if (old_loc.len > err_loc->len)
            {
                _GFPolyScale(&old_loc, delta, &new_loc);
                _GFPolyScale(err_loc, GF_INV(delta), &old_loc);
                _GFPolyCopy(&new_loc, err_loc);
            }
            
            /* Update with the discrepancy */
            _GFPolyScale(&old_loc, delta, &tmp);
            _GFPolyCopy(err_loc, &tmp2);
            _GFPolyAdd(&tmp2, &tmp, err_loc);
        }
    }

    /* Check if the result is correct, that there's not too many errors to correct */
    while ((err_loc->len) && (err_loc->array[0] == 0))
    {
        err_loc->len--;
        memmove(&err_loc->array[0], &err_loc->array[1], err_loc->len);
    }
    errs = err_loc->len - 1;
    if ((errs * 2) > nsym)
    {
        /* Too many errors to correct */
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if number of errors are correctable, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _RSFindErrors(const GFPoly_t *err_loc, uint8_t nmess, GFPoly_t *err_pos)
{
    uint8_t errs = (uint8_t) (err_loc->len - 1);
    uint16_t i;

    err_pos->len = 0;

    for (i = 0; i < nmess; i++)
    {
        if (_GFPolyEval(err_loc, GF_POW(2, i)) == 0)
        {
            err_pos->array[err_pos->len] = (uint8_t) (nmess - 1 - i);
            err_pos->len++;
        }
    }

    if (err_pos->len != errs)
    {
        /* Too many (or few) errors found by Chien Search for the errata locator polynomial */
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Finds the location of the errors.                                                             */
/* --------------------------------------------------------------------------------------------- */
static void _RSFindErrataLocator(const GFPoly_t *e_pos, GFPoly_t *e_loc)
{
    GFPoly_t tmp;
    GFPoly_t tmp2;
    GFPoly_t tmp3;
    GFPoly_t one;
    uint16_t i;

    e_loc->array[0] = 1;
    e_loc->len = 1;

    one.array[0] = 1;
    one.len = 1;

    for (i = 0; i < e_pos->len; i++)
    {   
        tmp3.array[0] = GF_POW(2, e_pos->array[i]);
        tmp3.array[1] = 0;
        tmp3.len = 2;
        _GFPolyAdd(&one, &tmp3, &tmp);
        _GFPolyMul(e_loc, &tmp, &tmp2);
        _GFPolyCopy(&tmp2, e_loc);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Corrects errata.                                                                              */
/* --------------------------------------------------------------------------------------------- */
static bool _RSCorrectErrata(GFPoly_t *msg_in, GFPoly_t *synd, GFPoly_t *err_pos, GFPoly_t* msg_out)
{
    GFPoly_t coef_pos;
    GFPoly_t err_loc;
    GFPoly_t synd_rev;
    GFPoly_t err_eval;
    GFPoly_t err_eval_rev;
    GFPoly_t X;
    GFPoly_t E;
    GFPoly_t err_loc_prime_tmp;
    uint16_t i;
    uint16_t j;
    uint8_t l;
    size_t Xlength;
    uint8_t Xi_inv;
    uint8_t err_loc_prime;
    uint8_t y;
    uint8_t magnitude;

    for (i = 0; i < err_pos->len; i++)
    {
        coef_pos.array[i] = (uint8_t) (msg_in->len - 1 - err_pos->array[i]);
    }
    coef_pos.len = err_pos->len;

    _RSFindErrataLocator(&coef_pos, &err_loc);

    _GFPolyCopyRev(synd, &synd_rev);

    _RSFindErrorEvaluator(&synd_rev, &err_loc, (uint8_t) (err_loc.len - 1), &err_eval_rev);
    _GFPolyCopyRev(&err_eval_rev, &err_eval);
    
    X.len = 0;
    for (i = 0; i < coef_pos.len; i++)
    {
        l = 255 - coef_pos.array[i];
        X.array[i] = GF_POW(2, -l);
        X.len++;
    }

    memset(E.array, 0, msg_in->len);
    E.len = msg_in->len;
    Xlength = X.len;
    for (i = 0; i < X.len; i++)
    {
        Xi_inv = GF_INV(X.array[i]);

        err_loc_prime_tmp.len = 0;

        for (j = 0; j < Xlength; j++)
        {
            if (j != i)
            {
                err_loc_prime_tmp.array[err_loc_prime_tmp.len] = GF_SUB(1, GF_MUL(Xi_inv, X.array[j]));
                err_loc_prime_tmp.len++;
            }
        }
        err_loc_prime = 1;

        for (j = 0; j < err_loc_prime_tmp.len; j++)
        {
            err_loc_prime = GF_MUL(err_loc_prime, err_loc_prime_tmp.array[j]);
        }

        _GFPolyCopyRev(&err_eval, &err_eval_rev);

        y = _GFPolyEval(&err_eval_rev, Xi_inv);
        y = GF_MUL(GF_POW(X.array[i], 1), y);

        if (err_loc_prime == 0)
            return false;

        magnitude = GF_DIV(y, err_loc_prime);
        E.array[err_pos->array[i]] = magnitude;
    }

    _GFPolyAdd(msg_in, &E, msg_out);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Computes Forney syndromes.                                                                    */
/* --------------------------------------------------------------------------------------------- */
static void _RSForneySyndromes(const GFPoly_t *synd, GFPoly_t *fsynd)
{
    uint16_t i;

    for (i = 0; i < synd->len; i++)
    {
        fsynd->array[i] = synd->array[i + 1];
    }
    fsynd->len = synd->len - 1;
}

/* --------------------------------------------------------------------------------------------- */
/* Corrects a message.                                                                           */
/* --------------------------------------------------------------------------------------------- */
static bool _RSCorrectMsg(GFPoly_t *msg_in, uint8_t nsym, GFPoly_t *msg_out)
{
    GFPoly_t err_loc;
    GFPoly_t err_loc_rev;
    GFPoly_t synd;
    GFPoly_t fsynd;
    GFPoly_t tmp;
    GFPoly_t err_pos;

    if (msg_in->len > 255)
        return false; // Message is too long

    _GFPolyCopy(msg_in, msg_out);

    if (_RSCheckSynd(msg_in, nsym, &synd))
    {
        /* No Errors */
        return true;
    }

    _RSForneySyndromes(&synd, &fsynd);
    _RSFindErrorLocator(&fsynd, nsym, &err_loc);
    _GFPolyCopyRev(&err_loc, &err_loc_rev);
    _RSFindErrors(&err_loc_rev, (uint8_t) msg_out->len, &err_pos);
    if (err_pos.len == 0)
    {
        /* Could not locate error */
        return false;
    }

    _GFPolyCopy(msg_out, &tmp);
    _RSCorrectErrata(&tmp, &synd, &err_pos, msg_out);

    return _RSCheck(msg_out, nsym);
}
#endif /* SSF_RS_ENABLE_DECODING */

#if SSF_RS_ENABLE_ENCODING == 1
/* --------------------------------------------------------------------------------------------- */
/* Encodes msg as a series of 1 or more eccNumBytes sized ECC blocks contiguously in eccBuf.     */
/* --------------------------------------------------------------------------------------------- */
void SSFRSEncode(const uint8_t *msg, uint16_t msgLen, uint8_t *eccBuf, uint16_t eccBufSize,
                 uint16_t *eccBufLen, uint8_t eccNumBytes, uint8_t chunkSize)
{
    GFPoly_t chunk;
    GFPoly_t ecc;

    SSF_REQUIRE(msg != NULL);
    SSF_REQUIRE(msgLen > 0);
    SSF_REQUIRE(eccBuf != NULL);
    SSF_REQUIRE(eccBufLen != NULL);
    SSF_REQUIRE(eccNumBytes <= SSF_RS_MAX_SYMBOLS);
    SSF_REQUIRE(eccNumBytes > 0);
    SSF_REQUIRE(chunkSize <= SSF_RS_MAX_CHUNK_SIZE);
    SSF_REQUIRE(chunkSize > 0);

    /* Iterate over msg and encode chunks up to chunkSize with eccChunkBytes symbols */
    *eccBufLen = 0;
    while (msgLen)
    {   
        SSF_ASSERT(eccBufSize >= eccNumBytes);

        /* Last chunk? If yes update chunkSize */
        if (msgLen < chunkSize) chunkSize = (uint8_t) msgLen;

        /* Encode */
        memcpy(chunk.array, msg, chunkSize);
        chunk.len = chunkSize;
        _RSEncodeMsg(&chunk, eccNumBytes, &ecc);

        /* Advance to next message chunk */
        msgLen -= chunkSize;
        msg += chunkSize;

        /* Save ECC and advance to next ecc block */
        SSF_ASSERT(ecc.len == eccNumBytes);
        memcpy(eccBuf, ecc.array, eccNumBytes);
        eccBufSize -= eccNumBytes;
        eccBuf += eccNumBytes;
        *eccBufLen += eccNumBytes;
    }
}
#endif /* SSF_RS_ENABLE_ENCODING */

#if SSF_RS_ENABLE_DECODING == 1
/* --------------------------------------------------------------------------------------------- */
/* Returns true and msgLen if decoding was successful, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSDecode(uint8_t* msg, uint16_t msgSize, uint16_t *msgLen, uint8_t eccNumBytes,
                 uint8_t chunkSize)
{
    uint16_t tmpSize;
    uint8_t tmpChunkSize;
    uint16_t eccBlockBytes;
    uint8_t *ecc;
    GFPoly_t chunkIn;
    GFPoly_t chunkOut;

    SSF_REQUIRE(msg != NULL);
    SSF_REQUIRE(msgSize > 0);
    SSF_REQUIRE(msgLen != NULL);
    SSF_REQUIRE(eccNumBytes <= SSF_RS_MAX_SYMBOLS);
    SSF_REQUIRE(eccNumBytes > 0);
    SSF_REQUIRE(chunkSize <= SSF_RS_MAX_CHUNK_SIZE);
    SSF_REQUIRE(chunkSize > 0);

    /* Determine start of the ECC blocks */
    eccBlockBytes = 0;
    tmpSize = msgSize;
    tmpChunkSize = chunkSize;
    while (tmpSize)
    {
        /* If remaining message too small return false */
        if (tmpSize <= eccNumBytes) return false;
        
        /* Last chunk? If yes update chunkSize */
        if ((tmpSize - eccNumBytes) < tmpChunkSize)
        { tmpChunkSize = (uint8_t) (tmpSize - eccNumBytes); }

        tmpSize -= eccNumBytes;
        tmpSize -= tmpChunkSize;

        eccBlockBytes += eccNumBytes;
    }
    ecc = &msg[msgSize - eccBlockBytes];

    /* Decode msg chunk by chunk correcting the msg buffer along the way */
    msgSize -= eccBlockBytes;
    *msgLen = 0;
    while (msgSize)
    {
        /* Last chunk? If yes update chunkSize */
        if (msgSize < chunkSize) chunkSize = (uint8_t) msgSize;

        /* Attempt correction, if it fails return false */
        memcpy(chunkIn.array, msg, chunkSize);
        memcpy(&chunkIn.array[chunkSize], ecc, eccNumBytes);
        chunkIn.len = ((size_t) chunkSize) + eccNumBytes;
        if (_RSCorrectMsg(&chunkIn, eccNumBytes, &chunkOut) == false)
        { return false; }
        SSF_ASSERT(chunkOut.len == (((size_t)chunkSize) + eccNumBytes));
        memcpy(msg, chunkOut.array, chunkSize);

        /* Advance to next msg block */
        msg += chunkSize;
        msgSize -= chunkSize;
        *msgLen += chunkSize;

        /* Advance to next ECC block */
        ecc += eccNumBytes;
    }

    /* All chunks were successfully corrected */
    return true;
}
#endif /* SSF_RS_ENABLE_DECODING */
