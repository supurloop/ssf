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
static const uint8_t _gfExp[255] =
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
    0x2C, 0x58, 0xB0, 0x7D, 0xFA, 0xE9, 0xCF, 0x83, 0x1B, 0x36, 0x6C, 0xD8, 0xAD, 0x47, 0x8E
};

static const uint8_t _gfInv[256] =
{
  0x01, 0x01, 0x8E, 0xF4, 0x47, 0xA7, 0x7A, 0xBA, 0xAD, 0x9D, 0xDD, 0x98, 0x3D, 0xAA, 0x5D, 0x96,
  0xD8, 0x72, 0xC0, 0x58, 0xE0, 0x3E, 0x4C, 0x66, 0x90, 0xDE, 0x55, 0x80, 0xA0, 0x83, 0x4B, 0x2A,
  0x6C, 0xED, 0x39, 0x51, 0x60, 0x56, 0x2C, 0x8A, 0x70, 0xD0, 0x1F, 0x4A, 0x26, 0x8B, 0x33, 0x6E,
  0x48, 0x89, 0x6F, 0x2E, 0xA4, 0xC3, 0x40, 0x5E, 0x50, 0x22, 0xCF, 0xA9, 0xAB, 0x0C, 0x15, 0xE1,
  0x36, 0x5F, 0xF8, 0xD5, 0x92, 0x4E, 0xA6, 0x04, 0x30, 0x88, 0x2B, 0x1E, 0x16, 0x67, 0x45, 0x93,
  0x38, 0x23, 0x68, 0x8C, 0x81, 0x1A, 0x25, 0x61, 0x13, 0xC1, 0xCB, 0x63, 0x97, 0x0E, 0x37, 0x41,
  0x24, 0x57, 0xCA, 0x5B, 0xB9, 0xC4, 0x17, 0x4D, 0x52, 0x8D, 0xEF, 0xB3, 0x20, 0xEC, 0x2F, 0x32,
  0x28, 0xD1, 0x11, 0xD9, 0xE9, 0xFB, 0xDA, 0x79, 0xDB, 0x77, 0x06, 0xBB, 0x84, 0xCD, 0xFE, 0xFC,
  0x1B, 0x54, 0xA1, 0x1D, 0x7C, 0xCC, 0xE4, 0xB0, 0x49, 0x31, 0x27, 0x2D, 0x53, 0x69, 0x02, 0xF5,
  0x18, 0xDF, 0x44, 0x4F, 0x9B, 0xBC, 0x0F, 0x5C, 0x0B, 0xDC, 0xBD, 0x94, 0xAC, 0x09, 0xC7, 0xA2,
  0x1C, 0x82, 0x9F, 0xC6, 0x34, 0xC2, 0x46, 0x05, 0xCE, 0x3B, 0x0D, 0x3C, 0x9C, 0x08, 0xBE, 0xB7,
  0x87, 0xE5, 0xEE, 0x6B, 0xEB, 0xF2, 0xBF, 0xAF, 0xC5, 0x64, 0x07, 0x7B, 0x95, 0x9A, 0xAE, 0xB6,
  0x12, 0x59, 0xA5, 0x35, 0x65, 0xB8, 0xA3, 0x9E, 0xD2, 0xF7, 0x62, 0x5A, 0x85, 0x7D, 0xA8, 0x3A,
  0x29, 0x71, 0xC8, 0xF6, 0xF9, 0x43, 0xD7, 0xD6, 0x10, 0x73, 0x76, 0x78, 0x99, 0x0A, 0x19, 0x91,
  0x14, 0x3F, 0xE6, 0xF0, 0x86, 0xB1, 0xE2, 0xF1, 0xFA, 0x74, 0xF3, 0xB4, 0x6D, 0x21, 0xB2, 0x6A,
  0xE3, 0xE7, 0xB5, 0xEA, 0x03, 0x8F, 0xD3, 0xC9, 0x42, 0xD4, 0xE8, 0x75, 0x7F, 0xFF, 0x7E, 0xFD
};

#define GF_ADD(x, y) (((uint8_t) x) ^ ((uint8_t) y))
#define GF_SUB(x, y) GF_ADD(x, y)
#define GF_MUL(x, y) ((x == 0) || (y == 0) ? 0 : _gfExp[MOD255(_gfLog[x] + _gfLog[y])])
#define MOD255(m) ((m) % 255)
#define GF_DIV(x, y) ((x == 0) ? 0 : _gfExp[MOD255(_gfLog[x] + 255 - _gfLog[y])])
#define GF_POW(x, p) (_gfExp[MOD255(((uint32_t) _gfLog[x]) * (p))])
#define GF_INV(x) (_gfInv[x])

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
#define _GFPolyCopy(src, dst) { \
    memcpy(dst, src, (src)->len); \
    (dst)->len = (src)->len; \
}

#if SSF_RS_ENABLE_DECODING == 1
/* --------------------------------------------------------------------------------------------- */
/* Make a reversed copy of a GF polynomial.                                                      */
/* --------------------------------------------------------------------------------------------- */
#define _GFPolyCopyRev(src, dst) { \
    uint16_t m; \
    uint16_t n; \
    size_t remLen; \
    remLen = (src)->len; \
    m = 0; \
    n = (uint16_t) (src)->len - 1; \
    while (remLen >= 8) { \
        (dst)->array[n--] = (src)->array[m++]; \
        (dst)->array[n--] = (src)->array[m++]; \
        (dst)->array[n--] = (src)->array[m++]; \
        (dst)->array[n--] = (src)->array[m++]; \
        (dst)->array[n--] = (src)->array[m++]; \
        (dst)->array[n--] = (src)->array[m++]; \
        (dst)->array[n--] = (src)->array[m++]; \
        (dst)->array[n--] = (src)->array[m++]; \
        remLen -= 8; } \
    for (; m < (src)->len; m++) { \
        (dst)->array[n--] = (src)->array[m]; } \
    (dst)->len = (src)->len; \
}

/* --------------------------------------------------------------------------------------------- */
/* Scale a GF polynomial.                                                                        */
/* --------------------------------------------------------------------------------------------- */
#define _GFPolyScale(p, s, d) { \
    size_t len; \
    const uint8_t *pptr; \
    uint8_t *dptr; \
    len = (d)->len = (p)->len; \
    pptr = (p)->array; \
    dptr = (d)->array; \
    while (len >= 8) { \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; \
        len -= 8; \
    } \
    while (len) { \
        *dptr = GF_MUL(*pptr, s); dptr++; pptr++; len--; \
    } \
}

/* --------------------------------------------------------------------------------------------- */
/* Add two polynomials.                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define _GFPolyAdd(p, q, d) { \
    uint16_t k; \
    (d)->len = SSF_MAX((p)->len, (q)->len); \
    memset((d)->array, 0, (d)->len); \
    for (k = 0; k < (p)->len; k++) { \
        (d)->array[k + (d)->len - (p)->len] = (p)->array[k]; } \
    for (k = 0; k < (q)->len; k++) { \
        (d)->array[k + (d)->len - (q)->len] ^= (q)->array[k]; } \
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the evaluation of the polynomial.                                                     */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _GFPolyEval(const GFPoly_t *p, uint8_t x)
{
    uint16_t i;
    uint8_t y;
    size_t rem;

    SSF_REQUIRE(p != NULL);

    y = p->array[0];
    rem = p->len - 1;
    i = 1;
    while (rem >= 8)
    {
        y = GF_MUL(y, x) ^ p->array[i++];
        y = GF_MUL(y, x) ^ p->array[i++];
        y = GF_MUL(y, x) ^ p->array[i++];
        y = GF_MUL(y, x) ^ p->array[i++];
        y = GF_MUL(y, x) ^ p->array[i++];
        y = GF_MUL(y, x) ^ p->array[i++];
        y = GF_MUL(y, x) ^ p->array[i++];
        y = GF_MUL(y, x) ^ p->array[i++];
        rem -= 8;
    }
    for (; i < p->len; i++) { y = GF_MUL(y, x) ^ p->array[i]; }
    return y;
}
#endif /* SSF_RS_ENABLE_DECODING */

/* --------------------------------------------------------------------------------------------- */
/* Multiply two polynomials.                                                                     */
/* --------------------------------------------------------------------------------------------- */
#define _GFPolyMul(p, q, d) { \
    uint8_t m; \
    uint16_t n; \
    size_t rem; \
    uint8_t qj; \
    (d)->len = (p)->len + (q)->len - 1; \
    SSF_ASSERT((d)->len <= sizeof((d)->array)); \
    memset((d)->array, 0, (d)->len); \
    for (n = 0; n < (q)->len; n++) { \
        qj = (q)->array[n]; \
        rem = (p)->len; \
        m = 0; \
        while (rem >= 4) { \
            (d)->array[m + n] ^= GF_MUL((p)->array[m], qj); m++; \
            (d)->array[m + n] ^= GF_MUL((p)->array[m], qj); m++; \
            (d)->array[m + n] ^= GF_MUL((p)->array[m], qj); m++; \
            (d)->array[m + n] ^= GF_MUL((p)->array[m], qj); m++; \
            rem -= 4; } \
        for (; m < (p)->len; m++) { \
            (d)->array[m + n] ^= GF_MUL((p)->array[m], qj); } } \
}

/* --------------------------------------------------------------------------------------------- */
/* Divide two polynomials.                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define _GFPolyDiv(dividend, divisor, quotient, remainder) { \
    uint8_t coef; \
    GFPoly_t tmp_out; \
    uint16_t m; \
    uint16_t n; \
    _GFPolyCopy((dividend), &tmp_out); \
    for (m = 0; m <= ((dividend)->len - (divisor)->len); m++) { \
        coef = tmp_out.array[m]; \
        if (coef != 0) { \
            for (n = 1; n < (divisor)->len; n++) { \
                if ((divisor)->array[n] != 0) { \
                    tmp_out.array[m + n] ^= GF_MUL((divisor)->array[n], coef); } } } } \
    (quotient)->len = tmp_out.len - ((divisor)->len - 1); \
    memcpy((remainder)->array, &tmp_out.array[(quotient)->len], (divisor)->len - 1); \
    (remainder)->len = ((divisor)->len - 1); \
}

/* --------------------------------------------------------------------------------------------- */
/* Reed-Solomon Galois Field GF(2^8) Encoding Operations                                         */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RS_ENABLE_ENCODING == 1
/* --------------------------------------------------------------------------------------------- */
/* Build Reed-Solomon generator polynomial                                                       */
/* --------------------------------------------------------------------------------------------- */
#define _RSGeneratorPoly(nsym, g) { \
    uint16_t k; \
    GFPoly_t c; \
    GFPoly_t q; \
    c.len = 0; \
    (g)->len = 1; \
    (g)->array[0] = 1; \
    q.len = 2; \
    q.array[0] = 1; \
    for (k = 0; k < nsym; k++) { \
        q.array[1] = GF_POW(2, k); \
        if ((k & 0x01) == 0) { _GFPolyMul(g, &q, &c); } \
        else { _GFPolyMul(&c, &q, g); } } \
    if ((k & 0x01) != 0) _GFPolyCopy(&c, g); \
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a message by returning the "checksum" to attach to the message                        */
/* --------------------------------------------------------------------------------------------- */
void _RSEncodeMsg(GFPoly_t *msg_in, uint8_t nsym, GFPoly_t *msg_out)
{
    GFPoly_t gen;
    GFPoly_t quot;

    _RSGeneratorPoly(nsym, &gen);

    memset(&msg_in->array[msg_in->len], 0, gen.len - 1);
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
#define _RSCalcSyndromes(msg, nsym, synd) { \
    uint16_t k; \
    memset((synd)->array, 0, ((size_t) nsym) + 1); \
    (synd)->len = ((size_t) nsym) + 1; \
    for (k = 0; k < nsym; k++) { \
        (synd)->array[k + 1] = _GFPolyEval((msg), GF_POW(2, k)); } \
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if message syndromes match, else false.                                          */
/* --------------------------------------------------------------------------------------------- */
static bool _RSCheck(const GFPoly_t *msg, uint8_t nsym)
{
    GFPoly_t synd;
    uint16_t i;

    _RSCalcSyndromes(msg, nsym, &synd);
    for (i = 1; i <= nsym; i++) { if (synd.array[i] != 0) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if syndromes match, else false.                                                  */
/* --------------------------------------------------------------------------------------------- */
static bool _RSCheckSynd(const GFPoly_t* msg, uint8_t nsym, GFPoly_t *synd)
{
    uint16_t i;

    _RSCalcSyndromes(msg, nsym, synd);
    for (i = 1; i <= nsym; i++) { if (synd->array[i] != 0) return false; }
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
    if ((errs << 1) > nsym)
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

    tmp2.len = 0;
    one.array[0] = 1;
    one.len = 1;
    tmp3.array[1] = 0;
    tmp3.len = 2;

    for (i = 0; i < e_pos->len; i++)
    {
        tmp3.array[0] = GF_POW(2, e_pos->array[i]);
        _GFPolyAdd(&one, &tmp3, &tmp);
        if ((i & 0x01) == 0) { _GFPolyMul(e_loc, &tmp, &tmp2); }
        else { _GFPolyMul(&tmp2, &tmp, e_loc); }
    }
    if ((i & 0x01) != 0) _GFPolyCopy(&tmp2, e_loc);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true is errata corrected else false.                                                  */
/* --------------------------------------------------------------------------------------------- */
static bool _RSCorrectErrata(GFPoly_t *msg_in, GFPoly_t *synd, GFPoly_t *err_pos,
                             GFPoly_t *msg_out)
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
                err_loc_prime_tmp.array[err_loc_prime_tmp.len] =
                    GF_SUB(1, GF_MUL(Xi_inv, X.array[j]));
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
    memcpy(&fsynd->array, &synd->array[1], synd->len);
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

    /* Is message too long? */
    if (msg_in->len > 255) return false;

    /* No, any errors? */
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

    /* Unable to locate error? */
    if (err_pos.len == 0) return false;

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
bool SSFRSDecode(uint8_t *msg, uint16_t msgSize, uint16_t *msgLen, uint8_t eccNumBytes,
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
