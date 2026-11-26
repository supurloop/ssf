/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbase64.c                                                                                   */
/* Provides Base64 encoder/decoder interface.                                                    */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfbase64.h"

/* --------------------------------------------------------------------------------------------- */
/* Local vars                                                                                    */
/* --------------------------------------------------------------------------------------------- */
static const uint8_t _b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/* --------------------------------------------------------------------------------------------- */
/* Branch-free masks for a byte value x (0-255): all ones if lo <= x <= hi (or x == c), else 0.  */
/* --------------------------------------------------------------------------------------------- */
#define _SSF_B64_IN(x, lo, hi) \
    ((uint32_t)0u - (((((uint32_t)(lo) - 1u) - (x)) & ((x) - ((uint32_t)(hi) + 1u))) >> 31))
#define _SSF_B64_EQ(x, c) ((uint32_t)0u - ((((x) ^ (uint32_t)(c)) - 1u) >> 31))

/* --------------------------------------------------------------------------------------------- */
/* Returns constant-time encoding 0-63 for valid char, 64 for '=' pad, else 65 for invalid.      */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFBase64GetEncoding(uint8_t e)
{
    uint32_t x = e;
    uint32_t mU = _SSF_B64_IN(x, 'A', 'Z');
    uint32_t mL = _SSF_B64_IN(x, 'a', 'z');
    uint32_t mD = _SSF_B64_IN(x, '0', '9');
    uint32_t mP = _SSF_B64_EQ(x, '+');
    uint32_t mS = _SSF_B64_EQ(x, '/');
    uint32_t mE = _SSF_B64_EQ(x, '=');
    uint32_t v;

    v = (mU & (x - 'A')) | (mL & (x - ('a' - 26u))) | (mD & (x + (52u - '0'))) |
        (mP & 62u) | (mS & 63u) | (mE & 64u);
    return (uint8_t)(v | ((~(mU | mL | mD | mP | mS | mE)) & 65u));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 1-3 on successful 32-bit block decode into 24-bit output, else 0 on decode error.     */
/* --------------------------------------------------------------------------------------------- */
uint8_t SSFBase64Dec32To24(const char *b32, uint8_t *b24out, size_t b24outSize)
{
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;

    SSF_REQUIRE(b32 != NULL);
    SSF_REQUIRE(b24out != NULL);
    SSF_REQUIRE(b24outSize >= 1);

    a = _SSFBase64GetEncoding(*b32);
    b = _SSFBase64GetEncoding(*(b32 + 1));
    c = _SSFBase64GetEncoding(*(b32 + 2));
    d = _SSFBase64GetEncoding(*(b32 + 3));

    /* Is any char invalid or is the first or second char a pad? */
    if ((a >= 64) || (b >= 64) || (c >= 65) || (d >= 65))
    {
        /* Yes, block is not valid */
        return 0;
    }
    /* Is the third char a pad without the fourth char being a pad? */
    if ((c == 64) && (d != 64))
    {
        /* Yes, block is not valid */
        return 0;
    }
    /* Is this a 1-byte block with any low 4 bits of b set (RFC 4648 Sec. 3.5 non-canonical)? */
    if ((c == 64) && ((b & 0x0Fu) != 0u))
    {
        /* Yes, block is not valid */
        return 0;
    }
    /* Is this a 2-byte block with any low 2 bits of c set (RFC 4648 Sec. 3.5 non-canonical)? */
    if ((d == 64) && (c != 64) && ((c & 0x03u) != 0u))
    {
        /* Yes, block is not valid */
        return 0;
    }
    *b24out = (uint8_t)((a << 2) | (b >> 4));
    if (c == 64) return 1;
    if (b24outSize <= 1) return 0;
    *(b24out + 1) = (uint8_t)((b << 4) | (c >> 2));
    if (d == 64) return 2;
    if (b24outSize <= 2) return 0;
    *(b24out + 2) = (uint8_t)((c << 6) | d);
    return 3;
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes 24-bit input block as 32-bit output.                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFBase64Enc24To32(const uint8_t *b24in, size_t b24inLen, char *b32out, size_t b32outSize)
{
    uint8_t b24[3];

    SSF_REQUIRE(b24in != NULL);
    SSF_REQUIRE(b24inLen > 0);
    SSF_REQUIRE(b32out != NULL);
    SSF_REQUIRE(b32outSize >= 4);

    b24[0] = b24in[0];
    if (b24inLen >= 2) b24[1] = b24in[1];
    else b24[1] = 0;
    if (b24inLen >= 3) b24[2] = b24in[2];
    else b24[2] = 0;
    *b32out = _b64[*b24 >> 2];
    *(b32out + 1) = _b64[((*b24 << 4) & 0x3f) | (*(b24 + 1) >> 4)];
    if (b24inLen >= 2) *(b32out + 2) = _b64[((*(b24 + 1) << 2) & 0x3f) | (*(b24 + 2) >> 6)];
    else b32out[2] = '=';
    if (b24inLen >= 3) *(b32out + 3) = _b64[*(b24 + 2) & 0x3f];
    else b32out[3] = '=';
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if input successfully encoded as C string output, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64Encode(const uint8_t *in, size_t inLen, SSFCStrOut_t outStr, size_t outSize,
                     size_t *outLenOpt)
{
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(outSize > 0);
    SSF_REQUIRE(outStr != NULL);

    if (outLenOpt != NULL) *outLenOpt = 0;
    /* Is there input left and room for another block plus the terminator? */
    while ((inLen > 0) && (outSize >= 5))
    {
        /* Yes, encode the next block */
        SSFBase64Enc24To32(in, inLen, outStr, outSize);
        in += 3;
        if (inLen >= 3) inLen -= 3;
        else inLen = 0;
        outStr += 4;
        outSize -= 4;
        if (outLenOpt != NULL) *outLenOpt += 4;
    }
    SSF_ASSERT(outSize > 0);
    *outStr = 0;
    return (inLen == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if C string input successfully decoded as output, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64Decode(SSFCStrIn_t inStr, size_t inLenLim, uint8_t *out, size_t outSize,
                     size_t *outLen)
{
    uint8_t len;

    SSF_REQUIRE(inStr != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    /* Is the input length not a multiple of 4? */
    if ((inLenLim & 0x03) != 0) return false;
    *outLen = 0;
    /* Is there another input block and room for output? */
    while ((inLenLim >= 4) && (outSize >= 1))
    {
        /* Yes, decode the next block */
        if ((len = SSFBase64Dec32To24(inStr, out, outSize)) == 0) return false;
        inLenLim -= 4;
        inStr += 4;
        out += len;
        *outLen += len;
        if (outSize >= len) outSize -= len;
        else outSize = 0;
    }
    return (inLenLim == 0);
}

