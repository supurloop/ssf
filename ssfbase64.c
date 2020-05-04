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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Local vars                                                                                    */
/* --------------------------------------------------------------------------------------------- */
static const uint8_t _b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/* --------------------------------------------------------------------------------------------- */
/* Returns encoding of 0-63 for valid encoded char, 64 for '=' pad, else 65 for invalid.         */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFBase64GetEncoding(uint8_t e)
{
    const uint8_t *p = _b64;

    while ((*p != e) && (*p != 0)) p++;
    return (uint8_t)(p - _b64);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 1-3 on successful 32-bit block decode into 24-bit output, else 0 on decode error.     */
/* --------------------------------------------------------------------------------------------- */
uint8_t SSFBase64Dec32To24(const uint8_t *b32, uint8_t *b24out, size_t b24outSize)
{
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;

    SSF_REQUIRE(b32 != NULL);
    SSF_REQUIRE(b24out != NULL);
    SSF_REQUIRE(b24outSize >= 3);

    a = _SSFBase64GetEncoding(*b32);
    b = _SSFBase64GetEncoding(*(b32 + 1));
    c = _SSFBase64GetEncoding(*(b32 + 2));
    d = _SSFBase64GetEncoding(*(b32 + 3));

    if (b24outSize == 0) return 0;
    if (a >= 64 || b >= 64 || c >= 65 || d >= 65) return 0;
    if (c == 64 && d != 64) return 0;
    *b24out = (a << 2) | (b >> 4);
    if (c == 64) return 1;
    if (b24outSize == 1) return 0;
    *(b24out + 1) = (b << 4) | (c >> 2);
    if (d == 64) return 2;
    if (b24outSize == 2) return 0;
    *(b24out + 2) = (c << 6) | d;
    return 3;
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes 24-bit input block as 32-bit output.                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFBase64Enc24To32(const uint8_t *b24in, size_t b24len, char *b32out, size_t b32outSize)
{
    uint8_t b24[3];

    SSF_REQUIRE(b24in != NULL);
    SSF_REQUIRE(b24len > 0);
    SSF_REQUIRE(b32out != NULL);
    SSF_REQUIRE(b32outSize >= 4);

    b24[0] = b24in[0];
    if (b24len >= 2)  b24[1] = b24in[1];
    else b24[1] = 0;
    if (b24len >= 3) b24[2] = b24in[2];
    else b24[2] = 0;
    *b32out = _b64[*b24 >> 2];
    *(b32out + 1) = _b64[((*b24 << 4) & 0x3f) | (*(b24 + 1) >> 4)];
    if (b24len >= 2) *(b32out + 2) = _b64[((*(b24 + 1) << 2) & 0x3f) | (*(b24 + 2) >> 6)];
    else b32out[2] = '=';
    if (b24len >= 3) *(b32out + 3) = _b64[*(b24 + 2) & 0x3f];
    else b32out[3] = '=';
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if input successfully encoded as C string output, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64Encode(const uint8_t *in, size_t inLen, SSFCStrOut_t out, size_t outSize,
                     size_t *outLen)
{
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);

    if (outLen != NULL) *outLen = 0;
    while ((inLen > 0) && (outSize >= 5))
    {
        SSFBase64Enc24To32(in, inLen, out, outSize);
        in += 3;
        if (inLen >= 3) inLen -= 3;
        else inLen = 0;
        out += 4;
        outSize -= 4;
        if (outLen != NULL) *outLen += 4;
    }
    if (outSize > 0) *out = 0;
    return inLen == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if C string input successfully decoded as output, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64Decode(SSFCStrIn_t in, size_t inLenLim, uint8_t *out, size_t outSize,
                     size_t *outLen)
{
    uint8_t len;

    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if ((inLenLim & 0x03) != 0) return false;
    *outLen = 0;
    while (inLenLim >= 4)
    {
        if ((len = SSFBase64Dec32To24(in, out, outSize)) == 0) return false;
        inLenLim -= 4;
        in += 4;
        out += len;
        *outLen += len;
        if (outSize >= len) outSize -= len;
        else outSize = 0;
    }
    return inLenLim == 0;
}

