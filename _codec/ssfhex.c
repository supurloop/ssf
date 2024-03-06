/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhex.c                                                                                      */
/* Provides ASCII hex encoder/decoder interface.                                                 */
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
#include <stdio.h>
#include <stdlib.h>
#include "ssfhex.h"
#include "ssfport.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Returns true if binary byte converted successfully to ASCII hex bytes, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexBinToByte(uint8_t in, char *out, size_t outSize, SSFHexCase_t hcase)
{
    #define SSF_HEX_BIN_TO_HEX(n, o, u) if (n <= 9) o = n + 0x30; else o = n + u;
    uint8_t un;
    uint8_t ln;
    uint8_t up;
    
    SSF_REQUIRE(out != NULL);
    if (outSize < 2) return false;

    un = in >> 4;
    ln = in & 0x0f;
    up = (hcase == SSF_HEX_CASE_UPPER) ? 0x37 : 0x57;
    SSF_HEX_BIN_TO_HEX(un, out[0], up);
    SSF_HEX_BIN_TO_HEX(ln, out[1], up);
    if (outSize >= 3) out[2] = 0;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if ASCII hex bytes converted successfully to binary byte, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexByteToBin(const char *hex, uint8_t *out)
{
    #define SSF_HEX_TO_BIN(n, i) \
        if ((i >= '0') && (i <= '9')) n = i - 0x30; \
        else if ((i >= 'A') && (i <= 'F')) n = i - 0x37; \
        else if ((i >= 'a') && (i <= 'f')) n = i - 0x57; \
        else return false;
    uint8_t un;
    uint8_t ln;

    SSF_REQUIRE(hex != NULL);
    SSF_REQUIRE(out != NULL);

    SSF_HEX_TO_BIN(un, hex[0]);
    SSF_HEX_TO_BIN(ln, hex[1]);
    *out = (un << 4) + ln;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if ASCII hex byte string converted successfully to binary bytes, else false.     */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexBytesToBin(SSFCStrIn_t in, size_t inLenLim, uint8_t *out, size_t outSize,
                      size_t *outLen, bool rev)
{
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (inLenLim & 0x01) return false;
    *outLen = 0;
    while ((inLenLim >= 2) && (outSize != 0))
    {
        if (rev)
        {
            if (!SSFHexByteToBin(&in[inLenLim - 2], out)) return false;
        }
        else
        {
            if (!SSFHexByteToBin(in, out)) return false;
            in += 2;
        }
        inLenLim -= 2;
        outSize--;
        out++;
        (*outLen)++;
    }
    return inLenLim == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if binary bytes converted successfully to ASCII hex byte string, else false.     */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexBinToBytes(const uint8_t *in, size_t inLen, SSFCStrOut_t out, size_t outSize,
                      size_t *outLen, bool rev, SSFHexCase_t hcase)
{
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outSize >= 1);
    SSF_REQUIRE((hcase > SSF_HEX_CASE_MIN) && (hcase < SSF_HEX_CASE_MAX));

    *out = 0;
    if (outLen != NULL) *outLen = 0;
    if ((rev) && (inLen > 0)) in += (inLen - 1);
    while ((inLen > 0) && (outSize >= 3))
    {
        if (!SSFHexBinToByte(*in, out, outSize, hcase)) return false;
        if (rev) in--;
        else in++;
        inLen--;
        out += 2;
        outSize -= 2;
        if (outLen != NULL) *outLen += 2;
    }
    return inLen == 0;
}

