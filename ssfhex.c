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
    int n;

    SSF_REQUIRE(out != NULL);

    if (hcase == SSF_HEX_CASE_UPPER) n = snprintf(out, outSize, "%02X", (unsigned int)in);
    else n = snprintf(out, outSize, "%02x", (unsigned int)in);

    return ((n >= 2) && (((size_t) n) < outSize));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if ASCII hex bytes converted successfully to binary byte, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexByteToBin(const char *hex, uint8_t *out)
{
    char tmp[3] = "  ";

    SSF_REQUIRE(hex != NULL);
    SSF_ASSERT(out != NULL);

    tmp[0] = hex[0];
    if (!SSFIsHex(tmp[0])) return false;
    tmp[1] = hex[1];
    if (!SSFIsHex(tmp[1])) return false;
    *out = (uint8_t)strtol(tmp, NULL, 16);
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
        {if (!SSFHexByteToBin(&in[inLenLim - 2], out)) return false; } else
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
    SSF_REQUIRE(hcase < SSF_HEX_CASE_MAX);

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

