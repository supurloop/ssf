/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbase64url.c                                                                                */
/* Provides Base64URL encoder/decoder implementation per RFC 4648 Section 5.                     */
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
#include "ssfbase64url.h"
#include "ssfbase64.h"

/* The decoder's padded-scratch buffer must have room for the largest expected input
 * plus up to 3 '=' padding chars and a NUL terminator. If the config drops below this
 * minimum, the sizeof(padded) - 4u expression in the length guard would underflow
 * (wrap to SIZE_MAX), silently disabling the guard and allowing a stack overrun. */
#if SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN < 8
#error "SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN must be >= 8 (4 input chars + 3 padding + NUL)"
#endif

/* --------------------------------------------------------------------------------------------- */
/* Encode binary data to Base64URL string.                                                       */
/* Standard Base64 encode then post-process for URL safety.                                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64URLEncode(const uint8_t *in, size_t inLen, SSFCStrOut_t out, size_t outSize,
                        size_t *outLen)
{
    size_t b64Len;
    size_t i;
    size_t writePos;

    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    /* Standard Base64 encode first */
    if (!SSFBase64Encode(in, inLen, out, outSize, &b64Len)) return false;

    /* Post-process: replace + with -, / with _, strip = padding */
    writePos = 0;
    for (i = 0; i < b64Len; i++)
    {
        if (out[i] == '+') { out[writePos++] = '-'; }
        else if (out[i] == '/') { out[writePos++] = '_'; }
        else if (out[i] == '=') { /* skip padding */ }
        else { out[writePos++] = out[i]; }
    }
    out[writePos] = '\0';
    *outLen = writePos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Decode Base64URL string to binary data.                                                       */
/* Pre-process URL-safe chars back to standard, add padding, then standard Base64 decode.        */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64URLDecode(SSFCStrIn_t in, size_t inLen, uint8_t *out, size_t outSize,
                        size_t *outLen)
{
    char padded[SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN];
    size_t i;
    size_t paddedLen;

    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (inLen >= sizeof(padded) - 4u) return false;

    /* Copy and replace URL-safe chars. RFC 4648 §3.3 requires rejection of characters
     * outside the §5 alphabet; '+' and '/' are in §4 but not §5, so we reject them
     * here rather than letting the underlying standard-Base64 decoder silently accept. */
    for (i = 0; i < inLen; i++)
    {
        if (in[i] == '+' || in[i] == '/') return false;
        if (in[i] == '-')      padded[i] = '+';
        else if (in[i] == '_') padded[i] = '/';
        else                   padded[i] = in[i];
    }

    /* Add padding to make length multiple of 4 */
    paddedLen = inLen;
    while ((paddedLen % 4u) != 0u)
    {
        padded[paddedLen++] = '=';
    }
    padded[paddedLen] = '\0';

    return SSFBase64Decode(padded, paddedLen, out, outSize, outLen);
}
