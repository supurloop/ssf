/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbase64url.c                                                                                */
/* Provides Base64URL encoder/decoder implementation per RFC 4648 Section 5.                     */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#include "ssfcrypt.h"

#if SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN < 8
#error "SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN must be >= 8 (4 input chars + 3 padding + NUL)"
#endif

/* --------------------------------------------------------------------------------------------- */
/* Returns true if binary data encoded to Base64URL string, else false.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64URLEncode(const uint8_t *in, size_t inLen, SSFCStrOut_t outStr, size_t outStrSize,
                        size_t *outStrLen)
{
    size_t b64Len;
    size_t i;
    size_t writePos;

    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(outStr != NULL);
    SSF_REQUIRE(outStrSize > 0);
    SSF_REQUIRE(outStrLen != NULL);

    /* Every failure path reports an empty string */
    *outStrLen = 0;

    /* Standard Base64 encode fits in outStr? */
    if (!SSFBase64Encode(in, inLen, outStr, outStrSize, &b64Len))
    {
        /* No, scrub the partial standard-alphabet encoding so nothing non-URL-safe remains */
        SSFCryptSecureZero(outStr, outStrSize);
        return false;
    }

    /* Yes, convert in place to the URL-safe alphabet and strip padding */
    writePos = 0;
    for (i = 0; i < b64Len; i++)
    {
        if (outStr[i] == '+') outStr[writePos++] = '-';
        else if (outStr[i] == '/') outStr[writePos++] = '_';
        else if (outStr[i] != '=') outStr[writePos++] = outStr[i];
    }
    SSF_ENSURE(writePos < outStrSize);
    outStr[writePos] = '\0';
    *outStrLen = writePos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if Base64URL string decoded to binary data, else false.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFBase64URLDecode(SSFCStrIn_t inStr, size_t inStrLen, uint8_t *out, size_t outSize,
                        size_t *outLen)
{
    char padded[SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN];
    size_t i;
    size_t paddedLen;
    size_t padStart;
    bool ok;

    SSF_REQUIRE(inStr != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    *outLen = 0;

    /* Input, up to 3 pad chars, and terminator fit in padded? */
    if (inStrLen >= (sizeof(padded) - 4u))
    {
        /* No, input too long */
        return false;
    }

    /* Yes, validate before copying; padStart == inStrLen means no pad char seen yet */
    padStart = inStrLen;
    for (i = 0; i < inStrLen; i++)
    {
        /* Standard alphabet char that is not in the URL-safe alphabet? */
        if ((inStr[i] == '+') || (inStr[i] == '/'))
        {
            /* Yes, reject per RFC 4648 Sec. 3.3 */
            return false;
        }

        /* Pad char? */
        if (inStr[i] == '=')
        {
            /* Yes, remember where padding starts */
            if (padStart == inStrLen) padStart = i;
        }
        /* No, data after padding started? */
        else if (padStart != inStrLen)
        {
            /* Yes, padding is only valid at the end per RFC 4648 Sec. 3.3 */
            return false;
        }
    }

    /* Padding present? */
    if (padStart != inStrLen)
    {
        /* Yes, at most 2 pad chars and length already a multiple of 4 per RFC 4648 Sec. 3.2 */
        if ((inStrLen - padStart) > 2u) return false;
        if ((inStrLen % 4u) != 0u) return false;
    }

    /* Copy and map URL-safe chars to the standard alphabet */
    for (i = 0; i < inStrLen; i++)
    {
        if (inStr[i] == '-') padded[i] = '+';
        else if (inStr[i] == '_') padded[i] = '/';
        else padded[i] = inStr[i];
    }

    /* Add padding to make length multiple of 4 */
    paddedLen = inStrLen;
    while ((paddedLen % 4u) != 0u)
    {
        padded[paddedLen++] = '=';
    }
    padded[paddedLen] = '\0';

    /* Standard Base64 decode succeeded? */
    ok = SSFBase64Decode(padded, paddedLen, out, outSize, outLen);
    if (!ok)
    {
        /* No, zero partial output: completed blocks plus up to 2 bytes of the rejected block */
        SSFCryptSecureZero(out, SSF_MIN(*outLen + 2u, outSize));
        *outLen = 0;
    }
    SSF_ENSURE(*outLen <= outSize);

    /* Scrub the stack copy since Base64URL commonly carries key material */
    SSFCryptSecureZero(padded, paddedLen + 1u);
    return ok;
}

