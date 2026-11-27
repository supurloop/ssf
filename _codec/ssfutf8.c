/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfutf8.c                                                                                     */
/* Provides a strict UTF-8 (RFC 3629) validator, decoder and encoder.                            */
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
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfutf8.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_UTF8_TRAIL_LO       (0x80u)    /* Default trail byte range */
#define SSF_UTF8_TRAIL_HI       (0xBFu)
#define SSF_UTF8_SURR_LO        (0xD800ul) /* UTF-16 surrogate code points */
#define SSF_UTF8_SURR_HI_END    (0xDBFFul)
#define SSF_UTF8_SURR_LO_START  (0xDC00ul)
#define SSF_UTF8_SURR_HI        (0xDFFFul)

/* --------------------------------------------------------------------------------------------- */
/* Returns true and sets *cpOut, *seqLenOut for the well-formed sequence at str, else false.     */
/* --------------------------------------------------------------------------------------------- */
bool SSFUTF8DecodeNext(const uint8_t *str, size_t strLen, uint32_t *cpOut, size_t *seqLenOut)
{
    uint32_t cp;
    size_t n;
    size_t i;
    uint8_t lo = SSF_UTF8_TRAIL_LO;
    uint8_t hi = SSF_UTF8_TRAIL_HI;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(cpOut != NULL);
    SSF_REQUIRE(seqLenOut != NULL);

    /* Is the input empty? */
    if (strLen == 0u)
    {
        /* Yes, no sequence */
        return false;
    }
    /* No */
    cp = str[0];

    /* Is the lead byte ASCII? */
    if (cp < 0x80u)
    {
        /* Yes, one byte */
        *cpOut = cp;
        *seqLenOut = 1u;
        return true;
    }
    /* No, is it a trail byte or an overlong 2-byte lead (C0, C1)? */
    if (cp < 0xC2u)
    {
        /* Yes, ill formed */
        return false;
    }
    /* No, is it a 2-byte lead? */
    else if (cp < 0xE0u)
    {
        /* Yes */
        n = 2u;
        cp &= 0x1Fu;
    }
    /* No, is it a 3-byte lead? */
    else if (cp < 0xF0u)
    {
        /* Yes */
        n = 3u;
        /* Is it E0, whose first trail byte must be A0..BF to avoid an overlong form? */
        if (cp == 0xE0u)
        {
            /* Yes */
            lo = 0xA0u;
        }
        /* No, is it ED, whose first trail byte must be 80..9F to avoid a surrogate? */
        else if (cp == 0xEDu)
        {
            /* Yes */
            hi = 0x9Fu;
        }
        /* No, any trail byte 80..BF */
        cp &= 0x0Fu;
    }
    /* No, is it a 4-byte lead? */
    else if (cp < 0xF5u)
    {
        /* Yes */
        n = 4u;
        /* Is it F0, whose first trail byte must be 90..BF to avoid an overlong form? */
        if (cp == 0xF0u)
        {
            /* Yes */
            lo = 0x90u;
        }
        /* No, is it F4, whose first trail byte must be 80..8F to stay within U+10FFFF? */
        else if (cp == 0xF4u)
        {
            /* Yes */
            hi = 0x8Fu;
        }
        /* No, any trail byte 80..BF */
        cp &= 0x07u;
    }
    else
    {
        /* No, F5..FF never appear in UTF-8 */
        return false;
    }

    /* Is the sequence cut off by the end of the input? */
    if (strLen < n)
    {
        /* Yes, ill formed */
        return false;
    }
    /* No */
    for (i = 1u; i < n; i++)
    {
        /* Is the trail byte outside its allowed range? */
        if ((str[i] < lo) || (str[i] > hi))
        {
            /* Yes, ill formed */
            return false;
        }
        /* No, only the first trail byte has a narrowed range */
        lo = SSF_UTF8_TRAIL_LO;
        hi = SSF_UTF8_TRAIL_HI;
        cp = (cp << 6) | (uint32_t)(str[i] & 0x3Fu);
    }
    *cpOut = cp;
    *seqLenOut = n;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all strLen bytes are well-formed UTF-8, U+0000 refused unless allowNul.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFUTF8IsValid(const uint8_t *str, size_t strLen, bool allowNul)
{
    size_t n = 0u;
    uint32_t cp = 0u;

    SSF_REQUIRE(str != NULL);

    while (strLen > 0u)
    {
        /* Is the next sequence ill formed, or a NUL that is not allowed? */
        if ((!SSFUTF8DecodeNext(str, strLen, &cp, &n)) || ((cp == 0u) && (!allowNul)))
        {
            /* Yes */
            return false;
        }
        /* No */
        SSF_ENSURE((n >= 1u) && (n <= strLen));
        str += n;
        strLen -= n;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and sets *outLenOut if cp's shortest UTF-8 form was written to out, else false.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUTF8EncodeCP(uint32_t cp, uint8_t *out, size_t outSize, size_t *outLenOut)
{
    size_t n;
    size_t i;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLenOut != NULL);

    /* Is cp a surrogate or above U+10FFFF? */
    if (((cp >= SSF_UTF8_SURR_LO) && (cp <= SSF_UTF8_SURR_HI)) || (cp > SSF_UTF8_MAX_CP))
    {
        /* Yes, not a Unicode scalar value */
        return false;
    }
    /* No, does cp fit in one byte? */
    if (cp < 0x80ul)
    {
        /* Yes */
        n = 1u;
    }
    /* No, does it fit in two bytes? */
    else if (cp < 0x800ul)
    {
        /* Yes */
        n = 2u;
    }
    /* No, does it fit in three bytes? */
    else if (cp < 0x10000ul)
    {
        /* Yes */
        n = 3u;
    }
    else
    {
        /* No, four bytes */
        n = 4u;
    }

    /* Is the output too small? */
    if (outSize < n)
    {
        /* Yes, write nothing */
        return false;
    }
    /* No, is it a one-byte form? */
    if (n == 1u)
    {
        /* Yes */
        out[0] = (uint8_t)cp;
    }
    else
    {
        /* No, trail bytes from the end, then the lead byte with n leading 1 bits */
        for (i = n - 1u; i > 0u; i--)
        {
            out[i] = (uint8_t)(SSF_UTF8_TRAIL_LO | (cp & 0x3Fu));
            cp >>= 6;
        }
        out[0] = (uint8_t)(((0xFF00u >> n) & 0xFFu) | cp);
    }
    *outLenOut = n;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and sets *cpOut if hi, lo are a high then low UTF-16 surrogate, else false.      */
/* --------------------------------------------------------------------------------------------- */
bool SSFUTF8FromUTF16Pair(uint16_t hi, uint16_t lo, uint32_t *cpOut)
{
    SSF_REQUIRE(cpOut != NULL);

    /* Is hi outside D800..DBFF or lo outside DC00..DFFF? */
    if ((hi < SSF_UTF8_SURR_LO) || (hi > SSF_UTF8_SURR_HI_END) ||
        (lo < SSF_UTF8_SURR_LO_START) || (lo > SSF_UTF8_SURR_HI))
    {
        /* Yes, not a surrogate pair */
        return false;
    }
    /* No */
    *cpOut = 0x10000ul + ((((uint32_t)hi) - SSF_UTF8_SURR_LO) << 10) +
             (((uint32_t)lo) - SSF_UTF8_SURR_LO_START);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and sets *countOut to the code points in str if well formed, else false.         */
/* --------------------------------------------------------------------------------------------- */
bool SSFUTF8Count(const uint8_t *str, size_t strLen, size_t *countOut)
{
    size_t n = 0u;
    size_t count = 0u;
    uint32_t cp;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(countOut != NULL);

    while (strLen > 0u)
    {
        /* Is the next sequence ill formed? */
        if (!SSFUTF8DecodeNext(str, strLen, &cp, &n))
        {
            /* Yes */
            return false;
        }
        /* No */
        SSF_ENSURE((n >= 1u) && (n <= strLen));
        str += n;
        strLen -= n;
        count++;
    }
    *countOut = count;
    return true;
}
