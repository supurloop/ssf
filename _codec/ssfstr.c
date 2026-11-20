/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfstr.c                                                                                      */
/* Provides safe C string interfaces.                                                            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2023 Supurloop Software LLC                                                         */
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
#include "ssfport.h"
#include "ssfstr.h"

/* --------------------------------------------------------------------------------------------- */
/* Converts a character to lowercase. Non-alpha characters are returned unchanged.               */
/* --------------------------------------------------------------------------------------------- */
char SSFStrCharToLower(char c)
{
    if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
    return c;
}

/* --------------------------------------------------------------------------------------------- */
/* Converts a character to uppercase. Non-alpha characters are returned unchanged.               */
/* --------------------------------------------------------------------------------------------- */
char SSFStrCharToUpper(char c)
{
    if (c >= 'a' && c <= 'z') return (char)(c - ('a' - 'A'));
    return c;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str is valid, else false.                                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrIsValid(SSFCStrIn_t cstr, size_t cstrSize)
{
    /* Valid pointer? */
    if (cstr == NULL) return false;

    /* Valid size? */
    if (cstrSize == 0) return false;

    /* NULL within size bytes? */
    while (cstrSize)
    {
        if (*cstr == 0) return true;
        cstr++;
        cstrSize--;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if length determined and cstrLenOut set, else false if NULL terminator not found.*/
/* --------------------------------------------------------------------------------------------- */
bool SSFStrLen(SSFCStrIn_t cstr, size_t cstrSize, size_t *cstrLenOut)
{
    SSF_REQUIRE(cstr != NULL);
    SSF_REQUIRE(cstrLenOut != NULL);

    *cstrLenOut = 0;
    while (cstrSize > 0)
    {
        if (*cstr == 0) { return true; }
        cstr++;
        (*cstrLenOut)++;
        cstrSize--;
    }

    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if src fully catted to dst with NULL terminator cstrDstOutLenOut set, else false.*/
/* --------------------------------------------------------------------------------------------- */
bool SSFStrCat(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOutOpt,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize)
{
    size_t dstLen;
    size_t srcLen;

    SSF_REQUIRE(cstrDstOut != NULL);
    SSF_REQUIRE(cstrSrc != NULL);

    /* Determine length of dst */
    if (SSFStrLen(cstrDstOut, cstrDstOutSize, &dstLen) == false) return false;

    /* Determine length of src */
    if (SSFStrLen(cstrSrc, cstrSrcSize, &srcLen) == false) return false;

    /* Will src fully cat to dst? */
    if ((dstLen + srcLen) >= cstrDstOutSize) return false;

    /* Perform cat, NULL terminate dst, and report the length if asked (AUDIT STR-3) */
    memmove(&cstrDstOut[dstLen], cstrSrc, srcLen); /* src may overlap dst (AUDIT STR-7) */
    cstrDstOut[dstLen + srcLen] = 0;
    if (cstrDstOutLenOutOpt != NULL) *cstrDstOutLenOutOpt = dstLen + srcLen;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if src fully copied to dst with NULL terminator cstrDstOutLenOut set, else false.*/
/* --------------------------------------------------------------------------------------------- */
bool SSFStrCpy(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOutOpt,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize)
{
    size_t srcLen;

    SSF_REQUIRE(cstrDstOut != NULL);
    SSF_REQUIRE(cstrSrc != NULL);

    /* Determine length of src */
    if (SSFStrLen(cstrSrc, cstrSrcSize, &srcLen) == false) return false;

    /* Will src fully cpy to dst? */
    if (srcLen >= cstrDstOutSize) return false;

    /* Perform cpy, NULL terminate dst, and report the length if asked (AUDIT STR-3) */
    memmove(cstrDstOut, cstrSrc, srcLen); /* src may overlap dst (AUDIT STR-7) */
    cstrDstOut[srcLen] = 0;
    if (cstrDstOutLenOutOpt != NULL) *cstrDstOutLenOutOpt = srcLen;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if both strings exactly match, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrCmp(SSFCStrIn_t cstr1, size_t cstr1Size, SSFCStrIn_t cstr2, size_t cstr2Size)
{
    size_t cstr1Len;
    size_t cstr2Len;

    SSF_REQUIRE(cstr1 != NULL);
    SSF_REQUIRE(cstr2 != NULL);

    /* Determine length of cstr1 */
    if (SSFStrLen(cstr1, cstr1Size, &cstr1Len) == false) return false;

    /* Determine length of cstr2 */
    if (SSFStrLen(cstr2, cstr2Size, &cstr2Len) == false) return false;

    /* Same length? */
    if (cstr1Len != cstr2Len) return false;

    /* Match exactly? */
    return memcmp(cstr1, cstr2, cstr1Len) == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if string converted to case, else false if NULL terminator not found.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrToCase(SSFCStrOut_t cstrOut, size_t cstrOutSize, SSFSTRCase_t toCase)
{
    size_t cstrOutLen;

    SSF_REQUIRE(cstrOut != NULL);
    SSF_REQUIRE((toCase > SSF_STR_CASE_MIN) && (toCase < SSF_STR_CASE_MAX));

    /* Determine length of cstrOut */
    if (SSFStrLen(cstrOut, cstrOutSize, &cstrOutLen) == false) return false;

    /* One loop for both cases (OPTIMIZE STR-O2) */
    while (cstrOutLen > 0)
    {
        *cstrOut = (toCase == SSF_STR_CASE_LOWER) ? SSFStrCharToLower(*cstrOut) :
                                                    SSFStrCharToUpper(*cstrOut);
        cstrOut++;
        cstrOutLen--;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if substring found in cstr and matchStrOptOut set to start of match, else false.                                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrStr(SSFCStrIn_t cstr, size_t cstrSize, SSFCStrIn_t *matchStrOptOut, SSFCStrIn_t substr,
               size_t substrSize)
{
    SSFCStrIn_t ss;
    SSFCStrIn_t cstrs;
    size_t sss;

    SSF_REQUIRE(cstr != NULL);
    SSF_REQUIRE(substr != NULL);

    ss = substr;
    sss = substrSize;
    cstrs = NULL;
    /* Each size is checked before its byte is read (AUDIT STR-2) */
    while ((cstrSize > 0u) && (*cstr != 0) && (sss > 1u) && (*ss != 0))
    {
        /* Character match? */
        if (*cstr == *ss)
        {
            /* Start of new potential match? */
            if (cstrs == NULL)
            {
                /* Yes, save start */
                cstrs = cstr;
            }

            /* Yes, end of substr? */
            if (*(ss + 1) == 0)
            {
                if (matchStrOptOut != NULL) *matchStrOptOut = cstr - (ss - substr);
                return true;
            }
            ss++;
            sss--;
        }
        else
        {
            /* No, reset substr and cstr */
            ss = substr;
            sss = substrSize;
            if (cstrs != NULL)
            {
                cstrSize += (size_t)(cstr - cstrs);
                cstr = cstrs;
                cstrs = NULL;
            }
            /* Is this the last byte of cstr? */
            if (cstrSize <= 1u)
            {
                /* Yes, no match; clear the output as every false return does (AUDIT STR-6) */
                if (matchStrOptOut != NULL) *matchStrOptOut = NULL;
                return false;
            }
            /* No */
        }

        /* Advance */
        cstr++;
        cstrSize--;
    }
    if (matchStrOptOut != NULL) *matchStrOptOut = NULL;
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and the next token (final one included) if it fits, else false, nothing used.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrTok(SSFCStrIn_t *cstr, size_t *cstrSizeInOut, SSFCStrOut_t tokenStrOut,
               size_t tokenStrSize, size_t *tokenStrLenOutOpt, SSFCStrIn_t delims,
               size_t delimsSize)
{
    SSFCStrIn_t cs;
    SSFCStrIn_t dlms;
    size_t remaining;
    size_t dlmss;
    size_t tokLen;
    bool delimFound = false;

    SSF_REQUIRE(cstr != NULL);
    SSF_REQUIRE(*cstr != NULL);
    SSF_REQUIRE(cstrSizeInOut != NULL);
    SSF_REQUIRE(tokenStrOut != NULL);
    SSF_REQUIRE(tokenStrSize > 0u);
    SSF_REQUIRE(delims != NULL);

    /* On false the token is empty and nothing is consumed (AUDIT STR-4/5) */
    tokenStrOut[0] = 0;
    if (tokenStrLenOutOpt != NULL) *tokenStrLenOutOpt = 0;

    /* Is there input left within the remaining size (AUDIT STR-1)? */
    if ((*cstrSizeInOut == 0u) || (**cstr == 0))
    {
        /* No, end of input */
        return false;
    }
    /* Yes, scan to a delimiter, the NUL, or the end of the remaining size */
    cs = *cstr;
    remaining = *cstrSizeInOut;
    while ((remaining > 0u) && (*cs != 0) && (!delimFound))
    {
        dlms = delims;
        dlmss = delimsSize;
        while ((dlmss > 0u) && (*dlms != 0) && (!delimFound))
        {
            delimFound = (*cs == *dlms);
            dlms++;
            dlmss--;
        }
        /* Is this character part of the token? */
        if (!delimFound)
        {
            /* Yes */
            cs++;
            remaining--;
        }
        /* No, it is the delimiter that ends the token */
    }
    tokLen = (size_t)(cs - *cstr);

    /* Does the token and its terminator fit (AUDIT STR-5)? */
    if (tokLen >= tokenStrSize)
    {
        /* No, return false without consuming it so the caller can retry with more room */
        return false;
    }
    /* Yes */
    memcpy(tokenStrOut, *cstr, tokLen);
    tokenStrOut[tokLen] = 0;
    if (tokenStrLenOutOpt != NULL) *tokenStrLenOutOpt = tokLen;

    /* Did a delimiter end the token? */
    if (delimFound)
    {
        /* Yes, consume it too */
        cs++;
        remaining--;
    }
    /* No, the final token ended at the NUL or the end of the size */
    *cstr = cs;
    *cstrSizeInOut = remaining;
    return true;
}
