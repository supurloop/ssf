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
bool SSFStrCat(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOut,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize)
{
    size_t dstLen;
    size_t srcLen;

    SSF_REQUIRE(cstrDstOut != NULL);
    SSF_REQUIRE(cstrDstOutLenOut != NULL);
    SSF_REQUIRE(cstrSrc != NULL);

    /* Determine length of dst */
    if (SSFStrLen(cstrDstOut, cstrDstOutSize, &dstLen) == false) return false;

    /* Determine length of src */
    if (SSFStrLen(cstrSrc, cstrSrcSize, &srcLen) == false) return false;

    /* Will src fully cat to dst? */
    if ((dstLen + srcLen) >= cstrDstOutSize) return false;

    /* Perform cat, update out len, and NULL terminate dst */
    memcpy(&cstrDstOut[dstLen], cstrSrc, srcLen);
    *cstrDstOutLenOut = dstLen + srcLen;
    cstrDstOut[*cstrDstOutLenOut] = 0;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if src fully copied to dst with NULL terminator cstrDstOutLenOut set, else false.*/
/* --------------------------------------------------------------------------------------------- */
bool SSFStrCpy(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOut,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize)
{
    //size_t dstLen;
    size_t srcLen;

    SSF_REQUIRE(cstrDstOut != NULL);
    SSF_REQUIRE(cstrDstOutLenOut != NULL);
    SSF_REQUIRE(cstrSrc != NULL);

    /* Determine length of dst */
    if (cstrDstOutSize == 0) return false;
    //if (SSFStrLen(cstrDstOut, cstrDstOutSize, &dstLen) == false) return false;

    /* Determine length of src */
    if (SSFStrLen(cstrSrc, cstrSrcSize, &srcLen) == false) return false;

    /* Will src fully cpy to dst? */
    if (srcLen >= cstrDstOutSize) return false;

    /* Perform cpy, update out len, and NULL terminate dst */
    memcpy(cstrDstOut, cstrSrc, srcLen);
    *cstrDstOutLenOut = srcLen;
    cstrDstOut[*cstrDstOutLenOut] = 0;

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
    #define SSFSTR_UPPER_LOWER_DELTA ((int8_t)('a' - 'A'))
    size_t cstrOutLen;

    SSF_REQUIRE(cstrOut != NULL);
    SSF_REQUIRE((toCase > SSF_STR_CASE_MIN) && (toCase < SSF_STR_CASE_MAX));

    /* Determine length of cstrOut */
    if (SSFStrLen(cstrOut, cstrOutSize, &cstrOutLen) == false) return false;

    switch(toCase)
    {
        case SSF_STR_CASE_LOWER:
            while (cstrOutLen > 0)
            {
                if ((*cstrOut >= 'A') && (*cstrOut <= 'Z')) (*cstrOut) += SSFSTR_UPPER_LOWER_DELTA;
                cstrOut++;
                cstrOutLen--;
            }
            break;
        case SSF_STR_CASE_UPPER:
            while (cstrOutLen > 0)
            {
                if ((*cstrOut >= 'a') && (*cstrOut <= 'z')) (*cstrOut) -= SSFSTR_UPPER_LOWER_DELTA;
                cstrOut++;
                cstrOutLen--;
            }
            break;
        default:
            SSF_ERROR();
            break;
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
    size_t sss;

    SSF_REQUIRE(cstr != NULL);
    SSF_REQUIRE(substr != NULL);

    ss = substr;
    sss = substrSize;
    while ((*cstr != 0) && (cstrSize > 0) && (*ss != 0) && (sss > 0))
    {
        /* Character match? */
        if (*cstr == *ss)
        {
            /* Yes, end of substr? */
            if (*(ss + 1) == 0)
            {
                if (matchStrOptOut != NULL) *matchStrOptOut = cstr - (ss - substr);
                return true;
            }
        }
        else
        {
            /* No, reset substr */
            ss = substr;
            sss = substrSize;
        }

        /* Advance */
        cstr++;
        cstrSize--;
        ss++;
        sss--;
    }
    if (matchStrOptOut != NULL) *matchStrOptOut = NULL;
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if delim found in cstr, else false. tokenStrLen >= 0 when tokenStr is set.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrTok(SSFCStrIn_t *cstr, size_t cstrSize, SSFCStrOut_t tokenStrOut, size_t tokenStrSize,
               int32_t *tokenStrLen, SSFCStrIn_t delims, size_t delimsSize)
{
    SSFCStrIn_t cs;
    SSFCStrIn_t dlms;
    size_t dlmss;
    bool retVal = false;

    SSF_REQUIRE(cstr != NULL);
    SSF_REQUIRE(*cstr != NULL);
    SSF_REQUIRE(tokenStrOut != NULL);
    SSF_REQUIRE(tokenStrLen != NULL);
    SSF_REQUIRE(delims != NULL);

    /* Iterate over cstr */
    cs = *cstr;
    while ((*cs != 0) && (cstrSize > 0))
    {
        /* Iterate over delims */
        dlms = delims;
        dlmss = delimsSize;
        while ((*dlms != 0) && (dlmss > 0))
        {
            /* Delim match? */
            if (*cs == *dlms)
            {
                /* Yes, return token */
                retVal = true;
                goto tokDone;
            }
            dlms++;
            dlmss--;
        }
        cs++;
        cstrSize--;
    }

tokDone:    
    /* Enough room to copy token? */
    if ((size_t)((cs - (*cstr)) + 1) <= tokenStrSize)
    {
        /* Yes, copy into token buffer */
        *tokenStrLen = cs - (*cstr);
        memcpy(tokenStrOut, *cstr, *tokenStrLen);
        tokenStrOut[*tokenStrLen] = 0;
    }
    /* No, tokenStr not set */
    else *tokenStrLen = -1;

    /* Set next token  */
    if (retVal) *cstr = cs + 1;
    else *cstr = cs;

    return retVal;
}
