/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmatch.c                                                                                    */
/* Provides lightweight pattern matching interfaces.                                             */
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
#include "ssfmatch.h"
#include "ssfstr.h"

/* --------------------------------------------------------------------------------------------- */
/* Returns true if aStr and bStr are equal ignoring ASCII case, else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchStrI(SSFCStrIn_t aStr, SSFCStrIn_t bStr)
{
    SSF_REQUIRE(aStr != NULL);
    SSF_REQUIRE(bStr != NULL);

    while ((*aStr != '\0') && (*bStr != '\0'))
    {
        if (SSFStrCharToLower(*aStr) != SSFStrCharToLower(*bStr)) return false;
        aStr++;
        bStr++;
    }
    return (*aStr == '\0') && (*bStr == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if up to len chars of aStr and bStr are equal ignoring ASCII case, else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchStrNI(SSFCStrIn_t aStr, SSFCStrIn_t bStr, uint32_t len)
{
    uint32_t i;
    char ca;
    char cb;

    SSF_REQUIRE(aStr != NULL);
    SSF_REQUIRE(bStr != NULL);

    for (i = 0; i < len; i++)
    {
        ca = SSFStrCharToLower(aStr[i]);
        cb = SSFStrCharToLower(bStr[i]);
        if (ca != cb) return false;

        /* Both strings ended at the same position, so stop before reading past a terminator */
        if (ca == '\0') return true;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str matches glob patternStr, else false.                                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchGlobInternal(SSFCStrIn_t patternStr, SSFCStrIn_t str, bool caseInsensitive)
{
    SSF_REQUIRE(patternStr != NULL);
    SSF_REQUIRE(str != NULL);

    while (*patternStr != '\0')
    {
        /* Run of '*' wildcards? */
        if (*patternStr == '*')
        {
            /* Yes, collapse the run; a trailing run matches whatever remains of str */
            while (*patternStr == '*') patternStr++;
            if (*patternStr == '\0') return true;

            /* Try the rest of the pattern at each remaining position of str */
            while (*str != '\0')
            {
                if (_SSFMatchGlobInternal(patternStr, str, caseInsensitive)) return true;
                str++;
            }
            return _SSFMatchGlobInternal(patternStr, str, caseInsensitive);
        }
        /* No, single char wildcard? */
        else if (*patternStr == '?')
        {
            /* Yes, it must consume exactly one char */
            if (*str == '\0') return false;
            patternStr++;
            str++;
        }
        /* No, literal char must match, optionally ignoring ASCII case */
        else
        {
            if (caseInsensitive)
            {
                if (SSFStrCharToLower(*patternStr) != SSFStrCharToLower(*str)) return false;
            }
            else if (*patternStr != *str) return false;
            patternStr++;
            str++;
        }
    }
    return (*str == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if patternStr has more than SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS '*' runs.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchGlobTooManyWildcards(SSFCStrIn_t patternStr)
{
    uint32_t runs = 0;
    bool inRun = false;

    SSF_REQUIRE(patternStr != NULL);

    while (*patternStr != '\0')
    {
        /* Start of a new '*' run? */
        if ((*patternStr == '*') && !inRun)
        {
            /* Yes, count it and stop as soon as the limit is exceeded */
            runs++;
            if (runs > SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS) return true;
        }
        inRun = (*patternStr == '*');
        patternStr++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str matches glob patternStr using '*' and '?' wildcards, else false.          */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchGlob(SSFCStrIn_t patternStr, SSFCStrIn_t str)
{
    SSF_REQUIRE(patternStr != NULL);
    SSF_REQUIRE(str != NULL);

    /* Pattern within the configured wildcard bound? */
    if (_SSFMatchGlobTooManyWildcards(patternStr))
    {
        /* No, refuse rather than risk exponential backtracking */
        return false;
    }
    return _SSFMatchGlobInternal(patternStr, str, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str matches glob patternStr ignoring ASCII case, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchGlobI(SSFCStrIn_t patternStr, SSFCStrIn_t str)
{
    SSF_REQUIRE(patternStr != NULL);
    SSF_REQUIRE(str != NULL);

    /* Pattern within the configured wildcard bound? */
    if (_SSFMatchGlobTooManyWildcards(patternStr))
    {
        /* No, refuse rather than risk exponential backtracking */
        return false;
    }
    return _SSFMatchGlobInternal(patternStr, str, true);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pathStr matches patternStr and extracts its {param} values, else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchPath(SSFCStrIn_t patternStr, SSFCStrIn_t pathStr, SSFMatchParam_t *paramsOutOpt,
                  uint32_t paramsOutOptSize, uint32_t *numParamsOut)
{
    const char *pp = patternStr;
    const char *rp = pathStr;
    const char *nameStart;
    const char *nameEnd;
    const char *valStart;
    uint32_t paramIdx = 0;

    SSF_REQUIRE(patternStr != NULL);
    SSF_REQUIRE(pathStr != NULL);
    SSF_REQUIRE((paramsOutOpt != NULL) || (paramsOutOptSize == 0));
    SSF_REQUIRE(numParamsOut != NULL);

    /* Every failure path reports zero parameters */
    *numParamsOut = 0;

    while ((*pp != '\0') && (*rp != '\0'))
    {
        /* Placeholder? */
        if (*pp == '{')
        {
            /* Yes, find the end of its name */
            nameStart = pp + 1;
            nameEnd = nameStart;
            while ((*nameEnd != '}') && (*nameEnd != '\0')) nameEnd++;

            /* Placeholder unterminated or named '{}'? */
            if ((*nameEnd != '}') || (nameEnd == nameStart))
            {
                /* Yes, malformed pattern */
                return false;
            }

            /* The value runs to the next '/', end of path, query '?' or fragment '#' */
            valStart = rp;
            while ((*rp != '/') && (*rp != '\0') && (*rp != '?') && (*rp != '#')) rp++;

            /* Placeholder bound an empty segment? */
            if (rp == valStart)
            {
                /* Yes, a placeholder must match one non-empty segment */
                return false;
            }

            /* Room to store this parameter? */
            if (paramIdx < paramsOutOptSize)
            {
                /* Yes, record it; otherwise it is only counted */
                paramsOutOpt[paramIdx].name = nameStart;
                paramsOutOpt[paramIdx].nameLen = (uint32_t)(nameEnd - nameStart);
                paramsOutOpt[paramIdx].value = valStart;
                paramsOutOpt[paramIdx].valueLen = (uint32_t)(rp - valStart);
            }
            paramIdx++;
            pp = nameEnd + 1;
        }
        /* No, literal chars must match */
        else
        {
            if (*pp != *rp) return false;
            pp++;
            rp++;
        }
    }

    /* Pattern exhausted and path exhausted or at a query '?' or fragment '#' (RFC 3986 3.3)? */
    if ((*pp != '\0') || ((*rp != '\0') && (*rp != '?') && (*rp != '#')))
    {
        /* No, mismatch */
        return false;
    }

    /* Yes, matched */
    *numParamsOut = paramIdx;
    return true;
}
