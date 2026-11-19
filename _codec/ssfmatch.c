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
/* Returns true if pattern char pc matches str char sc, optionally ignoring ASCII case.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchGlobCharEq(char pc, char sc, bool caseInsensitive)
{
    /* Is the comparison case-insensitive? */
    if (caseInsensitive)
    {
        /* Yes */
        return (SSFStrCharToLower(pc) == SSFStrCharToLower(sc));
    }
    /* No */
    return (pc == sc);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str matches glob patternStr (O(len * patLen) time, O(1) stack), else false.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchGlobInternal(SSFCStrIn_t patternStr, SSFCStrIn_t str, bool caseInsensitive)
{
    SSFCStrIn_t starPat = NULL;
    SSFCStrIn_t starStr = NULL;

    SSF_REQUIRE(patternStr != NULL);
    SSF_REQUIRE(str != NULL);

    /* Only the most recent '*' is ever retried, which is sufficient (AUDIT MATCH-2) */
    while (*str != '\0')
    {
        /* Is the pattern at a run of '*' wildcards? */
        if (*patternStr == '*')
        {
            /* Yes, collapse the run; a trailing run matches whatever remains of str */
            while (*patternStr == '*') patternStr++;
            if (*patternStr == '\0') return true;

            /* Remember where to resume if the rest of the pattern fails here */
            starPat = patternStr;
            starStr = str;
        }
        /* No, does '?' or a literal char match the current char of str? */
        else if ((*patternStr != '\0') &&
                 ((*patternStr == '?') || _SSFMatchGlobCharEq(*patternStr, *str, caseInsensitive)))
        {
            /* Yes, consume one char of each */
            patternStr++;
            str++;
        }
        /* No, is there an earlier '*' that can absorb one more char? */
        else if (starPat != NULL)
        {
            /* Yes, retry the rest of the pattern one char further along str */
            starStr++;
            str = starStr;
            patternStr = starPat;
        }
        else
        {
            /* No, mismatch */
            return false;
        }
    }

    /* str is used up, so only '*' wildcards may remain in the pattern */
    while (*patternStr == '*') patternStr++;
    return (*patternStr == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str matches glob patternStr using '*' and '?' wildcards, else false.          */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchGlob(SSFCStrIn_t patternStr, SSFCStrIn_t str)
{
    SSF_REQUIRE(patternStr != NULL);
    SSF_REQUIRE(str != NULL);

    return _SSFMatchGlobInternal(patternStr, str, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str matches glob patternStr ignoring ASCII case, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchGlobI(SSFCStrIn_t patternStr, SSFCStrIn_t str)
{
    SSF_REQUIRE(patternStr != NULL);
    SSF_REQUIRE(str != NULL);

    return _SSFMatchGlobInternal(patternStr, str, true);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the name in [nameStart, nameEnd) holds '/', '{', '?' or '#', else false.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchPathNameHasDelim(const char *nameStart, const char *nameEnd)
{
    SSF_REQUIRE(nameStart != NULL);
    SSF_REQUIRE(nameEnd != NULL);
    SSF_REQUIRE(nameStart <= nameEnd);

    while (nameStart < nameEnd)
    {
        /* Is this a path delimiter or the start of another placeholder? */
        if ((*nameStart == '/') || (*nameStart == '{') || (*nameStart == '?') ||
            (*nameStart == '#'))
        {
            /* Yes */
            return true;
        }
        /* No */
        nameStart++;
    }
    return false;
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

            /* Does the name hold a path delimiter or '{', the mark of a mistyped pattern? */
            if (_SSFMatchPathNameHasDelim(nameStart, nameEnd))
            {
                /* Yes, malformed pattern (AUDIT MATCH-5) */
                return false;
            }
            /* No */

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
