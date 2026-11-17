/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmatch.c                                                                                    */
/* Provides lightweight pattern matching interfaces.                                             */
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
#include "ssfassert.h"
#include "ssfmatch.h"
#include "ssfstr.h"

/* --------------------------------------------------------------------------------------------- */
/* Case-insensitive string comparison. Returns true if equal, else false.                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchStrI(SSFCStrIn_t a, SSFCStrIn_t b)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    while (*a != '\0' && *b != '\0')
    {
        if (SSFStrCharToLower(*a) != SSFStrCharToLower(*b)) return false;
        a++;
        b++;
    }
    return (*a == '\0') && (*b == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Case-insensitive string comparison for a given length. Stops at '\0' in either input (POSIX  */
/* strncasecmp semantics) so callers cannot accidentally read past the terminator when len is    */
/* larger than the actual string length.                                                         */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchStrNI(SSFCStrIn_t a, SSFCStrIn_t b, uint32_t len)
{
    uint32_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    for (i = 0; i < len; i++)
    {
        char ca = SSFStrCharToLower(a[i]);
        char cb = SSFStrCharToLower(b[i]);
        if (ca != cb) return false;
        if (ca == '\0') return true;   /* Both hit terminator at same position → equal. */
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal glob matching implementation.                                                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchGlobInternal(SSFCStrIn_t pattern, SSFCStrIn_t str, bool caseInsensitive)
{
    while (*pattern != '\0')
    {
        if (*pattern == '*')
        {
            /* Skip consecutive stars */
            while (*pattern == '*') pattern++;

            /* Trailing * matches everything */
            if (*pattern == '\0') return true;

            /* Try matching the rest of the pattern at each position in str */
            while (*str != '\0')
            {
                if (_SSFMatchGlobInternal(pattern, str, caseInsensitive)) return true;
                str++;
            }
            return _SSFMatchGlobInternal(pattern, str, caseInsensitive);
        }
        else if (*pattern == '?')
        {
            /* ? matches any single character */
            if (*str == '\0') return false;
            pattern++;
            str++;
        }
        else
        {
            /* Literal character match */
            if (caseInsensitive)
            {
                if (SSFStrCharToLower(*pattern) != SSFStrCharToLower(*str)) return false;
            }
            else
            {
                if (*pattern != *str) return false;
            }
            pattern++;
            str++;
        }
    }
    return (*str == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Glob pattern matching with * and ? wildcards.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchGlob(SSFCStrIn_t pattern, SSFCStrIn_t str)
{
    SSF_REQUIRE(pattern != NULL);
    SSF_REQUIRE(str != NULL);

    return _SSFMatchGlobInternal(pattern, str, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Case-insensitive glob pattern matching.                                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchGlobI(SSFCStrIn_t pattern, SSFCStrIn_t str)
{
    SSF_REQUIRE(pattern != NULL);
    SSF_REQUIRE(str != NULL);

    return _SSFMatchGlobInternal(pattern, str, true);
}

/* --------------------------------------------------------------------------------------------- */
/* URI path pattern matching with {param} placeholder extraction.                                */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchPath(SSFCStrIn_t pattern, SSFCStrIn_t path, SSFMatchParam_t *paramsOut,
                  uint32_t paramsSize, uint32_t *numParamsOut)
{
    const char *pp = pattern;
    const char *rp = path;
    uint32_t paramIdx = 0;

    SSF_REQUIRE(pattern != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE((paramsOut != NULL) || (paramsSize == 0));
    SSF_REQUIRE(numParamsOut != NULL);

    while (*pp != '\0' && *rp != '\0')
    {
        if (*pp == '{')
        {
            /* Extract parameter name from pattern */
            const char *nameStart = pp + 1;
            const char *nameEnd = nameStart;
            while (*nameEnd != '}' && *nameEnd != '\0') nameEnd++;
            if (*nameEnd != '}') return false;
            if (nameEnd == nameStart) return false;  /* Reject empty placeholder name '{}'. */

            /* Extract parameter value from path (until next '/' or end or '?') */
            {
                const char *valStart = rp;
                while (*rp != '/' && *rp != '\0' && *rp != '?') rp++;

                if (paramIdx < paramsSize)
                {
                    paramsOut[paramIdx].name = nameStart;
                    paramsOut[paramIdx].nameLen = (uint32_t)(nameEnd - nameStart);
                    paramsOut[paramIdx].value = valStart;
                    paramsOut[paramIdx].valueLen = (uint32_t)(rp - valStart);
                }
                paramIdx++;
            }
            pp = nameEnd + 1;
        }
        else
        {
            if (*pp != *rp) return false;
            pp++;
            rp++;
        }
    }

    /* Both must be exhausted (or path may have trailing query string) */
    if (*pp != '\0') return false;
    if (*rp != '\0' && *rp != '?') return false;

    *numParamsOut = paramIdx;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Validate a topic filter per MQTT v3.1.1 §4.7.1.2:                                             */
/*   '+' MUST occupy an entire level (preceded by '/' or start, followed by '/' or end).         */
/*   '#' MUST be the last character AND preceded by '/' (or be the whole filter).                */
/* Returns true if filter is syntactically valid, false otherwise.                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchTopicFilterIsValid(SSFCStrIn_t filter)
{
    const char *p = filter;
    char prev = '/';  /* Treat start-of-string as if it followed '/' so leading + / # is OK. */

    while (*p != '\0')
    {
        if (*p == '+')
        {
            if (prev != '/') return false;
            if (*(p + 1) != '/' && *(p + 1) != '\0') return false;
        }
        else if (*p == '#')
        {
            if (prev != '/') return false;
            if (*(p + 1) != '\0') return false;
        }
        prev = *p;
        p++;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* MQTT topic filter matching per MQTT v3.1.1 §4.7. Validates the filter first (§4.7.1.2) and    */
/* enforces the $-prefix rule (§4.7.2: filters starting with a wildcard do not match topics      */
/* starting with '$'). Returns false for malformed filters or $-prefix exemption.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFMatchTopic(SSFCStrIn_t filter, SSFCStrIn_t topic)
{
    SSF_REQUIRE(filter != NULL);
    SSF_REQUIRE(topic != NULL);

    /* §4.7.1.2: reject malformed filters up-front. */
    if (!_SSFMatchTopicFilterIsValid(filter)) return false;

    /* §4.7.2: a filter starting with a wildcard (# or +) does not match topics that
     * start with '$'. This guards $SYS-style internal topics from wildcard subscriptions. */
    if ((*filter == '+' || *filter == '#') && *topic == '$') return false;

    while (*filter != '\0' && *topic != '\0')
    {
        if (*filter == '#')
        {
            /* # matches everything remaining */
            return true;
        }
        else if (*filter == '+')
        {
            /* + matches one level: skip topic chars until next '/' or end */
            while (*topic != '/' && *topic != '\0') topic++;
            filter++;
        }
        else
        {
            /* Literal match */
            if (*filter != *topic) return false;
            filter++;
            topic++;
        }
    }

    /* Handle trailing # after / in filter: "sensor/#" matches "sensor" */
    if (*filter == '/' && *(filter + 1) == '#' && *(filter + 2) == '\0' && *topic == '\0')
    {
        return true;
    }

    /* §4.7.1.2 example: "sport/tennis/+" matches "sport/tennis/ball/". A trailing '/'
     * in the topic represents an optional empty final level; accept it when the
     * filter has consumed the level just before it. */
    if (*filter == '\0' && *topic == '/' && *(topic + 1) == '\0') return true;

    /* Trailing '+' absorbs the empty final level after a '/': "a/+" matches "a/",
     * "+" matches "a/" (after + has consumed the "a" level into the loop). */
    if (*filter == '+' && *(filter + 1) == '\0' && *topic == '\0') return true;

    /* Both must be exhausted, or filter ends with # */
    if (*filter == '#') return true;
    return (*filter == '\0') && (*topic == '\0');
}
