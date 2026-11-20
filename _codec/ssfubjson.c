/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfubjson.c                                                                                   */
/* Provides Universal Binary JSON parser/generator interface.                                    */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#include "ssfport.h"
#include "ssfubjson.h"
#include "ssfhex.h"
#include "ssfbase64.h"

/* --------------------------------------------------------------------------------------------- */
/* Local Defines                                                                                 */
/* --------------------------------------------------------------------------------------------- */
#define UBJ_TYPE_NULL 'Z'
#define UBJ_TYPE_NOOP 'N'
#define UBJ_TYPE_TRUE 'T'
#define UBJ_TYPE_FALSE 'F'
#define UBJ_TYPE_INT8 'i'
#define UBJ_TYPE_UINT8 'U'
#define UBJ_TYPE_INT16 'I'
#define UBJ_TYPE_INT32 'l'
#define UBJ_TYPE_INT64 'L'
#define UBJ_TYPE_FLOAT32 'd'
#define UBJ_TYPE_FLOAT64 'D'
#define UBJ_TYPE_CHAR 'C'
#define UBJ_TYPE_HPN 'H'
#define UBJ_TYPE_STRING 'S'
#define UBJ_TYPE_OBJ_OPEN '{'
#define UBJ_TYPE_ARRAY_OPEN '['
#define UBJ_TYPE_OBJ_CLOSE '}'
#define UBJ_TYPE_ARRAY_CLOSE ']'
#define UBJ_TYPE_ARRAY_OPT '$'
#define UBJ_TYPE_ARRAY_NUM '#'
#define SSF_UBJSON_MAGIC (0x55424A53ul)

/* --------------------------------------------------------------------------------------------- */
/* Local Prototypes.                                                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonValue(const uint8_t *js, size_t jsLen, size_t *index, size_t *start,
                            size_t *end, const SSFGPath_t *pathOpt, uint8_t depth,
                            SSFUBJsonType_t *jt, uint8_t override);

static bool _SSFUBJsonTypeField(const uint8_t *js, size_t jsLen, size_t *index, size_t *fstart,
                              size_t *fend, SSFUBJsonType_t *fjt, uint8_t override);

bool _SSFUBJsonObject(const uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                      const SSFGPath_t *pathOpt, uint8_t depth, SSFUBJsonType_t *jt);

/* --------------------------------------------------------------------------------------------- */
/* Returns true if array found, else false; If true returns type/start/end on path index match.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonArray(const uint8_t *js, size_t jsLen, size_t *index, size_t *start,
                            size_t *end, size_t *astart, size_t *aend, const SSFGPath_t *pathOpt,
                            uint8_t depth, SSFUBJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    size_t curIndex = 0;
    size_t pindex = (size_t)-1;
    SSFUBJsonType_t djt;
    size_t fstart;
    size_t fend;
    size_t len = (size_t)-1;
    SSFUBJsonType_t fjt;
    uint8_t t = 0;
    bool isOpt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(astart != NULL);
    SSF_REQUIRE(aend != NULL);
    SSF_REQUIRE(jt != NULL);

    if (depth == 0)
    {
        if (jsLen > SSF_UBJSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_UBJSON_TYPE_ERROR;
        *index = 0;
    }
    if (depth >= SSF_UBJSON_CONFIG_MAX_IN_DEPTH) return false;
    if (*index >= jsLen) return false;
    if (js[*index] != UBJ_TYPE_ARRAY_OPEN) return false;

    *astart = *index;
    /* Does the path end at this array? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_END))
    {
        /* Yes, it starts here */
        *start = *index;
    }
    (*index)++; if (*index >= jsLen) return false;

    /* Opt type field? */
    isOpt = (js[*index] == UBJ_TYPE_ARRAY_OPT);
    if (isOpt)
    {
        (*index)++; if (*index >= jsLen) return false;
        t = js[*index];
        (*index)++; if (*index >= jsLen) return false;
    }

    /* Is an array type missing the array count that must follow it? */
    if ((t != 0) && (js[*index] != UBJ_TYPE_ARRAY_NUM))
    {
        /* Yes, invalid */
        return false;
    }

    /* Opt len field? */
    if (js[*index] == UBJ_TYPE_ARRAY_NUM)
    {
        (*index)++; if (*index >= jsLen) return false;
        if (_SSFUBJsonTypeField(js, jsLen, index, &fstart, &fend, &fjt, 0) == false) return false;
        switch (fjt)
        {
        case SSF_UBJSON_TYPE_NUMBER_INT8:
        case SSF_UBJSON_TYPE_NUMBER_UINT8:
        case SSF_UBJSON_TYPE_NUMBER_CHAR:
            len = js[fstart];
            break;
        default:
            /* Not allowing 16, 32, 64-bit types for length */
            return false;
        }
    }

    /* Is the next path entry an array element index? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_INDEX))
    {
        /* Yes, select that element; any other kind of entry selects none */
        pindex = *(pathOpt[depth].u.index);
    }

    /* Is the array counted and empty? */
    if ((len != (size_t)-1) && (len == 0))
    {
        /* Yes, no elements to parse */
        goto valDone;
    }
    if (*index >= jsLen) return false;
    /* Is the array uncounted and closed right away? */
    if ((js[*index] == UBJ_TYPE_ARRAY_CLOSE) && (len == (size_t)-1))
    {
        /* Yes, no elements to parse */
        goto valDone;
    }
    while (true)
    {
        bool found;

        /* Is this the element at the path index? */
        if (pindex == curIndex)
        {
            /* Yes, it follows the path and reports straight into the caller's results */
            found = _SSFUBJsonValue(js, jsLen, index, start, end, pathOpt, depth, jt, t);
        }
        else
        {
            /* No, parse it only to skip it */
            found = _SSFUBJsonValue(js, jsLen, index, &valStart, &valEnd, NULL, depth, &djt, t);
        }
        if (!found) break;
        if (len != (size_t)-1) len--;
        /* Is the array counted and is this its last element? */
        if ((len != (size_t)-1) && (len == 0))
        {
            /* Yes, done */
            break;
        }
        if (isOpt == false)
        {
            if (*index >= jsLen) return false;
            /* Is the array uncounted and closed after this element? */
            if ((js[*index] == UBJ_TYPE_ARRAY_CLOSE) && (len == (size_t)-1))
            {
                /* Yes, done */
                break;
            }
        }
        curIndex++;
    }
valDone:
    /* Is the path index past the last element? */
    if ((pindex != (size_t)-1) && (pindex > curIndex))
    {
        /* Yes, the path matches nothing */
        *jt = SSF_UBJSON_TYPE_ERROR;
    }
    if (isOpt == false)
    {
        if (*index >= jsLen) return false;
        /* Is an uncounted array missing its closing marker? */
        if ((js[*index] != UBJ_TYPE_ARRAY_CLOSE) && (len == (size_t)-1))
        {
            /* Yes, invalid */
            return false;
        }
    }
    *aend = *index;

    /* Does the path end at this array? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_END))
    {
        /* Yes, report its span and type */
        *end = *index;
        *jt = SSF_UBJSON_TYPE_ARRAY;
    }
    if (len == (size_t)-1) (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if type field found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonTypeField(const uint8_t *js, size_t jsLen, size_t *index, size_t *fstart,
                              size_t *fend, SSFUBJsonType_t *fjt, uint8_t override)
{
    size_t len;
    uint8_t t;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(fstart != NULL);
    SSF_REQUIRE(fend != NULL);
    SSF_REQUIRE(fjt != NULL);

    if (override == 0)
    {
        while (js[*index] == UBJ_TYPE_NOOP)
        { (*index)++; if (*index >= jsLen) return false; }
        t = js[*index];
        /* Is the type marker followed by a payload (not a container open or close)? */
        if ((t != UBJ_TYPE_OBJ_OPEN) && (t != UBJ_TYPE_ARRAY_OPEN) &&
            (t != UBJ_TYPE_OBJ_CLOSE) && (t != UBJ_TYPE_ARRAY_CLOSE))
        {
            /* Yes, step past the marker */
            (*index)++;
            if (*index >= jsLen) return false;
        }
    }
    else { t = override; }

    switch (t)
    {
        case UBJ_TYPE_FLOAT32:
        *fjt = SSF_UBJSON_TYPE_NUMBER_FLOAT32; len = sizeof(float);
        goto _ssfubParseInt;
        case UBJ_TYPE_FLOAT64:
        *fjt = SSF_UBJSON_TYPE_NUMBER_FLOAT64; len = sizeof(double);
        goto _ssfubParseInt;
        case UBJ_TYPE_INT16:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT16; len = sizeof(int16_t);
        goto _ssfubParseInt;
        case UBJ_TYPE_INT32:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT32; len = sizeof(int32_t);
        goto _ssfubParseInt;
        case UBJ_TYPE_INT64:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT64; len = sizeof(int64_t);
        goto _ssfubParseInt;
        case UBJ_TYPE_CHAR:
        *fjt = SSF_UBJSON_TYPE_STRING;
        len = sizeof(uint8_t);
        goto _ssfubParseInt;
        case UBJ_TYPE_UINT8:
        *fjt = SSF_UBJSON_TYPE_NUMBER_UINT8; len = sizeof(uint8_t);
        goto _ssfubParseInt;
        case UBJ_TYPE_INT8:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT8; len = sizeof(int8_t);
        /* Fall through on purpose */
        _ssfubParseInt:
        *fstart = *index;
        (*index) += len; if (*index > jsLen) return false;
        *fend = *index;
        return true;
        case UBJ_TYPE_HPN:
#if SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING == 0
        return false;
#endif
        /* Fallthough, treat HPN as a string */
        case UBJ_TYPE_STRING:
        {
            size_t tstart;
            size_t tend;
            SSFUBJsonType_t tjt;

            if (_SSFUBJsonTypeField(js, jsLen, index, &tstart, &tend, &tjt, 0) == false)
            { return false; }
            switch (tjt)
            {
                case SSF_UBJSON_TYPE_NUMBER_INT8:
                case SSF_UBJSON_TYPE_NUMBER_UINT8:
                case SSF_UBJSON_TYPE_NUMBER_CHAR:
                len = js[tstart];
                break;
                default:
                /* Not allowing 16, 32, 64-bit types for name length */
                return false;
            }
            *fstart = *index;
            (*index) += len; if (*index > jsLen) return false;
            *fend = *index;
            *fjt = SSF_UBJSON_TYPE_STRING;
            return true;
        }
        case UBJ_TYPE_OBJ_OPEN:
        *fjt = SSF_UBJSON_TYPE_OBJECT;
        return true;
        case UBJ_TYPE_ARRAY_OPEN:
        *fjt = SSF_UBJSON_TYPE_ARRAY;
        return true;
        case UBJ_TYPE_TRUE:
        *fjt = SSF_UBJSON_TYPE_TRUE;
        goto _ssfubParseSingle;
        case UBJ_TYPE_FALSE:
        *fjt = SSF_UBJSON_TYPE_FALSE;
        goto _ssfubParseSingle;
        case UBJ_TYPE_NULL:
        *fjt = SSF_UBJSON_TYPE_NULL;
        _ssfubParseSingle:
        *fstart = *index;
        *fend = *fstart;
        return true;
        case UBJ_TYPE_OBJ_CLOSE:
        return false;
        case UBJ_TYPE_ARRAY_CLOSE:
        return false;
        default:
        break;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value found, else false; If true returns type/start/end on path match.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonValue(const uint8_t *js, size_t jsLen, size_t *index, size_t *start,
                            size_t *end, const SSFGPath_t *pathOpt, uint8_t depth,
                            SSFUBJsonType_t *jt, uint8_t override)
{
    size_t i;
    size_t astart;
    size_t aend;
    size_t valStart = 0;
    size_t valEnd = 0;
    SSFUBJsonType_t valType;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    if (_SSFUBJsonTypeField(js, jsLen, index, &valStart, &valEnd, &valType, override) == false)
    { return false; }

    i = *index;
    switch (valType)
    {
        case SSF_UBJSON_TYPE_OBJECT:
        if (_SSFUBJsonObject(js, jsLen, &i, start, end, pathOpt, depth + 1, jt))
        {
            *index = i;
            return true;
        }
        break;
        case SSF_UBJSON_TYPE_ARRAY:
        if (_SSFUBJsonArray(js, jsLen, &i, start, end, &astart, &aend, pathOpt, depth + 1, jt))
        {
            /* Does the path end at this array? */
            if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_END))
            {
                /* Yes, report the whole array as the span */
                *start = astart;
                *end = i;
            }
            *index = i;
            return true;
        }
        break;
        case SSF_UBJSON_TYPE_STRING:
        case SSF_UBJSON_TYPE_NUMBER_FLOAT32:
        case SSF_UBJSON_TYPE_NUMBER_FLOAT64:
        case SSF_UBJSON_TYPE_NUMBER_INT8:
        case SSF_UBJSON_TYPE_NUMBER_UINT8:
        case SSF_UBJSON_TYPE_NUMBER_CHAR:
        case SSF_UBJSON_TYPE_NUMBER_INT16:
        case SSF_UBJSON_TYPE_NUMBER_INT32:
        case SSF_UBJSON_TYPE_NUMBER_INT64:
        case SSF_UBJSON_TYPE_TRUE:
        case SSF_UBJSON_TYPE_FALSE:
        case SSF_UBJSON_TYPE_NULL:
        /* Is this scalar where the path ends (or is it only being skipped)? */
        if ((pathOpt == NULL) || (pathOpt[depth + 1].kind == SSF_GPATH_END))
        {
            /* Yes, report it */
            *start = valStart;
            *end = valEnd;
            *jt = valType;
        }
        /* No, a path continuing past a scalar matches nothing */
        *index = i; return true;
        default:
        break;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/value found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonNameValue(const uint8_t *js, size_t jsLen, size_t *index, size_t *start,
                              size_t *end, const SSFGPath_t *pathOpt, uint8_t depth,
                              SSFUBJsonType_t *jt, bool *keyMatched)
{
    size_t valStart;
    size_t valEnd;
    size_t fstart;
    size_t fend;
    size_t len;
    SSFUBJsonType_t fjt;
    SSFUBJsonType_t djt;
    bool retVal;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE(keyMatched != NULL);

    *keyMatched = false;
    /* Attempt to parse name field */
    if (_SSFUBJsonTypeField(js, jsLen, index, &fstart, &fend, &fjt, 0) == false) return false;
    switch (fjt)
    {
    case SSF_UBJSON_TYPE_NUMBER_INT8:
    case SSF_UBJSON_TYPE_NUMBER_UINT8:
    case SSF_UBJSON_TYPE_NUMBER_CHAR:
        len = js[fstart];
        break;
    default:
        /* Not allowing 16, 32, 64-bit types for name length */
        return false;
    }
    fstart = *index;
    (*index) += len; if (*index >= jsLen) return false;
    fend = *index;

    /* Is the next path entry an object member name equal to this name? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_KEY) &&
        ((fend - fstart) == strlen(pathOpt[depth].u.key)) &&
        (strncmp(pathOpt[depth].u.key, (char *)&js[fstart], fend - fstart) == 0))
    {
        /* Yes, the value follows the path and reports into the caller's results */
        *keyMatched = true;
        retVal = _SSFUBJsonValue(js, jsLen, index, start, end, pathOpt, depth, jt, 0);
    }
    else
    {
        /* No, parse the value only to skip it; its nesting counts toward the depth limit */
        retVal = _SSFUBJsonValue(js, jsLen, index, &valStart, &valEnd, NULL, depth, &djt, 0);
    }

    return retVal;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object found, else false; If true returns type/start/end on path match.       */
/* --------------------------------------------------------------------------------------------- */
bool _SSFUBJsonObject(const uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                      const SSFGPath_t *pathOpt, uint8_t depth, SSFUBJsonType_t *jt)
{
    const SSFGPath_t *memberPath = pathOpt;
    bool keyMatched;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    if (depth == 0)
    {
        if (jsLen > SSF_UBJSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_UBJSON_TYPE_ERROR;
        *index = 0;
    }
    if (depth >= SSF_UBJSON_CONFIG_MAX_IN_DEPTH) return false;

    if (*index >= jsLen) return false;
    if (js[*index] != UBJ_TYPE_OBJ_OPEN) return false;
    /* Is this a nested object or the top-level object the path ends at? */
    if ((depth != 0) || ((depth == 0) && (pathOpt != NULL) && (pathOpt[0].kind == SSF_GPATH_END)))
    {
        /* Yes, it starts here */
        *start = *index;
    }
    (*index)++; if (*index >= jsLen) return false;

    while (js[*index] == UBJ_TYPE_NOOP)
    { (*index)++; if (*index >= jsLen) return false; }

    if (js[*index] != UBJ_TYPE_OBJ_CLOSE)
    {
        /* Only the first member whose name matches follows the path; later duplicates skip */
        if (!_SSFUBJsonNameValue(js, jsLen, index, start, end, memberPath, depth, jt, &keyMatched))
        { return false; }
        if (keyMatched) memberPath = NULL;
        do
        {
            if (*index >= jsLen) return false;
            while (js[*index] == UBJ_TYPE_NOOP)
            { (*index)++; if (*index >= jsLen) return false; }
            if (js[*index] == UBJ_TYPE_OBJ_CLOSE) break;
            if (!_SSFUBJsonNameValue(js, jsLen, index, start, end, memberPath, depth, jt,
                                   &keyMatched))
            { return false; }
            if (keyMatched) memberPath = NULL;
        } while (true);
        if (js[*index] != UBJ_TYPE_OBJ_CLOSE) return false;
        (*index)++;
    }
    else { (*index)++; }
    /* Does the path end at this object? */
    if (((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_END)) ||
        ((depth == 0) && (pathOpt != NULL) && (pathOpt[0].kind == SSF_GPATH_END)))
    {
        /* Yes, report its span and type */
        *end = *index;
        *jt = SSF_UBJSON_TYPE_OBJECT;
    }
    /* Is this the top-level object with trailing data after it? */
    if ((depth == 0) && (*index != jsLen))
    {
        /* Yes, invalid */
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object|array found, else false; If true returns type/start/end on path match. */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonMessage(const uint8_t *js, size_t jsLen, size_t *index, size_t *start,
                              size_t *end, const SSFGPath_t *pathOpt, uint8_t depth,
                              SSFUBJsonType_t *jt)
{
    size_t astart;
    size_t aend;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE((pathOpt == NULL) ||
                (pathOpt[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END));
    SSF_REQUIRE((pathOpt == NULL) || SSFGPathIsValid(pathOpt, SSF_UBJSON_CONFIG_MAX_IN_DEPTH));

    if (!_SSFUBJsonObject(js, jsLen, index, start, end, pathOpt, depth, jt))
    {
        if (!_SSFUBJsonArray(js, jsLen, index, start, end, &astart, &aend, pathOpt, depth, jt))
        { return false; }
    }

    /* Is this a top-level parse (which sets *jt) whose found value's span is inverted? */
    if ((depth == 0u) && (*jt != SSF_UBJSON_TYPE_ERROR) && (*end < *start))
    {
        /* Yes, report it as not found rather than hand back an unusable span */
        *jt = SSF_UBJSON_TYPE_ERROR;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if UBJSON string is valid, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonIsValid(uint8_t *js, size_t jsLen)
{
    size_t start;
    size_t end;
    size_t index;
    SSFUBJsonType_t jt;
    SSFGPath_t path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(js != NULL);

    memset(path, 0, sizeof(path));
    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt))
    { return false; }

    return jt != SSF_UBJSON_TYPE_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SSF_JSON_TYPE_ERROR if JSON string is invalid or path not found, else valid type.     */
/* --------------------------------------------------------------------------------------------- */
SSFUBJsonType_t SSFUBJsonGetType(uint8_t *js, size_t jsLen, const SSFGPath_t *path)
{
    size_t start;
    size_t end;
    size_t index;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt))
    { jt = SSF_UBJSON_TYPE_ERROR; }

    SSF_ENSURE((jt > SSF_UBJSON_TYPE_MIN) && (jt < SSF_UBJSON_TYPE_MAX));
    return jt;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and copied into buffer w/NULL term., else false.                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetString(uint8_t *js, size_t jsLen, const SSFGPath_t *path, SSFCStrOut_t out,
                        size_t outSize, size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    size_t len;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(outSize > 0);
    SSF_REQUIRE(out != NULL);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt))
    {return false; }
    if (jt != SSF_UBJSON_TYPE_STRING) return false;
    end--;

    index = 0;
    len = (end - start) + 1;
    if (outLen != NULL) *outLen = 0;

    /* Is there input left and room for another character and the terminator? */
    while ((len != 0) && (index < (outSize - 1)))
    {
        /* Yes, copy it */
        out[index] = js[start];
        if (outLen != NULL) (*outLen)++;
        start++; index++; len--;
    }
    if (index < outSize) out[index] = 0;
    return len == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and converted ASCII Hex string to binary string, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetHex(uint8_t *js, size_t jsLen, const SSFGPath_t *path, uint8_t *out,
                     size_t outSize, size_t *outLen, bool rev)
{
    size_t start;
    size_t end;
    size_t index;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_UBJSON_TYPE_STRING) return false;
    end--;
    index = 0;
    if (outLen != NULL) *outLen = 0;

    return SSFHexBytesToBin((SSFCStrIn_t)&js[start], ((end - start) + 1), out, outSize, outLen,
                            rev);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and converted Base64 string to binary string, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetBase64(uint8_t *js, size_t jsLen, const SSFGPath_t *path, uint8_t *out,
                        size_t outSize, size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_UBJSON_TYPE_STRING) return false;
    end--;
    index = 0;
    if (outLen != NULL) *outLen = 0;

    return SSFBase64Decode((SSFCStrIn_t)&js[start], ((end - start) + 1), out, outSize, outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to float, else false.                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetFloat(uint8_t *js, size_t jsLen, const SSFGPath_t *path, float *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint32_t u32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_UBJSON_TYPE_NUMBER_FLOAT32) return false;
    if ((end - start) != sizeof(u32)) return false;
    memcpy(&u32, &js[start], sizeof(u32));
    u32 = ntohl(u32);
    memcpy(out, &u32, sizeof(float));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to double, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetDouble(uint8_t *js, size_t jsLen, const SSFGPath_t *path, double *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint32_t u32;
    float f;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt)) return false;
    switch (jt)
    {
        case SSF_UBJSON_TYPE_NUMBER_FLOAT32:
            if ((end - start) != sizeof(u32)) return false;
            memcpy(&u32, &js[start], sizeof(u32));
            u32 = ntohl(u32);
            memcpy(&f, &u32, sizeof(float));
            *out = (double)f;
        break;
        case SSF_UBJSON_TYPE_NUMBER_FLOAT64:
            if ((end - start) != sizeof(u64)) return false;
            memcpy(&u64, &js[start], sizeof(u64));
            u64 = ntohll(u64);
            memcpy(out, &u64, sizeof(double));
        break;
        default:
            return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and ptr and len of byte array data is set, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetByteArrayPtr(uint8_t *js, size_t jsLen, const SSFGPath_t *path, uint8_t **out,
                              size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt))
    {return false; }
    if (jt != SSF_UBJSON_TYPE_ARRAY) return false;
    /* Is the array too short for the [$T#TL header? */
    if ((end - start) < 6) return false;
    if (js[start] != UBJ_TYPE_ARRAY_OPEN) return false;
    start++;
    if (js[start] != UBJ_TYPE_ARRAY_OPT) return false;
    start++;
    /* Is the element type neither int8 nor uint8? */
    if ((js[start] != UBJ_TYPE_INT8) && (js[start] != UBJ_TYPE_UINT8))
    {
        /* Yes, not a byte array */
        return false;
    }
    start++;
    if (js[start] != UBJ_TYPE_ARRAY_NUM) return false;
    start++;
    /* Is the count type neither int8 nor uint8? */
    if ((js[start] != UBJ_TYPE_INT8) && (js[start] != UBJ_TYPE_UINT8))
    {
        /* Yes, not supported */
        return false;
    }
    start++;
    *outLen = js[start];
    start++;
    *out = &js[start];
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonGetUInt64(uint8_t *js, size_t jsLen, const SSFGPath_t *path,
                                int64_t *outi64, uint64_t *outu64)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(outi64 != NULL);
    SSF_REQUIRE(outu64 != NULL);

    if (!_SSFUBJsonMessage(js, jsLen, &index, &start, &end, path, 0, &jt)) return false;
    switch (jt)
    {
        case SSF_UBJSON_TYPE_NUMBER_INT8:
            if ((end - start) != sizeof(int8_t)) return false;
            *outi64 = (int64_t)(int8_t)js[start];
            *outu64 = (uint64_t)js[start];
        break;
        case SSF_UBJSON_TYPE_NUMBER_UINT8:
            if ((end - start) != sizeof(uint8_t)) return false;
            *outi64 = (uint64_t)js[start];
            *outu64 = (uint64_t)js[start];
        break;
        case SSF_UBJSON_TYPE_NUMBER_INT16:
            if ((end - start) != sizeof(u16)) return false;
            memcpy(&u16, &js[start], sizeof(u16));
            u16 = ntohs(u16);
            *outi64 = (int64_t)(int16_t)u16;
            *outu64 = (uint64_t)u16;
        break;
        case SSF_UBJSON_TYPE_NUMBER_INT32:
            if ((end - start) != sizeof(u32)) return false;
            memcpy(&u32, &js[start], sizeof(u32));
            u32 = ntohl(u32);
            *outi64 = (int64_t)(int32_t)u32;
            *outu64 = (uint64_t)u32;
        break;
        case SSF_UBJSON_TYPE_NUMBER_INT64:
            if ((end - start) != sizeof(u64)) return false;
            memcpy(&u64, &js[start], sizeof(u64));
            u64 = ntohll(u64);
            *outi64 = (int64_t)u64;
            *outu64 = u64;
        break;
        default:
            return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and value fits in requested int type, else false.                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt(uint8_t *js, size_t jsLen, const SSFGPath_t *path, void *out, uint8_t outSize,
                     bool isSigned)
{
    int64_t i64;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE((outSize == 1) || (outSize == 2) || (outSize == 4) || (outSize == 8));

    if (_SSFUBJsonGetUInt64(js, jsLen, path, &i64, &u64) == false) return false;
    switch (outSize)
    {
    case 1:
    {
        if (isSigned)
        {
            int8_t *pi8 = (int8_t *)out;

            /* Is the value out of int8 range? */
            if ((i64 < -128l) || (i64 > 127l))
            {
                /* Yes, it does not fit */
                return false;
            }
            *pi8 = (int8_t)i64;
        }
        else
        {
            uint8_t *pu8 = (uint8_t *)out;

            if (u64 > 255ul) return false;
            *pu8 = (uint8_t)u64;
        }
    }
        break;
    case 2:
        if (isSigned)
        {
            int16_t *pi16 = (int16_t *)out;

            /* Is the value out of int16 range? */
            if ((i64 < -32768l) || (i64 > 32767l))
            {
                /* Yes, it does not fit */
                return false;
            }
            *pi16 = (int16_t)i64;
        }
        else
        {
            uint16_t *pu16 = (uint16_t *)out;

            if (u64 > 65535ul) return false;
            *pu16 = (uint16_t)u64;
        }
        break;
    case 4:
        if (isSigned)
        {
            int32_t *pi32 = (int32_t *)out;

            /* Is the value out of int32 range? */
            if ((i64 < -2147483648ll) || (i64 > 2147483647ll))
            {
                /* Yes, it does not fit */
                return false;
            }
            *pi32 = (int32_t)i64;
        }
        else
        {
            uint32_t *pu32 = (uint32_t *)out;

            if (u64 > 4294967295ull) return false;
            *pu32 = (uint32_t)u64;
        }
        break;
    case 8:
        if (isSigned)
        {
            int64_t *pi64 = (int64_t *)out;

            *pi64 = i64;
        }
        else
        {
            uint64_t *pu64 = (uint64_t *)out;

            *pu64 = u64;
        }
        break;
    default:
        SSF_ERROR();
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if char added to js, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintChar(uint8_t *js, size_t jsSize, size_t start, size_t *end, const char in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (start >= jsSize) return false;
    js[start] = in;
    *end = start + 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all printing added successfully to JSON string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrint(uint8_t *js, size_t jsSize, size_t start, size_t *end,
                    SSFUBJsonPrintFn_t fnOpt, void *in, const char *ocOpt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (start >= jsSize) return false;
    /* Is there an opening character that does not fit? */
    if ((ocOpt != NULL) && (!SSFUBJsonPrintChar(js, jsSize, start, &start, ocOpt[0])))
    {
        /* Yes */
        return false;
    }
    /* Is there a callback that fails? */
    if ((fnOpt != NULL) && (!fnOpt(js, jsSize, start, &start, in)))
    {
        /* Yes */
        return false;
    }
    /* Is there a closing character that does not fit? */
    if ((ocOpt != NULL) && (!SSFUBJsonPrintChar(js, jsSize, start, &start, ocOpt[1])))
    {
        /* Yes */
        return false;
    }
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all printing of optimized array successfully to JSON string, else false.      */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintArrayOpt(uint8_t *js, size_t jsSize, size_t start, size_t *end,
                            SSFUBJsonPrintFn_t fnOpt, void *in, SSFUBJsonType_t atype, size_t alen)
{
    char t = 0;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((atype == SSF_UBJSON_TYPE_NUMBER_INT8) ||
                (atype == SSF_UBJSON_TYPE_NUMBER_UINT8) ||
                (atype == SSF_UBJSON_TYPE_NUMBER_INT16) ||
                (atype == SSF_UBJSON_TYPE_NUMBER_INT32) ||
                (atype == SSF_UBJSON_TYPE_NUMBER_INT64));
    SSF_REQUIRE(alen <= 255);

    if (start >= jsSize) return false;
    switch (atype)
    {
    case SSF_UBJSON_TYPE_NUMBER_INT8:
        t = UBJ_TYPE_INT8;
        break;
    case SSF_UBJSON_TYPE_NUMBER_UINT8:
        t = UBJ_TYPE_UINT8;
        break;
    case SSF_UBJSON_TYPE_NUMBER_INT16:
        t = UBJ_TYPE_INT16;
        break;
    case SSF_UBJSON_TYPE_NUMBER_INT32:
        t = UBJ_TYPE_INT32;
        break;
    case SSF_UBJSON_TYPE_NUMBER_INT64:
        t = UBJ_TYPE_INT64;
        break;
    default:
        SSF_ERROR();
    }

    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_ARRAY_OPEN)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_ARRAY_OPT)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, t)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_ARRAY_NUM)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_UINT8)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, (char)alen)) return false;
    /* Is there a callback that fails? */
    if ((fnOpt != NULL) && (!fnOpt(js, jsSize, start, &start, in)))
    {
        /* Yes */
        return false;
    }
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if inStr added successfully as string, else false.                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonPrintStringValue(uint8_t *js, size_t jsSize, size_t start, size_t *end,
                                       SSFCStrIn_t inStr)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(inStr != NULL);

    len = strlen(inStr);

    /* Only support strings up to 255 bytes */
    if (len > 255) return false;

    /* Always use uint8_t as type for string length */
    if (start >= jsSize) return false;
    js[start] = UBJ_TYPE_UINT8; start++; if (start >= jsSize) return false;
    js[start] = (uint8_t)len; start++; if (start >= jsSize) return false;

    while (start < jsSize)
    {
        js[start] = *inStr;
        if (*inStr == 0) { *end = start; return true; }
        start++;
        inStr++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if inStr added successfully as string, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintString(uint8_t *js, size_t jsSize, size_t start, size_t *end, SSFCStrIn_t inStr)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(inStr != NULL);

    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_STRING)) return false;
    if (!_SSFUBJsonPrintStringValue(js, jsSize, start, &start, inStr)) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in binary string added successfully as ASCII Hex string, else false.          */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintHex(uint8_t *js, size_t jsSize, size_t start, size_t *end, uint8_t *in,
                       size_t inLen, bool rev)
{
    size_t outLen;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(inLen <= 127);

    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_STRING)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_UINT8)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, (char)(inLen << 1))) return false;
    if (!SSFHexBinToBytes(in, inLen, (SSFCStrOut_t)&js[start], jsSize - start, &outLen, rev,
                          SSF_HEX_CASE_UPPER))
    { return false; }
    *end = start + (inLen << 1);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in binary string added successfully as Base64 string, else false.             */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintBase64(uint8_t *js, size_t jsSize, size_t start, size_t *end, uint8_t *in,
                          size_t inLen)
{
    size_t outLen;
    size_t lenIndex;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(inLen <= 189);

    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_STRING)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_UINT8)) return false;
    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, (char)(inLen << 1))) return false;
    lenIndex = start - 1;
    if (!SSFBase64Encode(in, inLen, (SSFCStrOut_t)&js[start], jsSize - start, &outLen))
    { return false; }
    js[lenIndex] = (uint8_t)outLen;
    *end = start + outLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if labelStr added successfully as string, else false.                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintLabel(uint8_t *js, size_t jsSize, size_t start, size_t *end,
                         SSFCStrIn_t labelStr)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(labelStr != NULL);

    if (labelStr[0] == 0) return false;
    return _SSFUBJsonPrintStringValue(js, jsSize, start, end, labelStr);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in signed int added successfully to JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintInt(uint8_t *js, size_t jsSize, size_t start, size_t *end, int64_t in, bool opt,
                       SSFUBJsonType_t optType)
{
    uint8_t type = 0;
    size_t len = 0;
    uint8_t *pi = NULL;
    int8_t i8;
    uint8_t ui8;
    int16_t i16;
    int32_t i32;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    if (opt)
    {
        SSF_REQUIRE((optType == SSF_UBJSON_TYPE_NUMBER_INT8) ||
                    (optType == SSF_UBJSON_TYPE_NUMBER_UINT8) ||
                    (optType == SSF_UBJSON_TYPE_NUMBER_INT16) ||
                    (optType == SSF_UBJSON_TYPE_NUMBER_INT32) ||
                    (optType == SSF_UBJSON_TYPE_NUMBER_INT64));
    }
    else { SSF_REQUIRE(optType == SSF_UBJSON_TYPE_ERROR); }

    if (opt)
    {
        switch(optType)
        {
            case SSF_UBJSON_TYPE_NUMBER_INT8:
                if (in >= 128l) return false;
                type = UBJ_TYPE_INT8;
                break;
            case SSF_UBJSON_TYPE_NUMBER_UINT8:
                if (in >= 256l) return false;
                type = UBJ_TYPE_UINT8;
                break;
            case SSF_UBJSON_TYPE_NUMBER_INT16:
                if (in >= 32768l) return false;
                type = UBJ_TYPE_INT16;
                break;
            case SSF_UBJSON_TYPE_NUMBER_INT32:
                if (in >= 2147483648ll) return false;
                type = UBJ_TYPE_INT32;
                break;
            case SSF_UBJSON_TYPE_NUMBER_INT64:
                type = UBJ_TYPE_INT64;
                break;
            default:
                SSF_ERROR();
                break;
        }
    }
    /* Does the value fit in int8? */
    else if ((in > -129l) && (in < 128l)) type = UBJ_TYPE_INT8;
    /* No, does it fit in uint8? */
    else if ((in > -1l) && (in < 256l)) type = UBJ_TYPE_UINT8;
    /* No, does it fit in int16? */
    else if ((in > -32769l) && (in < 32768l)) type = UBJ_TYPE_INT16;
    /* No, does it fit in int32? */
    else if ((in > -2147483649ll) && (in < 2147483648ll)) type = UBJ_TYPE_INT32;
    /* No, use int64 */
    else type = UBJ_TYPE_INT64;

    if (opt == false) { if (!SSFUBJsonPrintChar(js, jsSize, start, &start, type)) return false; }
    switch (type)
    {
    case UBJ_TYPE_INT8:
        i8 = (int8_t)in; pi = (uint8_t *)&i8; len = sizeof(i8);
        break;
    case UBJ_TYPE_UINT8:
        ui8 = (uint8_t)in; pi = &ui8; len = sizeof(ui8);
        break;
    case UBJ_TYPE_INT16:
        i16 = (int16_t)in; i16 = htons(i16); pi = (uint8_t *)&i16; len = sizeof(i16);
        break;
    case UBJ_TYPE_INT32:
        i32 = (int32_t)in; i32 = htonl(i32); pi = (uint8_t *)&i32; len = sizeof(i32);
        break;
    case UBJ_TYPE_INT64:
        /* Byte-swap the value's two's complement bits as unsigned, so no shift overflows */
        u64 = (uint64_t)in; u64 = htonll(u64); pi = (uint8_t *)&u64; len = sizeof(u64);
        break;
    default:
        SSF_ERROR();
    };
    if ((start + len) >= jsSize) return false;
    memcpy(&js[start], pi, len);
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in float added successfully to JSON string, else false.                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintFloat(uint8_t *js, size_t jsSize, size_t start, size_t *end, float in)
{
    uint32_t u32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_FLOAT32)) return false;
    if ((start + sizeof(in)) >= jsSize) return false;
    memcpy(&u32, &in, sizeof(in));
    u32 = htonl(u32);
    memcpy(&js[start], &u32, sizeof(in));
    *end = start + sizeof(in);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in double added successfully to JSON string, else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintDouble(uint8_t *js, size_t jsSize, size_t start, size_t *end, double in)
{
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (!SSFUBJsonPrintChar(js, jsSize, start, &start, UBJ_TYPE_FLOAT64)) return false;
    if ((start + sizeof(in)) >= jsSize) return false;
    memcpy(&u64, &in, sizeof(in));
    u64 = htonll(u64);
    memcpy(&js[start], &u64, sizeof(in));
    *end = start + sizeof(in);
    return true;
}

