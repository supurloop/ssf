/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfjson.c                                                                                     */
/* Provides JSON parser/generator interface.                                                     */
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
#include <stdio.h>
#include <stdlib.h>
#include "ssfjson.h"
#include "ssfbase64.h"
#include "ssfhex.h"
#include "ssfdec.h"
#if SSF_JSON_GOBJ_ENABLE == 1
#include "ssfgobj.h"
#endif /* SSF_JSON_GOBJ_ENABLE */

#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
    #include <math.h> /* round() */
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSFJsonIsEsc(e) (((e) == '"') || ((e) == '\\') || ((e) == '/') || ((e) == 'b') || \
                         ((e) == 'f') || ((e) == 'n') || ((e) == 'r') || ((e) == 't') || \
                         ((e) == 'u'))
#define SSFJsonEsc(j, b) do { (j)[start] = '\\'; start++; if (start >= jsSize) return false; \
                              (j)[start] = (b);} while (0)
#define SSF_JSON_COMMA(c) do { \
    if (((c) && (*(c))) && (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, ','))) \
    { return false; } \
    if (c) *(c) = true; } while (0)
#define SSF_JSON_ADD_ESC(e) out[index] = (e); start++; len--; index++; \
                            if (outLen != NULL) (*outLen)++; \
                            continue;

/* --------------------------------------------------------------------------------------------- */
/* Local prototypes                                                                              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonValue(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end,
                          const SSFGPath_t *pathOpt, uint8_t depth, SSFJsonType_t *jt);
static bool _SSFJsonObject(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end,
                           const SSFGPath_t *pathOpt, uint8_t depth, SSFJsonType_t *jt);

/* --------------------------------------------------------------------------------------------- */
/* Increments index past whitespace in JSON string                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFJsonWhitespace(SSFCStrIn_t jsStr, size_t *index)
{
    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);

    /* Is the next character JSON whitespace? */
    while ((jsStr[*index] == ' ') || (jsStr[*index] == '\n') || (jsStr[*index] == '\r') ||
           (jsStr[*index] == '\t'))
    {
        /* Yes, skip it */
        (*index)++;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if 1 or more digits 0-9 found in JSON string, else false.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNumberIsDigits(SSFCStrIn_t jsStr, size_t *index, size_t *end)
{
    bool foundDig = false;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(end != NULL);

    /* Is the next character a decimal digit? */
    while ((jsStr[*index] >= '0') && (jsStr[*index] <= '9'))
    {
        /* Yes, consume it */
        (*index)++;
        foundDig = true;
    }
    if (foundDig == true) *end = *index - 1;
    return foundDig;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if number found in JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNumber(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end)
{
    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);

    /* Is the first character neither a minus sign nor a digit? */
    if ((jsStr[*index] != '-') && !((jsStr[*index] >= '0') && (jsStr[*index] <= '9')))
    {
        /* Yes, not a number */
        return false;
    }
    *start = *index;
    if (jsStr[*index] == '-') (*index)++;
    if (jsStr[*index] != '0')
    {if (!_SSFJsonNumberIsDigits(jsStr, index, end)) return false; } else
    {(*index)++; }
    if (jsStr[*index] == '.')
    {(*index)++; if (!_SSFJsonNumberIsDigits(jsStr, index, end)) return false; }
    /* Is there an exponent? */
    if ((jsStr[*index] == 'e') || (jsStr[*index] == 'E'))
    {
        /* Yes, consume it and its optional sign */
        (*index)++;
        /* Does the exponent have a sign? */
        if ((jsStr[*index] == '-') || (jsStr[*index] == '+'))
        {
            /* Yes, skip it */
            (*index)++;
        }
        return _SSFJsonNumberIsDigits(jsStr, index, end);
    }
    *end = *index - 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if string found, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonString(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end)
{
    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);

    _SSFJsonWhitespace(jsStr, index);
    if (jsStr[*index] != '"') return false;
    *start = *index;
    (*index)++;
    /* Is there string content left before the closing quote? */
    while ((jsStr[*index] != 0) && (jsStr[*index] != '"'))
    {
        /* Yes, consume one character or escape sequence */
        if (jsStr[*index] == '\\')
        {
            (*index)++;
            if (!SSFJsonIsEsc(jsStr[*index])) return false;
            if (jsStr[*index] != 'u')
            {(*index)++; continue; }
            (*index)++;
            if (!SSFIsHex(jsStr[*index])) return false;
            if (!SSFIsHex(jsStr[(*index) + 1])) return false;
            if (!SSFIsHex(jsStr[(*index) + 2])) return false;
            if (!SSFIsHex(jsStr[(*index) + 3])) return false;
            (*index) += 4;
        } else (*index)++;
    }
    if (jsStr[*index] != '"') return false;
    *end = (*index);
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if array found, else false; If true returns type/start/end on path index match.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonArray(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end,
                          const SSFGPath_t *pathOpt, uint8_t depth, SSFJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    size_t curIndex = 0;
    size_t pindex = (size_t)-1;
    SSFJsonType_t djt;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    if (depth == 0)
    {
        uint32_t i;
        for (i = 0; (i <= SSF_JSON_CONFIG_MAX_IN_LEN) && (jsStr[i] != 0); i++);
        if (i > SSF_JSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_JSON_TYPE_ERROR;
        *index = 0;
    }

    if (depth >= SSF_JSON_CONFIG_MAX_IN_DEPTH) return false;
    _SSFJsonWhitespace(jsStr, index);
    if (jsStr[*index] != '[') return false;
    /* Does the path end at this array? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_END))
    {
        /* Yes, it starts here */
        *start = *index;
    }
    (*index)++;

    /* Is the next path entry an array element index? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_INDEX))
    {
        /* Yes, select that element; any other kind of entry selects none */
        pindex = *(pathOpt[depth].u.index);
    }
    do
    {
        bool found;

        /* Is this the element at the path index? */
        if (pindex == curIndex)
        {
            /* Yes, it follows the path and reports straight into the caller's results */
            found = _SSFJsonValue(jsStr, index, start, end, pathOpt, depth, jt);
        }
        else
        {
            /* No, parse it only to skip it */
            found = _SSFJsonValue(jsStr, index, &valStart, &valEnd, NULL, depth, &djt);
        }
        /* Is there no element here? */
        if (!found)
        {
            /* Yes, valid only for an empty array; a comma must be followed by an element */
            if (curIndex != 0) return false;
            break;
        }
        _SSFJsonWhitespace(jsStr, index);
        if (jsStr[*index] == ']') break;
        if (jsStr[*index] != ',') return false;
        (*index)++;
        curIndex++;
    } while (true);
    /* Is the path index past the last element? */
    if ((pindex != (size_t)-1) && (pindex > curIndex))
    {
        /* Yes, the path matches nothing */
        *jt = SSF_JSON_TYPE_ERROR;
    }
    if (jsStr[*index] != ']') return false;

    /* Does the path end at this array? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_END))
    {
        /* Yes, report its span and type */
        *end = *index;
        *jt = SSF_JSON_TYPE_ARRAY;
    }
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value found, else false; If true returns type/start/end on path match.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonValue(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end,
                          const SSFGPath_t *pathOpt, uint8_t depth, SSFJsonType_t *jt)
{
    size_t i;
    size_t valStart;
    size_t valEnd;
    SSFJsonType_t valType;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    _SSFJsonWhitespace(jsStr, index); i = *index;
    if (_SSFJsonString(jsStr, &i, &valStart, &valEnd)) valType = SSF_JSON_TYPE_STRING;
    else
    {
        i = *index;
        if (_SSFJsonObject(jsStr, &i, start, end, pathOpt, depth + 1, jt))
        { *index = i; return true; }
        i = *index;
        if (_SSFJsonArray(jsStr, &i, start, end, pathOpt, depth + 1, jt))
        { *index = i; return true; }
        i = *index;
        if (_SSFJsonNumber(jsStr, &i, &valStart, &valEnd)) valType = SSF_JSON_TYPE_NUMBER;
        else if (strncmp(&jsStr[i], "true", 4) == 0)
        {valType = SSF_JSON_TYPE_TRUE; valStart = i; i += 4; valEnd = i - 1; }
        else if (strncmp(&jsStr[i], "false", 5) == 0)
        {valType = SSF_JSON_TYPE_FALSE; valStart = i; i += 5; valEnd = i - 1; }
        else if (strncmp(&jsStr[i], "null", 4) == 0)
        {valType = SSF_JSON_TYPE_NULL; valStart = i; i += 4; valEnd = i - 1; }
        else return false;
    }

    /* Is this scalar where the path ends (or is it only being skipped)? */
    if ((pathOpt == NULL) || (pathOpt[depth + 1].kind == SSF_GPATH_END))
    {
        /* Yes, report it */
        *start = valStart;
        *end = valEnd;
        *jt = valType;
    }
    /* No, a path continuing past a scalar matches nothing */
    *index = i;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/value found, else false; sets *keyMatched if name is the next path key.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNameValue(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end,
                              const SSFGPath_t *pathOpt, uint8_t depth, SSFJsonType_t *jt,
                              bool *keyMatched)
{
    size_t valStart;
    size_t valEnd;
    SSFJsonType_t djt;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE(keyMatched != NULL);

    *keyMatched = false;
    if (_SSFJsonString(jsStr, index, &valStart, &valEnd) == false) return false;
    _SSFJsonWhitespace(jsStr, index);
    if (jsStr[*index] != ':') return false;
    (*index)++;
    /* Is the next path entry an object member name equal to this name? */
    if ((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_KEY) &&
        (((valEnd - valStart) - 1) == (size_t)strlen(pathOpt[depth].u.key)) &&
        (strncmp(pathOpt[depth].u.key, &jsStr[valStart + 1], ((valEnd - valStart) - 1)) == 0))
    {
        /* Yes, the value follows the path and reports into the caller's results */
        *keyMatched = true;
        return _SSFJsonValue(jsStr, index, start, end, pathOpt, depth, jt);
    }
    /* No, parse the value only to skip it; its nesting counts toward the depth limit */
    return _SSFJsonValue(jsStr, index, &valStart, &valEnd, NULL, depth, &djt);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object found, else false; If true returns type/start/end on path match.       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonObject(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end,
                           const SSFGPath_t *pathOpt, uint8_t depth, SSFJsonType_t *jt)
{
    const SSFGPath_t *memberPath = pathOpt;
    bool keyMatched;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE((pathOpt == NULL) || (pathOpt[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END));

    if (depth == 0)
    {
        uint32_t i;
        for (i = 0; (i <= SSF_JSON_CONFIG_MAX_IN_LEN) && (jsStr[i] != 0); i++);
        if (i > SSF_JSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_JSON_TYPE_ERROR;
        *index = 0;
    }
    if (depth >= SSF_JSON_CONFIG_MAX_IN_DEPTH) return false;

    _SSFJsonWhitespace(jsStr, index);
    if (jsStr[*index] != '{') return false;
    /* Is this a nested object or the top-level object the path ends at? */
    if ((depth != 0) || ((depth == 0) && (pathOpt != NULL) && (pathOpt[0].kind == SSF_GPATH_END)))
    {
        /* Yes, it starts here */
        *start = *index;
    }
    (*index)++;
    _SSFJsonWhitespace(jsStr, index);
    if (jsStr[*index] != '}')
    {
        /* Only the first member whose name matches follows the path; later duplicates skip */
        if (!_SSFJsonNameValue(jsStr, index, start, end, memberPath, depth, jt, &keyMatched))
        { return false; }
        if (keyMatched) memberPath = NULL;
        do
        {
            _SSFJsonWhitespace(jsStr, index);
            if (jsStr[*index] == '}') break;
            if (jsStr[*index] != ',') return false;
            (*index)++;
            if (!_SSFJsonNameValue(jsStr, index, start, end, memberPath, depth, jt, &keyMatched))
            { return false; }
            if (keyMatched) memberPath = NULL;
        } while (true);
        if (jsStr[*index] != '}') return false;
    }
    /* Does the path end at this object? */
    if (((pathOpt != NULL) && (pathOpt[depth].kind == SSF_GPATH_END)) ||
        ((depth == 0) && (pathOpt != NULL) && (pathOpt[0].kind == SSF_GPATH_END)))
    {
        /* Yes, report its span and type */
        *end = *index;
        *jt = SSF_JSON_TYPE_OBJECT;
    }
    (*index)++;
    if (depth == 0)
    {_SSFJsonWhitespace(jsStr, index); if (jsStr[*index] != 0) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object|array found, else false; If true returns type/start/end on path match. */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonMessage(SSFCStrIn_t jsStr, size_t *index, size_t *start, size_t *end,
                    const SSFGPath_t *pathOpt, uint8_t depth, SSFJsonType_t *jt)
{
    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE((pathOpt == NULL) || (pathOpt[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END));
    SSF_REQUIRE((pathOpt == NULL) || SSFGPathIsValid(pathOpt, SSF_JSON_CONFIG_MAX_IN_DEPTH));

    if (!_SSFJsonObject(jsStr, index, start, end, pathOpt, depth, jt))
    {
        if (!_SSFJsonArray(jsStr, index, start, end, pathOpt, depth, jt)) return false;
    }

    /* Is this a top-level parse (which sets *jt) whose found value's span is inverted? */
    if ((depth == 0u) && (*jt != SSF_JSON_TYPE_ERROR) && (*end < *start))
    {
        /* Yes, report it as not found rather than hand back an unusable span */
        *jt = SSF_JSON_TYPE_ERROR;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if JSON string is valid, else false.                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonIsValid(SSFCStrIn_t jsStr)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;
    SSFGPath_t path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(jsStr != NULL);

    memset(path, 0, sizeof(path));
    if (!SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt)) return false;
    return jt != SSF_JSON_TYPE_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SSF_JSON_TYPE_ERROR if JSON string is invalid or path not found, else valid type.     */
/* --------------------------------------------------------------------------------------------- */
SSFJsonType_t SSFJsonGetType(SSFCStrIn_t jsStr, const SSFGPath_t *path)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);

    if (!SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt)) jt = SSF_JSON_TYPE_ERROR;
    return jt;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is unescaped completely into buffer w/NULL term., else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetString(SSFCStrIn_t jsStr, const SSFGPath_t *path, char *out, size_t outSize,
                      size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    size_t len;
    SSFJsonType_t jt;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outSize > 0);

    if (!SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;

    index = 0;
    len = (end - start) + 1;
    if (outLen != NULL) *outLen = 0;

    /* Is there input left and room for another character and the terminator? */
    while ((len != 0) && (index < (outSize - 1)))
    {
        /* Yes, unescape the next character */
        if (jsStr[start] == '\\')
        {
            start++; len--;
            if (len == 0) return false;
            /* Is it an escaped quote, backslash or solidus? */
            if ((jsStr[start] == '"') || (jsStr[start] == '\\') || (jsStr[start] == '/'))
            {
                /* Yes, copy it as is */
                SSF_JSON_ADD_ESC(jsStr[start])
            }
            else if (jsStr[start] == 'n') { SSF_JSON_ADD_ESC('\x0a') }
            else if (jsStr[start] == 'r') { SSF_JSON_ADD_ESC('\x0d') }
            else if (jsStr[start] == 't') { SSF_JSON_ADD_ESC('\x09') }
            else if (jsStr[start] == 'f') { SSF_JSON_ADD_ESC('\x0c') }
            else if (jsStr[start] == 'b') { SSF_JSON_ADD_ESC('\x08') }
            else if (jsStr[start] != 'u') return false;

            if (outLen != NULL) (*outLen)++;
            start++; len--;
            if (len < 4) return false;
            if ((index + 2) >= outSize) return false;
            if (!SSFHexByteToBin(&jsStr[start], (uint8_t *)&out[index])) return false;
            index++;
            if (!SSFHexByteToBin(&jsStr[start + 2], (uint8_t *)&out[index])) return false;
            start += 3; len -= 3;
        }
        else { out[index] = jsStr[start]; }
        if (outLen != NULL) (*outLen)++;
        start++; index++; len--;
    }
    if (index < outSize) out[index] = 0;
    return len == 0;
}

#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to double, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetDouble(SSFCStrIn_t jsStr, const SSFGPath_t *path, double *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFJsonType_t jt;
    char *endptr;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);

    if (!SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_NUMBER) return false;
    *out = strtod(&jsStr[start], &endptr);
    if ((endptr - 1) != &jsStr[end]) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetInt(SSFCStrIn_t jsStr, const SSFGPath_t *path, int64_t *out)
{
    double dout;

    if (!SSFJsonGetDouble(jsStr, path, &dout)) return false;
    *out = (int64_t)round(dout);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to unsigned int, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetUInt(SSFCStrIn_t jsStr, const SSFGPath_t *path, uint64_t *out)
{
    double dout;

    if (!SSFJsonGetDouble(jsStr, path, &dout)) return false;
    if (dout < 0) return false;
    *out = (uint64_t)round(dout);
    return true;
}
#else
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool _SSFJsonGetXLong(SSFCStrIn_t jsStr, const SSFGPath_t *path, int64_t *outsOpt,
                      uint64_t *outuOpt)
{
    size_t index;
    size_t start;
    size_t end;
    SSFJsonType_t jt;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(((outsOpt != NULL) && (outuOpt == NULL)) ||
                ((outsOpt == NULL) && (outuOpt != NULL)));

    if (!SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_NUMBER) return false;
    if (outuOpt != NULL) return SSFDecStrToUInt(&jsStr[start], outuOpt);
    else return SSFDecStrToInt(&jsStr[start], outsOpt);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetInt(SSFCStrIn_t jsStr, const SSFGPath_t *path, int64_t *out)
{
    return _SSFJsonGetXLong(jsStr, path, out, NULL);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to unsigned int, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetUInt(SSFCStrIn_t jsStr, const SSFGPath_t *path, uint64_t *out)
{
    return _SSFJsonGetXLong(jsStr, path, NULL, out);
}
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and completely converted to binary data, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetHex(SSFCStrIn_t jsStr, const SSFGPath_t *path, uint8_t *out, size_t outSize,
                   size_t *outLen, bool rev)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (!SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;
    return SSFHexBytesToBin(&jsStr[start], ((end - start) + 1), out, outSize, outLen, rev);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found, entire decode successful, and outLen updated, else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetBase64(SSFCStrIn_t jsStr, const SSFGPath_t *path, uint8_t *out, size_t outSize,
                      size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH].kind == SSF_GPATH_END);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (!SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;

    return SSFBase64Decode(&jsStr[start], ((end - start) + 1), out, outSize, outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if char added to js, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonPrintUnescChar(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end,
                                   const char in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (start >= jsSize) return false;
    js[start] = in;
    *end = start + 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if inStr added successfully as escaped string, else false.                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintCString(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end,
                         SSFCStrIn_t inStr, bool *commaOpt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(inStr != NULL);

    SSF_JSON_COMMA(commaOpt);
    while (start < jsSize)
    {
        if (*inStr == '\\') SSFJsonEsc(js, '\\');
        else if (*inStr == '\"') SSFJsonEsc(js, '\"');
        else if (*inStr == '\r') SSFJsonEsc(js, 'r');
        else if (*inStr == '\n') SSFJsonEsc(js, 'n');
        else if (*inStr == '\t') SSFJsonEsc(js, 't');
        else if (*inStr == '\b') SSFJsonEsc(js, 'b');
        else if (*inStr == '\f') SSFJsonEsc(js, 'f');
        /* Is it a printable ASCII character or the terminator? */
        else if (((*inStr > 0x1f) && (*inStr < 0x7f)) || (*inStr == 0))
        {
            /* Yes, copy it as is */
            js[start] = *inStr;
        }
        else
        {
            /* No, escape it as \u00XX */
            if ((start + 6) >= jsSize) return false;
            js[start] = '\\'; start++;
            js[start] = 'u'; start++;
            js[start] = '0'; start++;
            js[start] = '0'; start++;
            SSF_ASSERT(SSFHexBinToByte(*inStr, &js[start], 2, SSF_HEX_CASE_UPPER));
            start++;
        }
        if (*inStr == 0)
        {*end = start; return true; }
        start++;
        inStr++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if inStr added successfully as quoted escaped string, else false.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintString(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end,
                        SSFCStrIn_t inStr, bool *commaOpt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(inStr != NULL);

    SSF_JSON_COMMA(commaOpt);
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, '\"')) return false;
    if (!SSFJsonPrintCString(js, jsSize, start, &start, inStr, NULL)) return false;
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, '\"')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if inStr label element added successfully, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintLabel(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end,
                       SSFCStrIn_t inStr, bool *commaOpt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(inStr != NULL);

    SSF_JSON_COMMA(commaOpt);
    if (!SSFJsonPrintString(js, jsSize, start, &start, inStr, NULL)) return false;
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, ':')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in data added successfully as quoted ASCII hex string, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintHex(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end, const uint8_t *in,
                     size_t inLen, bool rev, bool *commaOpt)
{
    size_t outLen;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    SSF_JSON_COMMA(commaOpt);
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, '"')) return false;
    if (!SSFHexBinToBytes(in, inLen, &js[start], jsSize - start, &outLen, rev, SSF_HEX_CASE_UPPER))
    {return false; }
    start += outLen;
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, '"')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in data added successfully as quoted Base64 string, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintBase64(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end,
                        const uint8_t *in, size_t inLen, bool *commaOpt)
{
    size_t outLen;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    SSF_JSON_COMMA(commaOpt);
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, '"')) return false;
    if (!SSFBase64Encode(in, inLen, &js[start], jsSize - start, &outLen)) return false;
    start += outLen;
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, '"')) return false;
    *end = start;
    return true;
}

#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
/* --------------------------------------------------------------------------------------------- */
/* Returns true if in double added successfully to JSON string, else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintDouble(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end, double in,
                        SSFJsonFltFmt_t fmt, bool *commaOpt)
{
    int len = 0;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= jsSize);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((fmt > SSF_JSON_FLT_FMT_MIN) && (fmt < SSF_JSON_FLT_FMT_MAX));

    SSF_JSON_COMMA(commaOpt);
    if (fmt == SSF_JSON_FLT_FMT_SHORT) len = snprintf(&js[start], jsSize - start, "%g", in);
    else if (fmt == SSF_JSON_FLT_FMT_STD) len = snprintf(&js[start], jsSize - start, "%f", in);
    else
    {
        size_t delta = jsSize - start;
        char *ptr = &js[start];

        switch (fmt)
        {
            case 0: len = snprintf(ptr, delta, "%.0f", in); break;
            case 1: len = snprintf(ptr, delta, "%.1f", in); break;
            case 2: len = snprintf(ptr, delta, "%.2f", in); break;
            case 3: len = snprintf(ptr, delta, "%.3f", in); break;
            case 4: len = snprintf(ptr, delta, "%.4f", in); break;
            case 5: len = snprintf(ptr, delta, "%.5f", in); break;
            case 6: len = snprintf(ptr, delta, "%.6f", in); break;
            case 7: len = snprintf(ptr, delta, "%.7f", in); break;
            case 8: len = snprintf(ptr, delta, "%.8f", in); break;
            case 9: len = snprintf(ptr, delta, "%.9f", in); break;
            case SSF_JSON_FLT_FMT_SHORT:
            case SSF_JSON_FLT_FMT_STD:
            case SSF_JSON_FLT_FMT_MAX:
            default:
                SSF_ERROR(); break;
        }
    }
    /* Did formatting fail or not fit with room for the terminator? */
    if ((len < 0) || (((size_t)len) >= (jsSize - start)))
    {
        /* Yes */
        return false;
    }
    *end = start + (size_t)len;
    return true;
}
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in signed int added successfully to JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintInt(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end, int64_t in,
                     bool *commaOpt)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= jsSize);
    SSF_REQUIRE(end != NULL);

    SSF_JSON_COMMA(commaOpt);
    len = SSFDecIntToStr(in, &js[start], jsSize - start);
    /* Did conversion fail or not fit with room for the terminator? */
    if ((len == 0) || (len >= (jsSize - start)))
    {
        /* Yes */
        return false;
    }
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in unsigned int added successfully to JSON string, else false.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintUInt(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end, uint64_t in,
                      bool *commaOpt)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= jsSize);
    SSF_REQUIRE(end != NULL);

    SSF_JSON_COMMA(commaOpt);
    len = SSFDecUIntToStr(in, &js[start], jsSize - start);
    /* Did conversion fail or not fit with room for the terminator? */
    if ((len == 0) || (len >= (jsSize - start)))
    {
        /* Yes */
        return false;
    }
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all printing added successfully to JSON string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrint(SSFCStrOut_t js, size_t jsSize, size_t start, size_t *end,
                  SSFJsonPrintFn_t fnOpt, void *in, const char *ocOpt, bool *commaOpt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= jsSize);
    SSF_REQUIRE(end != NULL);

    SSF_JSON_COMMA(commaOpt);
    /* Is there an opening character that does not fit? */
    if ((ocOpt != NULL) && (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, ocOpt[0])))
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
    if ((ocOpt != NULL) && (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, ocOpt[1])))
    {
        /* Yes */
        return false;
    }
    if (!_SSFJsonPrintUnescChar(js, jsSize, start, &start, 0)) return false;
    *end = start - 1;
    return true;
}

#if SSF_JSON_GOBJ_ENABLE == 1
/* --------------------------------------------------------------------------------------------- */
/* Unescapes a JSON string value (between quotes) into out buffer. Returns true on success.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjUnescStr(SSFCStrIn_t jsStr, size_t strStart, size_t strEnd,
                                 SSFCStrOut_t out, size_t outSize)
{
    size_t s;
    size_t o = 0;

    SSF_ASSERT(jsStr != NULL);
    SSF_ASSERT(out != NULL);
    SSF_ASSERT(outSize > 0);

    /* Skip opening and closing quotes */
    s = strStart + 1;
    strEnd--;

    while (s <= strEnd)
    {
        if (jsStr[s] == '\\')
        {
            s++;
            if (s > strEnd) return false;
            /* Is it an escaped quote, backslash or solidus? */
            if ((jsStr[s] == '"') || (jsStr[s] == '\\') || (jsStr[s] == '/'))
            {
                /* Yes, copy it as is */
                if (o >= (outSize - 1)) return false;
                out[o++] = jsStr[s++];
            }
            else if (jsStr[s] == 'n')
            { if (o >= (outSize - 1)) return false; out[o++] = '\x0a'; s++; }
            else if (jsStr[s] == 'r')
            { if (o >= (outSize - 1)) return false; out[o++] = '\x0d'; s++; }
            else if (jsStr[s] == 't')
            { if (o >= (outSize - 1)) return false; out[o++] = '\x09'; s++; }
            else if (jsStr[s] == 'f')
            { if (o >= (outSize - 1)) return false; out[o++] = '\x0c'; s++; }
            else if (jsStr[s] == 'b')
            { if (o >= (outSize - 1)) return false; out[o++] = '\x08'; s++; }
            else if (jsStr[s] == 'u')
            {
                s++;
                if (((strEnd - s) + 1) < 4) return false;
                if ((o + 2) >= outSize) return false;
                if (SSFHexByteToBin(&jsStr[s], (uint8_t *)&out[o]) == false) return false;
                o++;
                if (SSFHexByteToBin(&jsStr[s + 2], (uint8_t *)&out[o]) == false) return false;
                o++;
                s += 4;
            }
            else return false;
        }
        else
        {
            if (o >= (outSize - 1)) return false;
            out[o++] = jsStr[s++];
        }
    }
    out[o] = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Recursively converts a JSON value at jsStr[*index] into a gobj node; returns true on success. */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjValue(SSFCStrIn_t jsStr, size_t *index, SSFGObj_t *gobj,
                              uint16_t maxChildren, uint8_t depth)
{
    size_t start;
    size_t end;
    size_t i;
    char strBuf[SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE + 1];
    SSFGObj_t *child = NULL;

    SSF_ASSERT(jsStr != NULL);
    SSF_ASSERT(index != NULL);
    SSF_ASSERT(gobj != NULL);

    if (depth >= SSF_JSON_CONFIG_MAX_IN_DEPTH) return false;

    _SSFJsonWhitespace(jsStr, index);

    /* Object */
    if (jsStr[*index] == '{')
    {
        if (SSFGObjSetObject(gobj) == false) return false;
        (*index)++;
        _SSFJsonWhitespace(jsStr, index);
        if (jsStr[*index] != '}')
        {
            do
            {
                /* Parse key string */
                i = *index;
                if (_SSFJsonString(jsStr, &i, &start, &end) == false) return false;
                *index = i;
                if (_SSFJsonGObjUnescStr(jsStr, start, end, strBuf, sizeof(strBuf)) == false)
                { return false; }

                _SSFJsonWhitespace(jsStr, index);
                if (jsStr[*index] != ':') return false;
                (*index)++;

                /* Create child and set label */
                child = NULL;
                if (SSFGObjInit(&child, maxChildren) == false) return false;
                if (SSFGObjSetLabel(child, strBuf) == false)
                { SSFGObjDeInit(&child); return false; }

                /* Insert the still-empty child */
                if (SSFGObjInsertChild(gobj, child) == false)
                { SSFGObjDeInit(&child); return false; }
                if (_SSFJsonGObjValue(jsStr, index, child, maxChildren, depth + 1) == false)
                { return false; }

                _SSFJsonWhitespace(jsStr, index);
                if (jsStr[*index] == '}') break;
                if (jsStr[*index] != ',') return false;
                (*index)++;
            } while (true);
        }
        (*index)++;
        return true;
    }

    /* Array */
    if (jsStr[*index] == '[')
    {
        if (SSFGObjSetArray(gobj) == false) return false;
        (*index)++;
        _SSFJsonWhitespace(jsStr, index);
        if (jsStr[*index] != ']')
        {
            do
            {
                /* Create child */
                child = NULL;
                if (SSFGObjInit(&child, maxChildren) == false) return false;

                /* Insert the still-empty child and then populate */
                if (SSFGObjInsertChild(gobj, child) == false)
                { SSFGObjDeInit(&child); return false; }
                if (_SSFJsonGObjValue(jsStr, index, child, maxChildren, depth + 1) == false)
                { return false; }

                _SSFJsonWhitespace(jsStr, index);
                if (jsStr[*index] == ']') break;
                if (jsStr[*index] != ',') return false;
                (*index)++;
            } while (true);
        }
        (*index)++;
        return true;
    }

    /* String */
    i = *index;
    if (_SSFJsonString(jsStr, &i, &start, &end))
    {
        *index = i;
        if (_SSFJsonGObjUnescStr(jsStr, start, end, strBuf, sizeof(strBuf)) == false) return false;
        return SSFGObjSetString(gobj, strBuf);
    }

    /* Number */
    i = *index;
    if (_SSFJsonNumber(jsStr, &i, &start, &end))
    {
        size_t numLen = (end - start) + 1;
        bool hasDecimal = false;
        size_t n;
        int64_t intVal;

        *index = i;
        if (numLen > (sizeof(strBuf) - 1)) return false;

        /* Copy number to null-terminated buffer */
        memcpy(strBuf, &jsStr[start], numLen);
        strBuf[numLen] = 0;

        /* Check for decimal point or exponent */
        for (n = 0; n < numLen; n++)
        {
            /* Is it a decimal point or an exponent? */
            if ((strBuf[n] == '.') || (strBuf[n] == 'e') || (strBuf[n] == 'E'))
            {
                /* Yes, not an integer */
                hasDecimal = true;
                break;
            }
        }

        if (hasDecimal == false)
        {
            /* Try signed integer first, then unsigned */
            uint64_t uintVal;

            if (SSFDecStrToInt(strBuf, &intVal)) return SSFGObjSetInt(gobj, intVal);
            if (SSFDecStrToUInt(strBuf, &uintVal)) return SSFGObjSetUInt(gobj, uintVal);
        }

#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        {
            char *endptr;
            double dval;

            dval = strtod(strBuf, &endptr);
            if (endptr == &strBuf[numLen]) return SSFGObjSetFloat(gobj, dval);
        }
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        return false;
    }

    /* true */
    if (strncmp(&jsStr[*index], "true", 4) == 0)
    { *index += 4; return SSFGObjSetBool(gobj, true); }

    /* false */
    if (strncmp(&jsStr[*index], "false", 5) == 0)
    { *index += 5; return SSFGObjSetBool(gobj, false); }

    /* null */
    if (strncmp(&jsStr[*index], "null", 4) == 0)
    { *index += 4; return SSFGObjSetNull(gobj); }

    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if JSON string successfully converted to gobj representation, else false.        */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGObjCreate(SSFCStrIn_t jsStr, SSFGObj_t **gobj, uint16_t maxChildren)
{
    SSFGObj_t *root = NULL;
    size_t index;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(gobj != NULL);

    /* Validate JSON first */
    if (SSFJsonIsValid(jsStr) == false) return false;

    /* Create root node */
    if (SSFGObjInit(&root, maxChildren) == false) return false;

    /* Parse recursively */
    index = 0;
    if (_SSFJsonGObjValue(jsStr, &index, root, maxChildren, 0) == false)
    { SSFGObjDeInit(&root); return false; }

    /* Verify entire input was consumed (skip trailing whitespace) */
    _SSFJsonWhitespace(jsStr, &index);
    if (jsStr[index] != '\0')
    { SSFGObjDeInit(&root); return false; }

    *gobj = root;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Forward declaration for recursive printing.                                                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjPrintValue(SSFGObj_t *gobj, SSFCStrOut_t js, size_t jsSize, size_t start,
                                   size_t *end, bool *commaOpt);

/* --------------------------------------------------------------------------------------------- */
/* Callback that prints the children of a gobj container (object or array).                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjPrintChildrenFn(char *js, size_t jsSize, size_t start, size_t *end,
                                        void *in)
{
    SSFGObj_t *gobj = (SSFGObj_t *)in;
    SSFLLItem_t *item;
    SSFGObj_t *child;
    bool comma = false;
    bool isObject;
    char label[SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE + 1];

    SSF_ASSERT(gobj != NULL);
    SSF_REQUIRE(end != NULL);

    isObject = (SSFGObjGetType(gobj) == SSF_OBJ_TYPE_OBJECT);

    item = SSF_LL_HEAD(&(gobj->children));
    while (item != NULL)
    {
        child = (SSFGObj_t *)item;

        if (isObject)
        {
            /* Print "label": then value */
            if (SSFGObjGetLabel(child, label, sizeof(label)) == false) return false;
            if (SSFJsonPrintLabel(js, jsSize, start, &start, label, &comma) == false) return false;
            if (_SSFJsonGObjPrintValue(child, js, jsSize, start, &start, NULL) == false)
            { return false; }
        }
        else
        {
            /* Array: print value with comma tracking */
            if (_SSFJsonGObjPrintValue(child, js, jsSize, start, &start, &comma) == false)
            { return false; }
        }
        item = SSF_LL_NEXT_ITEM(item);
    }
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Prints a single gobj value into the JSON output buffer. Returns true on success.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjPrintValue(SSFGObj_t *gobj, SSFCStrOut_t js, size_t jsSize, size_t start,
                                   size_t *end, bool *commaOpt)
{
    char strVal[SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE + 1];
    int64_t intVal;
    uint64_t uintVal;
    bool boolVal;
#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
    double dblVal;
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */

    SSF_ASSERT(gobj != NULL);

    if (SSFGObjGetDepth(gobj) >= SSF_GOBJ_CONFIG_MAX_IN_DEPTH) return false;

    switch (SSFGObjGetType(gobj))
    {
    case SSF_OBJ_TYPE_STR:
        if (SSFGObjGetString(gobj, strVal, sizeof(strVal)) == false) return false;
        return SSFJsonPrintString(js, jsSize, start, end, strVal, commaOpt);
    case SSF_OBJ_TYPE_INT:
        if (SSFGObjGetInt(gobj, &intVal) == false) return false;
        return SSFJsonPrintInt(js, jsSize, start, end, intVal, commaOpt);
    case SSF_OBJ_TYPE_UINT:
        if (SSFGObjGetUInt(gobj, &uintVal) == false) return false;
        return SSFJsonPrintUInt(js, jsSize, start, end, uintVal, commaOpt);
    case SSF_OBJ_TYPE_BOOL:
        if (SSFGObjGetBool(gobj, &boolVal) == false) return false;
        if (boolVal) return SSFJsonPrintTrue(js, jsSize, start, end, commaOpt);
        else return SSFJsonPrintFalse(js, jsSize, start, end, commaOpt);
    case SSF_OBJ_TYPE_NULL:
        return SSFJsonPrintNull(js, jsSize, start, end, commaOpt);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
    case SSF_OBJ_TYPE_FLOAT:
        if (SSFGObjGetFloat(gobj, &dblVal) == false) return false;
        return SSFJsonPrintDouble(js, jsSize, start, end, dblVal, SSF_JSON_FLT_FMT_STD, commaOpt);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */
    case SSF_OBJ_TYPE_OBJECT:
        return SSFJsonPrintObject(js, jsSize, start, end, _SSFJsonGObjPrintChildrenFn, gobj,
                                  commaOpt);
    case SSF_OBJ_TYPE_ARRAY:
        return SSFJsonPrintArray(js, jsSize, start, end, _SSFJsonGObjPrintChildrenFn, gobj,
                                 commaOpt);
    default:
        return false;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if gobj representation successfully converted to JSON string, else false.        */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGObjPrint(SSFGObj_t *gobj, SSFCStrOut_t js, size_t jsSize, size_t *jsLen)
{
    size_t end;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(jsSize > 0);
    SSF_REQUIRE(jsLen != NULL);

    if (_SSFJsonGObjPrintValue(gobj, js, jsSize, 0, &end, NULL) == false) return false;
    *jsLen = end;
    return true;
}
#endif /* SSF_JSON_GOBJ_ENABLE */

