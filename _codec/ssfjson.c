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
#define SSFJsonEsc(j, b) do { j[start] = '\\'; start++; if (start >= size) return false; \
                              j[start] = b;} while (0)
#define SSF_JSON_COMMA(c) do { \
    if (((c) && (*c)) && (!_SSFJsonPrintUnescChar(js, size, start, &start, ','))) return false; \
    if (c) *c = true; } while (0);
#define SSF_JSON_ADD_ESC(e) out[index] = e; start++; len--; index++; \
                            if (outLen != NULL) (*outLen)++; \
                            continue;

/* --------------------------------------------------------------------------------------------- */
/* Local prototypes                                                                              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonValue(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                          SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt);
static bool _SSFJsonObject(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                           SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt);

/* --------------------------------------------------------------------------------------------- */
/* Increments index past whitespace in JSON string                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFJsonWhitespace(SSFCStrIn_t js, size_t *index)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);

    while ((js[*index] == ' ') || (js[*index] == '\n') || (js[*index] == '\r') ||
           (js[*index] == '\t')) (*index)++;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if 1 or more digits 0-9 found in JSON string, else false.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNumberIsDigits(SSFCStrIn_t js, size_t *index, size_t *end)
{
    bool foundDig = false;
    while ((js[*index] >= '0') && (js[*index] <= '9'))
    {(*index)++; foundDig = true; }
    if (foundDig == true) *end = *index - 1;
    return foundDig;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if number found in JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNumber(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);

    if ((js[*index] != '-') && !((js[*index] >= '0') && (js[*index] <= '9'))) return false;
    *start = *index;
    if (js[*index] == '-') (*index)++;
    if (js[*index] != '0')
    {if (!_SSFJsonNumberIsDigits(js, index, end)) return false; } else
    {(*index)++; }
    if (js[*index] == '.')
    {(*index)++; if (!_SSFJsonNumberIsDigits(js, index, end)) return false; }
    if ((js[*index] == 'e') || (js[*index] == 'E'))
    {
        (*index)++;
        if ((js[*index] == '-') || (js[*index] == '+')) (*index)++;
        return _SSFJsonNumberIsDigits(js, index, end);
    }
    *end = *index - 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if string found, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonString(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);

    _SSFJsonWhitespace(js, index);
    if (js[*index] != '"') return false;
    *start = *index;
    (*index)++;
    while ((js[*index] != 0) && (js[*index] != '"'))
    {
        if (js[*index] == '\\')
        {
            (*index)++;
            if (!SSFJsonIsEsc(js[*index])) return false;
            if (js[*index] != 'u')
            {(*index)++; continue; }
            (*index)++;
            if (!SSFIsHex(js[*index])) return false;
            if (!SSFIsHex(js[(*index) + 1])) return false;
            if (!SSFIsHex(js[(*index) + 2])) return false;
            if (!SSFIsHex(js[(*index) + 3])) return false;
            (*index) += 4;
        } else (*index)++;
    }
    if (js[*index] != '"') return false;
    *end = (*index);
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if array found, else false; If true returns type/start/end on path index match.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonArray(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                          SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    size_t curIndex = 0;
    size_t pindex = (size_t)-1;
    SSFJsonType_t djt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    if (depth == 0)
    {
        uint32_t i;
        for (i = 0; (i <= SSF_JSON_CONFIG_MAX_IN_LEN) && (js[i] != 0); i++);
        if (i > SSF_JSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_JSON_TYPE_ERROR;
        *index = 0;
    }

    if (depth >= SSF_JSON_CONFIG_MAX_IN_DEPTH) return false;
    _SSFJsonWhitespace(js, index);
    if (js[*index] != '[') return false;
    if ((path != NULL) && (path[depth] == NULL)) *start = *index;
    (*index)++;

    if ((path != NULL) && (path[depth] != NULL)) memcpy(&pindex, path[depth], sizeof(size_t));
    while (_SSFJsonValue(js, index, &valStart, &valEnd, path, depth, &djt) == true)
    {
        if (pindex == curIndex)
        {*start = valStart; *end = valEnd; *jt = djt; }
        _SSFJsonWhitespace(js, index);
        if (js[*index] == ']') break;
        if (js[*index] != ',') return false;
        (*index)++;
        curIndex++;
    }
    if ((pindex != (size_t)-1) && (pindex > curIndex)) *jt = SSF_JSON_TYPE_ERROR;
    if (js[*index] != ']') return false;

    if ((path != NULL) && (path[depth] == NULL)) {*end = *index; *jt = SSF_JSON_TYPE_ARRAY; }
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value found, else false; If true returns type/start/end on path match.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonValue(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                          SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt)
{
    size_t i;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    _SSFJsonWhitespace(js, index); i = *index;
    if (_SSFJsonString(js, &i, start, end)) {*jt = SSF_JSON_TYPE_STRING; *index = i; return true; }
    i = *index;
    if (_SSFJsonObject(js, &i, start, end, path, depth + 1, jt)) {*index = i; return true; }
    i = *index;
    if (_SSFJsonArray(js, &i, start, end, path, depth + 1, jt)) {*index = i; return true; }
    i = *index;
    if (_SSFJsonNumber(js, &i, start, end)) {*jt = SSF_JSON_TYPE_NUMBER; *index = i; return true; }
    i = *index;
    if (strncmp(&js[i], "true", 4) == 0)
    {*jt = SSF_JSON_TYPE_TRUE; *start = i; i += 4; *end = i - 1; *index = i; return true; }
    i = *index;
    if (strncmp(&js[i], "false", 5) == 0)
    {*jt = SSF_JSON_TYPE_FALSE; *start = i; i += 5; *end = i - 1; *index = i; return true; }
    i = *index;
    if (strncmp(&js[i], "null", 4) == 0)
    {*jt = SSF_JSON_TYPE_NULL; *start = i; i += 4; *end = i - 1; *index = i; return true; }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/value found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNameValue(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                              SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    SSFJsonType_t djt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    if (_SSFJsonString(js, index, &valStart, &valEnd) == false) return false;
    _SSFJsonWhitespace(js, index);
    if (js[*index] != ':') return false;
    (*index)++;
    if ((path != NULL) && (path[depth] != NULL) &&
        ((valEnd - valStart - 1) == (size_t)strlen(path[depth])) &&
        (strncmp(path[depth], &js[valStart + 1], (valEnd - valStart - 1)) == 0))
    {return _SSFJsonValue(js, index, start, end, path, depth, jt); }
    else return _SSFJsonValue(js, index, &valStart, &valEnd, NULL, 0, &djt);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object found, else false; If true returns type/start/end on path match.       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonObject(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                           SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE((path == NULL) || (path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL));

    if (depth == 0)
    {
        uint32_t i;
        for (i = 0; (i <= SSF_JSON_CONFIG_MAX_IN_LEN) && (js[i] != 0); i++);
        if (i > SSF_JSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_JSON_TYPE_ERROR;
        *index = 0;
    }
    if (depth >= SSF_JSON_CONFIG_MAX_IN_DEPTH) return false;

    _SSFJsonWhitespace(js, index);
    if (js[*index] != '{') return false;
    if ((depth != 0) || ((depth == 0) && (path != NULL) && (path[0] == NULL))) *start = *index;
    (*index)++;
    _SSFJsonWhitespace(js, index);
    if (js[*index] != '}')
    {
        if (!_SSFJsonNameValue(js, index, start, end, path, depth, jt)) return false;
        do
        {
            _SSFJsonWhitespace(js, index);
            if (js[*index] == '}') break;
            if (js[*index] != ',') return false;
            (*index)++;
            if (!_SSFJsonNameValue(js, index, start, end, path, depth, jt)) return false;
        } while (true);
        if (js[*index] != '}') return false;
    }
    if (((path != NULL) && (path[depth] == NULL)) ||
        ((depth == 0) && (path != NULL) && (path[0] == NULL)))
    {*end = *index; *jt = SSF_JSON_TYPE_OBJECT; }
    (*index)++;
    if (depth == 0)
    {_SSFJsonWhitespace(js, index); if (js[*index] != 0) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object|array found, else false; If true returns type/start/end on path match. */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonMessage(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end, SSFCStrIn_t *path,
                    uint8_t depth, SSFJsonType_t *jt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE((path == NULL) || (path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL));

    if (!_SSFJsonObject(js, index, start, end, path, depth, jt))
    {
        if (!_SSFJsonArray(js, index, start, end, path, depth, jt)) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if JSON string is valid, else false.                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonIsValid(SSFCStrIn_t js)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;
    char *path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(js != NULL);

    memset(path, 0, sizeof(path));
    if (!SSFJsonMessage(js, &index, &start, &end, (SSFCStrIn_t *)path, 0, &jt)) return false;
    return jt != SSF_JSON_TYPE_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SSF_JSON_TYPE_ERROR if JSON string is invalid or path not found, else valid type.     */
/* --------------------------------------------------------------------------------------------- */
SSFJsonType_t SSFJsonGetType(SSFCStrIn_t js, SSFCStrIn_t *path)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);

    if (!SSFJsonMessage(js, &index, &start, &end, path, 0, &jt)) jt = SSF_JSON_TYPE_ERROR;
    return jt;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is unescaped completely into buffer w/NULL term., else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetString(SSFCStrIn_t js, SSFCStrIn_t *path, char *out, size_t outSize, size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    size_t len;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outSize > 0);

    if (!SSFJsonMessage(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;

    index = 0;
    len = end - start + 1;
    if (outLen != NULL) *outLen = 0;

    while ((len != 0) && (index < (outSize - 1)))
    {
        if (js[start] == '\\')
        {
            start++; len--;
            if (len == 0) return false;
            /* Potential escape sequence */
            if (js[start] == '"' || js[start] == '\\' || js[start] == '/')
            { SSF_JSON_ADD_ESC(js[start]) }
            else if (js[start] == 'n') { SSF_JSON_ADD_ESC('\x0a') }
            else if (js[start] == 'r') { SSF_JSON_ADD_ESC('\x0d') }
            else if (js[start] == 't') { SSF_JSON_ADD_ESC('\x09') }
            else if (js[start] == 'f') { SSF_JSON_ADD_ESC('\x0c') }
            else if (js[start] == 'b') { SSF_JSON_ADD_ESC('\x08') }
            else if (js[start] != 'u') return false;

            if (outLen != NULL) (*outLen)++;
            start++; len--;
            if (len < 4) return false;
            if ((index + 2) >= outSize) return false;
            if (!SSFHexByteToBin(&js[start], (uint8_t *)&out[index])) return false;
            index++;
            if (!SSFHexByteToBin(&js[start + 2], (uint8_t *)&out[index])) return false;
            start += 3; len -= 3;
        }
        else { out[index] = js[start]; }
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
bool SSFJsonGetDouble(SSFCStrIn_t js, SSFCStrIn_t *path, double *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFJsonType_t jt;
    char *endptr;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFJsonMessage(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_NUMBER) return false;
    *out = strtod(&js[start], &endptr);
    if ((endptr - 1) != &js[end]) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetInt(SSFCStrIn_t js, SSFCStrIn_t *path, int64_t *out)
{
    double dout;

    if (!SSFJsonGetDouble(js, path, &dout)) return false;
    *out = (int64_t)round(dout);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to unsigned int, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetUInt(SSFCStrIn_t js, SSFCStrIn_t *path, uint64_t *out)
{
    double dout;

    if (!SSFJsonGetDouble(js, path, &dout)) return false;
    if (dout < 0) return false;
    *out = (uint64_t)round(dout);
    return true;
}
#else
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool _SSFJsonGetXLong(SSFCStrIn_t js, SSFCStrIn_t *path, int64_t *outs, uint64_t *outu)
{
    size_t index;
    size_t start;
    size_t end;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(((outs != NULL) && (outu == NULL)) || ((outs == NULL) && (outu != NULL)));

    if (!SSFJsonMessage(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_NUMBER) return false;
    if (outu != NULL) return SSFDecStrToUInt(&js[start], outu);
    else return SSFDecStrToInt(&js[start], outs);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetInt(SSFCStrIn_t js, SSFCStrIn_t *path, int64_t *out)
{
    return _SSFJsonGetXLong(js, path, out, NULL);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to unsigned int, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetUInt(SSFCStrIn_t js, SSFCStrIn_t *path, uint64_t *out)
{
    return _SSFJsonGetXLong(js, path, NULL, out);
}
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and completely converted to binary data, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetHex(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize, size_t *outLen,
                   bool rev)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (!SSFJsonMessage(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;
    return SSFHexBytesToBin(&js[start], (end - start + 1), out, outSize, outLen, rev);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found, entire decode successful, and outLen updated, else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetBase64(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                      size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (!SSFJsonMessage(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;

    return SSFBase64Decode(&js[start], (end - start + 1), out, outSize, outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if char added to js, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonPrintUnescChar(SSFCStrOut_t js, size_t size, size_t start, size_t *end, const char in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (start >= size) return false;
    js[start] = in;
    *end = start + 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in string added successfully as escaped string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintCString(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFCStrIn_t in,
                         bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    SSF_JSON_COMMA(comma);
    while (start < size)
    {
        if (*in == '\\') SSFJsonEsc(js, '\\');
        else if (*in == '\"') SSFJsonEsc(js, '\"');
        else if (*in == '\r') SSFJsonEsc(js, 'r');
        else if (*in == '\n') SSFJsonEsc(js, 'n');
        else if (*in == '\t') SSFJsonEsc(js, 't');
        else if (*in == '\b') SSFJsonEsc(js, 'b');
        else if (*in == '\f') SSFJsonEsc(js, 'f');
        else if (((*in > 0x1f) && (*in < 0x7f)) || (*in == 0))
        {js[start] = *in; } /* Normal ASCII character */
        else
        {
            if ((start + 6) >= size) return false;
            js[start] = '\\'; start++;
            js[start] = 'u'; start++;
            js[start] = '0'; start++;
            js[start] = '0'; start++;
            SSF_ASSERT(SSFHexBinToByte(*in, &js[start], 2, SSF_HEX_CASE_UPPER));
            start++;
        }
        if (*in == 0)
        {*end = start; return true; }
        start++;
        in++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in string added successfully as quoted escaped string, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintString(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFCStrIn_t in,
                        bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    SSF_JSON_COMMA(comma);
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, '\"')) return false;
    if (!SSFJsonPrintCString(js, size, start, &start, in, NULL)) return false;
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, '\"')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in label element added successfully, else false.                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintLabel(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFCStrIn_t in,
                       bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintString(js, size, start, &start, in, NULL)) return false;
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, ':')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in data added successfully as quoted ASCII hex string, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintHex(SSFCStrOut_t js, size_t size, size_t start, size_t *end, const uint8_t *in,
                     size_t inLen, bool rev, bool *comma)
{
    size_t outLen;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    SSF_JSON_COMMA(comma);
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    if (!SSFHexBinToBytes(in, inLen, &js[start], size - start, &outLen, rev, SSF_HEX_CASE_UPPER))
    {return false; }
    start += outLen;
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in data added successfully as quoted Base64 string, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintBase64(SSFCStrOut_t js, size_t size, size_t start, size_t *end, const uint8_t *in,
                        size_t inLen, bool *comma)
{
    size_t outLen;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    SSF_JSON_COMMA(comma);
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    if (!SSFBase64Encode(in, inLen, &js[start], size - start, &outLen)) return false;
    start += outLen;
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    *end = start;
    return true;
}

#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
/* --------------------------------------------------------------------------------------------- */
/* Returns true if in double added successfully to JSON string, else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintDouble(SSFCStrOut_t js, size_t size, size_t start, size_t *end, double in,
                        SSFJsonFltFmt_t fmt, bool *comma)
{
    int len = 0;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((fmt > SSF_JSON_FLT_FMT_MIN) && (fmt < SSF_JSON_FLT_FMT_MAX));

    SSF_JSON_COMMA(comma);
    if (fmt == SSF_JSON_FLT_FMT_SHORT) len = snprintf(&js[start], size - start, "%g", in);
    else if (fmt == SSF_JSON_FLT_FMT_STD) len = snprintf(&js[start], size - start, "%f", in);
    else
    {
        size_t delta = size - start;
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
    if ((len < 0) || (((size_t)len) >= (size - start))) return false;
    *end = start + len;
    return true;
}
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in signed int added successfully to JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end, int64_t in,
                     bool *comma)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);

    SSF_JSON_COMMA(comma);
    len = SSFDecIntToStr(in, &js[start], size - start);
    if ((len == 0) || (len >= (size - start))) return false;
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in unsigned int added successfully to JSON string, else false.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintUInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end, uint64_t in,
                      bool *comma)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);

    SSF_JSON_COMMA(comma);
    len = SSFDecUIntToStr(in, &js[start], size - start);
    if ((len == 0) || (len >= (size - start))) return false;
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all printing added successfully to JSON string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrint(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFJsonPrintFn_t fn,
                  void *in, const char *oc, bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);

    SSF_JSON_COMMA(comma);
    if ((oc != NULL) && (!_SSFJsonPrintUnescChar(js, size, start, &start, oc[0]))) return false;
    if ((fn != NULL) && (!fn(js, size, start, &start, in))) return false;
    if ((oc != NULL) && (!_SSFJsonPrintUnescChar(js, size, start, &start, oc[1]))) return false;
    if (!_SSFJsonPrintUnescChar(js, size, start, &start, 0)) return false;
    *end = start - 1;
    return true;
}

#if SSF_JSON_GOBJ_ENABLE == 1
/* --------------------------------------------------------------------------------------------- */
/* Unescapes a JSON string value (between quotes) into out buffer. Returns true on success.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjUnescStr(SSFCStrIn_t js, size_t strStart, size_t strEnd, SSFCStrOut_t out,
                                 size_t outSize)
{
    size_t s;
    size_t o = 0;

    SSF_ASSERT(js != NULL);
    SSF_ASSERT(out != NULL);
    SSF_ASSERT(outSize > 0);

    /* Skip opening and closing quotes */
    s = strStart + 1;
    strEnd--;

    while (s <= strEnd)
    {
        if (js[s] == '\\')
        {
            s++;
            if (s > strEnd) return false;
            if (js[s] == '"' || js[s] == '\\' || js[s] == '/')
            { if (o >= (outSize - 1)) return false; out[o++] = js[s++]; }
            else if (js[s] == 'n') { if (o >= (outSize - 1)) return false; out[o++] = '\x0a'; s++; }
            else if (js[s] == 'r') { if (o >= (outSize - 1)) return false; out[o++] = '\x0d'; s++; }
            else if (js[s] == 't') { if (o >= (outSize - 1)) return false; out[o++] = '\x09'; s++; }
            else if (js[s] == 'f') { if (o >= (outSize - 1)) return false; out[o++] = '\x0c'; s++; }
            else if (js[s] == 'b') { if (o >= (outSize - 1)) return false; out[o++] = '\x08'; s++; }
            else if (js[s] == 'u')
            {
                s++;
                if ((strEnd - s + 1) < 4) return false;
                if ((o + 2) >= outSize) return false;
                if (SSFHexByteToBin(&js[s], (uint8_t *)&out[o]) == false) return false;
                o++;
                if (SSFHexByteToBin(&js[s + 2], (uint8_t *)&out[o]) == false) return false;
                o++;
                s += 4;
            }
            else return false;
        }
        else
        {
            if (o >= (outSize - 1)) return false;
            out[o++] = js[s++];
        }
    }
    out[o] = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Recursively converts a JSON value at js[*index] into a gobj node. Returns true on success.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjValue(SSFCStrIn_t js, size_t *index, SSFGObj_t *gobj, uint16_t maxChildren,
                              uint8_t depth)
{
    size_t start;
    size_t end;
    size_t i;
    char strBuf[SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE + 1];
    SSFGObj_t *child = NULL;

    SSF_ASSERT(js != NULL);
    SSF_ASSERT(index != NULL);
    SSF_ASSERT(gobj != NULL);

    if (depth >= SSF_JSON_CONFIG_MAX_IN_DEPTH) return false;

    _SSFJsonWhitespace(js, index);

    /* Object */
    if (js[*index] == '{')
    {
        if (SSFGObjSetObject(gobj) == false) return false;
        (*index)++;
        _SSFJsonWhitespace(js, index);
        if (js[*index] != '}')
        {
            do
            {
                /* Parse key string */
                i = *index;
                if (_SSFJsonString(js, &i, &start, &end) == false) return false;
                *index = i;
                if (_SSFJsonGObjUnescStr(js, start, end, strBuf, sizeof(strBuf)) == false)
                { return false; }

                _SSFJsonWhitespace(js, index);
                if (js[*index] != ':') return false;
                (*index)++;

                /* Create child and set label */
                child = NULL;
                if (SSFGObjInit(&child, maxChildren) == false) return false;
                if (SSFGObjSetLabel(child, strBuf) == false)
                { SSFGObjDeInit(&child); return false; }

                /* Recurse for value */
                if (_SSFJsonGObjValue(js, index, child, maxChildren, depth + 1) == false)
                { SSFGObjDeInit(&child); return false; }
                if (SSFGObjInsertChild(gobj, child) == false)
                { SSFGObjDeInit(&child); return false; }

                _SSFJsonWhitespace(js, index);
                if (js[*index] == '}') break;
                if (js[*index] != ',') return false;
                (*index)++;
            } while (true);
        }
        (*index)++;
        return true;
    }

    /* Array */
    if (js[*index] == '[')
    {
        if (SSFGObjSetArray(gobj) == false) return false;
        (*index)++;
        _SSFJsonWhitespace(js, index);
        if (js[*index] != ']')
        {
            do
            {
                /* Create child */
                child = NULL;
                if (SSFGObjInit(&child, maxChildren) == false) return false;

                /* Recurse for value */
                if (_SSFJsonGObjValue(js, index, child, maxChildren, depth + 1) == false)
                { SSFGObjDeInit(&child); return false; }
                if (SSFGObjInsertChild(gobj, child) == false)
                { SSFGObjDeInit(&child); return false; }

                _SSFJsonWhitespace(js, index);
                if (js[*index] == ']') break;
                if (js[*index] != ',') return false;
                (*index)++;
            } while (true);
        }
        (*index)++;
        return true;
    }

    /* String */
    i = *index;
    if (_SSFJsonString(js, &i, &start, &end))
    {
        *index = i;
        if (_SSFJsonGObjUnescStr(js, start, end, strBuf, sizeof(strBuf)) == false) return false;
        return SSFGObjSetString(gobj, strBuf);
    }

    /* Number */
    i = *index;
    if (_SSFJsonNumber(js, &i, &start, &end))
    {
        size_t numLen = end - start + 1;
        bool hasDecimal = false;
        size_t n;
        int64_t intVal;

        *index = i;
        if (numLen > (sizeof(strBuf) - 1)) return false;

        /* Copy number to null-terminated buffer */
        memcpy(strBuf, &js[start], numLen);
        strBuf[numLen] = 0;

        /* Check for decimal point or exponent */
        for (n = 0; n < numLen; n++)
        {
            if (strBuf[n] == '.' || strBuf[n] == 'e' || strBuf[n] == 'E')
            { hasDecimal = true; break; }
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
    if (strncmp(&js[*index], "true", 4) == 0)
    { *index += 4; return SSFGObjSetBool(gobj, true); }

    /* false */
    if (strncmp(&js[*index], "false", 5) == 0)
    { *index += 5; return SSFGObjSetBool(gobj, false); }

    /* null */
    if (strncmp(&js[*index], "null", 4) == 0)
    { *index += 4; return SSFGObjSetNull(gobj); }

    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if JSON string successfully converted to gobj representation, else false.        */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGObjCreate(SSFCStrIn_t js, SSFGObj_t **gobj, uint16_t maxChildren)
{
    SSFGObj_t *root = NULL;
    size_t index;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(gobj != NULL);

    /* Validate JSON first */
    if (SSFJsonIsValid(js) == false) return false;

    /* Create root node */
    if (SSFGObjInit(&root, maxChildren) == false) return false;

    /* Parse recursively */
    index = 0;
    if (_SSFJsonGObjValue(js, &index, root, maxChildren, 0) == false)
    { SSFGObjDeInit(&root); return false; }

    /* Verify entire input was consumed (skip trailing whitespace) */
    _SSFJsonWhitespace(js, &index);
    if (js[index] != '\0')
    { SSFGObjDeInit(&root); return false; }

    *gobj = root;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Forward declaration for recursive printing.                                                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjPrintValue(SSFGObj_t *gobj, SSFCStrOut_t js, size_t size, size_t start,
                                   size_t *end, bool *comma);

/* --------------------------------------------------------------------------------------------- */
/* Callback that prints the children of a gobj container (object or array).                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonGObjPrintChildrenFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    SSFGObj_t *gobj = (SSFGObj_t *)in;
    SSFLLItem_t *item;
    SSFGObj_t *child;
    bool comma = false;
    bool isObject;
    char label[SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE + 1];

    SSF_ASSERT(gobj != NULL);

    isObject = (SSFGObjGetType(gobj) == SSF_OBJ_TYPE_OBJECT);

    item = SSF_LL_HEAD(&(gobj->children));
    while (item != NULL)
    {
        child = (SSFGObj_t *)item;

        if (isObject)
        {
            /* Print "label": then value */
            if (SSFGObjGetLabel(child, label, sizeof(label)) == false) return false;
            if (SSFJsonPrintLabel(js, size, start, &start, label, &comma) == false) return false;
            if (_SSFJsonGObjPrintValue(child, js, size, start, &start, NULL) == false) return false;
        }
        else
        {
            /* Array: print value with comma tracking */
            if (_SSFJsonGObjPrintValue(child, js, size, start, &start, &comma) == false)
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
static bool _SSFJsonGObjPrintValue(SSFGObj_t *gobj, SSFCStrOut_t js, size_t size, size_t start,
                                   size_t *end, bool *comma)
{
    char strVal[SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE + 1];
    int64_t intVal;
    uint64_t uintVal;
    bool boolVal;
#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
    double dblVal;
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */

    SSF_ASSERT(gobj != NULL);

    switch (SSFGObjGetType(gobj))
    {
    case SSF_OBJ_TYPE_STR:
        if (SSFGObjGetString(gobj, strVal, sizeof(strVal)) == false) return false;
        return SSFJsonPrintString(js, size, start, end, strVal, comma);
    case SSF_OBJ_TYPE_INT:
        if (SSFGObjGetInt(gobj, &intVal) == false) return false;
        return SSFJsonPrintInt(js, size, start, end, intVal, comma);
    case SSF_OBJ_TYPE_UINT:
        if (SSFGObjGetUInt(gobj, &uintVal) == false) return false;
        return SSFJsonPrintUInt(js, size, start, end, uintVal, comma);
    case SSF_OBJ_TYPE_BOOL:
        if (SSFGObjGetBool(gobj, &boolVal) == false) return false;
        if (boolVal) return SSFJsonPrintTrue(js, size, start, end, comma);
        else return SSFJsonPrintFalse(js, size, start, end, comma);
    case SSF_OBJ_TYPE_NULL:
        return SSFJsonPrintNull(js, size, start, end, comma);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
    case SSF_OBJ_TYPE_FLOAT:
        if (SSFGObjGetFloat(gobj, &dblVal) == false) return false;
        return SSFJsonPrintDouble(js, size, start, end, dblVal, SSF_JSON_FLT_FMT_STD, comma);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */
    case SSF_OBJ_TYPE_OBJECT:
        return SSFJsonPrintObject(js, size, start, end, _SSFJsonGObjPrintChildrenFn, gobj, comma);
    case SSF_OBJ_TYPE_ARRAY:
        return SSFJsonPrintArray(js, size, start, end, _SSFJsonGObjPrintChildrenFn, gobj, comma);
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

