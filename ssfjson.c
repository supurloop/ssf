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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include <stdio.h>
#include "ssfsm.h"
#include "ssfll.h"
#include "ssfmpool.h"
#include "ssfjson.h"
#include "ssfbase64.h"
#include "ssfhex.h"

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
    if (((c) && (*c)) && (!SSFJsonPrintUnescChar(js, size, start, &start, ','))) return false; \
    if (c) *c = true; } while (0);

/* --------------------------------------------------------------------------------------------- */
/* Structs                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef struct SSFJSONAddPath
{
    SSFCStrIn_t *path;
    uint8_t depth;
    SSFJsonPrintFn_t fn;
} SSFJSONAddPath_t;

/* --------------------------------------------------------------------------------------------- */
/* Local prototypes                                                                              */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonValue(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                         SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt); 

/* --------------------------------------------------------------------------------------------- */
/* Increments index past whitespace in JSON string                                               */
/* --------------------------------------------------------------------------------------------- */
static void SSFJsonWhitespace(SSFCStrIn_t js, size_t *index)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);

    while ((js[*index] == ' ') || (js[*index] == '\n') || (js[*index] == '\r') ||
           (js[*index] == '\t')) (*index)++;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if 1 or more digits 0-9 found in JSON string, else false.    */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonNumberIsDigits(SSFCStrIn_t js, size_t *index, size_t *end)
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
static bool SSFJsonNumber(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);

    if ((js[*index] != '-') && !((js[*index] >= '0') && (js[*index] <= '9'))) return false;
    *start = *index;
    if (js[*index] == '-') (*index)++;
    if (js[*index] != '0')
    {if (!SSFJsonNumberIsDigits(js, index, end)) return false; } else
    {(*index)++; }
    if (js[*index] == '.')
    {(*index)++; if (!SSFJsonNumberIsDigits(js, index, end)) return false; }
    if ((js[*index] == 'e') || (js[*index] == 'E'))
    {
        (*index)++;
        if ((js[*index] == '-') || (js[*index] == '+')) (*index)++;
        return SSFJsonNumberIsDigits(js, index, end);
    }
    *end = *index - 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if string found, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonString(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);

    SSFJsonWhitespace(js, index);
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
static bool SSFJsonArray(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
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
    SSF_REQUIRE(depth >= 1);
    SSF_REQUIRE(jt != NULL);

    if (depth >= SSF_JSON_CONFIG_MAX_IN_DEPTH) return false;
    SSFJsonWhitespace(js, index);
    if (js[*index] != '[') return false;
    if (path != NULL && path[depth] == NULL) *start = *index;
    (*index)++;

    if (path != NULL && path[depth] != NULL) pindex = *((const size_t *)path[depth]);
    while (SSFJsonValue(js, index, &valStart, &valEnd, path, depth, &djt) == true)
    {
        if (pindex == curIndex)
        {*start = valStart; *end = valEnd; *jt = djt; }
        SSFJsonWhitespace(js, index);
        if (js[*index] == ']') break;
        if (js[*index] != ',') return false;
        (*index)++;
        curIndex++;
    }
    if ((pindex != -1) && (pindex > curIndex)) *jt = SSF_JSON_TYPE_ERROR;
    if (js[*index] != ']') return false;

    if (path != NULL && path[depth] == NULL)
    {*end = *index; *jt = SSF_JSON_TYPE_ARRAY; }
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value found, else false; If true returns type/start/end on path match.        */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonValue(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                         SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt)
{
    size_t i;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(depth >= 0);
    SSF_REQUIRE(jt != NULL);

    SSFJsonWhitespace(js, index); i = *index;
    if (SSFJsonString(js, &i, start, end))
    {*jt = SSF_JSON_TYPE_STRING; goto VALRET; }
    i = *index;
    if (SSFJsonObject(js, &i, start, end, path, depth + 1, jt))
    {goto VALRET; }
    i = *index;
    if (SSFJsonArray(js, &i, start, end, path, depth + 1, jt))
    {goto VALRET; }
    i = *index;
    if (SSFJsonNumber(js, &i, start, end))
    {*jt = SSF_JSON_TYPE_NUMBER; goto VALRET; }
    i = *index;
    if (strncmp(&js[i], "true", 4) == 0)
    {*jt = SSF_JSON_TYPE_TRUE; *start = i; i += 4; *end = i - 1; goto VALRET; }
    i = *index;
    if (strncmp(&js[i], "false", 5) == 0)
    {*jt = SSF_JSON_TYPE_FALSE; *start = i; i += 5; *end = i - 1; goto VALRET; }
    i = *index;
    if (strncmp(&js[i], "null", 4) == 0)
    {*jt = SSF_JSON_TYPE_NULL; *start = i; i += 4; *end = i - 1; goto VALRET; }
    return false;

VALRET:
    *index = i;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/value found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonNameValue(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                             SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    SSFJsonType_t djt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(depth >= 0);
    SSF_REQUIRE(jt != NULL);

    if (SSFJsonString(js, index, &valStart, &valEnd) == false) return false;
    SSFJsonWhitespace(js, index);
    if (js[*index] != ':') return false;
    (*index)++;
    if ((path != NULL) && (path[depth] != NULL) &&
        (strncmp(path[depth], &js[valStart + 1],
                 SSF_MAX(valEnd - valStart - 1, (int)strlen(path[depth]))) == 0))
    {return SSFJsonValue(js, index, start, end, path, depth, jt); }
    else return SSFJsonValue(js, index, &valStart, &valEnd, NULL, 0, &djt);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object found, else false; If true returns type/start/end on path match.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonObject(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end, SSFCStrIn_t *path,
                   uint8_t depth, SSFJsonType_t *jt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(depth >= 0);
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

    SSFJsonWhitespace(js, index);
    if (js[*index] != '{') return false;
    if ((depth != 0) || ((depth == 0) && (path != NULL) && (path[0] == NULL))) *start = *index;
    (*index)++;
    SSFJsonWhitespace(js, index);
    if (js[*index] != '}')
    {
        if (!SSFJsonNameValue(js, index, start, end, path, depth, jt)) return false;
        do
        {
            SSFJsonWhitespace(js, index);
            if (js[*index] == '}') break;
            if (js[*index] != ',') return false;
            (*index)++;
            if (!SSFJsonNameValue(js, index, start, end, path, depth, jt)) return false;
        } while (true);
        if (js[*index] != '}') return false;
    }
    if (((path != NULL) && (path[depth] == NULL)) ||
        ((depth == 0) && (path != NULL) && (path[0] == NULL)))
    {*end = *index; *jt = SSF_JSON_TYPE_OBJECT; }
    (*index)++;
    if (depth == 0)
    {SSFJsonWhitespace(js, index); if (js[*index] != 0) return false; }
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
    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
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
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(path != NULL);

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) jt = SSF_JSON_TYPE_ERROR;
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

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;

    index = 0;
    len = end - start + 1;
    if (outLen != NULL) *outLen = len;

    while (len && (index < (outSize - 1)))
    {
        if (js[start] == '\\')
        {
            start++; len--;
            if (len == 0) return false;
            /* Potential escape sequence */
            if (js[start] == '"' || js[start] == '\\' || js[start] == '/')
            {out[index] = js[start]; } else if (js[start] == 'n') out[index] = '\x0a';
            else if (js[start] == 'r') out[index] = '\x0d';
            else if (js[start] == 't') out[index] = '\x09';
            else if (js[start] == 'f') out[index] = '\x0c';
            else if (js[start] == 'b') out[index] = '\x08';
            else if (js[start] != 'u') return false;

            start++; len--;
            if (len < 4) return false;
            if (index >= (outSize - 1 - 2)) return false;
            if (!SSFHexByteToBin(&js[start], &out[index])) return false;
            index++;
            if (!SSFHexByteToBin(&js[start + 2], &out[index])) return false;
            start += 3; len -= 3;
        } else out[index] = js[start];
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

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_NUMBER) return false;
    *out = strtod(&js[start], &endptr);
    if ((endptr - 1) != &js[end]) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetLong(SSFCStrIn_t js, SSFCStrIn_t *path, long int *out)
{
    double dout;

    if (!SSFJsonGetDouble(js, path, &dout)) return false;
    *out = (int32_t)round(dout);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to unsigned int, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetULong(SSFCStrIn_t js, SSFCStrIn_t *path, unsigned long int *out)
{
    double dout;

    if (!SSFJsonGetDouble(js, path, &dout)) return false;
    if (dout < 0) return false;
    *out = (uint32_t)round(dout);
    return true;
}
#else
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool _SSFJsonGetXLong(SSFCStrIn_t js, SSFCStrIn_t *path, long int *outs, unsigned long int *outu)
{
    size_t index;
    size_t start;
    size_t end;
    SSFJsonType_t jt;
    char *endptr;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(((outs != NULL) && (outu == NULL)) || ((outs == NULL) && (outu != NULL)));

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_NUMBER) return false;
    if (outu != NULL)
    {
        if (js[start] == '-') return false;
        *outu = strtoul(&js[start], &endptr, 10);
    } else *outs = strtol(&js[start], &endptr, 10);
    if ((endptr - 1) != &js[end]) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to signed int, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetLong(SSFCStrIn_t js, SSFCStrIn_t *path, long int *out)
{
    return _SSFJsonGetXLong(js, path, out, NULL);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to unsigned int, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetULong(SSFCStrIn_t js, SSFCStrIn_t *path, unsigned long int *out)
{
    return _SSFJsonGetXLong(js, path, NULL, out);
}
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and completely converted to binary data, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetHex(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                   size_t *outLen, bool rev)
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

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
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

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;

    return SSFBase64Decode(&js[start], (end - start + 1), out, outSize, outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if char added to js, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonPrintUnescChar(SSFCStrOut_t js, size_t size, size_t start, size_t *end, const char in)
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
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    while (start < size)
    {
        if (*in == '\\') SSFJsonEsc(js, '\\');
        else if (*in == '\"') SSFJsonEsc(js, '\"');
        else if (*in == '/') SSFJsonEsc(js, '/');
        else if (*in == '\r') SSFJsonEsc(js, 'r');
        else if (*in == '\n') SSFJsonEsc(js, 'n');
        else if (*in == '\t') SSFJsonEsc(js, 't');
        else if (*in == '\b') SSFJsonEsc(js, 'b');
        else if (*in == '\f') SSFJsonEsc(js, 'f');
        else if (((*in > 0x1f) && (*in < 0x7f)) || (*in == 0))
        {js[start] = *in; } /* Normal ASCII character */
        else
        {
            if (start + 6 >= size) return false;
            js[start] = '\\'; start++;
            js[start] = 'u'; start++;
            js[start] = '0'; start++;
            js[start] = '0'; start++;
            snprintf(&js[start], 3, "%02X", (uint8_t)*in);
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
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '\"')) return false;
    if (!SSFJsonPrintCString(js, size, start, &start, in, false)) return false;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '\"')) return false;
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
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintString(js, size, start, &start, in, false)) return false;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, ':')) return false;
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
    SSF_REQUIRE(inLen >= 0);
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    if (!SSFHexBinToBytes(in, inLen, &js[start], size - start, &outLen, rev, SSF_HEX_CASE_UPPER))
    {return false; }
    start += outLen;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in data added successfully as quoted Base64 string, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintBase64(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                        const uint8_t *in, size_t inLen, bool *comma)
{
    size_t outLen;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    if (!SSFBase64Encode(in, inLen, &js[start], size - start, &outLen)) return false;
    start += outLen;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
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
    int len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(fmt < SSF_JSON_FLT_FMT_MAX);
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    if (fmt == SSF_JSON_FLT_FMT_SHORT) len = snprintf(&js[start], size - start, "%g", in);
    else if (fmt == SSF_JSON_FLT_FMT_STD) len = snprintf(&js[start], size - start, "%f", in);
    else
    {
        char fstr[] = "%.0f";
        fstr[2] = (char)(fmt + '0');
        len = snprintf(&js[start], size - start, fstr, in);
    }
    if ((len < 0) || (((size_t)len) >= (size - start))) return false;
    *end = start + len;
    return true;
}
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in signed int added successfully to JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end, int32_t in,
                     bool *comma)
{
    int len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    len = snprintf(&js[start], size - start, "%d", in);
    if ((len < 0) || (((size_t)len) >= (size - start))) return false;
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in unsigned int added successfully to JSON string, else false.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintUInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end, uint32_t in,
                      bool *comma)
{
    int len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    len = snprintf(&js[start], size - start, "%u", in);
    if ((len < 0) || (((size_t)len) >= (size - start))) return false;
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
    SSF_REQUIRE((comma == NULL) || (comma != (bool *)true));

    SSF_JSON_COMMA(comma);
    if ((oc != NULL) && (!SSFJsonPrintUnescChar(js, size, start, &start, oc[0]))) return false;
    if ((fn != NULL) && (!fn(js, size, start, &start, in))) return false;
    if ((oc != NULL) && (!SSFJsonPrintUnescChar(js, size, start, &start, oc[1]))) return false;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, 0)) return false;
    *end = start - 1;
    return true;
}

#if SSF_JSON_CONFIG_ENABLE_UPDATE == 1
/* --------------------------------------------------------------------------------------------- */
/* Printer function for SSFJsonUpdate() when adding paths is required.                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonUpdateAddPath(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                                  void *in)
{
    SSFJSONAddPath_t *ap = (SSFJSONAddPath_t *)in;

    SSF_REQUIRE(in != NULL);

    if (ap->path[ap->depth] != NULL)
    {
        if (!SSFJsonPrintLabel(js, size, start, &start, ap->path[ap->depth], false))
        {return false; }
        ap->depth++;
        if (ap->path[ap->depth] == NULL)
        {
            if (!SSFJsonPrint(js, size, start, &start, _SSFJsonUpdateAddPath, ap, NULL, false))
            {return false; }
        } else
        {
            if (!SSFJsonPrintObject(js, size, start, &start, _SSFJsonUpdateAddPath, ap, false))
            {return false; }
        }
    } else ap->fn(js, size, start, &start, NULL);
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if field value updated, object path created as needed, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonUpdate(SSFCStrOut_t js, size_t size, SSFCStrIn_t *path, SSFJsonPrintFn_t fn)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;
    size_t len;
    char *path2[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
    uint8_t i;
    size_t startn;
    SSFJSONAddPath_t ap;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_JSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(fn != NULL);

    memcpy(path2, path, sizeof(path2));
    do
    {
        if (!SSFJsonObject(js, &index, &start, &end, path2, 0, &jt)) return false;
        if (jt != SSF_JSON_TYPE_ERROR) break;
        for (i = SSF_JSON_CONFIG_MAX_IN_DEPTH; (path2[i] == NULL) && (i >= 1); i--);
        path2[i] = NULL;
    } while (jt == SSF_JSON_TYPE_ERROR);

    if (memcmp(path, path2, sizeof(path2)) == 0)
    {
        size_t end2;

        /* Exact match to request, updated existing value */
        len = strlen(js);
        memmove(&js[size - len + end], &js[end + 1], len - end);
        if (!fn(&js[start], size - len - end, 0, &end2, &jt)) return false;
        memmove(&js[start + end2], &js[size - len + end], len - end);
        return true;
    }
    /* Not exact match to request, create missing path */
    if (jt != SSF_JSON_TYPE_OBJECT) return false;

    for (ap.depth = 0; (path2[ap.depth] != NULL) && (ap.depth <= SSF_JSON_CONFIG_MAX_IN_DEPTH);
         ap.depth++);
    len = strlen(js);
    startn = start + 1;
    end = end + 1;
    ap.fn = fn;
    ap.path = path;
    memmove(&js[size - len], &js[start + 1], len);
    if (!SSFJsonPrint(js, size - len - 1, startn, &end, _SSFJsonUpdateAddPath, &ap, NULL, false))
    {return false; }
    index = size - len;
    SSFJsonWhitespace(js, &index);
    if ((js[index] != '}') && (!SSFJsonPrintUnescChar(js, size - len - 1, end, &end, ',')))
    { return false; }
    memmove(&js[start + (end - startn + 1)], &js[size - len], len);
    return true;
}
#endif

