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
#include "ssfport.h"
#include "ssfubjson.h"
#include "ssfhex.h"

/* TODO - Address NOOP type */
/* TODO - Address CHAR type, 1 byte STRING */
/* TODO - Address code duplication with SSFJsonEsc */
/* TODO - Address code duplication with escape sequence processing */
/* TODO - Reduce code duplication in GetInt*() functions */
/* TODO - Add printer for float and double */
/* TODO - Add printer for ASCII Hex and Base64 */
/* TODO - Add decoders for ASCII Hex and Base64 */
/* TODO - Anything to do to cleanly not support HPNs? */
/* TODO - Parse optimized formatting. */
/* TODO - Print optimized array formatting. */
/* TODO - Generate dynamic data struct from parse. */
/* TODO - Update data struct interface */
/* TODO - Print data struct */
/* TODO - Write more unit tests */

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
#define UBJ_TYPE_STRING 'S'
#define UBJ_TYPE_OBJ_OPEN '{'
#define UBJ_TYPE_ARRAY_OPEN '['
#define UBJ_TYPE_ARRAY_OPT '$'
#define UBJ_TYPE_ARRAY_NUM '#'

// dup?
#define SSFJsonEsc(j, b) do { j[start] = '\\'; start++; if (start >= size) return false; \
                              j[start] = b;} while (0)

static bool _SSFUBJsonValue(uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                            SSFCStrIn_t *path, uint8_t depth, SSFUBJsonType_t *jt);

/* --------------------------------------------------------------------------------------------- */
/* Returns true if array found, else false; If true returns type/start/end on path index match.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonArray(uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                            size_t *astart, size_t *aend, SSFCStrIn_t *path, uint8_t depth,
                            SSFUBJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    size_t curIndex = 0;
    size_t pindex = (size_t)-1;
    SSFUBJsonType_t djt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(astart != NULL);
    SSF_REQUIRE(aend != NULL);
    SSF_REQUIRE(depth >= 1);
    SSF_REQUIRE(jt != NULL);

    if (depth >= SSF_UBJSON_CONFIG_MAX_IN_DEPTH) return false;
    if (js[*index] != '[') return false;
    *astart = *index;
    if ((path != NULL) && (path[depth] == NULL)) *start = *index;
    (*index)++; /*jlh added => */ if (*index >= jsLen) return false;

    if ((path != NULL) && (path[depth] != NULL)) memcpy(&pindex, path[depth], sizeof(size_t));

    while (_SSFUBJsonValue(js, jsLen, index, &valStart, &valEnd, path, depth, &djt) == true)
    {
        /* Emitter("array", &js[valStart], valEnd - valStart, djt); */
        if (pindex == curIndex)
        {
            *start = valStart; *end = valEnd; *jt = djt;
        }
        if (js[*index] == ']') break;
        curIndex++;
    }
    if ((pindex != (size_t)-1) && (pindex > curIndex)) *jt = SSF_UBJSON_TYPE_ERROR;
    if (js[*index] != ']') return false;
    *aend = *index;

    if ((path != NULL) && (path[depth] == NULL))
    {*end = *index; *jt = SSF_UBJSON_TYPE_ARRAY; }
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if type field found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonTypeField(uint8_t *js, size_t jsLen, size_t *index, size_t *fstart,
                              size_t *fend, SSFUBJsonType_t *fjt)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(fstart != NULL);
    SSF_REQUIRE(fend != NULL);
    SSF_REQUIRE(fjt != NULL);

    switch (js[*index])
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
        *fjt = SSF_UBJSON_TYPE_NUMBER_CHAR; len = sizeof(uint8_t);
        goto _ssfubParseInt;
    case UBJ_TYPE_UINT8:
        *fjt = SSF_UBJSON_TYPE_NUMBER_UINT8; len = sizeof(uint8_t);
        goto _ssfubParseInt;
    case UBJ_TYPE_INT8:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT8; len = sizeof(int8_t);

    _ssfubParseInt:
        (*index)++; if (*index >= jsLen) return false;
        *fstart = *index;
        (*index) += len; if (*index >= jsLen) return false;
        *fend = *index;
        return true;
    case UBJ_TYPE_STRING:
        {
            size_t tstart;
            size_t tend;
            SSFUBJsonType_t tjt;

            (*index)++; if (*index >= jsLen) return false;
            if (_SSFJsonTypeField(js, jsLen, index, &tstart, &tend, &tjt) == false) return false;
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
            (*index) += len; if (*index >= jsLen) return false;
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
        (*index)++; if (*index >= jsLen) return false;
        *fstart = *index;
        *fend = *fstart;
        return true;
    default:
        break;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value found, else false; If true returns type/start/end on path match.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonValue(uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                            SSFCStrIn_t *path, uint8_t depth, SSFUBJsonType_t *jt)
{
    size_t i;
    size_t astart;
    size_t aend;
    size_t oend;
    size_t ostart;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    /* Attempt to parse value field */
    if (_SSFJsonTypeField(js, jsLen, index, start, end, jt) == false)
    {return false; }

    i = *index;
    switch (*jt)
    {
    case SSF_UBJSON_TYPE_OBJECT:
        if (SSFUBJsonObject(js, jsLen, &i, start, end, &ostart, &oend, path, depth + 1, jt))
        { *index = i; return true; }
        break;
    case SSF_UBJSON_TYPE_ARRAY:
        if (_SSFUBJsonArray(js, jsLen, &i, start, end, &astart, &aend, path, depth + 1, jt))
        {
            *start = astart;
            *end = i;
            *index = i; return true;
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
        *index = i; return true;
    default:
        break;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/value found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNameValue(uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                              SSFCStrIn_t *path, uint8_t depth, SSFUBJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    size_t fstart;
    size_t fend;
    size_t len;
    SSFUBJsonType_t fjt;
    SSFUBJsonType_t djt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    /* Attempt to parse name field */
    if (_SSFJsonTypeField(js, jsLen, index, &fstart, &fend, &fjt) == false) return false;
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

    /* Is path set and do we have a match? */
    if ((path != NULL) && (path[depth] != NULL) &&
        (strncmp(path[depth], (char *)&js[fstart],
                 SSF_MAX(fend - fstart, (size_t)strlen(path[depth]))) == 0))
    {
        /* Yes, keep matching */
        return _SSFUBJsonValue(js, jsLen, index, start, end, path, depth, jt);
    }
    else
    {
        /* No, keep parsing */
        return _SSFUBJsonValue(js, jsLen, index, &valStart, &valEnd, NULL, 0, &djt);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object found, else false; If true returns type/start/end on path match.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonObject(uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                     size_t *ostart, size_t *oend, SSFCStrIn_t *path, uint8_t depth, SSFUBJsonType_t *jt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(ostart != NULL);
    SSF_REQUIRE(oend != NULL);
    SSF_REQUIRE(jt != NULL);
    SSF_REQUIRE((path == NULL) || (path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL));

    if (depth == 0)
    {
        if (jsLen > SSF_UBJSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_UBJSON_TYPE_ERROR;
        *index = 0;
    }
    if (depth >= SSF_UBJSON_CONFIG_MAX_IN_DEPTH) return false;

    if (js[*index] != '{') return false;
    *ostart = *index;
    if ((depth != 0) || ((depth == 0) && (path != NULL) && (path[0] == NULL))) *start = *index;
    (*index)++; if (*index >= jsLen) return false;

    if (js[*index] != '}')
    {
        if (!_SSFJsonNameValue(js, jsLen, index, start, end, path, depth, jt)) return false;
        do
        {
            if (js[*index] == '}') break;
            if (!_SSFJsonNameValue(js, jsLen, index, start, end, path, depth, jt)) return false;
        } while (true);
        if (js[*index] != '}') return false;
        (*index)++;
    }
    else
    {
        (*index)++; *end = *index; *jt = SSF_UBJSON_TYPE_OBJECT;
    }
    *oend = *index;
    if (((path != NULL) && (path[depth] == NULL)) ||
        ((depth == 0) && (path != NULL) && (path[0] == NULL)))
    {
        *end = *index; *jt = SSF_UBJSON_TYPE_OBJECT;
    }
    /* If not at end of object then consider it not valid */
    if ((depth == 0) && (*index != jsLen)) return false;
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
    size_t ostart;
    size_t oend;
    SSFUBJsonType_t jt;
    char *path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(js != NULL);

    memset(path, 0, sizeof(path));
    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, (SSFCStrIn_t *)path, 0,
                         &jt)) return false;
    return jt != SSF_UBJSON_TYPE_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SSF_JSON_TYPE_ERROR if JSON string is invalid or path not found, else valid type.     */
/* --------------------------------------------------------------------------------------------- */
SSFUBJsonType_t SSFUBJsonGetType(uint8_t *js, size_t jsLen, SSFCStrIn_t *path)
{
    size_t start;
    size_t end;
    size_t ostart;
    size_t oend;
    size_t index;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(path != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt))
    { jt = SSF_UBJSON_TYPE_ERROR; }
    return jt;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is unescaped completely into buffer w/NULL term., else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetString(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, SSFCStrOut_t out,
                        size_t outSize, size_t *outLen)
{
    size_t start;
    size_t end;
    size_t oend;
    size_t ostart;
    size_t index;
    size_t len;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_STRING) return false;
    end--;

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
            {
                out[index] = js[start];
            }
            else if (js[start] == 'n') //jlh bug in json parser!
            { out[index] = '\x0a'; goto nextesc; }
            else if (js[start] == 'r')
            { out[index] = '\x0d'; goto nextesc; }
            else if (js[start] == 't')
            { out[index] = '\x09'; goto nextesc; }
            else if (js[start] == 'f')
            { out[index] = '\x0c'; goto nextesc; }
            else if (js[start] == 'b')
            { out[index] = '\x08'; goto nextesc; }
            else if (js[start] != 'u') return false;

            if (outLen != NULL) (*outLen)++;
            start++; len--;
            if (len < 4) return false;
            if (index >= (outSize - 1 - 2)) return false;
            if (!SSFHexByteToBin((char *)&js[start], (uint8_t *)&out[index])) return false;
            index++;
            if (!SSFHexByteToBin((char *)&js[start + 2], (uint8_t *)&out[index])) return false;
            start += 3; len -= 3;
        }
        else
        {out[index] = js[start]; }
    nextesc:
        if (outLen != NULL) (*outLen)++;
        start++; index++; len--;
    }
    if (index < outSize) out[index] = 0;
    return len == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to float, else false.                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetFloat(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, float *out)
{
    size_t index;
    size_t start;
    size_t end;
    size_t oend;
    size_t ostart;
    SSFUBJsonType_t jt;
    uint32_t u32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt))
    { return false; }
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
bool SSFUBJsonGetDouble(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, double *out)
{
    size_t index;
    size_t start;
    size_t end;
    size_t oend;
    size_t ostart;
    SSFUBJsonType_t jt;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt)) return false;
    if (jt != SSF_UBJSON_TYPE_NUMBER_FLOAT64) return false;
    if ((end - start) != sizeof(u64)) return false;
    memcpy(&u64, &js[start], sizeof(u64));
    u64 = ntohll(u64);
    memcpy(out, &u64, sizeof(double));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt8(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int8_t *out)
{
    size_t index;
    size_t start;
    size_t oend;
    size_t ostart;
    size_t end;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT8) return false;
    if ((end - start) != sizeof(int8_t)) return false;
    *out = (int8_t)js[start];
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetUInt8(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out)
{
    size_t index;
    size_t start;
    size_t oend;
    size_t ostart;
    size_t end;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_UINT8) return false;
    if ((end - start) != sizeof(uint8_t)) return false;
    *out = js[start];
    return true;
}
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt16(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int16_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    size_t ostart;
    size_t oend;
    SSFUBJsonType_t jt;
    uint16_t u16;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt)) return false;
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT16) return false;
    if ((end - start) != sizeof(u16)) return false;
    memcpy(&u16, &js[start], sizeof(u16));
    u16 = ntohs(u16);
    *out = (int16_t)u16;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt32(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int32_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    size_t ostart;
    size_t oend;
    SSFUBJsonType_t jt;
    uint32_t u32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT32) return false;
    if ((end - start) != sizeof(u32)) return false;
    memcpy(&u32, &js[start], sizeof(u32));
    u32 = ntohl(u32);
    *out = (int32_t)u32;
    return true;
}
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt64(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int64_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    size_t ostart;
    size_t oend;
    SSFUBJsonType_t jt;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(js, jsLen, &index, &start, &end, &ostart, &oend, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT64) return false;
    if ((end - start) != sizeof(u64)) return false;
    memcpy(&u64, &js[start], sizeof(u64));
    u64 = ntohll(u64);
    *out = (int64_t)u64;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if char added to js, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintUnescChar(uint8_t *js, size_t size, size_t start, size_t *end, const char in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (start >= size) return false;
    js[start] = in;
    *end = start + 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all printing added successfully to JSON string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrint(uint8_t *js, size_t jsSize, size_t start, size_t *end, SSFUBJsonPrintFn_t fn,
                    void *in, const char *oc)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= jsSize);
    SSF_REQUIRE(end != NULL);

    if ((oc != NULL) && (!SSFUBJsonPrintUnescChar(js, jsSize, start, &start, oc[0]))) return false;
    if ((fn != NULL) && (!fn(js, jsSize, start, &start, in))) return false;
    if ((oc != NULL) && (!SSFUBJsonPrintUnescChar(js, jsSize, start, &start, oc[1]))) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in string added successfully as escaped string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintCString(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t in)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    len = strlen(in);

    /* Only support strings up to 255 bytes */
    if (len > 256) return false;

    /* Always use uint8_t as type for string length */
    js[start] = 'U'; start++; if (start >= size) return false;
    js[start] = (uint8_t)len; start++; if (start >= size) return false;

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
        {
            js[start] = *in;
        } /* Normal ASCII character */
        else
        {
            if (start + 6 >= size) return false;
            js[start] = '\\'; start++;
            js[start] = 'u'; start++;
            js[start] = '0'; start++;
            js[start] = '0'; start++;
            snprintf((char *)&js[start], 3, "%02X", (uint8_t)*in);
            start++;
        }
        if (*in == 0)
        {
            *end = start; return true;
        }
        start++;
        in++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in string added successfully as quoted escaped string, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintString(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    if (!SSFUBJsonPrintUnescChar(js, size, start, &start, 'S')) return false;
    if (!SSFUBJsonPrintCString(js, size, start, &start, in)) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in label added successfully as escaped string, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintLabel(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t label)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(label != NULL);

    if (label[0] == 0) return false;
    return SSFUBJsonPrintCString(js, size, start, end, label);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in signed int added successfully to JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintInt(uint8_t *js, size_t size, size_t start, size_t *end, int64_t in)
{
    uint8_t type;
    size_t len;
    uint8_t *pi;
    int8_t i8;
    uint8_t ui8;
    int16_t i16;
    int32_t i32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);

    if (in < 128l) type = UBJ_TYPE_INT8;
    else if (in < 256l) type = UBJ_TYPE_UINT8;
    else if (in < 32768l) type = UBJ_TYPE_INT16;
    else if (in < 2147483648ll) type = UBJ_TYPE_INT32;
    else type = UBJ_TYPE_INT64;

    if (!SSFUBJsonPrintUnescChar(js, size, start, &start, type)) return false;
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
        in = htonll(in); pi = (uint8_t *)&in; len = sizeof(in);
        break;
    default:
        SSF_ERROR();
    };
    if ((start + len) >= size) return false;
    memcpy(&js[start], pi, len);
    *end = start + len;
    return true;
}
