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
#include <stdio.h>
#include <math.h> /* round() */
#include "ssfsm.h"
#include "ssfll.h"
#include "ssfmpool.h"
#include "ssfjson.h"
#include "ssfbase64.h"
#include "ssfhex.h"

// #define to enable/disable float support.
// more pedandtic number parsing, reenable test cases that are commented out
// use _ for static vars and functions
// add somple format specifiers for float printing.
// update needs to be able to add non-existant field
// return error if get int or uint would overflow

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define SSFJsonIsEsc(e) (((e) == '"') || ((e) == '\\') || ((e) == '/') || ((e) == 'b') || \
                         ((e) == 'f') || ((e) == 'n') || ((e) == 'r') || ((e) == 't') || \
                         ((e) == 'u'))
#define SSFJsonEsc(j, b) do { j[start] = '\\'; start++; if (start >= size) return false; \
                              j[start] = b;} while (0)
#define SSF_JSON_COMMA(c) do { \
    if (((c) && (*c)) && (!SSFJsonPrintUnescChar(js, size, start, &start, ','))) return false; \
    if (c) *c = true; } while (0);

/* --------------------------------------------------------------------------------------------- */
/* Local prototypes                                                                              */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonValue(const char* js, size_t* index, size_t*start, size_t*end, const char **path, 
                         uint8_t depth, SSFJsonType_t* jt);

/* --------------------------------------------------------------------------------------------- */
/* Increments index past whitespace in JSON string                                               */
/* --------------------------------------------------------------------------------------------- */
static void SSFJsonWhitespace(const char *js, size_t*index)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);

    while ((js[*index] == ' ') || (js[*index] == '\n') || (js[*index] == '\r') || 
           (js[*index] == '\t')) (*index)++;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if number found in JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonNumber(const char *js, size_t*index, size_t*start, size_t *end)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);

    if ((js[*index] != '-') && !((js[*index] >= '0') && (js[*index] <= '9'))) return false;
    *start = *index;
    (*index)++;    
    while (true)
    {
        if ((js[*index] == '-') || ((js[*index] >= '0') && (js[*index] <= '9')) ||
            (js[*index] == 'e') || (js[*index] == 'E') || (js[*index] == '+') ||
            (js[*index] == '.')) { (*index)++; }
        else break;
    }
    *end = *index - 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and start/end index if string found, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonString(const char *js, size_t *index, size_t *start, size_t *end)
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
            if (js[*index] != 'u') { (*index)++; continue; }
            (*index)++;
            if (!SSFIsHex(js[*index])) return false;
            if (!SSFIsHex(js[(*index) + 1])) return false;
            if (!SSFIsHex(js[(*index) + 2])) return false;
            if (!SSFIsHex(js[(*index) + 3])) return false;
            (*index) += 4;
        }
        else (*index)++;
    }
    if (js[*index] != '"') return false;
    *end = (*index);
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if array found, else false; If true returns type/start/end on path index match.  */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonArray(const char* js, size_t* index, size_t* start, size_t* end, const char **path,
                         uint8_t depth, SSFJsonType_t* jt)
{
    size_t valStart;
    size_t valEnd;
    size_t curIndex = 0;
    size_t pindex = (size_t) -1;
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

    if (js[*index] != ']')
    {
        if (path != NULL && path[depth] != NULL) pindex = *((const size_t *)path[depth]);
        while (SSFJsonValue(js, index, &valStart, &valEnd, path, depth, &djt) == true)
        {
            if (pindex == curIndex) { *start = valStart; *end = valEnd; *jt = djt; }
            SSFJsonWhitespace(js, index);
            if (js[*index] == ']') break;
            if (js[*index] != ',') return false;
            (*index)++;
            curIndex++;
        }
        if ((pindex != -1) && (pindex > curIndex)) *jt = SSF_JSON_TYPE_ERROR;
        if (js[*index] != ']') return false;
    }
    if (path != NULL && path[depth] == NULL) { *end = *index; *jt = SSF_JSON_TYPE_ARRAY; }
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value found, else false; If true returns type/start/end on path match.        */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonValue(const char* js, size_t* index, size_t* start, size_t* end, const char **path,
                         uint8_t depth, SSFJsonType_t* jt)
{
    size_t i;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(depth >= 0);
    SSF_REQUIRE(jt != NULL);

    SSFJsonWhitespace(js, index); i = *index;
    if (SSFJsonString(js, &i, start, end)) { *jt = SSF_JSON_TYPE_STRING; goto VALRET; } i = *index;
    if (SSFJsonObject(js, &i, start, end, path, depth + 1, jt)) { goto VALRET; } i = *index;
    if (SSFJsonArray(js, &i, start, end, path, depth + 1, jt)) { goto VALRET; } i = *index;
    if (SSFJsonNumber(js, &i, start, end)) { *jt = SSF_JSON_TYPE_NUMBER; goto VALRET; } i = *index;
    if (strncmp(&js[i], "true", 4) == 0) 
    { *jt = SSF_JSON_TYPE_TRUE; *start = i; i += 4; *end = i - 1; goto VALRET; } i = *index;
    if (strncmp(&js[i], "false", 5) == 0)
    { *jt = SSF_JSON_TYPE_FALSE; *start = i; i += 5; *end = i - 1; goto VALRET; } i = *index;
    if (strncmp(&js[i], "null", 4) == 0)
    { *jt = SSF_JSON_TYPE_NULL; *start = i; i += 4; *end= i - 1; goto VALRET; }
    return false;

VALRET:
    *index = i;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/value found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool SSFJsonNameValue(const char* js, size_t* index, size_t* start, size_t* end, const char **path,
                             uint8_t depth, SSFJsonType_t* jt)
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
                 MAX(valEnd - valStart - 1, (int) strlen(path[depth]))) == 0))
    { return SSFJsonValue(js, index, start, end, path, depth, jt); }
    else return SSFJsonValue(js, index, &valStart, &valEnd, NULL, 0, &djt);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object found, else false; If true returns type/start/end on path match.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonObject(const char *js, size_t *index, size_t *start, size_t *end, const char** path,
                          uint8_t depth, SSFJsonType_t* jt)
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
    { *end = *index; *jt = SSF_JSON_TYPE_OBJECT; }
    (*index)++;
    if (depth == 0) { SSFJsonWhitespace(js, index); if (js[*index] != 0) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if JSON string is valid, else false.                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonIsValid(const char *js)
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
SSFJsonType_t SSFJsonGetType(const char *js, const char **path)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) jt = SSF_JSON_TYPE_ERROR;
    return jt;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is unescaped completely into buffer w/NULL term., else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetString(const char* js, const char **path, char* out, size_t outSize, size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    size_t len;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
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
            { out[index] = js[start]; }
            else if (js[start] == 'n') out[index] = '\x0a';
            else if (js[start] == 'r') out[index] = '\x0d';
            else if (js[start] == 't') out[index] = '\x09';
            else if (js[start] == 'f') out[index] = '\x0c';
            else if (js[start] == 'b') out[index] = '\x08';
            else if (js[start] != 'u') return false;

            start++; len--;
            if (len < 4) return false;
            if (index >= (outSize - 1 - 2)) return false;

            if (!SSFHexByteToBin(js[start], js[start + 1], &out[index])) return false;
            index++;
            if (!SSFHexByteToBin(js[start + 2], js[start + 3], &out[index])) return false;
            start += 3; len -= 3;
        }
        else out[index] = js[start];
        start++; index++; len--;
    }
    if (index < outSize) out[index] = 0;
    return len == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to double, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetDouble(const char* js, const char** path, double* out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFJsonType_t jt;
    char* endptr;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
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
bool SSFJsonGetInt(const char* js, const char **path, int32_t *out)
{
    double dout;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFJsonGetDouble(js, path, &dout)) return false;
    *out = (int32_t) round(dout);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to unsigned int, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetUInt(const char* js, const char** path, uint32_t* out)
{
    double dout;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFJsonGetDouble(js, path, &dout)) return false;
    if (dout < 0) return false;
    *out = (uint32_t) round(dout);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and completely converted to binary data, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetHex(const char* js, const char** path, uint8_t* out, size_t outSize, size_t *outLen,
                   bool rev)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;
    size_t i;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    start++; end--;

    if ((end - start + 1) & 0x01) return false; /* Odd number len string */
    *outLen = (end - start + 1) >> 1;
    if (outSize < (*outLen)) return false; /* Buffer too small */

    for (i = 0; i < *outLen; i++)
    {
        if (rev)
        { 
            if (!SSFHexByteToBin(js[end - (i << 1) - 1], js[end - (i << 1)], &out[i]))
            { return false; }
        }
        else 
        { 
            if (!SSFHexByteToBin(js[start + (i << 1)], js[start + (i << 1) + 1], &out[i])) 
            { return false; } 
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found, entire decode successful, and outLen updated, else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonGetBase64(const char* js, const char** path, uint8_t* out, size_t outSize, size_t* outLen)
{
    size_t start;
    size_t end;
    size_t index;
    SSFJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
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
static bool SSFJsonPrintUnescChar(char* js, size_t size, size_t start, size_t* end, const char in)
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
bool SSFJsonPrintCString(char* js, size_t size, size_t start, size_t *end, const char* in, bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

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
        { js[start] = *in; } /* Normal ASCII character */
        else
        {
            if (start + 6 >= size) return false;
            js[start] = '\\'; start++;
            js[start] = 'u'; start++;
            js[start] = '0'; start++;
            js[start] = '0'; start++;
            snprintf(&js[start], 3, "%02X", (uint8_t) *in);
            start++;
        }
        if (*in == 0) { *end = start; return true; }
        start++;
        in++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in string added successfully as quoted escaped string, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintString(char* js, size_t size, size_t start, size_t* end, const char* in, bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

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
bool SSFJsonPrintLabel(char* js, size_t size, size_t start, size_t* end, const char* in, bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintString(js, size, start, &start, in, false)) return false;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, ':')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in data added successfully as quoted ASCII hex string, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintHex(char* js, size_t size, size_t start, size_t* end, const uint8_t * in, size_t inLen,
                           bool rev, bool *comma)
{
    uint8_t hex[3] = "  ";

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(inLen >= 0);
    SSF_REQUIRE((comma == NULL) || (comma != (bool *) true));

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    while (inLen--)
    {
        if (rev) snprintf(hex, sizeof(hex), "%02X", (unsigned int) in[inLen]);
        else { snprintf(hex, sizeof(hex), "%02X", *in); in++; }
        if (!SSFJsonPrintCString(js, size, start, &start, hex, false)) return false;
    }
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in data added successfully as quoted Base64 string, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintBase64(char* js, size_t size, size_t start, size_t* end, const uint8_t* in,
                              size_t inLen, bool *comma)
{
    size_t outLen;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

    SSF_JSON_COMMA(comma);
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    if (!SSFBase64Encode(in, inLen, &js[start], size - start, &outLen)) return false;
    start += outLen;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, '"')) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in double added successfully to JSON string, else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintDouble(char* js, size_t size, size_t start, size_t* end, double in, bool *comma)
{
    int len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

    SSF_JSON_COMMA(comma);
    len = snprintf(&js[start], size - start, "%g", in);
    if ((len < 0) || (((size_t) len) >= (size - start))) return false;
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in signed int added successfully to JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintInt(char* js, size_t size, size_t start, size_t* end, int32_t in, bool *comma)
{
    int len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

    SSF_JSON_COMMA(comma);
    len = snprintf(&js[start], size - start, "%d", in);
    if ((len < 0) || (((size_t)len) >= (size - start))) return false;
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in unsigned int added successfully to JSON string, else false.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrintUInt(char* js, size_t size, size_t start, size_t* end, uint32_t in, bool *comma)
{
    int len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

    SSF_JSON_COMMA(comma);
    len = snprintf(&js[start], size - start, "%u", in);
    if ((len < 0) || (((size_t)len) >= (size - start))) return false;
    *end = start + len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all printing added successfully to JSON string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonPrint(char* js, size_t size, size_t start, size_t* end, SSFJsonPrintFn_t fn, void *in,
                    const char *oc, bool *comma)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE((comma == NULL) || (comma != (bool*)true));

    SSF_JSON_COMMA(comma);
    if ((oc != NULL) && (!SSFJsonPrintUnescChar(js, size, start, &start, oc[0]))) return false;
    if ((fn != NULL) && (!fn(js, size, start, &start, in))) return false;
    if ((oc != NULL) && (!SSFJsonPrintUnescChar(js, size, start, &start, oc[1]))) return false;
    if (!SSFJsonPrintUnescChar(js, size, start, &start, 0)) return false;
    *end = start - 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value of an existing field is updated successfully, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFJsonUpdate(char* js, size_t size, const char** path, SSFJsonPrintFn_t fn)
{
    size_t start;
    size_t end;
    size_t end2;
    size_t index;
    SSFJsonType_t jt;
    size_t len;

    if (!SSFJsonObject(js, &index, &start, &end, path, 0, &jt)) return false;
    if (jt == SSF_JSON_TYPE_ERROR) return false;
    len = strlen(js);
    memmove(&js[size - len + end], &js[end + 1], len - end);
    if (!fn(&js[start], size - len - end, 0, &end2, &jt)) return false;
    memmove(&js[start + end2], &js[size - len + end], len - end);
    return true;
}
