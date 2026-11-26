/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhttphdr.c                                                                                  */
/* Builds HTTP/1.1 request heads and parses response heads (RFC 9112); no I/O.                   */
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfhttphdr.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_HTTP_HDR_VERSION_TEXT        " HTTP/1.1\r\n"
#define SSF_HTTP_HDR_HOST_TEXT           "Host: "
#define SSF_HTTP_HDR_STATUS_LINE_MIN     (12u)          /* "HTTP/x.y nnn" */
#define SSF_HTTP_HDR_PORT_TEXT_MAX       (6u)           /* ":65535" */

/* Response parser states */
typedef enum
{
    SSF_HTTP_HDR_ST_STATUS,          /* Fixed-position "HTTP/x.y nnn" */
    SSF_HTTP_HDR_ST_STATUS_END,      /* After the code: SP then reason, or CR */
    SSF_HTTP_HDR_ST_REASON,
    SSF_HTTP_HDR_ST_LINE_START,      /* Start of a field line, or the empty line */
    SSF_HTTP_HDR_ST_NAME,
    SSF_HTTP_HDR_ST_VALUE,
    SSF_HTTP_HDR_ST_LF,              /* CR seen; LF must follow */
    SSF_HTTP_HDR_ST_END_LF           /* CR of the empty line seen */
} SSFHTTPHdrState_t;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if c is a tchar (RFC 9110 5.6.2).                                                */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsTChar(uint8_t c)
{
    if (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9')))
    { return true; }
    return (c != 0) && (memchr("!#$%&'*+-.^_`|~", c, 15) != NULL);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if c may appear in a field value or reason phrase: HTAB, SP, VCHAR, obs-text.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsValueChar(uint8_t c)
{
    return (c == '\t') || ((c >= 0x20u) && (c != 0x7Fu));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if c is a hex digit.                                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsHex(uint8_t c)
{
    return ((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the lower case of an ASCII letter, else c.                                            */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFHTTPHdrLower(uint8_t c)
{
    return ((c >= 'A') && (c <= 'Z')) ? (uint8_t)(c + ('a' - 'A')) : c;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a[0..aLen) equals bStr, ASCII case-insensitively if isCI.                     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrEquals(const uint8_t *a, size_t aLen, SSFCStrIn_t bStr, bool isCI)
{
    size_t i;

    SSF_REQUIRE((a != NULL) || (aLen == 0));
    SSF_REQUIRE(bStr != NULL);

    for (i = 0; i < aLen; i++)
    {
        uint8_t cb = (uint8_t)bStr[i];

        if (cb == 0) return false;
        /* Case-insensitive compare? */
        if (isCI)
        {
            /* Yes, compare lower-cased bytes */
            if (_SSFHTTPHdrLower(a[i]) != _SSFHTTPHdrLower(cb)) return false;
        }
        else
        {
            /* No, compare exact bytes */
            if (a[i] != cb) return false;
        }
    }
    return (bStr[aLen] == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with *lenOut set to the length of textStr if NUL is within textSize, else false. */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrLen(SSFCStrIn_t textStr, size_t textSize, size_t *lenOut)
{
    SSF_REQUIRE(textStr != NULL);
    SSF_REQUIRE(lenOut != NULL);

    return SSFStrLen(textStr, textSize, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if textStr[0..textLen) is a non-empty token.                                     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsToken(SSFCStrIn_t textStr, size_t textLen)
{
    size_t i;

    SSF_REQUIRE(textStr != NULL);

    if (textLen == 0) return false;
    for (i = 0; i < textLen; i++)
    { if (_SSFHTTPHdrIsTChar((uint8_t)textStr[i]) == false) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if textStr[0..textLen) is a non-empty request target with valid %XX escapes.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsTarget(SSFCStrIn_t textStr, size_t textLen)
{
    size_t i;

    SSF_REQUIRE(textStr != NULL);

    if (textLen == 0) return false;
    for (i = 0; i < textLen; i++)
    {
        uint8_t c = (uint8_t)textStr[i];

        /* Start of a percent escape? */
        if (c == '%')
        {
            /* Yes, two hex digits must follow */
            if ((i + 2u) >= textLen) return false;
            if ((_SSFHTTPHdrIsHex((uint8_t)textStr[i + 1u]) == false) ||
                (_SSFHTTPHdrIsHex((uint8_t)textStr[i + 2u]) == false))
            { return false; }
            i += 2u;
            continue;
        }
        if (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9')))
        { continue; }
        if ((c == 0) || (memchr("-._~:/?[]@!$&'()*+,;=", c, 21) == NULL)) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if textStr[0..textLen) is a non-empty host: letters, digits, '-', '.', '_', '~'. */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsHost(SSFCStrIn_t textStr, size_t textLen)
{
    size_t i;

    SSF_REQUIRE(textStr != NULL);

    if (textLen == 0) return false;
    for (i = 0; i < textLen; i++)
    {
        uint8_t c = (uint8_t)textStr[i];

        if (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9')))
        { continue; }
        if ((c != '-') && (c != '.') && (c != '_') && (c != '~')) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if textStr[0..textLen) is a field value, maybe empty, with no edge whitespace.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsValue(SSFCStrIn_t textStr, size_t textLen)
{
    size_t i;

    SSF_REQUIRE(textStr != NULL);

    if (textLen == 0) return true;
    if ((textStr[0] == ' ') || (textStr[0] == '\t') || (textStr[textLen - 1u] == ' ') ||
        (textStr[textLen - 1u] == '\t'))
    { return false; }
    for (i = 0; i < textLen; i++)
    { if (_SSFHTTPHdrIsValueChar((uint8_t)textStr[i]) == false) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends srcLen bytes of src at buf[*posInOut]; caller has checked they fit.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHTTPHdrPut(uint8_t *buf, size_t *posInOut, const void *src, size_t srcLen)
{
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(posInOut != NULL);
    SSF_REQUIRE((src != NULL) || (srcLen == 0));

    memcpy(&buf[*posInOut], src, srcLen);
    *posInOut += srcLen;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the request line and Host field written at buf[0], else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrReqBegin(uint8_t *buf, size_t bufSize, size_t *lenOut, SSFCStrIn_t methodStr,
                        SSFCStrIn_t targetStr, SSFCStrIn_t hostStr, uint16_t portOpt)
{
    size_t methodLen;
    size_t targetLen;
    size_t hostLen;
    size_t portLen = 0;
    size_t need;
    size_t pos = 0;
    char portText[SSF_HTTP_HDR_PORT_TEXT_MAX];                  /* Not NUL terminated */

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(lenOut != NULL);
    SSF_REQUIRE(methodStr != NULL);
    SSF_REQUIRE(targetStr != NULL);
    SSF_REQUIRE(hostStr != NULL);

    *lenOut = 0;
    /* Each NUL scan is bounded by the whole buffer: a longer string cannot fit anyway. */
    if ((_SSFHTTPHdrLen(methodStr, bufSize + 1u, &methodLen) == false) ||
        (_SSFHTTPHdrLen(targetStr, bufSize + 1u, &targetLen) == false) ||
        (_SSFHTTPHdrLen(hostStr, bufSize + 1u, &hostLen) == false))
    { return false; }
    if ((_SSFHTTPHdrIsToken(methodStr, methodLen) == false) ||
        (_SSFHTTPHdrIsTarget(targetStr, targetLen) == false) ||
        (_SSFHTTPHdrIsHost(hostStr, hostLen) == false))
    { return false; }

    /* Port specified? */
    if (portOpt != 0)
    {
        uint16_t p = portOpt;
        size_t i;

        /* Yes, format ":port" right to left */
        portText[0] = ':';
        for (portLen = 1; p > 0; p = (uint16_t)(p / 10u)) portLen++;
        for (i = portLen - 1u, p = portOpt; i > 0; i--, p = (uint16_t)(p / 10u))
        { portText[i] = (char)('0' + (p % 10u)); }
    }

    need = (methodLen + 1u + targetLen + (sizeof(SSF_HTTP_HDR_VERSION_TEXT) - 1u) +
            (sizeof(SSF_HTTP_HDR_HOST_TEXT) - 1u) + hostLen + portLen + 2u);
    if (need > bufSize) return false;

    _SSFHTTPHdrPut(buf, &pos, methodStr, methodLen);
    _SSFHTTPHdrPut(buf, &pos, " ", 1);
    _SSFHTTPHdrPut(buf, &pos, targetStr, targetLen);
    _SSFHTTPHdrPut(buf, &pos, SSF_HTTP_HDR_VERSION_TEXT, sizeof(SSF_HTTP_HDR_VERSION_TEXT) - 1u);
    _SSFHTTPHdrPut(buf, &pos, SSF_HTTP_HDR_HOST_TEXT, sizeof(SSF_HTTP_HDR_HOST_TEXT) - 1u);
    _SSFHTTPHdrPut(buf, &pos, hostStr, hostLen);
    _SSFHTTPHdrPut(buf, &pos, portText, portLen);
    _SSFHTTPHdrPut(buf, &pos, "\r\n", 2);
    SSF_ASSERT(pos == need);
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with "name: value CRLF" appended, else false with *lenInOut unchanged.           */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrReqAddField(uint8_t *buf, size_t bufSize, size_t *lenInOut, SSFCStrIn_t nameStr,
                           SSFCStrIn_t valueStr)
{
    size_t nameLen;
    size_t valueLen;
    size_t left;
    size_t pos;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(lenInOut != NULL);
    SSF_REQUIRE(*lenInOut <= bufSize);
    SSF_REQUIRE(nameStr != NULL);
    SSF_REQUIRE(valueStr != NULL);

    left = bufSize - *lenInOut;
    if ((_SSFHTTPHdrLen(nameStr, left + 1u, &nameLen) == false) ||
        (_SSFHTTPHdrLen(valueStr, left + 1u, &valueLen) == false))
    { return false; }
    if ((_SSFHTTPHdrIsToken(nameStr, nameLen) == false) ||
        (_SSFHTTPHdrIsValue(valueStr, valueLen) == false))
    { return false; }
    if (_SSFHTTPHdrEquals((const uint8_t *)nameStr, nameLen, "host", true)) return false;
    if ((nameLen + 2u + valueLen + 2u) > left) return false;

    pos = *lenInOut;
    _SSFHTTPHdrPut(buf, &pos, nameStr, nameLen);
    _SSFHTTPHdrPut(buf, &pos, ": ", 2);
    _SSFHTTPHdrPut(buf, &pos, valueStr, valueLen);
    _SSFHTTPHdrPut(buf, &pos, "\r\n", 2);
    *lenInOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the empty line appended, else false with *lenInOut unchanged.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrReqEnd(uint8_t *buf, size_t bufSize, size_t *lenInOut)
{
    size_t pos;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(lenInOut != NULL);
    SSF_REQUIRE(*lenInOut <= bufSize);

    if ((bufSize - *lenInOut) < 2u) return false;
    pos = *lenInOut;
    _SSFHTTPHdrPut(buf, &pos, "\r\n", 2);
    *lenInOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns COMPLETE with *respOut filled, INCOMPLETE if valid so far, else MALFORMED.            */
/* --------------------------------------------------------------------------------------------- */
SSFHTTPHdrParse_t SSFHTTPHdrParseResponse(const uint8_t *buf, size_t bufLen,
                                          SSFHTTPHdrResponse_t *respOut)
{
    static const char statusPrefix[] = "HTTP/";
    SSFHTTPHdrState_t st = SSF_HTTP_HDR_ST_STATUS;
    size_t lim = (bufLen > SSF_HTTP_HDR_MAX_HEAD_SIZE) ? SSF_HTTP_HDR_MAX_HEAD_SIZE : bufLen;
    size_t i;
    size_t nameOff = 0;
    size_t nameLen = 0;
    size_t valueOff = 0;
    size_t valueEnd = 0;
    bool isValueStarted = false;
    uint16_t status = 0;

    SSF_REQUIRE((buf != NULL) || (bufLen == 0));
    SSF_REQUIRE(respOut != NULL);

    memset(respOut, 0, sizeof(*respOut));
    for (i = 0; i < lim; i++)
    {
        uint8_t c = buf[i];

        switch (st)
        {
        case SSF_HTTP_HDR_ST_STATUS:
            /* "HTTP/" DIGIT "." DIGIT SP 3DIGIT: every byte has a fixed position */
            if (i < 5u) { if (c != (uint8_t)statusPrefix[i]) return SSF_HTTP_HDR_MALFORMED; }
            else if ((i == 5u) || (i == 7u) || (i >= 9u))
            {
                if ((c < '0') || (c > '9')) return SSF_HTTP_HDR_MALFORMED;
                if (i == 5u) respOut->versionMajor = (uint8_t)(c - '0');
                else if (i == 7u) respOut->versionMinor = (uint8_t)(c - '0');
                else status = (uint16_t)((status * 10u) + (uint16_t)(c - '0'));
            }
            else if ((i == 6u) && (c != '.')) return SSF_HTTP_HDR_MALFORMED;
            else if ((i == 8u) && (c != ' ')) return SSF_HTTP_HDR_MALFORMED;
            if (i == (SSF_HTTP_HDR_STATUS_LINE_MIN - 1u))
            {
                if ((status < 100u) || (status > 599u)) return SSF_HTTP_HDR_MALFORMED;
                respOut->status = status;
                st = SSF_HTTP_HDR_ST_STATUS_END;
            }
            break;

        case SSF_HTTP_HDR_ST_STATUS_END:
            respOut->reasonOff = (uint16_t)(i + 1u);
            if (c == ' ') st = SSF_HTTP_HDR_ST_REASON;
            else if (c == '\r') { respOut->reasonOff = (uint16_t)i; st = SSF_HTTP_HDR_ST_LF; }
            else return SSF_HTTP_HDR_MALFORMED;
            break;

        case SSF_HTTP_HDR_ST_REASON:
            if (c == '\r')
            {
                respOut->reasonLen = (uint16_t)(i - respOut->reasonOff);
                st = SSF_HTTP_HDR_ST_LF;
            }
            else if (_SSFHTTPHdrIsValueChar(c) == false) return SSF_HTTP_HDR_MALFORMED;
            break;

        case SSF_HTTP_HDR_ST_LF:
            if (c != '\n') return SSF_HTTP_HDR_MALFORMED;
            st = SSF_HTTP_HDR_ST_LINE_START;
            break;

        case SSF_HTTP_HDR_ST_LINE_START:
            /* A leading SP or HTAB would be obs-fold, which is refused */
            if (c == '\r') st = SSF_HTTP_HDR_ST_END_LF;
            else if (_SSFHTTPHdrIsTChar(c)) { nameOff = i; st = SSF_HTTP_HDR_ST_NAME; }
            else return SSF_HTTP_HDR_MALFORMED;
            break;

        case SSF_HTTP_HDR_ST_NAME:
            if (c == ':')
            {
                nameLen = i - nameOff;
                isValueStarted = false;                     /* Offsets set by the value */
                st = SSF_HTTP_HDR_ST_VALUE;
            }
            else if (_SSFHTTPHdrIsTChar(c) == false) return SSF_HTTP_HDR_MALFORMED;
            break;

        case SSF_HTTP_HDR_ST_VALUE:
            /* End of the field line? */
            if (c == '\r')
            {
                SSFHTTPHdrFieldRef_t *f;

                /* Yes, record the field */
                if (respOut->fieldCount >= SSF_HTTP_CONFIG_MAX_FIELDS)
                { return SSF_HTTP_HDR_MALFORMED; }
                f = &respOut->fields[respOut->fieldCount];
                f->nameOff = (uint16_t)nameOff;
                f->nameLen = (uint16_t)nameLen;
                if (isValueStarted == false)
                {
                    valueOff = i;
                    valueEnd = i;
                }
                f->valueOff = (uint16_t)valueOff;
                f->valueLen = (uint16_t)(valueEnd - valueOff);
                respOut->fieldCount++;
                st = SSF_HTTP_HDR_ST_LF;
            }
            else if (_SSFHTTPHdrIsValueChar(c) == false) return SSF_HTTP_HDR_MALFORMED;
            else if ((c != ' ') && (c != '\t'))
            {
                if (isValueStarted == false) { isValueStarted = true; valueOff = i; }
                valueEnd = i + 1u;
            }
            break;

        case SSF_HTTP_HDR_ST_END_LF:
            if (c != '\n') return SSF_HTTP_HDR_MALFORMED;
            respOut->headLen = (uint16_t)(i + 1u);
            return SSF_HTTP_HDR_COMPLETE;

        default:
            SSF_ERROR();
        }
    }
    return (bufLen > lim) ? SSF_HTTP_HDR_MALFORMED : SSF_HTTP_HDR_INCOMPLETE;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if field i of resp is named nameStr, case-insensitively.                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsNamed(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp, uint16_t i,
                               SSFCStrIn_t nameStr)
{
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(i < resp->fieldCount);
    SSF_REQUIRE(nameStr != NULL);

    return _SSFHTTPHdrEquals(&buf[resp->fields[i].nameOff], resp->fields[i].nameLen, nameStr,
                             true);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the next field named nameStr at or after *indexInOut, else false.           */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrFindField(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp, SSFCStrIn_t nameStr,
                         uint16_t *indexInOut, const uint8_t **valueOut, size_t *valueLenOut)
{
    uint16_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(resp->fieldCount <= SSF_HTTP_CONFIG_MAX_FIELDS);
    SSF_REQUIRE(nameStr != NULL);
    SSF_REQUIRE(indexInOut != NULL);
    SSF_REQUIRE(valueOut != NULL);
    SSF_REQUIRE(valueLenOut != NULL);

    for (i = *indexInOut; i < resp->fieldCount; i++)
    {
        /* Field has the wanted name? */
        if (_SSFHTTPHdrIsNamed(buf, resp, i, nameStr))
        {
            /* Yes, return its value and resume point */
            *valueOut = &buf[resp->fields[i].valueOff];
            *valueLenOut = resp->fields[i].valueLen;
            *indexInOut = (uint16_t)(i + 1u);
            return true;
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of fields named nameStr.                                                   */
/* --------------------------------------------------------------------------------------------- */
uint16_t SSFHTTPHdrFieldCount(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                              SSFCStrIn_t nameStr)
{
    uint16_t i;
    uint16_t n = 0;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(resp->fieldCount <= SSF_HTTP_CONFIG_MAX_FIELDS);
    SSF_REQUIRE(nameStr != NULL);

    for (i = 0; i < resp->fieldCount; i++) { if (_SSFHTTPHdrIsNamed(buf, resp, i, nameStr)) n++; }
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if exactly one field is named nameStr and its value equals valueStr.             */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrFieldIsOnly(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                           SSFCStrIn_t nameStr, SSFCStrIn_t valueStr, bool isCaseInsensitive)
{
    uint16_t idx = 0;
    const uint8_t *v;
    size_t vLen;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(nameStr != NULL);
    SSF_REQUIRE(valueStr != NULL);

    if (SSFHTTPHdrFieldCount(buf, resp, nameStr) != 1u) return false;
    if (SSFHTTPHdrFindField(buf, resp, nameStr, &idx, &v, &vLen) == false) return false;
    return _SSFHTTPHdrEquals(v, vLen, valueStr, isCaseInsensitive);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a list element of any field named nameStr equals tokenStr case-insensitively. */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrFieldHasToken(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                             SSFCStrIn_t nameStr, SSFCStrIn_t tokenStr)
{
    uint16_t idx = 0;
    const uint8_t *v;
    size_t vLen;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(nameStr != NULL);
    SSF_REQUIRE(tokenStr != NULL);

    if (tokenStr[0] == 0) return false;
    while (SSFHTTPHdrFindField(buf, resp, nameStr, &idx, &v, &vLen))
    {
        size_t i = 0;

        while (i < vLen)
        {
            size_t start;
            size_t end;

            /* One element: skip OWS, take up to the comma, trim trailing OWS */
            while ((i < vLen) && ((v[i] == ' ') || (v[i] == '\t'))) i++;
            start = i;
            while ((i < vLen) && (v[i] != ',')) i++;
            end = i;
            while ((end > start) && ((v[end - 1u] == ' ') || (v[end - 1u] == '\t'))) end--;
            if ((end > start) && _SSFHTTPHdrEquals(&v[start], end - start, tokenStr, true))
            { return true; }
            i++;                                            /* Past the comma */
        }
    }
    return false;
}
