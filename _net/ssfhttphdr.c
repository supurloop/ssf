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
    SSF_HTTP_HDR_ST_STATUS,          /* Fixed-position "HTTP/x.y nnn"                           */
    SSF_HTTP_HDR_ST_STATUS_END,      /* After the code: SP then reason, or CR                   */
    SSF_HTTP_HDR_ST_REASON,
    SSF_HTTP_HDR_ST_LINE_START,      /* Start of a field line, or the empty line                */
    SSF_HTTP_HDR_ST_NAME,
    SSF_HTTP_HDR_ST_VALUE,
    SSF_HTTP_HDR_ST_LF,              /* CR seen; LF must follow                                 */
    SSF_HTTP_HDR_ST_END_LF           /* CR of the empty line seen                               */
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
/* Returns true if a[0..len) equals the NUL terminated b, ASCII case-insensitively if ci.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrEquals(const uint8_t *a, size_t len, SSFCStrIn_t b, bool ci)
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        uint8_t cb = (uint8_t)b[i];

        if (cb == 0) return false;
        if (ci) { if (_SSFHTTPHdrLower(a[i]) != _SSFHTTPHdrLower(cb)) return false; }
        else if (a[i] != cb) return false;
    }
    return b[len] == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Sets *lenOut to the length of str if its NUL lies within size bytes; else returns false.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrLen(SSFCStrIn_t str, size_t size, size_t *lenOut)
{
    return SSFStrLen(str, size, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str[0..len) is a non-empty token.                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsToken(SSFCStrIn_t str, size_t len)
{
    size_t i;

    if (len == 0) return false;
    for (i = 0; i < len; i++) { if (_SSFHTTPHdrIsTChar((uint8_t)str[i]) == false) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str[0..len) is a non-empty request target: URI characters (RFC 3986           */
/* unreserved, gen-delims except '#', sub-delims) with well-formed %XX escapes.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsTarget(SSFCStrIn_t str, size_t len)
{
    size_t i;

    if (len == 0) return false;
    for (i = 0; i < len; i++)
    {
        uint8_t c = (uint8_t)str[i];

        if (c == '%')
        {
            if ((i + 2u) >= len) return false;
            if ((_SSFHTTPHdrIsHex((uint8_t)str[i + 1u]) == false) ||
                (_SSFHTTPHdrIsHex((uint8_t)str[i + 2u]) == false))
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
/* Returns true if str[0..len) is a non-empty host: letters, digits, '-', '.', '_', '~'.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsHost(SSFCStrIn_t str, size_t len)
{
    size_t i;

    if (len == 0) return false;
    for (i = 0; i < len; i++)
    {
        uint8_t c = (uint8_t)str[i];

        if (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9')))
        { continue; }
        if ((c != '-') && (c != '.') && (c != '_') && (c != '~')) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str[0..len) is a field value: value characters, not starting or ending with   */
/* a space or tab. An empty value is valid.                                                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsValue(SSFCStrIn_t str, size_t len)
{
    size_t i;

    if (len == 0) return true;
    if ((str[0] == ' ') || (str[0] == '\t') || (str[len - 1u] == ' ') || (str[len - 1u] == '\t'))
    { return false; }
    for (i = 0; i < len; i++)
    { if (_SSFHTTPHdrIsValueChar((uint8_t)str[i]) == false) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends len bytes at buf[*pos]; caller has checked they fit.                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHTTPHdrPut(uint8_t *buf, size_t *pos, const void *src, size_t len)
{
    memcpy(&buf[*pos], src, len);
    *pos += len;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the request line and Host field written at buf[0], else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrReqBegin(uint8_t *buf, size_t size, size_t *lenOut, SSFCStrIn_t method,
                        SSFCStrIn_t target, SSFCStrIn_t host, uint16_t portOpt)
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
    SSF_REQUIRE(method != NULL);
    SSF_REQUIRE(target != NULL);
    SSF_REQUIRE(host != NULL);

    *lenOut = 0;
    /* Each NUL scan is bounded by the whole buffer: a longer string cannot fit anyway. */
    if ((_SSFHTTPHdrLen(method, size + 1u, &methodLen) == false) ||
        (_SSFHTTPHdrLen(target, size + 1u, &targetLen) == false) ||
        (_SSFHTTPHdrLen(host, size + 1u, &hostLen) == false))
    { return false; }
    if ((_SSFHTTPHdrIsToken(method, methodLen) == false) ||
        (_SSFHTTPHdrIsTarget(target, targetLen) == false) ||
        (_SSFHTTPHdrIsHost(host, hostLen) == false))
    { return false; }

    if (portOpt != 0)
    {
        uint16_t p = portOpt;
        size_t i;

        portText[0] = ':';
        for (portLen = 1; p > 0; p = (uint16_t)(p / 10u)) portLen++;
        for (i = portLen - 1u, p = portOpt; i > 0; i--, p = (uint16_t)(p / 10u))
        { portText[i] = (char)('0' + (p % 10u)); }
    }

    need = methodLen + 1u + targetLen + (sizeof(SSF_HTTP_HDR_VERSION_TEXT) - 1u) +
           (sizeof(SSF_HTTP_HDR_HOST_TEXT) - 1u) + hostLen + portLen + 2u;
    if (need > size) return false;

    _SSFHTTPHdrPut(buf, &pos, method, methodLen);
    _SSFHTTPHdrPut(buf, &pos, " ", 1);
    _SSFHTTPHdrPut(buf, &pos, target, targetLen);
    _SSFHTTPHdrPut(buf, &pos, SSF_HTTP_HDR_VERSION_TEXT, sizeof(SSF_HTTP_HDR_VERSION_TEXT) - 1u);
    _SSFHTTPHdrPut(buf, &pos, SSF_HTTP_HDR_HOST_TEXT, sizeof(SSF_HTTP_HDR_HOST_TEXT) - 1u);
    _SSFHTTPHdrPut(buf, &pos, host, hostLen);
    _SSFHTTPHdrPut(buf, &pos, portText, portLen);
    _SSFHTTPHdrPut(buf, &pos, "\r\n", 2);
    SSF_ASSERT(pos == need);
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with "name: value CRLF" appended, else false with *lenInOut unchanged.           */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrReqAddField(uint8_t *buf, size_t size, size_t *lenInOut, SSFCStrIn_t name,
                           SSFCStrIn_t value)
{
    size_t nameLen;
    size_t valueLen;
    size_t left;
    size_t pos;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(lenInOut != NULL);
    SSF_REQUIRE(*lenInOut <= size);
    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE(value != NULL);

    left = size - *lenInOut;
    if ((_SSFHTTPHdrLen(name, left + 1u, &nameLen) == false) ||
        (_SSFHTTPHdrLen(value, left + 1u, &valueLen) == false))
    { return false; }
    if ((_SSFHTTPHdrIsToken(name, nameLen) == false) ||
        (_SSFHTTPHdrIsValue(value, valueLen) == false))
    { return false; }
    if (_SSFHTTPHdrEquals((const uint8_t *)name, nameLen, "host", true)) return false;
    if ((nameLen + 2u + valueLen + 2u) > left) return false;

    pos = *lenInOut;
    _SSFHTTPHdrPut(buf, &pos, name, nameLen);
    _SSFHTTPHdrPut(buf, &pos, ": ", 2);
    _SSFHTTPHdrPut(buf, &pos, value, valueLen);
    _SSFHTTPHdrPut(buf, &pos, "\r\n", 2);
    *lenInOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the empty line appended, else false with *lenInOut unchanged.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrReqEnd(uint8_t *buf, size_t size, size_t *lenInOut)
{
    size_t pos;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(lenInOut != NULL);
    SSF_REQUIRE(*lenInOut <= size);

    if ((size - *lenInOut) < 2u) return false;
    pos = *lenInOut;
    _SSFHTTPHdrPut(buf, &pos, "\r\n", 2);
    *lenInOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns COMPLETE with *respOut filled, INCOMPLETE if valid so far, else MALFORMED.            */
/* --------------------------------------------------------------------------------------------- */
SSFHTTPHdrParse_t SSFHTTPHdrParseResponse(const uint8_t *buf, size_t len,
                                          SSFHTTPHdrResponse_t *respOut)
{
    static const char statusPrefix[] = "HTTP/";
    SSFHTTPHdrState_t st = SSF_HTTP_HDR_ST_STATUS;
    size_t lim = (len > SSF_HTTP_HDR_MAX_HEAD_SIZE) ? SSF_HTTP_HDR_MAX_HEAD_SIZE : len;
    size_t i;
    size_t nameOff = 0;
    size_t nameLen = 0;
    size_t valueOff = 0;
    size_t valueEnd = 0;
    bool isValueStarted = false;
    uint16_t status = 0;

    SSF_REQUIRE((buf != NULL) || (len == 0));
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
            if (c == '\r')
            {
                SSFHTTPHdrFieldRef_t *f;

                if (respOut->fieldCount >= SSF_HTTP_CONFIG_MAX_FIELDS)
                { return SSF_HTTP_HDR_MALFORMED; }
                f = &respOut->fields[respOut->fieldCount];
                f->nameOff = (uint16_t)nameOff;
                f->nameLen = (uint16_t)nameLen;
                if (isValueStarted == false) valueOff = valueEnd = i;
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
    return (len > lim) ? SSF_HTTP_HDR_MALFORMED : SSF_HTTP_HDR_INCOMPLETE;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if field i of resp is named name, case-insensitively.                            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrIsNamed(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp, uint16_t i,
                               SSFCStrIn_t name)
{
    return _SSFHTTPHdrEquals(&buf[resp->fields[i].nameOff], resp->fields[i].nameLen, name, true);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the next field named name at or after *indexInOut, else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrFindField(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp, SSFCStrIn_t name,
                         uint16_t *indexInOut, const uint8_t **valueOut, size_t *valueLenOut)
{
    uint16_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(resp->fieldCount <= SSF_HTTP_CONFIG_MAX_FIELDS);
    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE(indexInOut != NULL);
    SSF_REQUIRE(valueOut != NULL);
    SSF_REQUIRE(valueLenOut != NULL);

    for (i = *indexInOut; i < resp->fieldCount; i++)
    {
        if (_SSFHTTPHdrIsNamed(buf, resp, i, name))
        {
            *valueOut = &buf[resp->fields[i].valueOff];
            *valueLenOut = resp->fields[i].valueLen;
            *indexInOut = (uint16_t)(i + 1u);
            return true;
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of fields named name.                                                      */
/* --------------------------------------------------------------------------------------------- */
uint16_t SSFHTTPHdrFieldCount(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                              SSFCStrIn_t name)
{
    uint16_t i;
    uint16_t n = 0;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(resp->fieldCount <= SSF_HTTP_CONFIG_MAX_FIELDS);
    SSF_REQUIRE(name != NULL);

    for (i = 0; i < resp->fieldCount; i++) { if (_SSFHTTPHdrIsNamed(buf, resp, i, name)) n++; }
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if exactly one field is named name and its value equals value.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrFieldIsOnly(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                           SSFCStrIn_t name, SSFCStrIn_t value, bool isCaseInsensitive)
{
    uint16_t idx = 0;
    const uint8_t *v;
    size_t vLen;

    SSF_REQUIRE(value != NULL);

    if (SSFHTTPHdrFieldCount(buf, resp, name) != 1u) return false;
    if (SSFHTTPHdrFindField(buf, resp, name, &idx, &v, &vLen) == false) return false;
    return _SSFHTTPHdrEquals(v, vLen, value, isCaseInsensitive);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a list element of any field named name equals token case-insensitively.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFHTTPHdrFieldHasToken(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                             SSFCStrIn_t name, SSFCStrIn_t token)
{
    uint16_t idx = 0;
    const uint8_t *v;
    size_t vLen;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(resp != NULL);
    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE(token != NULL);

    if (token[0] == 0) return false;
    while (SSFHTTPHdrFindField(buf, resp, name, &idx, &v, &vLen))
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
            if ((end > start) && _SSFHTTPHdrEquals(&v[start], end - start, token, true))
            { return true; }
            i++;                                            /* Past the comma */
        }
    }
    return false;
}
