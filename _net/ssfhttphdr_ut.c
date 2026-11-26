/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhttphdr_ut.c                                                                               */
/* Unit tests for the HTTP/1.1 message head codec.                                               */
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
#include "ssfhttphdr.h"

#if SSF_CONFIG_HTTPHDR_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* Local defines and data                                                                        */
/* --------------------------------------------------------------------------------------------- */
#define SSF_HTTPHDR_UT_BUF_SIZE     (512u)
#define SSF_HTTPHDR_UT_CANARY       (0xA5u)
#define SSF_HTTPHDR_UT_CSTR(s)      ((const uint8_t *)(s)), (sizeof(s) - 1u)

static uint8_t _utBuf[SSF_HTTPHDR_UT_BUF_SIZE];
static uint8_t _utBig[SSF_HTTP_HDR_MAX_HEAD_SIZE + 64u];
static SSFHTTPHdrResponse_t _utResp;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the value of the only field named nameStr equals valueStr exactly.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFHTTPHdrUTValueIs(const uint8_t *buf, SSFCStrIn_t nameStr, SSFCStrIn_t valueStr)
{
    uint16_t idx = 0;
    const uint8_t *v;
    size_t vLen;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(nameStr != NULL);
    SSF_REQUIRE(valueStr != NULL);

    /* Exactly one field with this name? */
    if (SSFHTTPHdrFieldCount(buf, &_utResp, nameStr) != 1u) return false;
    if (SSFHTTPHdrFindField(buf, &_utResp, nameStr, &idx, &v, &vLen) == false) return false;
    return ((vLen == strlen(valueStr)) && (memcmp(v, valueStr, vLen) == 0));
}

/* --------------------------------------------------------------------------------------------- */
/* Parses textStr, returning the result.                                                         */
/* --------------------------------------------------------------------------------------------- */
static SSFHTTPHdrParse_t _SSFHTTPHdrUTParse(const char *textStr)
{
    SSF_REQUIRE(textStr != NULL);

    return SSFHTTPHdrParseResponse((const uint8_t *)textStr, strlen(textStr), &_utResp);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the request head builder.                                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHTTPHdrUTBuild(void)
{
    static const char expected[] =
        "GET /mqtt?x=%2F HTTP/1.1\r\nHost: broker.example:8080\r\nUpgrade: websocket\r\n"
        "X-Empty: \r\n\r\n";
    static const char *const badMethods[] = { "", "G T", "GET\r", "G\x01T", "G:T", "G/T" };
    static const char *const goodTargets[] =
    { "/", "*", "/a/b?c=d&e=%2f;f=@:!$'()*+,~-._", "host.example:443", "http://h/p?q",
      "/azAZ09", "/%09%90%af%AF%Fa" };
    static const char *const badTargets[] =
    { "", "/a b", "/a\r\n", "/a#f", "/%zz", "/%4", "/%", "/\x7f", "/\x80", "/a\"", "/<", "/{",
      "/a\\b", "/^", "/`", "/|", "/}", "/>", "/a\tb", "/%4g", "/%g4", "/%41#", "/%41 ",
      "/%/0", "/%0:" };
    static const char *const goodHosts[] = { "a", "a-b.c_d~1", "10.0.0.1", "A.EXAMPLE", "zZ09" };
    static const char *const badHosts[] =
    { "", "a b", "a:1", "a/b", "a\r", "[::1]", "a@b", "a%41", "a?b", "a#b" };
    static const char *const goodNames[] = { "X-Custom", "!#$%&'*+-.^_`|~0aZ", "z9", "Hostx",
                                             "Hos" };
    static const char *const badNames[] = { "", "A B", "A:B", "A\r", "Host", "hOsT", "A\x80" };
    static const char *const goodValues[] = { "", "a", "a b\tc", "\x80\xff", "Bearer ab+/==" };
    static const char *const badValues[] = { "\r", "a\nb", "a\rb", "\x01", "a\x7f", " a", "a ",
                                             "\ta", "a\t" };
    size_t len;
    size_t full;
    size_t size;
    size_t i;

    /* Requires */
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqBegin(NULL, 1, &len, "GET", "/", "h", 0));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqBegin(_utBuf, 1, NULL, "GET", "/", "h", 0));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqBegin(_utBuf, 1, &len, NULL, "/", "h", 0));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqBegin(_utBuf, 1, &len, "GET", NULL, "h", 0));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqBegin(_utBuf, 1, &len, "GET", "/", NULL, 0));
    len = 0;
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqAddField(NULL, 1, &len, "A", "b"));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqAddField(_utBuf, 1, NULL, "A", "b"));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqAddField(_utBuf, 1, &len, NULL, "b"));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqAddField(_utBuf, 1, &len, "A", NULL));
    len = 2;
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqAddField(_utBuf, 1, &len, "A", "b"));   /* len > size */
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqEnd(NULL, 1, &len));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqEnd(_utBuf, 1, NULL));
    SSF_ASSERT_TEST((void)SSFHTTPHdrReqEnd(_utBuf, 1, &len));                  /* len > size */

    /* A whole head, byte exact */
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", "/mqtt?x=%2F",
                                  "broker.example", 8080));
    SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(_utBuf), &len, "Upgrade", "websocket"));
    SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(_utBuf), &len, "X-Empty", ""));
    SSF_ASSERT(SSFHTTPHdrReqEnd(_utBuf, sizeof(_utBuf), &len));
    SSF_ASSERT(len == (sizeof(expected) - 1u));
    SSF_ASSERT(memcmp(_utBuf, expected, len) == 0);
    full = len;

    /* Exact fits: request line 16, Host 12, field 8 and empty line 2 bytes, none to spare */
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, 28, &len, "GET", "/", "h", 80));
    SSF_ASSERT(len == 28u);
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, 27, &len, "GET", "/", "h", 80) == false);
    len = 28;
    SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, 35, &len, "A", "bcd") == false);
    SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, 36, &len, "A", "bcd"));
    SSF_ASSERT(len == 36u);
    SSF_ASSERT(SSFHTTPHdrReqEnd(_utBuf, 37, &len) == false);
    SSF_ASSERT(SSFHTTPHdrReqEnd(_utBuf, 38, &len));
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, 27, &len, "GET", "/", "h", 7));     /* 1-digit port */
    SSF_ASSERT((len == 27u) && (memcmp(_utBuf, "GET / HTTP/1.1\r\nHost: h:7\r\n", len) == 0));

    /* Port 0 omits the port */
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "OPTIONS", "*", "h", 0));
    SSF_ASSERT(len == strlen("OPTIONS * HTTP/1.1\r\nHost: h\r\n"));
    SSF_ASSERT(memcmp(_utBuf, "OPTIONS * HTTP/1.1\r\nHost: h\r\n", len) == 0);
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", "/", "h", 65535));
    SSF_ASSERT(memcmp(_utBuf, "GET / HTTP/1.1\r\nHost: h:65535\r\n", len) == 0);

    /* Every buffer size: fits or fails, never writes past size, failure keeps the length */
    for (size = 0; size <= full + 1u; size++)
    {
        bool ok;
        size_t before;

        memset(_utBuf, SSF_HTTPHDR_UT_CANARY, sizeof(_utBuf));
        len = 99;
        ok = SSFHTTPHdrReqBegin(_utBuf, size, &len, "GET", "/mqtt?x=%2F", "broker.example",
                                8080);
        if (ok == false) { SSF_ASSERT(len == 0); }
        if (ok)
        {
            before = len;
            ok = SSFHTTPHdrReqAddField(_utBuf, size, &len, "Upgrade", "websocket");
            if (ok == false) { SSF_ASSERT(len == before); }
        }
        if (ok)
        {
            before = len;
            ok = SSFHTTPHdrReqAddField(_utBuf, size, &len, "X-Empty", "");
            if (ok == false) { SSF_ASSERT(len == before); }
        }
        if (ok)
        {
            before = len;
            ok = SSFHTTPHdrReqEnd(_utBuf, size, &len);
            if (ok == false) { SSF_ASSERT(len == before); }
        }
        SSF_ASSERT(ok == (size >= full));
        if (ok) { SSF_ASSERT((len == full) && (memcmp(_utBuf, expected, full) == 0)); }
        for (i = size; i < sizeof(_utBuf); i++) SSF_ASSERT(_utBuf[i] == SSF_HTTPHDR_UT_CANARY);
    }

    /* Methods */
    for (i = 0; i < (sizeof(badMethods) / sizeof(badMethods[0])); i++)
    {
        len = 99;
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, badMethods[i], "/", "h", 0) ==
                   false);
        SSF_ASSERT(len == 0);
    }
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "CONNECT", "h:443", "h", 443));

    /* Targets */
    for (i = 0; i < (sizeof(goodTargets) / sizeof(goodTargets[0])); i++)
    {
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", goodTargets[i], "h",
                                      0));
    }
    for (i = 0; i < (sizeof(badTargets) / sizeof(badTargets[0])); i++)
    {
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", badTargets[i], "h",
                                      0) == false);
    }

    /* Hosts */
    for (i = 0; i < (sizeof(goodHosts) / sizeof(goodHosts[0])); i++)
    {
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", "/", goodHosts[i],
                                      0));
    }
    for (i = 0; i < (sizeof(badHosts) / sizeof(badHosts[0])); i++)
    {
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", "/", badHosts[i], 0) ==
                   false);
    }

    /* Field names and values */
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", "/", "h", 0));
    full = len;
    for (i = 0; i < (sizeof(goodNames) / sizeof(goodNames[0])); i++)
    {
        len = full;
        SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(_utBuf), &len, goodNames[i], "v"));
        SSF_ASSERT(len == ((full + strlen(goodNames[i])) + strlen(": v\r\n")));
    }
    for (i = 0; i < (sizeof(badNames) / sizeof(badNames[0])); i++)
    {
        len = full;
        SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(_utBuf), &len, badNames[i], "v") == false);
        SSF_ASSERT(len == full);
    }
    for (i = 0; i < (sizeof(goodValues) / sizeof(goodValues[0])); i++)
    {
        len = full;
        SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(_utBuf), &len, "A", goodValues[i]));
        SSF_ASSERT(memcmp(&_utBuf[full + 3u], goodValues[i], strlen(goodValues[i])) == 0);
    }
    for (i = 0; i < (sizeof(badValues) / sizeof(badValues[0])); i++)
    {
        len = full;
        SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(_utBuf), &len, "A", badValues[i]) ==
                   false);
        SSF_ASSERT(len == full);
    }

    /* Unterminated strings one byte longer than the scan bound are refused without overread */
    {
        static char noNul[8];

        memset(noNul, 'a', sizeof(noNul));
        len = 0;
        SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(noNul) - 1u, &len, "A", noNul) == false);
        SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(noNul) - 1u, &len, noNul, "v") == false);
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(noNul) - 1u, &len, noNul, "/", "h", 0) ==
                   false);
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(noNul) - 1u, &len, "G", noNul, "h", 0) ==
                   false);
        SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(noNul) - 1u, &len, "G", "/", noNul, 0) ==
                   false);
    }

    /* A string longer than the space left is refused without scanning past it */
    memset(_utBig, 'a', sizeof(_utBig) - 1u);
    _utBig[sizeof(_utBig) - 1u] = 0;
    len = full;
    SSF_ASSERT(SSFHTTPHdrReqAddField(_utBuf, sizeof(_utBuf), &len, "A", (const char *)_utBig) ==
               false);
    SSF_ASSERT(SSFHTTPHdrReqBegin(_utBuf, sizeof(_utBuf), &len, "GET", "/", (const char *)_utBig,
                                  0) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests response head parsing.                                                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHTTPHdrUTParseHead(void)
{
    static const char ws[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection:Upgrade\r\n"
        "Sec-WebSocket-Accept: \t s3pPLMBiTxaQ9kYGzzhZRbK+xOo= \t\r\n"
        "X-Empty:\r\n"
        "X-Obs: \x80\xff\r\n"
        "X-Inner: a  b\tc\r\n"
        "\r\n";
    static const char *const malformed[] =
    {
        /* Status line */
        "HTTP/1.1 10\r\n\r\n", "HTTP/1.1 1011\r\n\r\n", "HTTP/1.1 099 x\r\n\r\n",
        "HTTP/1.1 600 x\r\n\r\n", "http/1.1 101 x\r\n\r\n", "HTTP/11 101 x\r\n\r\n",
        "HTTP/1.1  101 x\r\n\r\n", "HTTP/1.1\t101 x\r\n\r\n", "HTTP/1.1 1a1 x\r\n\r\n",
        " HTTP/1.1 101 x\r\n\r\n", "\r\nHTTP/1.1 101 x\r\n\r\n", "HTTP/1.1 101 \x01\r\n\r\n",
        "HTTP/1.1 101 x\n\r\n", "HTTP/1.1 101 x\r\r\n\r\n", "HTTP/1.1 101 x\rX\r\n\r\n",
        "HTTP/1.1 101x\r\n\r\n", "HTTP/a.1 101 x\r\n\r\n", "HTTP/1.b 101 x\r\n\r\n",
        "HTTP/1.1 101 a\x7f\r\n\r\n", "HTTP/1.1\r\n\r\n",
        "\r\n\r\n", "HTTP/1.1 101 x\r\n\n",
        /* Fields */
        "HTTP/1.1 101 x\r\nName : v\r\n\r\n", "HTTP/1.1 101 x\r\nName\t: v\r\n\r\n",
        "HTTP/1.1 101 x\r\n: v\r\n\r\n", "HTTP/1.1 101 x\r\nNa me: v\r\n\r\n",
        "HTTP/1.1 101 x\r\nName v\r\n\r\n", "HTTP/1.1 101 x\r\nName:\x01\r\n\r\n",
        "HTTP/1.1 101 x\r\nName: a\x7f" "b\r\n\r\n",
        "HTTP/1.1 101 x\r\nA: b\r\n c\r\n\r\n", "HTTP/1.1 101 x\r\nA: b\r\n\tc\r\n\r\n",
        "HTTP/1.1 101 x\r\nA: b\nC: d\r\n\r\n", "HTTP/1.1 101 x\r\nA: b\rC: d\r\n\r\n",
        "HTTP/1.1 101 x\r\nA: b\r\nX\r\n\r\n", "HTTP/1.1 101 x\r\nA\x80: b\r\n\r\n",
        "HTTP/1.1 101 x\r\nA(: b\r\n\r\n", "HTTP/1.1 101 x\r\n\x01: b\r\n\r\n",
        /* Early: no terminator needed to see these */
        "HTTP/1.1 10\r\n", "HTTP/1.1 101 x\r\nA b\r\n", "HTTP/1.1 101 x\n", "HTTPS",
        "HTTP/1.1 101 x\r\n c",
    };
    static const char *const incomplete[] =
    { "", "H", "HTTP/1.1", "HTTP/1.1 101 x", "HTTP/1.1 101 x\r", "HTTP/1.1 101 x\r\n",
      "HTTP/1.1 101 x\r\nA: b", "HTTP/1.1 101 x\r\nA: b\r\n", "HTTP/1.1 101 x\r\nA: b\r\n\r" };
    size_t wsLen = sizeof(ws) - 1u;
    size_t i;
    size_t n;
    const uint8_t *v;
    size_t vLen;
    uint16_t idx;

    /* Requires */
    SSF_ASSERT_TEST((void)SSFHTTPHdrParseResponse(NULL, 1, &_utResp));
    SSF_ASSERT_TEST((void)SSFHTTPHdrParseResponse(_utBuf, 1, NULL));
    SSF_ASSERT(SSFHTTPHdrParseResponse(NULL, 0, &_utResp) == SSF_HTTP_HDR_INCOMPLETE);

    /* Minimal */
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/1.1 101 Switching Protocols\r\n\r\n") ==
               SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT(_utResp.headLen == 36u);
    SSF_ASSERT(_utResp.status == 101u);
    SSF_ASSERT((_utResp.versionMajor == 1u) && (_utResp.versionMinor == 1u));
    SSF_ASSERT((_utResp.reasonOff == 13u) && (_utResp.reasonLen == 19u));
    SSF_ASSERT(_utResp.fieldCount == 0);
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/1.0 599\r\n\r\n") == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT((_utResp.status == 599u) && (_utResp.versionMinor == 0u));
    SSF_ASSERT(_utResp.reasonLen == 0);
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/2.0 100 \r\n\r\n") == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT((_utResp.status == 100u) && (_utResp.versionMajor == 2u));
    SSF_ASSERT(_utResp.reasonLen == 0);
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/1.1 200 a \tb\x80\r\n\r\n") == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT(_utResp.reasonLen == 5u);
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/1.1 200 \tx\r\n\r\n") == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT((_utResp.reasonOff == 13u) && (_utResp.reasonLen == 2u));  /* Raw, not trimmed */

    /* Case folding at the ends of the alphabet */
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/1.1 200 x\r\nZA: aZ\r\n\r\n") == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT(SSFHTTPHdrFieldIsOnly((const uint8_t *)"HTTP/1.1 200 x\r\nZA: aZ\r\n\r\n", &_utResp,
                                     "za", "Az", true));

    /* A whitespace-only value is empty, positioned at the end of its line */
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/1.1 200 x\r\nA: \t \r\n\r\n") == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT((_utResp.fieldCount == 1u) && (_utResp.fields[0].valueLen == 0));
    SSF_ASSERT(_utResp.fields[0].valueOff == 21u);

    /* A typical upgrade response; bytes after the head are not examined */
    memcpy(_utBuf, ws, wsLen);
    memcpy(&_utBuf[wsLen], "\x82\x00\r\x01\n", 5);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBuf, wsLen + 5u, &_utResp) == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT(_utResp.headLen == wsLen);
    SSF_ASSERT(_utResp.fieldCount == 6u);
    SSF_ASSERT(_SSFHTTPHdrUTValueIs(_utBuf, "upgrade", "websocket"));
    SSF_ASSERT(_SSFHTTPHdrUTValueIs(_utBuf, "CONNECTION", "Upgrade"));
    SSF_ASSERT(_SSFHTTPHdrUTValueIs(_utBuf, "Sec-WebSocket-Accept",
                                    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    SSF_ASSERT(_SSFHTTPHdrUTValueIs(_utBuf, "X-Empty", ""));
    SSF_ASSERT(_SSFHTTPHdrUTValueIs(_utBuf, "X-Obs", "\x80\xff"));
    SSF_ASSERT(_SSFHTTPHdrUTValueIs(_utBuf, "X-Inner", "a  b\tc"));
    SSF_ASSERT((_utResp.fields[0].nameOff == 34u) && (_utResp.fields[0].nameLen == 7u));
    SSF_ASSERT((_utResp.fields[0].valueOff == 43u) && (_utResp.fields[0].valueLen == 9u));
    SSF_ASSERT(_utResp.fields[3].valueLen == 0);                      /* X-Empty */

    /* Every proper prefix is INCOMPLETE */
    for (n = 0; n < wsLen; n++)
    { SSF_ASSERT(SSFHTTPHdrParseResponse(_utBuf, n, &_utResp) == SSF_HTTP_HDR_INCOMPLETE); }
    for (i = 0; i < (sizeof(incomplete) / sizeof(incomplete[0])); i++)
    { SSF_ASSERT(_SSFHTTPHdrUTParse(incomplete[i]) == SSF_HTTP_HDR_INCOMPLETE); }

    /* Malformed; the cases with an embedded NUL are measured with sizeof, not strlen */
    for (i = 0; i < (sizeof(malformed) / sizeof(malformed[0])); i++)
    { SSF_ASSERT(_SSFHTTPHdrUTParse(malformed[i]) == SSF_HTTP_HDR_MALFORMED); }
    SSF_ASSERT(SSFHTTPHdrParseResponse(SSF_HTTPHDR_UT_CSTR("HTTP/1.1 101 a\0b\r\n\r\n"),
                                       &_utResp) == SSF_HTTP_HDR_MALFORMED);
    SSF_ASSERT(SSFHTTPHdrParseResponse(SSF_HTTPHDR_UT_CSTR("HTTP/1.1 101 x\r\nN: a\0b\r\n\r\n"),
                                       &_utResp) == SSF_HTTP_HDR_MALFORMED);
    SSF_ASSERT(SSFHTTPHdrParseResponse(SSF_HTTPHDR_UT_CSTR("HTTP/1.1 101 x\r\n\0: b\r\n\r\n"),
                                       &_utResp) == SSF_HTTP_HDR_MALFORMED);

    /* Field count limit */
    n = (size_t)snprintf((char *)_utBig, sizeof(_utBig), "HTTP/1.1 200 OK\r\n");
    for (i = 0; i < SSF_HTTP_CONFIG_MAX_FIELDS; i++)
    { n += (size_t)snprintf((char *)&_utBig[n], sizeof(_utBig) - n, "F%u: %u\r\n", (unsigned)i,
                            (unsigned)i); }
    memcpy(&_utBig[n], "\r\n", 2);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, n + 2u, &_utResp) == SSF_HTTP_HDR_COMPLETE);
    SSF_ASSERT(_utResp.fieldCount == SSF_HTTP_CONFIG_MAX_FIELDS);
    memcpy(&_utBig[n], "X: y\r\n\r\n", 8);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, n + 8u, &_utResp) == SSF_HTTP_HDR_MALFORMED);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, n + 4u, &_utResp) == SSF_HTTP_HDR_INCOMPLETE);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, n + 6u, &_utResp) == SSF_HTTP_HDR_MALFORMED);

    /* Head size limit: the maximum is accepted, one more byte or no end past it is MALFORMED */
    for (n = 0; n <= 1u; n++)
    {
        size_t head = SSF_HTTP_HDR_MAX_HEAD_SIZE + n;
        size_t pre = strlen("HTTP/1.1 200 OK\r\nA: ");

        memcpy(_utBig, "HTTP/1.1 200 OK\r\nA: ", pre);
        memset(&_utBig[pre], 'v', ((head - pre) - 4u));
        memcpy(&_utBig[head - 4u], "\r\n\r\n", 4);
        SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, head, &_utResp) ==
                   ((n == 0) ? SSF_HTTP_HDR_COMPLETE : SSF_HTTP_HDR_MALFORMED));
        if (n == 0) { SSF_ASSERT(_utResp.headLen == SSF_HTTP_HDR_MAX_HEAD_SIZE); }
    }
    memset(&_utBig[20], 'v', sizeof(_utBig) - 20u);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, SSF_HTTP_HDR_MAX_HEAD_SIZE, &_utResp) ==
               SSF_HTTP_HDR_INCOMPLETE);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, sizeof(_utBig), &_utResp) ==
               SSF_HTTP_HDR_MALFORMED);
    memcpy(&_utBig[SSF_HTTP_HDR_MAX_HEAD_SIZE - 3u], "\r\n\r", 3);
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, SSF_HTTP_HDR_MAX_HEAD_SIZE, &_utResp) ==
               SSF_HTTP_HDR_INCOMPLETE);
    _utBig[SSF_HTTP_HDR_MAX_HEAD_SIZE] = '\n';                 /* One past the maximum */
    SSF_ASSERT(SSFHTTPHdrParseResponse(_utBig, SSF_HTTP_HDR_MAX_HEAD_SIZE + 1u, &_utResp) ==
               SSF_HTTP_HDR_MALFORMED);

    /* Lookups: duplicates, case, tokens */
    SSF_ASSERT(_SSFHTTPHdrUTParse("HTTP/1.1 101 x\r\nConnection: keep-alive, Upgrade\r\n"
                                  "A: 1\r\nconnection: ,,\tclose\t,\r\nA: 2\r\nB: Upgrades\r\n"
                                  "C: up grade\r\nD:\r\nE: Up\r\n\r\n") == SSF_HTTP_HDR_COMPLETE);
    {
        const char *text = (const char *)"HTTP/1.1 101 x\r\nConnection: keep-alive, Upgrade\r\n"
                           "A: 1\r\nconnection: ,,\tclose\t,\r\nA: 2\r\nB: Upgrades\r\n"
                           "C: up grade\r\nD:\r\nE: Up\r\n\r\n";
        const uint8_t *b = (const uint8_t *)text;

        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldCount(NULL, &_utResp, "A"));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldCount(b, NULL, "A"));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldCount(b, &_utResp, NULL));
        idx = 0;
        SSF_ASSERT_TEST((void)SSFHTTPHdrFindField(NULL, &_utResp, "A", &idx, &v, &vLen));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFindField(b, NULL, "A", &idx, &v, &vLen));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFindField(b, &_utResp, NULL, &idx, &v, &vLen));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFindField(b, &_utResp, "A", NULL, &v, &vLen));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFindField(b, &_utResp, "A", &idx, NULL, &vLen));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFindField(b, &_utResp, "A", &idx, &v, NULL));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldIsOnly(NULL, &_utResp, "A", "1", true));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldIsOnly(b, NULL, "A", "1", true));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldIsOnly(b, &_utResp, NULL, "1", true));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldIsOnly(b, &_utResp, "A", NULL, true));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldHasToken(NULL, &_utResp, "A", "1"));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldHasToken(b, NULL, "A", "1"));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldHasToken(b, &_utResp, NULL, "1"));
        SSF_ASSERT_TEST((void)SSFHTTPHdrFieldHasToken(b, &_utResp, "A", NULL));

        SSF_ASSERT(SSFHTTPHdrFieldCount(b, &_utResp, "a") == 2u);
        SSF_ASSERT(SSFHTTPHdrFieldCount(b, &_utResp, "CONNECTION") == 2u);
        SSF_ASSERT(SSFHTTPHdrFieldCount(b, &_utResp, "Z") == 0);
        SSF_ASSERT(SSFHTTPHdrFieldCount(b, &_utResp, "") == 0);
        SSF_ASSERT(SSFHTTPHdrFieldCount(b, &_utResp, "Connectio") == 0);
        SSF_ASSERT(SSFHTTPHdrFieldCount(b, &_utResp, "Connections") == 0);

        idx = 0;
        SSF_ASSERT(SSFHTTPHdrFindField(b, &_utResp, "a", &idx, &v, &vLen));
        SSF_ASSERT((idx == 2u) && (vLen == 1u) && (v[0] == '1'));
        SSF_ASSERT(SSFHTTPHdrFindField(b, &_utResp, "a", &idx, &v, &vLen));
        SSF_ASSERT((idx == 4u) && (vLen == 1u) && (v[0] == '2'));
        SSF_ASSERT(SSFHTTPHdrFindField(b, &_utResp, "a", &idx, &v, &vLen) == false);
        SSF_ASSERT(idx == 4u);
        idx = 200;
        SSF_ASSERT(SSFHTTPHdrFindField(b, &_utResp, "a", &idx, &v, &vLen) == false);

        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "b", "upgrades", true));
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "b", "upgrades", false) == false);
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "b", "Upgrades", false));
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "b", "Upgrade", true) == false);
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "b", "Upgradess", true) == false);
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "a", "1", true) == false);   /* Two */
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "z", "", true) == false);    /* None */
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "d", "", false));

        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "connection", "upgrade"));
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "connection", "KEEP-ALIVE"));
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "connection", "close"));
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "connection", "") == false);
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "connection", "keep") == false);
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "b", "upgrade") == false);
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "c", "up") == false);
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "c", "up grade"));
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "d", "") == false);
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "e", "upgrade") == false);
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "e", "up"));
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "z", "up") == false);
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "E", "UP"));
        SSF_ASSERT(SSFHTTPHdrFieldHasToken(b, &_utResp, "Connection", "Close"));
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "e", "uP", true));
        SSF_ASSERT(SSFHTTPHdrFieldIsOnly(b, &_utResp, "e", "UZ", true) == false);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfhttphdr external interface.                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFHTTPHdrUnitTest(void)
{
    _SSFHTTPHdrUTBuild();
    _SSFHTTPHdrUTParseHead();
}

#endif /* SSF_CONFIG_HTTPHDR_UNIT_TEST */
