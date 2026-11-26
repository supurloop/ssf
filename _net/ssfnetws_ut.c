/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnetws_ut.c                                                                                 */
/* Unit tests for the WebSocket client transport.                                                */
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
#include <stdio.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfsha1.h"
#include "ssfbase64.h"
#include "ssfnetws.h"

#if SSF_CONFIG_NETWS_UNIT_TEST == 1

/* The scenarios write 3-byte payloads as one frame */
#if SSF_NETWS_CONFIG_TX_FRAME_SIZE < 8
#error ssfnetws_ut.c needs SSF_NETWS_CONFIG_TX_FRAME_SIZE of at least 8.
#endif

/* --------------------------------------------------------------------------------------------- */
/* Local defines and data                                                                        */
/* --------------------------------------------------------------------------------------------- */
#define SSF_NETWS_UT_TX_CAP         (140000u) /* A 65536-byte send at the largest frame size */
#define SSF_NETWS_UT_RX_CAP         (70000u)
#define SSF_NETWS_UT_GUID           "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define SSF_NETWS_UT_OP_CONT        (0x0u)
#define SSF_NETWS_UT_OP_TEXT        (0x1u)
#define SSF_NETWS_UT_OP_BIN         (0x2u)
#define SSF_NETWS_UT_OP_CLOSE       (0x8u)
#define SSF_NETWS_UT_OP_PING        (0x9u)
#define SSF_NETWS_UT_OP_PONG        (0xAu)
#define SSF_NETWS_UT_LOOPS          (64u)

/* Scripted inner transport */
typedef struct
{
    SSFNetTransport_t transport;     /* Must be first */
    bool openResult;
    bool isOpen;
    uint32_t openCount;
    uint32_t closeCount;
    uint32_t shutdownCount;
    char host[SSF_NETWS_CONFIG_MAX_HOST_SIZE + 8u];
    uint16_t port;
    uint32_t pollWant;               /* WANT_WRITE results pollOpen() returns first             */
    SSFNetIOResult_t pollResult;
    uint8_t tx[SSF_NETWS_UT_TX_CAP];
    size_t txLen;
    size_t txChunk;                  /* Most bytes send() takes per call; 0 = all               */
    bool isTxBlocked;                /* send() returns WANT_WRITE                               */
    SSFNetIOResult_t txFail;         /* Not SUCCESS: send() returns it                          */
    uint8_t rx[SSF_NETWS_UT_RX_CAP];
    size_t rxLen;
    size_t rxPos;
    size_t rxChunk;                  /* Most bytes recv() returns per call; 0 = all             */
    bool isRxEof;                    /* recv() returns CLOSED once rx is drained                */
    SSFNetIOResult_t rxFail;
    SSFNetIOResult_t shutdownResult;
} SSFNetWSUTMock_t;

static SSFNetWSUTMock_t _utMock;
static SSFNetWSSession_t _utWS;
static uint8_t _utOut[SSF_NETWS_UT_RX_CAP];
static uint8_t _utPayload[SSF_NETWS_UT_RX_CAP];
static char _utKey[32];

/* --------------------------------------------------------------------------------------------- */
/* Mock transport operations.                                                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSUTOpen(SSFNetTransport_t *t, SSFCStrIn_t host, size_t hostSize,
                            uint16_t port)
{
    size_t len;

    SSF_ASSERT(t == &_utMock.transport);
    SSF_ASSERT(_utMock.isOpen == false);
    SSF_ASSERT(SSFStrLen(host, hostSize, &len));
    SSF_ASSERT(len < sizeof(_utMock.host));
    memcpy(_utMock.host, host, len + 1u);
    _utMock.port = port;
    _utMock.openCount++;
    _utMock.isOpen = _utMock.openResult;
    return _utMock.openResult;
}

static SSFNetIOResult_t _SSFNetWSUTPollOpenFn(SSFNetTransport_t *t)
{
    SSF_ASSERT(t == &_utMock.transport);
    SSF_ASSERT(_utMock.isOpen);
    if (_utMock.pollWant > 0) { _utMock.pollWant--; return SSF_NET_IO_WANT_WRITE; }
    return _utMock.pollResult;
}

static SSFNetIOResult_t _SSFNetWSUTSend(SSFNetTransport_t *t, const uint8_t *buf, size_t len,
                                        size_t *sentOut)
{
    size_t n = len;

    SSF_ASSERT(t == &_utMock.transport);
    SSF_ASSERT(_utMock.isOpen);
    SSF_ASSERT((buf != NULL) && (len > 0) && (sentOut != NULL));
    *sentOut = 0;
    if (_utMock.txFail != SSF_NET_IO_SUCCESS) return _utMock.txFail;
    if (_utMock.isTxBlocked) return SSF_NET_IO_WANT_WRITE;
    if ((_utMock.txChunk != 0) && (n > _utMock.txChunk)) n = _utMock.txChunk;
    SSF_ASSERT((_utMock.txLen + n) <= sizeof(_utMock.tx));
    memcpy(&_utMock.tx[_utMock.txLen], buf, n);
    _utMock.txLen += n;
    *sentOut = n;
    return SSF_NET_IO_SUCCESS;
}

static SSFNetIOResult_t _SSFNetWSUTRecv(SSFNetTransport_t *t, uint8_t *buf, size_t size,
                                        size_t *gotOut)
{
    size_t n;

    SSF_ASSERT(t == &_utMock.transport);
    SSF_ASSERT(_utMock.isOpen);
    SSF_ASSERT((buf != NULL) && (size > 0) && (gotOut != NULL));
    *gotOut = 0;
    if (_utMock.rxFail != SSF_NET_IO_SUCCESS) return _utMock.rxFail;
    if (_utMock.rxPos >= _utMock.rxLen)
    { return _utMock.isRxEof ? SSF_NET_IO_CLOSED : SSF_NET_IO_WANT_READ; }
    n = _utMock.rxLen - _utMock.rxPos;
    if (n > size) n = size;
    if ((_utMock.rxChunk != 0) && (n > _utMock.rxChunk)) n = _utMock.rxChunk;
    memcpy(buf, &_utMock.rx[_utMock.rxPos], n);
    _utMock.rxPos += n;
    *gotOut = n;
    return SSF_NET_IO_SUCCESS;
}

static SSFNetIOResult_t _SSFNetWSUTShutdown(SSFNetTransport_t *t)
{
    SSF_ASSERT(t == &_utMock.transport);
    SSF_ASSERT(_utMock.isOpen);
    _utMock.shutdownCount++;
    return _utMock.shutdownResult;
}

static void _SSFNetWSUTClose(SSFNetTransport_t *t)
{
    SSF_ASSERT(t == &_utMock.transport);
    _utMock.closeCount++;
    _utMock.isOpen = false;
}

/* --------------------------------------------------------------------------------------------- */
/* Resets the mock to a cooperative inner transport.                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTMockReset(void)
{
    memset(&_utMock, 0, sizeof(_utMock));
    _utMock.transport.open = _SSFNetWSUTOpen;
    _utMock.transport.pollOpen = _SSFNetWSUTPollOpenFn;
    _utMock.transport.send = _SSFNetWSUTSend;
    _utMock.transport.recv = _SSFNetWSUTRecv;
    _utMock.transport.shutdown = _SSFNetWSUTShutdown;
    _utMock.transport.close = _SSFNetWSUTClose;
    _utMock.openResult = true;
    _utMock.pollResult = SSF_NET_IO_SUCCESS;
    _utMock.txFail = SSF_NET_IO_SUCCESS;
    _utMock.rxFail = SSF_NET_IO_SUCCESS;
    _utMock.shutdownResult = SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends bytes to the mock's receive script.                                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTInject(const void *bytes, size_t len)
{
    SSF_ASSERT((_utMock.rxLen + len) <= sizeof(_utMock.rx));
    memcpy(&_utMock.rx[_utMock.rxLen], bytes, len);
    _utMock.rxLen += len;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends a server frame. lenWidth 0 picks the minimal length encoding, else 1, 2 or 8 bytes.   */
/* masked sets the MASK bit with key 0 (the payload is unchanged); rsv is ORed into byte 0.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTFrameEx(bool fin, uint8_t rsv, uint8_t opcode, bool masked,
                               uint8_t lenWidth, const uint8_t *payload, uint64_t len)
{
    uint8_t hdr[14];
    size_t n = 0;
    uint8_t m = masked ? 0x80u : 0;

    hdr[n++] = (uint8_t)((fin ? 0x80u : 0) | rsv | opcode);
    if (lenWidth == 0) lenWidth = (len < 126u) ? 1u : ((len <= 0xFFFFu) ? 2u : 8u);
    if (lenWidth == 1u) { hdr[n++] = (uint8_t)(m | (uint8_t)len); }
    else if (lenWidth == 2u)
    { hdr[n++] = (uint8_t)(m | 126u); hdr[n++] = (uint8_t)(len >> 8); hdr[n++] = (uint8_t)len; }
    else
    {
        int i;

        hdr[n++] = (uint8_t)(m | 127u);
        for (i = 7; i >= 0; i--) hdr[n++] = (uint8_t)(len >> (8 * i));
    }
    if (masked) { memset(&hdr[n], 0, 4); n += 4u; }
    _SSFNetWSUTInject(hdr, n);
    if ((payload != NULL) && (len > 0)) _SSFNetWSUTInject(payload, (size_t)len);
}

static void _SSFNetWSUTFrame(bool fin, uint8_t opcode, const void *payload, size_t len)
{
    _SSFNetWSUTFrameEx(fin, 0, opcode, false, 0, (const uint8_t *)payload, len);
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes the client frame at _utMock.tx[*posInOut]: checks FIN, RSV 0, the MASK bit and the    */
/* minimal length encoding, unmasks the payload into out and returns its opcode.                 */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFNetWSUTClientFrame(size_t *posInOut, uint8_t *out, size_t outSize,
                                      size_t *lenOut, uint8_t maskOut[4])
{
    const uint8_t *p = &_utMock.tx[*posInOut];
    size_t avail = _utMock.txLen - *posInOut;
    size_t n = 2;
    uint64_t len;
    size_t i;

    SSF_ASSERT(avail >= 2u);
    SSF_ASSERT((p[0] & 0xF0u) == 0x80u);                 /* FIN, no RSV */
    SSF_ASSERT((p[1] & 0x80u) == 0x80u);                 /* Masked */
    len = p[1] & 0x7Fu;
    if (len == 126u)
    {
        SSF_ASSERT(avail >= 4u);
        len = ((uint64_t)p[2] << 8) | p[3];
        SSF_ASSERT(len >= 126u);
        n = 4;
    }
    else if (len == 127u)
    {
        SSF_ASSERT(avail >= 10u);
        len = 0;
        for (i = 0; i < 8u; i++) len = (len << 8) | p[2 + i];
        SSF_ASSERT(len > 0xFFFFu);
        n = 10;
    }
    SSF_ASSERT(avail >= (n + 4u + (size_t)len));
    SSF_ASSERT(len <= outSize);
    memcpy(maskOut, &p[n], 4);
    for (i = 0; i < (size_t)len; i++) out[i] = (uint8_t)(p[n + 4u + i] ^ maskOut[i & 3u]);
    *lenOut = (size_t)len;
    *posInOut += n + 4u + (size_t)len;
    return (uint8_t)(p[0] & 0x0Fu);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes Sec-WebSocket-Accept for key independently of the code under test.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTAccept(const char *key, char accept[SSF_NETWS_ACCEPT_SIZE])
{
    SSFSHA1Context_t ctx;
    uint8_t h[SSF_SHA1_HASH_SIZE];

    SSFSHA1Begin(&ctx);
    SSFSHA1Update(&ctx, (const uint8_t *)key, (uint32_t)strlen(key));
    SSFSHA1Update(&ctx, (const uint8_t *)SSF_NETWS_UT_GUID, (uint32_t)strlen(SSF_NETWS_UT_GUID));
    SSFSHA1End(&ctx, h);
    SSF_ASSERT(SSFBase64Encode(h, sizeof(h), accept, SSF_NETWS_ACCEPT_SIZE, NULL));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the value of field name in the NUL terminated request text, else NULL.                */
/* --------------------------------------------------------------------------------------------- */
static const char *_SSFNetWSUTReqField(const char *text, const char *name, size_t *valueLenOut)
{
    char pat[64];
    const char *f;
    const char *e;

    (void)snprintf(pat, sizeof(pat), "\r\n%s: ", name);
    f = strstr(text, pat);
    if (f == NULL) return NULL;
    SSF_ASSERT(strstr(f + 1, pat) == NULL);                  /* Exactly once */
    f += strlen(pat);
    e = strstr(f, "\r\n");
    SSF_ASSERT(e != NULL);
    *valueLenOut = (size_t)(e - f);
    return f;
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the Upgrade request at the start of the mock's tx, removes it, and saves its key in    */
/* _utKey. extraOpt is a field line expected verbatim, or NULL.                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTCheckRequest(const char *path, const char *expectedHost,
                                    const char *extraOpt)
{
    static char text[SSF_NETWS_CONFIG_HS_BUF_SIZE + 1u];
    char line[300];
    const char *end;
    const char *v;
    size_t vLen = 0;
    size_t reqLen;
    uint8_t keyBytes[32];
    size_t keyBytesLen;

    SSF_ASSERT(_utMock.txLen < sizeof(text));
    memcpy(text, _utMock.tx, _utMock.txLen);
    text[_utMock.txLen] = 0;
    end = strstr(text, "\r\n\r\n");
    SSF_ASSERT(end != NULL);
    reqLen = (size_t)(end - text) + 4u;
    text[reqLen - 2u] = 0;                                  /* Keep the last field's CRLF */

    (void)snprintf(line, sizeof(line), "GET %s HTTP/1.1\r\n", path);
    SSF_ASSERT(strncmp(text, line, strlen(line)) == 0);
    v = _SSFNetWSUTReqField(text, "Host", &vLen);
    SSF_ASSERT((v != NULL) && (vLen == strlen(expectedHost)));
    SSF_ASSERT(memcmp(v, expectedHost, vLen) == 0);
    v = _SSFNetWSUTReqField(text, "Upgrade", &vLen);
    SSF_ASSERT((v != NULL) && (vLen == 9u) && (memcmp(v, "websocket", 9) == 0));
    v = _SSFNetWSUTReqField(text, "Connection", &vLen);
    SSF_ASSERT((v != NULL) && (vLen == 7u) && (memcmp(v, "Upgrade", 7) == 0));
    v = _SSFNetWSUTReqField(text, "Sec-WebSocket-Version", &vLen);
    SSF_ASSERT((v != NULL) && (vLen == 2u) && (memcmp(v, "13", 2) == 0));
    v = _SSFNetWSUTReqField(text, "Sec-WebSocket-Protocol", &vLen);
    SSF_ASSERT((v != NULL) && (vLen == 4u) && (memcmp(v, "mqtt", 4) == 0));
    v = _SSFNetWSUTReqField(text, "Sec-WebSocket-Key", &vLen);
    SSF_ASSERT((v != NULL) && (vLen == 24u));                  /* base64 of 16 bytes */
    memcpy(_utKey, v, vLen);
    _utKey[vLen] = 0;
    SSF_ASSERT(SSFBase64Decode(_utKey, vLen, keyBytes, sizeof(keyBytes), &keyBytesLen));
    SSF_ASSERT(keyBytesLen == 16u);
    SSF_ASSERT(strstr(text, "Sec-WebSocket-Extensions") == NULL);
    if (extraOpt != NULL)
    {
        (void)snprintf(line, sizeof(line), "\r\n%s\r\n", extraOpt);
        SSF_ASSERT(strstr(text, line) != NULL);
    }

    /* Remove the request: what follows in tx is frames */
    memmove(_utMock.tx, &_utMock.tx[reqLen], _utMock.txLen - reqLen);
    _utMock.txLen -= reqLen;
}

/* --------------------------------------------------------------------------------------------- */
/* Injects a 101 response carrying the right accept for _utKey plus extraFields (each line       */
/* ending in CRLF), followed by trailerOpt bytes.                                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTRespond(const char *extraFields, const uint8_t *trailerOpt,
                               size_t trailerLen)
{
    char accept[SSF_NETWS_ACCEPT_SIZE];
    char resp[900];
    int n;

    _SSFNetWSUTAccept(_utKey, accept);
    n = snprintf(resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s\r\n", accept, extraFields);
    SSF_ASSERT((n > 0) && ((size_t)n < sizeof(resp)));
    _SSFNetWSUTInject(resp, (size_t)n);
    if (trailerOpt != NULL) _SSFNetWSUTInject(trailerOpt, trailerLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Calls pollOpen() until it stops returning WANT_*, at most SSF_NETWS_UT_LOOPS times.           */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSUTPollOpen(void)
{
    SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
    uint32_t i;

    for (i = 0; i < SSF_NETWS_UT_LOOPS; i++)
    {
        r = _utWS.transport.pollOpen(&_utWS.transport);
        if ((r != SSF_NET_IO_WANT_READ) && (r != SSF_NET_IO_WANT_WRITE)) break;
    }
    return r;
}

/* --------------------------------------------------------------------------------------------- */
/* Fresh mock and session for "/mqtt" on broker.example:8080, taken through the handshake to     */
/* the point of the response.                                                                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTToResponse(void)
{
    _SSFNetWSUTMockReset();
    SSFNetWSInit(&_utWS, &_utMock.transport, "/mqtt", NULL, 0);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "broker.example", 15, 8080));
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_WANT_READ);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_HS_RECV);
    _SSFNetWSUTCheckRequest("/mqtt", "broker.example:8080", NULL);
}

/* --------------------------------------------------------------------------------------------- */
/* Fresh mock and session taken to OPEN.                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTGoOpen(void)
{
    _SSFNetWSUTToResponse();
    _SSFNetWSUTRespond("Sec-WebSocket-Protocol: mqtt\r\n", NULL, 0);
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_OPEN);
    SSF_ASSERT(_utMock.txLen == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Closes and deinitializes the session.                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTEnd(void)
{
    _utWS.transport.close(&_utWS.transport);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_CLOSED);
    SSF_ASSERT(_utMock.isOpen == false);
    SSFNetWSDeInit(&_utWS);
}

/* --------------------------------------------------------------------------------------------- */
/* Reads up to want bytes into _utOut with reads of at most chunk bytes, until want bytes, a     */
/* run of WANT_READ, or a failure; returns the total and the last result in *rOut.               */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFNetWSUTRead(size_t want, size_t chunk, SSFNetIOResult_t *rOut)
{
    size_t total = 0;
    SSFNetIOResult_t r = SSF_NET_IO_SUCCESS;
    uint32_t idle = 0;

    while ((total < want) && (idle < SSF_NETWS_UT_LOOPS))
    {
        size_t got = 99;
        size_t n = want - total;

        if (n > chunk) n = chunk;
        r = _utWS.transport.recv(&_utWS.transport, &_utOut[total], n, &got);
        if (r == SSF_NET_IO_SUCCESS)
        { SSF_ASSERT((got >= 1u) && (got <= n)); total += got; idle = 0; }
        else if (r == SSF_NET_IO_WANT_READ) { SSF_ASSERT(got == 0); idle++; }
        else { SSF_ASSERT(got == 0); break; }
    }
    *rOut = r;
    return total;
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the accept computation against RFC 6455 1.3 and the init requirements.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioBasics(void)
{
    char accept[SSF_NETWS_ACCEPT_SIZE];
    SSFNetTransport_t bad;

    _SSFNetWSAcceptForTest("dGhlIHNhbXBsZSBub25jZQ==", accept);
    SSF_ASSERT(strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
    _SSFNetWSUTAccept("dGhlIHNhbXBsZSBub25jZQ==", accept);
    SSF_ASSERT(strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);

    _SSFNetWSUTMockReset();
    memset(&_utWS, 0, sizeof(_utWS));
    SSF_ASSERT_TEST(SSFNetWSInit(NULL, &_utMock.transport, "/", NULL, 0));
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, NULL, "/", NULL, 0));
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &_utMock.transport, NULL, NULL, 0));
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 1));
    bad = _utMock.transport; bad.open = NULL;
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &bad, "/", NULL, 0));
    bad = _utMock.transport; bad.pollOpen = NULL;
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &bad, "/", NULL, 0));
    bad = _utMock.transport; bad.send = NULL;
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &bad, "/", NULL, 0));
    bad = _utMock.transport; bad.recv = NULL;
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &bad, "/", NULL, 0));
    bad = _utMock.transport; bad.shutdown = NULL;
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &bad, "/", NULL, 0));
    bad = _utMock.transport; bad.close = NULL;
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &bad, "/", NULL, 0));

    SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 0);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_CLOSED);
    SSF_ASSERT_TEST(SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 0));  /* Twice */
    SSFNetWSDeInit(&_utWS);
    SSF_ASSERT_TEST(SSFNetWSDeInit(&_utWS));
    SSF_ASSERT_TEST((void)SSFNetWSGetState(NULL));
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that open() refuses bad arguments and configuration before touching the inner, and      */
/* that the other calls fail cleanly when not open.                                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioOpenRefused(void)
{
    static const SSFHTTPHdrField_t okField[] = { { "Authorization", "Bearer x" } };
    static const SSFHTTPHdrField_t badFields[][1] =
    {
        { { "Upgrade", "x" } }, { { "connection", "x" } }, { { "Host", "x" } },
        { { "Sec-WebSocket-Key", "x" } }, { { "SEC-WEBSOCKET-PROTOCOL", "x" } },
        { { "sec-websocket-extensions", "x" } }, { { "Sec-WebSocket-Version", "13" } },
        { { "Sec-WebSocket-", "x" } }, { { "X-Bad", "a\r\nInjected: 1" } }, { { "UPGRADE", "x" } },
        { { "HOST", "x" } }, { { "Content-Length", "5" } }, { { "transfer-encoding", "chunked" } },
        { { "Bad Name", "x" } }, { { "", "x" } },
    };
    static const char *const badPaths[] = { "", "/a b", "/a\r\nX: y", "/#", "/\x80" };
    static char longHost[SSF_NETWS_CONFIG_MAX_HOST_SIZE + 1u];
    static char longPath[SSF_NETWS_CONFIG_HS_BUF_SIZE];
    size_t i;
    size_t n;
    uint8_t b[4] = { 0 };

    memset(longHost, 'h', sizeof(longHost) - 1u);
    longHost[sizeof(longHost) - 1u] = 0;
    longPath[0] = '/';
    memset(&longPath[1], 'p', sizeof(longPath) - 2u);
    longPath[sizeof(longPath) - 1u] = 0;

    _SSFNetWSUTMockReset();
    SSFNetWSInit(&_utWS, &_utMock.transport, "/mqtt", okField, 1);
    SSF_ASSERT_TEST((void)_utWS.transport.open(&_utWS.transport, NULL, 2, 80));
    SSF_ASSERT_TEST((void)_utWS.transport.open(&_utWS.transport, "h", 0, 80));
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "", 1, 80) == false);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "hh", 2, 80) == false);  /* No NUL */
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 0) == false);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "::1", 4, 80) == false);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, longHost, sizeof(longHost), 80) == false);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "a b", 4, 80) == false);
    SSF_ASSERT(_utMock.openCount == 0);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_CLOSED);

    /* The inner refusing the open */
    _utMock.openResult = false;
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80) == false);
    SSF_ASSERT(_utMock.openCount == 1);
    SSF_ASSERT(_utMock.closeCount == 0);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_CLOSED);
    SSFNetWSDeInit(&_utWS);

    for (i = 0; i < (sizeof(badFields) / sizeof(badFields[0])); i++)
    {
        _SSFNetWSUTMockReset();
        SSFNetWSInit(&_utWS, &_utMock.transport, "/mqtt", badFields[i], 1);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80) == false);
        SSF_ASSERT(_utMock.openCount == 0);
        SSFNetWSDeInit(&_utWS);
    }
    for (i = 0; i < (sizeof(badPaths) / sizeof(badPaths[0])); i++)
    {
        _SSFNetWSUTMockReset();
        SSFNetWSInit(&_utWS, &_utMock.transport, badPaths[i], NULL, 0);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80) == false);
        SSF_ASSERT(_utMock.openCount == 0);
        SSFNetWSDeInit(&_utWS);
    }

    /* A request that does not fit the handshake buffer */
    _SSFNetWSUTMockReset();
    SSFNetWSInit(&_utWS, &_utMock.transport, longPath, NULL, 0);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80) == false);
    SSF_ASSERT(_utMock.openCount == 0);
    SSFNetWSDeInit(&_utWS);

    /* Names that only resemble reserved ones are allowed; a host one byte under the limit fits */
    {
        static const SSFHTTPHdrField_t near[] =
        { { "Hostx", "1" }, { "Hos", "2" }, { "X-Upgrade", "3" }, { "Sec-WebSocke", "4" },
          { "Content-Lengths", "5" } };

        _SSFNetWSUTMockReset();
        SSFNetWSInit(&_utWS, &_utMock.transport, "/", near, 5);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80));
        SSF_ASSERT(_utMock.openCount == 1);
        _utWS.transport.close(&_utWS.transport);
#if SSF_NETWS_CONFIG_HS_BUF_SIZE >= (SSF_NETWS_CONFIG_MAX_HOST_SIZE + 256u)
        longHost[sizeof(longHost) - 2u] = 0;                    /* MAX_HOST_SIZE - 1 chars */
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, longHost, sizeof(longHost), 80));
        SSF_ASSERT(_utMock.openCount == 2u);
        _utWS.transport.close(&_utWS.transport);
#endif
        SSFNetWSDeInit(&_utWS);
    }

    /* Calls that need a connection */
    _SSFNetWSUTMockReset();
    SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 0);
    SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_ERROR);
    n = 99;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
    SSF_ASSERT(n == 0);
    n = 99;
    SSF_ASSERT(_utWS.transport.recv(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
    SSF_ASSERT(n == 0);
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_ERROR);
    _utWS.transport.close(&_utWS.transport);                    /* Harmless when closed */
    SSF_ASSERT(_utMock.closeCount == 0);
    SSF_ASSERT_TEST((void)_utWS.transport.send(&_utWS.transport, NULL, 1, &n));
    SSF_ASSERT_TEST((void)_utWS.transport.send(&_utWS.transport, b, 0, &n));
    SSF_ASSERT_TEST((void)_utWS.transport.send(&_utWS.transport, b, 1, NULL));
    SSF_ASSERT_TEST((void)_utWS.transport.recv(&_utWS.transport, NULL, 1, &n));
    SSF_ASSERT_TEST((void)_utWS.transport.recv(&_utWS.transport, b, 0, &n));
    SSF_ASSERT_TEST((void)_utWS.transport.recv(&_utWS.transport, b, 1, NULL));
    SSFNetWSDeInit(&_utWS);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the session struct contains needle anywhere.                                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSUTSessionHas(const char *needle)
{
    const uint8_t *p = (const uint8_t *)&_utWS;
    size_t n = strlen(needle);
    size_t i;

    for (i = 0; (i + n) <= sizeof(_utWS); i++) { if (memcmp(&p[i], needle, n) == 0) return true; }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Injects fmt with its one %s replaced by the right accept for _utKey.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTRespondRaw(const char *fmt)
{
    char accept[SSF_NETWS_ACCEPT_SIZE];
    const char *at = strstr(fmt, "%s");
    size_t i;

    _SSFNetWSUTAccept(_utKey, accept);
    if (at == NULL)
    {
        /* %S: the accept with the case of every letter swapped */
        at = strstr(fmt, "%S");
        for (i = 0; accept[i] != 0; i++)
        {
            if ((accept[i] >= 'a') && (accept[i] <= 'z')) accept[i] = (char)(accept[i] - 32);
            else if ((accept[i] >= 'A') && (accept[i] <= 'Z')) accept[i] = (char)(accept[i] + 32);
        }
    }
    SSF_ASSERT(at != NULL);
    _SSFNetWSUTInject(fmt, (size_t)(at - fmt));
    _SSFNetWSUTInject(accept, strlen(accept));
    _SSFNetWSUTInject(at + 2, strlen(at + 2));
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts the session failed: every call but close() now returns ERROR.                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTExpectFailed(void)
{
    uint8_t b[4] = { 0 };
    size_t n = 99;

    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_FAILED);
    SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_ERROR);
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
    SSF_ASSERT(n == 0);
    n = 99;
    SSF_ASSERT(_utWS.transport.recv(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
    SSF_ASSERT(n == 0);
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_ERROR);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the handshake: request contents, the Host port rule, inner progress, split responses,   */
/* leftover bytes, secrets wiped, and reopening.                                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioHandshake(void)
{
    static const SSFHTTPHdrField_t fields[] =
    { { "Authorization", "Bearer t0k3n" }, { "X-Client", "ssf" } };
    static const uint8_t frame[] = { 0x82, 0x03, 'a', 'b', 'c' };
    static const uint16_t ports[] = { 80, 443, 8080, 1 };
    static const char *const hostFields[] = { "h.example", "h.example", "h.example:8080",
                                              "h.example:1" };
    char prevKey[sizeof(_utKey)];
    SSFNetIOResult_t r;
    size_t i;

    /* Extra fields and a query; the inner pollOpen() is driven to completion first; the        */
    /* request leaves in pieces; the response arrives one byte per read with a frame behind it  */
    _SSFNetWSUTMockReset();
    _utMock.pollWant = 3;
    _utMock.txChunk = 7;
    _utMock.rxChunk = 1;
    SSFNetWSInit(&_utWS, &_utMock.transport, "/mqtt?token=a%2Fb", fields, 2);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h.example", 10, 8883));
    SSF_ASSERT(_utMock.openCount == 1);
    SSF_ASSERT((strcmp(_utMock.host, "h.example") == 0) && (_utMock.port == 8883));
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_OPENING);
    SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_WANT_WRITE);
    SSF_ASSERT(_utMock.txLen == 0);
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_WANT_READ);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_HS_RECV);
    SSF_ASSERT(_SSFNetWSUTSessionHas("t0k3n") == false);        /* Wiped once sent */
    _SSFNetWSUTCheckRequest("/mqtt?token=a%2Fb", "h.example:8883", "Authorization: Bearer t0k3n");
    SSF_ASSERT(_utMock.txLen == 0);
    _SSFNetWSUTRespond("Sec-WebSocket-Protocol: mqtt\r\nX-Other: 1\r\n", frame, sizeof(frame));
    for (i = 0; i < 1000u; i++)
    {
        r = _utWS.transport.pollOpen(&_utWS.transport);
        if (r != SSF_NET_IO_WANT_READ) break;
    }
    SSF_ASSERT(r == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_OPEN);
    SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_SUCCESS);  /* Again */
    {
        char accept[SSF_NETWS_ACCEPT_SIZE];

        _SSFNetWSUTAccept(_utKey, accept);
        SSF_ASSERT(_SSFNetWSUTSessionHas(accept) == false);     /* Wiped once used */
    }
    SSF_ASSERT(_SSFNetWSUTRead(3, 3, &r) == 3u);
    SSF_ASSERT(memcmp(_utOut, "abc", 3) == 0);

    /* Close wipes; a reopen uses a new key */
    memcpy(prevKey, _utKey, sizeof(prevKey));
    _utWS.transport.close(&_utWS.transport);
    SSF_ASSERT(_utMock.closeCount == 1);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_CLOSED);
    SSF_ASSERT(_SSFNetWSUTSessionHas("Switching") == false);
    _utMock.txLen = 0;
    _utMock.rxLen = _utMock.rxPos = 0;
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h.example", 10, 8883));
    SSF_ASSERT_TEST((void)_utWS.transport.open(&_utWS.transport, "h.example", 10, 8883));
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_WANT_READ);
    _SSFNetWSUTCheckRequest("/mqtt?token=a%2Fb", "h.example:8883", "X-Client: ssf");
    SSF_ASSERT(strcmp(prevKey, _utKey) != 0);
    _SSFNetWSUTRespond("", NULL, 0);                            /* No subprotocol: accepted */
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_SUCCESS);
    SSFNetWSDeInit(&_utWS);                                     /* While open: closes the inner */
    SSF_ASSERT((_utMock.closeCount == 2u) && (_utMock.isOpen == false));

    /* Host carries the port unless it is 80 or 443 */
    for (i = 0; i < (sizeof(ports) / sizeof(ports[0])); i++)
    {
        _SSFNetWSUTMockReset();
        SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 0);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h.example", 10, ports[i]));
        SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_WANT_READ);
        _SSFNetWSUTCheckRequest("/", hostFields[i], NULL);
        _SSFNetWSUTEnd();
    }

    /* A blocked inner during the request: WANT_WRITE until it can take bytes */
    _SSFNetWSUTMockReset();
    _utMock.isTxBlocked = true;
    SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 0);
    SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80));
    SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_WANT_WRITE);
    SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_WANT_WRITE);
    SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_HS_SEND);
    _utMock.isTxBlocked = false;
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_WANT_READ);
    _SSFNetWSUTCheckRequest("/", "h", NULL);
    _SSFNetWSUTEnd();

    /* Responses that are accepted */
    {
        static const char *const ok[] =
        {
            "HTTP/1.1 101 \r\nUPGRADE: WebSocket\r\nconnection: keep-alive, upgrade\r\n"
            "sec-websocket-accept: %s\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nConnection: close\r\n"
            "Upgrade: websocket\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: mqtt\r\n"
            "Server: x\r\n\r\n",
        };

        for (i = 0; i < (sizeof(ok) / sizeof(ok[0])); i++)
        {
            _SSFNetWSUTToResponse();
            _SSFNetWSUTRespondRaw(ok[i]);
            SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_SUCCESS);
            _SSFNetWSUTEnd();
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that every bad response, and every inner failure, fails the open.                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioHandshakeRefused(void)
{
    static const char *const bad[] =
    {
        "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 301 Moved\r\nLocation: /x\r\nX: %s\r\n\r\n",
        "HTTP/1.1 401 No\r\nWWW-Authenticate: Basic\r\nX: %s\r\n\r\n",
        "HTTP/1.0 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/2.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket, h2c\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Accept: x\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX: %s\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %S\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Extensions:\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: mqttv3.1\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: MQTT\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: mqtt\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\nX: a\r\n b\r\n\r\n",
        "HTTP/1.1 101 x\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
    };
    static char big[SSF_NETWS_CONFIG_HS_BUF_SIZE + 64u];
    size_t i;

    for (i = 0; i < (sizeof(bad) / sizeof(bad[0])); i++)
    {
        _SSFNetWSUTToResponse();
        _SSFNetWSUTRespondRaw(bad[i]);
        SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_ERROR);
        _SSFNetWSUTExpectFailed();
        SSF_ASSERT(_utMock.closeCount == 0);                    /* close() is the caller's */
        _SSFNetWSUTEnd();
        SSF_ASSERT(_utMock.closeCount == 1);
        SSF_ASSERT(_utMock.txLen == 0);                         /* No Close frame */
    }

    /* A head larger than the buffer, with no end in sight */
    _SSFNetWSUTToResponse();
    memcpy(big, "HTTP/1.1 101 x\r\nX: ", 19);
    memset(&big[19], 'v', sizeof(big) - 19u);
    _SSFNetWSUTInject(big, sizeof(big));
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_ERROR);
    _SSFNetWSUTExpectFailed();
    _SSFNetWSUTEnd();

    /* The peer ending the stream, or the inner failing, mid-response */
    _SSFNetWSUTToResponse();
    _SSFNetWSUTInject("HTTP/1.1 101", 12);
    _utMock.isRxEof = true;
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_CLOSED);
    _SSFNetWSUTExpectFailed();
    _SSFNetWSUTEnd();
    _SSFNetWSUTToResponse();
    _utMock.rxFail = SSF_NET_IO_ERROR;
    SSF_ASSERT(_SSFNetWSUTPollOpen() == SSF_NET_IO_ERROR);
    _SSFNetWSUTExpectFailed();
    _SSFNetWSUTEnd();

    /* The inner open failing, and the inner failing while the request is sent */
    for (i = 0; i < 2u; i++)
    {
        _SSFNetWSUTMockReset();
        _utMock.pollResult = (i == 0) ? SSF_NET_IO_ERROR : SSF_NET_IO_CLOSED;
        SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 0);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80));
        SSF_ASSERT(_SSFNetWSUTPollOpen() == _utMock.pollResult);
        _SSFNetWSUTExpectFailed();
        _SSFNetWSUTEnd();

        _SSFNetWSUTMockReset();
        _utMock.txFail = (i == 0) ? SSF_NET_IO_ERROR : SSF_NET_IO_CLOSED;
        SSFNetWSInit(&_utWS, &_utMock.transport, "/", NULL, 0);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80));
        SSF_ASSERT(_SSFNetWSUTPollOpen() == _utMock.txFail);
        _SSFNetWSUTExpectFailed();
        _SSFNetWSUTEnd();
    }

    /* Credentials are wiped when the inner fails part way through the request */
    {
        static const SSFHTTPHdrField_t secret[] = { { "Authorization", "Bearer s3cr3t" } };

        _SSFNetWSUTMockReset();
        _utMock.txChunk = 5;
        SSFNetWSInit(&_utWS, &_utMock.transport, "/", secret, 1);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80));
        SSF_ASSERT(_SSFNetWSUTSessionHas("s3cr3t"));
        SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_WANT_READ);
        _SSFNetWSUTMockReset();
        _utMock.isOpen = true;
        SSFNetWSDeInit(&_utWS);
        _SSFNetWSUTMockReset();
        _utMock.txFail = SSF_NET_IO_ERROR;
        SSFNetWSInit(&_utWS, &_utMock.transport, "/", secret, 1);
        SSF_ASSERT(_utWS.transport.open(&_utWS.transport, "h", 2, 80));
        SSF_ASSERT(_utWS.transport.pollOpen(&_utWS.transport) == SSF_NET_IO_ERROR);
        _utWS.transport.close(&_utWS.transport);
        SSF_ASSERT(_SSFNetWSUTSessionHas("s3cr3t") == false);
        SSFNetWSDeInit(&_utWS);
    }

    /* send() and recv() are not valid while the handshake runs */
    {
        uint8_t b[4] = { 0 };
        size_t n = 99;

        _SSFNetWSUTToResponse();
        SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
        SSF_ASSERT(_utWS.transport.recv(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
        SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_ERROR);
        _SSFNetWSUTEnd();
        SSF_ASSERT(_utMock.txLen == 0);                         /* No Close while handshaking */
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Sends total bytes, calling send() until all are accepted; returns the number of calls.        */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFNetWSUTSendAll(const uint8_t *data, size_t total)
{
    size_t done = 0;
    uint32_t calls = 0;

    while (done < total)
    {
        size_t n = 99;
        SSFNetIOResult_t r = _utWS.transport.send(&_utWS.transport, &data[done], total - done, &n);

        SSF_ASSERT(calls++ < 100000u);
        if (r == SSF_NET_IO_WANT_WRITE) { SSF_ASSERT(n == 0); continue; }
        SSF_ASSERT(r == SSF_NET_IO_SUCCESS);
        SSF_ASSERT((n >= 1u) && (n <= SSF_NETWS_CONFIG_TX_FRAME_SIZE) && (n <= (total - done)));
        done += n;
    }
    return calls;
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes all client frames in the mock's tx into _utOut; asserts each is binary unless it is   */
/* listed; returns the payload total and the frame count.                                        */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFNetWSUTDecodeAll(uint32_t *framesOut, bool *isMaskVariedOut)
{
    size_t pos = 0;
    size_t total = 0;
    uint8_t first[4] = { 0 };
    uint8_t mask[4];

    *framesOut = 0;
    *isMaskVariedOut = false;
    while (pos < _utMock.txLen)
    {
        size_t len;

        SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, &_utOut[total], sizeof(_utOut) - total, &len,
                                          mask) == SSF_NETWS_UT_OP_BIN);
        SSF_ASSERT((len >= 1u) && (len <= SSF_NETWS_CONFIG_TX_FRAME_SIZE));
        if (*framesOut == 0) memcpy(first, mask, 4);
        else if (memcmp(first, mask, 4) != 0) *isMaskVariedOut = true;
        total += len;
        (*framesOut)++;
    }
    return total;
}

/* --------------------------------------------------------------------------------------------- */
/* Tests outbound framing: sizes, masking, partial and blocked inner writes, failures.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioSend(void)
{
    static const size_t sizes[] = { 1, 125, 126, 127, SSF_NETWS_CONFIG_TX_FRAME_SIZE,
                                    SSF_NETWS_CONFIG_TX_FRAME_SIZE + 1u, 1000, 4097 };
    static const size_t chunks[] = { 0, 1, 3, 13 };
    size_t i;
    size_t c;
    uint32_t frames;
    bool isVaried;
    size_t n;
    uint8_t b[2] = { 1, 2 };

    for (i = 0; i < sizeof(_utPayload); i++) _utPayload[i] = (uint8_t)((i * 7u) + 3u);

    for (c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++)
    {
        for (i = 0; i < (sizeof(sizes) / sizeof(sizes[0])); i++)
        {
            _SSFNetWSUTGoOpen();
            _utMock.txChunk = chunks[c];
            (void)_SSFNetWSUTSendAll(_utPayload, sizes[i]);
            SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) != SSF_NET_IO_ERROR);
            while (_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_WANT_WRITE) { }
            /* The Close is last; take it off before decoding the data frames */
            {
                size_t pos;
                size_t len;
                uint8_t mask[4];
                size_t closeAt = _utMock.txLen - 8u;            /* 2 + 4 + code 2 */

                pos = closeAt;
                SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
                           SSF_NETWS_UT_OP_CLOSE);
                SSF_ASSERT((len == 2u) && (_utOut[0] == 0x03u) && (_utOut[1] == 0xE8u));
                _utMock.txLen = closeAt;
            }
            SSF_ASSERT(_SSFNetWSUTDecodeAll(&frames, &isVaried) == sizes[i]);
            SSF_ASSERT(memcmp(_utOut, _utPayload, sizes[i]) == 0);
            SSF_ASSERT(frames == ((sizes[i] + SSF_NETWS_CONFIG_TX_FRAME_SIZE - 1u) /
                                  SSF_NETWS_CONFIG_TX_FRAME_SIZE));
            if (frames >= 4u) { SSF_ASSERT(isVaried); }
            SSF_ASSERT(_utMock.shutdownCount >= 1u);
            _SSFNetWSUTEnd();
        }
    }

    /* A blocked inner: the first send is accepted into the frame buffer, the next waits; recv() */
    /* keeps the buffered frame moving                                                           */
    _SSFNetWSUTGoOpen();
    _utMock.isTxBlocked = true;
    n = 99;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 2, &n) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(n == 2u);
    n = 99;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 2, &n) == SSF_NET_IO_WANT_WRITE);
    SSF_ASSERT(n == 0);
    SSF_ASSERT(_utMock.txLen == 0);
    _utMock.isTxBlocked = false;
    _utMock.txChunk = 1;
    for (i = 0; i < 20u; i++) { (void)_utWS.transport.recv(&_utWS.transport, b, 1, &n); }
    SSF_ASSERT(_utMock.txLen == 8u);                            /* 2 + 4 + 2 */
    SSF_ASSERT(_SSFNetWSUTDecodeAll(&frames, &isVaried) == 2u);
    SSF_ASSERT((_utOut[0] == 1u) && (_utOut[1] == 2u));
    _SSFNetWSUTEnd();

    /* The inner failing */
    for (i = 0; i < 2u; i++)
    {
        _SSFNetWSUTGoOpen();
        _utMock.txFail = (i == 0) ? SSF_NET_IO_ERROR : SSF_NET_IO_CLOSED;
        n = 99;
        SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 2, &n) == _utMock.txFail);
        SSF_ASSERT(n == 0);
        _SSFNetWSUTExpectFailed();
        _utMock.txFail = SSF_NET_IO_SUCCESS;
        _SSFNetWSUTEnd();
        SSF_ASSERT(_utMock.txLen == 0);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests inbound framing: length boundaries and encodings, streaming large frames, frames split  */
/* across reads, several frames per read, fragmentation and empty frames.                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioRecv(void)
{
    static const size_t sizes[] = { 0, 1, 125, 126, 127, 65535, 65536, 65537 };
    static const size_t reads[] = { 1, 100, 70000 };
    static const uint8_t mqttConnAck[] = { 0x20, 0x02, 0x00, 0x00 };
    SSFNetIOResult_t r;
    size_t i;
    size_t k;
    size_t got;
    uint8_t mask[4];
    size_t pos;
    size_t len;

    for (i = 0; i < sizeof(_utPayload); i++) _utPayload[i] = (uint8_t)((i * 13u) + 1u);

    /* Each size, through readers of several sizes */
    for (k = 0; k < (sizeof(reads) / sizeof(reads[0])); k++)
    {
        for (i = 0; i < (sizeof(sizes) / sizeof(sizes[0])); i++)
        {
            if ((reads[k] == 1u) && (sizes[i] > 200u)) continue;
            _SSFNetWSUTGoOpen();
            _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, _utPayload, sizes[i]);
            _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "Z", 1);
            got = _SSFNetWSUTRead(sizes[i] + 1u, reads[k], &r);
            SSF_ASSERT(got == (sizes[i] + 1u));
            SSF_ASSERT(memcmp(_utOut, _utPayload, sizes[i]) == 0);
            SSF_ASSERT(_utOut[sizes[i]] == 'Z');
            SSF_ASSERT(_SSFNetWSUTRead(1, 1, &r) == 0);
            SSF_ASSERT(r == SSF_NET_IO_WANT_READ);
            SSF_ASSERT(_utMock.txLen == 0);
            _SSFNetWSUTEnd();
        }
    }

    /* Non-minimal length encodings are accepted */
    _SSFNetWSUTGoOpen();
    _SSFNetWSUTFrameEx(true, 0, SSF_NETWS_UT_OP_BIN, false, 2, (const uint8_t *)"ab", 2);
    _SSFNetWSUTFrameEx(true, 0, SSF_NETWS_UT_OP_BIN, false, 8, (const uint8_t *)"cd", 2);
    _SSFNetWSUTFrameEx(true, 0, SSF_NETWS_UT_OP_BIN, false, 8, _utPayload, 300);
    SSF_ASSERT(_SSFNetWSUTRead(304, 1000, &r) == 304u);
    SSF_ASSERT(memcmp(_utOut, "abcd", 4) == 0);
    SSF_ASSERT(memcmp(&_utOut[4], _utPayload, 300) == 0);
    _SSFNetWSUTEnd();

    /* Several frames are returned by one read when the reader has room */
    _SSFNetWSUTGoOpen();
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "abc", 3);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "", 0);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "de", 2);
    got = 0;
    SSF_ASSERT(_utWS.transport.recv(&_utWS.transport, _utOut, 100, &got) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT((got == 5u) && (memcmp(_utOut, "abcde", 5) == 0));
    _SSFNetWSUTEnd();

    /* Every header form split across reads one byte at a time, and an MQTT packet split across */
    /* frames                                                                                    */
    _SSFNetWSUTGoOpen();
    _utMock.rxChunk = 1;
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, &mqttConnAck[0], 1);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, &mqttConnAck[1], 3);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, _utPayload, 130);
    _SSFNetWSUTFrameEx(true, 0, SSF_NETWS_UT_OP_BIN, false, 8, _utPayload, 3);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "p", 1);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "q", 1);
    SSF_ASSERT(_SSFNetWSUTRead(4u + 130u + 3u + 1u, 10, &r) == 138u);
    SSF_ASSERT(memcmp(_utOut, mqttConnAck, 4) == 0);
    SSF_ASSERT(memcmp(&_utOut[4], _utPayload, 130) == 0);
    SSF_ASSERT(memcmp(&_utOut[134], _utPayload, 3) == 0);
    SSF_ASSERT(_utOut[137] == 'q');
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_PONG);
    SSF_ASSERT((len == 1u) && (_utOut[0] == 'p') && (pos == _utMock.txLen));
    _SSFNetWSUTEnd();

    /* A fragmented message with a Ping inside it and empty fragments */
    _SSFNetWSUTGoOpen();
    _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_BIN, "ab", 2);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "x", 1);
    _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_CONT, "", 0);
    _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_CONT, "cd", 2);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PONG, "y", 1);       /* Ignored */
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CONT, "ef", 2);
    _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_BIN, "", 0);       /* A second message */
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CONT, "g", 1);
    SSF_ASSERT(_SSFNetWSUTRead(7, 3, &r) == 7u);
    SSF_ASSERT(memcmp(_utOut, "abcdefg", 7) == 0);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_PONG);
    SSF_ASSERT((len == 1u) && (_utOut[0] == 'x') && (pos == _utMock.txLen));
    _SSFNetWSUTEnd();

    /* The inner ending or failing */
    for (i = 0; i < 2u; i++)
    {
        _SSFNetWSUTGoOpen();
        _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, _utPayload, 10);
        _utMock.rxLen -= 4u;                                    /* Mid-frame */
        if (i == 0) _utMock.isRxEof = true;
        SSF_ASSERT(_SSFNetWSUTRead(10, 100, &r) == 6u);
        if (i == 1)
        {
            SSF_ASSERT(r == SSF_NET_IO_WANT_READ);
            _utMock.rxFail = SSF_NET_IO_ERROR;
            SSF_ASSERT(_SSFNetWSUTRead(10, 100, &r) == 0);
            SSF_ASSERT(r == SSF_NET_IO_ERROR);
            _SSFNetWSUTExpectFailed();
        }
        else { SSF_ASSERT(r == SSF_NET_IO_CLOSED); }
        _utMock.rxFail = SSF_NET_IO_SUCCESS;
        _SSFNetWSUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that every protocol violation in a server frame fails the connection, after any data    */
/* that preceded it in the same read has been returned.                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioRecvRefused(void)
{
    static uint8_t ctl126[126];
    SSFNetIOResult_t r;
    uint32_t v;
    uint8_t op;
    size_t got;

    for (v = 0; v < 40u; v++)
    {
        bool isBad = true;

        _SSFNetWSUTGoOpen();
        _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "ok", 2);
        switch (v)
        {
        case 0: _SSFNetWSUTFrameEx(true, 0, SSF_NETWS_UT_OP_BIN, true, 0,
                                   (const uint8_t *)"m", 1); break;            /* Masked */
        case 1: _SSFNetWSUTFrameEx(true, 0x40u, SSF_NETWS_UT_OP_BIN, false, 0,
                                   (const uint8_t *)"r", 1); break;            /* RSV1 */
        case 2: _SSFNetWSUTFrameEx(true, 0x20u, SSF_NETWS_UT_OP_BIN, false, 0,
                                   (const uint8_t *)"r", 1); break;            /* RSV2 */
        case 3: _SSFNetWSUTFrameEx(true, 0x10u, SSF_NETWS_UT_OP_BIN, false, 0,
                                   (const uint8_t *)"r", 1); break;            /* RSV3 */
        case 4: _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_TEXT, "t", 1); break;
        case 5: _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CONT, "c", 1); break;   /* No message */
        case 6: _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_BIN, "a", 1);
                _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "b", 1); break;    /* Overlap */
        case 7: _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_PING, "p", 1); break;  /* Fragmented */
        case 8: _SSFNetWSUTFrameEx(true, 0, SSF_NETWS_UT_OP_PING, false, 2, ctl126, 126); break;
        case 9: _SSFNetWSUTFrameEx(true, 0, SSF_NETWS_UT_OP_CLOSE, false, 2, ctl126, 126); break;
        case 10:
        {
            static const uint8_t huge[] = { 0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0 };
            _SSFNetWSUTInject(huge, sizeof(huge)); break;                      /* 2^63 */
        }
        case 11: _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CLOSE, "\x03", 1); break;
        case 12: _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_BIN, "a", 1);
                 _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_TEXT, "b", 1); break;
        case 13: _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_CLOSE, "", 0); break;
        case 14: _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_PONG, "", 0); break;
        case 15: _SSFNetWSUTFrame(false, SSF_NETWS_UT_OP_TEXT, "t", 1); break;
        default:
            /* Reserved opcodes 3..7 and 0xB..0xF, then a few that are fine */
            op = (uint8_t)((v < 21u) ? (v - 13u) : (v - 10u));
            if (v >= 26u)
            {
                isBad = false;
                if (v == 26u) _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, ctl126, 125);
                else if (v == 27u) _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PONG, ctl126, 125);
                else if (v == 28u) _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, ctl126, 126);
                else _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "", 0);
            }
            else { _SSFNetWSUTFrame(true, op, "o", 1); }
            break;
        }
        got = _SSFNetWSUTRead(1000, 1000, &r);
        SSF_ASSERT(got >= 2u);
        SSF_ASSERT(memcmp(_utOut, "ok", 2) == 0);
        if (isBad)
        {
            size_t pos = 0;
            size_t len;
            uint8_t mask[4];

            /* Only the overlap cases deliver the opening fragment's byte */
            SSF_ASSERT(got == (((v == 6u) || (v == 12u)) ? 3u : 2u));
            if (r == SSF_NET_IO_WANT_READ) { (void)_SSFNetWSUTRead(1, 1, &r); }
            SSF_ASSERT(r == SSF_NET_IO_ERROR);
            _SSFNetWSUTExpectFailed();
            _SSFNetWSUTEnd();
            SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
                       SSF_NETWS_UT_OP_CLOSE);                  /* Close 1002, nothing else */
            SSF_ASSERT((len == 2u) && (_utOut[0] == 0x03u) && (_utOut[1] == 0xEAu));
            SSF_ASSERT(pos == _utMock.txLen);
        }
        else
        {
            SSF_ASSERT(r == SSF_NET_IO_WANT_READ);
            SSF_ASSERT(SSFNetWSGetState(&_utWS) == SSF_NETWS_STATE_OPEN);
            _SSFNetWSUTEnd();
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests Ping and Pong: echo of the latest Ping, ordering behind a buffered data frame, size.    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioPingPong(void)
{
    static uint8_t big[SSF_NETWS_CTL_MAX];
    SSFNetIOResult_t r;
    uint8_t mask[4];
    size_t pos;
    size_t len;
    size_t n;
    size_t i;
    uint8_t b[3] = { 'd', 'a', 't' };

    for (i = 0; i < sizeof(big); i++) big[i] = (uint8_t)i;

    /* Empty and maximum Pings; each is answered by the recv() call that reads it */
    _SSFNetWSUTGoOpen();
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "", 0);
    n = 99;
    SSF_ASSERT(_utWS.transport.recv(&_utWS.transport, _utOut, 10, &n) == SSF_NET_IO_WANT_READ);
    SSF_ASSERT((n == 0) && (_utMock.txLen == 6u));               /* 2 + 4 mask */
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, big, sizeof(big));
    SSF_ASSERT(_SSFNetWSUTRead(1, 1, &r) == 0);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_PONG);
    SSF_ASSERT(len == 0);
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_PONG);
    SSF_ASSERT((len == sizeof(big)) && (memcmp(_utOut, big, len) == 0));
    SSF_ASSERT(pos == _utMock.txLen);
    _SSFNetWSUTEnd();

    /* Pings while a data frame waits on a blocked inner: the data goes first, then one Pong    */
    /* for the latest Ping                                                                       */
    _SSFNetWSUTGoOpen();
    _utMock.isTxBlocked = true;
    n = 0;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 3, &n) == SSF_NET_IO_SUCCESS);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "one", 3);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "two", 3);
    SSF_ASSERT(_SSFNetWSUTRead(1, 1, &r) == 0);
    SSF_ASSERT(_utMock.txLen == 0);
    _utMock.isTxBlocked = false;
    SSF_ASSERT(_SSFNetWSUTRead(1, 1, &r) == 0);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_BIN);
    SSF_ASSERT((len == 3u) && (memcmp(_utOut, "dat", 3) == 0));
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_PONG);
    SSF_ASSERT((len == 3u) && (memcmp(_utOut, "two", 3) == 0));
    SSF_ASSERT(pos == _utMock.txLen);
    _SSFNetWSUTEnd();

    /* The inner failing while the Pong is written: data already read is returned first */
    for (i = 0; i < 2u; i++)
    {
        _SSFNetWSUTGoOpen();
        _utMock.txFail = SSF_NET_IO_ERROR;
        if (i == 1u) _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "ok", 2);
        _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "p", 1);
        n = 99;
        r = _utWS.transport.recv(&_utWS.transport, _utOut, 100, &n);
        if (i == 1u)
        {
            SSF_ASSERT((r == SSF_NET_IO_SUCCESS) && (n == 2u));
            r = _utWS.transport.recv(&_utWS.transport, _utOut, 100, &n);
        }
        SSF_ASSERT((r == SSF_NET_IO_ERROR) && (n == 0));
        _SSFNetWSUTExpectFailed();
        _utMock.txFail = SSF_NET_IO_SUCCESS;
        _SSFNetWSUTEnd();
        SSF_ASSERT(_utMock.txLen == 0);
    }

    /* A Pong owed is sent ahead of the next data frame by send() as well */
    _SSFNetWSUTGoOpen();
    _utMock.isTxBlocked = true;
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "p", 1);
    SSF_ASSERT(_SSFNetWSUTRead(1, 1, &r) == 0);
    _utMock.isTxBlocked = false;
    n = 0;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 3, &n) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(n == 3u);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_PONG);
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_BIN);
    SSF_ASSERT(pos == _utMock.txLen);
    _SSFNetWSUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the server's Close, shutdown() and close().                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSUTScenarioClose(void)
{
    SSFNetIOResult_t r;
    uint8_t mask[4];
    size_t pos;
    size_t len;
    size_t n;
    size_t i;
    uint8_t b[3] = { 'd', 'a', 't' };

    /* Server Close with a code and reason: data first, then CLOSED and an echo of the code */
    _SSFNetWSUTGoOpen();
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "ok", 2);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CLOSE, "\x03\xE9" "bye", 5);
    SSF_ASSERT(_SSFNetWSUTRead(1000, 1000, &r) == 2u);
    if (r == SSF_NET_IO_WANT_READ) { (void)_SSFNetWSUTRead(1, 1, &r); }
    SSF_ASSERT(r == SSF_NET_IO_CLOSED);
    n = 99;
    SSF_ASSERT(_utWS.transport.recv(&_utWS.transport, b, 1, &n) == SSF_NET_IO_CLOSED);
    SSF_ASSERT(n == 0);
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 1, &n) == SSF_NET_IO_CLOSED);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_CLOSE);
    SSF_ASSERT((len == 2u) && (_utOut[0] == 0x03u) && (_utOut[1] == 0xE9u));
    SSF_ASSERT(pos == _utMock.txLen);
    _SSFNetWSUTEnd();
    SSF_ASSERT(pos == _utMock.txLen);                           /* No second Close */

    /* Server Close with no code: echoed empty, even when the inner was blocked at the time */
    _SSFNetWSUTGoOpen();
    _utMock.isTxBlocked = true;
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CLOSE, "", 0);
    SSF_ASSERT(_SSFNetWSUTRead(1, 1, &r) == 0);
    SSF_ASSERT(r == SSF_NET_IO_CLOSED);
    _utMock.isTxBlocked = false;
    _SSFNetWSUTEnd();                                           /* close() pushes it out */
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_CLOSE);
    SSF_ASSERT((len == 0) && (pos == _utMock.txLen));

    /* Close codes: those an endpoint may send are echoed exactly; the rest fail with 1002 */
    {
        static const uint16_t good[] = { 1000, 1001, 1003, 1007, 1011, 1014, 3000, 4999 };
        static const uint16_t bad[] = { 0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535 };
        uint8_t code[2];

        for (i = 0; i < (sizeof(good) / sizeof(good[0])) + (sizeof(bad) / sizeof(bad[0])); i++)
        {
            bool isGood = (i < (sizeof(good) / sizeof(good[0])));
            uint16_t c = isGood ? good[i] : bad[i - (sizeof(good) / sizeof(good[0]))];

            code[0] = (uint8_t)(c >> 8);
            code[1] = (uint8_t)c;
            _SSFNetWSUTGoOpen();
            _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CLOSE, code, 2);
            n = 99;
            r = _utWS.transport.recv(&_utWS.transport, _utOut, 10, &n);
            SSF_ASSERT(r == (isGood ? SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR));
            pos = 0;
            SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
                       SSF_NETWS_UT_OP_CLOSE);
            SSF_ASSERT((len == 2u) && (pos == _utMock.txLen));
            if (isGood) { SSF_ASSERT(memcmp(_utOut, code, 2) == 0); }
            else { SSF_ASSERT((_utOut[0] == 0x03u) && (_utOut[1] == 0xEAu)); }
            _SSFNetWSUTEnd();
            SSF_ASSERT(pos == _utMock.txLen);
        }
    }

    /* An echo owed behind a data frame on a blocked inner is not replaced by shutdown()'s 1000 */
    _SSFNetWSUTGoOpen();
    _utMock.isTxBlocked = true;
    n = 0;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 3, &n) == SSF_NET_IO_SUCCESS);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CLOSE, "\x0F\xA0", 2);  /* 4000 */
    SSF_ASSERT(_SSFNetWSUTRead(1, 1, &r) == 0);
    SSF_ASSERT(r == SSF_NET_IO_CLOSED);
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_WANT_WRITE);
    _utMock.isTxBlocked = false;
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_SUCCESS);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_BIN);
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_CLOSE);
    SSF_ASSERT((len == 2u) && (_utOut[0] == 0x0Fu) && (_utOut[1] == 0xA0u));
    SSF_ASSERT(pos == _utMock.txLen);
    _SSFNetWSUTEnd();

    /* A flood of Pings, one per inner read, bounds the work one recv() does */
    _SSFNetWSUTGoOpen();
    _utMock.rxChunk = 3;                                        /* One 3-byte Ping per read */
    for (i = 0; i < 40u; i++) _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_PING, "p", 1);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "d", 1);
    pos = _utMock.rxPos;
    n = 99;
    SSF_ASSERT(_utWS.transport.recv(&_utWS.transport, _utOut, 10, &n) == SSF_NET_IO_WANT_READ);
    SSF_ASSERT((n == 0) && ((_utMock.rxPos - pos) == 24u));    /* 8 reads of one Ping each */
    SSF_ASSERT(_SSFNetWSUTRead(1, 10, &r) == 1u);               /* Later calls get there */
    SSF_ASSERT(_utOut[0] == 'd');
    _SSFNetWSUTEnd();

    /* shutdown(): buffered data, then Close 1000, then the inner shutdown; idempotent; send()  */
    /* refused after it, recv() still works                                                     */
    _SSFNetWSUTGoOpen();
    _utMock.txChunk = 1;
    n = 0;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 3, &n) == SSF_NET_IO_SUCCESS);
    for (i = 0; i < 100u; i++)
    {
        r = _utWS.transport.shutdown(&_utWS.transport);
        if (r != SSF_NET_IO_WANT_WRITE) break;
        SSF_ASSERT(_utMock.shutdownCount == 0);
    }
    SSF_ASSERT(r == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(_utMock.shutdownCount == 1u);
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_BIN);
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_CLOSE);
    SSF_ASSERT((len == 2u) && (_utOut[0] == 0x03u) && (_utOut[1] == 0xE8u));
    SSF_ASSERT(pos == _utMock.txLen);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_BIN, "late", 4);
    _SSFNetWSUTFrame(true, SSF_NETWS_UT_OP_CLOSE, "\x03\xE8", 2);
    SSF_ASSERT(_SSFNetWSUTRead(100, 100, &r) == 4u);
    if (r == SSF_NET_IO_WANT_READ) { (void)_SSFNetWSUTRead(1, 1, &r); }
    SSF_ASSERT(r == SSF_NET_IO_CLOSED);
    SSF_ASSERT(pos == _utMock.txLen);                           /* Close not echoed twice */
    _SSFNetWSUTEnd();

    /* shutdown() on a blocked inner with data buffered: the Close waits behind the data, send() */
    /* is refused meanwhile, and repeated calls owe only one Close                               */
    _SSFNetWSUTGoOpen();
    _utMock.isTxBlocked = true;
    n = 0;
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 3, &n) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_WANT_WRITE);
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_WANT_WRITE);
    SSF_ASSERT(_utWS.transport.send(&_utWS.transport, b, 1, &n) == SSF_NET_IO_ERROR);
    SSF_ASSERT(_utMock.shutdownCount == 0);
    _utMock.isTxBlocked = false;
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(_utMock.shutdownCount == 1u);
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_BIN);
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_CLOSE);
    SSF_ASSERT(pos == _utMock.txLen);
    _SSFNetWSUTEnd();
    SSF_ASSERT(pos == _utMock.txLen);

    /* shutdown() passing on the inner's result */
    _SSFNetWSUTGoOpen();
    _utMock.shutdownResult = SSF_NET_IO_WANT_WRITE;
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_WANT_WRITE);
    _utMock.shutdownResult = SSF_NET_IO_ERROR;
    SSF_ASSERT(_utWS.transport.shutdown(&_utWS.transport) == SSF_NET_IO_ERROR);
    _SSFNetWSUTExpectFailed();
    _SSFNetWSUTEnd();

    /* close() while open sends a best-effort Close; after a failure it sends nothing */
    _SSFNetWSUTGoOpen();
    _SSFNetWSUTEnd();
    pos = 0;
    SSF_ASSERT(_SSFNetWSUTClientFrame(&pos, _utOut, sizeof(_utOut), &len, mask) ==
               SSF_NETWS_UT_OP_CLOSE);
    SSF_ASSERT((len == 2u) && (pos == _utMock.txLen));
    _SSFNetWSUTGoOpen();
    _utMock.isTxBlocked = true;
    _SSFNetWSUTEnd();
    SSF_ASSERT(_utMock.txLen == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfnetws external interface.                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFNetWSUnitTest(void)
{
    _SSFNetWSUTScenarioBasics();
    _SSFNetWSUTScenarioOpenRefused();
    _SSFNetWSUTScenarioHandshake();
    _SSFNetWSUTScenarioHandshakeRefused();
    _SSFNetWSUTScenarioSend();
    _SSFNetWSUTScenarioRecv();
    _SSFNetWSUTScenarioRecvRefused();
    _SSFNetWSUTScenarioPingPong();
    _SSFNetWSUTScenarioClose();
}

#endif /* SSF_CONFIG_NETWS_UNIT_TEST */
