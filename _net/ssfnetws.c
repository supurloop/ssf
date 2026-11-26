/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnetws.c                                                                                    */
/* WebSocket client transport (RFC 6455) layered on another ssfnet transport.                    */
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
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfsha1.h"
#include "ssfbase64.h"
#include "ssfcrypt.h"
#include "ssfprng.h"
#include "ssfhttphdr.h"
#include "ssfnetws.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_NETWS_MAGIC              (0x4e575353ul)   /* 'NWSS' */
#define SSF_NETWS_GUID               "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"   /* RFC 6455 1.3 */
#define SSF_NETWS_KEY_BYTES          (16u)
#define SSF_NETWS_KEY_SIZE           (25u)            /* base64 of 16 bytes, plus NUL */
#define SSF_NETWS_FIELD_PREFIX       "sec-websocket-"
#define SSF_NETWS_CLOSE_NORMAL       (1000u)
#define SSF_NETWS_CLOSE_PROTOCOL     (1002u)
#define SSF_NETWS_RECV_MAX_READS     (8u)   /* Inner reads per recv() that yield no payload */

/* Frame header (RFC 6455 5.2) */
#define SSF_NETWS_FIN                (0x80u)
#define SSF_NETWS_RSV_MASK           (0x70u)
#define SSF_NETWS_OPCODE_MASK        (0x0Fu)
#define SSF_NETWS_MASK_BIT           (0x80u)
#define SSF_NETWS_LEN_MASK           (0x7Fu)
#define SSF_NETWS_LEN_16             (126u)
#define SSF_NETWS_LEN_64             (127u)
#define SSF_NETWS_OP_CONT            (0x0u)
#define SSF_NETWS_OP_TEXT            (0x1u)
#define SSF_NETWS_OP_BIN             (0x2u)
#define SSF_NETWS_OP_CLOSE           (0x8u)
#define SSF_NETWS_OP_PING            (0x9u)
#define SSF_NETWS_OP_PONG            (0xAu)
#define SSF_NETWS_OP_IS_CONTROL(op)  (((op) & 0x8u) != 0)

/* Compile time check that transport is the session's first member */
typedef char _SSFNetWSTransportFirst_t[(offsetof(SSFNetWSSession_t, transport) == 0u) ? 1 : -1];

/* --------------------------------------------------------------------------------------------- */
/* Returns the session that owns transport t.                                                    */
/* --------------------------------------------------------------------------------------------- */
static SSFNetWSSession_t *_SSFNetWSSelf(SSFNetTransport_t *t)
{
    SSFNetWSSession_t *ws = (SSFNetWSSession_t *)(void *)t;

    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(ws->magic == SSF_NETWS_MAGIC);
    return ws;
}

/* --------------------------------------------------------------------------------------------- */
/* Writes base64(SHA-1(key || GUID)) to accept (RFC 6455 4.2.2).                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSAccept(SSFCStrIn_t keyStr, char accept[SSF_NETWS_ACCEPT_SIZE])
{
    SSFSHA1Context_t ctx;
    uint8_t hash[SSF_SHA1_HASH_SIZE];
    size_t keyLen;

    SSF_REQUIRE(keyStr != NULL);
    SSF_REQUIRE(accept != NULL);
    SSF_REQUIRE(SSFStrLen(keyStr, SSF_NETWS_KEY_SIZE, &keyLen));
    SSFSHA1Begin(&ctx);
    SSFSHA1Update(&ctx, (const uint8_t *)keyStr, (uint32_t)keyLen);
    SSFSHA1Update(&ctx, (const uint8_t *)SSF_NETWS_GUID, (uint32_t)(sizeof(SSF_NETWS_GUID) - 1u));
    SSFSHA1End(&ctx, hash);
    SSF_ASSERT(SSFBase64Encode(hash, sizeof(hash), accept, SSF_NETWS_ACCEPT_SIZE, NULL));
}

#if SSF_CONFIG_NETWS_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Exposes _SSFNetWSAccept() to the unit test.                                                   */
/* --------------------------------------------------------------------------------------------- */
void _SSFNetWSAcceptForTest(SSFCStrIn_t keyStr, char accept[SSF_NETWS_ACCEPT_SIZE])
{
    SSF_REQUIRE(keyStr != NULL);
    SSF_REQUIRE(accept != NULL);

    _SSFNetWSAccept(keyStr, accept);
}
#endif /* SSF_CONFIG_NETWS_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if nameStr is one the handshake writes itself, so an app field may not use it.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSIsReservedField(SSFCStrIn_t nameStr)
{
    static const char *const reserved[] = { "host", "upgrade", "connection", "content-length",
                                            "transfer-encoding" };
    size_t i;
    size_t j;

    SSF_REQUIRE(nameStr != NULL);

    for (i = 0; i < (sizeof(reserved) / sizeof(reserved[0])); i++)
    {
        for (j = 0; (reserved[i][j] != 0) && (nameStr[j] != 0); j++)
        {
            char c = nameStr[j];

            if ((c >= 'A') && (c <= 'Z')) c = (char)(c + ('a' - 'A'));
            if (c != reserved[i][j]) break;
        }
        if ((reserved[i][j] == 0) && (nameStr[j] == 0)) return true;
    }
    for (j = 0; SSF_NETWS_FIELD_PREFIX[j] != 0; j++)
    {
        char c = nameStr[j];

        if ((c >= 'A') && (c <= 'Z')) c = (char)(c + ('a' - 'A'));
        if (c != SSF_NETWS_FIELD_PREFIX[j]) return false;   /* Also stops at nameStr's NUL */
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Clears the connection state, wiping the buffers; the configuration is kept.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSReset(SSFNetWSSession_t *ws)
{
    SSFNetTransport_t transport;
    SSFNetTransport_t *inner;
    SSFCStrIn_t path;
    const SSFHTTPHdrField_t *fieldsOpt;
    uint32_t fieldCount;

    SSF_REQUIRE(ws != NULL);

    transport = ws->transport;
    inner = ws->inner;
    path = ws->path;
    fieldsOpt = ws->fieldsOpt;
    fieldCount = ws->fieldCount;
    SSFCryptSecureZero(ws, sizeof(*ws));
    ws->transport = transport;
    ws->inner = inner;
    ws->path = path;
    ws->fieldsOpt = fieldsOpt;
    ws->fieldCount = fieldCount;
    ws->state = SSF_NETWS_STATE_CLOSED;
    ws->magic = SSF_NETWS_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Fails the connection; only close() is valid afterwards. Returns CLOSED for CLOSED else ERROR. */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSFail(SSFNetWSSession_t *ws, SSFNetIOResult_t r)
{
    SSF_REQUIRE(ws != NULL);

    ws->state = SSF_NETWS_STATE_FAILED;
    return (r == SSF_NET_IO_CLOSED) ? SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the Upgrade request in hsBuf, else false if it is invalid or too large.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSBuildRequest(SSFNetWSSession_t *ws, SSFCStrIn_t keyStr)
{
    size_t len;
    uint32_t i;
    uint16_t hostPort;
    bool ok;

    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(keyStr != NULL);
    SSF_REQUIRE((ws->fieldsOpt != NULL) || (ws->fieldCount == 0));

    hostPort = ((ws->port == 80u) || (ws->port == 443u)) ? 0 : ws->port;
    ok = SSFHTTPHdrReqBegin(ws->hsBuf, sizeof(ws->hsBuf), &len, "GET", ws->path, ws->host,
                            hostPort);
    ok = ok && SSFHTTPHdrReqAddField(ws->hsBuf, sizeof(ws->hsBuf), &len, "Upgrade", "websocket");
    ok = ok && SSFHTTPHdrReqAddField(ws->hsBuf, sizeof(ws->hsBuf), &len, "Connection", "Upgrade");
    ok = ok && SSFHTTPHdrReqAddField(ws->hsBuf, sizeof(ws->hsBuf), &len, "Sec-WebSocket-Key",
                                     keyStr);
    ok = ok && SSFHTTPHdrReqAddField(ws->hsBuf, sizeof(ws->hsBuf), &len, "Sec-WebSocket-Version",
                                     "13");
    ok = ok && SSFHTTPHdrReqAddField(ws->hsBuf, sizeof(ws->hsBuf), &len, "Sec-WebSocket-Protocol",
                                     SSF_NETWS_SUBPROTOCOL);
    for (i = 0; ok && (i < ws->fieldCount); i++)
    {
        const SSFHTTPHdrField_t *f = &ws->fieldsOpt[i];

        SSF_REQUIRE(f->name != NULL);
        SSF_REQUIRE(f->value != NULL);
        ok = ((_SSFNetWSIsReservedField(f->name) == false) &&
              (SSFHTTPHdrReqAddField(ws->hsBuf, sizeof(ws->hsBuf), &len, f->name, f->value)));
    }
    ok = ok && SSFHTTPHdrReqEnd(ws->hsBuf, sizeof(ws->hsBuf), &len);
    if (ok == false) return false;
    ws->hsLen = len;
    ws->hsPos = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the parsed response accepts the upgrade as offered (RFC 6455 4.1, 4.2.2).     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSCheckResponse(const SSFNetWSSession_t *ws, const SSFHTTPHdrResponse_t *resp)
{
    const uint8_t *b;

    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(resp != NULL);

    b = ws->hsBuf;
    if ((resp->status != 101u) || (resp->versionMajor != 1u) || (resp->versionMinor != 1u))
    { return false; }
    if (SSFHTTPHdrFieldIsOnly(b, resp, "Upgrade", "websocket", true) == false) return false;
    if (SSFHTTPHdrFieldHasToken(b, resp, "Connection", "upgrade") == false) return false;
    if (SSFHTTPHdrFieldIsOnly(b, resp, "Sec-WebSocket-Accept", ws->accept, false) == false)
    { return false; }
    if (SSFHTTPHdrFieldCount(b, resp, "Sec-WebSocket-Extensions") != 0) return false;
    if ((SSFHTTPHdrFieldCount(b, resp, "Sec-WebSocket-Protocol") != 0) &&
        (SSFHTTPHdrFieldIsOnly(b, resp, "Sec-WebSocket-Protocol", SSF_NETWS_SUBPROTOCOL,
                               false) == false))
    { return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Handshake step 1 of 2: writes the request in hsBuf, then wipes it (it may carry credentials). */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSUpgradeSend(SSFNetWSSession_t *ws)
{
    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->hsPos <= ws->hsLen);

    while (ws->hsPos < ws->hsLen)
    {
        size_t n = 0;
        SSFNetIOResult_t r = ws->inner->send(ws->inner, &ws->hsBuf[ws->hsPos],
                                             ws->hsLen - ws->hsPos, &n);

        if ((r == SSF_NET_IO_WANT_WRITE) || (r == SSF_NET_IO_WANT_READ)) return r;
        if (r != SSF_NET_IO_SUCCESS) return _SSFNetWSFail(ws, r);
        SSF_ASSERT((n >= 1u) && (n <= (ws->hsLen - ws->hsPos)));
        ws->hsPos += n;
    }
    SSFCryptSecureZero(ws->hsBuf, sizeof(ws->hsBuf));
    ws->hsLen = 0;
    ws->hsPos = 0;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Handshake step 2 of 2: reads and checks the response head; any bytes after it stay in hsBuf.  */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSUpgradeRecv(SSFNetWSSession_t *ws)
{
    SSFHTTPHdrResponse_t resp;

    SSF_REQUIRE(ws != NULL);

    for (;;)
    {
        size_t n = 0;
        SSFNetIOResult_t r;
        SSFHTTPHdrParse_t p;

        if (ws->hsLen >= sizeof(ws->hsBuf)) return _SSFNetWSFail(ws, SSF_NET_IO_ERROR);
        r = ws->inner->recv(ws->inner, &ws->hsBuf[ws->hsLen], sizeof(ws->hsBuf) - ws->hsLen, &n);
        if ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) return r;
        if (r != SSF_NET_IO_SUCCESS) return _SSFNetWSFail(ws, r);
        SSF_ASSERT((n >= 1u) && (n <= (sizeof(ws->hsBuf) - ws->hsLen)));
        ws->hsLen += n;

        p = SSFHTTPHdrParseResponse(ws->hsBuf, ws->hsLen, &resp);
        if (p == SSF_HTTP_HDR_MALFORMED) return _SSFNetWSFail(ws, SSF_NET_IO_ERROR);
        /* Is the response head complete? */
        if (p == SSF_HTTP_HDR_COMPLETE)
        {
            /* Yes, check it and keep any frame bytes that followed it */
            if (_SSFNetWSCheckResponse(ws, &resp) == false)
            { return _SSFNetWSFail(ws, SSF_NET_IO_ERROR); }
            /* Keep what followed the head; it is frame data */
            memmove(ws->hsBuf, &ws->hsBuf[resp.headLen], ws->hsLen - resp.headLen);
            ws->hsLen -= resp.headLen;
            memset(&ws->hsBuf[ws->hsLen], 0, sizeof(ws->hsBuf) - ws->hsLen);
            ws->hsPos = 0;
            return SSF_NET_IO_SUCCESS;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Builds one masked frame of payload[0..payloadLen) in the empty frame buffer.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSBuildFrame(SSFNetWSSession_t *ws, uint8_t opcode, const uint8_t *payload,
                                size_t payloadLen)
{
    uint8_t *f;
    uint8_t mask[4];
    size_t n = 0;
    size_t i;

    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->txLen == 0);
    SSF_REQUIRE((opcode & SSF_NETWS_OPCODE_MASK) == opcode);
    SSF_REQUIRE(payloadLen <= SSF_NETWS_TX_PAYLOAD_MAX);
    SSF_REQUIRE((payload != NULL) || (payloadLen == 0));

    f = ws->txBuf;
    f[n++] = (uint8_t)(SSF_NETWS_FIN | opcode);
    /* Does the length fit in the 7-bit field? */
    if (payloadLen < SSF_NETWS_LEN_16) { f[n++] = (uint8_t)(SSF_NETWS_MASK_BIT | payloadLen); }
    else
    {
        /* No, use the 16-bit extended length */
        f[n++] = (uint8_t)(SSF_NETWS_MASK_BIT | SSF_NETWS_LEN_16);
        f[n++] = (uint8_t)(payloadLen >> 8);
        f[n++] = (uint8_t)payloadLen;
    }
    SSFPRNGGetRandom(&ws->prng, mask, sizeof(mask));           /* RFC 6455 5.3: fresh per frame */
    memcpy(&f[n], mask, sizeof(mask));
    n += sizeof(mask);
    for (i = 0; i < payloadLen; i++) f[n + i] = (uint8_t)(payload[i] ^ mask[(i & 3u)]);
    ws->txLen = n + payloadLen;
    ws->txPos = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Writes the frame buffer out as far as the inner allows; SUCCESS once empty.                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSFlush(SSFNetWSSession_t *ws)
{
    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->txPos <= ws->txLen);

    while (ws->txPos < ws->txLen)
    {
        size_t n = 0;
        SSFNetIOResult_t r = ws->inner->send(ws->inner, &ws->txBuf[ws->txPos],
                                             ws->txLen - ws->txPos, &n);

        if ((r == SSF_NET_IO_WANT_WRITE) || (r == SSF_NET_IO_WANT_READ))
        { return SSF_NET_IO_WANT_WRITE; }
        if (r != SSF_NET_IO_SUCCESS) return r;
        SSF_ASSERT((n >= 1u) && (n <= (ws->txLen - ws->txPos)));
        ws->txPos += n;
    }
    ws->txLen = 0;
    ws->txPos = 0;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Flushes the frame buffer, then any owed Close (first) or Pong; nothing follows a Close.       */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSFlushControl(SSFNetWSSession_t *ws)
{
    SSFNetIOResult_t r;

    SSF_REQUIRE(ws != NULL);

    r = _SSFNetWSFlush(ws);
    if (r != SSF_NET_IO_SUCCESS) return r;
    if (ws->isCloseSent) return SSF_NET_IO_SUCCESS;
    /* Is a Close owed? */
    if (ws->isCloseOwed)
    {
        /* Yes, send it; it supersedes any owed Pong */
        _SSFNetWSBuildFrame(ws, SSF_NETWS_OP_CLOSE, ws->close, ws->closeLen);
        ws->isCloseOwed = false;
        ws->isCloseSent = true;
        ws->isPongOwed = false;
        return _SSFNetWSFlush(ws);
    }
    /* Is a Pong owed? */
    if (ws->isPongOwed)
    {
        /* Yes, send it */
        _SSFNetWSBuildFrame(ws, SSF_NETWS_OP_PONG, ws->pong, ws->pongLen);
        ws->isPongOwed = false;
        return _SSFNetWSFlush(ws);
    }
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Owes a Close with the given status code, unless one is owed or sent already.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSOweClose(SSFNetWSSession_t *ws, const uint8_t *codeOpt)
{
    SSF_REQUIRE(ws != NULL);

    if ((ws->isCloseSent) || (ws->isCloseOwed)) return;
    ws->isCloseOwed = true;
    ws->closeLen = 0;
    /* Was a status code given? */
    if (codeOpt != NULL)
    {
        /* Yes, carry it in the Close body */
        ws->close[0] = codeOpt[0];
        ws->close[1] = codeOpt[1];
        ws->closeLen = 2u;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Takes one header byte; returns false on a protocol violation, else true, *isDoneOut if done.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSRxHeaderByte(SSFNetWSSession_t *ws, uint8_t b, bool *isDoneOut)
{
    uint8_t len7;
    uint8_t need;
    uint8_t i;

    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->rxHdrLen < sizeof(ws->rxHdr));
    SSF_REQUIRE(isDoneOut != NULL);

    *isDoneOut = false;
    ws->rxHdr[ws->rxHdrLen++] = b;
    /* Is this the first header byte? */
    if (ws->rxHdrLen == 1u)
    {
        /* Yes, check the flags and opcode */
        uint8_t op = (uint8_t)(b & SSF_NETWS_OPCODE_MASK);

        if ((b & SSF_NETWS_RSV_MASK) != 0) return false;        /* No extension negotiated */
        if ((op != SSF_NETWS_OP_CONT) && (op != SSF_NETWS_OP_BIN) && (op != SSF_NETWS_OP_CLOSE) &&
            (op != SSF_NETWS_OP_PING) && (op != SSF_NETWS_OP_PONG))
        { return false; }                                       /* Text (MQTT 6.0) or reserved */
        if ((SSF_NETWS_OP_IS_CONTROL(op)) && ((b & SSF_NETWS_FIN) == 0)) return false;
        return true;
    }
    /* Is this the second header byte? */
    if (ws->rxHdrLen == 2u)
    {
        /* Yes, check the mask bit and control frame length */
        if ((b & SSF_NETWS_MASK_BIT) != 0) return false;        /* Server frames are unmasked */
        len7 = (uint8_t)(b & SSF_NETWS_LEN_MASK);
        if ((SSF_NETWS_OP_IS_CONTROL(ws->rxHdr[0] & SSF_NETWS_OPCODE_MASK)) &&
            (len7 > SSF_NETWS_CTL_MAX))
        { return false; }
    }
    len7 = (uint8_t)(ws->rxHdr[1] & SSF_NETWS_LEN_MASK);
    need = (len7 == SSF_NETWS_LEN_16) ? 4u : ((len7 == SSF_NETWS_LEN_64) ? 10u : 2u);
    if ((len7 == SSF_NETWS_LEN_64) && (ws->rxHdrLen == 3u) && ((b & 0x80u) != 0)) return false;
    if (ws->rxHdrLen < need) return true;

    /* Header complete */
    /* Is the length in the 7-bit field? */
    if (len7 < SSF_NETWS_LEN_16) ws->rxRemain = len7;
    else
    {
        /* No, it is in the extended length bytes */
        ws->rxRemain = 0;
        for (i = 2; i < need; i++) ws->rxRemain = ((ws->rxRemain << 8) | ws->rxHdr[i]);
    }
    ws->rxOpcode = (uint8_t)(ws->rxHdr[0] & SSF_NETWS_OPCODE_MASK);
    ws->rxIsFin = ((ws->rxHdr[0] & SSF_NETWS_FIN) != 0);
    ws->rxHdrLen = 0;
    ws->rxCtlLen = 0;

    /* Fragmentation (RFC 6455 5.4): a message starts with BIN and goes on with CONT */
    /* Does this frame start a message? */
    if (ws->rxOpcode == SSF_NETWS_OP_BIN)
    {
        /* Yes, one must not already be in progress */
        if (ws->isInMessage) return false;
        ws->isInMessage = (ws->rxIsFin == false);
    }
    else if (ws->rxOpcode == SSF_NETWS_OP_CONT)
    {
        /* No, it continues one that must be in progress */
        if (ws->isInMessage == false) return false;
        if (ws->rxIsFin) ws->isInMessage = false;
    }
    *isDoneOut = true;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Acts on a complete control frame. Returns false on a protocol violation.                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSRxControlDone(SSFNetWSSession_t *ws)
{
    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->rxCtlLen <= SSF_NETWS_CTL_MAX);

    /* Is it a Ping? */
    if (ws->rxOpcode == SSF_NETWS_OP_PING)
    {
        /* Yes, owe a Pong with the same payload */
        memcpy(ws->pong, ws->rxCtl, ws->rxCtlLen);              /* Latest Ping wins (5.5.3) */
        ws->pongLen = ws->rxCtlLen;
        ws->isPongOwed = true;
    }
    else if (ws->rxOpcode == SSF_NETWS_OP_CLOSE)
    {
        /* No, it is a Close; owe a Close echoing a valid status code */
        if (ws->rxCtlLen == 1u) return false;                   /* A code is 2 bytes (5.5.1) */
        /* Does the Close carry a status code? */
        if (ws->rxCtlLen >= 2u)
        {
            /* Yes, only codes an endpoint may send (7.4.1, 7.4.2); 1005, 1006, 1015 never are */
            uint16_t code = (uint16_t)(((uint16_t)ws->rxCtl[0] << 8) | ws->rxCtl[1]);

            if (!(((code >= 1000u) && (code <= 1003u)) || ((code >= 1007u) && (code <= 1014u)) ||
                  ((code >= 3000u) && (code <= 4999u))))
            { return false; }
        }
        _SSFNetWSOweClose(ws, (ws->rxCtlLen >= 2u) ? ws->rxCtl : NULL);
        ws->isPeerClosed = true;
    }
    return true;                                                /* A Pong needs nothing */
}

/* --------------------------------------------------------------------------------------------- */
/* Fails the connection from recv(): payload already copied is returned first.                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSRxFail(SSFNetWSSession_t *ws, SSFNetIOResult_t r, size_t got,
                                        size_t *gotOut)
{
    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(gotOut != NULL);

    (void)_SSFNetWSFail(ws, r);
    if (got > 0) { *gotOut = got; return SSF_NET_IO_SUCCESS; }
    return (r == SSF_NET_IO_CLOSED) ? SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Fails recv() on a server protocol violation with a best-effort Close 1002 (RFC 6455 7.1.7).   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSRxProtocolFail(SSFNetWSSession_t *ws, size_t got, size_t *gotOut)
{
    static const uint8_t protocolError[2] = { (uint8_t)(SSF_NETWS_CLOSE_PROTOCOL >> 8),
                                              (uint8_t)(SSF_NETWS_CLOSE_PROTOCOL & 0xFFu) };

    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(gotOut != NULL);

    ws->isCloseOwed = false;                    /* A Close echo not yet built gives way to 1002 */
    _SSFNetWSOweClose(ws, protocolError);
    (void)_SSFNetWSFlushControl(ws);
    return _SSFNetWSRxFail(ws, SSF_NET_IO_ERROR, got, gotOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Starts connecting to hostStr:port: validates, builds the request, opens the inner.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetWSOpen(SSFNetTransport_t *t, SSFCStrIn_t hostStr, size_t hostSize,
                          uint16_t port)
{
    SSFNetWSSession_t *ws;
    size_t hostLen;
    uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
    uint8_t keyBytes[SSF_NETWS_KEY_BYTES];
    char key[SSF_NETWS_KEY_SIZE];
    bool ok;

    SSF_REQUIRE(hostStr != NULL);
    SSF_REQUIRE(hostSize > 0);
    ws = _SSFNetWSSelf(t);
    SSF_REQUIRE(ws->state == SSF_NETWS_STATE_CLOSED);

    if ((SSFStrLen(hostStr, hostSize, &hostLen) == false) || (hostLen == 0)) return false;
    if (hostLen >= sizeof(ws->host)) return false;
    if (port == 0) return false;
    if (memchr(hostStr, ':', hostLen) != NULL) return false;       /* IPv4 only (ssfnet.h) */

    _SSFNetWSReset(ws);
    memcpy(ws->host, hostStr, hostLen + 1u);                       /* Caller's copy may go */
    ws->port = port;

    /* A fresh key, and a mask generator seeded for this connection */
    if (SSFPortGetEntropy(seed, (uint16_t)sizeof(seed)) == false) return false;
    SSFPRNGInitContext(&ws->prng, seed, sizeof(seed));
    SSFCryptSecureZero(seed, sizeof(seed));
    SSFPRNGGetRandom(&ws->prng, keyBytes, sizeof(keyBytes));
    SSF_ASSERT(SSFBase64Encode(keyBytes, sizeof(keyBytes), key, sizeof(key), NULL));
    _SSFNetWSAccept(key, ws->accept);

    ok = _SSFNetWSBuildRequest(ws, key);
    ok = ok && ws->inner->open(ws->inner, ws->host, sizeof(ws->host), port);
    if (ok == false) { _SSFNetWSReset(ws); return false; }
    ws->isInnerOpen = true;
    ws->state = SSF_NETWS_STATE_OPENING;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Advances the open: inner open, request, response. SUCCESS once frames can flow.               */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSPollOpen(SSFNetTransport_t *t)
{
    SSFNetWSSession_t *ws = _SSFNetWSSelf(t);
    SSFNetIOResult_t r;

    /* Is the inner transport still opening? */
    if (ws->state == SSF_NETWS_STATE_OPENING)
    {
        /* Yes, advance it */
        r = ws->inner->pollOpen(ws->inner);
        if ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) return r;
        if (r != SSF_NET_IO_SUCCESS) return _SSFNetWSFail(ws, r);
        ws->state = SSF_NETWS_STATE_HS_SEND;
    }
    /* Is the Upgrade request being sent? */
    if (ws->state == SSF_NETWS_STATE_HS_SEND)
    {
        /* Yes, send more of it */
        r = _SSFNetWSUpgradeSend(ws);
        if (r != SSF_NET_IO_SUCCESS) return r;
        ws->state = SSF_NETWS_STATE_HS_RECV;
    }
    /* Is the Upgrade response being received? */
    if (ws->state == SSF_NETWS_STATE_HS_RECV)
    {
        /* Yes, receive and check it */
        r = _SSFNetWSUpgradeRecv(ws);
        if (r != SSF_NET_IO_SUCCESS) return r;
        SSFCryptSecureZero(ws->accept, sizeof(ws->accept));
        ws->state = SSF_NETWS_STATE_OPEN;
    }
    return (ws->state == SSF_NETWS_STATE_OPEN) ? SSF_NET_IO_SUCCESS : SSF_NET_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Frames up to SSF_NETWS_CONFIG_TX_FRAME_SIZE bytes of buf as one binary frame.                 */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSSend(SSFNetTransport_t *t, const uint8_t *buf, size_t bufLen,
                                      size_t *sentOut)
{
    SSFNetWSSession_t *ws;
    SSFNetIOResult_t r;
    size_t chunk;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(bufLen > 0);
    SSF_REQUIRE(sentOut != NULL);
    ws = _SSFNetWSSelf(t);

    *sentOut = 0;
    if (ws->state != SSF_NETWS_STATE_OPEN) return SSF_NET_IO_ERROR;
    if (ws->isPeerClosed) return SSF_NET_IO_CLOSED;
    if ((ws->isCloseSent) || (ws->isCloseOwed)) return SSF_NET_IO_ERROR;   /* After shutdown() */

    r = _SSFNetWSFlushControl(ws);
    if (r == SSF_NET_IO_WANT_WRITE) return r;
    if (r != SSF_NET_IO_SUCCESS) return _SSFNetWSFail(ws, r);

    chunk = (bufLen > SSF_NETWS_CONFIG_TX_FRAME_SIZE) ? SSF_NETWS_CONFIG_TX_FRAME_SIZE : bufLen;
    _SSFNetWSBuildFrame(ws, SSF_NETWS_OP_BIN, buf, chunk);
    r = _SSFNetWSFlush(ws);
    if ((r != SSF_NET_IO_SUCCESS) && (r != SSF_NET_IO_WANT_WRITE)) return _SSFNetWSFail(ws, r);
    *sentOut = chunk;                                           /* Framed; any tail is pending */
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns payload bytes from binary and continuation frames, handling control frames.           */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSRecv(SSFNetTransport_t *t, uint8_t *buf, size_t bufSize,
                                      size_t *gotOut)
{
    SSFNetWSSession_t *ws;
    SSFNetIOResult_t r;
    size_t got = 0;
    uint32_t reads = 0;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(bufSize > 0);
    SSF_REQUIRE(gotOut != NULL);
    ws = _SSFNetWSSelf(t);

    *gotOut = 0;
    if (ws->state != SSF_NETWS_STATE_OPEN) return SSF_NET_IO_ERROR;
    if (ws->isPeerClosed) return SSF_NET_IO_CLOSED;

    /* Keep buffered frames moving even when the caller only reads */
    r = _SSFNetWSFlushControl(ws);
    if ((r != SSF_NET_IO_SUCCESS) && (r != SSF_NET_IO_WANT_WRITE)) return _SSFNetWSFail(ws, r);

    while (got < bufSize)
    {
        size_t avail;
        size_t n;

        /* Is the staging buffer empty? */
        if (ws->hsPos >= ws->hsLen)
        {
            /* Yes, return what we have, or read more */
            if ((got > 0) || (reads >= SSF_NETWS_RECV_MAX_READS)) break;
            reads++;
            ws->hsPos = 0;
            ws->hsLen = 0;
            n = 0;
            r = ws->inner->recv(ws->inner, ws->hsBuf, sizeof(ws->hsBuf), &n);
            if ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) break;
            if (r != SSF_NET_IO_SUCCESS) return _SSFNetWSRxFail(ws, r, got, gotOut);
            SSF_ASSERT((n >= 1u) && (n <= sizeof(ws->hsBuf)));
            ws->hsLen = n;
        }

        /* Is a frame header still being read? */
        if (ws->rxIsPayload == false)
        {
            /* Yes, take one more header byte */
            bool isDone;

            if (_SSFNetWSRxHeaderByte(ws, ws->hsBuf[ws->hsPos++], &isDone) == false)
            { return _SSFNetWSRxProtocolFail(ws, got, gotOut); }
            if (isDone == false) continue;
            ws->rxIsPayload = true;
        }

        avail = ws->hsLen - ws->hsPos;
        n = (ws->rxRemain < (uint64_t)avail) ? (size_t)ws->rxRemain : avail;
        /* Is this a control frame? */
        if (SSF_NETWS_OP_IS_CONTROL(ws->rxOpcode))
        {
            /* Yes, collect its payload */
            memcpy(&ws->rxCtl[ws->rxCtlLen], &ws->hsBuf[ws->hsPos], n);   /* rxRemain <= 125 */
            ws->rxCtlLen = (uint8_t)(ws->rxCtlLen + n);
        }
        else
        {
            /* No, copy its payload to the caller */
            if (n > (bufSize - got)) n = bufSize - got;
            memcpy(&buf[got], &ws->hsBuf[ws->hsPos], n);
            got += n;
        }
        ws->hsPos += n;
        ws->rxRemain -= n;
        if (ws->rxRemain > 0) continue;

        /* Frame done */
        ws->rxIsPayload = false;
        /* Was it a control frame? */
        if (SSF_NETWS_OP_IS_CONTROL(ws->rxOpcode))
        {
            /* Yes, act on it */
            if (_SSFNetWSRxControlDone(ws) == false)
            { return _SSFNetWSRxProtocolFail(ws, got, gotOut); }
            if (ws->isPeerClosed) break;
        }
    }

    /* Answer any Ping or Close just received */
    r = _SSFNetWSFlushControl(ws);
    if ((r != SSF_NET_IO_SUCCESS) && (r != SSF_NET_IO_WANT_WRITE))
    { return _SSFNetWSRxFail(ws, r, got, gotOut); }
    if (got > 0) { *gotOut = got; return SSF_NET_IO_SUCCESS; }
    return ws->isPeerClosed ? SSF_NET_IO_CLOSED : SSF_NET_IO_WANT_READ;
}

/* --------------------------------------------------------------------------------------------- */
/* Writes out buffered frames and a Close (1000), then shuts down the inner transport.           */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetWSShutdown(SSFNetTransport_t *t)
{
    static const uint8_t normal[2] = { (uint8_t)(SSF_NETWS_CLOSE_NORMAL >> 8),
                                       (uint8_t)(SSF_NETWS_CLOSE_NORMAL & 0xFFu) };
    SSFNetWSSession_t *ws = _SSFNetWSSelf(t);
    SSFNetIOResult_t r;

    if (ws->state != SSF_NETWS_STATE_OPEN) return SSF_NET_IO_ERROR;
    _SSFNetWSOweClose(ws, normal);
    r = _SSFNetWSFlushControl(ws);
    if (r == SSF_NET_IO_WANT_WRITE) return r;
    if (r != SSF_NET_IO_SUCCESS) return _SSFNetWSFail(ws, r);

    r = ws->inner->shutdown(ws->inner);
    if ((r == SSF_NET_IO_SUCCESS) || (r == SSF_NET_IO_WANT_WRITE) || (r == SSF_NET_IO_WANT_READ))
    { return r; }
    return _SSFNetWSFail(ws, r);
}

/* --------------------------------------------------------------------------------------------- */
/* Ends the connection with a best-effort Close if open, closes the inner, wipes the buffers.    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetWSClose(SSFNetTransport_t *t)
{
    static const uint8_t normal[2] = { (uint8_t)(SSF_NETWS_CLOSE_NORMAL >> 8),
                                       (uint8_t)(SSF_NETWS_CLOSE_NORMAL & 0xFFu) };
    SSFNetWSSession_t *ws = _SSFNetWSSelf(t);

    /* Is the connection open? */
    if (ws->state == SSF_NETWS_STATE_OPEN)
    {
        /* Yes, try once to send a Close */
        _SSFNetWSOweClose(ws, normal);
        (void)_SSFNetWSFlushControl(ws);
    }
    if (ws->isInnerOpen) ws->inner->close(ws->inner);
    _SSFNetWSReset(ws);
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes a WebSocket session over inner.                                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFNetWSInit(SSFNetWSSession_t *ws, SSFNetTransport_t *inner, SSFCStrIn_t pathStr,
                  const SSFHTTPHdrField_t *fieldsOpt, uint32_t fieldsOptLen)
{
    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->magic != SSF_NETWS_MAGIC);
    SSF_REQUIRE(inner != NULL);
    SSF_REQUIRE(inner->open != NULL);
    SSF_REQUIRE(inner->pollOpen != NULL);
    SSF_REQUIRE(inner->send != NULL);
    SSF_REQUIRE(inner->recv != NULL);
    SSF_REQUIRE(inner->shutdown != NULL);
    SSF_REQUIRE(inner->close != NULL);
    SSF_REQUIRE(pathStr != NULL);
    SSF_REQUIRE((fieldsOpt != NULL) || (fieldsOptLen == 0));

    memset(ws, 0, sizeof(*ws));
    ws->transport.open = _SSFNetWSOpen;
    ws->transport.pollOpen = _SSFNetWSPollOpen;
    ws->transport.send = _SSFNetWSSend;
    ws->transport.recv = _SSFNetWSRecv;
    ws->transport.shutdown = _SSFNetWSShutdown;
    ws->transport.close = _SSFNetWSClose;
    ws->inner = inner;
    ws->path = pathStr;
    ws->fieldsOpt = fieldsOpt;
    ws->fieldCount = fieldsOptLen;
    ws->state = SSF_NETWS_STATE_CLOSED;
    ws->magic = SSF_NETWS_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Closes any connection and wipes the session.                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFNetWSDeInit(SSFNetWSSession_t *ws)
{
    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->magic == SSF_NETWS_MAGIC);

    _SSFNetWSClose(&ws->transport);
    SSFCryptSecureZero(ws, sizeof(*ws));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the connection state.                                                                 */
/* --------------------------------------------------------------------------------------------- */
SSFNetWSState_t SSFNetWSGetState(const SSFNetWSSession_t *ws)
{
    SSF_REQUIRE(ws != NULL);
    SSF_REQUIRE(ws->magic == SSF_NETWS_MAGIC);
    return ws->state;
}
