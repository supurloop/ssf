/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnetws.h                                                                                    */
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
#ifndef SSF_NETWS_H_INCLUDE
#define SSF_NETWS_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfnet.h"
#include "ssfhttphdr.h"
#include "ssfprng.h"

/* --------------------------------------------------------------------------------------------- */
/* Design                                                                                        */
/* --------------------------------------------------------------------------------------------- */
/* - An ssfnet transport that carries a byte stream in WebSocket binary messages (RFC 6455)      */
/*   over an inner transport: ssfnetsock for ws://, ssftlsc for wss://. A client such as         */
/*   ssfmqttc uses it like any other transport; it sees only the stream.                         */
/* - open() starts the inner open. pollOpen() finishes it, then sends the HTTP/1.1 Upgrade       */
/*   request (built with ssfhttphdr) and checks the response: status 101, Upgrade websocket,     */
/*   Connection upgrade, the right Sec-WebSocket-Accept, no extension, and a subprotocol that    */
/*   is absent or the one offered. Anything else fails the open with ERROR.                      */
/* - send() frames up to SSF_NETWS_CONFIG_TX_FRAME_SIZE bytes per call as one masked binary      */
/*   frame, with a fresh mask key from an ssfprng context seeded from SSFPortGetEntropy() at     */
/*   each open(). Accepted bytes may sit in the frame buffer until a later send(), recv() or     */
/*   shutdown() writes them out, as with TLS records.                                            */
/* - recv() strips framing and returns payload bytes as a stream: a message may span frames and  */
/*   a read may span messages, so nothing assumes the inner protocol aligns with frames (MQTT    */
/*   3.1.1 section 6). Frames of any length stream through without buffering. A Ping is          */
/*   answered with a Pong (latest Ping only, RFC 6455 5.5.3); a Pong is ignored; a Close is      */
/*   echoed and ends the stream with CLOSED. A text or reserved frame, a masked server frame,    */
/*   RSV bits, a fragmented or oversized control frame, a fragmentation error, or a Close        */
/*   with a 1-byte payload or a code an endpoint may not send (7.4) is ERROR, after a            */
/*   best-effort Close 1002.                                                                     */
/* - shutdown() writes out any buffered frame, sends Close (1000), then shuts down the inner     */
/*   transport. close() makes one best-effort attempt at the same, then closes the inner.        */
/* - The handshake goes through one internal step (send a request head, get a parsed 101 and the */
/*   bytes after it) so it can move onto a future HTTP client without touching the framing.      */
/* - The request may carry secrets in extra fields (Authorization); the handshake buffer is      */
/*   wiped once the request is sent and on close().                                              */
/* - IPv4 only, like every ssfnet transport. The Host field carries the port unless it is 80 or  */
/*   443.                                                                                        */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_NETWS_FRAME_HDR_MAX      (14u)  /* 2 + 8 length + 4 mask                           */
#define SSF_NETWS_CTL_MAX            (125u) /* Control frame payload limit                     */
#define SSF_NETWS_ACCEPT_SIZE        (29u)  /* base64 of a SHA-1, plus NUL                     */
#define SSF_NETWS_SUBPROTOCOL        "mqtt"

/* Largest frame payload sent: data frames up to the configured size, control frames (a Pong     */
/* echoing a Ping) up to 125 bytes, whichever is larger. txBuf holds one such frame.             */
#if SSF_NETWS_CONFIG_TX_FRAME_SIZE < SSF_NETWS_CTL_MAX
#define SSF_NETWS_TX_PAYLOAD_MAX     (SSF_NETWS_CTL_MAX)
#else
#define SSF_NETWS_TX_PAYLOAD_MAX     (SSF_NETWS_CONFIG_TX_FRAME_SIZE)
#endif

typedef enum
{
    SSF_NETWS_STATE_CLOSED,          /* Not open                                                */
    SSF_NETWS_STATE_OPENING,         /* Inner transport opening                                 */
    SSF_NETWS_STATE_HS_SEND,         /* Writing the Upgrade request                             */
    SSF_NETWS_STATE_HS_RECV,         /* Reading the response head                               */
    SSF_NETWS_STATE_OPEN,            /* Frames flow                                             */
    SSF_NETWS_STATE_FAILED           /* An error ended the connection; only close() is valid    */
} SSFNetWSState_t;

typedef struct
{
    SSFNetTransport_t transport;     /* Must be first; this is what a client is handed          */
    SSFNetTransport_t *inner;
    SSFCStrIn_t path;                /* Request target, app owned                               */
    const SSFHTTPHdrField_t *fieldsOpt; /* Extra request fields, app owned                     */
    uint32_t fieldCount;
    SSFNetWSState_t state;
    bool isInnerOpen;
    bool isCloseSent;                /* A Close is in, or through, the frame buffer             */
    bool isCloseOwed;                /* A Close waits for the frame buffer                      */
    bool isPeerClosed;               /* The server's Close was received                         */
    bool isPongOwed;                 /* A Pong of pong[0..pongLen) waits for the frame buffer   */
    bool isInMessage;                /* A fragmented data message is in progress                */
    bool rxIsPayload;                /* Header done; rxRemain payload bytes follow              */
    bool rxIsFin;
    uint8_t closeLen;                /* Close payload to send: 0, or 2 for a status code        */
    uint8_t close[2];
    uint8_t rxOpcode;
    uint8_t rxHdrLen;                /* Header bytes collected for the current frame            */
    uint8_t rxHdr[SSF_NETWS_FRAME_HDR_MAX];
    uint64_t rxRemain;               /* Payload bytes left in the current frame                 */
    uint8_t rxCtlLen;
    uint8_t rxCtl[SSF_NETWS_CTL_MAX];   /* Control frame payload being collected               */
    uint8_t pongLen;
    uint8_t pong[SSF_NETWS_CTL_MAX];
    uint16_t port;
    char host[SSF_NETWS_CONFIG_MAX_HOST_SIZE];
    char accept[SSF_NETWS_ACCEPT_SIZE];   /* Expected Sec-WebSocket-Accept                     */
    size_t hsLen;                    /* Bytes in hsBuf                                          */
    size_t hsPos;                    /* Next byte of hsBuf to send or to consume                */
    uint8_t hsBuf[SSF_NETWS_CONFIG_HS_BUF_SIZE];
    size_t txLen;
    size_t txPos;
    uint8_t txBuf[SSF_NETWS_FRAME_HDR_MAX + SSF_NETWS_TX_PAYLOAD_MAX];
    SSFPRNGContext_t prng;
    uint32_t magic;
} SSFNetWSSession_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Initializes a session over inner, which must outlive it. path is the request target, e.g.     */
/* "/mqtt" (a query string may follow). fieldsOpt are extra request fields, such as              */
/* Authorization; they may not name Host, Upgrade, Connection, Content-Length,                   */
/* Transfer-Encoding or any Sec-WebSocket- field. All strings are app owned and must stay        */
/* valid. They are checked by open(), which returns false if any is invalid or the request       */
/* does not fit SSF_NETWS_CONFIG_HS_BUF_SIZE. Pass &ws->transport to the client.                 */
void SSFNetWSInit(SSFNetWSSession_t *ws, SSFNetTransport_t *inner, SSFCStrIn_t path,
                  const SSFHTTPHdrField_t *fieldsOpt, uint32_t fieldCount);

/* Closes any connection and wipes the session. */
void SSFNetWSDeInit(SSFNetWSSession_t *ws);

/* Returns the connection state. */
SSFNetWSState_t SSFNetWSGetState(const SSFNetWSSession_t *ws);

#if SSF_CONFIG_NETWS_UNIT_TEST == 1
void SSFNetWSUnitTest(void);
void _SSFNetWSAcceptForTest(SSFCStrIn_t key, char accept[SSF_NETWS_ACCEPT_SIZE]);
#endif /* SSF_CONFIG_NETWS_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_NETWS_H_INCLUDE */
