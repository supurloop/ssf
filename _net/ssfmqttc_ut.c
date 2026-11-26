/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmqttc_ut.c                                                                                 */
/* Unit test for the MQTT 3.1.1 client.                                                          */
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
#include <stdio.h>
#include <string.h>
/* Sleep APIs for the broker test; included unconditionally because SSF_CONFIG_MQTTC_UNIT_TEST_  */
/* BROKER is not defined until ssfport.h below.                                                  */
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfsm.h"
#include "ssfstr.h"
#include "ssfnet.h"
#include "ssfnetsock.h"
#include "ssfnetws.h"
#include "ssfmqttc.h"

#if SSF_CONFIG_MQTTC_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* Design                                                                                        */
/* --------------------------------------------------------------------------------------------- */
/* Two layers. The first checks construction against the real socket transport without ever      */
/* starting the client, so no network is touched. The second drives the client through a scripted */
/* mock transport: the test injects the bytes a broker would send, captures the bytes the client */
/* sends and compares them to hand-encoded packets, and dials transport results on demand. All   */
/* timeouts in the mock scenarios are a few ticks so timer paths run in milliseconds. Keep-alive  */
/* uses keepAliveSec 1, which the unit test build's 250 ms SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT     */
/* allows; other scenarios use 120 and end long before their first ping.                         */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MQTTC_UT_TX_BLOCKS       (4u)
#define SSF_MQTTC_UT_TX_BLOCK_SIZE   (128u)
#define SSF_MQTTC_UT_RX_BLOCK_SIZE   (128u)
#define SSF_MQTTC_UT_BROKER_HOST     "test.mosquitto.org"
#define SSF_MQTTC_UT_BROKER_PORT     (1883u)
#define SSF_MQTTC_UT_MOCK_BUF_SIZE   (2048u)
#define SSF_MQTTC_UT_PUMP_ITERATIONS (10u)
#define SSF_MQTTC_UT_EVENT_LOG_SIZE  (16u)
#define SSF_MQTTC_UT_SHORT_TICKS     (50u)              /* Timeouts the scenarios wait out */
#define SSF_MQTTC_UT_BACKOFF_TICKS   (200u)            /* Longer than any waited-out timeout */
#define SSF_MQTTC_UT_SLACK_TICKS     (30u)
#define SSF_MQTTC_UT_LOAD_TICKS      (500u)            /* Wait bound slack on a loaded host */

#define SSF_MQTTC_UT_ARRAY(a) (a), sizeof(a)

/* --------------------------------------------------------------------------------------------- */
/* Mock transport                                                                                */
/* --------------------------------------------------------------------------------------------- */
typedef struct
{
    SSFNetTransport_t transport;      /* Must be first */
    /* Script */
    bool openResult;                  /* What open() returns                                   */
    SSFNetIOResult_t pollResult;      /* What pollOpen() returns while opening                 */
    SSFNetIOResult_t sendResult;      /* SUCCESS accepts bytes; anything else is returned      */
    size_t sendChunk;                 /* Max bytes accepted per send(); 0 => unlimited         */
    SSFNetIOResult_t recvEmptyResult; /* Returned when no injected bytes remain                */
    size_t recvChunk;                 /* Max bytes returned per recv(); 0 => unlimited         */
    uint32_t shutdownWants;           /* shutdown() returns WANT_WRITE this many times first   */
    SSFNetIOResult_t shutdownResult;  /* Then this                                             */
    /* Observation */
    uint32_t shutdownCount;           /* shutdown() calls on the current connection            */
    bool isShutdown;                  /* shutdown() returned SUCCESS; send() is now invalid    */
    bool wasShutdownAtClose;          /* isShutdown when close() last ran                      */
    bool isOpening;
    bool isOpen;
    uint32_t openCount;
    uint32_t closeCount;
    uint32_t recvCount;               /* recv() calls, to see reads suspended by back-pressure */
    char host[SSF_MQTTC_CONFIG_MAX_HOST_SIZE];
    uint16_t port;
    uint8_t tx[SSF_MQTTC_UT_MOCK_BUF_SIZE];
    size_t txLen;
    uint8_t rx[SSF_MQTTC_UT_MOCK_BUF_SIZE];
    size_t rxLen;
    size_t rxPos;
    size_t rxPadPos;                  /* rx offset at which rxPadLeft filler bytes are served  */
    size_t rxPadLeft;                 /* Filler bytes still to serve; models huge packets      */
} SSFMQTTCUTMock_t;

static SSFMQTTCUTMock_t _utMock;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the scripted open succeeds and records host and port, else false.             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCUTMockOpen(SSFNetTransport_t *t, SSFCStrIn_t host, size_t hostSize,
                                uint16_t port)
{
    SSFMQTTCUTMock_t *m = (SSFMQTTCUTMock_t *)t;
    size_t len;

    SSF_REQUIRE(t == &_utMock.transport);
    SSF_REQUIRE(host != NULL);
    SSF_REQUIRE(hostSize > 0);
    SSF_REQUIRE(m->isOpening == false);
    SSF_REQUIRE(m->isOpen == false);

    m->openCount++;
    SSF_ASSERT(SSFStrLen(host, hostSize, &len));
    SSF_ASSERT(len < sizeof(m->host));
    memcpy(m->host, host, len + 1);
    m->port = port;
    if (m->openResult == false) return false;
    m->isOpening = true;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the scripted poll result, connecting the mock on SUCCESS.                             */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFMQTTCUTMockPollOpen(SSFNetTransport_t *t)
{
    SSFMQTTCUTMock_t *m = (SSFMQTTCUTMock_t *)t;

    SSF_REQUIRE(t == &_utMock.transport);
    SSF_REQUIRE(m->isOpening);

    if (m->pollResult == SSF_NET_IO_SUCCESS)
    {
        m->isOpening = false;
        m->isOpen = true;
    }
    else if ((m->pollResult != SSF_NET_IO_WANT_READ) && (m->pollResult != SSF_NET_IO_WANT_WRITE))
    {
        m->isOpening = false;
    }
    return m->pollResult;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the scripted send result, capturing accepted bytes.                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFMQTTCUTMockSend(SSFNetTransport_t *t, const uint8_t *buf,
                                            size_t len, size_t *sentOut)
{
    SSFMQTTCUTMock_t *m = (SSFMQTTCUTMock_t *)t;
    size_t n = len;

    SSF_REQUIRE(t == &_utMock.transport);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(len > 0);
    SSF_REQUIRE(sentOut != NULL);
    SSF_REQUIRE(m->isOpen);
    SSF_ASSERT(m->isShutdown == false);           /* ssfnet.h: send() is not valid after it */

    *sentOut = 0;
    if (m->sendResult != SSF_NET_IO_SUCCESS) return m->sendResult;
    if ((m->sendChunk > 0) && (n > m->sendChunk)) n = m->sendChunk;
    SSF_ASSERT((m->txLen + n) <= sizeof(m->tx));
    memcpy(&m->tx[m->txLen], buf, n);
    m->txLen += n;
    *sentOut = n;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns injected bytes, or the scripted empty result when none remain.                        */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFMQTTCUTMockRecv(SSFNetTransport_t *t, uint8_t *buf, size_t size,
                                            size_t *gotOut)
{
    SSFMQTTCUTMock_t *m = (SSFMQTTCUTMock_t *)t;
    size_t avail;

    SSF_REQUIRE(t == &_utMock.transport);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(gotOut != NULL);
    SSF_REQUIRE(m->isOpen);

    avail = m->rxLen - m->rxPos;

    m->recvCount++;
    *gotOut = 0;
    if ((m->recvChunk > 0) && (size > m->recvChunk)) size = m->recvChunk;
    if ((m->rxPadLeft > 0) && (m->rxPos == m->rxPadPos))
    {
        avail = (m->rxPadLeft < size) ? m->rxPadLeft : size;
        memset(buf, 'p', avail);
        m->rxPadLeft -= avail;
        *gotOut = avail;
        return SSF_NET_IO_SUCCESS;
    }
    if ((m->rxPadLeft > 0) && (avail > (m->rxPadPos - m->rxPos))) avail = m->rxPadPos - m->rxPos;
    if (avail == 0) return m->recvEmptyResult;
    if (avail > size) avail = size;
    memcpy(buf, &m->rx[m->rxPos], avail);
    m->rxPos += avail;
    *gotOut = avail;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns WANT_WRITE shutdownWants times, then the scripted shutdown result.                    */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFMQTTCUTMockShutdown(SSFNetTransport_t *t)
{
    SSFMQTTCUTMock_t *m = (SSFMQTTCUTMock_t *)t;

    SSF_REQUIRE(t == &_utMock.transport);
    SSF_ASSERT(m->isOpen);                        /* Only after pollOpen() SUCCESS */

    m->shutdownCount++;
    if (m->shutdownWants > 0) { m->shutdownWants--; return SSF_NET_IO_WANT_WRITE; }
    if (m->shutdownResult == SSF_NET_IO_SUCCESS) m->isShutdown = true;
    return m->shutdownResult;
}

/* --------------------------------------------------------------------------------------------- */
/* Closes the mock and counts the close.                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTMockClose(SSFNetTransport_t *t)
{
    SSFMQTTCUTMock_t *m = (SSFMQTTCUTMock_t *)t;

    SSF_REQUIRE(t == &_utMock.transport);
    SSF_REQUIRE(m->isOpen || m->isOpening);

    m->closeCount++;
    m->wasShutdownAtClose = m->isShutdown;
    m->isShutdown = false;
    m->isOpen = false;
    m->isOpening = false;
}

/* --------------------------------------------------------------------------------------------- */
/* Resets the mock to a cooperative script.                                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTMockReset(void)
{
    memset(&_utMock, 0, sizeof(_utMock));
    _utMock.transport.open = _SSFMQTTCUTMockOpen;
    _utMock.transport.pollOpen = _SSFMQTTCUTMockPollOpen;
    _utMock.transport.send = _SSFMQTTCUTMockSend;
    _utMock.transport.recv = _SSFMQTTCUTMockRecv;
    _utMock.transport.shutdown = _SSFMQTTCUTMockShutdown;
    _utMock.transport.close = _SSFMQTTCUTMockClose;
    _utMock.shutdownResult = SSF_NET_IO_SUCCESS;
    _utMock.openResult = true;
    _utMock.pollResult = SSF_NET_IO_SUCCESS;
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _utMock.recvEmptyResult = SSF_NET_IO_WANT_READ;
}

/* --------------------------------------------------------------------------------------------- */
/* Queues bytes for the client to receive.                                                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTInject(const uint8_t *bytes, size_t len)
{
    SSF_REQUIRE(bytes != NULL);
    SSF_REQUIRE(len > 0);
    SSF_ASSERT((_utMock.rxLen + len) <= sizeof(_utMock.rx));

    memcpy(&_utMock.rx[_utMock.rxLen], bytes, len);
    _utMock.rxLen += len;
}

/* --------------------------------------------------------------------------------------------- */
/* Queues n filler bytes after the bytes injected so far, without storing them.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTInjectPad(size_t n)
{
    SSF_REQUIRE(n > 0);
    SSF_ASSERT(_utMock.rxPadLeft == 0);             /* One filler segment at a time */

    _utMock.rxPadPos = _utMock.rxLen;
    _utMock.rxPadLeft = n;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts the client sent exactly these bytes since the last check, then clears them.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTExpectTx(const uint8_t *bytes, size_t len)
{
    SSF_REQUIRE((bytes != NULL) || (len == 0));

    SSF_ASSERT(_utMock.txLen == len);
    if (len > 0) SSF_ASSERT(memcmp(_utMock.tx, bytes, len) == 0);
    _utMock.txLen = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Callback recording                                                                            */
/* --------------------------------------------------------------------------------------------- */
typedef struct
{
    SSFMQTTCEvent_t event;
    SSFMQTTCReason_t reason;
} SSFMQTTCUTEventRec_t;

static SSFMQTTCUTEventRec_t _utEvents[SSF_MQTTC_UT_EVENT_LOG_SIZE];
static uint32_t _utEventCount;
static uint32_t _utEventCtx;

static SSFMQTTCRxPublish_t _utRx;             /* Last offer; topic/payload copied below */
static char _utRxTopic[SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE];
static uint8_t _utRxPayload[SSF_MQTTC_UT_RX_BLOCK_SIZE];
static uint32_t _utRxPublishCount;
static char _utRxTaken[64];                   /* First topic byte of each accepted PUBLISH */
static uint32_t _utRxTakenCount;
static bool _utRxAccept;                      /* What the rxPublish callback returns */
static uint32_t _utRxPublishCtx;

static uint32_t _utTxDoneCount;
static uint32_t _utTxDoneTrueCount;
static void *_utTxDoneLastCtx;

/* --------------------------------------------------------------------------------------------- */
/* Clears all callback records.                                                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTRecordReset(void)
{
    memset(_utEvents, 0, sizeof(_utEvents));
    _utEventCount = 0;
    memset(&_utRx, 0, sizeof(_utRx));
    _utRxPublishCount = 0;
    memset(_utRxTaken, 0, sizeof(_utRxTaken));
    _utRxTakenCount = 0;
    _utRxAccept = true;
    _utTxDoneCount = 0;
    _utTxDoneTrueCount = 0;
    _utTxDoneLastCtx = NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the scripted accept flag after recording the offered PUBLISH.                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCUTRxPublish(void *ctx, const SSFMQTTCRxPublish_t *rxPublish)
{
    SSF_REQUIRE(ctx == &_utRxPublishCtx);
    SSF_REQUIRE(rxPublish != NULL);
    SSF_REQUIRE(rxPublish->topic != NULL);
    SSF_REQUIRE(rxPublish->topic[rxPublish->topicLen] == 0);
    SSF_REQUIRE((rxPublish->payload != NULL) || (rxPublish->payloadLen == 0));
    SSF_ASSERT(rxPublish->topicLen < sizeof(_utRxTopic));
    SSF_ASSERT(rxPublish->payloadLen <= sizeof(_utRxPayload));

    _utRxPublishCount++;
    _utRx = *rxPublish;
    memcpy(_utRxTopic, rxPublish->topic, rxPublish->topicLen + 1);
    if (rxPublish->payloadLen > 0) memcpy(_utRxPayload, rxPublish->payload, rxPublish->payloadLen);
    _utRx.topic = _utRxTopic;
    _utRx.payload = _utRxPayload;
    if (_utRxAccept && (_utRxTakenCount < (sizeof(_utRxTaken) - 1u)))
    { _utRxTaken[_utRxTakenCount++] = rxPublish->topic[0]; }
    return _utRxAccept;
}

/* --------------------------------------------------------------------------------------------- */
/* Records an event and reason.                                                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason)
{
    SSF_REQUIRE(ctx == &_utEventCtx);
    SSF_REQUIRE((event > SSF_MQTTC_EVENT_MIN) && (event < SSF_MQTTC_EVENT_MAX));
    SSF_REQUIRE((reason > SSF_MQTTC_REASON_MIN) && (reason < SSF_MQTTC_REASON_MAX));
    SSF_ASSERT(_utEventCount < SSF_MQTTC_UT_EVENT_LOG_SIZE);

    _utEvents[_utEventCount].event = event;
    _utEvents[_utEventCount].reason = reason;
    _utEventCount++;
}

/* --------------------------------------------------------------------------------------------- */
/* Records a txPublish completion.                                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTTxDone(void *ctx, bool isPublished)
{
    _utTxDoneCount++;
    if (isPublished) _utTxDoneTrueCount++;
    _utTxDoneLastCtx = ctx;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts the event log holds exactly these events in order, then clears it.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTExpectEvents(const SSFMQTTCUTEventRec_t *expected, uint32_t count)
{
    uint32_t i;

    SSF_REQUIRE((expected != NULL) || (count == 0));

    SSF_ASSERT(_utEventCount == count);
    for (i = 0; i < count; i++)
    {
        SSF_ASSERT(_utEvents[i].event == expected[i].event);
        SSF_ASSERT(_utEvents[i].reason == expected[i].reason);
    }
    _utEventCount = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Runs both tasks until event chains settle.                                                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTPump(void)
{
    uint32_t i;

    for (i = 0; i < SSF_MQTTC_UT_PUMP_ITERATIONS; i++)
    {
        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Runs both tasks for at least ticks of wall clock time.                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTPumpFor(SSFPortTick_t ticks)
{
    SSFPortTick_t end = SSFPortGetTick64() + ticks;

    while (SSFPortGetTick64() < end) _SSFMQTTCUTPump();
    _SSFMQTTCUTPump();
}

/* --------------------------------------------------------------------------------------------- */
/* Pumps until the client is in state, asserting if that takes more than ticks.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTPumpUntilState(SSFMQTTCState_t state, SSFPortTick_t ticks)
{
    SSFPortTick_t end = SSFPortGetTick64() + ticks;

    for (;;)
    {
        bool isLate = (SSFPortGetTick64() > end);  /* Sampled before the tasks run */

        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
        if (SSFMQTTCGetState() == state) break;
        SSF_ASSERT(isLate == false);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Scenario scaffolding                                                                          */
/* --------------------------------------------------------------------------------------------- */
static const SSFMQTTCSub_t _utOneSub[] = { { "a/b", SSF_MQTTC_QOS_1 } };

/* --------------------------------------------------------------------------------------------- */
/* Fills opts for the mock: short timeouts, client id "ut", keep-alive 120.                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTOptsInit(SSFMQTTCOpts_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->host = "mock";
    opts->port = 1883;
    opts->clientId = "ut";
    opts->subsOpt = _utOneSub;
    opts->subCount = 1;
    opts->keepAliveSec = 120;                      /* As in _utPktConnect; no ping in a scenario */
    opts->connectTimeout = SSF_MQTTC_UT_SHORT_TICKS;
    opts->subscribeTimeout = SSF_MQTTC_UT_SHORT_TICKS;
    opts->txPublishTimeout = SSF_MQTTC_UT_SHORT_TICKS;
    opts->reconnectMinWait = SSF_MQTTC_UT_BACKOFF_TICKS;
    opts->reconnectMaxWait = SSF_MQTTC_UT_BACKOFF_TICKS * 4;
}

/* --------------------------------------------------------------------------------------------- */
/* Creates a fresh state machine, mock and STOPPED client with the given rx block size.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTBeginRx(uint32_t txBlocks, uint32_t rxBlockSize)
{
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    _SSFMQTTCUTMockReset();
    _SSFMQTTCUTRecordReset();
    SSFMQTTCInit(&_utMock.transport, txBlocks, SSF_MQTTC_UT_TX_BLOCK_SIZE, rxBlockSize,
                 _SSFMQTTCUTRxPublish, &_utRxPublishCtx, _SSFMQTTCUTEvent, &_utEventCtx);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
}

/* --------------------------------------------------------------------------------------------- */
/* Creates a fresh state machine, mock and STOPPED client with the default rx block size.        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTBegin(uint32_t txBlocks)
{
    _SSFMQTTCUTBeginRx(txBlocks, SSF_MQTTC_UT_RX_BLOCK_SIZE);
}

/* --------------------------------------------------------------------------------------------- */
/* Stops the client if running and tears everything down.                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTEnd(void)
{
    if (SSFMQTTCIsStarted())
    {
        SSFMQTTCStop();
        _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SLACK_TICKS);
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    }
    SSFMQTTCDeInit();
    SSFSMDeInit();
}

/* Hand-encoded packets for client id "ut", keep-alive 120, filter "a/b" QoS 1. */
static const uint8_t _utPktConnect[] =
{ 0x10, 0x0E, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x78, 0x00, 0x02, 'u', 't' };
static const uint8_t _utPktConnAckOk[] = { 0x20, 0x02, 0x00, 0x00 };
static const uint8_t _utPktSubscribe1[] = { 0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'a', '/', 'b', 0x01 };
static const uint8_t _utPktSubAckOk1[] = { 0x90, 0x03, 0x00, 0x01, 0x01 };
static const uint8_t _utPktDisconnect[] = { 0xE0, 0x00 };

/* --------------------------------------------------------------------------------------------- */
/* Drives the client to READY against a cooperative mock, verifying every byte.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTGoReady(const SSFMQTTCOpts_t *opts)
{
    static const SSFMQTTCUTEventRec_t expected[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_NONE },
    };

    SSFMQTTCStart(opts);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.openCount == 1);
    SSF_ASSERT(strcmp(_utMock.host, opts->host) == 0);
    SSF_ASSERT(_utMock.port == opts->port);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTING);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));

    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_SUBSCRIBING);
    SSF_ASSERT(SSFMQTTCIsConnected());
    SSF_ASSERT(SSFMQTTCIsReady() == false);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribe1));

    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktSubAckOk1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    SSF_ASSERT(SSFMQTTCIsReady());
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTExpectEvents(expected, 2);
}

/* --------------------------------------------------------------------------------------------- */
/* Layer 1: construction against the real socket transport, never started                       */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSock_t _utSock;

/* --------------------------------------------------------------------------------------------- */
/* Tests construction and option validation on the socket transport without starting.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTConstruction(void)
{
    static const SSFMQTTCSub_t subs[] =
    {
        { "ssf/ut/+/status", SSF_MQTTC_QOS_1 },
        { "ssf/ut/control/#", SSF_MQTTC_QOS_0 },
    };
    SSFMQTTCOpts_t opts;

    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    SSFNetSockInit(&_utSock);
    _SSFMQTTCUTRecordReset();

    /* Init requires */
    SSF_ASSERT_TEST(SSFMQTTCInit(NULL, SSF_MQTTC_UT_TX_BLOCKS, SSF_MQTTC_UT_TX_BLOCK_SIZE,
                                 SSF_MQTTC_UT_RX_BLOCK_SIZE, _SSFMQTTCUTRxPublish,
                                 &_utRxPublishCtx, _SSFMQTTCUTEvent, &_utEventCtx));
    SSF_ASSERT_TEST(SSFMQTTCInit(&_utSock.transport, 0, SSF_MQTTC_UT_TX_BLOCK_SIZE,
                                 SSF_MQTTC_UT_RX_BLOCK_SIZE, _SSFMQTTCUTRxPublish,
                                 &_utRxPublishCtx, _SSFMQTTCUTEvent, &_utEventCtx));
    SSF_ASSERT_TEST(SSFMQTTCInit(&_utSock.transport, SSF_MQTTC_UT_TX_BLOCKS, 3,
                                 SSF_MQTTC_UT_RX_BLOCK_SIZE, _SSFMQTTCUTRxPublish,
                                 &_utRxPublishCtx, _SSFMQTTCUTEvent, &_utEventCtx));
    SSF_ASSERT_TEST(SSFMQTTCInit(&_utSock.transport, SSF_MQTTC_UT_TX_BLOCKS,
                                 SSF_MQTTC_UT_TX_BLOCK_SIZE, 3, _SSFMQTTCUTRxPublish,
                                 &_utRxPublishCtx, _SSFMQTTCUTEvent, &_utEventCtx));
    SSF_ASSERT_TEST(SSFMQTTCInit(&_utSock.transport, SSF_MQTTC_UT_TX_BLOCKS,
                                 SSF_MQTTC_UT_TX_BLOCK_SIZE, SSF_MQTTC_UT_RX_BLOCK_SIZE, NULL,
                                 &_utRxPublishCtx, _SSFMQTTCUTEvent, &_utEventCtx));
    SSF_ASSERT_TEST(SSFMQTTCInit(&_utSock.transport, SSF_MQTTC_UT_TX_BLOCKS,
                                 SSF_MQTTC_UT_TX_BLOCK_SIZE, SSF_MQTTC_UT_RX_BLOCK_SIZE,
                                 _SSFMQTTCUTRxPublish, &_utRxPublishCtx, NULL, &_utEventCtx));

    {
        SSFNetTransport_t noShutdown = _utSock.transport;

        noShutdown.shutdown = NULL;
        SSF_ASSERT_TEST(SSFMQTTCInit(&noShutdown, SSF_MQTTC_UT_TX_BLOCKS,
                                     SSF_MQTTC_UT_TX_BLOCK_SIZE, SSF_MQTTC_UT_RX_BLOCK_SIZE,
                                     _SSFMQTTCUTRxPublish, &_utRxPublishCtx, _SSFMQTTCUTEvent,
                                     &_utEventCtx));
    }

    /* Nothing may be used before Init */
    SSF_ASSERT_TEST(SSFMQTTCGetState());
    SSF_ASSERT_TEST(SSFMQTTCStop());
    SSF_ASSERT_TEST(SSFMQTTCDeInit());

    /* Init; the client is STOPPED and silent */
    SSFMQTTCInit(&_utSock.transport, SSF_MQTTC_UT_TX_BLOCKS, SSF_MQTTC_UT_TX_BLOCK_SIZE,
                 SSF_MQTTC_UT_RX_BLOCK_SIZE, _SSFMQTTCUTRxPublish, &_utRxPublishCtx,
                 _SSFMQTTCUTEvent, &_utEventCtx);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(SSFMQTTCIsStarted() == false);
    SSF_ASSERT(SSFMQTTCIsConnected() == false);
    SSF_ASSERT(SSFMQTTCIsReady() == false);
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT_TEST(SSFMQTTCInit(&_utSock.transport, SSF_MQTTC_UT_TX_BLOCKS,
                                 SSF_MQTTC_UT_TX_BLOCK_SIZE, SSF_MQTTC_UT_RX_BLOCK_SIZE,
                                 _SSFMQTTCUTRxPublish, &_utRxPublishCtx, _SSFMQTTCUTEvent,
                                 &_utEventCtx));                         /* Twice */

    /* Stop and TxPublish are not valid when not started */
    SSF_ASSERT_TEST(SSFMQTTCStop());
    SSF_ASSERT(SSFMQTTCTxPublish("ssf/ut/0001/status", (const uint8_t *)"x", 1,
                                 SSF_MQTTC_QOS_0, false, NULL, NULL) == false);

    /* Options for a public broker, validated by Start() but the client is never started */
    memset(&opts, 0, sizeof(opts));
    opts.host = SSF_MQTTC_UT_BROKER_HOST;
    opts.port = SSF_MQTTC_UT_BROKER_PORT;
    opts.clientId = "ssf-ut-0001";
    opts.subsOpt = subs;
    opts.subCount = (uint32_t)(sizeof(subs) / sizeof(subs[0]));
    opts.keepAliveSec = 120;
    opts.connectTimeout = SSF_TICKS_PER_SEC * 10;
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 10;
    opts.txPublishTimeout = SSF_TICKS_PER_SEC * 10;
    opts.reconnectMinWait = SSF_TICKS_PER_SEC * 2;
    opts.reconnectMaxWait = SSF_TICKS_PER_SEC * 60;

    /* Start requires, each on a copy with one field broken */
    {
        SSFMQTTCOpts_t bad;

        SSF_ASSERT_TEST(SSFMQTTCStart(NULL));
        bad = opts; bad.host = NULL;                      SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.port = 0;                         SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.clientId = NULL;                  SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.clientId = "";                    SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.passwordOpt = (const uint8_t *)"p"; bad.passwordLen = 1;
                                                          SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.subsOpt = NULL;                   SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.subCount = SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS + 1;
                                                          SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.keepAliveSec = 0;                 SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.connectTimeout = 0;               SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.subscribeTimeout = 0;             SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.txPublishTimeout = 0;             SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.reconnectMinWait = 0;             SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.reconnectMaxWait = opts.reconnectMinWait - 1;
                                                          SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        /* Strings are printable ASCII; filters need valid wildcard placement */
        bad = opts; bad.clientId = "dev\x01";             SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.clientId = "d\xc3\xa9v";          SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.usernameOpt = "u\x7f";            SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        {
            static const SSFMQTTCSub_t badSubs[][1] =
            {
                { { "a/#/b", SSF_MQTTC_QOS_0 } }, { { "a+", SSF_MQTTC_QOS_0 } },
                { { "#/", SSF_MQTTC_QOS_0 } }, { { "a\tb", SSF_MQTTC_QOS_0 } },
            };
            static const SSFMQTTCWill_t badWill = { "w\x1f", NULL, 0, SSF_MQTTC_QOS_0, false };
            volatile uint32_t i;                          /* Survives SSF_ASSERT_TEST's longjmp */

            for (i = 0; i < (sizeof(badSubs) / sizeof(badSubs[0])); i++)
            {
                bad = opts; bad.subsOpt = badSubs[i]; bad.subCount = 1;
                SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
            }
            bad = opts; bad.willOpt = &badWill;            SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        }
    }

    /* Idle pump: nothing to do while STOPPED */
    {
        SSFPortTick_t to = SSF_MAX_NEXT_TIMEOUT;
        SSF_ASSERT(SSFMQTTCTask(&to) == false);
        SSF_ASSERT(to == SSF_MAX_NEXT_TIMEOUT);
        SSF_ASSERT(SSFMQTTCTask(NULL) == false);
        SSF_ASSERT(SSFSMTask(NULL) == false);
    }
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT(_utRxPublishCount == 0);

    SSFMQTTCDeInit();
    SSF_ASSERT_TEST(SSFMQTTCDeInit());                                   /* Twice */
    SSFNetSockDeInit(&_utSock);
    SSFSMDeInit();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests connect, subscribe, READY, and Stop with DISCONNECT and STOPPED.                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioHappyPath(void)
{
    static const SSFMQTTCUTEventRec_t stopped[] = { { SSF_MQTTC_EVENT_STOPPED, SSF_MQTTC_REASON_NONE } };
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    /* A second Start while running asserts */
    SSF_ASSERT_TEST(SSFMQTTCStart(&opts));

    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utMock.closeCount == 1);
    SSF_ASSERT(_utMock.shutdownCount == 1);         /* DISCONNECT delivered before close() */
    SSF_ASSERT(_utMock.wasShutdownAtClose);
    _SSFMQTTCUTExpectEvents(stopped, 1);
    SSF_ASSERT_TEST(SSFMQTTCStop());                                      /* Twice */
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests a pending open and a transport that accepts one byte per send.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSlowTransport(void)
{
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _utMock.pollResult = SSF_NET_IO_WANT_WRITE;
    _utMock.sendChunk = 1;

    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.isOpening);
    SSF_ASSERT(_utMock.txLen == 0);                 /* Nothing sent until connected */

    _utMock.pollResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPump();                              /* Each pass sends one byte; pump reports more */
    SSF_ASSERT(SSFMQTTCTask(NULL));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that READY follows CONNACK directly with no subscriptions.                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioNoSubscriptions(void)
{
    static const SSFMQTTCUTEventRec_t expected[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_NONE },
    };
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    opts.subsOpt = NULL;
    opts.subCount = 0;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCIsReady());
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTExpectEvents(expected, 2);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests outbound QoS 0 and QoS 1 publishes: bytes, completion and context.                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioTxPublish(void)
{
    static const uint8_t pub0[] = { 0x30, 0x07, 0x00, 0x03, 'a', '/', 'b', 'h', 'i' };
    static const uint8_t pub1[] = { 0x32, 0x09, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x02, 'h', 'i' };
    static const uint8_t pubAck2[] = { 0x40, 0x02, 0x00, 0x02 };
    static const uint8_t pub0R[] = { 0x31, 0x07, 0x00, 0x03, 'a', '/', 'b', 'h', 'i' };
    static const uint8_t pub1R[] = { 0x33, 0x09, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x03, 'h', 'i' };
    static const uint8_t pubAck3[] = { 0x40, 0x02, 0x00, 0x03 };
    static const uint8_t clearR[] = { 0x31, 0x05, 0x00, 0x03, 'a', '/', 'b' };
    static uint8_t ctx0;
    static uint8_t ctx1;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    /* Argument requires */
    SSF_ASSERT_TEST(SSFMQTTCTxPublish(NULL, (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, false,
                                      NULL, NULL));
    SSF_ASSERT_TEST(SSFMQTTCTxPublish("a/b", NULL, 2, SSF_MQTTC_QOS_0, false, NULL, NULL));
    SSF_ASSERT_TEST(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_2, false,
                                      NULL, NULL));
    SSF_ASSERT_TEST(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, false,
                                      NULL, &ctx0));

    /* Refusals that are not app errors */
    SSF_ASSERT(SSFMQTTCTxPublish("", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, false, NULL,
                                 NULL) == false);
    {
        /* A wildcard, or a character outside printable ASCII, would make the broker disconnect */
        static const char *badTopics[] =
        { "a/+", "#", "a/b#", "+", "a\tb", "caf\xc3\xa9", "\x7f" };
        uint32_t i;

        for (i = 0; i < (sizeof(badTopics) / sizeof(badTopics[0])); i++)
        {
            SSF_ASSERT(SSFMQTTCTxPublish(badTopics[i], (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_1,
                                         false, _SSFMQTTCUTTxDone, NULL) == false);
        }
        SSF_ASSERT(_utTxDoneCount == 0);              /* Refused: no completion */
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectTx(NULL, 0);
        SSF_ASSERT(SSFMQTTCIsReady());
    }
    {
        uint8_t big[SSF_MQTTC_UT_TX_BLOCK_SIZE];
        memset(big, 'x', sizeof(big));
        SSF_ASSERT(SSFMQTTCTxPublish("a/b", big, sizeof(big), SSF_MQTTC_QOS_0, false, NULL,
                                     NULL) == false);
    }

    /* QoS 0 completes when sent, from the pump, with its context */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, false,
                                 _SSFMQTTCUTTxDone, &ctx0));
    SSF_ASSERT(_utTxDoneCount == 0);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pub0));
    SSF_ASSERT(_utTxDoneCount == 1);
    SSF_ASSERT(_utTxDoneTrueCount == 1);
    SSF_ASSERT(_utTxDoneLastCtx == &ctx0);

    /* QoS 1 takes packet id 2 (SUBSCRIBE took 1) and completes on PUBACK */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_1, false,
                                 _SSFMQTTCUTTxDone, &ctx1));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pub1));
    SSF_ASSERT(_utTxDoneCount == 1);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pubAck2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utTxDoneCount == 2);
    SSF_ASSERT(_utTxDoneTrueCount == 2);
    SSF_ASSERT(_utTxDoneLastCtx == &ctx1);

    /* RETAIN at QoS 0 sets bit 0 and completes when sent */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, true,
                                 _SSFMQTTCUTTxDone, &ctx0));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pub0R));
    SSF_ASSERT(_utTxDoneCount == 3);
    SSF_ASSERT(_utTxDoneTrueCount == 3);
    SSF_ASSERT(_utTxDoneLastCtx == &ctx0);

    /* RETAIN at QoS 1 sets bit 0 and still completes on PUBACK */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_1, true,
                                 _SSFMQTTCUTTxDone, &ctx1));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pub1R));
    SSF_ASSERT(_utTxDoneCount == 3);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pubAck3));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utTxDoneCount == 4);
    SSF_ASSERT(_utTxDoneTrueCount == 4);
    SSF_ASSERT(_utTxDoneLastCtx == &ctx1);

    /* An empty retained payload, the message that clears a retained topic */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", NULL, 0, SSF_MQTTC_QOS_0, true, NULL, NULL));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(clearR));

    /* A PUBACK for an unknown id is ignored */
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pubAck2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCIsReady());
    SSF_ASSERT(_utEventCount == 0);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests tx pool exhaustion behind a stalled transport and recovery.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioTxPoolFull(void)
{
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(2);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"1", 1, SSF_MQTTC_QOS_0, false,
                                 _SSFMQTTCUTTxDone, NULL));
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"2", 1, SSF_MQTTC_QOS_0, false,
                                 _SSFMQTTCUTTxDone, NULL));
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"3", 1, SSF_MQTTC_QOS_0, false,
                                 _SSFMQTTCUTTxDone, NULL) == false);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.txLen == 0);
    SSF_ASSERT(_utTxDoneCount == 0);

    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.txLen == 2 * 8);             /* Two 8-byte QoS 0 publishes */
    SSF_ASSERT(_utTxDoneCount == 2);
    SSF_ASSERT(_utTxDoneTrueCount == 2);
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"3", 1, SSF_MQTTC_QOS_0, false, NULL,
                                 NULL));
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests inbound PUBLISH delivery, acknowledgement and flag propagation.                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxPublish(void)
{
    static const uint8_t in1[] = { 0x32, 0x06, 0x00, 0x01, 't', 0x01, 0x01, 'p' };    /* QoS 1 id 0x0101 */
    static const uint8_t ack1[] = { 0x40, 0x02, 0x01, 0x01 };
    static const uint8_t in0[] = { 0x31, 0x03, 0x00, 0x01, 'u' };                     /* QoS 0, RETAIN, no payload */
    static const uint8_t inDup[] = { 0x3B, 0x06, 0x00, 0x01, 'v', 0x02, 0x02, 'q' };  /* QoS 1 id 0x0202, DUP, RETAIN */
    static const uint8_t ackDup[] = { 0x40, 0x02, 0x02, 0x02 };
    static const uint8_t badDup0[] = { 0x38, 0x03, 0x00, 0x01, 'w' };                 /* DUP at QoS 0 is malformed */
    static const SSFMQTTCUTEventRec_t protocol[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(in1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, "t") == 0);
    SSF_ASSERT(_utRx.topicLen == 1);
    SSF_ASSERT(_utRx.payloadLen == 1);
    SSF_ASSERT(_utRxPayload[0] == 'p');
    SSF_ASSERT(_utRx.qos == SSF_MQTTC_QOS_1);
    SSF_ASSERT(_utRx.retain == false);
    SSF_ASSERT(_utRx.dup == false);
    SSF_ASSERT(_utRx.offerCount == 1);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ack1));

    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(in0));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 2);
    SSF_ASSERT(strcmp(_utRxTopic, "u") == 0);
    SSF_ASSERT(_utRx.payloadLen == 0);
    SSF_ASSERT(_utRx.qos == SSF_MQTTC_QOS_0);
    SSF_ASSERT(_utRx.retain);
    SSF_ASSERT(_utRx.dup == false);
    _SSFMQTTCUTExpectTx(NULL, 0);

    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(inDup));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 3);
    SSF_ASSERT(strcmp(_utRxTopic, "v") == 0);
    SSF_ASSERT(_utRx.qos == SSF_MQTTC_QOS_1);
    SSF_ASSERT(_utRx.retain);
    SSF_ASSERT(_utRx.dup);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ackDup));
    SSF_ASSERT(_utEventCount == 0);

    /* DUP with QoS 0 violates the specification and ends the connection */
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(badDup0));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 3);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(protocol, 1);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests a deferred inbound PUBLISH: blocking, retry timing and later acknowledgement.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxDefer(void)
{
    static const uint8_t inA[] = { 0x32, 0x05, 0x00, 0x01, 'a', 0x00, 0x0A };
    static const uint8_t inB[] = { 0x30, 0x03, 0x00, 0x01, 'b' };
    static const uint8_t ackA[] = { 0x40, 0x02, 0x00, 0x0A };
    SSFMQTTCOpts_t opts;
    SSFPortTick_t to;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    _utRxAccept = false;
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(inA));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(inB));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);             /* Offered once, deferred; B waits behind it */
    SSF_ASSERT(strcmp(_utRxTopic, "a") == 0);
    SSF_ASSERT(_utRx.offerCount == 1);
    _SSFMQTTCUTExpectTx(NULL, 0);                   /* No PUBACK for a deferred packet */

    /* The pump reports the retry due time, and does not re-offer before it */
    to = SSF_MAX_NEXT_TIMEOUT;
    (void)SSFMQTTCTask(&to);
    SSF_ASSERT(to <= SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS);
    SSF_ASSERT(_utRxPublishCount == 1);

    _utRxAccept = true;
    {
        SSFPortTick_t end = SSFPortGetTick64() + SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS +
                            (4u * SSF_MQTTC_UT_LOAD_TICKS);

        while ((_utRxTakenCount < 2) && (SSFPortGetTick64() < end)) _SSFMQTTCUTPump();
        _SSFMQTTCUTPump();
    }
    SSF_ASSERT(strcmp(_utRxTaken, "ab") == 0);      /* A re-offered and taken, then B */
    SSF_ASSERT(_utRxPublishCount >= 3);             /* A loaded host may re-offer A once more */
    SSF_ASSERT(strcmp(_utRxTopic, "b") == 0);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ackA));
    SSF_ASSERT(_utEventCount == 0);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a QoS 0 PUBLISH finding the queue full is dropped and reported, unacknowledged,   */
/* and that reading goes on: QoS 0 never causes back-pressure.                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxQueueFull(void)
{
    static const uint8_t in[] = { 0x32, 0x05, 0x00, 0x01, 'q', 0x00, 0x01 };
    static const uint8_t in0[] = { 0x30, 0x03, 0x00, 0x01, 'z' };
    static const SSFMQTTCUTEventRec_t dropped[] =
    {
        { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_QUEUE_FULL },
        { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_QUEUE_FULL },
    };
    uint8_t pkt[sizeof(in)];
    uint32_t i;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    _utRxAccept = false;                            /* Head is deferred; queue fills behind it */
    memcpy(pkt, in, sizeof(pkt));
    for (i = 0; i < SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        pkt[sizeof(pkt) - 1] = (uint8_t)(i + 1);    /* Distinct packet ids 1..depth */
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(in0));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(in0));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(_utMock.rxPos == _utMock.rxLen);    /* Everything read */
    _SSFMQTTCUTExpectEvents(dropped, 2);
    _SSFMQTTCUTExpectTx(NULL, 0);                   /* No PUBACK for QoS 0 */

    /* Teardown discards the queued packets without further offers; stop flushes nothing else */
    _SSFMQTTCUTEnd();
    SSF_ASSERT(_utRxPublishCount == 1);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests a refused CONNACK: reason, no DISCONNECT, backoff and a new attempt.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioConnAckRefused(void)
{
    static const uint8_t connAckBad[] = { 0x20, 0x02, 0x00, 0x04 };
    static const SSFMQTTCUTEventRec_t failed[] =
    { { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_CONNACK_BAD_CREDENTIALS } };
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(connAckBad));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utMock.closeCount == 1);
    _SSFMQTTCUTExpectTx(NULL, 0);                   /* No DISCONNECT: no session was up */
    _SSFMQTTCUTExpectEvents(failed, 1);

    /* Not before the backoff, then a second open and a fresh CONNECT */
    SSF_ASSERT(_utMock.openCount == 1);
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(_utMock.openCount == 2);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTING);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTEnd();
}

/* Two filters: "a/b" QoS 1 and "c" QoS 0. */
static const SSFMQTTCSub_t _utTwoSubs[] = { { "a/b", SSF_MQTTC_QOS_1 }, { "c", SSF_MQTTC_QOS_0 } };
static const uint8_t _utPktSubscribe2Subs[] =
{ 0x82, 0x0C, 0x00, 0x01, 0x00, 0x03, 'a', '/', 'b', 0x01, 0x00, 0x01, 'c', 0x00 };

/* --------------------------------------------------------------------------------------------- */
/* Drives a fresh client with opts through CONNACK, expects subscribe, injects subAck and pumps. */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTSubAckAttemptOpts(const SSFMQTTCOpts_t *opts, const uint8_t *subscribe,
                                         size_t subscribeLen, const uint8_t *subAck,
                                         size_t subAckLen)
{
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    SSFMQTTCStart(opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(subscribe, subscribeLen);
    _SSFMQTTCUTInject(subAck, subAckLen);
    _SSFMQTTCUTPump();
}

/* --------------------------------------------------------------------------------------------- */
/* Fills opts for subs/subCount with timeouts long enough for a loaded host.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTSubOptsInit(SSFMQTTCOpts_t *opts, const SSFMQTTCSub_t *subs,
                                   uint32_t subCount)
{
    _SSFMQTTCUTOptsInit(opts);
    opts->subsOpt = subs;
    opts->subCount = subCount;
    opts->connectTimeout = SSF_TICKS_PER_SEC * 5u;    /* Reconnects must not race a loaded host */
    opts->subscribeTimeout = SSF_TICKS_PER_SEC * 5u;
}

/* --------------------------------------------------------------------------------------------- */
/* Drives a fresh client through CONNACK, injects subAck and pumps; opts uses subs/subCount.     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTSubAckAttempt(const SSFMQTTCSub_t *subs, uint32_t subCount,
                                     const uint8_t *subscribe, size_t subscribeLen,
                                     const uint8_t *subAck, size_t subAckLen)
{
    static SSFMQTTCOpts_t opts;                       /* Read on every reconnect */

    _SSFMQTTCUTSubOptsInit(&opts, subs, subCount);
    _SSFMQTTCUTSubAckAttemptOpts(&opts, subscribe, subscribeLen, subAck, subAckLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts SSFMQTTCGetSubResult() for each declared filter.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTExpectSubResults(const uint8_t *expected, uint32_t count)
{
    uint32_t i;
    uint8_t r;

    for (i = 0; i < count; i++)
    {
        r = 0xAA;
        SSF_ASSERT(SSFMQTTCGetSubResult(i, &r));
        SSF_ASSERT(r == expected[i]);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a SUBACK failure code reaches READY with SUBSCRIBE_REFUSED, even when every filter */
/* was refused, that each filter's result is reported, and that the connection works.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSubAckRefused(void)
{
    static const uint8_t subAckFail[] = { 0x90, 0x03, 0x00, 0x01, 0x80 };
    static const uint8_t subAckFirst[] = { 0x90, 0x04, 0x00, 0x01, 0x80, 0x00 };
    static const uint8_t subAckSecond[] = { 0x90, 0x04, 0x00, 0x01, 0x01, 0x80 };
    static const uint8_t subAckDownFail[] = { 0x90, 0x04, 0x00, 0x01, 0x00, 0x80 };
    static const uint8_t subAckBoth[] = { 0x90, 0x04, 0x00, 0x01, 0x80, 0x80 };
    static const uint8_t results[5][2] =
    {
        { SSF_MQTTC_SUB_REFUSED, 0 },
        { SSF_MQTTC_SUB_REFUSED, 0 },
        { 1, SSF_MQTTC_SUB_REFUSED },
        { 0, SSF_MQTTC_SUB_REFUSED },
        { SSF_MQTTC_SUB_REFUSED, SSF_MQTTC_SUB_REFUSED },
    };
    static const SSFMQTTCUTEventRec_t expected[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_SUBSCRIBE_REFUSED },
    };
    static const uint8_t pub0[] = { 0x30, 0x06, 0x00, 0x03, 'a', '/', 'b', 'x' };
    const uint8_t *subAcks[5];
    uint32_t i;

    subAcks[0] = subAckFail;
    subAcks[1] = subAckFirst;
    subAcks[2] = subAckSecond;
    subAcks[3] = subAckDownFail;
    subAcks[4] = subAckBoth;
    for (i = 0; i < 5; i++)
    {
        if (i == 0)
        {
            _SSFMQTTCUTSubAckAttempt(_utOneSub, 1, SSF_MQTTC_UT_ARRAY(_utPktSubscribe1),
                                     subAcks[i], sizeof(subAckFail));
        }
        else
        {
            _SSFMQTTCUTSubAckAttempt(_utTwoSubs, 2, SSF_MQTTC_UT_ARRAY(_utPktSubscribe2Subs),
                                     subAcks[i], sizeof(subAckFirst));
        }
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
        _SSFMQTTCUTExpectEvents(expected, 2);
        _SSFMQTTCUTExpectSubResults(results[i], (i == 0) ? 1u : 2u);
        _SSFMQTTCUTExpectTx(NULL, 0);
        /* The connection works: the app can publish its diagnostic */
        SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_0, false, NULL,
                                     NULL));
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pub0));
        _SSFMQTTCUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a lower granted QoS reaches READY with SUBSCRIBE_DOWNGRADED, that the connection   */
/* then works, and that the next connection's exact grant reports READY with NONE.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSubAckDowngraded(void)
{
    static const uint8_t subAckDown[] = { 0x90, 0x03, 0x00, 0x01, 0x00 };
    static const uint8_t subAckDown2[] = { 0x90, 0x04, 0x00, 0x01, 0x00, 0x00 };
    static const uint8_t subAckExact2[] = { 0x90, 0x04, 0x00, 0x01, 0x01, 0x00 };
    static const uint8_t rxQos0[] = { 0x30, 0x04, 0x00, 0x01, 'u', 'x' };
    static const uint8_t reserved[] = { 0xF0, 0x00 };
    static const uint8_t subscribeId2[] =
    { 0x82, 0x08, 0x00, 0x02, 0x00, 0x03, 'a', '/', 'b', 0x01 };
    static const uint8_t subAckOkId2[] = { 0x90, 0x03, 0x00, 0x02, 0x01 };
    static const uint8_t subAckDownId2[] = { 0x90, 0x03, 0x00, 0x02, 0x00 };
    static const SSFMQTTCUTEventRec_t down[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_SUBSCRIBE_DOWNGRADED },
    };
    static const SSFMQTTCUTEventRec_t exact[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_NONE },
    };
    static const SSFMQTTCUTEventRec_t lost[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    uint32_t i;
    SSFMQTTCOpts_t opts;

    /* One filter, QoS 1 requested, QoS 0 granted: READY, and a QoS 0 PUBLISH is delivered */
    _SSFMQTTCUTSubAckAttempt(_utOneSub, 1, SSF_MQTTC_UT_ARRAY(_utPktSubscribe1),
                             SSF_MQTTC_UT_ARRAY(subAckDown));
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    SSF_ASSERT(SSFMQTTCIsReady());
    _SSFMQTTCUTExpectEvents(down, 2);
    {
        static const uint8_t granted0[] = { 0 };
        _SSFMQTTCUTExpectSubResults(granted0, 1);
    }
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(rxQos0));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, "u") == 0);
    SSF_ASSERT(_utRx.qos == SSF_MQTTC_QOS_0);
    SSF_ASSERT((_utRx.payloadLen == 1) && (_utRxPayload[0] == 'x'));
    _SSFMQTTCUTExpectTx(NULL, 0);

    /* Lose the connection; the reconnect's exact grant is not reported as downgraded */
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(reserved));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(lost, 1);
    _utMock.txLen = 0;
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(subscribeId2));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckOkId2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectEvents(exact, 2);
    _SSFMQTTCUTEnd();

    /* The reverse: exact first, downgraded on the reconnect */
    _SSFMQTTCUTSubAckAttempt(_utOneSub, 1, SSF_MQTTC_UT_ARRAY(_utPktSubscribe1),
                             SSF_MQTTC_UT_ARRAY(_utPktSubAckOk1));
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectEvents(exact, 2);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(reserved));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectEvents(lost, 1);
    _utMock.txLen = 0;
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(subscribeId2));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckDownId2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectEvents(down, 2);
    _SSFMQTTCUTEnd();

    /* Downgraded, stopped, restarted with no subscriptions: READY is not reported downgraded */
    _SSFMQTTCUTSubAckAttempt(_utOneSub, 1, SSF_MQTTC_UT_ARRAY(_utPktSubscribe1),
                             SSF_MQTTC_UT_ARRAY(subAckDown));
    _SSFMQTTCUTExpectEvents(down, 2);
    SSFMQTTCStop();
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    _utEventCount = 0;
    _utMock.txLen = 0;
    _SSFMQTTCUTOptsInit(&opts);
    opts.subsOpt = NULL;
    opts.subCount = 0;
    opts.connectTimeout = SSF_TICKS_PER_SEC * 5u;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectEvents(exact, 2);
    _SSFMQTTCUTEnd();

    /* Two filters: downgraded on the first only, then exact on both */
    for (i = 0; i < 2; i++)
    {
        _SSFMQTTCUTSubAckAttempt(_utTwoSubs, 2, SSF_MQTTC_UT_ARRAY(_utPktSubscribe2Subs),
                                 (i == 0) ? subAckDown2 : subAckExact2, sizeof(subAckDown2));
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
        _SSFMQTTCUTExpectEvents((i == 0) ? down : exact, 2);
        _SSFMQTTCUTExpectTx(NULL, 0);
        _SSFMQTTCUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a SUBACK with the wrong packet id or code count fails with PROTOCOL whatever its   */
/* codes say, and that a second SUBACK after READY ends the connection.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSubAckMismatch(void)
{
    static const uint8_t wrongIdFail[] = { 0x90, 0x03, 0x00, 0x02, 0x80 };
    static const uint8_t wrongIdDown[] = { 0x90, 0x03, 0x00, 0x02, 0x00 };
    static const uint8_t tooFew[] = { 0x90, 0x03, 0x00, 0x01, 0x01 };
    static const uint8_t tooMany[] = { 0x90, 0x05, 0x00, 0x01, 0x01, 0x00, 0x00 };
    static const uint8_t subAckDown[] = { 0x90, 0x03, 0x00, 0x01, 0x00 };
    static const SSFMQTTCUTEventRec_t failed[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_PROTOCOL },
    };
    static const SSFMQTTCUTEventRec_t down[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_SUBSCRIBE_DOWNGRADED },
    };
    static const SSFMQTTCUTEventRec_t lost[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    uint32_t i;

    /* One filter declared: wrong id carrying 0x80 or a downgrade */
    for (i = 0; i < 2; i++)
    {
        _SSFMQTTCUTSubAckAttempt(_utOneSub, 1, SSF_MQTTC_UT_ARRAY(_utPktSubscribe1),
                                 (i == 0) ? wrongIdFail : wrongIdDown, sizeof(wrongIdFail));
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        _SSFMQTTCUTExpectTx(NULL, 0);               /* No DISCONNECT on failure */
        _SSFMQTTCUTExpectEvents(failed, 2);
        _SSFMQTTCUTEnd();
    }

    /* Two filters declared: one code, or three, all of them grants */
    _SSFMQTTCUTSubAckAttempt(_utTwoSubs, 2, SSF_MQTTC_UT_ARRAY(_utPktSubscribe2Subs),
                             SSF_MQTTC_UT_ARRAY(tooFew));
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectTx(NULL, 0);                   /* No DISCONNECT on failure */
    _SSFMQTTCUTExpectEvents(failed, 2);
    _SSFMQTTCUTEnd();
    _SSFMQTTCUTSubAckAttempt(_utTwoSubs, 2, SSF_MQTTC_UT_ARRAY(_utPktSubscribe2Subs),
                             SSF_MQTTC_UT_ARRAY(tooMany));
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectTx(NULL, 0);                   /* No DISCONNECT on failure */
    _SSFMQTTCUTExpectEvents(failed, 2);
    _SSFMQTTCUTEnd();

    /* Downgraded READY, then the same SUBACK again: not a second READY */
    _SSFMQTTCUTSubAckAttempt(_utOneSub, 1, SSF_MQTTC_UT_ARRAY(_utPktSubscribe1),
                             SSF_MQTTC_UT_ARRAY(subAckDown));
    _SSFMQTTCUTExpectEvents(down, 2);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckDown));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(lost, 1);
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a granted QoS higher than requested ends the attempt with SUBSCRIBE_QOS_EXCEEDED,  */
/* taking precedence over a failure code on another filter.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSubAckQoSExceeded(void)
{
    static const uint8_t subAckQos2[] = { 0x90, 0x03, 0x00, 0x01, 0x02 };
    static const uint8_t subAck0To1[] = { 0x90, 0x04, 0x00, 0x01, 0x01, 0x01 };
    static const uint8_t subAck0To2[] = { 0x90, 0x04, 0x00, 0x01, 0x01, 0x02 };
    static const uint8_t subAckFailFirst[] = { 0x90, 0x04, 0x00, 0x01, 0x80, 0x01 };
    static const uint8_t subAckFailSecond[] = { 0x90, 0x04, 0x00, 0x01, 0x02, 0x80 };
    static const uint8_t subAckDownFirst[] = { 0x90, 0x04, 0x00, 0x01, 0x00, 0x01 };
    static const SSFMQTTCUTEventRec_t expected[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_SUBSCRIBE_QOS_EXCEEDED },
    };
    const uint8_t *subAcks[6];
    uint32_t i;

    subAcks[0] = subAckQos2;
    subAcks[1] = subAck0To1;
    subAcks[2] = subAck0To2;
    subAcks[3] = subAckFailFirst;
    subAcks[4] = subAckFailSecond;
    subAcks[5] = subAckDownFirst;
    for (i = 0; i < 6; i++)
    {
        if (i == 0)
        {
            _SSFMQTTCUTSubAckAttempt(_utOneSub, 1, SSF_MQTTC_UT_ARRAY(_utPktSubscribe1),
                                     subAcks[i], sizeof(subAckQos2));
        }
        else
        {
            _SSFMQTTCUTSubAckAttempt(_utTwoSubs, 2, SSF_MQTTC_UT_ARRAY(_utPktSubscribe2Subs),
                                     subAcks[i], sizeof(subAck0To1));
        }
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        _SSFMQTTCUTExpectTx(NULL, 0);           /* No DISCONNECT on failure: the will fires */
        _SSFMQTTCUTExpectEvents(expected, 2);
        _SSFMQTTCUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that broker protocol violations end a READY connection.                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioProtocolErrors(void)
{
    static const uint8_t qos3[] = { 0x36, 0x05, 0x00, 0x01, 'z', 0x00, 0x01 };
    static const uint8_t connAckAgain[] = { 0x20, 0x02, 0x00, 0x00 };
    static const uint8_t reserved[] = { 0xF0, 0x00 };
    static const uint8_t pubRel[] = { 0x62, 0x02, 0x00, 0x01 };
    static const SSFMQTTCUTEventRec_t expected[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    const uint8_t *pkts[4];
    size_t lens[4];
    uint32_t i;
    SSFMQTTCOpts_t opts;

    pkts[0] = qos3;         lens[0] = sizeof(qos3);
    pkts[1] = connAckAgain; lens[1] = sizeof(connAckAgain);
    pkts[2] = reserved;     lens[2] = sizeof(reserved);
    pkts[3] = pubRel;       lens[3] = sizeof(pubRel);
    for (i = 0; i < 4; i++)
    {
        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        _SSFMQTTCUTGoReady(&opts);
        _SSFMQTTCUTInject(pkts[i], lens[i]);
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        SSF_ASSERT(_utMock.closeCount == 1);
        _SSFMQTTCUTExpectEvents(expected, 1);
        _SSFMQTTCUTExpectTx(NULL, 0);               /* No DISCONNECT on failure: the will fires */
        _SSFMQTTCUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that an inbound packet other than PUBLISH larger than the rx block ends the connection. */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxOverflow(void)
{
    static const SSFMQTTCUTEventRec_t expected[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_RX_OVERFLOW } };
    uint8_t pkt[4];
    SSFMQTTCOpts_t opts;

    /* SUBACK whose remaining length exceeds the rx block, known from the fixed header alone */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    pkt[0] = 0x90; pkt[1] = 0x80; pkt[2] = 0x02; pkt[3] = 0x00;   /* 256 bytes remaining */
    _SSFMQTTCUTInject(pkt, 3);
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(expected, 1);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the bytes written to buf for a PUBLISH with first byte b0, a topic of topicLen 'x'    */
/* bytes, packetId when b0 has QoS bits, and a payload of payloadLen bytes of which only the     */
/* first payloadWritten ('y') are written. *hdrLenOut is the fixed header length.                */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFMQTTCUTBuildPublish(uint8_t *buf, size_t size, uint8_t b0, size_t topicLen,
                                      uint16_t packetId, size_t payloadLen,
                                      size_t payloadWritten, size_t *hdrLenOut)
{
    size_t remaining = 2 + topicLen + payloadLen + (((b0 & 0x06u) != 0) ? 2u : 0u);
    size_t v = remaining;
    size_t n = 0;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(payloadWritten <= payloadLen);
    SSF_REQUIRE(hdrLenOut != NULL);
    SSF_ASSERT((5 + 2 + topicLen + 2 + payloadWritten) <= size);

    buf[n++] = b0;
    do
    {
        uint8_t b = (uint8_t)(v & 0x7Fu);
        v >>= 7;
        if (v > 0) b |= 0x80u;
        buf[n++] = b;
    } while (v > 0);
    *hdrLenOut = n;
    buf[n++] = (uint8_t)(topicLen >> 8);
    buf[n++] = (uint8_t)(topicLen & 0xFFu);
    memset(&buf[n], 'x', topicLen);
    n += topicLen;
    if ((b0 & 0x06u) != 0)
    {
        buf[n++] = (uint8_t)(packetId >> 8);
        buf[n++] = (uint8_t)(packetId & 0xFFu);
    }
    memset(&buf[n], 'y', payloadWritten);
    n += payloadWritten;
    return n;
}

static const uint8_t _utPktRxSmall0[] = { 0x30, 0x03, 0x00, 0x01, 'u' };    /* QoS 0, topic "u" */
static const uint8_t _utPktRxSmall1[] = { 0x32, 0x05, 0x00, 0x01, 'v', 0x00, 0x07 }; /* QoS 1, 7 */
static const uint8_t _utPktRxSmall1Ack[] = { 0x40, 0x02, 0x00, 0x07 };

/* --------------------------------------------------------------------------------------------- */
/* Tests that a PUBLISH larger than the rx block is dropped and the stream stays in sync.        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxTooLarge(void)
{
    static const SSFMQTTCUTEventRec_t dropped[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOO_LARGE } };
    static const uint8_t ackBig[] = { 0x40, 0x02, 0x12, 0x34, 0x40, 0x02, 0x00, 0x07 };
    static const size_t chunks[] = { 0, 1, 2, 3, 5, 64, 127, 128, 129 };
    uint8_t pkt[512];
    size_t len;
    size_t hdrLen;
    uint32_t i;
    SSFMQTTCOpts_t opts;

    /* QoS 0, 3-byte fixed header, followed in the same read by a packet that fits */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x30, 1, 0, 200, 200, &hdrLen);
    SSF_ASSERT(hdrLen == 3);
    _SSFMQTTCUTInject(pkt, len);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktRxSmall0));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, "u") == 0);
    _SSFMQTTCUTExpectEvents(dropped, 1);
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTEnd();

    /* QoS 1 whose topic alone is longer than the rx block, so its packet id lies beyond the  */
    /* block; acknowledged, then the next packet is delivered and acknowledged. Every read     */
    /* size, so the topic length and packet id bytes split across reads in every way.          */
    for (i = 0; i < (sizeof(chunks) / sizeof(chunks[0])); i++)
    {
        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        _SSFMQTTCUTGoReady(&opts);
        _utMock.recvChunk = chunks[i];
        len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, 200, 0x1234, 5, 5, &hdrLen);
        _SSFMQTTCUTInject(pkt, len);
        _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktRxSmall1));
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
        SSF_ASSERT(_utRxPublishCount == 1);
        SSF_ASSERT(strcmp(_utRxTopic, "v") == 0);
        _SSFMQTTCUTExpectEvents(dropped, 1);
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ackBig));
        _SSFMQTTCUTEnd();
    }

    /* Retained, DUP, 5-byte fixed header (over 2 MB), the bulk served as filler */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x3B, 1, 0x1234, 2100000ul, 0, &hdrLen);
    SSF_ASSERT(hdrLen == 5);
    _SSFMQTTCUTInject(pkt, len);
    _SSFMQTTCUTInjectPad(2100000ul);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktRxSmall1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    SSF_ASSERT(_utMock.rxPadLeft == 0);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, "v") == 0);
    _SSFMQTTCUTExpectEvents(dropped, 1);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ackBig));
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a PUBLISH that fits but whose topic is too long is dropped and acknowledged.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxTopicTooLong(void)
{
    static const SSFMQTTCUTEventRec_t dropped[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG } };
    static const uint8_t ack[] = { 0x40, 0x02, 0x0A, 0x0B, 0x40, 0x02, 0x00, 0x07 };
    uint8_t pkt[512];
    size_t len;
    size_t hdrLen;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, 512);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    /* Longest allowed topic is delivered */
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x30, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE - 1, 0,
                                  1, 1, &hdrLen);
    _SSFMQTTCUTInject(pkt, len);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(_utRx.topicLen == (SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE - 1));
    SSF_ASSERT(_utEventCount == 0);

    /* One byte longer is dropped, acknowledged, and the next packet still arrives */
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, 0x0A0B,
                                  1, 1, &hdrLen);
    _SSFMQTTCUTInject(pkt, len);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktRxSmall1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    SSF_ASSERT(_utRxPublishCount == 2);
    SSF_ASSERT(strcmp(_utRxTopic, "v") == 0);
    _SSFMQTTCUTExpectEvents(dropped, 1);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ack));
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a malformed PUBLISH larger than the rx block still ends the connection.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxTooLargeMalformed(void)
{
    static const SSFMQTTCUTEventRec_t protocol[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    static const size_t chunks[] = { 0, 1, 129 };   /* Fields seen whole, byte by byte, split */
    uint8_t pkt[512];
    size_t len = 0;
    size_t hdrLen;
    uint32_t i;
    SSFMQTTCOpts_t opts;

    for (i = 0; i < (12u * (sizeof(chunks) / sizeof(chunks[0]))); i++)
    {
        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        _SSFMQTTCUTGoReady(&opts);
        _utMock.recvChunk = chunks[i / 12u];
        switch (i % 12u)
        {
        case 0:     /* Zero-length topic */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x30, 0, 0, 200, 200, &hdrLen);
            break;
        case 1:     /* Packet id 0 */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, 1, 0, 200, 200, &hdrLen);
            break;
        case 2:     /* QoS 1 but the packet ends right after the topic: no room for the id */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x30, 199, 0, 0, 0, &hdrLen);
            pkt[0] = 0x32;
            break;
        case 3:     /* Topic length runs past the end of the packet */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x30, 1, 0, 200, 200, &hdrLen);
            pkt[hdrLen] = 0xFF; pkt[hdrLen + 1] = 0xFF;
            break;
        case 4:     /* QoS 3 */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x36, 1, 1, 200, 200, &hdrLen);
            break;
        case 5:     /* DUP at QoS 0 */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x38, 1, 0, 200, 200, &hdrLen);
            break;
        case 6:     /* QoS 1, one byte short of a packet id */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x30, 200, 0, 1, 1, &hdrLen);
            pkt[0] = 0x32;
            break;
        case 7:     /* QoS 0, topic length one byte longer than the packet */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x30, 1, 0, 200, 200, &hdrLen);
            pkt[hdrLen] = 0x00; pkt[hdrLen + 1] = 202;
            break;
        case 8:     /* Embedded NUL in the topic, within the first block */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, 3, 0x1234, 200, 200, &hdrLen);
            pkt[hdrLen + 2 + 1] = 0;
            break;
        case 9:     /* Embedded NUL in the topic, beyond the first block */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, 200, 0x1234, 5, 5, &hdrLen);
            pkt[hdrLen + 2 + 150] = 0;
            break;
        case 10:    /* Embedded NUL as the last topic byte */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, 200, 0x1234, 5, 5, &hdrLen);
            pkt[hdrLen + 2 + 199] = 0;
            break;
        default:    /* QoS 3 with DUP (QoS 2 has its own reason; see RxPublishQoS2) */
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x3E, 1, 1, 200, 200, &hdrLen);
            break;
        }
        _SSFMQTTCUTInject(pkt, len);
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        SSF_ASSERT(_utRxPublishCount == 0);
        _SSFMQTTCUTExpectEvents(protocol, 1);        /* Never reported as a drop first */
        _utMock.txLen = 0;
        _SSFMQTTCUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a QoS 2 PUBLISH, which no subscription allows, ends the connection with            */
/* RX_PUBLISH_QOS2 on both inbound paths and before READY, without delivery or acknowledgement.  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxPublishQoS2(void)
{
    static const uint8_t small[] = { 0x34, 0x05, 0x00, 0x01, 'z', 0x00, 0x01 };
    static const uint8_t smallDup[] = { 0x3C, 0x06, 0x00, 0x01, 'z', 0x00, 0x02, 'p' };
    static const uint8_t smallBadId[] = { 0x34, 0x05, 0x00, 0x01, 'z', 0x00, 0x00 };
    static const uint8_t smallNoTopic[] = { 0x34, 0x04, 0x00, 0x00, 0x00, 0x01 };
    static const SSFMQTTCUTEventRec_t lost[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_RX_PUBLISH_QOS2 } };
    static const SSFMQTTCUTEventRec_t failed[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_RX_PUBLISH_QOS2 },
    };
    static const size_t chunks[] = { 0, 1, 129 };
    const uint8_t *pkts[4];
    size_t lens[4];
    uint8_t pkt[512];
    size_t len;
    size_t hdrLen;
    uint32_t i;
    SSFMQTTCOpts_t opts;

    /* Packets that fit the rx block, the flags alone deciding even when the body is malformed */
    pkts[0] = small;        lens[0] = sizeof(small);
    pkts[1] = smallDup;     lens[1] = sizeof(smallDup);
    pkts[2] = smallBadId;   lens[2] = sizeof(smallBadId);
    pkts[3] = smallNoTopic; lens[3] = sizeof(smallNoTopic);
    for (i = 0; i < 4u; i++)
    {
        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        _SSFMQTTCUTGoReady(&opts);
        _SSFMQTTCUTInject(pkts[i], lens[i]);
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        SSF_ASSERT(_utRxPublishCount == 0);
        _SSFMQTTCUTExpectEvents(lost, 1);
        _SSFMQTTCUTExpectTx(NULL, 0);           /* No PUBREC or PUBACK; the link closes at once */
        _SSFMQTTCUTEnd();
    }

    /* Larger than the rx block, read whole, byte by byte, and split */
    for (i = 0; i < (sizeof(chunks) / sizeof(chunks[0])); i++)
    {
        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        _SSFMQTTCUTGoReady(&opts);
        _utMock.recvChunk = chunks[i];
        len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x34, 1, 1, 200, 200, &hdrLen);
        _SSFMQTTCUTInject(pkt, len);
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        SSF_ASSERT(_utRxPublishCount == 0);
        _SSFMQTTCUTExpectEvents(lost, 1);                   /* Never reported as a drop first */
        _SSFMQTTCUTExpectTx(NULL, 0);
        _SSFMQTTCUTEnd();
    }

    /* Before CONNACK, small and oversized: the attempt fails */
    for (i = 0; i < 2u; i++)
    {
        static const SSFMQTTCUTEventRec_t early[] =
        { { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_RX_PUBLISH_QOS2 } };

        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        SSFMQTTCStart(&opts);
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
        if (i == 0) { _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(small)); }
        else
        {
            len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x34, 1, 1, 200, 200, &hdrLen);
            _SSFMQTTCUTInject(pkt, len);
        }
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        SSF_ASSERT(_utRxPublishCount == 0);
        _SSFMQTTCUTExpectEvents(early, 1);
        _SSFMQTTCUTExpectTx(NULL, 0);
        _SSFMQTTCUTEnd();
    }

    /* Before READY: the attempt fails */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribe1));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(small));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utRxPublishCount == 0);
    _SSFMQTTCUTExpectEvents(failed, 2);
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a retained oversized PUBLISH between SUBACK and READY no longer blocks READY.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxTooLargeRetained(void)
{
    static const SSFMQTTCUTEventRec_t expected[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOO_LARGE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_NONE },
    };
    static const uint8_t ack[] = { 0x40, 0x02, 0x00, 0x2A };
    uint8_t pkt[512];
    size_t len;
    size_t hdrLen;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribe1));
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x33, 3, 0x002A, 300, 300, &hdrLen);
    _SSFMQTTCUTInject(pkt, len);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktSubAckOk1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectEvents(expected, 3);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ack));
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a PUBLISH dropped before CONNACK is not acknowledged, so nothing precedes CONNECT. */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxDropBeforeConnAck(void)
{
    static const SSFMQTTCUTEventRec_t tooLarge[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOO_LARGE } };
    static const SSFMQTTCUTEventRec_t tooLong[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG } };
    uint8_t pkt[512];
    size_t len;
    size_t hdrLen;
    SSFMQTTCOpts_t opts;

    /* Oversized QoS 1, sent by the broker as soon as the transport opens */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, 3, 0x1234, 200, 200, &hdrLen);
    _SSFMQTTCUTInject(pkt, len);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTING);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTExpectEvents(tooLarge, 1);
    _SSFMQTTCUTEnd();

    /* QoS 1 that fits but whose topic is too long */
    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, 512);
    _SSFMQTTCUTOptsInit(&opts);
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, 0x1234,
                                  1, 1, &hdrLen);
    _SSFMQTTCUTInject(pkt, len);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTING);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTExpectEvents(tooLong, 1);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a connection lost in the middle of a dropped PUBLISH leaves no state behind.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxTooLargeLinkLoss(void)
{
    static const SSFMQTTCUTEventRec_t closed[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PEER_CLOSED } };
    static const SSFMQTTCUTEventRec_t ready[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_NONE },
    };
    static const uint8_t subAck2[] = { 0x90, 0x03, 0x00, 0x02, 0x01 };
    uint8_t pkt[512];
    size_t len;
    size_t hdrLen;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    opts.connectTimeout = SSF_TICKS_PER_SEC * 5u;   /* The reconnect must not race a loaded host */
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 5u;
    _SSFMQTTCUTGoReady(&opts);
    len = _SSFMQTTCUTBuildPublish(pkt, sizeof(pkt), 0x32, 200, 0x1234, 5, 5, &hdrLen);
    _SSFMQTTCUTInject(pkt, 150);                    /* Partway through the topic */
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    SSF_ASSERT(_utEventCount == 0);
    _utMock.recvEmptyResult = SSF_NET_IO_CLOSED;
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(closed, 1);

    /* The new connection frames from its first byte */
    _utMock.recvEmptyResult = SSF_NET_IO_WANT_READ;
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();                              /* Transport open, CONNECT sent */
    SSF_ASSERT(_utMock.openCount == 2);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAck2));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktRxSmall0));
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTED, SSF_MQTTC_UT_LOAD_TICKS);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, "u") == 0);
    _SSFMQTTCUTExpectEvents(ready, 2);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Drives the client to READY with keepAliveSec (1 => ping every 250 ms; PINGRESP timeout is     */
/* 250 ms). Connect and subscribe timeouts are long so a loaded host cannot trip them.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTGoReadyKeepAlive(uint16_t keepAliveSec)
{
    static uint8_t connect[sizeof(_utPktConnect)];
    static const SSFMQTTCUTEventRec_t ready[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_NONE },
    };
    static SSFMQTTCOpts_t opts;                     /* Must outlive the run */

    SSF_REQUIRE((keepAliveSec > 0) && (keepAliveSec < 256));
    SSF_ASSERT((SSF_TICKS_PER_SEC / 4u) == SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT);
    memcpy(connect, _utPktConnect, sizeof(connect));
    connect[10] = 0x00;
    connect[11] = (uint8_t)keepAliveSec;            /* Keep alive MSB, LSB */
    _SSFMQTTCUTOptsInit(&opts);
    opts.keepAliveSec = keepAliveSec;
    opts.connectTimeout = SSF_TICKS_PER_SEC * 5u;
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 5u;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(connect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribe1));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktSubAckOk1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectEvents(ready, 2);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the tick by which the client had sent at least len bytes, pumping for at most ticks;  */
/* asserts if it had not by then.                                                                */
/* --------------------------------------------------------------------------------------------- */
static SSFPortTick_t _SSFMQTTCUTPumpUntilTx(size_t len, SSFPortTick_t ticks)
{
    SSFPortTick_t end = SSFPortGetTick64() + ticks;

    for (;;)
    {
        bool isLate = (SSFPortGetTick64() > end);  /* Sampled before the tasks run */

        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
        if (_utMock.txLen >= len) break;
        SSF_ASSERT(isLate == false);
    }
    return SSFPortGetTick64();
}


/* --------------------------------------------------------------------------------------------- */
/* Tests that an unanswered PINGREQ ends the connection within the PINGRESP timeout, also when   */
/* the next keep-alive interval falls due on the same tick as that timeout.                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioKeepAliveTimeout(void)
{
    static const uint8_t pingReq[] = { 0xC0, 0x00 };
    static const SSFMQTTCUTEventRec_t keepAlive[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_KEEPALIVE } };
    static const uint8_t subAck2[] = { 0x90, 0x03, 0x00, 0x02, 0x01 };
    static const uint8_t subscribe2[] = { 0x82, 0x08, 0x00, 0x02, 0x00, 0x03, 'a', '/', 'b', 0x01 };

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTGoReadyKeepAlive(1);

    (void)_SSFMQTTCUTPumpUntilTx(sizeof(pingReq),
                                 SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pingReq));

    /* No PINGRESP. Before the fix the failure never came: each interval restarted the timeout. */
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_RECONNECT_WAIT,
                              SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectEvents(keepAlive, 1);
    _SSFMQTTCUTExpectTx(NULL, 0);    /* Never a second PINGREQ; no DISCONNECT on failure */

    /* The next connection starts with no ping pending, so it pings again */
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();                              /* Transport open, CONNECT sent */
    _utMock.txLen = 0;                              /* CONNECT, checked by the first connection */
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAck2));
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTED, SSF_MQTTC_UT_LOAD_TICKS);
    _utEventCount = 0;                              /* CONNECTED, READY */
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(subscribe2) + sizeof(pingReq),
                                 SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT + SSF_MQTTC_UT_LOAD_TICKS);
    SSF_ASSERT(_utMock.txLen == (sizeof(subscribe2) + sizeof(pingReq)));
    SSF_ASSERT(memcmp(_utMock.tx, subscribe2, sizeof(subscribe2)) == 0);
    SSF_ASSERT(memcmp(&_utMock.tx[sizeof(subscribe2)], pingReq, sizeof(pingReq)) == 0);
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that answered pings keep the connection up and each interval sends one PINGREQ. A       */
/* 500 ms interval leaves time to check that no second PINGREQ follows an answer.                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioKeepAliveAnswered(void)
{
    static const uint8_t pingReq[] = { 0xC0, 0x00 };
    static const uint8_t pingResp[] = { 0xD0, 0x00 };
    uint32_t i;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTGoReadyKeepAlive(2);

    for (i = 0; i < 3; i++)
    {
        (void)_SSFMQTTCUTPumpUntilTx(sizeof(pingReq),
                                     (2u * SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT) +
                                     SSF_MQTTC_UT_LOAD_TICKS);
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pingReq));
        _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pingResp));
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
        _SSFMQTTCUTExpectTx(NULL, 0);
        SSF_ASSERT(_utEventCount == 0);
    }
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a PINGRESP arriving while our PINGREQ is still unsent is ignored: no second        */
/* PINGREQ is queued, and the stalled connection still ends with KEEPALIVE.                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioKeepAliveUnsolicitedPingResp(void)
{
    static const uint8_t pingResp[] = { 0xD0, 0x00 };
    static const SSFMQTTCUTEventRec_t keepAlive[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_KEEPALIVE } };

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTGoReadyKeepAlive(1);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;     /* Broker stops reading: PINGREQ stays queued */

    /* First ping queued at one interval; answer it before it could have been sent */
    _SSFMQTTCUTPumpFor(SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT + SSF_MQTTC_UT_SLACK_TICKS);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pingResp));

    /* Past the next interval and the timeout of the unsent ping */
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_RECONNECT_WAIT,
                              (2u * SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT) + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectEvents(keepAlive, 1);
    _SSFMQTTCUTExpectTx(NULL, 0);                   /* Nothing ever accepted by the transport */
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Back-pressure scaffolding                                                                     */
/* --------------------------------------------------------------------------------------------- */
static const uint8_t _utPktSubscribeId2[] =
{ 0x82, 0x08, 0x00, 0x02, 0x00, 0x03, 'a', '/', 'b', 0x01 };
static const uint8_t _utPktSubAckOkId2[] = { 0x90, 0x03, 0x00, 0x02, 0x01 };

/* --------------------------------------------------------------------------------------------- */
/* Writes a 7-byte QoS 1 PUBLISH with a one-character topic and packetId to pkt.                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTPub1(uint8_t pkt[7], char topic, uint16_t packetId)
{
    pkt[0] = 0x32; pkt[1] = 0x05; pkt[2] = 0x00; pkt[3] = 0x01; pkt[4] = (uint8_t)topic;
    pkt[5] = (uint8_t)(packetId >> 8); pkt[6] = (uint8_t)packetId;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends the PUBACK for packetId to buf at *lenInOut.                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTAppendAck(uint8_t *buf, size_t size, size_t *lenInOut, uint16_t packetId)
{
    SSF_ASSERT((*lenInOut + 4u) <= size);
    buf[(*lenInOut)++] = 0x40; buf[(*lenInOut)++] = 0x02;
    buf[(*lenInOut)++] = (uint8_t)(packetId >> 8); buf[(*lenInOut)++] = (uint8_t)packetId;
}

/* --------------------------------------------------------------------------------------------- */
/* Pumps until count events are logged, asserting if that takes more than ticks.                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTPumpUntilEvents(uint32_t count, SSFPortTick_t ticks)
{
    SSFPortTick_t end = SSFPortGetTick64() + ticks;

    for (;;)
    {
        bool isLate = (SSFPortGetTick64() > end);  /* Sampled before the tasks run */

        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
        if (_utEventCount >= count) break;
        SSF_ASSERT(isLate == false);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Pumps until count inbound PUBLISH packets were accepted, asserting if that takes more than    */
/* ticks.                                                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTPumpUntilTaken(uint32_t count, SSFPortTick_t ticks)
{
    SSFPortTick_t end = SSFPortGetTick64() + ticks;

    for (;;)
    {
        bool isLate = (SSFPortGetTick64() > end);  /* Sampled before the tasks run */

        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
        if (_utRxTakenCount >= count) break;
        SSF_ASSERT(isLate == false);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if more than budget ticks passed since since. Keep-alive scenarios use it to     */
/* judge only runs the host did not stall: on a heavily loaded host a pump can overrun a 250 ms  */
/* PINGRESP timeout several times, and keep-alive then rightly ends the connection.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCUTIsStalled(SSFPortTick_t since, SSFPortTick_t budget)
{
    return (SSFPortGetTick64() - since) > budget;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts the connection is up with only the hold-timeout drop logged, unless the host stalled  */
/* past budget since since, in which case only that the drop came first.                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTExpectHeldUp(SSFPortTick_t since, SSFPortTick_t budget)
{
    static const SSFMQTTCUTEventRec_t held[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_HOLD_TIMEOUT } };

    if (_SSFMQTTCUTIsStalled(since, budget))
    {
        /* Either the hold ended first, or keep-alive fired before the hold could start */
        SSF_ASSERT(_utEventCount >= 1);
        SSF_ASSERT((_utEvents[0].reason == held[0].reason) ||
                   (_utEvents[0].reason == SSF_MQTTC_REASON_KEEPALIVE));
        _utEventCount = 0;
        return;
    }
    /* The deferred head may also have timed out if the host stalled earlier in the scenario */
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    while ((_utEventCount > 1) &&
           (_utEvents[_utEventCount - 1u].reason == SSF_MQTTC_REASON_RX_PUBLISH_TIMEOUT))
    { _utEventCount--; }
    _SSFMQTTCUTExpectEvents(held, 1);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests back-pressure: with the transport blocked, delivered messages' PUBACKs use up the ctl   */
/* blocks, later messages wait in the queue, and the QoS 1 PUBLISH that then finds it full is    */
/* held while reading stops. Once the transport drains, the held packet is queued, reading       */
/* resumes, and every message is delivered once, in order, and acknowledged in order.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxBackPressure(void)
{
    uint8_t pkt[7];
    uint8_t acks[64];
    size_t acksLen = 0;
    char expected[16];
    uint32_t total = (2u * SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH) + 2u;
    uint32_t i;
    uint32_t n;
    size_t base;
    SSFPortTick_t to;
    SSFMQTTCOpts_t opts;

    SSF_ASSERT(total < sizeof(expected));
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvChunk = sizeof(pkt);                /* One packet per read */
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    base = _utMock.rxPos;
    for (i = 0; i < total; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
        expected[i] = (char)('a' + i);
        _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, (uint16_t)(i + 1u));
    }
    expected[total] = 0;
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxTakenCount == SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH);  /* PUBACKs stuck */
    SSF_ASSERT((_utMock.rxPos - base) == ((total - 1u) * sizeof(pkt)));   /* Last one unread */
    n = _utMock.recvCount;
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.recvCount == n);             /* Reads suspended */
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT(_utMock.txLen == 0);
    to = SSF_MAX_NEXT_TIMEOUT;
    (void)SSFMQTTCTask(&to);
    SSF_ASSERT(to <= SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS);

    /* The transport drains */
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPumpUntilTaken(total, SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();
    SSF_ASSERT(strcmp(_utRxTaken, expected) == 0);
    SSF_ASSERT(_utMock.rxPos == _utMock.rxLen);
    _SSFMQTTCUTExpectTx(acks, acksLen);
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the hold cap: a held QoS 1 PUBLISH is dropped and acknowledged after                    */
/* RX_HOLD_MAX_TICKS, reading resumes, and a QoS 0 PUBLISH that was waiting behind it is then    */
/* dropped as queue full. The connection stays up.                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxHoldTimeout(void)
{
    static const uint8_t in0[] = { 0x30, 0x03, 0x00, 0x01, 'z' };
    static const SSFMQTTCUTEventRec_t expected[] =
    {
        { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_HOLD_TIMEOUT },
        { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_QUEUE_FULL },
    };
    uint8_t pkt[7];
    uint8_t ack[4];
    size_t ackLen = 0;
    uint32_t i;
    SSFPortTick_t start;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(in0));
    _SSFMQTTCUTAppendAck(ack, sizeof(ack), &ackLen,
                         (uint16_t)(SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + 1u));
    start = SSFPortGetTick64();
    _SSFMQTTCUTPumpUntilEvents(1, SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    SSF_ASSERT((SSFPortGetTick64() - start) >= SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectEvents(expected, 2);
    _SSFMQTTCUTExpectTx(ack, ackLen);
    SSF_ASSERT(_utMock.rxPos == _utMock.rxLen);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests keep-alive across back-pressure: a PINGRESP stuck behind a held packet past its timeout */
/* does not end the connection; but with reads stopped for an owed PUBACK on a dead uplink,      */
/* keep-alive still does.                                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxHoldKeepAlive(void)
{
    static const uint8_t pingReq[] = { 0xC0, 0x00 };
    static const uint8_t pingResp[] = { 0xD0, 0x00 };
    static const SSFMQTTCUTEventRec_t dead[] =
    {
        { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG },
        { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_KEEPALIVE },
    };
    uint8_t pkt[7];
    uint8_t big[512];
    size_t len;
    size_t hdrLen;
    uint32_t i;
    SSFPortTick_t start;

    SSF_ASSERT(SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS > SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT);

    /* Hold right after a PINGREQ, with its PINGRESP queued behind the held packet */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTGoReadyKeepAlive(1);
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(pingReq), (2u * SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT) +
                                                  SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pingReq));
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pingResp));
    start = SSFPortGetTick64();
    _SSFMQTTCUTPumpUntilEvents(1, SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS +
                                  (4u * SSF_MQTTC_UT_LOAD_TICKS));
    _SSFMQTTCUTPump();                              /* The PINGRESP is read now */
    _SSFMQTTCUTExpectHeldUp(start, SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS +
                                   SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT);
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();

    /* A hold that ends just before the PINGRESP deadline: the PINGRESP, arriving only after   */
    /* that deadline, still gets a full timeout from the end of the hold                        */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTGoReadyKeepAlive(1);
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(pingReq), (2u * SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT) +
                                                  SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pingReq));
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPumpUntilEvents(1, SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS +
                                  (4u * SSF_MQTTC_UT_LOAD_TICKS));
    start = SSFPortGetTick64();                     /* The hold just ended */
    _SSFMQTTCUTPumpFor((SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT * 3u) / 5u);   /* Past the deadline */
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pingResp));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectHeldUp(start, SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT);
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();

    /* A hold, then no PINGRESP ever (dead downlink): the deadline is extended once at most,   */
    /* and keep-alive still ends the connection                                                  */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTGoReadyKeepAlive(1);
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(pingReq), (2u * SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT) +
                                                  SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pingReq));
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_RECONNECT_WAIT,
                              SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS +
                              (4u * SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT) +
                              (8u * SSF_MQTTC_UT_LOAD_TICKS));   /* Several timer phases */
    SSF_ASSERT(_utEventCount >= 1u);
    SSF_ASSERT(_utEvents[_utEventCount - 1u].event == SSF_MQTTC_EVENT_DISCONNECTED);
    SSF_ASSERT(_utEvents[_utEventCount - 1u].reason == SSF_MQTTC_REASON_KEEPALIVE);
    _utEventCount = 0;
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();

    /* Owed PUBACK on a dead uplink: reads stop, PINGREQ cannot be sent, keep-alive ends it */
    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, sizeof(big));
    _SSFMQTTCUTGoReadyKeepAlive(1);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    for (i = 0; i < SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();                              /* Delivered; their PUBACKs use the blocks */
    SSF_ASSERT(_utRxTakenCount == SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH);
    len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, 9, 1, 1,
                                  &hdrLen);
    _SSFMQTTCUTInject(big, len);                    /* Its PUBACK is owed */
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_RECONNECT_WAIT,
                              (4u * SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT) +
                              (8u * SSF_MQTTC_UT_LOAD_TICKS));   /* Two timer phases */
    _SSFMQTTCUTExpectEvents(dead, 2);
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the owed PUBACK: each drop path that finds no PUBACK block owes the id and stops reads  */
/* until the PUBACK is queued; it goes out before the PUBACK of any later delivery.              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxPubAckOwed(void)
{
    static const SSFMQTTCUTEventRec_t tooLong[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG } };
    static const SSFMQTTCUTEventRec_t tooLarge[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOO_LARGE } };
    static const SSFMQTTCUTEventRec_t timedOut[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TIMEOUT } };
    static const SSFMQTTCUTEventRec_t held[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_HOLD_TIMEOUT } };
    const uint32_t depth = SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH;
    uint8_t pkt[7];
    uint8_t big[512];
    uint8_t acks[128];
    size_t acksLen;
    size_t len;
    size_t hdrLen;
    uint32_t i;
    uint32_t kind;
    uint32_t n;
    SSFMQTTCOpts_t opts;

    /* Kinds 0 and 1: a topic too long, a packet too large, after depth deliveries whose        */
    /* PUBACKs are stuck behind a blocked transport                                             */
    for (kind = 0; kind < 2u; kind++)
    {
        acksLen = 0;
        _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, (kind == 0) ? sizeof(big) :
                                                                 SSF_MQTTC_UT_RX_BLOCK_SIZE);
        _SSFMQTTCUTOptsInit(&opts);
        _SSFMQTTCUTGoReady(&opts);
        _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
        for (i = 0; i < depth; i++)
        {
            _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
            _SSFMQTTCUTInject(pkt, sizeof(pkt));
            _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, (uint16_t)(i + 1u));
        }
        _SSFMQTTCUTPump();
        SSF_ASSERT(_utRxTakenCount == depth);
        if (kind == 0)
        {
            len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE,
                                          0x0109, 1, 1, &hdrLen);
        }
        else len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, 1, 0x0109, 200, 200, &hdrLen);
        _SSFMQTTCUTInject(big, len);
        _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, 0x0109);
        if (kind == 0)
        {
            /* A second one in the same read waits behind the owed PUBACK, unprocessed */
            big[len - 3u] = 0x02;                   /* Packet id 0x0109 -> 0x0209 */
            _SSFMQTTCUTInject(big, len);
            _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, 0x0209);
        }
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectEvents((kind == 0) ? tooLong : tooLarge, 1);
        _SSFMQTTCUTPub1(pkt, 'n', 10);
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
        _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, 10);
        n = _utMock.recvCount;
        _SSFMQTTCUTPump();
        SSF_ASSERT(_utMock.recvCount == n);         /* Reads suspended while the id is owed */
        SSF_ASSERT(_utRxTakenCount == depth);
        _SSFMQTTCUTExpectTx(NULL, 0);

        _utMock.sendResult = SSF_NET_IO_SUCCESS;
        _SSFMQTTCUTPumpUntilTaken(depth + 1u, SSF_MQTTC_UT_LOAD_TICKS);
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectTx(acks, acksLen);         /* Owed one before the later delivery's */
        if (kind == 0) { _SSFMQTTCUTExpectEvents(tooLong, 1); }   /* The second drop */
        SSF_ASSERT(_utEventCount == 0);
        _SSFMQTTCUTEnd();
    }

    /* Kind 2: a deferred head times out after drops have used up the PUBACK blocks */
    acksLen = 0;
    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, sizeof(big));
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    _utRxAccept = false;
    _SSFMQTTCUTPub1(pkt, 'e', 5);
    _SSFMQTTCUTInject(pkt, sizeof(pkt));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);             /* Offered and deferred */
    for (i = 0; i < depth; i++)
    {
        len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE,
                                      (uint16_t)(11u + i), 1, 1, &hdrLen);
        _SSFMQTTCUTInject(big, len);
        _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, (uint16_t)(11u + i));
    }
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utEventCount == depth);
    _utEventCount = 0;
    _SSFMQTTCUTPumpUntilEvents(1, SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS +
                                  SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS +
                                  SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectEvents(timedOut, 1);
    _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, 5);
    _SSFMQTTCUTPub1(pkt, 'n', 6);
    _SSFMQTTCUTInject(pkt, sizeof(pkt));
    _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, 6);
    n = _utMock.recvCount;
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.recvCount == n);
    _utRxAccept = true;
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPumpUntilTaken(1, SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxTaken[0] == 'n');
    _SSFMQTTCUTExpectTx(acks, acksLen);
    SSF_ASSERT(_utEventCount == 0);
    _SSFMQTTCUTEnd();

    /* Kind 2b: a deferred head times out while another PUBACK is already owed: it waits its    */
    /* turn rather than owing a second, and its PUBACK follows the owed one                      */
    acksLen = 0;
    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, sizeof(big));
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    _utRxAccept = false;
    _SSFMQTTCUTPub1(pkt, 'e', 5);
    _SSFMQTTCUTInject(pkt, sizeof(pkt));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);
    for (i = 0; i <= depth; i++)                    /* depth acknowledged, the last one owed */
    {
        len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE,
                                      (uint16_t)(11u + i), 1, 1, &hdrLen);
        _SSFMQTTCUTInject(big, len);
        _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, (uint16_t)(11u + i));
    }
    _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, 5);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utEventCount == (depth + 1u));
    _utEventCount = 0;
    _SSFMQTTCUTPumpFor(SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS +
                       SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS);
    SSF_ASSERT(_utEventCount == 0);                 /* Due, but waiting for the owed PUBACK */
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPumpUntilEvents(1, SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS +
                                  SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectEvents(timedOut, 1);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(acks, acksLen);
    _SSFMQTTCUTEnd();

    /* Kind 3: the hold cap expires while the PUBACK blocks are used up. The owed PUBACK goes   */
    /* out before those of the queued messages delivered after it.                              */
    acksLen = 0;
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    _utMock.recvChunk = sizeof(pkt);
    for (i = 0; i <= (2u * depth); i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    for (i = 0; i < depth; i++)
    { _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, (uint16_t)(i + 1u)); }
    _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, (uint16_t)((2u * depth) + 1u));
    for (i = depth; i < (2u * depth); i++)
    { _SSFMQTTCUTAppendAck(acks, sizeof(acks), &acksLen, (uint16_t)(i + 1u)); }
    _SSFMQTTCUTPumpUntilEvents(1, SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectEvents(held, 1);
    SSF_ASSERT(_utRxTakenCount == depth);
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPumpUntilTaken(2u * depth, SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(acks, acksLen);
    SSF_ASSERT(_utEventCount == 0);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that a held packet and an owed PUBACK die with their connection: nothing stale is sent  */
/* after Stop, after a link failure, or on the next session.                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxHoldLifetime(void)
{
    static const SSFMQTTCUTEventRec_t failed[] =
    {
        { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG },
        { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_TRANSPORT_ERROR },
    };
    uint8_t pkt[7];
    uint8_t big[512];
    size_t len;
    size_t hdrLen;
    uint32_t i;
    SSFMQTTCOpts_t opts;

    /* Held, then Stop: DISCONNECT only; then a new session sends no PUBACK */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();
    SSFMQTTCStop();
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
    _utEventCount = 0;
    _utRxAccept = true;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribeId2));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktSubAckOkId2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTPumpFor(SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTEnd();

    /* Held, then a link failure: the next session reads normally */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    opts.connectTimeout = SSF_TICKS_PER_SEC * 5u;
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 5u;
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();
    _utMock.sendResult = SSF_NET_IO_ERROR;
    SSF_ASSERT(SSFMQTTCTxPublish("t", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_0, false, NULL,
                                 NULL));
    _SSFMQTTCUTPump();                              /* The write fails: link down */
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _utMock.txLen = 0;
    _utEventCount = 0;
    _utRxAccept = true;
    _utRxTakenCount = 0;
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribeId2));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktSubAckOkId2));
    _SSFMQTTCUTPub1(pkt, 'n', 0x0123);
    _SSFMQTTCUTInject(pkt, sizeof(pkt));
    _SSFMQTTCUTPumpUntilTaken(1, SSF_MQTTC_UT_LOAD_TICKS);   /* Reads are not suspended */
    SSF_ASSERT(_utRxTaken[0] == 'n');
    _utMock.txLen = 0;
    _utEventCount = 0;
    _SSFMQTTCUTEnd();

    /* Owed, then a link failure: the next session sends no PUBACK */
    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, sizeof(big));
    _SSFMQTTCUTOptsInit(&opts);
    opts.connectTimeout = SSF_TICKS_PER_SEC * 5u;
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 5u;
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    for (i = 0; i < SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();                              /* Delivered; their PUBACKs use the blocks */
    SSF_ASSERT(_utRxTakenCount == SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH);
    len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, 9, 1, 1,
                                  &hdrLen);
    _SSFMQTTCUTInject(big, len);                    /* Its PUBACK is owed */
    _SSFMQTTCUTPump();
    _utMock.sendResult = SSF_NET_IO_ERROR;
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(failed, 2);
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _utMock.txLen = 0;
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribeId2));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktSubAckOkId2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts SSFMQTTCTask() neither asks to be called again at once nor sets a zero timeout, a   */
/* few times over: no busy loop.                                                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTExpectIdle(void)
{
    uint32_t i;

    for (i = 0; i < 5u; i++)
    {
        SSFPortTick_t to = SSF_MAX_NEXT_TIMEOUT;

        (void)SSFSMTask(NULL);
        SSF_ASSERT(SSFMQTTCTask(&to) == false);
        SSF_ASSERT(to > 0);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests back-pressure edges: no busy loop while a packet is held behind an owed PUBACK or     */
/* while shutting down; nothing after DISCONNECT; no hold before CONNACK; an immediate wake-up  */
/* once a slot frees under a hold.                                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxHoldEdges(void)
{
    const uint32_t depth = SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH;
    uint8_t pkt[7];
    uint8_t big[512];
    size_t len;
    size_t hdrLen;
    size_t base;
    uint32_t i;
    SSFPortTick_t to;
    SSFPortTick_t t0;
    SSFMQTTCOpts_t opts;

    /* 1. Held behind an owed PUBACK: a deferred head times out with no PUBACK block free,     */
    /* freeing a slot the held packet cannot take until the owed PUBACK is queued               */
    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, sizeof(big));
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    _SSFMQTTCUTPub1(pkt, 'e', 5);
    _SSFMQTTCUTInject(pkt, sizeof(pkt));
    _SSFMQTTCUTPump();
    t0 = SSFPortGetTick64();                        /* e's first offer */
    SSF_ASSERT(_utRxPublishCount == 1);
    _utMock.recvChunk = 0;
    for (i = 0; i < depth; i++)                     /* Use up the PUBACK blocks */
    {
        len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE,
                                      (uint16_t)(11u + i), 1, 1, &hdrLen);
        _SSFMQTTCUTInject(big, len);
    }
    for (i = 1; i < depth; i++)                     /* Fill the queue behind e */
    {
        _SSFMQTTCUTPub1(pkt, (char)('e' + i), (uint16_t)(5u + i));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utEventCount == depth);
    _utEventCount = 0;
    while ((SSFPortGetTick64() - t0) <
           (SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS - (SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS / 2u)))
    { _SSFMQTTCUTPump(); }
    _SSFMQTTCUTPub1(pkt, 'z', 99);                  /* Held shortly before e times out */
    _SSFMQTTCUTInject(pkt, sizeof(pkt));
    _SSFMQTTCUTPumpUntilEvents(1, SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    /* e's timeout owes its PUBACK; on a loaded host the hold cap may expire first and owe    */
    /* the held packet's instead. Either way a PUBACK is owed and nothing may spin.             */
    SSF_ASSERT((_utEvents[0].reason == SSF_MQTTC_REASON_RX_PUBLISH_TIMEOUT) ||
               (_utEvents[0].reason == SSF_MQTTC_REASON_RX_PUBLISH_HOLD_TIMEOUT));
    _SSFMQTTCUTExpectIdle();
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _utEventCount = 0;
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();

    /* 2. Held while shutting down: no busy loop past the hold cap */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    opts.txPublishTimeout = SSF_TICKS_PER_SEC * 5u;  /* Bounds STOPPING */
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= depth; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();
    _utMock.shutdownWants = 0xffffffffu;
    SSFMQTTCStop();
    _SSFMQTTCUTPumpFor(SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPING);
    to = SSF_MAX_NEXT_TIMEOUT;
    (void)SSFMQTTCTask(&to);
    SSF_ASSERT(to > 0);
    _utMock.shutdownWants = 0;
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    _utEventCount = 0;
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();

    /* 3. Nothing after DISCONNECT: a hold, then Stop with the uplink blocked, the hold cap     */
    /* passing and a further QoS 1 PUBLISH arriving while STOPPING, then the uplink drains      */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    opts.txPublishTimeout = SSF_TICKS_PER_SEC * 5u;
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvChunk = sizeof(pkt);
    _utRxAccept = false;
    for (i = 0; i <= depth; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPub1(pkt, 'y', 0x77);
    _SSFMQTTCUTInject(pkt, sizeof(pkt));
    _SSFMQTTCUTPump();
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    SSFMQTTCStop();
    _SSFMQTTCUTPumpFor(SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPING);
    _SSFMQTTCUTExpectIdle();                        /* Blocked, but no busy loop */
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_STOPPED, SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));   /* DISCONNECT alone, last */
    _utEventCount = 0;
    _SSFMQTTCUTEnd();

    /* 3b. Nothing after DISCONNECT when a PUBACK is owed at Stop: the owed one is abandoned   */
    _SSFMQTTCUTBeginRx(SSF_MQTTC_UT_TX_BLOCKS, sizeof(big));
    _SSFMQTTCUTOptsInit(&opts);
    opts.txPublishTimeout = SSF_TICKS_PER_SEC * 5u;
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    for (i = 0; i < depth; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();
    len = _SSFMQTTCUTBuildPublish(big, sizeof(big), 0x32, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, 9, 1, 1,
                                  &hdrLen);
    _SSFMQTTCUTInject(big, len);
    _SSFMQTTCUTPump();                              /* Id 9 owed */
    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    _utMock.sendChunk = 3;                          /* Blocks free before DISCONNECT is out */
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_STOPPED, SSF_MQTTC_UT_LOAD_TICKS);
    SSF_ASSERT(_utMock.txLen == ((depth * 4u) + sizeof(_utPktDisconnect)));
    SSF_ASSERT(memcmp(&_utMock.tx[_utMock.txLen - 2u], _utPktDisconnect, 2) == 0);
    _utMock.txLen = 0;
    _utEventCount = 0;
    _SSFMQTTCUTEnd();

    /* 4. No hold before CONNACK: a hostile burst ahead of CONNACK is dropped unacknowledged and */
    /* the CONNACK behind it is still read                                                       */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
    _utMock.recvChunk = sizeof(pkt);
    for (i = 0; i <= depth; i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_SUBSCRIBING, SSF_MQTTC_UT_LOAD_TICKS);
    SSF_ASSERT(_utMock.rxPos == _utMock.rxLen);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribe1));   /* No PUBACK */
    _utEventCount = 0;
    _SSFMQTTCUTEnd();

    /* 5. Wake-up: once the transport drains under a hold and a slot frees, the task asks to be  */
    /* called again at once                                                                      */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvChunk = sizeof(pkt);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    base = _utMock.rxPos;
    for (i = 0; i < ((2u * depth) + 1u); i++)
    {
        _SSFMQTTCUTPub1(pkt, (char)('a' + i), (uint16_t)(i + 1u));
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();
    SSF_ASSERT((_utMock.rxPos - base) == (((2u * depth) + 1u) * sizeof(pkt)));
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    {
        bool isWoken = false;

        for (i = 0; (i < 3u) && (isWoken == false); i++)
        {
            to = SSF_MAX_NEXT_TIMEOUT;
            (void)SSFSMTask(NULL);
            if (SSFMQTTCTask(&to) || (to == 0)) isWoken = true;
        }
        SSF_ASSERT(isWoken);
    }
    _SSFMQTTCUTPumpUntilTaken((2u * depth) + 1u, SSF_MQTTC_UT_LOAD_TICKS);
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests a peer close while READY.                                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioPeerClosed(void)
{
    static const SSFMQTTCUTEventRec_t expected[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PEER_CLOSED } };
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.recvEmptyResult = SSF_NET_IO_CLOSED;
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utMock.closeCount == 1);
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTExpectEvents(expected, 1);
    _utMock.recvEmptyResult = SSF_NET_IO_WANT_READ;
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests a refused open and a connect timeout.                                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioConnectFailures(void)
{
    static const SSFMQTTCUTEventRec_t openFailed[] =
    { { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_TRANSPORT_ERROR } };
    static const SSFMQTTCUTEventRec_t timedOut[] =
    { { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_CONNECT_TIMEOUT } };
    SSFMQTTCOpts_t opts;

    /* open() refuses */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _utMock.openResult = false;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utMock.closeCount == 0);            /* Never opened, so never closed */
    _SSFMQTTCUTExpectEvents(openFailed, 1);
    _SSFMQTTCUTEnd();

    /* pollOpen() never completes */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _utMock.pollResult = SSF_NET_IO_WANT_WRITE;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utMock.closeCount == 1);
    _SSFMQTTCUTExpectEvents(timedOut, 1);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* After a backoff: expects CONNECT, accepts it, and grants the SUBSCRIBE (whatever its id).     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTWillReconnect(const uint8_t *connect, size_t connectLen)
{
    uint8_t subAck[] = { 0x90, 0x03, 0x00, 0x00, 0x01 };

    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(connect, connectLen);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.txLen == sizeof(_utPktSubscribe1));
    subAck[2] = _utMock.tx[2];                      /* SUBSCRIBE packet id */
    subAck[3] = _utMock.tx[3];
    _utMock.txLen = 0;
    _SSFMQTTCUTInject(subAck, sizeof(subAck));
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTED, SSF_MQTTC_UT_LOAD_TICKS);
    _utEventCount = 0;                              /* CONNECTED, READY */
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the Last Will: CONNECT carries it on every attempt, a failure closes without DISCONNECT */
/* so the broker publishes it, Stop() still sends DISCONNECT, and Start() rejects a bad will.    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioWill(void)
{
    static const uint8_t willMsg[] = { 'o', 'f', 'f' };
    static const SSFMQTTCWill_t will = { "d/s", willMsg, sizeof(willMsg), SSF_MQTTC_QOS_1, true };
    /* Flags 0x02 | 0x04 | (1 << 3) | 0x20 = 0x2E; will topic and message after the client id */
    static const uint8_t connectWill[] =
    {
        0x10, 0x18, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x2E, 0x00, 0x78, 0x00, 0x02, 'u', 't',
        0x00, 0x03, 'd', '/', 's', 0x00, 0x03, 'o', 'f', 'f'
    };
    static const uint8_t reserved[] = { 0xF0, 0x00 };
    static const SSFMQTTCUTEventRec_t lost[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    static uint8_t bigMsg[SSF_MQTTC_UT_TX_BLOCK_SIZE];
    SSFMQTTCWill_t bad;
    SSFMQTTCOpts_t opts;
    uint32_t i;

    /* Start() rejects a will that cannot be sent */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    opts.willOpt = &bad;
    {
        static const char *badTopics[] = { "a/+", "#", "a/b#", "+/x", "" };
        for (i = 0; i < (sizeof(badTopics) / sizeof(badTopics[0])); i++)
        {
            bad = will; bad.topic = badTopics[i];
            SSF_ASSERT_TEST(SSFMQTTCStart(&opts));
        }
    }
    bad = will; bad.topic = NULL;
    SSF_ASSERT_TEST(SSFMQTTCStart(&opts));
    bad = will; bad.qos = SSF_MQTTC_QOS_2;
    SSF_ASSERT_TEST(SSFMQTTCStart(&opts));
    bad = will; bad.payloadOpt = NULL;
    SSF_ASSERT_TEST(SSFMQTTCStart(&opts));
    /* The CONNECT, will included, must fit a tx block */
    bad = will; bad.payloadOpt = bigMsg; bad.payloadLen = sizeof(bigMsg);
    SSF_ASSERT_TEST(SSFMQTTCStart(&opts));
    bad = will; bad.payloadOpt = bigMsg;
    bad.payloadLen = (uint16_t)(SSF_MQTTC_UT_TX_BLOCK_SIZE - (sizeof(connectWill) - 3u) + 1u);
    SSF_ASSERT_TEST(SSFMQTTCStart(&opts));             /* One byte too large */
    bad.payloadLen--;                                  /* Exactly fills a block */
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.txLen == SSF_MQTTC_UT_TX_BLOCK_SIZE);
    _utMock.txLen = 0;
    _SSFMQTTCUTEnd();
    /* An empty message with a NULL pointer is valid */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    bad = will; bad.payloadOpt = NULL; bad.payloadLen = 0; bad.qos = SSF_MQTTC_QOS_0;
    bad.retain = false;
    opts.willOpt = &bad;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    {
        static const uint8_t connectEmpty[] =
        {
            0x10, 0x15, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x06, 0x00, 0x78, 0x00, 0x02, 'u',
            't', 0x00, 0x03, 'd', '/', 's', 0x00, 0x00
        };
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(connectEmpty));
    }
    _SSFMQTTCUTEnd();

    /* The will rides on CONNECT; a failure closes without DISCONNECT */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    opts.willOpt = &will;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(connectWill));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribe1));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktSubAckOk1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCIsReady());
    _utEventCount = 0;
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(reserved));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utMock.closeCount == 1);
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTExpectEvents(lost, 1);

    /* The next attempt carries the will again */
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTWillReconnect(connectWill, sizeof(connectWill));

    /* A publish timeout is a failure too: no DISCONNECT behind the PUBLISH */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_1, false, NULL,
                                 NULL));
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utMock.txLen == 10u);               /* The QoS 1 PUBLISH alone */
    SSF_ASSERT(_utMock.tx[0] == 0x32);
    _utMock.txLen = 0;

    /* Stop() from READY still sends DISCONNECT, so an orderly stop never fires the will */
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                              SSF_MQTTC_UT_BACKOFF_TICKS * 2u + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTWillReconnect(connectWill, sizeof(connectWill));
    SSFMQTTCStop();
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_STOPPED, SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
    _SSFMQTTCUTEnd();
}

/* Three filters: "a/b" QoS 1, "c" QoS 0, "d" QoS 1. */
static const SSFMQTTCSub_t _utThreeSubs[] =
{ { "a/b", SSF_MQTTC_QOS_1 }, { "c", SSF_MQTTC_QOS_0 }, { "d", SSF_MQTTC_QOS_1 } };
static const uint8_t _utPktSubscribe3Subs[] =
{
    0x82, 0x10, 0x00, 0x01, 0x00, 0x03, 'a', '/', 'b', 0x01, 0x00, 0x01, 'c', 0x00, 0x00, 0x01,
    'd', 0x01
};
/* "a/b" and "d" refused, "c" granted */
static const uint8_t _utPktSubAck3RefuseAD[] = { 0x90, 0x05, 0x00, 0x01, 0x80, 0x00, 0x80 };

/* --------------------------------------------------------------------------------------------- */
/* Reaches READY with "a/b" and "d" of _utThreeSubs refused; opts must outlive the client run.   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTGoReadyRefusedAD(SSFMQTTCOpts_t *opts)
{
    static const SSFMQTTCUTEventRec_t ready[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_SUBSCRIBE_REFUSED },
    };
    static const uint8_t results[] = { SSF_MQTTC_SUB_REFUSED, 0, SSF_MQTTC_SUB_REFUSED };

    _SSFMQTTCUTSubAckAttemptOpts(opts, SSF_MQTTC_UT_ARRAY(_utPktSubscribe3Subs),
                                 SSF_MQTTC_UT_ARRAY(_utPktSubAck3RefuseAD));
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED);
    _SSFMQTTCUTExpectEvents(ready, 2);
    _SSFMQTTCUTExpectSubResults(results, 3);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the automatic retry of refused filters: only they are re-subscribed, every              */
/* SSF_MQTTC_CONFIG_SUB_RETRY_TICKS, until granted; SUBSCRIPTION_CHANGED reports each gain.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSubRetry(void)
{
    /* Retries carry "a/b" and "d" only, with the next packet ids */
    static const uint8_t retryAD2[] =
    { 0x82, 0x0C, 0x00, 0x02, 0x00, 0x03, 'a', '/', 'b', 0x01, 0x00, 0x01, 'd', 0x01 };
    static const uint8_t retryAD3[] =
    { 0x82, 0x0C, 0x00, 0x03, 0x00, 0x03, 'a', '/', 'b', 0x01, 0x00, 0x01, 'd', 0x01 };
    static const uint8_t retryA4[] = { 0x82, 0x08, 0x00, 0x04, 0x00, 0x03, 'a', '/', 'b', 0x01 };
    static const uint8_t subAckGrantDown2[] = { 0x90, 0x04, 0x00, 0x02, 0x01, 0x00 };
    static const uint8_t subAckRefuseBoth2[] = { 0x90, 0x04, 0x00, 0x02, 0x80, 0x80 };
    static const uint8_t subAckGrantD3[] = { 0x90, 0x04, 0x00, 0x03, 0x80, 0x01 };
    static const uint8_t subAckGrantA4[] = { 0x90, 0x03, 0x00, 0x04, 0x01 };
    static const uint8_t subAckWrongId[] = { 0x90, 0x04, 0x00, 0x09, 0x01, 0x01 };
    static const uint8_t subAckTooFew2[] = { 0x90, 0x03, 0x00, 0x02, 0x01 };
    static const uint8_t subAckExceeded2[] = { 0x90, 0x04, 0x00, 0x02, 0x02, 0x01 };
    static const uint8_t subAckStray1[] = { 0x90, 0x05, 0x00, 0x01, 0x01, 0x00, 0x01 };
    static const uint8_t pubX[] = { 0x30, 0x06, 0x00, 0x03, 'a', '/', 'b', 'x' };
    static const SSFMQTTCUTEventRec_t allGranted[] =
    { { SSF_MQTTC_EVENT_SUBSCRIPTION_CHANGED, SSF_MQTTC_REASON_NONE } };
    static const SSFMQTTCUTEventRec_t someGranted[] =
    { { SSF_MQTTC_EVENT_SUBSCRIPTION_CHANGED, SSF_MQTTC_REASON_SUBSCRIBE_REFUSED } };
    static const SSFMQTTCUTEventRec_t protocol[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    static const SSFMQTTCUTEventRec_t subTimeout[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_SUBSCRIBE_TIMEOUT } };
    static const SSFMQTTCUTEventRec_t exceeded[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_SUBSCRIBE_QOS_EXCEEDED } };
    static const SSFMQTTCUTEventRec_t stopped[] =
    { { SSF_MQTTC_EVENT_STOPPED, SSF_MQTTC_REASON_NONE } };
    static const uint8_t resultsGrantDown[] = { 1, 0, 0 };
    static const uint8_t resultsGrantD[] = { SSF_MQTTC_SUB_REFUSED, 0, 1 };
    static const uint8_t resultsAll[] = { 1, 0, 1 };
    static SSFMQTTCOpts_t opts;
    SSFPortTick_t readyAt;
    SSFPortTick_t sentAt;
    uint32_t i;
    uint8_t r;

    _SSFMQTTCUTSubOptsInit(&opts, _utThreeSubs, 3);

    /* Results: false outside CONNECTED; a bad index or NULL output asserts */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    SSF_ASSERT(SSFMQTTCGetSubResult(0, &r) == false);
    _SSFMQTTCUTEnd();

    /* The first retry, one interval after READY, grants "a/b" and grants "d" at a lower QoS */
    _SSFMQTTCUTGoReadyRefusedAD(&opts);
    readyAt = SSFPortGetTick64();
    SSF_ASSERT_TEST(SSFMQTTCGetSubResult(3, &r));
    SSF_ASSERT_TEST(SSFMQTTCGetSubResult(0, NULL));
    sentAt = _SSFMQTTCUTPumpUntilTx(sizeof(retryAD2),
                                    SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    SSF_ASSERT((sentAt - readyAt) >= SSF_MQTTC_CONFIG_SUB_RETRY_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD2));
    SSF_ASSERT(_utEventCount == 0);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckGrantDown2));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectEvents(allGranted, 1);
    _SSFMQTTCUTExpectSubResults(resultsGrantDown, 3);
    /* Nothing refused: no further retry */
    _SSFMQTTCUTPumpFor((SSF_MQTTC_CONFIG_SUB_RETRY_TICKS * 2u) + SSF_MQTTC_UT_SLACK_TICKS);
    _SSFMQTTCUTExpectTx(NULL, 0);
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT(SSFMQTTCIsReady());
    /* A repeat of that SUBACK, with no retry outstanding, is a protocol error */
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckGrantDown2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(protocol, 1);
    _SSFMQTTCUTEnd();

    /* Still refused: no event, retried again; then one granted, then the last */
    _SSFMQTTCUTGoReadyRefusedAD(&opts);
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryAD2),
                                 SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD2));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckRefuseBoth2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utEventCount == 0);
    {
        static const uint8_t same[] = { SSF_MQTTC_SUB_REFUSED, 0, SSF_MQTTC_SUB_REFUSED };
        _SSFMQTTCUTExpectSubResults(same, 3);
    }
    sentAt = SSFPortGetTick64();
    readyAt = _SSFMQTTCUTPumpUntilTx(sizeof(retryAD3),
                                     SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    SSF_ASSERT((readyAt - sentAt) >=
               (SSF_MQTTC_CONFIG_SUB_RETRY_TICKS - SSF_MQTTC_UT_SLACK_TICKS));
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD3));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckGrantD3));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectEvents(someGranted, 1);
    _SSFMQTTCUTExpectSubResults(resultsGrantD, 3);
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryA4),
                                 SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryA4));
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckGrantA4));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectEvents(allGranted, 1);
    _SSFMQTTCUTExpectSubResults(resultsAll, 3);
    _SSFMQTTCUTEnd();

    /* Retry SUBACK with the wrong id, the wrong count, or a higher QoS ends the connection */
    for (i = 0; i < 3; i++)
    {
        _SSFMQTTCUTGoReadyRefusedAD(&opts);
        (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryAD2),
                                     SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD2));
        if (i == 0) _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckWrongId));
        else if (i == 1) _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckTooFew2));
        else _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckExceeded2));
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        SSF_ASSERT(SSFMQTTCGetSubResult(0, &r) == false);
        _SSFMQTTCUTExpectEvents((i < 2) ? protocol : exceeded, 1);
        _SSFMQTTCUTExpectTx(NULL, 0);
        _SSFMQTTCUTEnd();
    }

    /* A SUBACK while no retry is outstanding is a protocol error */
    _SSFMQTTCUTGoReadyRefusedAD(&opts);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(subAckStray1));
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(protocol, 1);
    _SSFMQTTCUTEnd();

    /* Two SUBACKs in one read: the second is a broker error and must not replace the first's   */
    /* results, so READY still reports the refusals before the connection ends                 */
    {
        static const uint8_t subAckGrantAll1[] = { 0x90, 0x05, 0x00, 0x01, 0x01, 0x00, 0x01 };
        static const SSFMQTTCUTEventRec_t readyThenLost[] =
        {
            { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
            { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_SUBSCRIBE_REFUSED },
            { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL },
        };
        uint8_t both[sizeof(_utPktSubAck3RefuseAD) + sizeof(subAckGrantAll1)];

        memcpy(both, _utPktSubAck3RefuseAD, sizeof(_utPktSubAck3RefuseAD));
        memcpy(&both[sizeof(_utPktSubAck3RefuseAD)], subAckGrantAll1, sizeof(subAckGrantAll1));
        _SSFMQTTCUTSubAckAttemptOpts(&opts, SSF_MQTTC_UT_ARRAY(_utPktSubscribe3Subs),
                                     SSF_MQTTC_UT_ARRAY(both));
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        _SSFMQTTCUTExpectEvents(readyThenLost, 3);
        _SSFMQTTCUTEnd();
    }

    /* No SUBACK for a retry within subscribeTimeout ends the connection */
    opts.subscribeTimeout = SSF_MQTTC_UT_SHORT_TICKS;
    _SSFMQTTCUTGoReadyRefusedAD(&opts);
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryAD2),
                                 SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD2));
    _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_RECONNECT_WAIT,
                              SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectEvents(subTimeout, 1);
    _SSFMQTTCUTEnd();
    _SSFMQTTCUTSubOptsInit(&opts, _utThreeSubs, 3);

    /* No free tx block when the retry falls due: skipped, tried again one interval later */
    opts.txPublishTimeout = SSF_MQTTC_CONFIG_SUB_RETRY_TICKS * 4u;
    _SSFMQTTCUTGoReadyRefusedAD(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    for (i = 0; i < SSF_MQTTC_UT_TX_BLOCKS; i++)
    {
        SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_0, false, NULL,
                                     NULL));
    }
    _SSFMQTTCUTPumpFor(SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.txLen == (SSF_MQTTC_UT_TX_BLOCKS * sizeof(pubX)));   /* No SUBSCRIBE */
    _utMock.txLen = 0;
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryAD2),
                                 SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD2));
    SSF_ASSERT(_utEventCount == 0);
    _SSFMQTTCUTEnd();
    _SSFMQTTCUTSubOptsInit(&opts, _utThreeSubs, 3);

    /* Stop with a retry outstanding, and Stop before one is due: DISCONNECT, then nothing */
    for (i = 0; i < 2; i++)
    {
        _SSFMQTTCUTGoReadyRefusedAD(&opts);
        if (i == 0)
        {
            (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryAD2), SSF_MQTTC_CONFIG_SUB_RETRY_TICKS +
                                                           SSF_MQTTC_UT_LOAD_TICKS);
            _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD2));
        }
        SSFMQTTCStop();
        _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_STOPPED, SSF_MQTTC_UT_LOAD_TICKS);
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
        _SSFMQTTCUTExpectEvents(stopped, 1);
        _SSFMQTTCUTPumpFor((SSF_MQTTC_CONFIG_SUB_RETRY_TICKS * 2u) + SSF_MQTTC_UT_SLACK_TICKS);
        _SSFMQTTCUTExpectTx(NULL, 0);
        SSF_ASSERT(_utEventCount == 0);
        _SSFMQTTCUTEnd();
    }

    /* A new connection subscribes the full set again and starts with fresh results, also when */
    /* the old one ended with a retry outstanding                                              */
    _SSFMQTTCUTGoReadyRefusedAD(&opts);
    (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryAD2),
                                 SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(retryAD2));
    {
        static const uint8_t reserved[] = { 0xF0, 0x00 };
        static const SSFMQTTCUTEventRec_t ready[] =
        {
            { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
            { SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_SUBSCRIBE_REFUSED },
        };
        static const uint8_t resultsRefuseA[] = { SSF_MQTTC_SUB_REFUSED, 0, 1 };
        static const uint8_t retryA[] =
        { 0x82, 0x08, 0x00, 0x00, 0x00, 0x03, 'a', '/', 'b', 0x01 };     /* Id not checked */
        /* This connection refuses "a/b" only */
        uint8_t subAck[] = { 0x90, 0x05, 0x00, 0x00, 0x80, 0x00, 0x01 };

        _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(reserved));
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectEvents(protocol, 1);
        _SSFMQTTCUTPumpUntilState(SSF_MQTTC_STATE_CONNECTING,
                                  SSF_MQTTC_UT_BACKOFF_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
        _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
        _SSFMQTTCUTPump();
        SSF_ASSERT(_utMock.txLen == sizeof(_utPktSubscribe3Subs));     /* The full set */
        SSF_ASSERT(memcmp(&_utMock.tx[4], &_utPktSubscribe3Subs[4],
                          sizeof(_utPktSubscribe3Subs) - 4u) == 0);
        subAck[2] = _utMock.tx[2];
        subAck[3] = _utMock.tx[3];
        _utMock.txLen = 0;
        _SSFMQTTCUTInject(subAck, sizeof(subAck));
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectEvents(ready, 2);
        _SSFMQTTCUTExpectSubResults(resultsRefuseA, 3);
        /* Its retry carries just "a/b": nothing of the old connection's retry survived */
        (void)_SSFMQTTCUTPumpUntilTx(sizeof(retryA),
                                     SSF_MQTTC_CONFIG_SUB_RETRY_TICKS + SSF_MQTTC_UT_LOAD_TICKS);
        SSF_ASSERT(_utMock.txLen == sizeof(retryA));
        SSF_ASSERT((_utMock.tx[0] == retryA[0]) && (_utMock.tx[1] == retryA[1]));
        SSF_ASSERT(memcmp(&_utMock.tx[4], &retryA[4], sizeof(retryA) - 4u) == 0);
        _utMock.txLen = 0;
    }
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the SUBACK timeout and the txPublish deadline.                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSessionTimeouts(void)
{
    static const SSFMQTTCUTEventRec_t subTimeout[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_SUBSCRIBE_TIMEOUT },
    };
    static const SSFMQTTCUTEventRec_t pubTimeout[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_TX_PUBLISH_TIMEOUT } };
    static const uint8_t pubX[] = { 0x32, 0x08, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x02, 'x' };
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    /* CONNECT and SUBSCRIBE only: no DISCONNECT on failure */
    SSF_ASSERT(_utMock.txLen == (sizeof(_utPktConnect) + sizeof(_utPktSubscribe1)));
    SSF_ASSERT(memcmp(&_utMock.tx[sizeof(_utPktConnect)], _utPktSubscribe1,
                      sizeof(_utPktSubscribe1)) == 0);
    _utMock.txLen = 0;
    _SSFMQTTCUTExpectEvents(subTimeout, 2);
    _SSFMQTTCUTEnd();

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_1, false,
                                 _SSFMQTTCUTTxDone, NULL));
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utTxDoneCount == 1);
    SSF_ASSERT(_utTxDoneTrueCount == 0);            /* Completed false by the teardown */
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pubX));  /* The PUBLISH only: no DISCONNECT */
    _SSFMQTTCUTExpectEvents(pubTimeout, 1);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests Stop from READY, CONNECTING, RECONNECT_WAIT and a stalled flush.                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioStopPaths(void)
{
    static const SSFMQTTCUTEventRec_t stopped[] = { { SSF_MQTTC_EVENT_STOPPED, SSF_MQTTC_REASON_NONE } };
    SSFMQTTCOpts_t opts;

    /* Stop while READY with a QoS 1 publish awaiting PUBACK */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_1, false,
                                 _SSFMQTTCUTTxDone, NULL));
    _SSFMQTTCUTPump();
    _utMock.txLen = 0;
    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
    SSF_ASSERT(_utTxDoneCount == 1);
    SSF_ASSERT(_utTxDoneTrueCount == 0);
    _SSFMQTTCUTExpectEvents(stopped, 1);
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_0, false, NULL,
                                 NULL) == false);
    _SSFMQTTCUTEnd();

    /* Stop while CONNECTING: no DISCONNECT, just close and STOPPED */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _utMock.pollResult = SSF_NET_IO_WANT_WRITE;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utMock.closeCount == 1);
    _SSFMQTTCUTExpectTx(NULL, 0);
    _SSFMQTTCUTExpectEvents(stopped, 1);
    _SSFMQTTCUTEnd();

    /* Stop while RECONNECT_WAIT: no transport activity at all */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _utMock.openResult = false;
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _utEventCount = 0;
    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utMock.closeCount == 0);
    _SSFMQTTCUTExpectEvents(stopped, 1);
    _SSFMQTTCUTEnd();

    /* Stop while the transport will not drain: the flush limit ends it */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendResult = SSF_NET_IO_WANT_WRITE;
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_0, false,
                                 _SSFMQTTCUTTxDone, NULL));
    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPING);
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utTxDoneCount == 1);
    SSF_ASSERT(_utTxDoneTrueCount == 0);
    _SSFMQTTCUTExpectEvents(stopped, 1);
    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that Stop delivers DISCONNECT through shutdown() before close(), and its limits.        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioGracefulClose(void)
{
    static const SSFMQTTCUTEventRec_t stopped[] = { { SSF_MQTTC_EVENT_STOPPED, SSF_MQTTC_REASON_NONE } };
    SSFMQTTCOpts_t opts;
    uint32_t i;

    /* shutdown() is not started until DISCONNECT is fully accepted, then polled until SUCCESS */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.sendChunk = 1;                          /* DISCONNECT goes out a byte per call */
    _utMock.shutdownWants = 3;
    SSFMQTTCStop();
    (void)SSFSMTask(NULL);                          /* Enter STOPPING: DISCONNECT queued */
    (void)SSFMQTTCTask(NULL);                       /* First byte only */
    SSF_ASSERT(_utMock.txLen == 1);
    SSF_ASSERT(_utMock.shutdownCount == 0);
    for (i = 0; (i < 8u) && (_utMock.closeCount == 0); i++)
    {
        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
        if (_utMock.shutdownCount > 0) SSF_ASSERT(_utMock.txLen == 2);   /* Whole packet first */
    }
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utMock.shutdownCount == 4);         /* 3 x WANT_WRITE, then SUCCESS, no more */
    SSF_ASSERT(_utMock.closeCount == 1);
    SSF_ASSERT(_utMock.wasShutdownAtClose);
    _SSFMQTTCUTExpectEvents(stopped, 1);
    _SSFMQTTCUTEnd();

    /* While shutdown() reports WANT_WRITE the client stays STOPPING and does not close */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.shutdownWants = 0xffffffffu;
    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPING);
    SSF_ASSERT(_utMock.closeCount == 0);
    SSF_ASSERT(_utMock.shutdownCount > 0);
    /* ... until the stop limit (txPublishTimeout) closes it anyway, without a second DISCONNECT */
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utMock.closeCount == 1);
    SSF_ASSERT(_utMock.wasShutdownAtClose == false);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
    _SSFMQTTCUTExpectEvents(stopped, 1);
    _SSFMQTTCUTEnd();

    /* A shutdown() failure ends the stop at once: close, STOPPED, nothing re-sent */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    _utMock.shutdownResult = SSF_NET_IO_ERROR;
    SSFMQTTCStop();
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utMock.shutdownCount == 1);
    SSF_ASSERT(_utMock.closeCount == 1);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));
    _SSFMQTTCUTExpectEvents(stopped, 1);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Layer 3: round trip against a public broker over the real socket transport                    */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_MQTTC_UNIT_TEST_BROKER == 1
#define SSF_MQTTC_UT_BROKER_STEP_TICKS   (SSF_TICKS_PER_SEC * 20u)   /* Per phase */
#define SSF_MQTTC_UT_BROKER_WS_PORT      (8080u)                     /* ws:// listener */
#define SSF_MQTTC_UT_BROKER_WS_PATH      "/mqtt"

static SSFNetWSSession_t _utBrokerWS;

/* --------------------------------------------------------------------------------------------- */
/* Runs both tasks once, yielding briefly when idle.                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTBrokerStep(void)
{
    SSFPortTick_t to = SSF_MAX_NEXT_TIMEOUT;

    (void)SSFSMTask(&to);
    if (SSFMQTTCTask(&to) == false)
    {
#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the most recent logged event, or EVENT_MIN if none.                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFMQTTCEvent_t _SSFMQTTCUTLastEvent(void)
{
    return (_utEventCount == 0) ? SSF_MQTTC_EVENT_MIN : _utEvents[_utEventCount - 1].event;
}

/* --------------------------------------------------------------------------------------------- */
/* Tests a QoS 1 publish echoed back by a public broker over transport. Returns false if it was  */
/* skipped because the broker was unreachable, which isRequired turns into a failure.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCUTBrokerEchoOver(SSFNetTransport_t *transport, uint16_t port,
                                      const char *label, bool isRequired)
{
    static char clientId[32];
    static char topic[64];
    static char payload[48];
    static char retained[48];
    static const SSFMQTTCSub_t subs[1] = { { topic, SSF_MQTTC_QOS_1 } };
    SSFMQTTCOpts_t opts;
    SSFPortTick_t end;
    SSFPortTick_t now = SSFPortGetTick64();

    (void)snprintf(clientId, sizeof(clientId), "ssf-ut-%08lx", (unsigned long)(now & 0xFFFFFFFFul));
    (void)snprintf(topic, sizeof(topic), "ssf/ut/%s/echo", clientId);
    (void)snprintf(payload, sizeof(payload), "echo %lu", (unsigned long)(now & 0xFFFFFFFFul));
    (void)snprintf(retained, sizeof(retained), "retained %lu",
                   (unsigned long)(now & 0xFFFFFFFFul));

    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    _SSFMQTTCUTRecordReset();
    SSFMQTTCInit(transport, SSF_MQTTC_UT_TX_BLOCKS, SSF_MQTTC_UT_TX_BLOCK_SIZE,
                 SSF_MQTTC_UT_RX_BLOCK_SIZE, _SSFMQTTCUTRxPublish, &_utRxPublishCtx,
                 _SSFMQTTCUTEvent, &_utEventCtx);

    memset(&opts, 0, sizeof(opts));
    opts.host = SSF_MQTTC_UT_BROKER_HOST;
    opts.port = port;
    opts.clientId = clientId;
    opts.subsOpt = subs;
    opts.subCount = 1;
    opts.keepAliveSec = 120;
    opts.connectTimeout = SSF_TICKS_PER_SEC * 10;
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 10;
    opts.txPublishTimeout = SSF_TICKS_PER_SEC * 10;
    opts.reconnectMinWait = SSF_TICKS_PER_SEC * 5;
    opts.reconnectMaxWait = SSF_TICKS_PER_SEC * 5;
    SSFMQTTCStart(&opts);

    /* Reach READY, or learn that the broker is not reachable from here */
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while ((SSFMQTTCIsReady() == false) && (_SSFMQTTCUTLastEvent() != SSF_MQTTC_EVENT_CONNECT_FAILED) &&
           (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }

    if (SSFMQTTCIsReady() == false)
    {
        SSFMQTTCReason_t reason = (_utEventCount == 0) ? SSF_MQTTC_REASON_NONE :
                                  _utEvents[_utEventCount - 1].reason;
        bool isUnreachable = (reason == SSF_MQTTC_REASON_TRANSPORT_ERROR) ||
                             (reason == SSF_MQTTC_REASON_PEER_CLOSED) ||
                             (reason == SSF_MQTTC_REASON_CONNECT_TIMEOUT) ||
                             (reason == SSF_MQTTC_REASON_CONNACK_SERVER_UNAVAILABLE) ||
                             (_utEventCount == 0);
        SSF_ASSERT(isUnreachable);                  /* Anything else is a real failure */
        SSF_ASSERT(isRequired == false);
        printf("ssfmqttc: %s:%u (%s) unreachable (reason %d); broker round trip skipped\r\n",
               SSF_MQTTC_UT_BROKER_HOST, (unsigned)port, label, (int)reason);
        SSFMQTTCStop();
        end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
        while ((SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED) && (SSFPortGetTick64() < end))
        { _SSFMQTTCUTBrokerStep(); }
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
        SSFMQTTCDeInit();
        SSFSMDeInit();
        return false;
    }
    SSF_ASSERT(_utEventCount == 2);
    SSF_ASSERT(_utEvents[0].event == SSF_MQTTC_EVENT_CONNECTED);
    SSF_ASSERT(_utEvents[1].event == SSF_MQTTC_EVENT_READY);
    _utEventCount = 0;

    /* Publish to the subscribed topic and wait for the completion and the echo */
    SSF_ASSERT(SSFMQTTCTxPublish(topic, (const uint8_t *)payload, strlen(payload),
                                 SSF_MQTTC_QOS_1, false, _SSFMQTTCUTTxDone, &_utTxDoneCount));
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while (((_utTxDoneCount == 0) || (_utRxPublishCount == 0)) && (_utEventCount == 0) &&
           (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(_utEventCount == 0);                 /* No disconnect or drop along the way */
    SSF_ASSERT(_utTxDoneCount == 1);
    SSF_ASSERT(_utTxDoneTrueCount == 1);
    SSF_ASSERT(_utTxDoneLastCtx == &_utTxDoneCount);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, topic) == 0);
    SSF_ASSERT(_utRx.topicLen == strlen(topic));
    SSF_ASSERT(_utRx.payloadLen == strlen(payload));
    SSF_ASSERT(memcmp(_utRxPayload, payload, strlen(payload)) == 0);
    SSF_ASSERT(_utRx.qos == SSF_MQTTC_QOS_1);
    SSF_ASSERT(_utRx.retain == false);
    SSF_ASSERT(_utRx.offerCount == 1);

    /* A retained publish reaches the live subscriber with RETAIN 0 (3.3.1.3) */
    _SSFMQTTCUTRecordReset();
    SSF_ASSERT(SSFMQTTCTxPublish(topic, (const uint8_t *)retained, strlen(retained),
                                 SSF_MQTTC_QOS_1, true, _SSFMQTTCUTTxDone, &_utTxDoneCount));
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while (((_utTxDoneCount == 0) || (_utRxPublishCount == 0)) && (_utEventCount == 0) &&
           (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT(_utTxDoneTrueCount == 1);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(_utRx.payloadLen == strlen(retained));
    SSF_ASSERT(memcmp(_utRxPayload, retained, strlen(retained)) == 0);
    SSF_ASSERT(_utRx.retain == false);

    /* A new session gets the stored message with RETAIN 1 */
    SSFMQTTCStop();
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while ((SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED) && (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    _SSFMQTTCUTRecordReset();
    SSFMQTTCStart(&opts);
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while (((SSFMQTTCIsReady() == false) || (_utRxPublishCount == 0)) &&
           (_utEventCount <= 2) && (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(SSFMQTTCIsReady());
    SSF_ASSERT(_utEventCount == 2);
    SSF_ASSERT(_utEvents[0].event == SSF_MQTTC_EVENT_CONNECTED);
    SSF_ASSERT(_utEvents[1].event == SSF_MQTTC_EVENT_READY);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, topic) == 0);
    SSF_ASSERT(_utRx.payloadLen == strlen(retained));
    SSF_ASSERT(memcmp(_utRxPayload, retained, strlen(retained)) == 0);
    SSF_ASSERT(_utRx.retain == true);

    /* An empty retained publish clears it; the live subscriber still sees it, with RETAIN 0 */
    _SSFMQTTCUTRecordReset();
    SSF_ASSERT(SSFMQTTCTxPublish(topic, NULL, 0, SSF_MQTTC_QOS_1, true, _SSFMQTTCUTTxDone,
                                 &_utTxDoneCount));
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while (((_utTxDoneCount == 0) || (_utRxPublishCount == 0)) && (_utEventCount == 0) &&
           (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT(_utTxDoneTrueCount == 1);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(_utRx.payloadLen == 0);
    SSF_ASSERT(_utRx.retain == false);
    _utEventCount = 0;

    /* Orderly stop */
    SSFMQTTCStop();
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while ((SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED) && (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utEventCount == 1);
    SSF_ASSERT(_utEvents[0].event == SSF_MQTTC_EVENT_STOPPED);

    SSFMQTTCDeInit();
    SSFSMDeInit();
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the Last Will against the broker: ssfmqttc subscribes to a unique will topic, then a    */
/* second raw connection CONNECTs with that will (encoded by ssfmqttpkt) and closes without      */
/* DISCONNECT. The broker must publish the will to ssfmqttc. The will is not retained.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTBrokerWill(void)
{
    static char clientId[32];
    static char rawId[32];
    static char topic[64];
    static const uint8_t willMsg[] = { 'g', 'o', 'n', 'e' };
    static const SSFMQTTCSub_t subs[1] = { { topic, SSF_MQTTC_QOS_1 } };
    static SSFNetSock_t raw;
    SSFNetTransport_t *t = &raw.transport;
    SSFMQTTPktWill_t will;
    SSFMQTTCOpts_t opts;
    uint8_t pkt[96];
    size_t len;
    size_t pos;
    size_t n;
    SSFNetIOResult_t r;
    SSFPortTick_t end;
    SSFPortTick_t now = SSFPortGetTick64();

    (void)snprintf(clientId, sizeof(clientId), "ssf-ut-%08lx", (unsigned long)(now & 0xFFFFFFFFul));
    (void)snprintf(rawId, sizeof(rawId), "ssf-ut-%08lx-w", (unsigned long)(now & 0xFFFFFFFFul));
    (void)snprintf(topic, sizeof(topic), "ssf/ut/%s/will", clientId);

    /* ssfmqttc subscribes to the will topic */
    SSFNetSockInit(&_utSock);
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    _SSFMQTTCUTRecordReset();
    SSFMQTTCInit(&_utSock.transport, SSF_MQTTC_UT_TX_BLOCKS, SSF_MQTTC_UT_TX_BLOCK_SIZE,
                 SSF_MQTTC_UT_RX_BLOCK_SIZE, _SSFMQTTCUTRxPublish, &_utRxPublishCtx,
                 _SSFMQTTCUTEvent, &_utEventCtx);
    memset(&opts, 0, sizeof(opts));
    opts.host = SSF_MQTTC_UT_BROKER_HOST;
    opts.port = SSF_MQTTC_UT_BROKER_PORT;
    opts.clientId = clientId;
    opts.subsOpt = subs;
    opts.subCount = 1;
    opts.keepAliveSec = 120;
    opts.connectTimeout = SSF_TICKS_PER_SEC * 10;
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 10;
    opts.txPublishTimeout = SSF_TICKS_PER_SEC * 10;
    opts.reconnectMinWait = SSF_TICKS_PER_SEC * 5;
    opts.reconnectMaxWait = SSF_TICKS_PER_SEC * 5;
    SSFMQTTCStart(&opts);
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while ((SSFMQTTCIsReady() == false) && (SSFPortGetTick64() < end)) _SSFMQTTCUTBrokerStep();
    SSF_ASSERT(SSFMQTTCIsReady());                  /* The TCP leg just reached the broker */
    _SSFMQTTCUTRecordReset();

    /* The raw connection registers a will in CONNECT and waits for CONNACK accepted */
    SSFNetSockInit(&raw);
    SSF_ASSERT(t->open(t, SSF_MQTTC_UT_BROKER_HOST,
                                  sizeof(SSF_MQTTC_UT_BROKER_HOST), SSF_MQTTC_UT_BROKER_PORT));
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    do
    {
        r = t->pollOpen(t);
        _SSFMQTTCUTBrokerStep();
    } while (((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) &&
             (SSFPortGetTick64() < end));
    SSF_ASSERT(r == SSF_NET_IO_SUCCESS);
    will.topic = topic;
    will.payloadOpt = willMsg;
    will.payloadLen = sizeof(willMsg);
    will.qos = SSF_MQTTC_QOS_1;
    will.retain = false;
    SSFMQTTPktEncodeConnect(pkt, sizeof(pkt), &len, rawId, sizeof(rawId), &will, sizeof(topic),
                            NULL, 0, NULL, 0, 60);
    for (pos = 0; (pos < len) && (SSFPortGetTick64() < end); pos += n)
    {
        n = 0;
        r = t->send(t, &pkt[pos], len - pos, &n);
        SSF_ASSERT((r == SSF_NET_IO_SUCCESS) || (r == SSF_NET_IO_WANT_WRITE));
        _SSFMQTTCUTBrokerStep();
    }
    SSF_ASSERT(pos == len);
    for (pos = 0; (pos < 4u) && (SSFPortGetTick64() < end); pos += n)
    {
        n = 0;
        r = t->recv(t, &pkt[pos], 4u - pos, &n);
        SSF_ASSERT((r == SSF_NET_IO_SUCCESS) || (r == SSF_NET_IO_WANT_READ));
        _SSFMQTTCUTBrokerStep();
    }
    SSF_ASSERT(pos == 4u);
    SSF_ASSERT((pkt[0] == 0x20) && (pkt[1] == 0x02) && (pkt[3] == 0x00));   /* Accepted */

    /* Abnormal end: no DISCONNECT, so the broker publishes the will */
    t->close(t);
    SSFNetSockDeInit(&raw);
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while ((_utRxPublishCount == 0) && (_utEventCount == 0) && (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(_utEventCount == 0);
    SSF_ASSERT(_utRxPublishCount == 1);
    SSF_ASSERT(strcmp(_utRxTopic, topic) == 0);
    SSF_ASSERT(_utRx.payloadLen == sizeof(willMsg));
    SSF_ASSERT(memcmp(_utRxPayload, willMsg, sizeof(willMsg)) == 0);
    SSF_ASSERT(_utRx.retain == false);

    SSFMQTTCStop();
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while ((SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED) && (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSFMQTTCDeInit();
    SSFSMDeInit();
    SSFNetSockDeInit(&_utSock);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the broker round trip over plain TCP, then over WebSocket on the same TCP transport.    */
/* A WebSocket handshake failure looks like TRANSPORT_ERROR, so once TCP has reached the broker  */
/* the WebSocket leg may not be skipped.                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTBrokerEcho(void)
{
    bool isReached;

    SSFNetSockInit(&_utSock);
    isReached = _SSFMQTTCUTBrokerEchoOver(&_utSock.transport, SSF_MQTTC_UT_BROKER_PORT, "tcp",
                                          false);
    SSFNetSockDeInit(&_utSock);
    if (isReached) _SSFMQTTCUTBrokerWill();

    SSFNetSockInit(&_utSock);
    SSFNetWSInit(&_utBrokerWS, &_utSock.transport, SSF_MQTTC_UT_BROKER_WS_PATH, NULL, 0);
    (void)_SSFMQTTCUTBrokerEchoOver(&_utBrokerWS.transport, SSF_MQTTC_UT_BROKER_WS_PORT, "ws",
                                    isReached);
    SSFNetWSDeInit(&_utBrokerWS);
    SSFNetSockDeInit(&_utSock);
}
#endif /* SSF_CONFIG_MQTTC_UNIT_TEST_BROKER */

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfmqttc external interface.                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTCUnitTest(void)
{
    _SSFMQTTCUTConstruction();
    _SSFMQTTCUTScenarioHappyPath();
    _SSFMQTTCUTScenarioSlowTransport();
    _SSFMQTTCUTScenarioNoSubscriptions();
    _SSFMQTTCUTScenarioTxPublish();
    _SSFMQTTCUTScenarioTxPoolFull();
    _SSFMQTTCUTScenarioRxPublish();
    _SSFMQTTCUTScenarioRxDefer();
    _SSFMQTTCUTScenarioRxQueueFull();
    _SSFMQTTCUTScenarioConnAckRefused();
    _SSFMQTTCUTScenarioSubAckRefused();
    _SSFMQTTCUTScenarioSubAckDowngraded();
    _SSFMQTTCUTScenarioSubAckQoSExceeded();
    _SSFMQTTCUTScenarioSubAckMismatch();
    _SSFMQTTCUTScenarioProtocolErrors();
    _SSFMQTTCUTScenarioRxOverflow();
    _SSFMQTTCUTScenarioRxTooLarge();
    _SSFMQTTCUTScenarioRxTopicTooLong();
    _SSFMQTTCUTScenarioRxTooLargeMalformed();
    _SSFMQTTCUTScenarioRxTooLargeRetained();
    _SSFMQTTCUTScenarioRxPublishQoS2();
    _SSFMQTTCUTScenarioRxTooLargeLinkLoss();
    _SSFMQTTCUTScenarioRxDropBeforeConnAck();
    _SSFMQTTCUTScenarioKeepAliveTimeout();
    _SSFMQTTCUTScenarioKeepAliveAnswered();
    _SSFMQTTCUTScenarioKeepAliveUnsolicitedPingResp();
    _SSFMQTTCUTScenarioRxBackPressure();
    _SSFMQTTCUTScenarioRxHoldTimeout();
    _SSFMQTTCUTScenarioRxHoldKeepAlive();
    _SSFMQTTCUTScenarioRxPubAckOwed();
    _SSFMQTTCUTScenarioRxHoldLifetime();
    _SSFMQTTCUTScenarioRxHoldEdges();
    _SSFMQTTCUTScenarioPeerClosed();
    _SSFMQTTCUTScenarioConnectFailures();
    _SSFMQTTCUTScenarioSessionTimeouts();
    _SSFMQTTCUTScenarioSubRetry();
    _SSFMQTTCUTScenarioWill();
    _SSFMQTTCUTScenarioStopPaths();
    _SSFMQTTCUTScenarioGracefulClose();
#if SSF_CONFIG_MQTTC_UNIT_TEST_BROKER == 1
    _SSFMQTTCUTBrokerEcho();
#endif
}

#endif /* SSF_CONFIG_MQTTC_UNIT_TEST */
