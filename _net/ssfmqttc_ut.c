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
#if SSF_CONFIG_MQTTC_UNIT_TEST_BROKER == 1
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#endif
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfsm.h"
#include "ssfstr.h"
#include "ssfnet.h"
#include "ssfnetsock.h"
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
/* is not exercised: its interval is bounded below by SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT, which    */
/* is a compile-time value measured in tens of seconds.                                          */

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
    /* Observation */
    bool isOpening;
    bool isOpen;
    uint32_t openCount;
    uint32_t closeCount;
    char host[SSF_MQTTC_CONFIG_MAX_HOST_SIZE];
    uint16_t port;
    uint8_t tx[SSF_MQTTC_UT_MOCK_BUF_SIZE];
    size_t txLen;
    uint8_t rx[SSF_MQTTC_UT_MOCK_BUF_SIZE];
    size_t rxLen;
    size_t rxPos;
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
    size_t avail = m->rxLen - m->rxPos;

    SSF_REQUIRE(t == &_utMock.transport);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(gotOut != NULL);
    SSF_REQUIRE(m->isOpen);

    *gotOut = 0;
    if (avail == 0) return m->recvEmptyResult;
    if (avail > size) avail = size;
    memcpy(buf, &m->rx[m->rxPos], avail);
    m->rxPos += avail;
    *gotOut = avail;
    return SSF_NET_IO_SUCCESS;
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
    _utMock.transport.close = _SSFMQTTCUTMockClose;
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
/* Scenario scaffolding                                                                          */
/* --------------------------------------------------------------------------------------------- */
static const SSFMQTTCSub_t _utOneSub[] = { { "a/b", SSF_MQTTC_QOS_1 } };

/* --------------------------------------------------------------------------------------------- */
/* Fills opts for the mock: short timeouts, client id "ut", minimum keep-alive.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTOptsInit(SSFMQTTCOpts_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->host = "mock";
    opts->port = 1883;
    opts->clientId = "ut";
    opts->subsOpt = _utOneSub;
    opts->subCount = 1;
    opts->keepAliveSec = (uint16_t)((SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT * 4u) / SSF_TICKS_PER_SEC);
    opts->connectTimeout = SSF_MQTTC_UT_SHORT_TICKS;
    opts->subscribeTimeout = SSF_MQTTC_UT_SHORT_TICKS;
    opts->txPublishTimeout = SSF_MQTTC_UT_SHORT_TICKS;
    opts->reconnectMinWait = SSF_MQTTC_UT_BACKOFF_TICKS;
    opts->reconnectMaxWait = SSF_MQTTC_UT_BACKOFF_TICKS * 4;
}

/* --------------------------------------------------------------------------------------------- */
/* Creates a fresh state machine, mock and STOPPED client.                                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTBegin(uint32_t txBlocks)
{
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    _SSFMQTTCUTMockReset();
    _SSFMQTTCUTRecordReset();
    SSFMQTTCInit(&_utMock.transport, txBlocks, SSF_MQTTC_UT_TX_BLOCK_SIZE,
                 SSF_MQTTC_UT_RX_BLOCK_SIZE, _SSFMQTTCUTRxPublish, &_utRxPublishCtx,
                 _SSFMQTTCUTEvent, &_utEventCtx);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
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
                                 SSF_MQTTC_QOS_0, NULL, NULL) == false);

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
        bad = opts; bad.keepAliveSec = 1;                 SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.connectTimeout = 0;               SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.subscribeTimeout = 0;             SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.txPublishTimeout = 0;             SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.reconnectMinWait = 0;             SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
        bad = opts; bad.reconnectMaxWait = opts.reconnectMinWait - 1;
                                                          SSF_ASSERT_TEST(SSFMQTTCStart(&bad));
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
    static uint8_t ctx0;
    static uint8_t ctx1;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    /* Argument requires */
    SSF_ASSERT_TEST(SSFMQTTCTxPublish(NULL, (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, NULL, NULL));
    SSF_ASSERT_TEST(SSFMQTTCTxPublish("a/b", NULL, 2, SSF_MQTTC_QOS_0, NULL, NULL));
    SSF_ASSERT_TEST(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_2, NULL, NULL));
    SSF_ASSERT_TEST(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, NULL, &ctx0));

    /* Refusals that are not app errors */
    SSF_ASSERT(SSFMQTTCTxPublish("", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0, NULL, NULL) == false);
    {
        uint8_t big[SSF_MQTTC_UT_TX_BLOCK_SIZE];
        memset(big, 'x', sizeof(big));
        SSF_ASSERT(SSFMQTTCTxPublish("a/b", big, sizeof(big), SSF_MQTTC_QOS_0, NULL, NULL) == false);
    }

    /* QoS 0 completes when sent, from the pump, with its context */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_0,
                                 _SSFMQTTCUTTxDone, &ctx0));
    SSF_ASSERT(_utTxDoneCount == 0);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pub0));
    SSF_ASSERT(_utTxDoneCount == 1);
    SSF_ASSERT(_utTxDoneTrueCount == 1);
    SSF_ASSERT(_utTxDoneLastCtx == &ctx0);

    /* QoS 1 takes packet id 2 (SUBSCRIBE took 1) and completes on PUBACK */
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"hi", 2, SSF_MQTTC_QOS_1,
                                 _SSFMQTTCUTTxDone, &ctx1));
    _SSFMQTTCUTPump();
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(pub1));
    SSF_ASSERT(_utTxDoneCount == 1);
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(pubAck2));
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utTxDoneCount == 2);
    SSF_ASSERT(_utTxDoneTrueCount == 2);
    SSF_ASSERT(_utTxDoneLastCtx == &ctx1);

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
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"1", 1, SSF_MQTTC_QOS_0, _SSFMQTTCUTTxDone, NULL));
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"2", 1, SSF_MQTTC_QOS_0, _SSFMQTTCUTTxDone, NULL));
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"3", 1, SSF_MQTTC_QOS_0, _SSFMQTTCUTTxDone, NULL) == false);
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.txLen == 0);
    SSF_ASSERT(_utTxDoneCount == 0);

    _utMock.sendResult = SSF_NET_IO_SUCCESS;
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utMock.txLen == 2 * 8);             /* Two 8-byte QoS 0 publishes */
    SSF_ASSERT(_utTxDoneCount == 2);
    SSF_ASSERT(_utTxDoneTrueCount == 2);
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"3", 1, SSF_MQTTC_QOS_0, NULL, NULL));
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
    _SSFMQTTCUTPumpFor(SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(_utRxPublishCount == 3);             /* A re-offered and taken, then B */
    SSF_ASSERT(strcmp(_utRxTopic, "b") == 0);
    _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(ackA));
    SSF_ASSERT(_utEventCount == 0);
    _SSFMQTTCUTEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that an inbound PUBLISH beyond the queue depth is dropped, reported and acknowledged.   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxQueueFull(void)
{
    static const uint8_t in[] = { 0x32, 0x05, 0x00, 0x01, 'q', 0x00, 0x01 };
    static const SSFMQTTCUTEventRec_t dropped[] =
    { { SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_QUEUE_FULL } };
    uint8_t pkt[sizeof(in)];
    uint32_t i;
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);

    _utRxAccept = false;                            /* Head is deferred; queue fills behind it */
    memcpy(pkt, in, sizeof(pkt));
    for (i = 0; i < SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + 1; i++)
    {
        pkt[sizeof(pkt) - 1] = (uint8_t)(i + 1);    /* Distinct packet ids 1..depth+1 */
        _SSFMQTTCUTInject(pkt, sizeof(pkt));
    }
    _SSFMQTTCUTPump();
    SSF_ASSERT(_utRxPublishCount == 1);
    _SSFMQTTCUTExpectEvents(dropped, 1);
    pkt[0] = 0x40; pkt[1] = 0x02; pkt[2] = 0x00; pkt[3] = (uint8_t)(SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + 1);
    _SSFMQTTCUTExpectTx(pkt, 4);                    /* PUBACK for the dropped one only */

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

/* --------------------------------------------------------------------------------------------- */
/* Tests SUBACK failure code and QoS downgrade both ending the attempt.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioSubAckRefused(void)
{
    static const uint8_t subAckFail[] = { 0x90, 0x03, 0x00, 0x01, 0x80 };
    static const uint8_t subAckDown[] = { 0x90, 0x03, 0x00, 0x01, 0x00 };
    static const SSFMQTTCUTEventRec_t expected[] =
    {
        { SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE },
        { SSF_MQTTC_EVENT_CONNECT_FAILED, SSF_MQTTC_REASON_SUBSCRIBE_REFUSED },
    };
    const uint8_t *subAcks[2];
    uint32_t i;
    SSFMQTTCOpts_t opts;

    subAcks[0] = subAckFail;
    subAcks[1] = subAckDown;
    for (i = 0; i < 2; i++)
    {
        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        SSFMQTTCStart(&opts);
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktConnect));
        _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
        _SSFMQTTCUTPump();
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktSubscribe1));
        _SSFMQTTCUTInject(subAcks[i], sizeof(subAckFail));
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        _SSFMQTTCUTExpectTx(SSF_MQTTC_UT_ARRAY(_utPktDisconnect));   /* Session was up */
        _SSFMQTTCUTExpectEvents(expected, 2);
        _SSFMQTTCUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that broker protocol violations end a READY connection.                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioProtocolErrors(void)
{
    static const uint8_t qos2[] = { 0x34, 0x05, 0x00, 0x01, 'z', 0x00, 0x01 };
    static const uint8_t connAckAgain[] = { 0x20, 0x02, 0x00, 0x00 };
    static const uint8_t reserved[] = { 0xF0, 0x00 };
    static const SSFMQTTCUTEventRec_t expected[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_PROTOCOL } };
    const uint8_t *pkts[3];
    size_t lens[3];
    uint32_t i;
    SSFMQTTCOpts_t opts;

    pkts[0] = qos2;         lens[0] = sizeof(qos2);
    pkts[1] = connAckAgain; lens[1] = sizeof(connAckAgain);
    pkts[2] = reserved;     lens[2] = sizeof(reserved);
    for (i = 0; i < 3; i++)
    {
        _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
        _SSFMQTTCUTOptsInit(&opts);
        _SSFMQTTCUTGoReady(&opts);
        _SSFMQTTCUTInject(pkts[i], lens[i]);
        _SSFMQTTCUTPump();
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
        SSF_ASSERT(_utMock.closeCount == 1);
        _SSFMQTTCUTExpectEvents(expected, 1);
        _utMock.txLen = 0;                          /* DISCONNECT only when the pump found the link open */
        _SSFMQTTCUTEnd();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Tests that an inbound packet larger than the rx block ends the connection.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTScenarioRxOverflow(void)
{
    static const SSFMQTTCUTEventRec_t expected[] =
    { { SSF_MQTTC_EVENT_DISCONNECTED, SSF_MQTTC_REASON_RX_OVERFLOW } };
    uint8_t pkt[4];
    SSFMQTTCOpts_t opts;

    /* Remaining length larger than the rx block, known from the fixed header alone */
    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    pkt[0] = 0x30; pkt[1] = 0x80; pkt[2] = 0x02; pkt[3] = 0x00;   /* 256 bytes remaining */
    _SSFMQTTCUTInject(pkt, 3);
    _SSFMQTTCUTPump();
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(expected, 1);
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
    SSFMQTTCOpts_t opts;

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    SSFMQTTCStart(&opts);
    _SSFMQTTCUTPump();
    _SSFMQTTCUTInject(SSF_MQTTC_UT_ARRAY(_utPktConnAckOk));
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    _SSFMQTTCUTExpectEvents(subTimeout, 2);
    _SSFMQTTCUTEnd();

    _SSFMQTTCUTBegin(SSF_MQTTC_UT_TX_BLOCKS);
    _SSFMQTTCUTOptsInit(&opts);
    _SSFMQTTCUTGoReady(&opts);
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_1,
                                 _SSFMQTTCUTTxDone, NULL));
    _SSFMQTTCUTPumpFor(SSF_MQTTC_UT_SHORT_TICKS + SSF_MQTTC_UT_SLACK_TICKS);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_RECONNECT_WAIT);
    SSF_ASSERT(_utTxDoneCount == 1);
    SSF_ASSERT(_utTxDoneTrueCount == 0);            /* Completed false by the teardown */
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
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_1,
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
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_0, NULL, NULL) == false);
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
    SSF_ASSERT(SSFMQTTCTxPublish("a/b", (const uint8_t *)"x", 1, SSF_MQTTC_QOS_0,
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
/* Layer 3: round trip against a public broker over the real socket transport                    */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_MQTTC_UNIT_TEST_BROKER == 1
#define SSF_MQTTC_UT_BROKER_STEP_TICKS   (SSF_TICKS_PER_SEC * 20u)   /* Per phase */

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
/* Tests a QoS 1 publish echoed back by a public broker; skipped if unreachable.                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCUTBrokerEcho(void)
{
    static char clientId[32];
    static char topic[64];
    static char payload[48];
    static const SSFMQTTCSub_t subs[1] = { { topic, SSF_MQTTC_QOS_1 } };
    SSFMQTTCOpts_t opts;
    SSFPortTick_t end;
    SSFPortTick_t now = SSFPortGetTick64();

    (void)snprintf(clientId, sizeof(clientId), "ssf-ut-%08lx", (unsigned long)(now & 0xFFFFFFFFul));
    (void)snprintf(topic, sizeof(topic), "ssf/ut/%s/echo", clientId);
    (void)snprintf(payload, sizeof(payload), "echo %lu", (unsigned long)(now & 0xFFFFFFFFul));

    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    SSFNetSockInit(&_utSock);
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
        printf("ssfmqttc: %s unreachable (reason %d); broker round trip skipped\r\n",
               SSF_MQTTC_UT_BROKER_HOST, (int)reason);
        SSFMQTTCStop();
        end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
        while ((SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED) && (SSFPortGetTick64() < end))
        { _SSFMQTTCUTBrokerStep(); }
        SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
        SSFMQTTCDeInit();
        SSFNetSockDeInit(&_utSock);
        SSFSMDeInit();
        return;
    }
    SSF_ASSERT(_utEventCount == 2);
    SSF_ASSERT(_utEvents[0].event == SSF_MQTTC_EVENT_CONNECTED);
    SSF_ASSERT(_utEvents[1].event == SSF_MQTTC_EVENT_READY);
    _utEventCount = 0;

    /* Publish to the subscribed topic and wait for the completion and the echo */
    SSF_ASSERT(SSFMQTTCTxPublish(topic, (const uint8_t *)payload, strlen(payload),
                                 SSF_MQTTC_QOS_1, _SSFMQTTCUTTxDone, &_utTxDoneCount));
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

    /* Orderly stop */
    SSFMQTTCStop();
    end = SSFPortGetTick64() + SSF_MQTTC_UT_BROKER_STEP_TICKS;
    while ((SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED) && (SSFPortGetTick64() < end))
    { _SSFMQTTCUTBrokerStep(); }
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_utEventCount == 1);
    SSF_ASSERT(_utEvents[0].event == SSF_MQTTC_EVENT_STOPPED);

    SSFMQTTCDeInit();
    SSFNetSockDeInit(&_utSock);
    SSFSMDeInit();
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
    _SSFMQTTCUTScenarioProtocolErrors();
    _SSFMQTTCUTScenarioRxOverflow();
    _SSFMQTTCUTScenarioPeerClosed();
    _SSFMQTTCUTScenarioConnectFailures();
    _SSFMQTTCUTScenarioSessionTimeouts();
    _SSFMQTTCUTScenarioStopPaths();
#if SSF_CONFIG_MQTTC_UNIT_TEST_BROKER == 1
    _SSFMQTTCUTBrokerEcho();
#endif
}

#endif /* SSF_CONFIG_MQTTC_UNIT_TEST */
