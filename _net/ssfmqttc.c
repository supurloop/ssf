/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmqttc.c                                                                                    */
/* Provides a single threaded, non-blocking MQTT 3.1.1 client (QoS 0 and 1) for one connection.  */
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
#include "ssfll.h"
#include "ssfmpool.h"
#include "ssfsm.h"
#include "ssfstr.h"
#include "ssfnet.h"
#include "ssfmqttpkt.h"
#include "ssfmqttc.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MQTTC_INIT_MAGIC             (0x4d515443ul)   /* 'MQTC' */
#define SSF_MQTTC_PUBACK_SIZE            (4u)
#define SSF_MQTTC_DISCONNECT_SIZE        (2u)
#define SSF_MQTTC_CTL_PKT_SIZE           SSF_MQTTC_PUBACK_SIZE   /* Largest control packet       */
#define SSF_MQTTC_CTL_RESERVE            (2u)   /* ctl blocks PUBACK may not take: _SSFMQTTCCtlAlloc()   */
#define SSF_MQTTC_CTL_BLOCKS             (SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + \
                                          SSF_MQTTC_CTL_RESERVE)
#define SSF_MQTTC_RX_BLOCKS              (SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + \
                                          1u)   /* + the framing block */
#define SSF_MQTTC_MIN_BLOCK_SIZE         (4u)   /* Smallest packet worth a pool: CONNACK, PUBACK */
#define SSF_MQTTC_KEEPALIVE_DIV          (4u)   /* PINGREQ interval = keepAliveSec / this        */

/* --------------------------------------------------------------------------------------------- */
/* Typedefs                                                                                      */
/* --------------------------------------------------------------------------------------------- */
/* Header at the start of every pool block. Packet bytes follow immediately. */
/* Outbound block header: tx and ctl pools. Lives in txQueue and txInflight. The type           */
/* is fixed at allocation and selects the owning pool on free (see _SSFMQTTCTxBlockFree()).            */
typedef struct
{
    SSFLLItem_t item;                 /* Must be first                                         */
    SSFMQTTPktType_t type;
    SSFMQTTCQoS_t qos;                /* PUBLISH                                               */
    uint16_t packetId;                /* PUBLISH QoS 1, SUBSCRIBE, PUBACK                      */
    size_t len;                       /* Encoded packet length                                 */
    size_t sent;                      /* Bytes handed to the transport so far                  */
    bool isTxPublish;                 /* Originated from SSFMQTTCTxPublish()                   */
    SSFPortTick_t deadline;           /* txPublish: completion deadline                        */
    SSFMQTTCTxPublishFn_t txFn;       /* txPublish: completion callback                        */
    void *txFnCtx;
} SSFMQTTCTxBlock_t;

/* Inbound block header: rx pool. The framing block and rxQueue entries.                       */
typedef struct
{
    SSFLLItem_t item;                 /* Must be first                                         */
    SSFMQTTCQoS_t qos;
    uint16_t packetId;
    uint16_t topicLen;
    size_t payloadLen;
    bool retain;
    bool dup;
    uint32_t offerCount;
    SSFPortTick_t firstOffer;         /* Tick of first offer to the app; 0 => not yet offered  */
    SSFPortTick_t lastOffer;          /* Tick of the most recent deferred offer                */
} SSFMQTTCRxBlock_t;

/* Inbound PUBLISH larger than the rx block, consumed as it arrives and dropped. Only the fields */
/* needed to validate and acknowledge it are captured. left == 0 => not skipping.                */
typedef struct
{
    size_t left;                      /* Packet bytes still to consume                         */
    size_t pos;                       /* Packet offset of the next byte to consume             */
    size_t tlOff;                     /* Offset of the topic length (fixed header length)        */
    uint16_t topicLen;
    uint16_t packetId;                /* QoS 1 only                                            */
    SSFMQTTCQoS_t qos;
    bool isTopicNul;                  /* Topic holds U+0000: malformed (MQTT-1.5.3-2)          */
} SSFMQTTCRxSkip_t;

#define SSF_MQTTC_TX_DATA(b) (((uint8_t *)(b)) + sizeof(SSFMQTTCTxBlock_t))
#define SSF_MQTTC_RX_DATA(b) (((uint8_t *)(b)) + sizeof(SSFMQTTCRxBlock_t))

typedef enum
{
    SSF_MQTTC_LINK_CLOSED,
    SSF_MQTTC_LINK_OPENING,
    SSF_MQTTC_LINK_OPEN,
    SSF_MQTTC_LINK_SHUTTING_DOWN,     /* STOPPING: DISCONNECT accepted, shutdown() delivering it  */
    SSF_MQTTC_LINK_SHUT_DOWN          /* shutdown() done; TX_DRAINED posted, close() follows      */
} SSFMQTTCLink_t;

/* Event payloads posted by the pump. Each must fit in sizeof(void *) or ssfsm heap-allocates.  */
typedef struct { uint8_t code; uint8_t sessionPresent; } SSFMQTTCEvConnAck_t;
typedef struct { uint16_t packetId; uint8_t count; uint8_t verdict; } SSFMQTTCEvSubAck_t;

/* SSFMQTTCEvSubAck_t verdict, worst over all filters; a higher value takes precedence. */
#define SSF_MQTTC_SUBACK_EXACT          (0u)   /* Every filter granted at the requested QoS    */
#define SSF_MQTTC_SUBACK_DOWNGRADED     (1u)   /* A filter granted a lower QoS                 */
#define SSF_MQTTC_SUBACK_REFUSED        (2u)   /* A filter returned the failure code           */
#define SSF_MQTTC_SUBACK_QOS_EXCEEDED   (3u)   /* A filter granted a higher QoS: broker error  */
typedef struct { uint16_t packetId; } SSFMQTTCEvPubAck_t;

typedef struct
{
    /* Fixed at init */
    SSFNetTransport_t *transport;
    uint32_t txBlockSize;             /* Packet bytes per tx block                             */
    uint32_t rxBlockSize;             /* Packet bytes per rx block                             */
    SSFMPool_t txPool;
    SSFMPool_t rxPool;
    SSFMPool_t ctlPool;
    SSFMQTTCRxPublishFn_t rxPublishFn;
    void *rxPublishFnCtx;
    SSFMQTTCEventFn_t eventFn;
    void *eventFnCtx;
    SSFMQTTCRxBlock_t *rxFrame;       /* Reserved framing block                                */

    /* Per run */
    SSFMQTTCOpts_t opts;              /* Pointer fields remain app owned                       */
    bool isStarted;                   /* Between Start() and Stop(); gates both synchronously  */
    SSFPortTick_t backoff;            /* Current reconnect wait; 0 => start at min             */
    uint16_t nextPacketId;            /* Last id issued; 0 at init so the first is 1. Not reset  */
                                      /* on reconnect: clean session makes that unnecessary    */

    /* Per connection */
    uint16_t subscribePacketId;
    bool isPingPending;               /* PINGREQ queued or sent, PINGRESP not yet received     */
    bool isSubDowngraded;             /* SUBACK granted a filter a lower QoS than requested    */

    /* Pump owned */
    SSFMQTTCLink_t link;              /* Transport state; closed by the pump on fatal error    */
    size_t rxLen;                     /* Bytes in rxFrame                                      */
    SSFMQTTCRxSkip_t rxSkip;          /* Oversized inbound PUBLISH being dropped               */

    /* Queues of SSFMQTTCTxBlock_t (tx*) and SSFMQTTCRxBlock_t (rxQueue) */
    SSFLL_t txQueue;                  /* Waiting for the transport                             */
    SSFLL_t txInflight;               /* QoS 1 PUBLISH / SUBSCRIBE awaiting acknowledgement    */
    SSFLL_t rxQueue;                  /* Inbound PUBLISH awaiting the app                      */

    SSFMQTTCState_t state;
    uint32_t magic;
} SSFMQTTC_t;

/* --------------------------------------------------------------------------------------------- */
/* Module variables                                                                              */
/* --------------------------------------------------------------------------------------------- */
static SSFMQTTC_t _mqttc;

/* --------------------------------------------------------------------------------------------- */
/* Local prototypes                                                                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCStateStopped(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler);
static void _SSFMQTTCStateConnecting(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                             SSFVoidFn_t *superHandler);
static void _SSFMQTTCSuperStateSession(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler);
static void _SSFMQTTCStateSubscribing(SSFSMEventId_t eid, const SSFSMData_t *data,
                              SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);
static void _SSFMQTTCStateReady(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                        SSFVoidFn_t *superHandler);
static void _SSFMQTTCStateReconnectWait(SSFSMEventId_t eid, const SSFSMData_t *data,
                                SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);
static void _SSFMQTTCStateStopping(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                           SSFVoidFn_t *superHandler);

/* --------------------------------------------------------------------------------------------- */
/* Helpers: app notification                                                                     */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Reports an event and reason to the app if an event callback is installed.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCReport(SSFMQTTCEvent_t event, SSFMQTTCReason_t reason)
{
    SSF_REQUIRE((event > SSF_MQTTC_EVENT_MIN) && (event < SSF_MQTTC_EVENT_MAX));
    SSF_REQUIRE((reason > SSF_MQTTC_REASON_MIN) && (reason < SSF_MQTTC_REASON_MAX));

    if (_mqttc.eventFn != NULL) _mqttc.eventFn(_mqttc.eventFnCtx, event, reason);
}

/* --------------------------------------------------------------------------------------------- */
/* Closes the transport on a fatal link error and posts LINK_FAIL to the state machine.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCLinkFail(SSFMQTTCReason_t reason)
{
    uint8_t r = (uint8_t)reason;

    SSF_REQUIRE((reason > SSF_MQTTC_REASON_MIN) && (reason < SSF_MQTTC_REASON_MAX));

    if (_mqttc.link != SSF_MQTTC_LINK_CLOSED) _mqttc.transport->close(_mqttc.transport);
    _mqttc.link = SSF_MQTTC_LINK_CLOSED;
    SSFSMPutEventData(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_LINK_FAIL, &r, sizeof(r));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if CONNACK has been accepted on the current transport, else false.               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCIsSessionUp(void)
{
    return (_mqttc.state == SSF_MQTTC_STATE_SUBSCRIBING) ||
           (_mqttc.state == SSF_MQTTC_STATE_CONNECTED) ||
           (_mqttc.state == SSF_MQTTC_STATE_STOPPING);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a block from pool with its header zeroed, or NULL if the pool is empty.               */
/* --------------------------------------------------------------------------------------------- */
static void *_SSFMQTTCPoolAlloc(SSFMPool_t *pool, size_t hdrLen)
{
    void *b;

    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(hdrLen > 0);

    if (SSFMPoolIsEmpty(pool)) return NULL;
    b = SSFMPoolAlloc(pool, SSFMPoolBlockSize(pool), 0);
    memset(b, 0, hdrLen);
    return b;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if type lives in the ctl pool (PINGREQ, DISCONNECT, PUBACK), else false.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCIsCtlType(SSFMQTTPktType_t type)
{
    return (type == SSF_MQTT_PKT_PINGREQ) || (type == SSF_MQTT_PKT_DISCONNECT) ||
           (type == SSF_MQTT_PKT_PUBACK);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a tx pool block with type set, or NULL if the pool is empty.                          */
/* --------------------------------------------------------------------------------------------- */
static SSFMQTTCTxBlock_t *_SSFMQTTCTxBlockAlloc(SSFMQTTPktType_t type)
{
    SSFMQTTCTxBlock_t *b;

    SSF_REQUIRE(_SSFMQTTCIsCtlType(type) == false);
    b = (SSFMQTTCTxBlock_t *)_SSFMQTTCPoolAlloc(&_mqttc.txPool, sizeof(SSFMQTTCTxBlock_t));
    if (b != NULL) b->type = type;
    return b;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a tx or ctl block to the pool its type belongs to.                                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCTxBlockFree(SSFMQTTCTxBlock_t *b)
{
    SSF_REQUIRE(b != NULL);
    SSFMPoolFree(_SSFMQTTCIsCtlType(b->type) ? &_mqttc.ctlPool : &_mqttc.txPool, b);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns an rx pool block, or NULL if the pool is empty.                                       */
/* --------------------------------------------------------------------------------------------- */
static SSFMQTTCRxBlock_t *_SSFMQTTCRxBlockAlloc(void)
{
    return (SSFMQTTCRxBlock_t *)_SSFMQTTCPoolAlloc(&_mqttc.rxPool, sizeof(SSFMQTTCRxBlock_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a block to the rx pool.                                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxBlockFree(SSFMQTTCRxBlock_t *b)
{
    SSF_REQUIRE(b != NULL);
    SSFMPoolFree(&_mqttc.rxPool, b);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a ctl pool block with type set, or NULL if none is free or the reserve is reached.    */
/* --------------------------------------------------------------------------------------------- */
static SSFMQTTCTxBlock_t *_SSFMQTTCCtlAlloc(SSFMQTTPktType_t type, bool isReserved)
{
    SSFMQTTCTxBlock_t *b;

    SSF_REQUIRE(_SSFMQTTCIsCtlType(type));
    if ((isReserved == false) && (SSFMPoolLen(&_mqttc.ctlPool) <= SSF_MQTTC_CTL_RESERVE)) return NULL;
    b = (SSFMQTTCTxBlock_t *)_SSFMQTTCPoolAlloc(&_mqttc.ctlPool, sizeof(SSFMQTTCTxBlock_t));
    if (b != NULL) b->type = type;
    return b;
}

/* --------------------------------------------------------------------------------------------- */
/* Frees every rx block in ll.                                                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxFreeList(SSFLL_t *ll)
{
    SSFMQTTCRxBlock_t *b;

    SSF_REQUIRE(ll != NULL);

    while (SSF_LL_FIFO_POP(ll, &b)) _SSFMQTTCRxBlockFree(b);
}

/* --------------------------------------------------------------------------------------------- */
/* Helpers: outbound                                                                             */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Returns the next non-zero packet id.                                                          */
/* --------------------------------------------------------------------------------------------- */
static uint16_t _SSFMQTTCNextPacketId(void)
{
    _mqttc.nextPacketId++;
    if (_mqttc.nextPacketId == 0) _mqttc.nextPacketId = 1;
    return _mqttc.nextPacketId;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the PINGREQ interval in ticks.                                                        */
/* --------------------------------------------------------------------------------------------- */
static SSFPortTick_t _SSFMQTTCKeepAliveTicks(void)
{
    return (((SSFPortTick_t)_mqttc.opts.keepAliveSec) * SSF_TICKS_PER_SEC) /
           SSF_MQTTC_KEEPALIVE_DIV;
}

/* SSF_LL_FIFO_PUSH asserts on a NULL block at the call site, so no wrapper function is needed. */
#define _SSFMQTTCTxEnqueue(b) SSF_LL_FIFO_PUSH(&_mqttc.txQueue, (b))

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a packet of type is waiting in the tx queue, else false.                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCIsTxQueued(SSFMQTTPktType_t type)
{
    SSFLLItem_t *item;

    for (item = SSF_LL_HEAD(&_mqttc.txQueue); item != NULL; item = SSF_LL_NEXT_ITEM(item))
    { if (((SSFMQTTCTxBlock_t *)item)->type == type) return true; }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Queues a PINGREQ or DISCONNECT; the ctl reserve guarantees a block for each.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCTxEnqueueSimple(SSFMQTTPktType_t type)
{
    SSFMQTTCTxBlock_t *b;

    SSF_REQUIRE((type == SSF_MQTT_PKT_PINGREQ) || (type == SSF_MQTT_PKT_DISCONNECT));
    /* At most one of each is ever queued: PINGREQ by isPingPending, which only a PINGRESP after */
    /* the PINGREQ was sent clears, DISCONNECT by STOPPING being entered once. The reserve holds */
    /* exactly those two.                                                                        */
    SSF_ASSERT(_SSFMQTTCIsTxQueued(type) == false);
    b = _SSFMQTTCCtlAlloc(type, true);
    SSF_ASSERT(b != NULL);
    if (type == SSF_MQTT_PKT_PINGREQ)
    { SSFMQTTPktEncodePingReq(SSF_MQTTC_TX_DATA(b), SSF_MQTTC_CTL_PKT_SIZE, &b->len); }
    else SSFMQTTPktEncodeDisconnect(SSF_MQTTC_TX_DATA(b), SSF_MQTTC_CTL_PKT_SIZE, &b->len);
    _SSFMQTTCTxEnqueue(b);
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a PUBACK into an allocated ctl block and queues it.                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCTxEnqueuePubAckBlock(SSFMQTTCTxBlock_t *b, uint16_t packetId)
{
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(packetId != 0);

    SSFMQTTPktEncodePubAck(SSF_MQTTC_TX_DATA(b), SSF_MQTTC_CTL_PKT_SIZE, &b->len, packetId);
    b->packetId = packetId;
    _SSFMQTTCTxEnqueue(b);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a PUBACK was queued, else false if no ctl block is available.                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCTxEnqueuePubAck(uint16_t packetId)
{
    SSFMQTTCTxBlock_t *b;

    SSF_REQUIRE(packetId != 0);

    b = _SSFMQTTCCtlAlloc(SSF_MQTT_PKT_PUBACK, false);
    if (b == NULL) return false;
    _SSFMQTTCTxEnqueuePubAckBlock(b, packetId);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Completes every txPublish in ll with isPublished and frees all its blocks.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCTxCompleteList(SSFLL_t *ll, bool isPublished)
{
    SSFMQTTCTxBlock_t *b;

    SSF_REQUIRE(ll != NULL);

    while (SSF_LL_FIFO_POP(ll, &b))
    {
        if (b->isTxPublish && (b->txFn != NULL)) b->txFn(b->txFnCtx, isPublished);
        _SSFMQTTCTxBlockFree(b);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if any txPublish is outstanding, with minOut its earliest deadline, else false.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCTxPublishMinDeadline(SSFPortTick_t *minOut)
{
    SSFLL_t *lists[2];
    SSFLLItem_t *item;
    SSFMQTTCTxBlock_t *b;
    bool found = false;
    uint32_t i;

    SSF_REQUIRE(minOut != NULL);

    lists[0] = &_mqttc.txQueue;
    lists[1] = &_mqttc.txInflight;
    for (i = 0; i < 2; i++)
    {
        for (item = SSF_LL_HEAD(lists[i]); item != NULL; item = SSF_LL_NEXT_ITEM(item))
        {
            b = (SSFMQTTCTxBlock_t *)item;
            if (b->isTxPublish == false) continue;
            if ((found == false) || (b->deadline < *minOut)) { *minOut = b->deadline; found = true; }
        }
    }
    return found;
}

/* --------------------------------------------------------------------------------------------- */
/* Arms the READY deadline timer for the earliest outstanding txPublish or a full timeout.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCTxPublishArmTimer(void)
{
    SSFPortTick_t min;
    SSFPortTick_t now = SSFPortGetTick64();

    if (_SSFMQTTCTxPublishMinDeadline(&min))
    { SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_TX_PUBLISH, (min > now) ? (min - now) : 1); }
    else SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_TX_PUBLISH, _mqttc.opts.txPublishTimeout);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the in-flight block was found, freed and its callback returned, else false.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCTxInflightRemove(SSFMQTTPktType_t type, uint16_t packetId,
                              SSFMQTTCTxPublishFn_t *fnOut, void **fnCtxOut)
{
    SSFLLItem_t *item;

    SSF_REQUIRE(fnOut != NULL);
    SSF_REQUIRE(fnCtxOut != NULL);

    for (item = SSF_LL_HEAD(&_mqttc.txInflight); item != NULL; item = SSF_LL_NEXT_ITEM(item))
    {
        SSFMQTTCTxBlock_t *b = (SSFMQTTCTxBlock_t *)item;
        if ((b->type == type) && (b->packetId == packetId))
        {
            SSF_LL_GET(&_mqttc.txInflight, &b, b);
            *fnOut = b->txFn;
            *fnCtxOut = b->txFnCtx;
            _SSFMQTTCTxBlockFree(b);
            return true;
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Helpers: inbound framing                                                                      */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Empties the inbound framing buffer.                                                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxFrameReset(void)
{
    _mqttc.rxLen = 0;
    memset(&_mqttc.rxSkip, 0, sizeof(_mqttc.rxSkip));
}

/* --------------------------------------------------------------------------------------------- */
/* Removes the first pktLen bytes from the inbound framing buffer.                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxFrameConsume(size_t pktLen)
{
    uint8_t *frame = SSF_MQTTC_RX_DATA(_mqttc.rxFrame);

    SSF_REQUIRE(pktLen <= _mqttc.rxLen);
    _mqttc.rxLen -= pktLen;
    if (_mqttc.rxLen > 0) memmove(frame, frame + pktLen, _mqttc.rxLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Drops an inbound PUBLISH: acknowledges QoS 1 if a control block is free so the broker window  */
/* moves on, then reports the drop. Before CONNACK nothing is acknowledged: a PUBLISH there is a */
/* broker error, and a PUBACK could otherwise reach the wire ahead of CONNECT.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxPublishDrop(SSFMQTTCQoS_t qos, uint16_t packetId, SSFMQTTCReason_t reason)
{
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (qos == SSF_MQTTC_QOS_1));
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (packetId != 0));

    if ((qos == SSF_MQTTC_QOS_1) && _SSFMQTTCIsSessionUp())
    { (void)_SSFMQTTCTxEnqueuePubAck(packetId); }
    _SSFMQTTCReport(SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, reason);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the inbound PUBLISH was queued or dropped, else false if the link failed.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxPublishQueue(const uint8_t *pkt, size_t pktLen)
{
    SSFMQTTPktPublish_t pub;
    SSFMQTTCRxBlock_t *b;
    uint8_t *d;

    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);

    if ((SSFMQTTPktDecodePublish(pkt, pktLen, &pub) == false) || (pub.qos >= SSF_MQTTC_QOS_2))
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }
    if (pub.topicLen >= SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE)
    {
        _SSFMQTTCRxPublishDrop(pub.qos, pub.packetId, SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG);
        return true;
    }

    /* The rx pool holds exactly the framing block plus the queue depth, so an empty pool is   */
    /* the queue-full condition.                                                                */
    if ((b = _SSFMQTTCRxBlockAlloc()) == NULL)
    {
        _SSFMQTTCRxPublishDrop(pub.qos, pub.packetId, SSF_MQTTC_REASON_RX_PUBLISH_QUEUE_FULL);
        return true;
    }

    /* Normalize to [topic][NUL][payload]. Always fits: the wire form also carried a fixed      */
    /* header and a 2-byte topic length.                                                        */
    d = SSF_MQTTC_RX_DATA(b);
    memcpy(d, pub.topic, pub.topicLen);
    d[pub.topicLen] = 0;
    if (pub.payloadLen > 0) memcpy(d + pub.topicLen + 1, pub.payload, pub.payloadLen);
    b->qos = pub.qos;
    b->packetId = pub.packetId;
    b->topicLen = pub.topicLen;
    b->payloadLen = pub.payloadLen;
    b->retain = pub.retain;
    b->dup = pub.dup;
    SSF_LL_FIFO_PUSH(&_mqttc.rxQueue, b);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the control packet was decoded and posted, else false if the link failed.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxControlPost(const uint8_t *pkt, size_t pktLen)
{
    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);

    switch (SSF_MQTT_PKT_TYPE(pkt[0]))
    {
    case SSF_MQTT_PKT_CONNACK:
    {
        SSFMQTTCEvConnAck_t ev;
        bool sessionPresent;

        if (SSFMQTTPktDecodeConnAck(pkt, pktLen, &sessionPresent, &ev.code) == false) break;
        ev.sessionPresent = sessionPresent ? 1u : 0u;
        SSFSMPutEventData(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_RX_CONNACK, (SSFSMData_t *)&ev,
                          sizeof(ev));
        return true;
    }
    case SSF_MQTT_PKT_SUBACK:
    {
        SSFMQTTCEvSubAck_t ev;
        uint8_t codes[SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS];
        uint32_t count;
        uint32_t i;
        uint8_t verdict;

        if (SSFMQTTPktDecodeSubAck(pkt, pktLen, &ev.packetId, codes, sizeof(codes), &count) == false)
        { break; }
        /* The declared set is immutable while not STOPPED, so the codes can be compared here  */
        /* and only the verdict travels in the payload. The decoder admits only 0..2 and 0x80. */
        ev.count = (uint8_t)count;
        ev.verdict = SSF_MQTTC_SUBACK_EXACT;
        for (i = 0; (i < count) && (i < _mqttc.opts.subCount); i++)
        {
            if (codes[i] == SSF_MQTT_PKT_SUBACK_FAILURE) verdict = SSF_MQTTC_SUBACK_REFUSED;
            else if (codes[i] > (uint8_t)_mqttc.opts.subsOpt[i].qos)
            { verdict = SSF_MQTTC_SUBACK_QOS_EXCEEDED; }
            else if (codes[i] < (uint8_t)_mqttc.opts.subsOpt[i].qos)
            { verdict = SSF_MQTTC_SUBACK_DOWNGRADED; }
            else verdict = SSF_MQTTC_SUBACK_EXACT;
            if (verdict > ev.verdict) ev.verdict = verdict;
        }
        SSFSMPutEventData(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_RX_SUBACK, (SSFSMData_t *)&ev,
                          sizeof(ev));
        return true;
    }
    case SSF_MQTT_PKT_PUBACK:
    {
        SSFMQTTCEvPubAck_t ev;

        if (SSFMQTTPktDecodePubAck(pkt, pktLen, &ev.packetId) == false) break;
        SSFSMPutEventData(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_RX_PUBACK, (SSFSMData_t *)&ev,
                          sizeof(ev));
        return true;
    }
    case SSF_MQTT_PKT_PINGRESP:
        SSFSMPutEvent(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_RX_PINGRESP);
        return true;
    default:
        break;      /* Client-only types, QoS 2 flow, reserved: never valid from a broker */
    }
    _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a skip of the oversized PUBLISH at the start of the framing buffer began,     */
/* else false if its fixed header flags are malformed or QoS 2 and the link failed.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxSkipStart(const uint8_t *frame, size_t pktLen)
{
    SSFMQTTCRxSkip_t *s = &_mqttc.rxSkip;
    uint8_t qosBits;
    size_t hdrLen = 2;

    SSF_REQUIRE(frame != NULL);
    SSF_REQUIRE(pktLen > _mqttc.rxBlockSize);
    SSF_REQUIRE(SSF_MQTT_PKT_TYPE(frame[0]) == SSF_MQTT_PKT_PUBLISH);

    /* The same flag rules as SSFMQTTPktDecodePublish(), which cannot see this packet whole */
    qosBits = (uint8_t)((frame[0] & 0x06u) >> 1);
    if ((qosBits >= (uint8_t)SSF_MQTTC_QOS_2) ||
        ((qosBits == (uint8_t)SSF_MQTTC_QOS_0) && ((frame[0] & 0x08u) != 0)))
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }

    /* SSFMQTTPktFrame() returned a length, so the whole fixed header is in the buffer and its */
    /* length bytes end at the first one without the continuation bit.                         */
    while ((frame[hdrLen - 1] & 0x80u) != 0) hdrLen++;
    SSF_ASSERT(hdrLen <= SSF_MQTT_PKT_MAX_FIXED_HDR_LEN);

    memset(s, 0, sizeof(*s));
    s->left = pktLen;
    s->tlOff = hdrLen;
    s->qos = (SSFMQTTCQoS_t)qosBits;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Captures the bytes of the big endian 16-bit field at packet offset at that lie in the n bytes */
/* at p, which start at packet offset _mqttc.rxSkip.pos.                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxSkipTakeU16(const uint8_t *p, size_t n, size_t at, uint16_t *v)
{
    size_t pos = _mqttc.rxSkip.pos;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(v != NULL);

    if ((at >= pos) && ((at - pos) < n))
    { *v = (uint16_t)((*v & 0x00FFu) | ((uint16_t)p[at - pos] << 8)); }
    if (((at + 1) >= pos) && ((at + 1 - pos) < n))
    { *v = (uint16_t)((*v & 0xFF00u) | p[at + 1 - pos]); }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the skipped PUBLISH was well formed and has been dropped, else false if it    */
/* was malformed and the link failed.                                                            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxSkipFinish(void)
{
    SSFMQTTCRxSkip_t *s = &_mqttc.rxSkip;
    size_t need;

    SSF_REQUIRE(s->left == 0);

    /* pos is now the packet length. Checks match SSFMQTTPktDecodePublish() (neither checks     */
    /* UTF-8).                                                                                  */
    need = s->tlOff + 2u + s->topicLen + ((s->qos == SSF_MQTTC_QOS_1) ? 2u : 0u);
    if ((s->topicLen == 0) || (need > s->pos) || s->isTopicNul ||
        ((s->qos == SSF_MQTTC_QOS_1) && (s->packetId == 0)))
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }

    _SSFMQTTCRxPublishDrop(s->qos, s->packetId, SSF_MQTTC_REASON_RX_PUBLISH_TOO_LARGE);
    memset(s, 0, sizeof(*s));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the skip consumed what the framing buffer holds of it, else false if the      */
/* skipped packet was malformed and the link failed.                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxSkipConsume(void)
{
    SSFMQTTCRxSkip_t *s = &_mqttc.rxSkip;
    const uint8_t *frame = SSF_MQTTC_RX_DATA(_mqttc.rxFrame);
    size_t n;

    SSF_REQUIRE(s->left > 0);

    n = (_mqttc.rxLen < s->left) ? _mqttc.rxLen : s->left;
    _SSFMQTTCRxSkipTakeU16(frame, n, s->tlOff, &s->topicLen);
    /* Topic and packet id offsets are final once both topic length bytes have been seen */
    if ((s->pos + n) >= (s->tlOff + 2u))
    {
        size_t lo = s->tlOff + 2u;              /* Topic bytes within this chunk: [lo, hi) */
        size_t hi = lo + s->topicLen;

        if (lo < s->pos) lo = s->pos;
        if (hi > (s->pos + n)) hi = s->pos + n;
        if ((lo < hi) && (memchr(&frame[lo - s->pos], 0, hi - lo) != NULL)) s->isTopicNul = true;
        if (s->qos == SSF_MQTTC_QOS_1)
        { _SSFMQTTCRxSkipTakeU16(frame, n, s->tlOff + 2u + s->topicLen, &s->packetId); }
    }
    s->pos += n;
    s->left -= n;
    _SSFMQTTCRxFrameConsume(n);
    if (s->left == 0) return _SSFMQTTCRxSkipFinish();
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if every complete inbound packet was dispatched, else false if the link failed.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxFrameProcess(void)
{
    uint8_t *frame = SSF_MQTTC_RX_DATA(_mqttc.rxFrame);
    size_t pktLen;
    SSFMQTTPktFrame_t fr;
    bool ok;

    while (_mqttc.rxLen > 0)
    {
        /* An oversized PUBLISH is consumed before anything after it is framed */
        if (_mqttc.rxSkip.left > 0)
        {
            if (_SSFMQTTCRxSkipConsume() == false) return false;
            continue;
        }

        fr = SSFMQTTPktFrame(frame, _mqttc.rxLen, &pktLen);
        if (fr == SSF_MQTT_PKT_FRAME_MALFORMED)
        { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }
        if ((pktLen != 0) && (pktLen > _mqttc.rxBlockSize))
        {
            /* A PUBLISH that cannot fit is dropped as it arrives; the fixed header gives its   */
            /* length, so the stream stays in sync. Any other packet that cannot fit is fatal.  */
            if (SSF_MQTT_PKT_TYPE(frame[0]) != SSF_MQTT_PKT_PUBLISH)
            { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_RX_OVERFLOW); return false; }
            if (_SSFMQTTCRxSkipStart(frame, pktLen) == false) return false;
            continue;
        }
        if (fr == SSF_MQTT_PKT_FRAME_INCOMPLETE) return true;

        if (SSF_MQTT_PKT_TYPE(frame[0]) == SSF_MQTT_PKT_PUBLISH) ok = _SSFMQTTCRxPublishQueue(frame, pktLen);
        else ok = _SSFMQTTCRxControlPost(frame, pktLen);
        if (ok == false) return false;
        _SSFMQTTCRxFrameConsume(pktLen);
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Sends a best effort DISCONNECT if requested, then closes the transport.                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCTransportClose(bool sendDisconnect)
{
    if ((_mqttc.link == SSF_MQTTC_LINK_OPEN) && sendDisconnect)
    {
        SSFMQTTCTxBlock_t *head = (SSFMQTTCTxBlock_t *)SSF_LL_TAIL(&_mqttc.txQueue);
        if ((head == NULL) || (head->sent == 0))
        {
            uint8_t pkt[SSF_MQTTC_DISCONNECT_SIZE];
            size_t len;
            size_t sent;
            SSFMQTTPktEncodeDisconnect(pkt, sizeof(pkt), &len);
            (void)_mqttc.transport->send(_mqttc.transport, pkt, len, &sent);
        }
    }
    if (_mqttc.link != SSF_MQTTC_LINK_CLOSED) _mqttc.transport->close(_mqttc.transport);
    _mqttc.link = SSF_MQTTC_LINK_CLOSED;
}

/* --------------------------------------------------------------------------------------------- */
/* Closes the transport, completes pending txPublish callbacks false and empties the queues.     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCConnectionTeardown(bool sendDisconnect)
{
    _SSFMQTTCTransportClose(sendDisconnect);
    _SSFMQTTCTxCompleteList(&_mqttc.txQueue, false);
    _SSFMQTTCTxCompleteList(&_mqttc.txInflight, false);
    _SSFMQTTCRxFreeList(&_mqttc.rxQueue);
    _SSFMQTTCRxFrameReset();
}

/* --------------------------------------------------------------------------------------------- */
/* Tears down the connection, reports the failure and transitions to RECONNECT_WAIT.             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCFail(SSFMQTTCReason_t reason)
{
    SSFMQTTCEvent_t event = (_mqttc.state == SSF_MQTTC_STATE_CONNECTED) ?
                            SSF_MQTTC_EVENT_DISCONNECTED : SSF_MQTTC_EVENT_CONNECT_FAILED;

    SSF_REQUIRE((reason > SSF_MQTTC_REASON_MIN) && (reason < SSF_MQTTC_REASON_MAX));

    _SSFMQTTCConnectionTeardown(_SSFMQTTCIsSessionUp());
    _SSFMQTTCReport(event, reason);
    SSFSMTran(_SSFMQTTCStateReconnectWait);
}

/* --------------------------------------------------------------------------------------------- */
/* Lowers *nextTimeoutOpt to ticks if it is larger.                                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCNextTimeoutLower(SSFPortTick_t *nextTimeoutOpt, SSFPortTick_t ticks)
{
    if ((nextTimeoutOpt != NULL) && (*nextTimeoutOpt > ticks)) *nextTimeoutOpt = ticks;
}

/* --------------------------------------------------------------------------------------------- */
/* Offers queued inbound PUBLISH packets to the app while the client state allows delivery.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxPublishService(SSFPortTick_t *nextTimeoutOpt)
{
    SSFMQTTCRxBlock_t *b;
    SSFMQTTCTxBlock_t *ack;
    SSFMQTTCRxPublish_t rx;
    SSFPortTick_t now;

    if ((_mqttc.state != SSF_MQTTC_STATE_SUBSCRIBING) &&
        (_mqttc.state != SSF_MQTTC_STATE_CONNECTED)) return;

    while ((b = (SSFMQTTCRxBlock_t *)SSF_LL_TAIL(&_mqttc.rxQueue)) != NULL)
    {
        now = SSFPortGetTick64();
        if (b->firstOffer != 0)
        {
            if ((now - b->firstOffer) >= SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS)
            {
                SSF_LL_FIFO_POP(&_mqttc.rxQueue, &b);
                if (b->qos == SSF_MQTTC_QOS_1) (void)_SSFMQTTCTxEnqueuePubAck(b->packetId);
                _SSFMQTTCRxBlockFree(b);
                _SSFMQTTCReport(SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, SSF_MQTTC_REASON_RX_PUBLISH_TIMEOUT);
                continue;
            }
            if ((now - b->lastOffer) < SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS)
            {
                _SSFMQTTCNextTimeoutLower(nextTimeoutOpt,
                                  SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS - (now - b->lastOffer));
                return;
            }
        }

        ack = NULL;
        if ((b->qos == SSF_MQTTC_QOS_1) && ((ack = _SSFMQTTCCtlAlloc(SSF_MQTT_PKT_PUBACK, false)) == NULL))
        {
            _SSFMQTTCNextTimeoutLower(nextTimeoutOpt, SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS);
            return;
        }

        if (b->firstOffer == 0) b->firstOffer = (now == 0) ? 1 : now;
        b->offerCount++;
        rx.topic = (SSFCStrIn_t)SSF_MQTTC_RX_DATA(b);
        rx.topicLen = b->topicLen;
        rx.payload = SSF_MQTTC_RX_DATA(b) + b->topicLen + 1;
        rx.payloadLen = b->payloadLen;
        rx.qos = b->qos;
        rx.retain = b->retain;
        rx.dup = b->dup;
        rx.offerCount = b->offerCount;
        if (_mqttc.rxPublishFn(_mqttc.rxPublishFnCtx, &rx) == false)
        {
            if (ack != NULL) _SSFMQTTCTxBlockFree(ack);
            b->lastOffer = now;
            _SSFMQTTCNextTimeoutLower(nextTimeoutOpt, SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS);
            return;
        }
        SSF_LL_FIFO_POP(&_mqttc.rxQueue, &b);
        if (ack != NULL) _SSFMQTTCTxEnqueuePubAckBlock(ack, b->packetId);
        _SSFMQTTCRxBlockFree(b);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the next reconnect wait, doubling from the minimum to the maximum.                    */
/* --------------------------------------------------------------------------------------------- */
static SSFPortTick_t _SSFMQTTCNextBackoff(void)
{
    SSFPortTick_t wait;

    if (_mqttc.backoff == 0) wait = _mqttc.opts.reconnectMinWait;
    else wait = _mqttc.backoff << 1;
    if ((wait > _mqttc.opts.reconnectMaxWait) || (wait < _mqttc.backoff))
    { wait = _mqttc.opts.reconnectMaxWait; }
    _mqttc.backoff = wait;
    return wait;
}

/* --------------------------------------------------------------------------------------------- */
/* Handles state machine events in STOPPED.                                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCStateStopped(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler)
{
    SSF_REQUIRE((eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(superHandler != NULL);

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        _mqttc.state = SSF_MQTTC_STATE_STOPPED;
        /* Silent at init: SSFMQTTCInit() enters this state before installing the callback. */
        _SSFMQTTCReport(SSF_MQTTC_EVENT_STOPPED, SSF_MQTTC_REASON_NONE);
        break;
    case SSF_SM_EVENT_MQTTC_START:
        _mqttc.backoff = 0;
        SSFSMTran(_SSFMQTTCStateConnecting);
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Handles state machine events in CONNECTING.                                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCStateConnecting(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                             SSFVoidFn_t *superHandler)
{
    SSF_REQUIRE((eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(superHandler != NULL);

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        _mqttc.state = SSF_MQTTC_STATE_CONNECTING;
        SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_CONNECT, _mqttc.opts.connectTimeout);
        if (_mqttc.transport->open(_mqttc.transport, _mqttc.opts.host,
                                   SSF_MQTTC_CONFIG_MAX_HOST_SIZE, _mqttc.opts.port))
        { _mqttc.link = SSF_MQTTC_LINK_OPENING; }
        else _SSFMQTTCLinkFail(SSF_MQTTC_REASON_TRANSPORT_ERROR);   /* Cannot Tran from ENTRY */
        break;

    case SSF_SM_EVENT_MQTTC_TRANSPORT_OPEN:
    {
        SSFMQTTCTxBlock_t *b = _SSFMQTTCTxBlockAlloc(SSF_MQTT_PKT_CONNECT);

        SSF_ASSERT(b != NULL);  /* Nothing else holds tx blocks before CONNACK */
        /* Asserts if CONNECT is larger than txBlockSize: a configuration error */
        SSFMQTTPktEncodeConnect(SSF_MQTTC_TX_DATA(b), _mqttc.txBlockSize, &b->len,
                                _mqttc.opts.clientId, SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE,
                                _mqttc.opts.usernameOpt, SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE,
                                _mqttc.opts.passwordOpt, _mqttc.opts.passwordLen,
                                _mqttc.opts.keepAliveSec);
        _SSFMQTTCTxEnqueue(b);
        break;
    }

    case SSF_SM_EVENT_MQTTC_RX_CONNACK:
    {
        SSFMQTTCEvConnAck_t ev;

        SSF_SM_EVENT_DATA_ALIGN(ev);
        if ((ev.code == 0) && ev.sessionPresent)   /* Session Present must be 0: clean session */
        { _SSFMQTTCFail(SSF_MQTTC_REASON_PROTOCOL); break; }

        switch (ev.code)
        {
        case 0:
            SSFSMTran((_mqttc.opts.subCount == 0) ? _SSFMQTTCStateReady : _SSFMQTTCStateSubscribing);
            break;
        case 1:  _SSFMQTTCFail(SSF_MQTTC_REASON_CONNACK_PROTOCOL_VERSION); break;
        case 2:  _SSFMQTTCFail(SSF_MQTTC_REASON_CONNACK_CLIENT_ID); break;
        case 3:  _SSFMQTTCFail(SSF_MQTTC_REASON_CONNACK_SERVER_UNAVAILABLE); break;
        case 4:  _SSFMQTTCFail(SSF_MQTTC_REASON_CONNACK_BAD_CREDENTIALS); break;
        case 5:  _SSFMQTTCFail(SSF_MQTTC_REASON_CONNACK_NOT_AUTHORIZED); break;
        default: _SSFMQTTCFail(SSF_MQTTC_REASON_CONNACK_UNKNOWN); break;
        }
        break;
    }

    case SSF_SM_EVENT_MQTTC_RX_SUBACK:
    case SSF_SM_EVENT_MQTTC_RX_PUBACK:
    case SSF_SM_EVENT_MQTTC_RX_PINGRESP:
        _SSFMQTTCFail(SSF_MQTTC_REASON_PROTOCOL);        /* Nothing but CONNACK may precede CONNACK */
        break;

    case SSF_SM_EVENT_MQTTC_TO_CONNECT:
        _SSFMQTTCFail(SSF_MQTTC_REASON_CONNECT_TIMEOUT);
        break;

    case SSF_SM_EVENT_MQTTC_LINK_FAIL:
    {
        uint8_t r;
        SSF_SM_EVENT_DATA_ALIGN(r);
        _SSFMQTTCFail((SSFMQTTCReason_t)r);
        break;
    }

    case SSF_SM_EVENT_MQTTC_STOP:
        _SSFMQTTCConnectionTeardown(false);
        SSFSMTran(_SSFMQTTCStateStopped);
        break;

    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Queues one SUBSCRIBE for the configured subscription set & arms timeout.                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCSessionSubscribe(void)
{
    SSFMQTTCTxBlock_t *b;

    b = _SSFMQTTCTxBlockAlloc(SSF_MQTT_PKT_SUBSCRIBE);
    SSF_ASSERT(b != NULL);      /* Only CONNECT took a tx block and it has been sent */
    _mqttc.subscribePacketId = _SSFMQTTCNextPacketId();
    /* Asserts if SUBSCRIBE is larger than txBlockSize: a configuration error */
    SSFMQTTPktEncodeSubscribe(SSF_MQTTC_TX_DATA(b), _mqttc.txBlockSize, &b->len,
                              _mqttc.subscribePacketId, _mqttc.opts.subsOpt, _mqttc.opts.subCount,
                              SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE);
    b->packetId = _mqttc.subscribePacketId;
    _SSFMQTTCTxEnqueue(b);
    SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_SUBSCRIBE, _mqttc.opts.subscribeTimeout);
}

/* --------------------------------------------------------------------------------------------- */
/* Acts on a decoded SUBACK: READY if every filter was granted, at the requested or a lower QoS, */
/* else fails the attempt.                                                                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCSessionRxSubAck(const SSFMQTTCEvSubAck_t *ev)
{
    SSFMQTTCTxPublishFn_t fn;
    void *fnCtx;

    SSF_REQUIRE(ev != NULL);

    if ((ev->packetId != _mqttc.subscribePacketId) || (ev->count != _mqttc.opts.subCount))
    { _SSFMQTTCFail(SSF_MQTTC_REASON_PROTOCOL); return; }

    (void)_SSFMQTTCTxInflightRemove(SSF_MQTT_PKT_SUBSCRIBE, ev->packetId, &fn, &fnCtx);
    SSFSMStopTimer(SSF_SM_EVENT_MQTTC_TO_SUBSCRIBE);
    if (ev->verdict == SSF_MQTTC_SUBACK_QOS_EXCEEDED)
    { _SSFMQTTCFail(SSF_MQTTC_REASON_SUBSCRIBE_QOS_EXCEEDED); return; }
    if (ev->verdict == SSF_MQTTC_SUBACK_REFUSED)
    { _SSFMQTTCFail(SSF_MQTTC_REASON_SUBSCRIBE_REFUSED); return; }
    _mqttc.isSubDowngraded = (ev->verdict == SSF_MQTTC_SUBACK_DOWNGRADED);
    SSFSMTran(_SSFMQTTCStateReady);
}

/* --------------------------------------------------------------------------------------------- */
/* Acts on a decoded PUBACK: completes the matching in-flight txPublish.                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCSessionRxPubAck(const SSFMQTTCEvPubAck_t *ev)
{
    SSFMQTTCTxPublishFn_t fn;
    void *fnCtx;

    SSF_REQUIRE(ev != NULL);

    if (_SSFMQTTCTxInflightRemove(SSF_MQTT_PKT_PUBLISH, ev->packetId, &fn, &fnCtx) && (fn != NULL))
    { fn(fnCtx, true); }
}

/* --------------------------------------------------------------------------------------------- */
/* Handles state machine events common to SUBSCRIBING and CONNECTED.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCSuperStateSession(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler)
{
    SSF_REQUIRE((eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(superHandler != NULL);

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        _mqttc.state = SSF_MQTTC_STATE_SUBSCRIBING;   /* Substate ENTRY follows and may change it */
        _mqttc.isPingPending = false;
        _mqttc.isSubDowngraded = false;
        SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_KEEPALIVE, _SSFMQTTCKeepAliveTicks());
        _SSFMQTTCReport(SSF_MQTTC_EVENT_CONNECTED, SSF_MQTTC_REASON_NONE);
        break;

    case SSF_SM_EVENT_EXIT:
        break;        /* ssfsm cancels this state's timers */

    case SSF_SM_EVENT_MQTTC_RX_PUBACK:
    {
        SSFMQTTCEvPubAck_t ev;
        SSF_SM_EVENT_DATA_ALIGN(ev);
        _SSFMQTTCSessionRxPubAck(&ev);
        break;
    }

    case SSF_SM_EVENT_MQTTC_RX_PINGRESP:
        /* Only an answer to a PINGREQ already sent counts. One arriving while ours is unsent  */
        /* (or with none pending) is ignored, so a stalled send still times out and the ping   */
        /* stays pending, which keeps a second PINGREQ out of the queue.                       */
        if (_mqttc.isPingPending && (_SSFMQTTCIsTxQueued(SSF_MQTT_PKT_PINGREQ) == false))
        {
            _mqttc.isPingPending = false;
            SSFSMStopTimer(SSF_SM_EVENT_MQTTC_TO_PINGRESP);
        }
        break;

    case SSF_SM_EVENT_MQTTC_RX_CONNACK:          /* CONNACK twice */
    case SSF_SM_EVENT_MQTTC_RX_SUBACK:           /* SUBACK outside SUBSCRIBING */
        _SSFMQTTCFail(SSF_MQTTC_REASON_PROTOCOL);
        break;

    case SSF_SM_EVENT_MQTTC_TO_KEEPALIVE:
        /* An unanswered PINGREQ, queued or already sent, has its PINGRESP timer running; it    */
        /* will fail the connection or be answered. Queue another only when none is pending:    */
        /* restarting that timer would cancel its deadline, and when this interval and the      */
        /* timeout fall due on the same tick (the default 120 s / 30 s) it would never fire.    */
        if (_mqttc.isPingPending == false)
        {
            _SSFMQTTCTxEnqueueSimple(SSF_MQTT_PKT_PINGREQ);
            _mqttc.isPingPending = true;
            SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_PINGRESP, SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT);
        }
        SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_KEEPALIVE, _SSFMQTTCKeepAliveTicks());
        break;

    case SSF_SM_EVENT_MQTTC_TO_PINGRESP:
        _SSFMQTTCFail(SSF_MQTTC_REASON_KEEPALIVE);
        break;

    case SSF_SM_EVENT_MQTTC_LINK_FAIL:
    {
        uint8_t r;
        SSF_SM_EVENT_DATA_ALIGN(r);
        _SSFMQTTCFail((SSFMQTTCReason_t)r);
        break;
    }

    case SSF_SM_EVENT_MQTTC_STOP:
        SSFSMTran(_SSFMQTTCStateStopping);
        break;

    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Handles state machine events in SUBSCRIBING, substate of SESSION.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCStateSubscribing(SSFSMEventId_t eid, const SSFSMData_t *data,
                              SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    SSF_REQUIRE((eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(superHandler != NULL);

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        _mqttc.state = SSF_MQTTC_STATE_SUBSCRIBING;
        _SSFMQTTCSessionSubscribe();
        break;

    case SSF_SM_EVENT_EXIT:
        break;        /* ssfsm cancels the subscribe timer */

    case SSF_SM_EVENT_MQTTC_RX_SUBACK:
    {
        SSFMQTTCEvSubAck_t ev;
        SSF_SM_EVENT_DATA_ALIGN(ev);
        _SSFMQTTCSessionRxSubAck(&ev);
        break;
    }

    case SSF_SM_EVENT_MQTTC_TO_SUBSCRIBE:
        _SSFMQTTCFail(SSF_MQTTC_REASON_SUBSCRIBE_TIMEOUT);
        break;

    default:
        SSF_SM_SUPER(_SSFMQTTCSuperStateSession);
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Handles state machine events in CONNECTED (READY), substate of SESSION.                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCStateReady(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                        SSFVoidFn_t *superHandler)
{
    SSF_REQUIRE((eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(superHandler != NULL);

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        _mqttc.state = SSF_MQTTC_STATE_CONNECTED;
        _mqttc.backoff = 0;
        _SSFMQTTCTxPublishArmTimer();
        _SSFMQTTCReport(SSF_MQTTC_EVENT_READY, _mqttc.isSubDowngraded ?
                        SSF_MQTTC_REASON_SUBSCRIBE_DOWNGRADED : SSF_MQTTC_REASON_NONE);
        break;

    case SSF_SM_EVENT_EXIT:
        break;        /* ssfsm cancels the txPublish timer */

    case SSF_SM_EVENT_MQTTC_TO_TX_PUBLISH:
    {
        SSFPortTick_t min;
        if (_SSFMQTTCTxPublishMinDeadline(&min) && (min <= SSFPortGetTick64()))
        { _SSFMQTTCFail(SSF_MQTTC_REASON_TX_PUBLISH_TIMEOUT); break; }
        _SSFMQTTCTxPublishArmTimer();
        break;
    }

    default:
        SSF_SM_SUPER(_SSFMQTTCSuperStateSession);
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Handles state machine events in RECONNECT_WAIT.                                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCStateReconnectWait(SSFSMEventId_t eid, const SSFSMData_t *data,
                                SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    SSF_REQUIRE((eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(superHandler != NULL);

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        _mqttc.state = SSF_MQTTC_STATE_RECONNECT_WAIT;
        SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_RECONNECT, _SSFMQTTCNextBackoff());
        break;

    case SSF_SM_EVENT_MQTTC_TO_RECONNECT:
        SSFSMTran(_SSFMQTTCStateConnecting);
        break;

    case SSF_SM_EVENT_MQTTC_STOP:
        SSFSMTran(_SSFMQTTCStateStopped);
        break;

    default:
        break;        /* Stale pump events from the torn-down connection */
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Handles state machine events in STOPPING.                                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCStateStopping(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                           SSFVoidFn_t *superHandler)
{
    SSF_REQUIRE((eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(superHandler != NULL);

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        _mqttc.state = SSF_MQTTC_STATE_STOPPING;
        /* Flush the queue with DISCONNECT appended; the pump posts TX_DRAINED when it empties.  */
        /* Nothing can refill the queue in this state, so exactly one TX_DRAINED is ever posted. */
        _SSFMQTTCTxEnqueueSimple(SSF_MQTT_PKT_DISCONNECT);
        SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_STOP, _mqttc.opts.txPublishTimeout);
        break;

    case SSF_SM_EVENT_MQTTC_TX_DRAINED:
        _SSFMQTTCConnectionTeardown(false);   /* DISCONNECT delivered (send(), then shutdown()) */
        SSFSMTran(_SSFMQTTCStateStopped);
        break;

    case SSF_SM_EVENT_MQTTC_TO_STOP:
    case SSF_SM_EVENT_MQTTC_LINK_FAIL:
        _SSFMQTTCConnectionTeardown(true);
        SSFSMTran(_SSFMQTTCStateStopped);
        break;

    default:
        break;        /* Inbound packets and drops no longer matter */
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes the MQTT client; SSFSMInit() must have been called.                               */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTCInit(SSFNetTransport_t *transport, uint32_t txBlocks, uint32_t txBlockSize,
                  uint32_t rxBlockSize, SSFMQTTCRxPublishFn_t rxPublishFn,
                  void *rxPublishFnCtxOpt, SSFMQTTCEventFn_t eventFnOpt, void *eventFnCtxOpt)
{
    SSF_REQUIRE(_mqttc.magic != SSF_MQTTC_INIT_MAGIC);
    SSF_REQUIRE(transport != NULL);
    SSF_REQUIRE(transport->open != NULL);
    SSF_REQUIRE(transport->pollOpen != NULL);
    SSF_REQUIRE(transport->send != NULL);
    SSF_REQUIRE(transport->recv != NULL);
    SSF_REQUIRE(transport->shutdown != NULL);
    SSF_REQUIRE(transport->close != NULL);
    SSF_REQUIRE(txBlocks >= 1);
    SSF_REQUIRE(txBlockSize >= SSF_MQTTC_MIN_BLOCK_SIZE);
    SSF_REQUIRE(rxBlockSize >= SSF_MQTTC_MIN_BLOCK_SIZE);
    SSF_REQUIRE(rxPublishFn != NULL);
    SSF_REQUIRE((eventFnOpt != NULL) || (eventFnCtxOpt == NULL));   /* Context needs a callback */

    memset(&_mqttc, 0, sizeof(_mqttc));
    _mqttc.transport = transport;
    _mqttc.txBlockSize = txBlockSize;
    _mqttc.rxBlockSize = rxBlockSize;
    _mqttc.rxPublishFn = rxPublishFn;
    _mqttc.rxPublishFnCtx = rxPublishFnCtxOpt;

    SSFMPoolInit(&_mqttc.txPool, txBlocks, txBlockSize + (uint32_t)sizeof(SSFMQTTCTxBlock_t));
    SSFMPoolInit(&_mqttc.rxPool, SSF_MQTTC_RX_BLOCKS,
                 rxBlockSize + (uint32_t)sizeof(SSFMQTTCRxBlock_t));
    SSFMPoolInit(&_mqttc.ctlPool, SSF_MQTTC_CTL_BLOCKS,
                 SSF_MQTTC_CTL_PKT_SIZE + (uint32_t)sizeof(SSFMQTTCTxBlock_t));
    SSFLLInit(&_mqttc.txQueue, txBlocks + SSF_MQTTC_CTL_BLOCKS);   /* tx and ctl blocks */
    SSFLLInit(&_mqttc.txInflight, txBlocks);
    SSFLLInit(&_mqttc.rxQueue, SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH);

    _mqttc.rxFrame = _SSFMQTTCRxBlockAlloc();
    SSF_ASSERT(_mqttc.rxFrame != NULL);

    _mqttc.magic = SSF_MQTTC_INIT_MAGIC;
    SSFSMInitHandler(SSF_SM_MQTTC, _SSFMQTTCStateStopped);   /* Enters STOPPED */

    /* Installed after the initial state is entered so that entry does not report STOPPED. Every */
    /* later STOPPED entry follows a Stop() and is reported.                                      */
    _mqttc.eventFn = eventFnOpt;
    _mqttc.eventFnCtx = eventFnCtxOpt;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes the MQTT client; only valid in STOPPED.                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTCDeInit(void)
{
    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    SSF_REQUIRE(_mqttc.state == SSF_MQTTC_STATE_STOPPED);
    SSF_REQUIRE(_mqttc.isStarted == false);

    SSFSMDeInitHandler(SSF_SM_MQTTC);
    _SSFMQTTCRxBlockFree(_mqttc.rxFrame);
    SSFLLDeInit(&_mqttc.rxQueue);
    SSFLLDeInit(&_mqttc.txInflight);
    SSFLLDeInit(&_mqttc.txQueue);
    SSFMPoolDeInit(&_mqttc.ctlPool);   /* Each asserts every block was returned */
    SSFMPoolDeInit(&_mqttc.rxPool);
    SSFMPoolDeInit(&_mqttc.txPool);
    memset(&_mqttc, 0, sizeof(_mqttc));
}

/* --------------------------------------------------------------------------------------------- */
/* Starts the client; only valid in STOPPED.                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTCStart(const SSFMQTTCOpts_t *opts)
{
    size_t len;
    uint32_t i;

    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    SSF_REQUIRE(_mqttc.state == SSF_MQTTC_STATE_STOPPED);
    SSF_REQUIRE(_mqttc.isStarted == false);
    SSF_REQUIRE(opts != NULL);
    SSF_REQUIRE(opts->host != NULL);
    SSF_REQUIRE(SSFStrLen(opts->host, SSF_MQTTC_CONFIG_MAX_HOST_SIZE, &len) && (len > 0));
    SSF_REQUIRE(opts->port != 0);
    SSF_REQUIRE(opts->clientId != NULL);
    SSF_REQUIRE(SSFStrLen(opts->clientId, SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE, &len) &&
                (len > 0));
    SSF_REQUIRE((opts->subsOpt != NULL) || (opts->subCount == 0));
    SSF_REQUIRE(opts->subCount <= SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS);
    for (i = 0; i < opts->subCount; i++)
    {
        SSF_REQUIRE((opts->subsOpt[i].qos == SSF_MQTTC_QOS_0) ||
                    (opts->subsOpt[i].qos == SSF_MQTTC_QOS_1));
        SSF_REQUIRE(SSFMQTTPktIsValidFilter(opts->subsOpt[i].filter,
                                            SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE));
    }
    SSF_REQUIRE((opts->usernameOpt == NULL) ||
                SSFStrLen(opts->usernameOpt, SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE, &len));
    SSF_REQUIRE((opts->passwordOpt == NULL) || (opts->usernameOpt != NULL));
    SSF_REQUIRE(((opts->passwordOpt == NULL) && (opts->passwordLen == 0)) ||
                ((opts->passwordOpt != NULL) &&
                 (opts->passwordLen <= SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN)));
    SSF_REQUIRE((((SSFPortTick_t)opts->keepAliveSec) * SSF_TICKS_PER_SEC) >=
                (SSF_MQTTC_KEEPALIVE_DIV * (SSFPortTick_t)SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT));
    SSF_REQUIRE(opts->connectTimeout > 0);
    SSF_REQUIRE(opts->subscribeTimeout > 0);
    SSF_REQUIRE(opts->txPublishTimeout > 0);
    SSF_REQUIRE(opts->reconnectMinWait > 0);
    SSF_REQUIRE(opts->reconnectMaxWait >= opts->reconnectMinWait);

    memcpy(&_mqttc.opts, opts, sizeof(_mqttc.opts));

    _mqttc.isStarted = true;
    SSFSMPutEvent(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_START);
}

/* --------------------------------------------------------------------------------------------- */
/* Stops the client; valid exactly once per Start().                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTCStop(void)
{
    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    SSF_REQUIRE(_mqttc.isStarted);

    _mqttc.isStarted = false;
    SSFSMPutEvent(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_STOP);
}

/* --------------------------------------------------------------------------------------------- */
/* Advances shutdown() while STOPPING: posts TX_DRAINED once every accepted byte, DISCONNECT     */
/* included, is delivered; a failure is LINK_FAIL. WANT_* waits, bounded by the stop timer.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCShutdownPoll(void)
{
    SSFNetIOResult_t r;

    SSF_REQUIRE(_mqttc.link == SSF_MQTTC_LINK_SHUTTING_DOWN);

    r = _mqttc.transport->shutdown(_mqttc.transport);
    if (r == SSF_NET_IO_SUCCESS)
    {
        _mqttc.link = SSF_MQTTC_LINK_SHUT_DOWN;
        SSFSMPutEvent(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_TX_DRAINED);
    }
    else if ((r != SSF_NET_IO_WANT_WRITE) && (r != SSF_NET_IO_WANT_READ))
    {
        _SSFMQTTCLinkFail((r == SSF_NET_IO_CLOSED) ? SSF_MQTTC_REASON_PEER_CLOSED :
                                                 SSF_MQTTC_REASON_TRANSPORT_ERROR);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if more transport work is immediately available, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTCTask(SSFPortTick_t *nextTimeoutOpt)
{
    bool more = false;
    SSFNetTransport_t *t;

    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    t = _mqttc.transport;

    /* Graceful end, resumed: deliver the accepted DISCONNECT before close() */
    if (_mqttc.link == SSF_MQTTC_LINK_SHUTTING_DOWN) { _SSFMQTTCShutdownPoll(); goto done; }

    /* Transport opening */
    if (_mqttc.link == SSF_MQTTC_LINK_OPENING)
    {
        switch (t->pollOpen(t))
        {
        case SSF_NET_IO_SUCCESS:
            _mqttc.link = SSF_MQTTC_LINK_OPEN;
            SSFSMPutEvent(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_TRANSPORT_OPEN);
            break;
        case SSF_NET_IO_WANT_READ:
        case SSF_NET_IO_WANT_WRITE:
            /* No socket to wait on yet, so ask to be called again soon */
            _SSFMQTTCNextTimeoutLower(nextTimeoutOpt, SSF_MQTTC_CONFIG_OPEN_POLL_TICKS);
            break;
        default:
            _SSFMQTTCLinkFail(SSF_MQTTC_REASON_TRANSPORT_ERROR);
            break;
        }
    }
    if (_mqttc.link != SSF_MQTTC_LINK_OPEN) goto done;

    /* Send */
    for (;;)
    {
        SSFMQTTCTxBlock_t *b = (SSFMQTTCTxBlock_t *)SSF_LL_TAIL(&_mqttc.txQueue);
        size_t sent = 0;
        SSFNetIOResult_t r;

        if (b == NULL) break;
        r = t->send(t, SSF_MQTTC_TX_DATA(b) + b->sent, b->len - b->sent, &sent);
        if (r == SSF_NET_IO_WANT_WRITE) break;
        if (r != SSF_NET_IO_SUCCESS)
        {
            _SSFMQTTCLinkFail((r == SSF_NET_IO_CLOSED) ? SSF_MQTTC_REASON_PEER_CLOSED :
                                                     SSF_MQTTC_REASON_TRANSPORT_ERROR);
            goto done;
        }
        b->sent += sent;
        if (b->sent < b->len) { more = true; break; }   /* Partial; try again next call */

        SSF_LL_FIFO_POP(&_mqttc.txQueue, &b);
        b->sent = 0;
        if ((b->type == SSF_MQTT_PKT_SUBSCRIBE) ||
            ((b->type == SSF_MQTT_PKT_PUBLISH) && (b->qos == SSF_MQTTC_QOS_1)))
        { SSF_LL_FIFO_PUSH(&_mqttc.txInflight, b); }
        else if (b->type == SSF_MQTT_PKT_PUBLISH)
        {
            /* QoS 0: sent is published. Complete here; nothing is left for the state machine. */
            SSFMQTTCTxPublishFn_t fn = b->txFn;
            void *fnCtx = b->txFnCtx;
            _SSFMQTTCTxBlockFree(b);
            if (fn != NULL) fn(fnCtx, true);
        }
        else _SSFMQTTCTxBlockFree(b);
        /* The one list change the state machine must act on: STOPPING ends when the flush is   */
        /* complete. The queue empties exactly once in that state; the DISCONNECT that ends it   */
        /* may still be buffered in the transport (TLS), so shutdown() delivers it and then      */
        /* posts TX_DRAINED, at most once.                                                       */
        if (SSFLLIsEmpty(&_mqttc.txQueue) && (_mqttc.state == SSF_MQTTC_STATE_STOPPING))
        {
            _mqttc.link = SSF_MQTTC_LINK_SHUTTING_DOWN;
            _SSFMQTTCShutdownPoll();
            goto done;
        }
    }

    /* Receive */
    for (;;)
    {
        uint8_t *frame = SSF_MQTTC_RX_DATA(_mqttc.rxFrame);
        size_t space;
        size_t got = 0;
        SSFNetIOResult_t r;

        if (_SSFMQTTCRxFrameProcess() == false) break;
        space = _mqttc.rxBlockSize - _mqttc.rxLen;
        if (space == 0) { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_RX_OVERFLOW); break; }
        r = t->recv(t, frame + _mqttc.rxLen, space, &got);
        if (r == SSF_NET_IO_WANT_READ) break;
        if (r == SSF_NET_IO_CLOSED) { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PEER_CLOSED); break; }
        if (r != SSF_NET_IO_SUCCESS) { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_TRANSPORT_ERROR); break; }
        if (got == 0) break;
        _mqttc.rxLen += got;
    }

done:
    _SSFMQTTCRxPublishService(nextTimeoutOpt);
    if (more && (nextTimeoutOpt != NULL)) *nextTimeoutOpt = 0;
    return more;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the PUBLISH was queued, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTCTxPublish(SSFCStrIn_t topic, const uint8_t *payload, size_t payloadLen,
                       SSFMQTTCQoS_t qos, SSFMQTTCTxPublishFn_t txPublishFnOpt,
                       void *txPublishFnCtxOpt)
{
    SSFMQTTCTxBlock_t *b;
    size_t topicLen;
    size_t pktLen;

    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    SSF_REQUIRE(topic != NULL);
    SSF_REQUIRE((payload != NULL) || (payloadLen == 0));
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (qos == SSF_MQTTC_QOS_1));
    SSF_REQUIRE((txPublishFnOpt != NULL) || (txPublishFnCtxOpt == NULL)); /* Context needs a callback */

    if (_mqttc.state != SSF_MQTTC_STATE_CONNECTED) return false;
    if (SSFMQTTPktIsValidTopic(topic, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE) == false) return false;
    (void)SSFStrLen(topic, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, &topicLen);   /* Valid above */
    pktLen = SSFMQTTPktPublishLen(topicLen, payloadLen, qos);
    if ((pktLen == 0) || (pktLen > _mqttc.txBlockSize)) return false;   /* Too large for a block */
    if ((b = _SSFMQTTCTxBlockAlloc(SSF_MQTT_PKT_PUBLISH)) == NULL) return false;

    b->packetId = (qos == SSF_MQTTC_QOS_1) ? _SSFMQTTCNextPacketId() : 0;
    SSFMQTTPktEncodePublish(SSF_MQTTC_TX_DATA(b), _mqttc.txBlockSize, &b->len, topic,
                            SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, payload, payloadLen, qos,
                            b->packetId);

    b->qos = qos;
    b->isTxPublish = true;
    b->txFn = txPublishFnOpt;
    b->txFnCtx = txPublishFnCtxOpt;
    b->deadline = SSFPortGetTick64() + _mqttc.opts.txPublishTimeout;
    _SSFMQTTCTxEnqueue(b);    /* The READY deadline timer is always running and will see this block */
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the client state.                                                                     */
/* --------------------------------------------------------------------------------------------- */
SSFMQTTCState_t SSFMQTTCGetState(void)
{
    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    return _mqttc.state;
}
