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
#include <stddef.h>
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
#define SSF_MQTTC_CTL_PKT_SIZE           SSF_MQTTC_PUBACK_SIZE   /* Largest control packet */
#define SSF_MQTTC_CTL_RESERVE            (2u)   /* ctl blocks PUBACK may not take: _SSFMQTTCCtlAlloc() */
#define SSF_MQTTC_CTL_BLOCKS             (SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + \
                                          SSF_MQTTC_CTL_RESERVE)
#define SSF_MQTTC_RX_BLOCKS              (SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + \
                                          1u)   /* + the framing block */
#define SSF_MQTTC_MIN_BLOCK_SIZE         (4u)   /* Smallest packet worth a pool: CONNACK, PUBACK */
#define SSF_MQTTC_KEEPALIVE_DIV          (4u)   /* PINGREQ interval = keepAliveSec / this */

/* --------------------------------------------------------------------------------------------- */
/* Typedefs                                                                                      */
/* --------------------------------------------------------------------------------------------- */
/* Outbound block header for the tx and ctl pools; packet bytes follow it */
typedef struct
{
    SSFLLItem_t item;                 /* Must be first */
    SSFMQTTPktType_t type;
    SSFMQTTCQoS_t qos;                /* PUBLISH */
    uint16_t packetId;                /* PUBLISH QoS 1, SUBSCRIBE, PUBACK */
    size_t len;                       /* Encoded packet length */
    size_t sent;                      /* Bytes handed to the transport so far */
    bool isTxPublish;                 /* Originated from SSFMQTTCTxPublish() */
    SSFPortTick_t deadline;           /* txPublish: completion deadline */
    SSFMQTTCTxPublishFn_t txFn;       /* txPublish: completion callback */
    void *txFnCtx;
} SSFMQTTCTxBlock_t;

/* Inbound block header for the rx pool; packet bytes follow it */
typedef struct
{
    SSFLLItem_t item;                 /* Must be first */
    SSFMQTTCQoS_t qos;
    uint16_t packetId;
    uint16_t topicLen;
    size_t payloadLen;
    bool retain;
    bool dup;
    uint32_t offerCount;
    SSFPortTick_t firstOffer;         /* Tick of first offer to the app; 0 => not yet offered */
    SSFPortTick_t lastOffer;          /* Tick of the most recent deferred offer */
} SSFMQTTCRxBlock_t;

/* Converts a queued item, the first member of its aligned pool block, back to its block */
#define _SSFMQTTCTxBlockOf(itm) ((SSFMQTTCTxBlock_t *)(void *)(itm))
#define _SSFMQTTCRxBlockOf(itm) ((SSFMQTTCRxBlock_t *)(void *)(itm))
typedef char _SSFMQTTCTxItemFirst_t[(offsetof(SSFMQTTCTxBlock_t, item) == 0u) ? 1 : -1];
typedef char _SSFMQTTCRxItemFirst_t[(offsetof(SSFMQTTCRxBlock_t, item) == 0u) ? 1 : -1];

/* Inbound PUBLISH larger than the rx block, consumed and dropped; left == 0 => not skipping */
typedef struct
{
    size_t left;                      /* Packet bytes still to consume */
    size_t pos;                       /* Packet offset of the next byte to consume */
    size_t tlOff;                     /* Offset of the topic length (fixed header length) */
    uint16_t topicLen;
    uint16_t packetId;                /* QoS 1 only */
    SSFMQTTCQoS_t qos;
    bool isTopicNul;                  /* Topic holds U+0000: malformed (MQTT-1.5.3-2) */
} SSFMQTTCRxSkip_t;

#define SSF_MQTTC_TX_DATA(b) (((uint8_t *)(b)) + sizeof(SSFMQTTCTxBlock_t))
#define SSF_MQTTC_RX_DATA(b) (((uint8_t *)(b)) + sizeof(SSFMQTTCRxBlock_t))

typedef enum
{
    SSF_MQTTC_LINK_CLOSED,
    SSF_MQTTC_LINK_OPENING,
    SSF_MQTTC_LINK_OPEN,
    SSF_MQTTC_LINK_SHUTTING_DOWN,     /* STOPPING: DISCONNECT accepted, shutdown() delivering it */
    SSF_MQTTC_LINK_SHUT_DOWN          /* shutdown() done; TX_DRAINED posted, close() follows */
} SSFMQTTCLink_t;

/* Event payloads posted by the pump. Each must fit in sizeof(void *) or ssfsm heap-allocates. */
typedef struct
{
    uint8_t code;
    uint8_t sessionPresent;
} SSFMQTTCEvConnAck_t;
/* Per-filter SUBACK results are staged in subAckRefused and subAckDowngraded */
typedef struct
{
    uint16_t packetId;
    uint8_t count;
    uint8_t isQosExceeded;
} SSFMQTTCEvSubAck_t;
typedef struct
{
    uint16_t packetId;
} SSFMQTTCEvPubAck_t;

typedef struct
{
    /* Fixed at init */
    SSFNetTransport_t *transport;
    uint32_t txBlockSize;             /* Packet bytes per tx block */
    uint32_t rxBlockSize;             /* Packet bytes per rx block */
    SSFMPool_t txPool;
    SSFMPool_t rxPool;
    SSFMPool_t ctlPool;
    SSFMQTTCRxPublishFn_t rxPublishFn;
    void *rxPublishFnCtx;
    SSFMQTTCEventFn_t eventFn;
    void *eventFnCtx;
    SSFMQTTCRxBlock_t *rxFrame;       /* Reserved framing block */

    /* Per run */
    SSFMQTTCOpts_t opts;              /* Pointer fields remain app owned */
    bool isStarted;                   /* Between Start() and Stop(); gates both synchronously */
    SSFPortTick_t backoff;            /* Current reconnect wait; 0 => start at min */
    uint16_t nextPacketId;            /* Last id issued; 0 at init so the first is 1 */

    /* Per connection */
    uint16_t subscribePacketId;       /* Of the outstanding SUBSCRIBE, initial or retry */
    bool isPingPending;               /* PINGREQ queued or sent, PINGRESP not yet received */
    uint16_t subRefused;              /* Bit i: subsOpt[i] refused by the broker (SUBACK 0x80) */
    uint16_t subDowngraded;           /* Bit i: subsOpt[i] granted QoS 0 for QoS 1 requested */
    uint16_t subAckRefused;           /* Staged by the pump from the last SUBACK, bit i as above */
    uint16_t subAckDowngraded;
    bool isSubAckStaged;              /* Pump staged a SUBACK the state machine has not handled */
    bool isSubRetryPending;           /* A retry SUBSCRIBE for subRetryIndex[] is outstanding */
    uint8_t subRetryCount;            /* Filters in the retry SUBSCRIBE */
    uint8_t subRetryIndex[SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS];  /* Retry entry -> subsOpt index */

    /* Pump owned */
    SSFMQTTCLink_t link;              /* Transport state; closed by the pump on fatal error */
    size_t rxLen;                     /* Bytes in rxFrame */
    SSFMQTTCRxSkip_t rxSkip;          /* Oversized inbound PUBLISH being dropped */
    bool isRxHeld;                    /* A QoS 1 PUBLISH at the front of rxFrame awaits space */
    SSFPortTick_t rxHeldSince;        /* When the current hold began */
    bool isRxHoldEnded;               /* A hold ended since the PINGRESP deadline was armed */
    bool isRxConnAckSeen;             /* A CONNACK was framed on this connection (3.2.0: first) */
    uint16_t pubAckOwed;              /* Packet id of a PUBACK no ctl block could take, or 0 */

    /* Queues of SSFMQTTCTxBlock_t (tx*) and SSFMQTTCRxBlock_t (rxQueue) */
    SSFLL_t txQueue;                  /* Waiting for the transport */
    SSFLL_t txInflight;               /* QoS 1 PUBLISH / SUBSCRIBE awaiting acknowledgement */
    SSFLL_t rxQueue;                  /* Inbound PUBLISH awaiting the app */

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
/* Returns true if an inbound QoS 1 PUBLISH may be acknowledged or held, else false.             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCIsRxAckAllowed(void)
{
    return ((_mqttc.state == SSF_MQTTC_STATE_SUBSCRIBING) ||
            (_mqttc.state == SSF_MQTTC_STATE_CONNECTED));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a block from pool with its header zeroed, or NULL if the pool is empty.               */
/* --------------------------------------------------------------------------------------------- */
static void *_SSFMQTTCPoolAlloc(SSFMPool_t *pool, size_t hdrLen)
{
    void *b;

    SSF_REQUIRE(pool != NULL);
    SSF_REQUIRE(hdrLen > 0);
    SSF_REQUIRE(hdrLen <= SSFMPoolBlockSize(pool));

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
    return ((type == SSF_MQTT_PKT_PINGREQ) || (type == SSF_MQTT_PKT_DISCONNECT) ||
            (type == SSF_MQTT_PKT_PUBACK));
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
    SSFMPoolFree((_SSFMQTTCIsCtlType(b->type) ? (&_mqttc.ctlPool) : (&_mqttc.txPool)), b);
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

/* Queues a tx or ctl block for the transport */
#define _SSFMQTTCTxEnqueue(b) SSF_LL_FIFO_PUSH(&_mqttc.txQueue, (b))

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a packet of type is waiting in the tx queue, else false.                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCIsTxQueued(SSFMQTTPktType_t type)
{
    SSFLLItem_t *item;

    for (item = SSF_LL_HEAD(&_mqttc.txQueue); item != NULL; item = SSF_LL_NEXT_ITEM(item))
    { if (_SSFMQTTCTxBlockOf(item)->type == type) return true; }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Queues a PINGREQ or DISCONNECT; the ctl reserve guarantees a block for each.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCTxEnqueueSimple(SSFMQTTPktType_t type)
{
    SSFMQTTCTxBlock_t *b;

    SSF_REQUIRE((type == SSF_MQTT_PKT_PINGREQ) || (type == SSF_MQTT_PKT_DISCONNECT));
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
            b = _SSFMQTTCTxBlockOf(item);
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

    SSF_REQUIRE((type == SSF_MQTT_PKT_PUBLISH) || (type == SSF_MQTT_PKT_SUBSCRIBE));
    SSF_REQUIRE(fnOut != NULL);
    SSF_REQUIRE(fnCtxOut != NULL);

    for (item = SSF_LL_HEAD(&_mqttc.txInflight); item != NULL; item = SSF_LL_NEXT_ITEM(item))
    {
        SSFMQTTCTxBlock_t *b = _SSFMQTTCTxBlockOf(item);
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
    _mqttc.isRxHeld = false;                    /* All belong to the connection */
    _mqttc.isRxHoldEnded = false;
    _mqttc.pubAckOwed = 0;
    _mqttc.isRxConnAckSeen = false;
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
/* Queues a PUBACK for a dropped QoS 1 PUBLISH, or owes it if no ctl block is free.              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxPubAckOrOwe(uint16_t packetId)
{
    SSF_REQUIRE(packetId != 0);
    SSF_REQUIRE(_mqttc.pubAckOwed == 0);

    if (_SSFMQTTCTxEnqueuePubAck(packetId) == false) _mqttc.pubAckOwed = packetId;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if no PUBACK is owed: queues the owed one if a ctl block is now free.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxPubAckOwedFlush(void)
{
    if ((_mqttc.pubAckOwed != 0) && _SSFMQTTCIsRxAckAllowed() &&
        _SSFMQTTCTxEnqueuePubAck(_mqttc.pubAckOwed))
    { _mqttc.pubAckOwed = 0; }
    return (_mqttc.pubAckOwed == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Drops an inbound PUBLISH, acknowledging QoS 1 when allowed, and reports the drop.             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxPublishDrop(SSFMQTTCQoS_t qos, uint16_t packetId, SSFMQTTCReason_t reason)
{
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (qos == SSF_MQTTC_QOS_1));
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (packetId != 0));

    if ((qos == SSF_MQTTC_QOS_1) && _SSFMQTTCIsRxAckAllowed()) _SSFMQTTCRxPubAckOrOwe(packetId);
    _SSFMQTTCReport(SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, reason);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if PUBLISH first byte b0 carries QoS 2, else false.                              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxIsQoS2(uint8_t b0)
{
    return (((b0 & 0x06u) >> 1) == (uint8_t)SSF_MQTTC_QOS_2);
}

/* --------------------------------------------------------------------------------------------- */
/* Ends a back-pressure hold, noting it for keep-alive.                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxHoldEnd(void)
{
    SSF_REQUIRE(_mqttc.isRxHeld);

    _mqttc.isRxHeld = false;
    _mqttc.isRxHoldEnded = true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the inbound PUBLISH was queued, dropped or held, else false if link failed.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxPublishQueue(const uint8_t *pkt, size_t pktLen, bool *isHeldOut)
{
    SSFMQTTPktPublish_t pub;
    SSFMQTTCRxBlock_t *b;
    uint8_t *d;

    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);
    SSF_REQUIRE(isHeldOut != NULL);

    *isHeldOut = false;

    /* Is the PUBLISH QoS 2 by its fixed header flags? */
    if (_SSFMQTTCRxIsQoS2(pkt[0]))
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_RX_PUBLISH_QOS2); return false; }
    if (SSFMQTTPktDecodePublish(pkt, pktLen, &pub) == false)
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }
    if (pub.topicLen >= SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE)
    {
        _SSFMQTTCRxPublishDrop(pub.qos, pub.packetId, SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG);
        return true;
    }

    /* Is the rx queue full? */
    if ((b = _SSFMQTTCRxBlockAlloc()) == NULL)
    {
        /* Yes, may this PUBLISH be held for queue space? */
        if ((pub.qos == SSF_MQTTC_QOS_1) && _SSFMQTTCIsRxAckAllowed())
        {
            /* Yes, hold it until RX_HOLD_MAX_TICKS elapse, then drop it */
            SSFPortTick_t now = SSFPortGetTick64();

            if (_mqttc.isRxHeld == false)
            {
                _mqttc.isRxHeld = true;
                _mqttc.rxHeldSince = now;
            }
            if ((now - _mqttc.rxHeldSince) < SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS)
            {
                *isHeldOut = true;
                return true;
            }
            _SSFMQTTCRxHoldEnd();
            _SSFMQTTCRxPublishDrop(pub.qos, pub.packetId,
                                   SSF_MQTTC_REASON_RX_PUBLISH_HOLD_TIMEOUT);
            return true;
        }
        /* No, drop it at once */
        if (_mqttc.isRxHeld) _SSFMQTTCRxHoldEnd();      /* A hold abandoned on Stop */
        _SSFMQTTCRxPublishDrop(pub.qos, pub.packetId, SSF_MQTTC_REASON_RX_PUBLISH_QUEUE_FULL);
        return true;
    }
    if (_mqttc.isRxHeld) _SSFMQTTCRxHoldEnd();

    /* Normalize to [topic][NUL][payload], which is smaller than the wire form */
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
        _mqttc.isRxConnAckSeen = true;
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
        uint32_t expected;
        uint32_t i;
        uint32_t idx;

        if (SSFMQTTPktDecodeSubAck(pkt, pktLen, &ev.packetId, codes, sizeof(codes), &count) == false)
        { break; }
        /* A second SUBACK before the first is handled is a broker error */
        if (_mqttc.isSubAckStaged) break;
        /* A retry SUBACK answers the filters in subRetryIndex[] only */
        expected = _mqttc.isSubRetryPending ? _mqttc.subRetryCount : _mqttc.opts.subCount;
        ev.count = (uint8_t)count;
        ev.isQosExceeded = 0;
        _mqttc.subAckRefused = 0;
        _mqttc.subAckDowngraded = 0;
        for (i = 0; (i < count) && (i < expected); i++)
        {
            idx = _mqttc.isSubRetryPending ? _mqttc.subRetryIndex[i] : i;
            if (codes[i] == SSF_MQTT_PKT_SUBACK_FAILURE)
            { _mqttc.subAckRefused |= (uint16_t)(1u << idx); }
            else if (codes[i] > (uint8_t)_mqttc.opts.subsOpt[idx].qos) ev.isQosExceeded = 1;
            else if (codes[i] < (uint8_t)_mqttc.opts.subsOpt[idx].qos)
            { _mqttc.subAckDowngraded |= (uint16_t)(1u << idx); }
        }
        _mqttc.isSubAckStaged = true;
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
        if (SSFMQTTPktDecodePingResp(pkt, pktLen) == false) break;
        SSFSMPutEvent(SSF_SM_MQTTC, SSF_SM_EVENT_MQTTC_RX_PINGRESP);
        return true;
    default:
        break;      /* Client-only types, QoS 2 flow, reserved: never valid from a broker */
    }
    _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a skip of an oversized PUBLISH began, else false if the link failed.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxSkipStart(const uint8_t *frame, size_t pktLen)
{
    SSFMQTTCRxSkip_t *s = &_mqttc.rxSkip;
    uint8_t qosBits;
    size_t hdrLen = 2;

    SSF_REQUIRE(frame != NULL);
    SSF_REQUIRE(pktLen > _mqttc.rxBlockSize);
    SSF_REQUIRE(SSF_MQTT_PKT_TYPE(frame[0]) == SSF_MQTT_PKT_PUBLISH);

    /* Apply the fixed header flag rules of SSFMQTTPktDecodePublish() */
    if (_SSFMQTTCRxIsQoS2(frame[0]))
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_RX_PUBLISH_QOS2); return false; }
    qosBits = (uint8_t)((frame[0] & 0x06u) >> 1);
    if ((qosBits >= (uint8_t)SSF_MQTTC_QOS_2) ||
        ((qosBits == (uint8_t)SSF_MQTTC_QOS_0) && ((frame[0] & 0x08u) != 0)))
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }

    /* The fixed header ends at the first length byte without the continuation bit */
    while ((frame[hdrLen - 1] & 0x80u) != 0) hdrLen++;
    SSF_ASSERT(hdrLen <= SSF_MQTT_PKT_MAX_FIXED_HDR_LEN);

    memset(s, 0, sizeof(*s));
    s->left = pktLen;
    s->tlOff = hdrLen;
    s->qos = (SSFMQTTCQoS_t)qosBits;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Captures the bytes in p of the big endian 16-bit field at packet offset at.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCRxSkipTakeU16(const uint8_t *p, size_t pLen, size_t at, uint16_t *v)
{
    size_t pos = _mqttc.rxSkip.pos;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(v != NULL);

    if ((at >= pos) && ((at - pos) < pLen))
    { *v = (uint16_t)((*v & 0x00FFu) | (((uint16_t)p[at - pos]) << 8)); }
    if (((at + 1) >= pos) && ((at + 1 - pos) < pLen))
    { *v = (uint16_t)((*v & 0xFF00u) | p[at + 1 - pos]); }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the skipped PUBLISH was well formed and dropped, else false if link failed.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCRxSkipFinish(void)
{
    SSFMQTTCRxSkip_t *s = &_mqttc.rxSkip;
    size_t need;

    SSF_REQUIRE(s->left == 0);

    /* Apply the field checks of SSFMQTTPktDecodePublish(); pos is now the packet length */
    need = s->tlOff + 2u + s->topicLen + ((s->qos == SSF_MQTTC_QOS_1) ? 2u : 0u);
    if ((s->topicLen == 0) || (need > s->pos) || s->isTopicNul ||
        ((s->qos == SSF_MQTTC_QOS_1) && (s->packetId == 0)))
    { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }

    _SSFMQTTCRxPublishDrop(s->qos, s->packetId, SSF_MQTTC_REASON_RX_PUBLISH_TOO_LARGE);
    memset(s, 0, sizeof(*s));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the skip consumed the framing buffer, else false if the link failed.          */
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
        /* Nothing further is processed while a PUBACK is owed */
        if (_mqttc.pubAckOwed != 0) return true;

        /* An oversized PUBLISH is consumed before anything after it is framed */
        if (_mqttc.rxSkip.left > 0)
        {
            if (_SSFMQTTCRxSkipConsume() == false) return false;
            continue;
        }

        fr = SSFMQTTPktFrame(frame, _mqttc.rxLen, &pktLen);
        if (fr == SSF_MQTT_PKT_FRAME_MALFORMED)
        { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }
        /* Is this a non-QoS 2 PUBLISH framed before CONNACK (3.2.0)? */
        if ((SSF_MQTT_PKT_TYPE(frame[0]) == SSF_MQTT_PKT_PUBLISH) &&
            (_mqttc.isRxConnAckSeen == false) && (_SSFMQTTCRxIsQoS2(frame[0]) == false))
        { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_PROTOCOL); return false; }
        /* Is the packet too large for the rx block? */
        if ((pktLen != 0) && (pktLen > _mqttc.rxBlockSize))
        {
            /* Yes, skip a PUBLISH as it arrives, any other packet is fatal */
            if (SSF_MQTT_PKT_TYPE(frame[0]) != SSF_MQTT_PKT_PUBLISH)
            { _SSFMQTTCLinkFail(SSF_MQTTC_REASON_RX_OVERFLOW); return false; }
            if (_SSFMQTTCRxSkipStart(frame, pktLen) == false) return false;
            continue;
        }
        if (fr == SSF_MQTT_PKT_FRAME_INCOMPLETE) return true;

        if (SSF_MQTT_PKT_TYPE(frame[0]) == SSF_MQTT_PKT_PUBLISH)
        {
            bool isHeld;

            ok = _SSFMQTTCRxPublishQueue(frame, pktLen, &isHeld);
            if (ok && isHeld) return true;          /* Stays in front; nothing behind is read */
        }
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
        SSFMQTTCTxBlock_t *head = _SSFMQTTCTxBlockOf(SSF_LL_TAIL(&_mqttc.txQueue));
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

    /* No DISCONNECT, so the broker publishes the will */
    _SSFMQTTCConnectionTeardown(false);
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

    while ((b = _SSFMQTTCRxBlockOf(SSF_LL_TAIL(&_mqttc.rxQueue))) != NULL)
    {
        now = SSFPortGetTick64();
        if (b->firstOffer != 0)
        {
            if ((now - b->firstOffer) >= SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS)
            {
                /* A QoS 1 drop owes its PUBACK; while another is owed it waits its turn */
                if ((b->qos == SSF_MQTTC_QOS_1) && (_mqttc.pubAckOwed != 0))
                {
                    _SSFMQTTCNextTimeoutLower(nextTimeoutOpt,
                                              SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS);
                    return;
                }
                SSF_LL_FIFO_POP(&_mqttc.rxQueue, &b);
                if (b->qos == SSF_MQTTC_QOS_1) _SSFMQTTCRxPubAckOrOwe(b->packetId);
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

        /* A QoS 1 delivery needs its PUBACK block and waits behind an owed PUBACK */
        ack = NULL;
        if ((b->qos == SSF_MQTTC_QOS_1) && ((_mqttc.pubAckOwed != 0) ||
            ((ack = _SSFMQTTCCtlAlloc(SSF_MQTT_PKT_PUBACK, false)) == NULL)))
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
        /* Silent at init: SSFMQTTCInit() enters this state before installing the callback */
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

        SSF_ASSERT(b != NULL);
        /* Fits: checked by Start() */
        SSFMQTTPktEncodeConnect(SSF_MQTTC_TX_DATA(b), _mqttc.txBlockSize, &b->len,
                                _mqttc.opts.clientId, SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE,
                                _mqttc.opts.willOpt, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE,
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

    SSF_REQUIRE(_mqttc.opts.subCount > 0);

    b = _SSFMQTTCTxBlockAlloc(SSF_MQTT_PKT_SUBSCRIBE);
    SSF_ASSERT(b != NULL);
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
/* Returns true if the staged SUBACK answers the outstanding SUBSCRIBE, else false.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTCSessionSubAckTake(const SSFMQTTCEvSubAck_t *ev, uint32_t count)
{
    SSFMQTTCTxPublishFn_t fn;
    void *fnCtx;

    SSF_REQUIRE(ev != NULL);
    SSF_REQUIRE(count <= SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS);

    _mqttc.isSubAckStaged = false;
    if ((ev->packetId != _mqttc.subscribePacketId) || (ev->count != count)) return false;
    (void)_SSFMQTTCTxInflightRemove(SSF_MQTT_PKT_SUBSCRIBE, ev->packetId, &fn, &fnCtx);
    SSFSMStopTimer(SSF_SM_EVENT_MQTTC_TO_SUBSCRIBE);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Acts on the SUBACK for the initial SUBSCRIBE, recording each filter's result.                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCSessionRxSubAck(const SSFMQTTCEvSubAck_t *ev)
{
    SSF_REQUIRE(ev != NULL);

    if (_SSFMQTTCSessionSubAckTake(ev, _mqttc.opts.subCount) == false)
    { _SSFMQTTCFail(SSF_MQTTC_REASON_PROTOCOL); return; }
    if (ev->isQosExceeded != 0) { _SSFMQTTCFail(SSF_MQTTC_REASON_SUBSCRIBE_QOS_EXCEEDED); return; }
    _mqttc.subRefused = _mqttc.subAckRefused;
    _mqttc.subDowngraded = _mqttc.subAckDowngraded;
    SSFSMTran(_SSFMQTTCStateReady);
}

/* --------------------------------------------------------------------------------------------- */
/* Queues a SUBSCRIBE for just the refused filters, or rearms the retry timer if no block.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCSessionSubRetry(void)
{
    SSFMQTTPktSub_t subs[SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS];
    SSFMQTTCTxBlock_t *b;
    uint32_t i;
    uint8_t n = 0;

    SSF_REQUIRE(_mqttc.subRefused != 0);
    SSF_REQUIRE(_mqttc.isSubRetryPending == false);

    if ((b = _SSFMQTTCTxBlockAlloc(SSF_MQTT_PKT_SUBSCRIBE)) == NULL)
    {
        SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_SUB_RETRY, SSF_MQTTC_CONFIG_SUB_RETRY_TICKS);
        return;
    }
    for (i = 0; i < _mqttc.opts.subCount; i++)
    {
        if ((_mqttc.subRefused & (1u << i)) == 0) continue;
        subs[n] = _mqttc.opts.subsOpt[i];
        _mqttc.subRetryIndex[n] = (uint8_t)i;
        n++;
    }
    _mqttc.subRetryCount = n;
    _mqttc.subscribePacketId = _SSFMQTTCNextPacketId();
    /* A subset of the initial SUBSCRIBE, which fit a tx block */
    SSFMQTTPktEncodeSubscribe(SSF_MQTTC_TX_DATA(b), _mqttc.txBlockSize, &b->len,
                              _mqttc.subscribePacketId, subs, n, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE);
    b->packetId = _mqttc.subscribePacketId;
    _SSFMQTTCTxEnqueue(b);
    _mqttc.isSubRetryPending = true;
    SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_SUBSCRIBE, _mqttc.opts.subscribeTimeout);
}

/* --------------------------------------------------------------------------------------------- */
/* Acts on a SUBACK in READY, which must answer the outstanding retry SUBSCRIBE.                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTCReadyRxSubAck(const SSFMQTTCEvSubAck_t *ev)
{
    uint16_t granted;

    SSF_REQUIRE(ev != NULL);

    if ((_mqttc.isSubRetryPending == false) ||
        (_SSFMQTTCSessionSubAckTake(ev, _mqttc.subRetryCount) == false))
    { _SSFMQTTCFail(SSF_MQTTC_REASON_PROTOCOL); return; }
    _mqttc.isSubRetryPending = false;
    if (ev->isQosExceeded != 0) { _SSFMQTTCFail(SSF_MQTTC_REASON_SUBSCRIBE_QOS_EXCEEDED); return; }
    /* Every refused filter was in the retry, so its SUBACK is the new refused set */
    granted = (uint16_t)(_mqttc.subRefused & ((uint16_t)(~_mqttc.subAckRefused)));
    _mqttc.subRefused = _mqttc.subAckRefused;
    _mqttc.subDowngraded |= _mqttc.subAckDowngraded;
    if (_mqttc.subRefused != 0)
    { SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_SUB_RETRY, SSF_MQTTC_CONFIG_SUB_RETRY_TICKS); }
    if (granted != 0)
    {
        _SSFMQTTCReport(SSF_MQTTC_EVENT_SUBSCRIPTION_CHANGED, (_mqttc.subRefused != 0) ?
                        SSF_MQTTC_REASON_SUBSCRIBE_REFUSED : SSF_MQTTC_REASON_NONE);
    }
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
        _mqttc.subRefused = 0;
        _mqttc.subDowngraded = 0;
        _mqttc.isSubAckStaged = false;
        _mqttc.isSubRetryPending = false;
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
        /* Does this PINGRESP answer a PINGREQ already sent? */
        if (_mqttc.isPingPending && (_SSFMQTTCIsTxQueued(SSF_MQTT_PKT_PINGREQ) == false))
        {
            _mqttc.isPingPending = false;
            SSFSMStopTimer(SSF_SM_EVENT_MQTTC_TO_PINGRESP);
        }
        break;

    case SSF_SM_EVENT_MQTTC_RX_CONNACK:          /* CONNACK twice; each substate takes SUBACK */
        _SSFMQTTCFail(SSF_MQTTC_REASON_PROTOCOL);
        break;

    case SSF_SM_EVENT_MQTTC_TO_KEEPALIVE:
        /* Is no PINGREQ pending, so its PINGRESP deadline is not restarted? */
        if (_mqttc.isPingPending == false)
        {
            _SSFMQTTCTxEnqueueSimple(SSF_MQTT_PKT_PINGREQ);
            _mqttc.isPingPending = true;
            _mqttc.isRxHoldEnded = false;           /* Only holds from here on extend it */
            SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_PINGRESP, SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT);
        }
        SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_KEEPALIVE, _SSFMQTTCKeepAliveTicks());
        break;

    case SSF_SM_EVENT_MQTTC_TO_PINGRESP:
        /* Could the PINGRESP be waiting behind an app hold rather than a blocked link? */
        if ((_mqttc.pubAckOwed == 0) && (_mqttc.isRxHeld || _mqttc.isRxHoldEnded))
        {
            /* Yes, wait a full timeout again */
            _mqttc.isRxHoldEnded = false;
            SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_PINGRESP, SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT);
            break;
        }
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
        if (_mqttc.subRefused != 0)
        { SSFSMStartTimer(SSF_SM_EVENT_MQTTC_TO_SUB_RETRY, SSF_MQTTC_CONFIG_SUB_RETRY_TICKS); }
        _SSFMQTTCReport(SSF_MQTTC_EVENT_READY,
                        (_mqttc.subRefused != 0) ? SSF_MQTTC_REASON_SUBSCRIBE_REFUSED :
                        (_mqttc.subDowngraded != 0) ? SSF_MQTTC_REASON_SUBSCRIBE_DOWNGRADED :
                        SSF_MQTTC_REASON_NONE);
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

    case SSF_SM_EVENT_MQTTC_TO_SUB_RETRY:
        _SSFMQTTCSessionSubRetry();
        break;

    case SSF_SM_EVENT_MQTTC_RX_SUBACK:
    {
        SSFMQTTCEvSubAck_t ev;
        SSF_SM_EVENT_DATA_ALIGN(ev);
        _SSFMQTTCReadyRxSubAck(&ev);
        break;
    }

    case SSF_SM_EVENT_MQTTC_TO_SUBSCRIBE:       /* No SUBACK for a retry */
        _SSFMQTTCFail(SSF_MQTTC_REASON_SUBSCRIBE_TIMEOUT);
        break;

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
        /* Flush the queue with DISCONNECT appended; the pump posts TX_DRAINED when it empties */
        _mqttc.isRxHeld = false;
        _mqttc.pubAckOwed = 0;
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
        break;        /* Inbound packets and drops are ignored */
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
    SSF_REQUIRE((eventFnOpt != NULL) || (eventFnCtxOpt == NULL));

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

    /* Installed after the initial state is entered so that entry does not report STOPPED */
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
    SSF_REQUIRE(SSFMQTTPktConnectLen(opts->clientId, SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE,
                                     opts->willOpt, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE,
                                     opts->usernameOpt, SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE,
                                     opts->passwordOpt, opts->passwordLen) <=
                _mqttc.txBlockSize);

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
/* Advances shutdown() while STOPPING, posting TX_DRAINED when all bytes are delivered.          */
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
        SSFMQTTCTxBlock_t *b = _SSFMQTTCTxBlockOf(SSF_LL_TAIL(&_mqttc.txQueue));
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
        /* Has STOPPING flushed its queue, so shutdown() can deliver the DISCONNECT? */
        if (SSFLLIsEmpty(&_mqttc.txQueue) && (_mqttc.state == SSF_MQTTC_STATE_STOPPING))
        {
            _mqttc.link = SSF_MQTTC_LINK_SHUTTING_DOWN;
            _SSFMQTTCShutdownPoll();
            goto done;
        }
    }

    /* An owed PUBACK is queued as soon as a ctl block is free; the next call sends it */
    if ((_mqttc.pubAckOwed != 0) && _SSFMQTTCRxPubAckOwedFlush()) more = true;

    /* Receive, unless back-pressure has suspended reads */
    for (;;)
    {
        uint8_t *frame = SSF_MQTTC_RX_DATA(_mqttc.rxFrame);
        size_t space;
        size_t got = 0;
        SSFNetIOResult_t r;

        if (_SSFMQTTCRxFrameProcess() == false) break;
        if (_mqttc.isRxHeld || (_mqttc.pubAckOwed != 0)) break;
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
    if (_mqttc.isRxHeld && (_mqttc.pubAckOwed == 0) && (_mqttc.link == SSF_MQTTC_LINK_OPEN))
    {
        /* Retry the held packet at once if a slot just freed, else by the hold deadline */
        SSFPortTick_t held = SSFPortGetTick64() - _mqttc.rxHeldSince;

        if (SSFMPoolLen(&_mqttc.rxPool) > 0) more = true;
        else _SSFMQTTCNextTimeoutLower(nextTimeoutOpt,
                                       (held >= SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS) ? 0 :
                                       (SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS - held));
    }
    if (more && (nextTimeoutOpt != NULL)) *nextTimeoutOpt = 0;
    return more;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the PUBLISH was queued, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTCTxPublish(SSFCStrIn_t topicStr, const uint8_t *payload, size_t payloadLen,
                       SSFMQTTCQoS_t qos, bool retain, SSFMQTTCTxPublishFn_t txPublishFnOpt,
                       void *txPublishFnCtxOpt)
{
    SSFMQTTCTxBlock_t *b;
    size_t topicLen;
    size_t pktLen;

    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    SSF_REQUIRE(topicStr != NULL);
    SSF_REQUIRE((payload != NULL) || (payloadLen == 0));
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (qos == SSF_MQTTC_QOS_1));
    SSF_REQUIRE((txPublishFnOpt != NULL) || (txPublishFnCtxOpt == NULL));

    if (_mqttc.state != SSF_MQTTC_STATE_CONNECTED) return false;
    if (SSFMQTTPktIsValidTopic(topicStr, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE) == false) return false;
    (void)SSFStrLen(topicStr, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, &topicLen);   /* Valid above */
    pktLen = SSFMQTTPktPublishLen(topicLen, payloadLen, qos);
    if ((pktLen == 0) || (pktLen > _mqttc.txBlockSize)) return false;   /* Too large for a block */
    if ((b = _SSFMQTTCTxBlockAlloc(SSF_MQTT_PKT_PUBLISH)) == NULL) return false;

    b->packetId = (qos == SSF_MQTTC_QOS_1) ? _SSFMQTTCNextPacketId() : 0;
    SSFMQTTPktEncodePublish(SSF_MQTTC_TX_DATA(b), _mqttc.txBlockSize, &b->len, topicStr,
                            SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE, payload, payloadLen, qos, retain,
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

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the result of declared filter index while READY, else false.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTCGetSubResult(uint32_t index, uint8_t *resultOut)
{
    uint16_t bit;

    SSF_REQUIRE(_mqttc.magic == SSF_MQTTC_INIT_MAGIC);
    SSF_REQUIRE(resultOut != NULL);

    if (_mqttc.state != SSF_MQTTC_STATE_CONNECTED) return false;
    SSF_REQUIRE(index < _mqttc.opts.subCount);
    bit = (uint16_t)(1u << index);
    if ((_mqttc.subRefused & bit) != 0) *resultOut = SSF_MQTTC_SUB_REFUSED;
    else if ((_mqttc.subDowngraded & bit) != 0) *resultOut = (uint8_t)SSF_MQTTC_QOS_0;
    else *resultOut = (uint8_t)_mqttc.opts.subsOpt[index].qos;
    return true;
}
