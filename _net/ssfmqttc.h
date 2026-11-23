/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmqttc.h                                                                                    */
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
#ifndef SSF_MQTTC_H_INCLUDE
#define SSF_MQTTC_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfnet.h"
#include "ssfmqttpkt.h"

/* --------------------------------------------------------------------------------------------- */
/* Documentation                                                                                 */
/* --------------------------------------------------------------------------------------------- */
/* Design, lifecycle, buffer sizing, callback contracts and option constraints are documented in  */
/* ssfmqttc.md. Comments here are summaries; the document is the contract.                       */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
/* Sizes include the NUL terminator. MQTT 3.1.1 caps every string field at 65535 bytes; brokers  */
/* must accept client ids of 1-23 chars and may accept longer.                                   */
#if SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE < 2 || SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE > 65536
#error SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE must be between 2 and 65536.
#endif
#if SSF_MQTTC_CONFIG_MAX_HOST_SIZE < 2 || SSF_MQTTC_CONFIG_MAX_HOST_SIZE > 256
#error SSF_MQTTC_CONFIG_MAX_HOST_SIZE must be between 2 and 256 (DNS name limit + NUL).
#endif
#if SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE < 2 || SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE > 65536
#error SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE must be between 2 and 65536.
#endif
#if SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE < 2 || SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE > 65536
#error SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE must be between 2 and 65536.
#endif
#if SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN < 1 || SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN > 65535
#error SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN must be between 1 and 65535.
#endif

typedef enum
{
    SSF_MQTTC_STATE_MIN = -1,
    SSF_MQTTC_STATE_STOPPED,         /* Initialized, not running                                */
    SSF_MQTTC_STATE_CONNECTING,      /* Transport opening / CONNECT sent / awaiting CONNACK     */
    SSF_MQTTC_STATE_SUBSCRIBING,     /* CONNACK accepted, SUBSCRIBE sent, awaiting SUBACK       */
    SSF_MQTTC_STATE_CONNECTED,       /* Session up; all declared subscriptions granted          */
    SSF_MQTTC_STATE_RECONNECT_WAIT,  /* Attempt failed or connection lost; backoff before retry */
    SSF_MQTTC_STATE_STOPPING,        /* Stop requested; flushing, DISCONNECT sent, closing      */
    SSF_MQTTC_STATE_MAX
} SSFMQTTCState_t;

typedef enum
{
    SSF_MQTTC_REASON_MIN = -1,
    SSF_MQTTC_REASON_NONE,
    SSF_MQTTC_REASON_TRANSPORT_ERROR,
    SSF_MQTTC_REASON_PEER_CLOSED,
    SSF_MQTTC_REASON_CONNECT_TIMEOUT,    /* Transport open + CONNACK exceeded connectTimeout     */
    /* Broker rejected CONNECT; one reason per MQTT 3.1.1 CONNACK return code 1..5 */
    SSF_MQTTC_REASON_CONNACK_PROTOCOL_VERSION,  /* 1: unacceptable protocol version             */
    SSF_MQTTC_REASON_CONNACK_CLIENT_ID,         /* 2: client identifier rejected                */
    SSF_MQTTC_REASON_CONNACK_SERVER_UNAVAILABLE,/* 3: server unavailable (transient)            */
    SSF_MQTTC_REASON_CONNACK_BAD_CREDENTIALS,   /* 4: bad user name or password                 */
    SSF_MQTTC_REASON_CONNACK_NOT_AUTHORIZED,    /* 5: not authorized                            */
    SSF_MQTTC_REASON_CONNACK_UNKNOWN,           /* Reserved/undefined return code               */
    SSF_MQTTC_REASON_SUBSCRIBE_TIMEOUT,  /* SUBACK not received within subscribeTimeout          */
    SSF_MQTTC_REASON_SUBSCRIBE_REFUSED,  /* SUBACK returned 0x80, or granted a QoS lower than    */
                                         /* requested, for one or more declared filters          */
    SSF_MQTTC_REASON_KEEPALIVE,          /* No PINGRESP within SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT */
    SSF_MQTTC_REASON_TX_PUBLISH_TIMEOUT, /* A txPublish did not complete within txPublishTimeout */
    SSF_MQTTC_REASON_PROTOCOL,           /* Malformed packet, QoS 2, unexpected packet           */
    SSF_MQTTC_REASON_RX_OVERFLOW,        /* Inbound packet larger than rxBlockSize, or topic     */
                                         /* length >= SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE            */
    SSF_MQTTC_REASON_RX_PUBLISH_TIMEOUT, /* App deferred an rxPublish past RX_PUBLISH_MAX_TICKS  */
    SSF_MQTTC_REASON_RX_PUBLISH_QUEUE_FULL, /* rxPublish queue full                              */
    SSF_MQTTC_REASON_MAX
} SSFMQTTCReason_t;

typedef enum
{
    SSF_MQTTC_EVENT_MIN = -1,
    SSF_MQTTC_EVENT_CONNECTED,       /* CONNACK accepted; SUBSCRIBE for declared set sent       */
    SSF_MQTTC_EVENT_READY,           /* Every declared subscription granted (or none declared). */
                                     /* Publishing and receiving now active.                    */
    SSF_MQTTC_EVENT_CONNECT_FAILED,  /* An attempt ended before READY; reason valid. Reported at */
                                     /* the point of failure; the client then enters            */
                                     /* RECONNECT_WAIT and will try again.                      */
    SSF_MQTTC_EVENT_DISCONNECTED,    /* A READY connection was lost; reason valid. Reported at  */
                                     /* the point of failure; the client then enters            */
                                     /* RECONNECT_WAIT and will try again.                      */
    SSF_MQTTC_EVENT_STOPPED,         /* SSFMQTTCStop() complete; client is in STOPPED           */
    SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED, /* An rxPublish was discarded; reason is                 */
                                     /* RX_PUBLISH_TIMEOUT or RX_PUBLISH_QUEUE_FULL. Connection */
                                     /* is unaffected.                                          */
    SSF_MQTTC_EVENT_MAX
} SSFMQTTCEvent_t;

typedef struct
{
    SSFCStrIn_t topic;               /* NUL terminated, < SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE;      */
                                     /* valid only during the callback                          */
    size_t topicLen;
    const uint8_t *payload;          /* Valid only during the callback                          */
    size_t payloadLen;
    SSFMQTTCQoS_t qos;
    bool retain;                     /* Set by broker when delivering a retained message        */
    bool dup;                        /* Wire DUP flag as sent by the broker                     */
    uint32_t offerCount;             /* 1 on first offer; +1 each time the app deferred it      */
} SSFMQTTCRxPublish_t;

/* Callbacks run on the app thread from SSFSMTask() or SSFMQTTCTask(); see ssfmqttc.md.          */

/* Lifecycle events. reason is NONE unless the event says otherwise. */
typedef void (*SSFMQTTCEventFn_t)(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason);

/* Publish completion: fires exactly once per accepted SSFMQTTCTxPublish(), within              */
/* txPublishTimeout. false means the message was not published and will not be re-sent.          */
typedef void (*SSFMQTTCTxPublishFn_t)(void *ctx, bool isPublished);

/* Inbound PUBLISH offer. Return true to consume, false to defer (re-offered later). */
typedef bool (*SSFMQTTCRxPublishFn_t)(void *ctx, const SSFMQTTCRxPublish_t *rxPublish);

/* Pointed-to memory is app owned and must stay valid from Start() until the STOPPED event. */
typedef SSFMQTTPktSub_t SSFMQTTCSub_t;   /* Topic filter + requested QoS (0 or 1) */

typedef struct
{
    SSFCStrIn_t host;                /* < SSF_MQTTC_CONFIG_MAX_HOST_SIZE                        */
    uint16_t port;
    SSFCStrIn_t clientId;            /* Required, >= 1 char, < SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE */
    SSFCStrIn_t usernameOpt;         /* < SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE; NULL => none      */
    const uint8_t *passwordOpt;      /* Binary; NULL => none; requires usernameOpt              */
    uint16_t passwordLen;            /* <= SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN                    */
    const SSFMQTTCSub_t *subsOpt;    /* Subscription set, app owned; NULL => none. Each filter  */
                                     /* < SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE and valid             */
    uint32_t subCount;               /* Entries in subsOpt; <= SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS */
    uint16_t keepAliveSec;           /* Advertised to the broker. PINGREQ every                */
                                     /* keepAliveSec / 4, which must be >=                     */
                                     /* SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT                      */
    SSFPortTick_t connectTimeout;    /* > 0. Transport open through CONNACK accepted           */
    SSFPortTick_t subscribeTimeout;  /* > 0. SUBSCRIBE sent through SUBACK received            */
    SSFPortTick_t txPublishTimeout;  /* > 0. txPublish call through completion. On expiry the  */
                                     /* connection is dropped (TX_PUBLISH_TIMEOUT) and every   */
                                     /* pending txPublish callback fires false                 */
    SSFPortTick_t reconnectMinWait;  /* > 0. First backoff; doubles per consecutive failure    */
    SSFPortTick_t reconnectMaxWait;  /* >= reconnectMinWait. Backoff cap; no jitter is added   */
} SSFMQTTCOpts_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Builds the tx, rx and ctl pools and registers with ssfsm; STOPPED on return. txBlocks >= 1,    */
/* block sizes >= 4. See ssfmqttc.md for sizing.                                                 */
void SSFMQTTCInit(SSFNetTransport_t *transport, uint32_t txBlocks, uint32_t txBlockSize,
                  uint32_t rxBlockSize, SSFMQTTCRxPublishFn_t rxPublishFn,
                  void *rxPublishFnCtxOpt, SSFMQTTCEventFn_t eventFnOpt, void *eventFnCtxOpt);
void SSFMQTTCDeInit(void);           /* Only valid in STOPPED; frees the pools                  */

/* Starts the client; it then keeps itself connected until Stop(). Asserts unless STOPPED and    */
/* opts is valid.                                                                                */
void SSFMQTTCStart(const SSFMQTTCOpts_t *opts);

/* Stops the client; valid exactly once per Start(). STOPPED is reported asynchronously.        */
void SSFMQTTCStop(void);

/* Pumps transport I/O and inbound delivery; call every loop iteration after SSFSMTask().        */
/* nextTimeoutOpt is only ever lowered. Returns true when more work is immediately available.    */
bool SSFMQTTCTask(SSFPortTick_t *nextTimeoutOpt);

/* Queues a PUBLISH; valid only when SSFMQTTCIsReady(). Returns false if not READY, the topic is */
/* invalid, the packet does not fit a tx block, or no tx block is free.                          */
bool SSFMQTTCTxPublish(SSFCStrIn_t topic, const uint8_t *payload, size_t payloadLen,
                       SSFMQTTCQoS_t qos, SSFMQTTCTxPublishFn_t txPublishFnOpt,
                       void *txPublishFnCtxOpt);

SSFMQTTCState_t SSFMQTTCGetState(void);

/* Not STOPPED: client is working to stay connected                                              */
#define SSFMQTTCIsStarted() (SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED)
/* SUBSCRIBING or CONNECTED: session is up                                                       */
#define SSFMQTTCIsConnected() ((SSFMQTTCGetState() == SSF_MQTTC_STATE_SUBSCRIBING) || \
                               (SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED))
/* CONNECTED: all subscriptions granted as requested; may txPublish                              */
#define SSFMQTTCIsReady() (SSFMQTTCGetState() == SSF_MQTTC_STATE_CONNECTED)

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
void SSFMQTTCUnitTest(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_MQTTC_H_INCLUDE */
