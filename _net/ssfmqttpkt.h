/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmqttpkt.h                                                                                  */
/* Provides MQTT 3.1.1 control packet framing, encoding and decoding for a QoS 0/1 client.       */
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
#ifndef SSF_MQTTPKT_H_INCLUDE
#define SSF_MQTTPKT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssf.h"

/* --------------------------------------------------------------------------------------------- */
/* Design                                                                                        */
/* --------------------------------------------------------------------------------------------- */
/* - Pure functions over caller-supplied buffers; no state, no allocation.                      */
/* - Encoders write one complete packet (fixed header included) and set *lenOut to its length.  */
/*   A packet that does not fit in size bytes, or an argument that is not encodable, is an app  */
/*   error and asserts. Callers that need to refuse an oversized PUBLISH at run time check with  */
/*   SSFMQTTPktPublishLen() first.                                                               */
/* - Decoders take exactly one complete packet as delimited by SSFMQTTPktFrame() and return     */
/*   false if it is malformed for its type. They do not judge whether the packet is expected.   */
/* - Strings supplied by the app are NUL terminated and validated with a bounded scan against   */
/*   the given size (which includes the NUL), so a string must be strictly shorter than size.   */
/* - UTF-8 well-formedness of strings is not checked, and neither is wildcard placement in       */
/*   topics and filters. Both are developer errors the broker reports on first use, as a SUBACK  */
/*   failure code or a disconnect, which the client already surfaces to the app.                 */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MQTT_PKT_MAX_REMAINING_LEN   (268435455ul)  /* 4-byte variable length integer */
#define SSF_MQTT_PKT_MAX_FIXED_HDR_LEN   (5u)           /* type byte + 4 length bytes     */
#define SSF_MQTT_PKT_MAX_STRING_LEN      (65535u)

/* Control packet type: upper nibble of the first byte. Values are those of the specification. */
typedef enum
{
    SSF_MQTT_PKT_RESERVED_0 = 0,
    SSF_MQTT_PKT_CONNECT = 1,
    SSF_MQTT_PKT_CONNACK = 2,
    SSF_MQTT_PKT_PUBLISH = 3,
    SSF_MQTT_PKT_PUBACK = 4,
    SSF_MQTT_PKT_PUBREC = 5,
    SSF_MQTT_PKT_PUBREL = 6,
    SSF_MQTT_PKT_PUBCOMP = 7,
    SSF_MQTT_PKT_SUBSCRIBE = 8,
    SSF_MQTT_PKT_SUBACK = 9,
    SSF_MQTT_PKT_UNSUBSCRIBE = 10,
    SSF_MQTT_PKT_UNSUBACK = 11,
    SSF_MQTT_PKT_PINGREQ = 12,
    SSF_MQTT_PKT_PINGRESP = 13,
    SSF_MQTT_PKT_DISCONNECT = 14,
    SSF_MQTT_PKT_RESERVED_15 = 15
} SSFMQTTPktType_t;

#define SSF_MQTT_PKT_TYPE(b0) ((SSFMQTTPktType_t)(((uint8_t)(b0)) >> 4))

typedef enum
{
    SSF_MQTTC_QOS_MIN = -1,
    SSF_MQTTC_QOS_0,                 /* At most once                                            */
    SSF_MQTTC_QOS_1,                 /* At least once                                           */
    SSF_MQTTC_QOS_2,                 /* Exactly once; recognized on the wire, not supported     */
    SSF_MQTTC_QOS_MAX
} SSFMQTTCQoS_t;

typedef enum
{
    SSF_MQTT_PKT_FRAME_MALFORMED,    /* Fixed header invalid; the stream cannot be resynced     */
    SSF_MQTT_PKT_FRAME_INCOMPLETE,   /* More bytes needed                                       */
    SSF_MQTT_PKT_FRAME_COMPLETE      /* A whole packet is present at the start of the buffer    */
} SSFMQTTPktFrame_t;

/* Decoded PUBLISH. Pointers reference the packet buffer passed to the decoder.                  */
typedef struct
{
    const uint8_t *topic;            /* Not NUL terminated                                      */
    uint16_t topicLen;               /* >= 1                                                    */
    const uint8_t *payload;          /* NULL when payloadLen == 0                               */
    size_t payloadLen;
    uint16_t packetId;               /* 0 for QoS 0                                             */
    SSFMQTTCQoS_t qos;               /* 0, 1 or 2                                               */
    bool retain;
    bool dup;
} SSFMQTTPktPublish_t;

/* SUBACK return codes. */
#define SSF_MQTT_PKT_SUBACK_FAILURE      (0x80u)

/* One SUBSCRIBE entry: a topic filter and the QoS requested for it. */
typedef struct
{
    SSFCStrIn_t filter;              /* NUL terminated, app owned                               */
    SSFMQTTCQoS_t qos;               /* 0 or 1                                                  */
} SSFMQTTPktSub_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Framing. Inspects the fixed header at the start of buf. On COMPLETE and on INCOMPLETE where   */
/* the fixed header itself is complete, *pktLenOut is the total packet length; otherwise 0. A    */
/* caller can therefore reject an oversized packet before receiving all of it.                   */
SSFMQTTPktFrame_t SSFMQTTPktFrame(const uint8_t *buf, size_t len, size_t *pktLenOut);

/* Encoders. Each asserts if the packet does not fit or an argument is not encodable. */
void SSFMQTTPktEncodeConnect(uint8_t *buf, size_t size, size_t *lenOut, SSFCStrIn_t clientId,
                             size_t clientIdSize, SSFCStrIn_t usernameOpt, size_t usernameSize,
                             const uint8_t *passwordOpt, size_t passwordLen,
                             uint16_t keepAliveSec);
void SSFMQTTPktEncodePublish(uint8_t *buf, size_t size, size_t *lenOut, SSFCStrIn_t topic,
                             size_t topicSize, const uint8_t *payload, size_t payloadLen,
                             SSFMQTTCQoS_t qos, uint16_t packetId);
void SSFMQTTPktEncodeSubscribe(uint8_t *buf, size_t size, size_t *lenOut, uint16_t packetId,
                               const SSFMQTTPktSub_t *subs, uint32_t count, size_t filterSize);
void SSFMQTTPktEncodePubAck(uint8_t *buf, size_t size, size_t *lenOut, uint16_t packetId);
void SSFMQTTPktEncodePingReq(uint8_t *buf, size_t size, size_t *lenOut);
void SSFMQTTPktEncodeDisconnect(uint8_t *buf, size_t size, size_t *lenOut);

/* Encoded length of a PUBLISH with a valid topic of topicLen bytes, so a caller can refuse one  */
/* that will not fit its buffer before encoding. Returns 0 if it would exceed the protocol max. */
size_t SSFMQTTPktPublishLen(size_t topicLen, size_t payloadLen, SSFMQTTCQoS_t qos);

/* Decoders. pkt/pktLen delimit exactly one complete packet of the named type. */
bool SSFMQTTPktDecodeConnAck(const uint8_t *pkt, size_t pktLen, bool *sessionPresentOut,
                             uint8_t *codeOut);
bool SSFMQTTPktDecodeSubAck(const uint8_t *pkt, size_t pktLen, uint16_t *packetIdOut,
                            uint8_t *codes, size_t codesSize, uint32_t *countOut);
bool SSFMQTTPktDecodePubAck(const uint8_t *pkt, size_t pktLen, uint16_t *packetIdOut);
bool SSFMQTTPktDecodePublish(const uint8_t *pkt, size_t pktLen, SSFMQTTPktPublish_t *pubOut);

/* Validation: encodable, meaning NUL terminated within size and 1..65535 bytes. Wildcard syntax */
/* is not checked (see the design notes), so a filter is validated exactly like a topic name.    */
bool SSFMQTTPktIsValidTopic(SSFCStrIn_t topic, size_t topicSize);
#define SSFMQTTPktIsValidFilter(filter, filterSize) SSFMQTTPktIsValidTopic((filter), (filterSize))

#if SSF_CONFIG_MQTTPKT_UNIT_TEST == 1
void SSFMQTTPktUnitTest(void);
#endif /* SSF_CONFIG_MQTTPKT_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_MQTTPKT_H_INCLUDE */
