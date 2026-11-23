/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmqttpkt.c                                                                                  */
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfmqttpkt.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MQTT_PROTOCOL_NAME           "MQTT"
#define SSF_MQTT_PROTOCOL_LEVEL          (4u)           /* 3.1.1 */

/* CONNECT flags */
#define SSF_MQTT_CONNECT_FLAG_CLEAN      (0x02u)
#define SSF_MQTT_CONNECT_FLAG_PASSWORD   (0x40u)
#define SSF_MQTT_CONNECT_FLAG_USERNAME   (0x80u)

/* PUBLISH fixed header flags */
#define SSF_MQTT_PUBLISH_FLAG_RETAIN     (0x01u)
#define SSF_MQTT_PUBLISH_QOS_SHIFT       (1u)
#define SSF_MQTT_PUBLISH_QOS_MASK        (0x06u)
#define SSF_MQTT_PUBLISH_FLAG_DUP        (0x08u)

#define SSF_MQTT_SUBSCRIBE_FLAGS         (0x02u)        /* Mandatory reserved bits */
#define SSF_MQTT_FLAGS_MASK              (0x0Fu)

/* Remaining length is a variable length integer: 7 value bits per byte, top bit set when another */
/* byte follows. One byte therefore covers 0..127.                                                */
#define SSF_MQTT_VLI_BITS                (7u)
#define SSF_MQTT_VLI_BASE                (1u << SSF_MQTT_VLI_BITS)          /* 128 */
#define SSF_MQTT_VLI_VALUE_MASK          ((uint8_t)(SSF_MQTT_VLI_BASE - 1u)) /* 0x7F */
#define SSF_MQTT_VLI_CONTINUE            ((uint8_t)SSF_MQTT_VLI_BASE)        /* 0x80 */

/* --------------------------------------------------------------------------------------------- */
/* Local types                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Bounded writer over the caller's buffer. The body is written from offset 0; _SSFMQTTPktWriterFinish()  */
/* then derives the remaining length from what was written, shifts the body up and prepends the */
/* fixed header, so no encoder computes a length twice. Overflow is recorded during writes and   */
/* asserted once at finish.                                                                      */
typedef struct
{
    uint8_t *buf;
    size_t size;
    size_t len;
    bool isOverflow;
} SSFMQTTPktWriter_t;

/* --------------------------------------------------------------------------------------------- */
/* Helpers: writer                                                                               */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Initializes a writer over buf.                                                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktWriterInit(SSFMQTTPktWriter_t *w, uint8_t *buf, size_t size)
{
    SSF_REQUIRE(w != NULL);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);

    w->buf = buf;
    w->size = size;
    w->len = 0;
    w->isOverflow = false;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends one byte, recording overflow instead of writing past size.                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktPutU8(SSFMQTTPktWriter_t *w, uint8_t v)
{
    SSF_REQUIRE(w != NULL);

    if (w->len < w->size) w->buf[w->len] = v;
    else w->isOverflow = true;
    w->len++;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends a 16-bit big endian value.                                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktPutU16(SSFMQTTPktWriter_t *w, uint16_t v)
{
    SSF_REQUIRE(w != NULL);

    _SSFMQTTPktPutU8(w, (uint8_t)(v >> 8));
    _SSFMQTTPktPutU8(w, (uint8_t)(v & 0xFFu));
}

/* --------------------------------------------------------------------------------------------- */
/* Appends n bytes.                                                                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktPutBytes(SSFMQTTPktWriter_t *w, const uint8_t *p, size_t n)
{
    SSF_REQUIRE(w != NULL);
    SSF_REQUIRE((p != NULL) || (n == 0));

    if ((n > 0) && ((w->len + n) <= w->size)) memcpy(&w->buf[w->len], p, n);
    else if (n > 0) w->isOverflow = true;
    w->len += n;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends a 16-bit big endian length followed by n bytes.                                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktPutField(SSFMQTTPktWriter_t *w, const uint8_t *p, size_t n)
{
    SSF_REQUIRE(w != NULL);
    SSF_REQUIRE((p != NULL) || (n == 0));

    _SSFMQTTPktPutU16(w, (uint16_t)n);
    _SSFMQTTPktPutBytes(w, p, n);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the length of a NUL terminated string field; asserts if unterminated or too long.     */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFMQTTPktFieldLen(SSFCStrIn_t cstr, size_t cstrSize)
{
    size_t len;

    SSF_REQUIRE(cstr != NULL);
    SSF_REQUIRE(cstrSize > 0);
    SSF_REQUIRE(SSFStrLen(cstr, cstrSize, &len));
    SSF_REQUIRE(len <= SSF_MQTT_PKT_MAX_STRING_LEN);
    return len;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the fixed header length for a remaining length.                                       */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFMQTTPktFixedHeaderLen(size_t remaining)
{
    size_t n = 2;

    SSF_REQUIRE(remaining <= SSF_MQTT_PKT_MAX_REMAINING_LEN);

    while (remaining >= SSF_MQTT_VLI_BASE) { remaining >>= SSF_MQTT_VLI_BITS; n++; }
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the fixed header length after writing it at p.                                        */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFMQTTPktWriteFixedHeader(uint8_t *p, SSFMQTTPktType_t type, uint8_t flags,
                                size_t remaining)
{
    size_t n = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(remaining <= SSF_MQTT_PKT_MAX_REMAINING_LEN);

    p[n++] = (uint8_t)(((uint8_t)type << 4) | (flags & SSF_MQTT_FLAGS_MASK));
    do
    {
        uint8_t b = (uint8_t)(remaining & SSF_MQTT_VLI_VALUE_MASK);
        remaining >>= SSF_MQTT_VLI_BITS;
        if (remaining > 0) b |= SSF_MQTT_VLI_CONTINUE;
        p[n++] = b;
    } while (remaining > 0);
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Prepends the fixed header to the written body and sets *lenOut to the packet length.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktWriterFinish(SSFMQTTPktWriter_t *w, SSFMQTTPktType_t type, uint8_t flags,
                          size_t *lenOut)
{
    size_t remaining;
    size_t hdrLen;

    SSF_REQUIRE(w != NULL);
    SSF_REQUIRE(lenOut != NULL);

    remaining = w->len;
    SSF_ASSERT(w->isOverflow == false);
    SSF_ASSERT(remaining <= SSF_MQTT_PKT_MAX_REMAINING_LEN);
    hdrLen = _SSFMQTTPktFixedHeaderLen(remaining);
    SSF_ASSERT((hdrLen + remaining) <= w->size);

    if (remaining > 0) memmove(&w->buf[hdrLen], w->buf, remaining);
    (void)_SSFMQTTPktWriteFixedHeader(w->buf, type, flags, remaining);
    *lenOut = hdrLen + remaining;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the frame state of buf, outputting header and remaining lengths once they are known.  */
/* --------------------------------------------------------------------------------------------- */
static SSFMQTTPktFrame_t _SSFMQTTPktParseFixedHeader(const uint8_t *buf, size_t len, size_t *hdrLenOut,
                                           size_t *remainingOut)
{
    size_t remaining = 0;
    uint32_t mult = 1;
    size_t i;

    SSF_REQUIRE((buf != NULL) || (len == 0));
    SSF_REQUIRE(hdrLenOut != NULL);
    SSF_REQUIRE(remainingOut != NULL);

    *hdrLenOut = 0;
    *remainingOut = 0;
    if (len == 0) return SSF_MQTT_PKT_FRAME_INCOMPLETE;
    if ((SSF_MQTT_PKT_TYPE(buf[0]) == SSF_MQTT_PKT_RESERVED_0) ||
        (SSF_MQTT_PKT_TYPE(buf[0]) == SSF_MQTT_PKT_RESERVED_15))
    { return SSF_MQTT_PKT_FRAME_MALFORMED; }

    for (i = 1; i < SSF_MQTT_PKT_MAX_FIXED_HDR_LEN; i++)
    {
        if (i >= len) return SSF_MQTT_PKT_FRAME_INCOMPLETE;
        remaining += (size_t)(buf[i] & SSF_MQTT_VLI_VALUE_MASK) * mult;
        if ((buf[i] & SSF_MQTT_VLI_CONTINUE) == 0) break;
        mult *= SSF_MQTT_VLI_BASE;
    }
    if (i >= SSF_MQTT_PKT_MAX_FIXED_HDR_LEN) return SSF_MQTT_PKT_FRAME_MALFORMED;

    *hdrLenOut = i + 1;
    *remainingOut = remaining;
    return ((*hdrLenOut + remaining) <= len) ? SSF_MQTT_PKT_FRAME_COMPLETE :
                                               SSF_MQTT_PKT_FRAME_INCOMPLETE;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pkt is one complete packet of type with the given flags, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTPktCheckPacket(const uint8_t *pkt, size_t pktLen, SSFMQTTPktType_t type,
                         uint8_t flags, uint8_t flagsMask, size_t *bodyOut, size_t *remainingOut)
{
    size_t hdrLen;
    size_t remaining;

    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);
    SSF_REQUIRE(bodyOut != NULL);
    SSF_REQUIRE(remainingOut != NULL);

    if (SSF_MQTT_PKT_TYPE(pkt[0]) != type) return false;
    if ((pkt[0] & flagsMask) != (flags & flagsMask)) return false;
    if (_SSFMQTTPktParseFixedHeader(pkt, pktLen, &hdrLen, &remaining) != SSF_MQTT_PKT_FRAME_COMPLETE)
    { return false; }
    if ((hdrLen + remaining) != pktLen) return false;
    *bodyOut = hdrLen;
    *remainingOut = remaining;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the 16-bit big endian value at p.                                                     */
/* --------------------------------------------------------------------------------------------- */
static uint16_t _SSFMQTTPktGetU16(const uint8_t *p)
{
    SSF_REQUIRE(p != NULL);

    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if len is a legal topic or filter length, else false.                            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTPktIsTopicLenOk(size_t len)
{
    return (len >= 1) && (len <= SSF_MQTT_PKT_MAX_STRING_LEN);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if an inbound topic has a legal length and no embedded NUL, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTPktIsInboundTopicOk(const uint8_t *t, size_t len)
{
    size_t i;

    SSF_REQUIRE((t != NULL) || (len == 0));

    if (_SSFMQTTPktIsTopicLenOk(len) == false) return false;
    for (i = 0; i < len; i++) { if (t[i] == 0) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Framing                                                                                       */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Returns the frame state of buf and sets *pktLenOut to the packet length when known.           */
/* --------------------------------------------------------------------------------------------- */
SSFMQTTPktFrame_t SSFMQTTPktFrame(const uint8_t *buf, size_t len, size_t *pktLenOut)
{
    size_t hdrLen;
    size_t remaining;
    SSFMQTTPktFrame_t fr;

    SSF_REQUIRE((buf != NULL) || (len == 0));
    SSF_REQUIRE(pktLenOut != NULL);

    fr = _SSFMQTTPktParseFixedHeader(buf, len, &hdrLen, &remaining);
    *pktLenOut = (hdrLen == 0) ? 0 : (hdrLen + remaining);
    return fr;
}

/* --------------------------------------------------------------------------------------------- */
/* Encoders                                                                                      */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Encodes a CONNECT packet.                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTPktEncodeConnect(uint8_t *buf, size_t size, size_t *lenOut, SSFCStrIn_t clientId,
                             size_t clientIdSize, SSFCStrIn_t usernameOpt, size_t usernameSize,
                             const uint8_t *passwordOpt, size_t passwordLen,
                             uint16_t keepAliveSec)
{
    SSFMQTTPktWriter_t w;
    uint8_t flags = SSF_MQTT_CONNECT_FLAG_CLEAN;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(lenOut != NULL);
    SSF_REQUIRE(clientId != NULL);
    SSF_REQUIRE((passwordOpt == NULL) || (usernameOpt != NULL));
    SSF_REQUIRE((passwordOpt != NULL) || (passwordLen == 0));
    SSF_REQUIRE(passwordLen <= SSF_MQTT_PKT_MAX_STRING_LEN);

    if (usernameOpt != NULL) flags |= SSF_MQTT_CONNECT_FLAG_USERNAME;
    if (passwordOpt != NULL) flags |= SSF_MQTT_CONNECT_FLAG_PASSWORD;

    _SSFMQTTPktWriterInit(&w, buf, size);
    _SSFMQTTPktPutField(&w, (const uint8_t *)SSF_MQTT_PROTOCOL_NAME, sizeof(SSF_MQTT_PROTOCOL_NAME) - 1);
    _SSFMQTTPktPutU8(&w, SSF_MQTT_PROTOCOL_LEVEL);
    _SSFMQTTPktPutU8(&w, flags);
    _SSFMQTTPktPutU16(&w, keepAliveSec);
    _SSFMQTTPktPutField(&w, (const uint8_t *)clientId, _SSFMQTTPktFieldLen(clientId, clientIdSize));
    if (usernameOpt != NULL)
    { _SSFMQTTPktPutField(&w, (const uint8_t *)usernameOpt, _SSFMQTTPktFieldLen(usernameOpt, usernameSize)); }
    if (passwordOpt != NULL) _SSFMQTTPktPutField(&w, passwordOpt, passwordLen);
    _SSFMQTTPktWriterFinish(&w, SSF_MQTT_PKT_CONNECT, 0, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the encoded PUBLISH length, or 0 if it exceeds the protocol maximum.                  */
/* --------------------------------------------------------------------------------------------- */
size_t SSFMQTTPktPublishLen(size_t topicLen, size_t payloadLen, SSFMQTTCQoS_t qos)
{
    size_t remaining;

    SSF_REQUIRE((topicLen >= 1) && (topicLen <= SSF_MQTT_PKT_MAX_STRING_LEN));
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (qos == SSF_MQTTC_QOS_1));

    remaining = 2 + topicLen + payloadLen;
    if (qos != SSF_MQTTC_QOS_0) remaining += 2;
    if (remaining > SSF_MQTT_PKT_MAX_REMAINING_LEN) return 0;
    return _SSFMQTTPktFixedHeaderLen(remaining) + remaining;
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a PUBLISH packet.                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTPktEncodePublish(uint8_t *buf, size_t size, size_t *lenOut, SSFCStrIn_t topic,
                             size_t topicSize, const uint8_t *payload, size_t payloadLen,
                             SSFMQTTCQoS_t qos, uint16_t packetId)
{
    SSFMQTTPktWriter_t w;
    uint8_t flags;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(lenOut != NULL);
    SSF_REQUIRE(topic != NULL);
    SSF_REQUIRE((payload != NULL) || (payloadLen == 0));
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (qos == SSF_MQTTC_QOS_1));
    SSF_REQUIRE((qos == SSF_MQTTC_QOS_0) || (packetId != 0));
    SSF_REQUIRE(SSFMQTTPktIsValidTopic(topic, topicSize));

    flags = (uint8_t)((uint8_t)qos << SSF_MQTT_PUBLISH_QOS_SHIFT);   /* No DUP, no RETAIN */
    _SSFMQTTPktWriterInit(&w, buf, size);
    _SSFMQTTPktPutField(&w, (const uint8_t *)topic, _SSFMQTTPktFieldLen(topic, topicSize));
    if (qos != SSF_MQTTC_QOS_0) _SSFMQTTPktPutU16(&w, packetId);
    _SSFMQTTPktPutBytes(&w, payload, payloadLen);
    _SSFMQTTPktWriterFinish(&w, SSF_MQTT_PKT_PUBLISH, flags, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a SUBSCRIBE packet.                                                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTPktEncodeSubscribe(uint8_t *buf, size_t size, size_t *lenOut, uint16_t packetId,
                               const SSFMQTTPktSub_t *subs, uint32_t count, size_t filterSize)
{
    SSFMQTTPktWriter_t w;
    uint32_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(lenOut != NULL);
    SSF_REQUIRE(packetId != 0);
    SSF_REQUIRE(subs != NULL);
    SSF_REQUIRE(count >= 1);
    SSF_REQUIRE(filterSize > 0);

    _SSFMQTTPktWriterInit(&w, buf, size);
    _SSFMQTTPktPutU16(&w, packetId);
    for (i = 0; i < count; i++)
    {
        SSF_REQUIRE((subs[i].qos == SSF_MQTTC_QOS_0) || (subs[i].qos == SSF_MQTTC_QOS_1));
        SSF_REQUIRE(SSFMQTTPktIsValidFilter(subs[i].filter, filterSize));
        _SSFMQTTPktPutField(&w, (const uint8_t *)subs[i].filter,
                            _SSFMQTTPktFieldLen(subs[i].filter, filterSize));
        _SSFMQTTPktPutU8(&w, (uint8_t)subs[i].qos);
    }
    _SSFMQTTPktWriterFinish(&w, SSF_MQTT_PKT_SUBSCRIBE, SSF_MQTT_SUBSCRIBE_FLAGS, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a PUBACK packet.                                                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTPktEncodePubAck(uint8_t *buf, size_t size, size_t *lenOut, uint16_t packetId)
{
    SSFMQTTPktWriter_t w;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(lenOut != NULL);
    SSF_REQUIRE(packetId != 0);

    _SSFMQTTPktWriterInit(&w, buf, size);
    _SSFMQTTPktPutU16(&w, packetId);
    _SSFMQTTPktWriterFinish(&w, SSF_MQTT_PKT_PUBACK, 0, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a PINGREQ packet.                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTPktEncodePingReq(uint8_t *buf, size_t size, size_t *lenOut)
{
    SSFMQTTPktWriter_t w;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(lenOut != NULL);

    _SSFMQTTPktWriterInit(&w, buf, size);
    _SSFMQTTPktWriterFinish(&w, SSF_MQTT_PKT_PINGREQ, 0, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a DISCONNECT packet.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTPktEncodeDisconnect(uint8_t *buf, size_t size, size_t *lenOut)
{
    SSFMQTTPktWriter_t w;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(lenOut != NULL);

    _SSFMQTTPktWriterInit(&w, buf, size);
    _SSFMQTTPktWriterFinish(&w, SSF_MQTT_PKT_DISCONNECT, 0, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Decoders                                                                                      */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pkt is a well formed CONNACK and outputs its fields, else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTPktDecodeConnAck(const uint8_t *pkt, size_t pktLen, bool *sessionPresentOut,
                             uint8_t *codeOut)
{
    size_t body;
    size_t remaining;

    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);
    SSF_REQUIRE(sessionPresentOut != NULL);
    SSF_REQUIRE(codeOut != NULL);

    if (_SSFMQTTPktCheckPacket(pkt, pktLen, SSF_MQTT_PKT_CONNACK, 0, SSF_MQTT_FLAGS_MASK, &body,
                      &remaining) == false)
    { return false; }
    if (remaining != 2) return false;
    if ((pkt[body] & 0xFEu) != 0) return false;      /* Connect Acknowledge Flags reserved bits */
    *sessionPresentOut = ((pkt[body] & 0x01u) != 0);
    *codeOut = pkt[body + 1];
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pkt is a well formed SUBACK and outputs its fields, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTPktDecodeSubAck(const uint8_t *pkt, size_t pktLen, uint16_t *packetIdOut,
                            uint8_t *codes, size_t codesSize, uint32_t *countOut)
{
    size_t body;
    size_t remaining;
    size_t count;
    size_t i;

    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);
    SSF_REQUIRE(packetIdOut != NULL);
    SSF_REQUIRE(codes != NULL);
    SSF_REQUIRE(countOut != NULL);

    if (_SSFMQTTPktCheckPacket(pkt, pktLen, SSF_MQTT_PKT_SUBACK, 0, SSF_MQTT_FLAGS_MASK, &body,
                      &remaining) == false)
    { return false; }
    if (remaining < 3) return false;                 /* Packet id and at least one return code */
    count = remaining - 2;
    if (count > codesSize) return false;

    *packetIdOut = _SSFMQTTPktGetU16(&pkt[body]);
    if (*packetIdOut == 0) return false;
    for (i = 0; i < count; i++)
    {
        uint8_t c = pkt[body + 2 + i];
        if ((c != (uint8_t)SSF_MQTTC_QOS_0) && (c != (uint8_t)SSF_MQTTC_QOS_1) &&
            (c != (uint8_t)SSF_MQTTC_QOS_2) && (c != SSF_MQTT_PKT_SUBACK_FAILURE))
        { return false; }
        codes[i] = c;
    }
    *countOut = (uint32_t)count;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pkt is a well formed PUBACK and outputs its packet id, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTPktDecodePubAck(const uint8_t *pkt, size_t pktLen, uint16_t *packetIdOut)
{
    size_t body;
    size_t remaining;

    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);
    SSF_REQUIRE(packetIdOut != NULL);

    if (_SSFMQTTPktCheckPacket(pkt, pktLen, SSF_MQTT_PKT_PUBACK, 0, SSF_MQTT_FLAGS_MASK, &body,
                      &remaining) == false)
    { return false; }
    if (remaining != 2) return false;
    *packetIdOut = _SSFMQTTPktGetU16(&pkt[body]);
    return (*packetIdOut != 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pkt is a well formed PUBLISH and fills pubOut, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTPktDecodePublish(const uint8_t *pkt, size_t pktLen, SSFMQTTPktPublish_t *pubOut)
{
    size_t body;
    size_t remaining;
    size_t end;
    size_t pos;
    uint8_t qosBits;

    SSF_REQUIRE(pkt != NULL);
    SSF_REQUIRE(pktLen > 0);
    SSF_REQUIRE(pubOut != NULL);

    /* Flags are data for PUBLISH, so none are checked here */
    if (_SSFMQTTPktCheckPacket(pkt, pktLen, SSF_MQTT_PKT_PUBLISH, 0, 0, &body, &remaining) == false) return false;
    end = body + remaining;

    qosBits = (uint8_t)((pkt[0] & SSF_MQTT_PUBLISH_QOS_MASK) >> SSF_MQTT_PUBLISH_QOS_SHIFT);
    if (qosBits > (uint8_t)SSF_MQTTC_QOS_2) return false;              /* QoS 3 is malformed */
    pubOut->qos = (SSFMQTTCQoS_t)qosBits;
    pubOut->retain = ((pkt[0] & SSF_MQTT_PUBLISH_FLAG_RETAIN) != 0);
    pubOut->dup = ((pkt[0] & SSF_MQTT_PUBLISH_FLAG_DUP) != 0);
    if ((pubOut->qos == SSF_MQTTC_QOS_0) && pubOut->dup) return false;   /* DUP must be 0 at QoS 0 */

    /* Topic name */
    pos = body;
    if ((end - pos) < 2) return false;
    pubOut->topicLen = _SSFMQTTPktGetU16(&pkt[pos]);
    pos += 2;
    if ((end - pos) < pubOut->topicLen) return false;
    pubOut->topic = &pkt[pos];
    if (_SSFMQTTPktIsInboundTopicOk(pubOut->topic, pubOut->topicLen) == false) return false;
    pos += pubOut->topicLen;

    /* Packet identifier, QoS 1 and 2 only */
    pubOut->packetId = 0;
    if (pubOut->qos != SSF_MQTTC_QOS_0)
    {
        if ((end - pos) < 2) return false;
        pubOut->packetId = _SSFMQTTPktGetU16(&pkt[pos]);
        if (pubOut->packetId == 0) return false;
        pos += 2;
    }

    /* Payload is the rest */
    pubOut->payloadLen = end - pos;
    pubOut->payload = (pubOut->payloadLen > 0) ? &pkt[pos] : NULL;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Validation                                                                                    */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if topic is NUL terminated within topicSize and 1..65535 bytes, else false.      */
/* --------------------------------------------------------------------------------------------- */
bool SSFMQTTPktIsValidTopic(SSFCStrIn_t topic, size_t topicSize)
{
    size_t len;

    SSF_REQUIRE(topic != NULL);
    SSF_REQUIRE(topicSize > 0);

    if (SSFStrLen(topic, topicSize, &len) == false) return false;
    return _SSFMQTTPktIsTopicLenOk(len);
}
