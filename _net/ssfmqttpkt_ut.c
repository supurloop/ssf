/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmqttpkt_ut.c                                                                               */
/* Unit test for MQTT 3.1.1 control packet framing, encoding and decoding.                       */
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
#include "ssfmqttpkt.h"

#if SSF_CONFIG_MQTTPKT_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* Local defines and data                                                                        */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MQTTPKT_UT_BUF_SIZE          (256u)
#define SSF_MQTTPKT_UT_BIG_PAYLOAD_LEN   (126u)         /* Pushes remaining length to 2 bytes */

static uint8_t _utBuf[SSF_MQTTPKT_UT_BUF_SIZE];
static size_t _utLen;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if buf equals expected and frames as exactly one complete packet, else false.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMQTTPktUTIsPacket(const uint8_t *buf, size_t len, const uint8_t *expected,
                                  size_t expectedLen)
{
    size_t pktLen;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(expected != NULL);

    if (len != expectedLen) return false;
    if (memcmp(buf, expected, len) != 0) return false;
    if (SSFMQTTPktFrame(buf, len, &pktLen) != SSF_MQTT_PKT_FRAME_COMPLETE) return false;
    return (pktLen == len);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests SSFMQTTPktFrame() over partial, complete, malformed and multi-byte length headers.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTFrame(void)
{
    static const uint8_t ping[] = { 0xC0, 0x00 };
    static const uint8_t pingPlus[] = { 0xC0, 0x00, 0xD0 };                 /* Next packet starts */
    static const uint8_t type0[] = { 0x00, 0x00 };
    static const uint8_t type15[] = { 0xF0, 0x00 };
    static const uint8_t partial[] = { 0x30, 0x05, 0x00, 0x01, 0x61 };      /* 3 of 5 body bytes */
    static const uint8_t vli2[] = { 0x30, 0x80, 0x01 };                     /* Remaining 128 */
    static const uint8_t vli3[] = { 0x30, 0x80, 0x80, 0x01 };               /* Remaining 16384 */
    static const uint8_t vli4[] = { 0x30, 0xFF, 0xFF, 0xFF, 0x7F };         /* Remaining max */
    static const uint8_t vli5[] = { 0x30, 0x80, 0x80, 0x80, 0x80 };         /* Needs a 5th byte */
    uint8_t big[131];
    size_t pktLen;

    SSF_ASSERT_TEST((void)SSFMQTTPktFrame(NULL, 1, &pktLen));
    SSF_ASSERT_TEST((void)SSFMQTTPktFrame(ping, sizeof(ping), NULL));

    /* Nothing yet */
    pktLen = 99;
    SSF_ASSERT(SSFMQTTPktFrame(NULL, 0, &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 0);
    SSF_ASSERT(SSFMQTTPktFrame(ping, 1, &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 0);

    /* Minimal packets, alone and followed by the start of another */
    SSF_ASSERT(SSFMQTTPktFrame(ping, sizeof(ping), &pktLen) == SSF_MQTT_PKT_FRAME_COMPLETE);
    SSF_ASSERT(pktLen == 2);
    SSF_ASSERT(SSFMQTTPktFrame(pingPlus, sizeof(pingPlus), &pktLen) == SSF_MQTT_PKT_FRAME_COMPLETE);
    SSF_ASSERT(pktLen == 2);

    /* Reserved types are judged on the first byte, before any length byte */
    SSF_ASSERT(SSFMQTTPktFrame(type0, sizeof(type0), &pktLen) == SSF_MQTT_PKT_FRAME_MALFORMED);
    SSF_ASSERT(pktLen == 0);
    SSF_ASSERT(SSFMQTTPktFrame(type0, 1, &pktLen) == SSF_MQTT_PKT_FRAME_MALFORMED);
    SSF_ASSERT(SSFMQTTPktFrame(type15, sizeof(type15), &pktLen) == SSF_MQTT_PKT_FRAME_MALFORMED);
    SSF_ASSERT(pktLen == 0);

    /* Complete header, partial body: total length is known early */
    SSF_ASSERT(SSFMQTTPktFrame(partial, sizeof(partial), &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 7);
    SSF_ASSERT(SSFMQTTPktFrame(partial, 2, &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 7);

    /* Two byte remaining length, partial and complete */
    SSF_ASSERT(SSFMQTTPktFrame(vli2, 2, &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 0);
    SSF_ASSERT(SSFMQTTPktFrame(vli2, sizeof(vli2), &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 131);
    memset(big, 0, sizeof(big));
    memcpy(big, vli2, sizeof(vli2));
    SSF_ASSERT(SSFMQTTPktFrame(big, sizeof(big) - 1, &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 131);
    SSF_ASSERT(SSFMQTTPktFrame(big, sizeof(big), &pktLen) == SSF_MQTT_PKT_FRAME_COMPLETE);
    SSF_ASSERT(pktLen == 131);

    /* Three and four byte remaining lengths */
    SSF_ASSERT(SSFMQTTPktFrame(vli3, sizeof(vli3), &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 16388);
    SSF_ASSERT(SSFMQTTPktFrame(vli4, sizeof(vli4), &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == (SSF_MQTT_PKT_MAX_REMAINING_LEN + SSF_MQTT_PKT_MAX_FIXED_HDR_LEN));

    /* A continuation bit on the fourth length byte is malformed, but only once it is seen */
    SSF_ASSERT(SSFMQTTPktFrame(vli5, 4, &pktLen) == SSF_MQTT_PKT_FRAME_INCOMPLETE);
    SSF_ASSERT(pktLen == 0);
    SSF_ASSERT(SSFMQTTPktFrame(vli5, sizeof(vli5), &pktLen) == SSF_MQTT_PKT_FRAME_MALFORMED);
    SSF_ASSERT(pktLen == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the PINGREQ, DISCONNECT and PUBACK encoders, including exact fit and no fit.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTEncodeSimple(void)
{
    static const uint8_t ping[] = { 0xC0, 0x00 };
    static const uint8_t disc[] = { 0xE0, 0x00 };
    static const uint8_t pubAck[] = { 0x40, 0x02, 0x12, 0x34 };

    SSF_ASSERT_TEST(SSFMQTTPktEncodePingReq(NULL, sizeof(_utBuf), &_utLen));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePingReq(_utBuf, 0, &_utLen));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePingReq(_utBuf, sizeof(_utBuf), NULL));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePingReq(_utBuf, sizeof(ping) - 1, &_utLen));
    SSFMQTTPktEncodePingReq(_utBuf, sizeof(ping), &_utLen);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, ping, sizeof(ping)));
    SSFMQTTPktEncodePingReq(_utBuf, sizeof(_utBuf), &_utLen);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, ping, sizeof(ping)));

    SSF_ASSERT_TEST(SSFMQTTPktEncodeDisconnect(NULL, sizeof(_utBuf), &_utLen));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeDisconnect(_utBuf, 0, &_utLen));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeDisconnect(_utBuf, sizeof(_utBuf), NULL));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeDisconnect(_utBuf, sizeof(disc) - 1, &_utLen));
    SSFMQTTPktEncodeDisconnect(_utBuf, sizeof(disc), &_utLen);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, disc, sizeof(disc)));
    SSFMQTTPktEncodeDisconnect(_utBuf, sizeof(_utBuf), &_utLen);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, disc, sizeof(disc)));

    SSF_ASSERT_TEST(SSFMQTTPktEncodePubAck(NULL, sizeof(_utBuf), &_utLen, 0x1234));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePubAck(_utBuf, 0, &_utLen, 0x1234));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePubAck(_utBuf, sizeof(_utBuf), NULL, 0x1234));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePubAck(_utBuf, sizeof(_utBuf), &_utLen, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePubAck(_utBuf, sizeof(pubAck) - 1, &_utLen, 0x1234));
    SSFMQTTPktEncodePubAck(_utBuf, sizeof(pubAck), &_utLen, 0x1234);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, pubAck, sizeof(pubAck)));
    SSFMQTTPktEncodePubAck(_utBuf, sizeof(_utBuf), &_utLen, 0x1234);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, pubAck, sizeof(pubAck)));
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the CONNECT encoder with and without credentials and with an empty client id.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTEncodeConnect(void)
{
    static const char id[] = "abc";
    static const char user[] = "u";
    static const uint8_t pass[] = { 0x01, 0x02 };
    static const char willTopic[] = "w/t";
    static const uint8_t willMsg[] = { 'x', 'y' };
    static const SSFMQTTPktWill_t will1R = { willTopic, willMsg, sizeof(willMsg), SSF_MQTTC_QOS_1,
                                             true };
    static const SSFMQTTPktWill_t will0 = { willTopic, NULL, 0, SSF_MQTTC_QOS_0, false };
    static const uint8_t noAuth[] = {
        0x10, 0x0F, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x03, 'a', 'b',
        'c' };
    static const uint8_t userOnly[] = {
        0x10, 0x12, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x82, 0x00, 0x3C, 0x00, 0x03, 'a', 'b',
        'c', 0x00, 0x01, 'u' };
    static const uint8_t userPass[] = {
        0x10, 0x16, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0xC2, 0xFF, 0xFF, 0x00, 0x03, 'a', 'b',
        'c', 0x00, 0x01, 'u', 0x00, 0x02, 0x01, 0x02 };
    static const uint8_t emptyId[] = {
        0x10, 0x0C, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00 };
    /* Will QoS 1 + retain: flags 0x02 | 0x04 | (1 << 3) | 0x20 = 0x2E; will after client id */
    static const uint8_t will1RNoAuth[] = {
        0x10, 0x18, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x2E, 0x00, 0x3C, 0x00, 0x03, 'a', 'b',
        'c', 0x00, 0x03, 'w', '/', 't', 0x00, 0x02, 'x', 'y' };
    /* Will before username and password (3.1.3) */
    static const uint8_t will1RUserPass[] = {
        0x10, 0x1F, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0xEE, 0x00, 0x3C, 0x00, 0x03, 'a', 'b',
        'c', 0x00, 0x03, 'w', '/', 't', 0x00, 0x02, 'x', 'y', 0x00, 0x01, 'u', 0x00, 0x02, 0x01,
        0x02 };
    /* Will QoS 0, no retain, empty message: flags 0x06, message field 00 00 */
    static const uint8_t will0NoAuth[] = {
        0x10, 0x16, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x06, 0x00, 0x3C, 0x00, 0x03, 'a', 'b',
        'c', 0x00, 0x03, 'w', '/', 't', 0x00, 0x00 };
    SSFMQTTPktWill_t bad;

    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(NULL, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL,
                                            0, NULL, 0, NULL, 0, 60));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, 0, &_utLen, id, sizeof(id), NULL, 0, NULL, 0,
                                            NULL, 0, 60));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), NULL, id, sizeof(id), NULL, 0,
                                            NULL, 0, NULL, 0, 60));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, NULL, sizeof(id),
                                            NULL, 0, NULL, 0, NULL, 0, 60));
    /* Password without username */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL,
                                            0, NULL, 0, pass, sizeof(pass), 60));
    /* Password length without password */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL,
                                            0, user, sizeof(user), NULL, sizeof(pass), 60));
    /* Password too long for a field */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL,
                                            0, user, sizeof(user), pass,
                                            SSF_MQTT_PKT_MAX_STRING_LEN + 1, 60));
    /* Unterminated client id and username */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id) - 1,
                                            NULL, 0, NULL, 0, NULL, 0, 60));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL,
                                            0, user, sizeof(user) - 1, NULL, 0, 60));
    /* Does not fit by one byte */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(noAuth) - 1, &_utLen, id, sizeof(id),
                                            NULL, 0, NULL, 0, NULL, 0, 60));

    /* Will arguments: unterminated or empty topic, NULL topic, QoS 2, length without message */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id),
                                            &will1R, sizeof(willTopic) - 1, NULL, 0, NULL, 0, 60));
    bad = will1R; bad.topic = "";
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), &bad,
                                            sizeof(willTopic), NULL, 0, NULL, 0, 60));
    bad = will1R; bad.topic = NULL;
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), &bad,
                                            sizeof(willTopic), NULL, 0, NULL, 0, 60));
    bad = will1R; bad.qos = SSF_MQTTC_QOS_2;
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), &bad,
                                            sizeof(willTopic), NULL, 0, NULL, 0, 60));
    bad = will1R; bad.payloadOpt = NULL;
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), &bad,
                                            sizeof(willTopic), NULL, 0, NULL, 0, 60));
    /* A will that does not fit by one byte */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(will1RNoAuth) - 1, &_utLen, id,
                                            sizeof(id), &will1R, sizeof(willTopic), NULL, 0, NULL,
                                            0, 60));

    SSFMQTTPktEncodeConnect(_utBuf, sizeof(noAuth), &_utLen, id, sizeof(id), NULL, 0, NULL, 0,
                            NULL, 0, 60);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, noAuth, sizeof(noAuth)));
    SSF_ASSERT(SSFMQTTPktConnectLen(id, sizeof(id), NULL, 0, NULL, 0, NULL, 0) == _utLen);
    SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL, 0, NULL, 0,
                            NULL, 0, 60);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, noAuth, sizeof(noAuth)));
    SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL, 0, user,
                            sizeof(user), NULL, 0, 60);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, userOnly, sizeof(userOnly)));
    SSF_ASSERT(SSFMQTTPktConnectLen(id, sizeof(id), NULL, 0, user, sizeof(user), NULL, 0) ==
               _utLen);
    SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL, 0, user,
                            sizeof(user), pass, sizeof(pass), 0xFFFF);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, userPass, sizeof(userPass)));
    SSF_ASSERT(SSFMQTTPktConnectLen(id, sizeof(id), NULL, 0, user, sizeof(user), pass,
                                    sizeof(pass)) == _utLen);
    SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, "", 1, NULL, 0, NULL, 0, NULL, 0,
                            60);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, emptyId, sizeof(emptyId)));
    SSF_ASSERT(SSFMQTTPktConnectLen("", 1, NULL, 0, NULL, 0, NULL, 0) == _utLen);

    /* With a will */
    SSFMQTTPktEncodeConnect(_utBuf, sizeof(will1RNoAuth), &_utLen, id, sizeof(id), &will1R,
                            sizeof(willTopic), NULL, 0, NULL, 0, 60);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, will1RNoAuth, sizeof(will1RNoAuth)));
    SSF_ASSERT(SSFMQTTPktConnectLen(id, sizeof(id), &will1R, sizeof(willTopic), NULL, 0, NULL,
                                    0) == _utLen);
    SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), &will1R,
                            sizeof(willTopic), user, sizeof(user), pass, sizeof(pass), 60);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, will1RUserPass, sizeof(will1RUserPass)));
    SSF_ASSERT(SSFMQTTPktConnectLen(id, sizeof(id), &will1R, sizeof(willTopic), user,
                                    sizeof(user), pass, sizeof(pass)) == _utLen);
    SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), &will0,
                            sizeof(willTopic), NULL, 0, NULL, 0, 60);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, will0NoAuth, sizeof(will0NoAuth)));
    SSF_ASSERT(SSFMQTTPktConnectLen(id, sizeof(id), &will0, sizeof(willTopic), NULL, 0, NULL,
                                    0) == _utLen);

    /* The largest will message */
    {
        static uint8_t bigMsg[SSF_MQTT_PKT_MAX_STRING_LEN];
        SSFMQTTPktWill_t big = { willTopic, bigMsg, SSF_MQTT_PKT_MAX_STRING_LEN,
                                 SSF_MQTTC_QOS_0, false };
        SSF_ASSERT(SSFMQTTPktConnectLen(id, sizeof(id), &big, sizeof(willTopic), NULL, 0, NULL,
                                        0) == (1u + 3u + 10u + 5u + 5u + 2u +
                                               SSF_MQTT_PKT_MAX_STRING_LEN));   /* 3-byte length */
    }

    /* Client id and username: printable ASCII only (the password is binary) */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, "a\tb", 4, NULL, 0,
                                            NULL, 0, NULL, 0, 60));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), NULL,
                                            0, "\x80", 2, NULL, 0, 60));
    SSF_ASSERT_TEST(SSFMQTTPktConnectLen("\x7f", 2, NULL, 0, NULL, 0, NULL, 0));
    SSF_ASSERT_TEST(SSFMQTTPktConnectLen(id, sizeof(id), NULL, 0, "u\x01", 3, NULL, 0));
    {
        static const uint8_t binPass[] = { 0x00, 0x80, 0xFF };
        SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, " ~", 3, NULL, 0, user,
                                sizeof(user), binPass, sizeof(binPass), 60);
        SSF_ASSERT(_utLen == SSFMQTTPktConnectLen(" ~", 3, NULL, 0, user, sizeof(user), binPass,
                                                  sizeof(binPass)));
    }
    /* A will topic follows the topic name rules */
    bad = will1R; bad.topic = "w/+";
    SSF_ASSERT_TEST(SSFMQTTPktEncodeConnect(_utBuf, sizeof(_utBuf), &_utLen, id, sizeof(id), &bad,
                                            sizeof(willTopic) + 1, NULL, 0, NULL, 0, 60));

    /* ConnectLen requires what the encoder requires */
    SSF_ASSERT_TEST(SSFMQTTPktConnectLen(NULL, sizeof(id), NULL, 0, NULL, 0, NULL, 0));
    SSF_ASSERT_TEST(SSFMQTTPktConnectLen(id, sizeof(id), NULL, 0, NULL, 0, pass, sizeof(pass)));
    SSF_ASSERT_TEST(SSFMQTTPktConnectLen(id, sizeof(id), &will1R, sizeof(willTopic) - 1, NULL, 0,
                                         NULL, 0));
    bad = will1R; bad.qos = SSF_MQTTC_QOS_2;
    SSF_ASSERT_TEST(SSFMQTTPktConnectLen(id, sizeof(id), &bad, sizeof(willTopic), NULL, 0, NULL,
                                         0));
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the PUBLISH encoder and length predictor and round trips results through the decoder.   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTEncodePublish(void)
{
    static const char topic[] = "a/b";
    static const char topic1[] = "t";
    static const uint8_t payload[] = { 'h', 'i' };
    static const uint8_t qos0[] = { 0x30, 0x07, 0x00, 0x03, 'a', '/', 'b', 'h', 'i' };
    static const uint8_t qos1[] = { 0x32, 0x09, 0x00, 0x03, 'a', '/', 'b', 0x01, 0x02, 'h', 'i' };
    static const uint8_t empty[] = { 0x30, 0x05, 0x00, 0x03, 'a', '/', 'b' };
    static const uint8_t bigHdr[] = { 0x30, 0x81, 0x01, 0x00, 0x01, 't' };
    uint8_t big[SSF_MQTTPKT_UT_BIG_PAYLOAD_LEN];
    SSFMQTTPktPublish_t pub;
    size_t i;

    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(NULL, sizeof(_utBuf), &_utLen, topic, sizeof(topic),
                                            payload, sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, 0, &_utLen, topic, sizeof(topic), payload,
                                            sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), NULL, topic, sizeof(topic),
                                            payload, sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, NULL, sizeof(topic),
                                            payload, sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic),
                                            NULL, sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic),
                                            payload, sizeof(payload), SSF_MQTTC_QOS_2, false, 1));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic),
                                            payload, sizeof(payload), SSF_MQTTC_QOS_MIN, false,
                                            1));
    /* QoS 1 needs a non-zero packet id */
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic),
                                            payload, sizeof(payload), SSF_MQTTC_QOS_1, false, 0));
    /* Empty and unterminated topics */
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, "", 1, payload,
                                            sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic,
                                            sizeof(topic) - 1, payload, sizeof(payload),
                                            SSF_MQTTC_QOS_0, false, 0));
    /* A wildcard or non-printable character in the topic name */
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, "a/+", 4, payload,
                                            sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, "a\n", 3, payload,
                                            sizeof(payload), SSF_MQTTC_QOS_0, false, 0));
    /* Does not fit by one byte */
    SSF_ASSERT_TEST(SSFMQTTPktEncodePublish(_utBuf, sizeof(qos0) - 1, &_utLen, topic,
                                            sizeof(topic), payload, sizeof(payload),
                                            SSF_MQTTC_QOS_0, false, 0));

    /* QoS 0, exact fit; the packet id is ignored */
    SSFMQTTPktEncodePublish(_utBuf, sizeof(qos0), &_utLen, topic, sizeof(topic), payload,
                            sizeof(payload), SSF_MQTTC_QOS_0, false, 0x5555);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, qos0, sizeof(qos0)));
    SSF_ASSERT(SSFMQTTPktPublishLen(sizeof(topic) - 1, sizeof(payload), SSF_MQTTC_QOS_0) == _utLen);
    SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, _utLen, &pub));
    SSF_ASSERT(pub.qos == SSF_MQTTC_QOS_0);
    SSF_ASSERT(pub.retain == false);
    SSF_ASSERT(pub.dup == false);
    SSF_ASSERT(pub.packetId == 0);
    SSF_ASSERT(pub.topic == &_utBuf[4]);
    SSF_ASSERT(pub.topicLen == (sizeof(topic) - 1));
    SSF_ASSERT(memcmp(pub.topic, topic, pub.topicLen) == 0);
    SSF_ASSERT(pub.payload == &_utBuf[7]);
    SSF_ASSERT(pub.payloadLen == sizeof(payload));
    SSF_ASSERT(memcmp(pub.payload, payload, pub.payloadLen) == 0);

    /* QoS 1 */
    SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic), payload,
                            sizeof(payload), SSF_MQTTC_QOS_1, false, 0x0102);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, qos1, sizeof(qos1)));
    SSF_ASSERT(SSFMQTTPktPublishLen(sizeof(topic) - 1, sizeof(payload), SSF_MQTTC_QOS_1) == _utLen);
    SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, _utLen, &pub));
    SSF_ASSERT(pub.qos == SSF_MQTTC_QOS_1);
    SSF_ASSERT(pub.retain == false);
    SSF_ASSERT(pub.dup == false);
    SSF_ASSERT(pub.packetId == 0x0102);
    SSF_ASSERT(pub.topic == &_utBuf[4]);
    SSF_ASSERT(pub.topicLen == (sizeof(topic) - 1));
    SSF_ASSERT(pub.payload == &_utBuf[9]);
    SSF_ASSERT(pub.payloadLen == sizeof(payload));
    SSF_ASSERT(memcmp(pub.payload, payload, pub.payloadLen) == 0);

    /* Empty payload, NULL pointer allowed */
    SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic), NULL, 0,
                            SSF_MQTTC_QOS_0, false, 0);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, empty, sizeof(empty)));
    SSF_ASSERT(SSFMQTTPktPublishLen(sizeof(topic) - 1, 0, SSF_MQTTC_QOS_0) == _utLen);
    SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, _utLen, &pub));
    SSF_ASSERT(pub.payload == NULL);
    SSF_ASSERT(pub.payloadLen == 0);

    /* RETAIN sets only bit 0 of the first byte, at both QoS levels, and decodes back */
    {
        static const uint8_t qos0R[] = { 0x31, 0x07, 0x00, 0x03, 'a', '/', 'b', 'h', 'i' };
        static const uint8_t qos1R[] = { 0x33, 0x09, 0x00, 0x03, 'a', '/', 'b', 0x01, 0x02,
                                         'h', 'i' };
        static const uint8_t clearR[] = { 0x31, 0x05, 0x00, 0x03, 'a', '/', 'b' };

        SSFMQTTPktEncodePublish(_utBuf, sizeof(qos0R), &_utLen, topic, sizeof(topic), payload,
                                sizeof(payload), SSF_MQTTC_QOS_0, true, 0);
        SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, qos0R, sizeof(qos0R)));
        SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, _utLen, &pub));
        SSF_ASSERT(pub.retain == true);
        SSF_ASSERT(pub.dup == false);
        SSF_ASSERT(pub.qos == SSF_MQTTC_QOS_0);

        SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic), payload,
                                sizeof(payload), SSF_MQTTC_QOS_1, true, 0x0102);
        SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, qos1R, sizeof(qos1R)));
        SSF_ASSERT(SSFMQTTPktPublishLen(sizeof(topic) - 1, sizeof(payload), SSF_MQTTC_QOS_1) ==
                   _utLen);
        SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, _utLen, &pub));
        SSF_ASSERT(pub.retain == true);
        SSF_ASSERT(pub.dup == false);
        SSF_ASSERT(pub.qos == SSF_MQTTC_QOS_1);
        SSF_ASSERT(pub.packetId == 0x0102);

        /* Empty retained payload: the message that clears a retained topic */
        SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic, sizeof(topic), NULL, 0,
                                SSF_MQTTC_QOS_0, true, 0);
        SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, clearR, sizeof(clearR)));
        SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, _utLen, &pub));
        SSF_ASSERT(pub.retain == true);
        SSF_ASSERT(pub.payloadLen == 0);
    }

    /* Payload large enough for a two byte remaining length (2 + 1 + 126 = 129 = 0x81 0x01) */
    for (i = 0; i < sizeof(big); i++) big[i] = (uint8_t)i;
    SSFMQTTPktEncodePublish(_utBuf, sizeof(_utBuf), &_utLen, topic1, sizeof(topic1), big,
                            sizeof(big), SSF_MQTTC_QOS_0, false, 0);
    SSF_ASSERT(_utLen == (sizeof(bigHdr) + sizeof(big)));
    SSF_ASSERT(memcmp(_utBuf, bigHdr, sizeof(bigHdr)) == 0);
    SSF_ASSERT(memcmp(&_utBuf[sizeof(bigHdr)], big, sizeof(big)) == 0);
    SSF_ASSERT(SSFMQTTPktPublishLen(sizeof(topic1) - 1, sizeof(big), SSF_MQTTC_QOS_0) == _utLen);
    SSF_ASSERT(SSFMQTTPktFrame(_utBuf, _utLen, &i) == SSF_MQTT_PKT_FRAME_COMPLETE);
    SSF_ASSERT(i == _utLen);
    SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, _utLen, &pub));
    SSF_ASSERT(pub.topicLen == 1);
    SSF_ASSERT(pub.topic[0] == 't');
    SSF_ASSERT(pub.payloadLen == sizeof(big));
    SSF_ASSERT(memcmp(pub.payload, big, sizeof(big)) == 0);

    /* Length predictor contract and protocol limit */
    SSF_ASSERT_TEST((void)SSFMQTTPktPublishLen(0, 0, SSF_MQTTC_QOS_0));
    SSF_ASSERT_TEST((void)SSFMQTTPktPublishLen(SSF_MQTT_PKT_MAX_STRING_LEN + 1, 0, SSF_MQTTC_QOS_0));
    SSF_ASSERT_TEST((void)SSFMQTTPktPublishLen(1, 0, SSF_MQTTC_QOS_2));
    SSF_ASSERT(SSFMQTTPktPublishLen(1, 0, SSF_MQTTC_QOS_0) == 5);
    SSF_ASSERT(SSFMQTTPktPublishLen(1, 0, SSF_MQTTC_QOS_1) == 7);
    SSF_ASSERT(SSFMQTTPktPublishLen(1, 124, SSF_MQTTC_QOS_0) == 129);        /* Remaining 127 */
    SSF_ASSERT(SSFMQTTPktPublishLen(1, 125, SSF_MQTTC_QOS_0) == 131);        /* Remaining 128 */
    SSF_ASSERT(SSFMQTTPktPublishLen(1, SSF_MQTT_PKT_MAX_REMAINING_LEN - 3, SSF_MQTTC_QOS_0) ==
               (SSF_MQTT_PKT_MAX_REMAINING_LEN + SSF_MQTT_PKT_MAX_FIXED_HDR_LEN));
    SSF_ASSERT(SSFMQTTPktPublishLen(1, SSF_MQTT_PKT_MAX_REMAINING_LEN - 2, SSF_MQTTC_QOS_0) == 0);
    SSF_ASSERT(SSFMQTTPktPublishLen(1, SSF_MQTT_PKT_MAX_REMAINING_LEN - 5, SSF_MQTTC_QOS_1) ==
               (SSF_MQTT_PKT_MAX_REMAINING_LEN + SSF_MQTT_PKT_MAX_FIXED_HDR_LEN));
    SSF_ASSERT(SSFMQTTPktPublishLen(1, SSF_MQTT_PKT_MAX_REMAINING_LEN - 4, SSF_MQTTC_QOS_1) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the SUBSCRIBE encoder with one and several filters.                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTEncodeSubscribe(void)
{
    static const SSFMQTTPktSub_t subs[2] = { { "a/#", SSF_MQTTC_QOS_1 }, { "b", SSF_MQTTC_QOS_0 } };
    static const SSFMQTTPktSub_t badQos[1] = { { "a", SSF_MQTTC_QOS_2 } };
    static const SSFMQTTPktSub_t emptyFilter[1] = { { "", SSF_MQTTC_QOS_0 } };
    static const SSFMQTTPktSub_t longFilter[1] = { { "abcdef", SSF_MQTTC_QOS_0 } };
    static const SSFMQTTPktSub_t badPlace[1] = { { "#/a", SSF_MQTTC_QOS_0 } };
    static const uint8_t two[] = { 0x82, 0x0C, 0x00, 0x01, 0x00, 0x03, 'a', '/', '#', 0x01, 0x00,
                                   0x01, 'b', 0x00 };
    static const uint8_t one[] = { 0x82, 0x08, 0xBE, 0xEF, 0x00, 0x03, 'a', '/', '#', 0x01 };
    const size_t filterSize = 4;

    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(NULL, sizeof(_utBuf), &_utLen, 1, subs, 2,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, 0, &_utLen, 1, subs, 2, filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), NULL, 1, subs, 2,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 0, subs, 2,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, NULL, 2,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, subs, 0,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, badPlace, 1,
                                              filterSize));             /* '#' not last */
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, subs, 2, 0));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, badQos, 1,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, emptyFilter, 1,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, longFilter, 1,
                                              filterSize));
    SSF_ASSERT_TEST(SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(two) - 1, &_utLen, 1, subs, 2,
                                              filterSize));

    SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(two), &_utLen, 1, subs, 2, filterSize);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, two, sizeof(two)));
    SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, subs, 2, filterSize);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, two, sizeof(two)));
    SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 0xBEEF, subs, 1, filterSize);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, one, sizeof(one)));
    /* A larger filterSize is fine as long as every filter terminates within it */
    SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 0xBEEF, subs, 1, 64);
    SSF_ASSERT(_SSFMQTTPktUTIsPacket(_utBuf, _utLen, one, sizeof(one)));
    SSFMQTTPktEncodeSubscribe(_utBuf, sizeof(_utBuf), &_utLen, 1, longFilter, 1, 7);
    SSF_ASSERT(_utLen == 13);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the CONNACK, SUBACK and PUBACK decoders on valid, malformed and mistyped packets.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTDecodeAcks(void)
{
    static const uint8_t connAck[] = { 0x20, 0x02, 0x00, 0x00 };
    static const uint8_t connAckSp[] = { 0x20, 0x02, 0x01, 0x05 };
    static const uint8_t connAckRsv[] = { 0x20, 0x02, 0x02, 0x00 };          /* Reserved ack bit */
    static const uint8_t connAckFlags[] = { 0x21, 0x02, 0x00, 0x00 };        /* Reserved hdr bit */
    static const uint8_t connAckLong[] = { 0x20, 0x03, 0x00, 0x00, 0x00 };
    static const uint8_t connAckShort[] = { 0x20, 0x01, 0x00 };
    static const uint8_t subAck1[] = { 0x90, 0x03, 0x12, 0x34, 0x01 };
    static const uint8_t subAck3[] = { 0x90, 0x05, 0x00, 0x01, 0x00, 0x80, 0x02 };
    static const uint8_t subAckNoCodes[] = { 0x90, 0x02, 0x00, 0x01 };
    static const uint8_t subAckId0[] = { 0x90, 0x03, 0x00, 0x00, 0x00 };
    static const uint8_t subAckCode3[] = { 0x90, 0x03, 0x00, 0x01, 0x03 };
    static const uint8_t subAckCode7F[] = { 0x90, 0x03, 0x00, 0x01, 0x7F };
    static const uint8_t subAckFlags[] = { 0x92, 0x03, 0x00, 0x01, 0x00 };
    static const uint8_t pubAck[] = { 0x40, 0x02, 0xAB, 0xCD };
    static const uint8_t pubAckId0[] = { 0x40, 0x02, 0x00, 0x00 };
    static const uint8_t pubAckLong[] = { 0x40, 0x03, 0xAB, 0xCD, 0x00 };
    static const uint8_t pubAckShort[] = { 0x40, 0x01, 0xAB };
    static const uint8_t pubAckFlags[] = { 0x41, 0x02, 0xAB, 0xCD };
    bool sp;
    uint8_t code;
    uint16_t id;
    uint8_t codes[3];
    uint32_t count;

    /* CONNACK */
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeConnAck(NULL, sizeof(connAck), &sp, &code));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeConnAck(connAck, 0, &sp, &code));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeConnAck(connAck, sizeof(connAck), NULL, &code));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeConnAck(connAck, sizeof(connAck), &sp, NULL));
    sp = true;
    code = 0xFF;
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAck, sizeof(connAck), &sp, &code));
    SSF_ASSERT(sp == false);
    SSF_ASSERT(code == 0);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAckSp, sizeof(connAckSp), &sp, &code));
    SSF_ASSERT(sp);
    SSF_ASSERT(code == 5);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAckRsv, sizeof(connAckRsv), &sp, &code) == false);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAckFlags, sizeof(connAckFlags), &sp, &code) == false);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAckLong, sizeof(connAckLong), &sp, &code) == false);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAckShort, sizeof(connAckShort), &sp, &code) == false);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAck, sizeof(connAck) - 1, &sp, &code) == false);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(connAckLong, sizeof(connAckLong) - 1, &sp, &code) == false);
    SSF_ASSERT(SSFMQTTPktDecodeConnAck(pubAck, sizeof(pubAck), &sp, &code) == false);

    /* SUBACK */
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeSubAck(NULL, sizeof(subAck1), &id, codes, sizeof(codes),
                                                 &count));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeSubAck(subAck1, 0, &id, codes, sizeof(codes), &count));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeSubAck(subAck1, sizeof(subAck1), NULL, codes,
                                                 sizeof(codes), &count));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeSubAck(subAck1, sizeof(subAck1), &id, NULL,
                                                 sizeof(codes), &count));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodeSubAck(subAck1, sizeof(subAck1), &id, codes,
                                                 sizeof(codes), NULL));
    id = 0;
    count = 0;
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAck1, sizeof(subAck1), &id, codes, sizeof(codes), &count));
    SSF_ASSERT(id == 0x1234);
    SSF_ASSERT(count == 1);
    SSF_ASSERT(codes[0] == 0x01);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAck3, sizeof(subAck3), &id, codes, sizeof(codes), &count));
    SSF_ASSERT(id == 1);
    SSF_ASSERT(count == 3);
    SSF_ASSERT(codes[0] == 0x00);
    SSF_ASSERT(codes[1] == SSF_MQTT_PKT_SUBACK_FAILURE);
    SSF_ASSERT(codes[2] == 0x02);
    /* More codes than the caller can hold */
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAck3, sizeof(subAck3), &id, codes, 2, &count) == false);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAckNoCodes, sizeof(subAckNoCodes), &id, codes,
                                      sizeof(codes), &count) == false);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAckId0, sizeof(subAckId0), &id, codes, sizeof(codes),
                                      &count) == false);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAckCode3, sizeof(subAckCode3), &id, codes, sizeof(codes),
                                      &count) == false);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAckCode7F, sizeof(subAckCode7F), &id, codes,
                                      sizeof(codes), &count) == false);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAckFlags, sizeof(subAckFlags), &id, codes, sizeof(codes),
                                      &count) == false);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(subAck1, sizeof(subAck1) - 1, &id, codes, sizeof(codes),
                                      &count) == false);
    SSF_ASSERT(SSFMQTTPktDecodeSubAck(pubAck, sizeof(pubAck), &id, codes, sizeof(codes),
                                      &count) == false);

    /* PUBACK */
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePubAck(NULL, sizeof(pubAck), &id));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePubAck(pubAck, 0, &id));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePubAck(pubAck, sizeof(pubAck), NULL));
    id = 0;
    SSF_ASSERT(SSFMQTTPktDecodePubAck(pubAck, sizeof(pubAck), &id));
    SSF_ASSERT(id == 0xABCD);
    SSF_ASSERT(SSFMQTTPktDecodePubAck(pubAckId0, sizeof(pubAckId0), &id) == false);
    SSF_ASSERT(SSFMQTTPktDecodePubAck(pubAckLong, sizeof(pubAckLong), &id) == false);
    SSF_ASSERT(SSFMQTTPktDecodePubAck(pubAckShort, sizeof(pubAckShort), &id) == false);
    SSF_ASSERT(SSFMQTTPktDecodePubAck(pubAckFlags, sizeof(pubAckFlags), &id) == false);
    SSF_ASSERT(SSFMQTTPktDecodePubAck(pubAck, sizeof(pubAck) - 1, &id) == false);
    SSF_ASSERT(SSFMQTTPktDecodePubAck(connAck, sizeof(connAck), &id) == false);
    SSF_ASSERT(SSFMQTTPktDecodePubAck(subAck1, sizeof(subAck1), &id) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the PUBLISH decoder on hand built packets covering every flag and malformation.         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTDecodePublish(void)
{
    static const uint8_t pubRetain[] = { 0x31, 0x04, 0x00, 0x01, 't', 'p' };
    static const uint8_t pubDupQos1[] = { 0x3A, 0x05, 0x00, 0x01, 't', 0x00, 0x07 };
    static const uint8_t pubQos2[] = { 0x34, 0x06, 0x00, 0x01, 't', 0x12, 0x34, 'p' };
    static const uint8_t pubQos3[] = { 0x36, 0x06, 0x00, 0x01, 't', 0x12, 0x34, 'p' };
    static const uint8_t pubDupQos0[] = { 0x38, 0x04, 0x00, 0x01, 't', 'p' };
    static const uint8_t pubNoTopic[] = { 0x30, 0x02, 0x00, 0x00 };
    static const uint8_t pubNulTopic[] = { 0x30, 0x04, 0x00, 0x02, 't', 0x00 };
    static const uint8_t pubTopicPastEnd[] = { 0x30, 0x03, 0x00, 0x05, 't' };
    static const uint8_t pubHalfTopicLen[] = { 0x30, 0x01, 0x00 };
    static const uint8_t pubEmptyBody[] = { 0x30, 0x00 };
    static const uint8_t pubNoId[] = { 0x32, 0x03, 0x00, 0x01, 't' };
    static const uint8_t pubHalfId[] = { 0x32, 0x04, 0x00, 0x01, 't', 0x00 };
    static const uint8_t pubZeroId[] = { 0x32, 0x05, 0x00, 0x01, 't', 0x00, 0x00 };
    static const uint8_t notPub[] = { 0x40, 0x02, 0x00, 0x01 };
    /* A received topic name holds no wildcard (3.3.2.1); non-ASCII bytes are accepted */
    static const uint8_t pubPlusTopic[] = { 0x30, 0x05, 0x00, 0x03, 'a', '/', '+' };
    static const uint8_t pubHashTopic[] = { 0x30, 0x03, 0x00, 0x01, '#' };
    static const uint8_t pubMidHashTopic[] = { 0x30, 0x05, 0x00, 0x03, 'a', '#', 'b' };
    static const uint8_t pubUtf8Topic[] = { 0x30, 0x06, 0x00, 0x04, 'c', 'a', 0xC3, 0xA9 };
    SSFMQTTPktPublish_t pub;

    SSF_ASSERT(SSFMQTTPktDecodePublish(pubPlusTopic, sizeof(pubPlusTopic), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubHashTopic, sizeof(pubHashTopic), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubMidHashTopic, sizeof(pubMidHashTopic), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubUtf8Topic, sizeof(pubUtf8Topic), &pub));
    SSF_ASSERT(pub.topicLen == 4);

    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePublish(NULL, sizeof(pubRetain), &pub));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePublish(pubRetain, 0, &pub));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePublish(pubRetain, sizeof(pubRetain), NULL));

    SSF_ASSERT(SSFMQTTPktDecodePublish(pubRetain, sizeof(pubRetain), &pub));
    SSF_ASSERT(pub.qos == SSF_MQTTC_QOS_0);
    SSF_ASSERT(pub.retain);
    SSF_ASSERT(pub.dup == false);
    SSF_ASSERT(pub.packetId == 0);
    SSF_ASSERT(pub.topicLen == 1);
    SSF_ASSERT(pub.topic == &pubRetain[4]);
    SSF_ASSERT(pub.payloadLen == 1);
    SSF_ASSERT(pub.payload == &pubRetain[5]);

    SSF_ASSERT(SSFMQTTPktDecodePublish(pubDupQos1, sizeof(pubDupQos1), &pub));
    SSF_ASSERT(pub.qos == SSF_MQTTC_QOS_1);
    SSF_ASSERT(pub.retain == false);
    SSF_ASSERT(pub.dup);
    SSF_ASSERT(pub.packetId == 7);
    SSF_ASSERT(pub.topicLen == 1);
    SSF_ASSERT(pub.payloadLen == 0);
    SSF_ASSERT(pub.payload == NULL);

    /* QoS 2 is recognized on the wire even though the client does not support it */
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubQos2, sizeof(pubQos2), &pub));
    SSF_ASSERT(pub.qos == SSF_MQTTC_QOS_2);
    SSF_ASSERT(pub.packetId == 0x1234);
    SSF_ASSERT(pub.payloadLen == 1);

    SSF_ASSERT(SSFMQTTPktDecodePublish(pubQos3, sizeof(pubQos3), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubDupQos0, sizeof(pubDupQos0), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubNoTopic, sizeof(pubNoTopic), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubNulTopic, sizeof(pubNulTopic), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubTopicPastEnd, sizeof(pubTopicPastEnd), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubHalfTopicLen, sizeof(pubHalfTopicLen), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubEmptyBody, sizeof(pubEmptyBody), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubNoId, sizeof(pubNoId), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubHalfId, sizeof(pubHalfId), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubZeroId, sizeof(pubZeroId), &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(notPub, sizeof(notPub), &pub) == false);

    /* pktLen must delimit exactly one packet */
    SSF_ASSERT(SSFMQTTPktDecodePublish(pubRetain, sizeof(pubRetain) - 1, &pub) == false);
    memcpy(_utBuf, pubRetain, sizeof(pubRetain));
    _utBuf[sizeof(pubRetain)] = 0xC0;
    _utBuf[sizeof(pubRetain) + 1] = 0x00;
    SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, sizeof(pubRetain) + 2, &pub) == false);
    SSF_ASSERT(SSFMQTTPktDecodePublish(_utBuf, sizeof(pubRetain), &pub));
}

/* --------------------------------------------------------------------------------------------- */
/* Tests the PINGRESP decoder: exactly D0 00 (3.12, 2.2.2).                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTDecodePingResp(void)
{
    static const uint8_t ok[] = { 0xD0, 0x00 };
    static const uint8_t flags[] = { 0xD1, 0x00 };
    static const uint8_t flags8[] = { 0xD8, 0x00 };
    static const uint8_t body[] = { 0xD0, 0x01, 0x00 };
    static const uint8_t notPingResp[] = { 0xC0, 0x00 };          /* PINGREQ */
    static const uint8_t trailing[] = { 0xD0, 0x00, 0x00 };       /* Not one packet */

    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePingResp(NULL, 2));
    SSF_ASSERT_TEST((void)SSFMQTTPktDecodePingResp(ok, 0));

    SSF_ASSERT(SSFMQTTPktDecodePingResp(ok, sizeof(ok)));
    SSF_ASSERT(SSFMQTTPktDecodePingResp(flags, sizeof(flags)) == false);
    SSF_ASSERT(SSFMQTTPktDecodePingResp(flags8, sizeof(flags8)) == false);
    SSF_ASSERT(SSFMQTTPktDecodePingResp(body, sizeof(body)) == false);
    SSF_ASSERT(SSFMQTTPktDecodePingResp(notPingResp, sizeof(notPingResp)) == false);
    SSF_ASSERT(SSFMQTTPktDecodePingResp(trailing, sizeof(trailing)) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Tests topic and filter validation: limits, termination, character set and wildcards.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFMQTTPktUTValidTopic(void)
{
    static char big[SSF_MQTT_PKT_MAX_STRING_LEN + 2];

    SSF_ASSERT_TEST((void)SSFMQTTPktIsValidTopic(NULL, 1));
    SSF_ASSERT_TEST((void)SSFMQTTPktIsValidTopic("a", 0));

    SSF_ASSERT(SSFMQTTPktIsValidTopic("a", 2));
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a", 10));
    SSF_ASSERT(SSFMQTTPktIsValidTopic("abc", 4));
    SSF_ASSERT(SSFMQTTPktIsValidTopic("", 1) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("abc", 3) == false);                     /* Unterminated */
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a", 1) == false);
    SSF_ASSERT(SSFMQTTPktIsValidFilter("a/#", 4));
    SSF_ASSERT(SSFMQTTPktIsValidFilter("+/b", 4));
    SSF_ASSERT(SSFMQTTPktIsValidFilter("", 4) == false);
    SSF_ASSERT(SSFMQTTPktIsValidFilter("a/#", 3) == false);
    SSF_ASSERT_TEST((void)SSFMQTTPktIsValidFilter(NULL, 1));
    SSF_ASSERT_TEST((void)SSFMQTTPktIsValidFilter("a", 0));

    /* Printable ASCII only, 0x20..0x7E: space and every punctuation mark, nothing else */
    SSF_ASSERT(SSFMQTTPktIsValidTopic(" ", 2));
    SSF_ASSERT(SSFMQTTPktIsValidTopic("~", 2));
    SSF_ASSERT(SSFMQTTPktIsValidTopic("$aws/things/a b/!\"'()*,-.:;<=>?@[]^_`{|}", 64));
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a\x1f" "b", 4) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a\x7f", 3) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a\tb", 4) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("caf\xc3\xa9", 6) == false);             /* UTF-8 e-acute */
    SSF_ASSERT(SSFMQTTPktIsValidTopic("\x80", 2) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("\xff", 2) == false);
    SSF_ASSERT(SSFMQTTPktIsValidFilter("a\x01/#", 5) == false);
    SSF_ASSERT(SSFMQTTPktIsValidFilter("\xc3\xa9/+", 5) == false);

    /* A topic name holds no wildcard (3.3.2.1) */
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a/+", 4) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("#", 2) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a+b", 4) == false);
    SSF_ASSERT(SSFMQTTPktIsValidTopic("a/b#", 5) == false);

    /* Filter wildcard placement (4.7.1): '#' alone in the last level, '+' alone in a level */
    {
        static const char *good[] =
        { "#", "+", "/", "a", "a/#", "/#", "+/+", "a/+/b", "+/#", "a//b", "a/+/#", "/+", "+/" };
        static const char *bad[] =
        {
            "a#", "#/", "#/a", "a/#/b", "a/b#", "##", "a+", "+a", "a/+b", "a/b+/c", "++", "#+",
            "+#"
        };
        size_t i;

        for (i = 0; i < (sizeof(good) / sizeof(good[0])); i++)
        { SSF_ASSERT(SSFMQTTPktIsValidFilter(good[i], 16)); }
        for (i = 0; i < (sizeof(bad) / sizeof(bad[0])); i++)
        { SSF_ASSERT(SSFMQTTPktIsValidFilter(bad[i], 16) == false); }
    }

    /* Longest legal topic, then one byte more */
    memset(big, 'a', sizeof(big));
    big[SSF_MQTT_PKT_MAX_STRING_LEN] = 0;
    SSF_ASSERT(SSFMQTTPktIsValidTopic(big, sizeof(big)));
    big[SSF_MQTT_PKT_MAX_STRING_LEN] = 'a';
    big[SSF_MQTT_PKT_MAX_STRING_LEN + 1] = 0;
    SSF_ASSERT(SSFMQTTPktIsValidTopic(big, sizeof(big)) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfmqttpkt external interface.                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFMQTTPktUnitTest(void)
{
    _SSFMQTTPktUTFrame();
    _SSFMQTTPktUTEncodeSimple();
    _SSFMQTTPktUTEncodeConnect();
    _SSFMQTTPktUTEncodePublish();
    _SSFMQTTPktUTEncodeSubscribe();
    _SSFMQTTPktUTDecodeAcks();
    _SSFMQTTPktUTDecodePublish();
    _SSFMQTTPktUTDecodePingResp();
    _SSFMQTTPktUTValidTopic();
}

#endif /* SSF_CONFIG_MQTTPKT_UNIT_TEST */
