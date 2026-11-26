/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfmqttc configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_MQTTC_OPT_H_INCLUDE
#define SSF_MQTTC_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Tick-based values below use SSF_TICKS_PER_SEC from ssfport.h, which must be included first   */
/* (ssfoptions.h does this).                                                                     */

/* String limits. Sizes include the NUL terminator; app strings must be strictly shorter.        */
/* MQTT 3.1.1 caps every string field at 65535 bytes.                                            */

/* Topic names and topic filters. 2..65536. Also bounds inbound PUBLISH topics; a longer one is  */
/* dropped with SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG.                                      */
#define SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE         (128u)

/* Broker host name or address. 2..256 (DNS name limit + NUL).                                   */
#define SSF_MQTTC_CONFIG_MAX_HOST_SIZE          (64u)

/* Client identifier, supplied by the app. 2..65536. Brokers must accept 1-23 characters and may */
/* accept longer.                                                                                */
#define SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE     (64u)

/* User name. 2..65536.                                                                          */
#define SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE      (64u)

/* Password, binary, not NUL terminated. 1..65535.                                               */
#define SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN       (64u)

/* Maximum number of entries in the Start option subscription set. 1..16. All filters are sent   */
/* in one SUBSCRIBE, so the tx block size must hold them.                                        */
#define SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS      (8u)

/* Inbound PUBLISH packets held for the app. >= 1. Sizes the rx pool (depth + 1 framing block)  */
/* and the PUBACK capacity of the control pool.                                                  */
#define SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH (4u)

/* A deferred rxPublish is offered to the app again after this many ticks. >= 1.                */
#define SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS (SSF_TICKS_PER_SEC)

/* A deferred rxPublish is dropped once this many ticks have elapsed since its first offer.      */
/* >= SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS. The ssfmqttc unit test build uses 5 s so the drop */
/* can be tested. Override with -D.                                                              */
#ifndef SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS   (SSF_TICKS_PER_SEC * 5u)
#else
#define SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS   (SSF_TICKS_PER_SEC * 30u)
#endif
#endif

/* Back-pressure: a QoS 1 PUBLISH that finds the rx queue full is held, unread bytes behind it   */
/* stay in the transport, for at most this many ticks; it is then dropped and acknowledged       */
/* (SSF_MQTTC_REASON_RX_PUBLISH_HOLD_TIMEOUT) and reading resumes. A hold delays everything      */
/* behind it, PINGRESP and PUBACKs for the app's own publishes included, so txPublishTimeout and */
/* subscribeTimeout should exceed it. >= 1. The ssfmqttc unit test build uses 400 ms, longer     */
/* than its PINGRESP timeout, so that keep-alive across a hold can be tested. Override with -D.  */
#ifndef SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS      ((SSF_TICKS_PER_SEC * 2u) / 5u)
#else
#define SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS      (SSF_TICKS_PER_SEC * 10u)
#endif
#endif

/* Connection is dropped (SSF_MQTTC_REASON_KEEPALIVE) if PINGRESP does not arrive within this    */
/* many ticks of PINGREQ. >= 1. PINGREQ is sent every keepAliveSec / 4, which must be at least   */
/* this value; with 30 s the smallest keepAliveSec is 120. The ssfmqttc unit test build uses     */
/* 250 ms so that keep-alive can be tested with keepAliveSec 1 (the same interval-to-timeout     */
/* ratio as 120 s with 30 s). Override with -D.                                                  */
#ifndef SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT       (SSF_TICKS_PER_SEC / 4u)
#else
#define SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT       (SSF_TICKS_PER_SEC * 30u)
#endif
#endif

/* A filter the broker refused (SUBACK 0x80) is subscribed again this many ticks after READY,   */
/* and after each refused retry, until granted. At least 60 s, so a fleet does not hammer a      */
/* broker whose policy refuses it. The ssfmqttc unit test build uses 500 ms. Override with -D.   */
#ifndef SSF_MQTTC_CONFIG_SUB_RETRY_TICKS
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_SUB_RETRY_TICKS        (SSF_TICKS_PER_SEC / 2u)
#else
#define SSF_MQTTC_CONFIG_SUB_RETRY_TICKS        (SSF_TICKS_PER_SEC * 300u)
#endif
#endif

/* While the transport is opening (name lookup, then connect) SSFMQTTCTask() lowers its next     */
/* timeout to this many ticks, since there is no socket yet for the app loop to wait on. >= 1.   */
#define SSF_MQTTC_CONFIG_OPEN_POLL_TICKS        (SSF_TICKS_PER_SEC / 100u)

#if SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS < 1
#error SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS must be at least 1.
#endif
#if SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS > 16
#error SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS must be at most 16 (per-filter SUBACK result masks).
#endif
#if (SSF_CONFIG_MQTTC_UNIT_TEST != 1) && \
    (SSF_MQTTC_CONFIG_SUB_RETRY_TICKS < (SSF_TICKS_PER_SEC * 60u))
#error SSF_MQTTC_CONFIG_SUB_RETRY_TICKS must be at least 60 s.
#endif
#if SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH < 1
#error SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH must be at least 1.
#endif
#if SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS < 1
#error SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS must be at least 1.
#endif
#if SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS < SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS
#error SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS must be >= SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS.
#endif
#if SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT < 1
#error SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT must be at least 1.
#endif
#if SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS < 1
#error SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS must be at least 1.
#endif
#if SSF_MQTTC_CONFIG_OPEN_POLL_TICKS < 1
#error SSF_MQTTC_CONFIG_OPEN_POLL_TICKS must be at least 1.
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_MQTTC_OPT_H_INCLUDE */
