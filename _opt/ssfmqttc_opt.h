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

/* Topic names and topic filters. 2..65536. Also bounds inbound PUBLISH topics; a longer one     */
/* ends the connection with SSF_MQTTC_REASON_RX_OVERFLOW.                                        */
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

/* Maximum number of entries in the Start option subscription set. >= 1. All entries are sent    */
/* filters are sent in one SUBSCRIBE, so the tx block size must hold them.                       */
#define SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS      (8u)

/* Inbound PUBLISH packets held for the app. >= 1. Sizes the rx pool (depth + 1 framing block)  */
/* and the PUBACK capacity of the control pool.                                                  */
#define SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH (4u)

/* A deferred rxPublish is offered to the app again after this many ticks. >= 1.                */
#define SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS (SSF_TICKS_PER_SEC)

/* A deferred rxPublish is dropped once this many ticks have elapsed since its first offer.      */
/* >= SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS.                                                   */
#define SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS   (SSF_TICKS_PER_SEC * 30u)

/* Connection is dropped (SSF_MQTTC_REASON_KEEPALIVE) if PINGRESP does not arrive within this    */
/* many ticks of PINGREQ. >= 1. PINGREQ is sent every keepAliveSec / 4, which must be at least   */
/* this value; with 30 s the smallest keepAliveSec is 120.                                       */
#define SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT       (SSF_TICKS_PER_SEC * 30u)

#if SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS < 1
#error SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS must be at least 1.
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

#ifdef __cplusplus
}
#endif

#endif /* SSF_MQTTC_OPT_H_INCLUDE */
