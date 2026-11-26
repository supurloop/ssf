/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfmqttc configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_MQTTC_OPT_H_INCLUDE
#define SSF_MQTTC_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes include the NUL terminator; tick values use SSF_TICKS_PER_SEC; see ssfmqttc.md */

/* Maximum topic name or filter size, 2..65536 */
#define SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE         (128u)

/* Maximum broker host name or address size, 2..256 */
#define SSF_MQTTC_CONFIG_MAX_HOST_SIZE          (64u)

/* Maximum client identifier size, 2..65536 */
#define SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE     (64u)

/* Maximum user name size, 2..65536 */
#define SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE      (64u)

/* Maximum password length, binary, 1..65535 */
#define SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN       (64u)

/* Maximum entries in the Start option subscription set, 1..16 */
#define SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS      (8u)

/* Inbound PUBLISH packets held for the app, >= 1 */
#define SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH (4u)

/* Ticks before a deferred rxPublish is offered to the app again, >= 1 */
#define SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS (SSF_TICKS_PER_SEC)

/* Ticks after its first offer that a deferred rxPublish is dropped, >= RX_PUBLISH_RETRY_TICKS */
#ifndef SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS   (SSF_TICKS_PER_SEC * 5u)
#else
#define SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS   (SSF_TICKS_PER_SEC * 30u)
#endif
#endif

/* Maximum ticks a QoS 1 PUBLISH is held waiting for rx queue space, >= 1 */
#ifndef SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS      ((SSF_TICKS_PER_SEC * 2u) / 5u)
#else
#define SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS      (SSF_TICKS_PER_SEC * 10u)
#endif
#endif

/* Ticks after PINGREQ within which PINGRESP must arrive, >= 1 */
#ifndef SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT       (SSF_TICKS_PER_SEC / 4u)
#else
#define SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT       (SSF_TICKS_PER_SEC * 30u)
#endif
#endif

/* Ticks between resubscribe attempts for refused filters, >= 60 s */
#ifndef SSF_MQTTC_CONFIG_SUB_RETRY_TICKS
#if SSF_CONFIG_MQTTC_UNIT_TEST == 1
#define SSF_MQTTC_CONFIG_SUB_RETRY_TICKS        (SSF_TICKS_PER_SEC / 2u)
#else
#define SSF_MQTTC_CONFIG_SUB_RETRY_TICKS        (SSF_TICKS_PER_SEC * 300u)
#endif
#endif

/* Maximum task timeout in ticks while the transport is opening, >= 1 */
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
