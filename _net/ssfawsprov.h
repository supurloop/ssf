/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfawsprov.h                                                                                  */
/* AWS IoT Core Fleet Provisioning over MQTT (CreateCertificateFromCsr, RegisterThing).          */
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
#ifndef SSF_AWSPROV_H_INCLUDE
#define SSF_AWSPROV_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfmqttc.h"
#include "ssfec.h"
#include "ssfecdsa.h"
#include "ssfx509.h"
#include "ssfpkey.h"
#include "ssftlsc.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* Template name size with NUL; AWS allows 1..36 characters of [0-9A-Za-z_-] */
#define SSF_AWSPROV_TEMPLATE_NAME_SIZE (37u)

/* Longest topic size with NUL: $aws/provisioning-templates/<36>/provision/json/rejected */
#define SSF_AWSPROV_MAX_TOPIC_SIZE (89u)

#if SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE < SSF_AWSPROV_MAX_TOPIC_SIZE
#error SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE must be at least SSF_AWSPROV_MAX_TOPIC_SIZE.
#endif
#if SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE < SSF_AWSPROV_CONFIG_THING_NAME_SIZE
#error SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE must be at least SSF_AWSPROV_CONFIG_THING_NAME_SIZE.
#endif
#if SSF_JSON_CONFIG_MAX_IN_LEN < (SSF_AWSPROV_CONFIG_RX_SIZE - 1u)
#error SSF_JSON_CONFIG_MAX_IN_LEN must be at least SSF_AWSPROV_CONFIG_RX_SIZE - 1.
#endif

/* CreateCertificateFromCsr request topic and its response topics, JSON payload format */
#define SSF_AWSPROV_TOPIC_CSR          "$aws/certificates/create-from-csr/json"
#define SSF_AWSPROV_TOPIC_CSR_ACCEPTED "$aws/certificates/create-from-csr/json/accepted"
#define SSF_AWSPROV_TOPIC_CSR_REJECTED "$aws/certificates/create-from-csr/json/rejected"

/* Entries of SSFAWSProvTopics_t.subs, in subscription order */
#define SSF_AWSPROV_SUB_CSR_ACCEPTED  (0u)
#define SSF_AWSPROV_SUB_CSR_REJECTED  (1u)
#define SSF_AWSPROV_SUB_PROV_ACCEPTED (2u)
#define SSF_AWSPROV_SUB_PROV_REJECTED (3u)
#define SSF_AWSPROV_SUB_COUNT         (4u)

/* Longest request topic: $aws/provisioning-templates/<36>/provision/json (9 shorter than the */
/* longest response topic, .../rejected) */
#define SSF_AWSPROV_MAX_REQ_TOPIC_LEN (SSF_AWSPROV_MAX_TOPIC_SIZE - 1u - 9u)

/* Length of a QoS 1 PUBLISH of a topic of t and a payload of p bytes, as ssfmqttc counts it */
#define SSF_AWSPROV_PUB_REM(t, p) (2u + (t) + 2u + (p))
#define SSF_AWSPROV_PUB_LEN(t, p) (1u + SSF_AWSPROV_PUB_REM(t, p) + \
    ((SSF_AWSPROV_PUB_REM(t, p) < 128u) ? 1u : ((SSF_AWSPROV_PUB_REM(t, p) < 16384u) ? 2u : \
     ((SSF_AWSPROV_PUB_REM(t, p) < 2097152ul) ? 3u : 4u))))

/* Smallest SSFMQTTCInit rxBlockSize that takes any response the parsers accept, and the */
/* smallest txBlockSize that takes any request the builders make (any template name) */
#define SSF_AWSPROV_MIN_RX_BLOCK_SIZE \
    SSF_AWSPROV_PUB_LEN(SSF_AWSPROV_MAX_TOPIC_SIZE - 1u, SSF_AWSPROV_CONFIG_RX_SIZE - 1u)
#define SSF_AWSPROV_MIN_TX_CSR \
    SSF_AWSPROV_PUB_LEN(sizeof(SSF_AWSPROV_TOPIC_CSR) - 1u, SSF_AWSPROV_CONFIG_CSR_REQ_SIZE - 1u)
#define SSF_AWSPROV_MIN_TX_REG \
    SSF_AWSPROV_PUB_LEN(SSF_AWSPROV_MAX_REQ_TOPIC_LEN, SSF_AWSPROV_CONFIG_REG_REQ_SIZE - 1u)
#define SSF_AWSPROV_MIN_TX_BLOCK_SIZE \
    ((SSF_AWSPROV_MIN_TX_CSR > SSF_AWSPROV_MIN_TX_REG) ? SSF_AWSPROV_MIN_TX_CSR : \
     SSF_AWSPROV_MIN_TX_REG)

/* certificateId size with NUL: 64 lowercase hex characters */
#define SSF_AWSPROV_CERT_ID_SIZE (65u)

#if SSF_AWSPROV_CONFIG_CERT_DER_SIZE > SSF_X509_CONFIG_MAX_CERT_SIZE
#error SSF_AWSPROV_CONFIG_CERT_DER_SIZE must be at most SSF_X509_CONFIG_MAX_CERT_SIZE.
#endif
#if SSF_JSON_CONFIG_MAX_IN_DEPTH < 2u
#error SSF_JSON_CONFIG_MAX_IN_DEPTH must be at least 2 for the RegisterThing parameters object.
#endif
#if SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS < SSF_AWSPROV_SUB_COUNT
#error SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS must be at least SSF_AWSPROV_SUB_COUNT.
#endif
#if SSF_JSON_CONFIG_MAX_IN_LEN < (SSF_AWSPROV_CONFIG_REG_REQ_SIZE - 1u)
#error SSF_JSON_CONFIG_MAX_IN_LEN must be at least SSF_AWSPROV_CONFIG_REG_REQ_SIZE - 1.
#endif

#if SSF_AWSPROV_CONFIG_CERT_DER_SIZE > 65000u
#error SSF_AWSPROV_CONFIG_CERT_DER_SIZE must be at most 65000 (blob size within 16 bits).
#endif

/* Credentials blob v1: "AWSC", version, curve, privLen, priv, certLen (2, big-endian), */
/* certDer, nameLen, thingName, certificateId (64), CRC32 (4, big-endian) of all before */
#define SSF_AWSPROV_CRED_BLOB_VERSION  (1u)
#define SSF_AWSPROV_CRED_BLOB_MAX_SIZE (4u + 1u + 1u + 1u + SSF_PKEY_MAX_PRIV_SIZE + 2u + \
                                        SSF_AWSPROV_CONFIG_CERT_DER_SIZE + 1u + \
                                        (SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 1u) + \
                                        (SSF_AWSPROV_CERT_ID_SIZE - 1u) + 4u)

/* Rejected-response errorCode and errorMessage sizes kept for the result, with NUL */
#define SSF_AWSPROV_ERROR_CODE_SIZE    (64u)
#define SSF_AWSPROV_ERROR_MESSAGE_SIZE (128u)

/* --------------------------------------------------------------------------------------------- */
/* Typedefs                                                                                      */
/* --------------------------------------------------------------------------------------------- */
/* RegisterThing topics and the four response filters; subs point into this instance, no copies */
typedef struct
{
    char provReq[SSF_AWSPROV_MAX_TOPIC_SIZE];
    char provAccepted[SSF_AWSPROV_MAX_TOPIC_SIZE];
    char provRejected[SSF_AWSPROV_MAX_TOPIC_SIZE];
    SSFMQTTCSub_t subs[SSF_AWSPROV_SUB_COUNT];
} SSFAWSProvTopics_t;

/* CreateCertificateFromCsr accepted response; cert points into certDer, no copies */
typedef struct
{
    char certificateId[SSF_AWSPROV_CERT_ID_SIZE];
    char token[SSF_AWSPROV_CONFIG_TOKEN_SIZE];
    size_t tokenLen;
    uint8_t certDer[SSF_AWSPROV_CONFIG_CERT_DER_SIZE];
    size_t certDerLen;
    SSFX509Cert_t cert;
} SSFAWSProvCsrAccepted_t;

/* RegisterThing template parameter; key and value are printable ASCII or control bytes */
typedef struct
{
    SSFCStrIn_t keyStr;
    SSFCStrIn_t valueStr;
} SSFAWSProvParam_t;

/* Why provisioning ended; NONE means it succeeded */
typedef enum
{
    SSF_AWSPROV_REASON_MIN = -1,
    SSF_AWSPROV_REASON_NONE,              /* DONE: certificate and thing registered */
    SSF_AWSPROV_REASON_BUILD,             /* A request could not be built: template name, */
                                          /* CSR or RegisterThing request too large */
    SSF_AWSPROV_REASON_REJECTED,          /* AWS rejected with a fatal statusCode */
    SSF_AWSPROV_REASON_ATTEMPTS,          /* maxAttempts reached on timeouts, retryable */
                                          /* rejects or connect failures */
    SSF_AWSPROV_REASON_BAD_RESPONSE,      /* maxAttempts reached, last response unparseable */
    SSF_AWSPROV_REASON_TX_REFUSED,        /* maxAttempts reached, last request refused by */
                                          /* SSFMQTTCTxPublish (txBlockSize or pool) */
    SSF_AWSPROV_REASON_DEADLINE,          /* deadline passed */
    SSF_AWSPROV_REASON_SUBSCRIBE_REFUSED, /* A response filter was refused (claim policy) */
    SSF_AWSPROV_REASON_CONNECT_REFUSED,   /* CONNACK 1, 2, 4 or 5 */
    SSF_AWSPROV_REASON_MAX
} SSFAWSProvReason_t;

/* Start options; everything pointed to must stay valid until the done callback or Stop */
typedef struct
{
    SSFMQTTCOpts_t mqtt;                  /* Claim connection; subsOpt, subCount and willOpt */
                                          /* must be NULL/0 (the module sets the filters) */
    SSFCStrIn_t templateName;             /* Provisioning template, 1..36 of [0-9A-Za-z_-] */
    SSFECCurve_t curve;                   /* Device key; used only inside Start */
    const uint8_t *privKey;
    size_t privKeyLen;
    const SSFX509GenName_t *subjectOpt;   /* CSR subject; NULL => empty */
    const SSFAWSProvParam_t *paramsOpt;   /* RegisterThing parameters; NULL => none */
    size_t paramCount;
    /* Each timeout is at most 2^62 ticks */
    SSFPortTick_t responseTimeout;        /* > 0. Request sent through response received */
    SSFPortTick_t retryMinWait;           /* > 0. First backoff; doubles per retry */
    SSFPortTick_t retryMaxWait;           /* >= retryMinWait. Backoff cap; jitter [w/2, w] */
    SSFPortTick_t deadline;               /* From Start; 0 => none */
    SSFPortTick_t tokenLifetime;          /* > 0. Older token at a RegisterThing send => */
                                          /* back to CreateCertificateFromCsr */
    uint32_t maxAttempts;                 /* Tries per step for the whole run (sends, connect */
                                          /* failures); 0 => none. maxAttempts or deadline > 0 */
} SSFAWSProvOpts_t;

/* Recommended bounds (D4) */
#define SSF_AWSPROV_DEFAULT_RESPONSE_TIMEOUT (SSF_TICKS_PER_SEC * 10u)
#define SSF_AWSPROV_DEFAULT_RETRY_MIN_WAIT   (SSF_TICKS_PER_SEC)
#define SSF_AWSPROV_DEFAULT_RETRY_MAX_WAIT   (SSF_TICKS_PER_SEC * 60u)
#define SSF_AWSPROV_DEFAULT_TOKEN_LIFETIME   (SSF_TICKS_PER_SEC * 55u * 60u)
#define SSF_AWSPROV_DEFAULT_MAX_ATTEMPTS     (8u)
#define SSF_AWSPROV_TRUSTED_USER_DEADLINE    (SSF_TICKS_PER_SEC * 5u * 60u)

/* Outcome; every pointer is valid only during the done callback */
typedef struct
{
    SSFAWSProvReason_t reason;
    uint16_t statusCode;                  /* Last rejected statusCode, else 0 */
    SSFCStrIn_t errorCode;                /* Last rejected errorCode, else "" */
    SSFCStrIn_t errorMessage;             /* Last rejected errorMessage, else "" */
    const SSFAWSProvCsrAccepted_t *certOpt; /* DONE only: certificate, id and token */
    SSFCStrIn_t thingNameOpt;             /* DONE only */
    SSFCStrIn_t deviceConfigOpt;          /* DONE only: object text, at least "{}" */
    size_t deviceConfigLen;
} SSFAWSProvResult_t;

/* Done callback; isDone is reason == NONE. Runs on the app thread. */
typedef void (*SSFAWSProvDoneFn_t)(void *ctx, bool isDone, const SSFAWSProvResult_t *result);

/* Operational credentials: the device key, the issued certificate and its names. Holds the */
/* private key, so wipe it with SSFAWSProvCredWipe. Not copyable: cert and chain point into */
/* certDer. After SSFAWSProvApplyTLS the session points into it: clear the session's client */
/* certificate (SSFTLSCSetClientCert(s, NULL, NULL, 0, NULL)) or SSFTLSCDeInit it before a  */
/* Wipe, a new Decode into it, or freeing it. */
typedef struct
{
    SSFPKey_t key;
    uint8_t certDer[SSF_AWSPROV_CONFIG_CERT_DER_SIZE];
    size_t certDerLen;
    SSFX509Cert_t cert;
    char thingName[SSF_AWSPROV_CONFIG_THING_NAME_SIZE];
    char certificateId[SSF_AWSPROV_CERT_ID_SIZE];
    const uint8_t *chain[1];
    uint32_t chainLen[1];
} SSFAWSProvCred_t;

/* Caller-owned work set for one provisioning run; fields are not part of the API */
typedef struct
{
    SSFAWSProvOpts_t opts;
    SSFAWSProvTopics_t topics;
    char rx[SSF_AWSPROV_CONFIG_RX_SIZE];
    char csrReq[SSF_AWSPROV_CONFIG_CSR_REQ_SIZE];
    size_t csrReqLen;
    char regReq[SSF_AWSPROV_CONFIG_REG_REQ_SIZE];
    size_t regReqLen;
    SSFAWSProvCsrAccepted_t acc;
    uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
    size_t pubLen;
    char thingName[SSF_AWSPROV_CONFIG_THING_NAME_SIZE];
    char deviceConfig[SSF_AWSPROV_CONFIG_DEVICE_CONFIG_SIZE];
    size_t deviceConfigLen;
    uint16_t statusCode;
    char errorCode[SSF_AWSPROV_ERROR_CODE_SIZE];
    char errorMessage[SSF_AWSPROV_ERROR_MESSAGE_SIZE];
    SSFPortTick_t tokenTick;
    SSFPortTick_t wait;
    uint32_t tries[2];                    /* Per step, for the whole run */
    uint32_t jitter;
    uint8_t step;
    uint8_t response;
    uint8_t lastFail;
} SSFAWSProvWork_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvTemplateNameIsValid(SSFCStrIn_t nameStr, size_t nameSize);
bool SSFAWSProvTopicsInit(SSFAWSProvTopics_t *topicsOut, SSFCStrIn_t templateNameStr,
                          size_t templateNameSize);
/* rxSize must hold the payload, a NUL, the unescaped certificate PEM and a NUL */
bool SSFAWSProvParseCsrAccepted(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                                size_t rxSize, SSFECCurve_t curve, const uint8_t *pubKey,
                                size_t pubKeyLen, SSFAWSProvCsrAccepted_t *out);
/* tokenStr: raw text from SSFAWSProvParseCsrAccepted; result <= SSF_JSON_CONFIG_MAX_IN_LEN */
bool SSFAWSProvBuildRegisterRequest(const char *tokenStr, size_t tokenLen,
                                    const SSFAWSProvParam_t *paramsOpt, size_t paramCount,
                                    char *outStr, size_t outSize, size_t *outLen);
bool SSFAWSProvParseRegisterAccepted(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                                     size_t rxSize, char *thingNameOut, size_t thingNameSize,
                                     char *cfgOutOpt, size_t cfgSize, size_t *cfgLenOutOpt);
bool SSFAWSProvParseRejected(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                             size_t rxSize, uint16_t *statusCodeOut, char *errorCodeOut,
                             size_t errorCodeSize, char *errorMessageOut,
                             size_t errorMessageSize);
/* true for 429 (throttled) and 5xx (AWS fault); any other statusCode is fatal */
bool SSFAWSProvIsRetryable(uint16_t statusCode);
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
/* privKey and the subject strings must not overlap scratch or outStr */
bool SSFAWSProvCsrRequestSizes(SSFECCurve_t curve, const SSFX509GenName_t *subjectOpt,
                               size_t *scratchSizeOut, size_t *outSizeOut);
bool SSFAWSProvBuildCsrRequest(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                               const SSFX509GenName_t *subjectOpt, uint8_t *scratch,
                               size_t scratchSize, char *outStr, size_t outSize, size_t *outLen);

/* Provisioning state machine; SSFSMInit() first. One run at a time (ssfmqttc is a singleton). */
/* Every call and callback is on the app thread that runs SSFSMTask() and SSFMQTTCTask().      */
void SSFAWSProvInit(void);
/* After the run has ended and ssfmqttc reported STOPPED */
void SSFAWSProvDeInit(void);
/* Pass these to SSFMQTTCInit (contexts NULL); ssfmqttc STOPPED. doneFn is called once, */
/* possibly before Start returns (reason BUILD); then work is wiped and ssfmqttc stopped. */
/* doneFn must not call Start or Stop; start a new run after ssfmqttc reports STOPPED.    */
void SSFAWSProvStart(SSFAWSProvWork_t *work, const SSFAWSProvOpts_t *opts,
                     SSFAWSProvDoneFn_t doneFn, void *doneCtxOpt,
                     SSFMQTTCEventFn_t appEventFnOpt, void *appEventCtxOpt);
/* Ends a run with no done callback: work is wiped before return, ssfmqttc stops after */
void SSFAWSProvStop(void);
bool SSFAWSProvIsStarted(void);
bool SSFAWSProvRxPublish(void *ctx, const SSFMQTTCRxPublish_t *rxPublish);
void SSFAWSProvEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason);

/* Credentials: from a DONE result (in doneFn) and the device key (32 bytes for P-256, 48 for  */
/* P-384); false if they don't match or a field fails Decode's rules                          */
bool SSFAWSProvCredFromResult(const SSFAWSProvResult_t *result, SSFECCurve_t curve,
                              const uint8_t *priv, size_t privLen, SSFAWSProvCred_t *credOut);
/* The blob holds the private key: store it as a secret. out zeroed on false. */
bool SSFAWSProvCredEncode(const SSFAWSProvCred_t *cred, uint8_t *out, size_t outSize,
                          size_t *outLen);
/* Checks the CRC, each field's format, that the certificate parses and is for the key (not   */
/* its CA signature, nor certificateId against the certificate); credOut zeroed on false     */
bool SSFAWSProvCredDecode(const uint8_t *blob, size_t blobLen, SSFAWSProvCred_t *credOut);
/* Sets cred as the session's client certificate and key; cred must outlive that use */
bool SSFAWSProvApplyTLS(SSFTLSCSession_t *session, SSFAWSProvCred_t *cred);
void SSFAWSProvCredWipe(SSFAWSProvCred_t *cred);
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_AWSPROV_UNIT_TEST == 1
void SSFAWSProvUnitTest(void);
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
SSFPortTick_t _SSFAWSProvUTNextBackoff(SSFAWSProvWork_t *w);
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */
#endif /* SSF_CONFIG_AWSPROV_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_AWSPROV_H_INCLUDE */
