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
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_AWSPROV_UNIT_TEST == 1
void SSFAWSProvUnitTest(void);
#endif /* SSF_CONFIG_AWSPROV_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_AWSPROV_H_INCLUDE */
