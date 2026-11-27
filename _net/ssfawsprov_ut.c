/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfawsprov_ut.c                                                                               */
/* ssfawsprov unit test.                                                                         */
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfmqttpkt.h"
#include "ssfjson.h"
#include "ssfpem.h"
#include "ssfawsprov.h"

#if SSF_CONFIG_AWSPROV_UNIT_TEST == 1
#include "ssfawsprov_ut_fix.h"

/* --------------------------------------------------------------------------------------------- */
/* Local defines and data                                                                        */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_UT_PT_PREFIX     "$aws/provisioning-templates/"
#define SSF_AWSPROV_UT_PT_REQ        "/provision/json"
#define SSF_AWSPROV_UT_PT_ACCEPTED   "/provision/json/accepted"
#define SSF_AWSPROV_UT_PT_REJECTED   "/provision/json/rejected"
#define SSF_AWSPROV_UT_CSR_REQ       "$aws/certificates/create-from-csr/json"
#define SSF_AWSPROV_UT_CSR_ACCEPTED  "$aws/certificates/create-from-csr/json/accepted"
#define SSF_AWSPROV_UT_CSR_REJECTED  "$aws/certificates/create-from-csr/json/rejected"
#define SSF_AWSPROV_UT_NAME_MAX_LEN  (36u)
#define SSF_AWSPROV_UT_NAME_CHARS    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                                     "abcdefghijklmnopqrstuvwxyz_-"
#define SSF_AWSPROV_UT_LIT_LEN(s)    (sizeof(s) - 1u)
#define SSF_AWSPROV_UT_CANARY        (0xA5u)

static char _utName[SSF_AWSPROV_TEMPLATE_NAME_SIZE + 4u];
static char _utTopic[SSF_AWSPROV_MAX_TOPIC_SIZE + 8u];
static SSFAWSProvTopics_t _utTopics;
static SSFAWSProvTopics_t _utCanary;

/* --------------------------------------------------------------------------------------------- */
/* Fills _utName with len copies of fill followed by a NUL.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTNameFill(char fill, size_t len)
{
    SSF_REQUIRE(len < sizeof(_utName));

    memset(_utName, fill, len);
    _utName[len] = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Builds the expected template topic for nameStr and suffixStr into _utTopic.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTTopicExpect(const char *nameStr, const char *suffixStr)
{
    size_t prefixLen = SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_PT_PREFIX);
    size_t nameLen;
    size_t suffixLen;

    SSF_REQUIRE(nameStr != NULL);
    SSF_REQUIRE(suffixStr != NULL);
    nameLen = strlen(nameStr);
    suffixLen = strlen(suffixStr);
    SSF_REQUIRE((prefixLen + nameLen + suffixLen) < sizeof(_utTopic));

    memcpy(_utTopic, SSF_AWSPROV_UT_PT_PREFIX, prefixLen);
    memcpy(&_utTopic[prefixLen], nameStr, nameLen);
    memcpy(&_utTopic[prefixLen + nameLen], suffixStr, (suffixLen + 1u));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the protocol size constants against the AWS topic strings.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSizes(void)
{
    SSF_ASSERT(SSF_AWSPROV_TEMPLATE_NAME_SIZE == (SSF_AWSPROV_UT_NAME_MAX_LEN + 1u));

    _SSFAWSProvUTNameFill('n', SSF_AWSPROV_UT_NAME_MAX_LEN);
    _SSFAWSProvUTTopicExpect(_utName, SSF_AWSPROV_UT_PT_REJECTED);
    SSF_ASSERT((strlen(_utTopic) + 1u) == SSF_AWSPROV_MAX_TOPIC_SIZE);
    _SSFAWSProvUTTopicExpect(_utName, SSF_AWSPROV_UT_PT_ACCEPTED);
    SSF_ASSERT((strlen(_utTopic) + 1u) == SSF_AWSPROV_MAX_TOPIC_SIZE);
    _SSFAWSProvUTTopicExpect(_utName, SSF_AWSPROV_UT_PT_REQ);
    SSF_ASSERT((strlen(_utTopic) + 1u) < SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(sizeof(SSF_AWSPROV_UT_CSR_REQ) < SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(sizeof(SSF_AWSPROV_UT_CSR_ACCEPTED) < SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(sizeof(SSF_AWSPROV_UT_CSR_REJECTED) < SSF_AWSPROV_MAX_TOPIC_SIZE);

    SSF_ASSERT(strcmp(SSF_AWSPROV_TOPIC_CSR, SSF_AWSPROV_UT_CSR_REQ) == 0);
    SSF_ASSERT(strcmp(SSF_AWSPROV_TOPIC_CSR_ACCEPTED, SSF_AWSPROV_UT_CSR_ACCEPTED) == 0);
    SSF_ASSERT(strcmp(SSF_AWSPROV_TOPIC_CSR_REJECTED, SSF_AWSPROV_UT_CSR_REJECTED) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Checks at run time the configuration relations that ssfawsprov.h enforces at build.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTConfig(void)
{
    SSF_ASSERT(SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE >= SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE >= SSF_AWSPROV_CONFIG_THING_NAME_SIZE);
    SSF_ASSERT(SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS >= SSF_AWSPROV_SUB_COUNT);
    SSF_ASSERT(SSF_JSON_CONFIG_MAX_IN_LEN >= (SSF_AWSPROV_CONFIG_RX_SIZE - 1u));
    SSF_ASSERT((SSF_AWSPROV_CONFIG_RX_SIZE >= 2u) && (SSF_AWSPROV_CONFIG_RX_SIZE <= 65536ul));
    SSF_ASSERT((SSF_AWSPROV_CONFIG_THING_NAME_SIZE >= 2u) &&
               (SSF_AWSPROV_CONFIG_THING_NAME_SIZE <= 129u));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks template name validation: lengths, sizes and every byte value at three positions.      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTNameIsValid(void)
{
    static const size_t pos[] = { 0u, 17u, (SSF_AWSPROV_UT_NAME_MAX_LEN - 1u) };
    uint16_t b;
    size_t i;
    bool expect;

    SSF_ASSERT(strlen(SSF_AWSPROV_UT_NAME_CHARS) == 64u);

    /* Lengths and sizes */
    _SSFAWSProvUTNameFill('a', 1u);
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, 2u));
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, sizeof(_utName)));
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, 1u) == false);
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, 0u) == false);
    _SSFAWSProvUTNameFill('a', SSF_AWSPROV_UT_NAME_MAX_LEN);
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, SSF_AWSPROV_TEMPLATE_NAME_SIZE));
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, sizeof(_utName)));
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, SSF_AWSPROV_UT_NAME_MAX_LEN) == false);
    _SSFAWSProvUTNameFill('a', 0u);
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, sizeof(_utName)) == false);
    _SSFAWSProvUTNameFill('a', (SSF_AWSPROV_UT_NAME_MAX_LEN + 1u));
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, sizeof(_utName)) == false);

    /* A NUL inside the buffer ends the name */
    memcpy(_utName, "ab\0cd", 6u);
    SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, 6u));

    /* Each allowed character alone */
    for (i = 0; i < SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_NAME_CHARS); i++)
    {
        _utName[0] = SSF_AWSPROV_UT_NAME_CHARS[i];
        _utName[1] = 0;
        SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, 2u));
    }

    /* Every byte value at the first, a middle and the last position of a longest name */
    for (b = 1u; b <= 0xFFu; b++)
    {
        expect = (memchr(SSF_AWSPROV_UT_NAME_CHARS, (int)b,
                         SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_NAME_CHARS)) != NULL);
        for (i = 0; i < (sizeof(pos) / sizeof(pos[0])); i++)
        {
            _SSFAWSProvUTNameFill('Z', SSF_AWSPROV_UT_NAME_MAX_LEN);
            _utName[pos[i]] = (char)b;
            SSF_ASSERT(SSFAWSProvTemplateNameIsValid(_utName, sizeof(_utName)) == expect);
        }
    }

    SSF_ASSERT_TEST((void)SSFAWSProvTemplateNameIsValid(NULL, 2u));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if init with nameStr fails and leaves a canary-filled struct unchanged.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTInitRefused(const char *nameStr, size_t nameSize)
{
    SSF_REQUIRE(nameStr != NULL);

    memset(&_utTopics, SSF_AWSPROV_UT_CANARY, sizeof(_utTopics));
    memcpy(&_utCanary, &_utTopics, sizeof(_utCanary));
    if (SSFAWSProvTopicsInit(&_utTopics, nameStr, nameSize)) return false;
    return (memcmp(&_utTopics, &_utCanary, sizeof(_utTopics)) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the topics and subscription set built for nameStr.                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTTopicsCheck(const char *nameStr)
{
    size_t i;

    SSF_REQUIRE(nameStr != NULL);

    memset(&_utTopics, SSF_AWSPROV_UT_CANARY, sizeof(_utTopics));
    SSF_ASSERT(SSFAWSProvTopicsInit(&_utTopics, nameStr, (strlen(nameStr) + 1u)));

    _SSFAWSProvUTTopicExpect(nameStr, SSF_AWSPROV_UT_PT_REQ);
    SSF_ASSERT(strcmp(_utTopics.provReq, _utTopic) == 0);
    _SSFAWSProvUTTopicExpect(nameStr, SSF_AWSPROV_UT_PT_ACCEPTED);
    SSF_ASSERT(strcmp(_utTopics.provAccepted, _utTopic) == 0);
    _SSFAWSProvUTTopicExpect(nameStr, SSF_AWSPROV_UT_PT_REJECTED);
    SSF_ASSERT(strcmp(_utTopics.provRejected, _utTopic) == 0);

    SSF_ASSERT(strcmp(_utTopics.subs[SSF_AWSPROV_SUB_CSR_ACCEPTED].filter,
                      SSF_AWSPROV_UT_CSR_ACCEPTED) == 0);
    SSF_ASSERT(strcmp(_utTopics.subs[SSF_AWSPROV_SUB_CSR_REJECTED].filter,
                      SSF_AWSPROV_UT_CSR_REJECTED) == 0);
    SSF_ASSERT(_utTopics.subs[SSF_AWSPROV_SUB_PROV_ACCEPTED].filter == _utTopics.provAccepted);
    SSF_ASSERT(_utTopics.subs[SSF_AWSPROV_SUB_PROV_REJECTED].filter == _utTopics.provRejected);

    for (i = 0; i < SSF_AWSPROV_SUB_COUNT; i++)
    {
        SSF_ASSERT(_utTopics.subs[i].qos == SSF_MQTTC_QOS_1);
        SSF_ASSERT(SSFMQTTPktIsValidFilter(_utTopics.subs[i].filter,
                                           SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE));
    }
    SSF_ASSERT(SSFMQTTPktIsValidTopic(_utTopics.provReq, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE));
    SSF_ASSERT(SSFMQTTPktIsValidTopic(SSF_AWSPROV_TOPIC_CSR, SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks SSFAWSProvTopicsInit success, refusal and DBC.                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTTopicsInit(void)
{
    _SSFAWSProvUTTopicsCheck("Tmpl_1-x");
    SSF_ASSERT(strcmp(_utTopics.provAccepted,
                      "$aws/provisioning-templates/Tmpl_1-x/provision/json/accepted") == 0);
    _SSFAWSProvUTTopicsCheck("a");

    _SSFAWSProvUTNameFill('z', SSF_AWSPROV_UT_NAME_MAX_LEN);
    _SSFAWSProvUTTopicsCheck(_utName);
    SSF_ASSERT((strlen(_utTopics.provAccepted) + 1u) == SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT((strlen(_utTopics.provRejected) + 1u) == SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT((strlen(_utTopics.provReq) + 1u) < SSF_AWSPROV_MAX_TOPIC_SIZE);

    SSF_ASSERT(_SSFAWSProvUTInitRefused("", 1u));
    SSF_ASSERT(_SSFAWSProvUTInitRefused("a/b", 4u));
    SSF_ASSERT(_SSFAWSProvUTInitRefused("+", 2u));
    SSF_ASSERT(_SSFAWSProvUTInitRefused("#", 2u));
    SSF_ASSERT(_SSFAWSProvUTInitRefused("$aws", 5u));
    SSF_ASSERT(_SSFAWSProvUTInitRefused("ab", 2u));
    _SSFAWSProvUTNameFill('z', (SSF_AWSPROV_UT_NAME_MAX_LEN + 1u));
    SSF_ASSERT(_SSFAWSProvUTInitRefused(_utName, sizeof(_utName)));

    SSF_ASSERT_TEST((void)SSFAWSProvTopicsInit(NULL, "a", 2u));
    SSF_ASSERT_TEST((void)SSFAWSProvTopicsInit(&_utTopics, NULL, 2u));
}

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
/* --------------------------------------------------------------------------------------------- */
/* CSR request test data                                                                         */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_UT_CSR_BUF_SIZE (2048u)

static uint8_t _utScratch[SSF_AWSPROV_UT_CSR_BUF_SIZE];
static char _utOut[SSF_AWSPROV_UT_CSR_BUF_SIZE];
static char _utPem[SSF_AWSPROV_UT_CSR_BUF_SIZE];
static uint8_t _utDer[SSF_AWSPROV_UT_CSR_BUF_SIZE];

#if SSF_EC_CONFIG_ENABLE_P256 == 1
static const uint8_t _utAWSProvP256N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
static const uint8_t _utAWSProvP384N[48] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
};
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if key[0..keyLen) occurs anywhere in buf[0..bufSize).                            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTContains(const uint8_t *buf, size_t bufSize, const uint8_t *key,
                                  size_t keyLen)
{
    size_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(keyLen > 0u);

    for (i = 0; (i + keyLen) <= bufSize; i++)
    {
        if (memcmp(&buf[i], key, keyLen) == 0) return true;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a build fails with outStr "" and outLen 0, and leaks no key bytes.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTBuildRefused(SSFECCurve_t curve, const uint8_t *priv, size_t privLen,
                                      const SSFX509GenName_t *subjectOpt, size_t scratchSize,
                                      size_t outSize)
{
    size_t outLen = 1u;

    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(scratchSize <= sizeof(_utScratch));
    SSF_REQUIRE((outSize > 0u) && (outSize <= sizeof(_utOut)));

    memset(_utScratch, SSF_AWSPROV_UT_CANARY, sizeof(_utScratch));
    memset(_utOut, 'x', sizeof(_utOut));
    if (SSFAWSProvBuildCsrRequest(curve, priv, privLen, subjectOpt, _utScratch, scratchSize,
                                  _utOut, outSize, &outLen)) return false;
    if ((outLen != 0u) || (_utOut[0] != 0)) return false;
    if (privLen == 0u) return true;
    if (_SSFAWSProvUTContains(_utScratch, sizeof(_utScratch), priv, privLen)) return false;
    return (_SSFAWSProvUTContains((const uint8_t *)_utOut, sizeof(_utOut), priv, privLen) ==
            false);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes the bounds for der from a max-length signature, PEM encoding a buffer that size.     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTExpectBounds(const uint8_t *der, size_t derLen, size_t sigMaxLen,
                                      size_t *scratchOut, size_t *outOut)
{
    size_t i;
    size_t sigLen = 0;
    size_t derMax;
    size_t pemLen;
    size_t lines = 0;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(scratchOut != NULL);
    SSF_REQUIRE(outOut != NULL);
    SSF_REQUIRE(derLen > 120u);

    /* The signature is the last element: 03 len 00 30 sigLen-2 ... */
    for (i = (derLen - 110u); i < (derLen - 60u); i++)
    {
        if ((der[i] == 0x30u) && (((size_t)der[i + 1u] + 2u) == (derLen - i)) &&
            (der[i - 1u] == 0u) && (der[i - 3u] == 0x03u)) sigLen = derLen - i;
    }
    SSF_ASSERT((sigLen > 0u) && (sigLen <= sigMaxLen));
    SSF_ASSERT((der[0] == 0x30u) && ((der[1] == 0x81u) || (der[1] == 0x82u)));
    derMax = derLen + (sigMaxLen - sigLen);
    if ((der[1] == 0x81u) && (((size_t)der[2] + (sigMaxLen - sigLen)) > 0xFFu)) derMax++;

    memset(_utDer, 0, derMax);
    SSF_ASSERT(SSFPEMEncode("CERTIFICATE REQUEST", _utDer, derMax, _utPem, sizeof(_utPem),
                            &pemLen));
    for (i = 0; i < pemLen; i++)
    {
        if (_utPem[i] == '\n') lines++;
    }
    *scratchOut = derMax + pemLen + 1u;
    *outOut = strlen("{\"certificateSigningRequest\":\"") + pemLen + lines + strlen("\"}") + 1u;
}

/* --------------------------------------------------------------------------------------------- */
/* Builds a CSR request and checks it against its OpenSSL fixture, sizes and round trip.         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCsrFixture(SSFECCurve_t curve, const uint8_t *priv, size_t privLen,
                                    const SSFX509GenName_t *subjectOpt, const char *jsonStr,
                                    const uint8_t *der, size_t derLen)
{
    size_t scratchExpect;
    size_t outExpect;
    SSFGPath_t path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
    size_t scratchBound;
    size_t outBound;
    size_t outLen;
    size_t pemLen;
    size_t pos;
    size_t len;
    size_t need;
    const char *label;
    size_t labelLen;

    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(jsonStr != NULL);
    SSF_REQUIRE(der != NULL);

    /* Bounds, then the exact output */
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(curve, subjectOpt, &scratchBound, &outBound));
    SSF_ASSERT((scratchBound <= sizeof(_utScratch)) && (outBound <= sizeof(_utOut)));
    _SSFAWSProvUTExpectBounds(der, derLen, (8u + (2u * privLen)), &scratchExpect, &outExpect);
    SSF_ASSERT((scratchBound == scratchExpect) && (outBound == outExpect));
    memset(_utScratch, 0, sizeof(_utScratch));
    memset(_utOut, 'x', sizeof(_utOut));
    SSF_ASSERT(SSFAWSProvBuildCsrRequest(curve, priv, privLen, subjectOpt, _utScratch,
                                         scratchBound, _utOut, outBound, &outLen));
    SSF_ASSERT((outLen == strlen(jsonStr)) && (strcmp(_utOut, jsonStr) == 0));
    SSF_ASSERT(_SSFAWSProvUTContains(_utScratch, sizeof(_utScratch), priv, privLen) == false);
    SSF_ASSERT(_SSFAWSProvUTContains((const uint8_t *)_utOut, sizeof(_utOut), priv, privLen) ==
               false);

    /* The JSON parses back to a PEM that decodes to the fixture DER */
    memset((void *)path, 0, sizeof(path));
    SSF_GPATH_SET_KEY(path[0], "certificateSigningRequest");
    SSF_ASSERT(SSFJsonGetString(_utOut, path, _utPem, sizeof(_utPem), &pemLen));
    pos = 0;
    SSF_ASSERT(SSFPEMDecodeNext(_utPem, pemLen, &pos, &label, &labelLen, _utDer, sizeof(_utDer),
                                &len) == SSF_PEM_BLOCK);
    SSF_ASSERT(SSFPEMLabelIs(label, labelLen, "CERTIFICATE REQUEST"));
    SSF_ASSERT((len == derLen) && (memcmp(_utDer, der, derLen) == 0));

    /* Exact output fit passes, one byte short fails */
    SSF_ASSERT(SSFAWSProvBuildCsrRequest(curve, priv, privLen, subjectOpt, _utScratch,
                                         scratchBound, _utOut, (outLen + 1u), &len));
    SSF_ASSERT((len == outLen) && (strcmp(_utOut, jsonStr) == 0));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, subjectOpt, scratchBound, outLen));

    /* Exact scratch fit (DER then PEM with NUL) passes, one byte short fails */
    need = derLen + SSF_PEM_ENCODE_SIZE(19u, derLen);
    SSF_ASSERT(need <= scratchBound);
    SSF_ASSERT(SSFAWSProvBuildCsrRequest(curve, priv, privLen, subjectOpt, _utScratch, need,
                                         _utOut, outBound, &len));
    SSF_ASSERT((len == outLen) && (strcmp(_utOut, jsonStr) == 0));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, subjectOpt, (need - 1u),
                                         outBound));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, subjectOpt, (derLen - 1u),
                                         outBound));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, subjectOpt, derLen, outBound));
}

/* --------------------------------------------------------------------------------------------- */
/* Builds many subjects and checks each output fits the bounds from the sizes call.              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCsrBoundSweep(SSFECCurve_t curve, const uint8_t *priv, size_t privLen)
{
    SSFX509GenName_t subject;
    char cn[8];
    size_t scratchBound;
    size_t outBound;
    size_t outLen;
    size_t minLen = (size_t)-1;
    size_t maxLen = 0;
    uint16_t i;

    SSF_REQUIRE(priv != NULL);

    memset(&subject, 0, sizeof(subject));
    memcpy(cn, "dev-000", sizeof(cn));
    subject.cn = cn;
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(curve, &subject, &scratchBound, &outBound));
    for (i = 0; i < 200u; i++)
    {
        cn[4] = (char)('0' + (i / 100u));
        cn[5] = (char)('0' + ((i / 10u) % 10u));
        cn[6] = (char)('0' + (i % 10u));
        SSF_ASSERT(SSFAWSProvBuildCsrRequest(curve, priv, privLen, &subject, _utScratch,
                                             scratchBound, _utOut, outBound, &outLen));
        SSF_ASSERT((outLen + 1u) <= outBound);
        if (outLen < minLen) minLen = outLen;
        if (outLen > maxLen) maxLen = outLen;
    }
    SSF_ASSERT(minLen < maxLen);
    SSF_ASSERT((maxLen + 1u) == outBound);
}

/* --------------------------------------------------------------------------------------------- */
/* Checks key, subject, curve and buffer refusals for one curve.                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCsrRefusals(SSFECCurve_t curve, const uint8_t *priv, size_t privLen,
                                     const uint8_t *n)
{
    static const char cn65[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint8_t bad[SSF_ECDSA_MAX_PRIV_KEY_SIZE + 1u];
    SSFX509GenName_t subject;
    size_t scratchBound;
    size_t outBound;
    size_t outLen;

    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(n != NULL);
    SSF_REQUIRE(privLen < sizeof(bad));
    SSF_ASSERT(strlen(cn65) == 65u);

    memset(&subject, 0, sizeof(subject));
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(curve, NULL, &scratchBound, &outBound));

    /* Private keys: 0, n, all 0xFF, wrong lengths */
    memset(bad, 0, sizeof(bad));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, bad, privLen, NULL, scratchBound, outBound));
    memcpy(bad, n, privLen);
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, bad, privLen, NULL, scratchBound, outBound));
    memset(bad, 0xFF, sizeof(bad));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, bad, privLen, NULL, scratchBound, outBound));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, (privLen - 1u), NULL, scratchBound,
                                         outBound));
    memcpy(bad, priv, privLen);
    bad[privLen] = 0;
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, bad, (privLen + 1u), NULL, scratchBound,
                                         outBound));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, 0u, NULL, scratchBound, outBound));

    /* Subjects: CN of 65 bytes and a non-UTF-8 O; a CN of 64 bytes is accepted */
    subject.cn = cn65;
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(curve, &subject, &scratchBound, &outBound) == false);
    SSF_ASSERT((scratchBound == 0u) && (outBound == 0u));
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(curve, NULL, &scratchBound, &outBound));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, &subject, sizeof(_utScratch),
                                         sizeof(_utOut)));
    subject.cn = &cn65[1];
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(curve, &subject, &scratchBound, &outBound));
    SSF_ASSERT(SSFAWSProvBuildCsrRequest(curve, priv, privLen, &subject, _utScratch,
                                         scratchBound, _utOut, outBound, &outLen));
    subject.cn = NULL;
    subject.o = "\xC0\xAF";
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(curve, &subject, &scratchBound, &outBound) == false);
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, &subject, sizeof(_utScratch),
                                         sizeof(_utOut)));

    /* Tiny buffers */
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, NULL, 0u, sizeof(_utOut)));
    SSF_ASSERT(_SSFAWSProvUTBuildRefused(curve, priv, privLen, NULL, sizeof(_utScratch), 1u));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the CreateCertificateFromCsr request builder.                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCsrRequest(void)
{
    SSFX509GenName_t subject;
    size_t scratchSize;
    size_t outSize;
    size_t outLen;

    memset(&subject, 0, sizeof(subject));
    subject.c = "US";
    subject.o = "SSF";

#if SSF_EC_CONFIG_ENABLE_P256 == 1
    _SSFAWSProvUTCsrFixture(SSF_EC_CURVE_P256, _utAWSProvP256Priv, sizeof(_utAWSProvP256Priv),
                            NULL, _utAWSProvP256EmptyJson, _utAWSProvP256EmptyDer,
                            sizeof(_utAWSProvP256EmptyDer));
    subject.cn = "dev-1";
    _SSFAWSProvUTCsrFixture(SSF_EC_CURVE_P256, _utAWSProvP256Priv, sizeof(_utAWSProvP256Priv),
                            &subject, _utAWSProvP256CNOCJson, _utAWSProvP256CNOCDer,
                            sizeof(_utAWSProvP256CNOCDer));
    _SSFAWSProvUTCsrBoundSweep(SSF_EC_CURVE_P256, _utAWSProvP256Priv, sizeof(_utAWSProvP256Priv));
    _SSFAWSProvUTCsrRefusals(SSF_EC_CURVE_P256, _utAWSProvP256Priv, sizeof(_utAWSProvP256Priv),
                             _utAWSProvP256N);
#else
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(SSF_EC_CURVE_P256, NULL, &scratchSize, &outSize) ==
               false);
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    _SSFAWSProvUTCsrFixture(SSF_EC_CURVE_P384, _utAWSProvP384Priv, sizeof(_utAWSProvP384Priv),
                            NULL, _utAWSProvP384EmptyJson, _utAWSProvP384EmptyDer,
                            sizeof(_utAWSProvP384EmptyDer));
    subject.cn = "dev-384";
    _SSFAWSProvUTCsrFixture(SSF_EC_CURVE_P384, _utAWSProvP384Priv, sizeof(_utAWSProvP384Priv),
                            &subject, _utAWSProvP384CNOCJson, _utAWSProvP384CNOCDer,
                            sizeof(_utAWSProvP384CNOCDer));
    _SSFAWSProvUTCsrBoundSweep(SSF_EC_CURVE_P384, _utAWSProvP384Priv, sizeof(_utAWSProvP384Priv));
    _SSFAWSProvUTCsrRefusals(SSF_EC_CURVE_P384, _utAWSProvP384Priv, sizeof(_utAWSProvP384Priv),
                             _utAWSProvP384N);
#else
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(SSF_EC_CURVE_P384, NULL, &scratchSize, &outSize) ==
               false);
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    /* Curves that are not built or not defined */
    SSF_ASSERT(SSFAWSProvCsrRequestSizes(SSF_EC_CURVE_MAX, NULL, &scratchSize, &outSize) ==
               false);
    SSF_ASSERT((scratchSize == 0u) && (outSize == 0u));
    memset(_utOut, 'x', sizeof(_utOut));
    outLen = 1u;
    SSF_ASSERT(SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_MAX, (const uint8_t *)"k", 1u, NULL,
                                         _utScratch, sizeof(_utScratch), _utOut, sizeof(_utOut),
                                         &outLen) == false);
    SSF_ASSERT((outLen == 0u) && (_utOut[0] == 0));

    /* DBC */
    SSF_ASSERT_TEST((void)SSFAWSProvCsrRequestSizes(SSF_EC_CURVE_P256, NULL, NULL, &outSize));
    SSF_ASSERT_TEST((void)SSFAWSProvCsrRequestSizes(SSF_EC_CURVE_P256, NULL, &scratchSize, NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, NULL, 32u, NULL,
                                                    _utScratch, sizeof(_utScratch), _utOut,
                                                    sizeof(_utOut), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utScratch, 32u, NULL,
                                                    NULL, sizeof(_utScratch), _utOut,
                                                    sizeof(_utOut), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utDer, 32u, NULL,
                                                    _utScratch, sizeof(_utScratch), NULL,
                                                    sizeof(_utOut), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utDer, 32u, NULL,
                                                    _utScratch, sizeof(_utScratch), _utOut,
                                                    0u, &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utDer, 32u, NULL,
                                                    _utScratch, sizeof(_utScratch), _utOut,
                                                    sizeof(_utOut), NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utDer, 32u, NULL,
                                                    _utScratch, sizeof(_utScratch),
                                                    (char *)&_utScratch[8], 64u, &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utDer, 32u, NULL,
                                                    &_utScratch[16], 64u,
                                                    (char *)_utScratch, 17u, &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, &_utScratch[4], 32u, NULL,
                                                    _utScratch, sizeof(_utScratch), _utOut,
                                                    sizeof(_utOut), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, (uint8_t *)&_utOut[4],
                                                    32u, NULL, _utScratch, sizeof(_utScratch),
                                                    _utOut, sizeof(_utOut), &outLen));
    memset(&subject, 0, sizeof(subject));
    memcpy(&_utScratch[100], "dev", 4u);
    subject.l = (const char *)&_utScratch[100];
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utDer, 32u, &subject,
                                                    _utScratch, sizeof(_utScratch), _utOut,
                                                    sizeof(_utOut), &outLen));
    memcpy(&_utOut[100], "dev", 4u);
    subject.l = NULL;
    subject.cn = &_utOut[100];
    SSF_ASSERT_TEST((void)SSFAWSProvBuildCsrRequest(SSF_EC_CURVE_P256, _utDer, 32u, &subject,
                                                    _utScratch, sizeof(_utScratch), _utOut,
                                                    sizeof(_utOut), &outLen));
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */

/* --------------------------------------------------------------------------------------------- */
/* Runs the ssfawsprov unit test.                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFAWSProvUnitTest(void)
{
    _SSFAWSProvUTSizes();
    _SSFAWSProvUTConfig();
    _SSFAWSProvUTNameIsValid();
    _SSFAWSProvUTTopicsInit();
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
    _SSFAWSProvUTCsrRequest();
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */
}

#endif /* SSF_CONFIG_AWSPROV_UNIT_TEST */
