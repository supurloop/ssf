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
#include "ssfsm.h"
#include "ssfnet.h"
#include "ssfmqttpkt.h"
#include "ssfcrc32.h"
#include "ssfcfg.h"
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
/* CSR accepted and rejected response test data                                                  */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_UT_RX_SIZE (2u * SSF_AWSPROV_CONFIG_RX_SIZE)
#if (SSF_AWSPROV_CONFIG_TOKEN_SIZE >= 1024u) && (SSF_AWSPROV_CONFIG_CERT_DER_SIZE >= 1024u) && \
    (SSF_JSON_CONFIG_MAX_IN_LEN >= 4095u)
#define SSF_AWSPROV_UT_ACC_FULL (1u)
#else
#define SSF_AWSPROV_UT_ACC_FULL (0u)
#endif

static char _utRx[SSF_AWSPROV_UT_RX_SIZE];
static char _utJson[SSF_AWSPROV_UT_RX_SIZE];
static char _utVal[SSF_AWSPROV_UT_RX_SIZE];
static char _utPemText[SSF_AWSPROV_UT_RX_SIZE];
static char _utPemTmp[SSF_AWSPROV_UT_RX_SIZE];
static uint8_t _utDerTmp[2048];
static SSFAWSProvCsrAccepted_t _utAcc;
static SSFAWSProvCsrAccepted_t _utAccZero;
static uint8_t _utPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
static size_t _utPubLen;

/* --------------------------------------------------------------------------------------------- */
/* Appends str to buf at *len; asserts it fits with its NUL.                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCat(char *buf, size_t size, size_t *len, const char *str)
{
    size_t n;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(len != NULL);
    SSF_REQUIRE(str != NULL);

    n = strlen(str);
    SSF_ASSERT((*len + n) < size);
    memcpy(&buf[*len], str, (n + 1u));
    *len += n;
}

/* --------------------------------------------------------------------------------------------- */
/* Writes pemStr into _utVal as a quoted JSON string with each newline escaped.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _utEscSlash;

static void _SSFAWSProvUTQuotePem(const char *pemStr)
{
    size_t o = 0;
    size_t i;

    SSF_REQUIRE(pemStr != NULL);

    _utVal[o++] = '"';
    for (i = 0; pemStr[i] != 0; i++)
    {
        SSF_ASSERT((o + 3u) < sizeof(_utVal));
        if (pemStr[i] == '\n')
        {
            _utVal[o++] = '\\';
            _utVal[o++] = 'n';
        }
        else if ((pemStr[i] == '/') && _utEscSlash)
        {
            _utVal[o++] = '\\';
            _utVal[o++] = '/';
        }
        else _utVal[o++] = pemStr[i];
    }
    _utVal[o++] = '"';
    _utVal[o] = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Builds an accepted response in _utJson from raw JSON values; NULL omits a member.             */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFAWSProvUTAccJson(const char *tokenValOpt, const char *idValOpt,
                                   const char *pemValOpt)
{
    size_t len = 0;
    bool comma = false;

    _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, "{");
    if (tokenValOpt != NULL)
    {
        _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, "\"certificateOwnershipToken\":");
        _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, tokenValOpt);
        comma = true;
    }
    if (idValOpt != NULL)
    {
        if (comma) _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, ",");
        _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, "\"certificateId\":");
        _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, idValOpt);
        comma = true;
    }
    if (pemValOpt != NULL)
    {
        if (comma) _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, ",");
        _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, "\"certificatePem\":");
        _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, pemValOpt);
    }
    _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, "}");
    return len;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the first occurrence of key[0..keyLen) in buf[0..bufSize), or NULL.                   */
/* --------------------------------------------------------------------------------------------- */
static uint8_t *_SSFAWSProvUTFind(uint8_t *buf, size_t bufSize, const uint8_t *key, size_t keyLen)
{
    size_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(key != NULL);

    for (i = 0; (i + keyLen) <= bufSize; i++)
    {
        if (memcmp(&buf[i], key, keyLen) == 0) return &buf[i];
    }
    return NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if every byte of buf[0..size) is zero.                                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTIsZero(const void *buf, size_t size)
{
    const uint8_t *b = (const uint8_t *)buf;
    size_t i;

    SSF_REQUIRE(buf != NULL);

    for (i = 0; i < size; i++)
    {
        if (b[i] != 0u) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if parsing payload fails and leaves out and the rx copy zeroed.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTAccRefused(const char *payload, size_t payloadLen, size_t rxSize,
                                    SSFECCurve_t curve)
{
    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE(rxSize <= sizeof(_utRx));

    memset(&_utAcc, 0x5A, sizeof(_utAcc));
    memset(_utRx, 0x5A, sizeof(_utRx));
    if (SSFAWSProvParseCsrAccepted((const uint8_t *)payload, payloadLen, _utRx, rxSize, curve,
                                   _utPub, _utPubLen, &_utAcc)) return false;
    if (memcmp(&_utAcc, &_utAccZero, sizeof(_utAcc)) != 0) return false;
    return _SSFAWSProvUTIsZero(_utRx, rxSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Parses an accepted response that must succeed and checks every output.                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTAccOk(const char *payload, size_t payloadLen, size_t rxSize,
                               SSFECCurve_t curve, const uint8_t *der, size_t derLen)
{
    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(rxSize <= sizeof(_utRx));

    memset(&_utAcc, 0x5A, sizeof(_utAcc));
    memset(_utRx, 0x5A, sizeof(_utRx));
    SSF_ASSERT(SSFAWSProvParseCsrAccepted((const uint8_t *)payload, payloadLen, _utRx, rxSize,
                                          curve, _utPub, _utPubLen, &_utAcc));
    SSF_ASSERT(strcmp(_utAcc.certificateId, _utAWSProvCertId) == 0);
    SSF_ASSERT(_utAcc.tokenLen == strlen(_utAWSProvToken));
    SSF_ASSERT(strcmp(_utAcc.token, _utAWSProvToken) == 0);
    SSF_ASSERT((_utAcc.certDerLen == derLen) && (memcmp(_utAcc.certDer, der, derLen) == 0));
    SSF_ASSERT(_utAcc.cert.notAfter == SSF_AWSPROV_UT_CERT_NOT_AFTER);
    SSF_ASSERT(_utAcc.cert.pubKeyLen == _utPubLen);
    SSF_ASSERT(_SSFAWSProvUTIsZero(_utRx, rxSize));
}

#if SSF_AWSPROV_UT_ACC_FULL == 0
/* --------------------------------------------------------------------------------------------- */
/* Checks the happy path is accepted exactly when the configured buffers can hold it.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTAccSized(size_t len, SSFECCurve_t curve, const char *pemStr,
                                  const uint8_t *der, size_t derLen)
{
    bool fits;

    SSF_REQUIRE(pemStr != NULL);
    SSF_REQUIRE(der != NULL);

    fits = ((len <= SSF_JSON_CONFIG_MAX_IN_LEN) &&
            (strlen(_utAWSProvToken) < SSF_AWSPROV_CONFIG_TOKEN_SIZE) &&
            (derLen <= SSF_AWSPROV_CONFIG_CERT_DER_SIZE) &&
            ((len + 1u + strlen(pemStr) + 1u) <= sizeof(_utRx)));
    /* Does the response fit this build's limits? */
    if (fits)
    {
        /* Yes, accepted */
        _SSFAWSProvUTAccOk(_utJson, len, sizeof(_utRx), curve, der, derLen);
    }
    else
    {
        /* No, refused */
        SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), curve));
    }
}
#endif /* SSF_AWSPROV_UT_ACC_FULL */

/* --------------------------------------------------------------------------------------------- */
/* Builds the happy-path accepted response for pemStr in _utJson and returns its length.         */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFAWSProvUTAccGood(const char *pemStr)
{
    static char tok[sizeof(_utAWSProvToken) + 2u];
    static char id[sizeof(_utAWSProvCertId) + 2u];

    SSF_REQUIRE(pemStr != NULL);

    tok[0] = '"';
    memcpy(&tok[1], _utAWSProvToken, (sizeof(_utAWSProvToken) - 1u));
    memcpy(&tok[sizeof(_utAWSProvToken)], "\"", 2u);
    id[0] = '"';
    memcpy(&id[1], _utAWSProvCertId, (sizeof(_utAWSProvCertId) - 1u));
    memcpy(&id[sizeof(_utAWSProvCertId)], "\"", 2u);
    _SSFAWSProvUTQuotePem(pemStr);
    return _SSFAWSProvUTAccJson(tok, id, _utVal);
}

#if (SSF_EC_CONFIG_ENABLE_P256 == 1) && (SSF_AWSPROV_UT_ACC_FULL == 1)
/* --------------------------------------------------------------------------------------------- */
/* Checks accepted-response refusals on P-256: fields, id, token, PEM, key and payload.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTAccRefusals(void)
{
    static char tok[SSF_AWSPROV_CONFIG_TOKEN_SIZE + 4u];
    static const char goodTok[] = "\"abc\"";
    static const char goodId[] =
        "\"cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e48\"";
    size_t len;
    size_t i;
    size_t need;
    bool expect;
    char *at;

    SSF_ASSERT(strstr(goodId, _utAWSProvCertId) != NULL);
    _SSFAWSProvUTQuotePem(_utAWSProvP256CertPem);
    memcpy(_utPemText, _utVal, (strlen(_utVal) + 1u));

    /* Each member missing, and each of the wrong type */
    len = _SSFAWSProvUTAccJson(NULL, goodId, _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok, NULL, _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok, goodId, NULL);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson("{}", goodId, _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson("12", goodId, _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok, "5", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok, "[\"a\"]", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok, goodId, "null");
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));

    /* certificateId: 63 and 65 characters, uppercase, non-hex */
    len = _SSFAWSProvUTAccJson(goodTok,
        "\"cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e4\"", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok,
        "\"cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e480\"", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok,
        "\"Cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e48\"", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok,
        "\"cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e4g\"", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok,
        "\"cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e4/\"", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok,
        "\"cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e4:\"", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccJson(goodTok,
        "\"cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e4`\"", _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));

    /* Token: empty refused; TOKEN_SIZE - 1 characters fit, TOKEN_SIZE do not */
    len = _SSFAWSProvUTAccJson("\"\"", goodId, _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    tok[0] = '"';
    memset(&tok[1], 'T', SSF_AWSPROV_CONFIG_TOKEN_SIZE);
    tok[SSF_AWSPROV_CONFIG_TOKEN_SIZE] = '"';
    tok[SSF_AWSPROV_CONFIG_TOKEN_SIZE + 1u] = 0;
    len = _SSFAWSProvUTAccJson(tok, goodId, _utPemText);
    need = len + 1u + strlen(_utAWSProvP256CertPem) + 1u;
    expect = ((len <= SSF_JSON_CONFIG_MAX_IN_LEN) && (need <= sizeof(_utRx)));
#if (SSF_AWSPROV_CONFIG_TOKEN_SIZE == 2048u) && (SSF_JSON_CONFIG_MAX_IN_LEN >= 4095u)
    SSF_ASSERT(expect);
#endif
    memset(&_utAcc, 0, sizeof(_utAcc));
    SSF_ASSERT(SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx,
                                          ((need <= sizeof(_utRx)) ? need : sizeof(_utRx)),
                                          SSF_EC_CURVE_P256, _utPub, _utPubLen, &_utAcc) ==
               expect);
    SSF_ASSERT((expect == false) || (_utAcc.tokenLen == (SSF_AWSPROV_CONFIG_TOKEN_SIZE - 1u)));
    tok[SSF_AWSPROV_CONFIG_TOKEN_SIZE + 1u] = '"';
    tok[SSF_AWSPROV_CONFIG_TOKEN_SIZE + 2u] = 0;
    tok[SSF_AWSPROV_CONFIG_TOKEN_SIZE] = 'T';
    len = _SSFAWSProvUTAccJson(tok, goodId, _utPemText);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));

    /* PEM: two blocks, wrong label, damaged Base64, a \u escape, truncated DER */
    memcpy(_utVal, _utPemText, (strlen(_utPemText) - 1u));
    _utVal[strlen(_utPemText) - 1u] = 0;
    i = strlen(_utVal);
    memcpy(&_utVal[i], &_utPemText[1], (strlen(_utPemText)));
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    memcpy(_utVal, _utPemText, (strlen(_utPemText) + 1u));
    at = strstr(_utVal, "BEGIN CERTIFICATE");
    SSF_ASSERT(at != NULL);
    memcpy(&at[6], "CERTIFICATX", 11u);
    at = strstr(_utVal, "END CERTIFICATE");
    SSF_ASSERT(at != NULL);
    memcpy(&at[4], "CERTIFICATX", 11u);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    memcpy(_utVal, _utPemText, (strlen(_utPemText) + 1u));
    _utVal[80] = '*';
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    memcpy(_utVal, _utPemText, (strlen(_utPemText) + 1u));
    memcpy(&_utVal[80], "\\u0041", 6u);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    SSF_ASSERT(SSFPEMEncode("CERTIFICATE", _utAWSProvP256CertDer,
                            (sizeof(_utAWSProvP256CertDer) - 16u), _utPemTmp,
                            sizeof(_utPemTmp), &need));
    _SSFAWSProvUTQuotePem(_utPemTmp);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));

    /* The device key under another key algorithm OID */
    memcpy(_utDerTmp, _utAWSProvP256CertDer, sizeof(_utAWSProvP256CertDer));
    at = (char *)_SSFAWSProvUTFind(_utDerTmp, sizeof(_utAWSProvP256CertDer),
                                   (const uint8_t *)"\x2A\x86\x48\xCE\x3D\x02\x01", 7u);
    SSF_ASSERT(at != NULL);
    at[6] = 0x02;
    SSF_ASSERT(SSFPEMEncode("CERTIFICATE", _utDerTmp, sizeof(_utAWSProvP256CertDer), _utPemTmp,
                            sizeof(_utPemTmp), &need));
    _SSFAWSProvUTQuotePem(_utPemTmp);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));

    /* The device key under another curve OID, and with unused bits 1 */
    memcpy(_utDerTmp, _utAWSProvP256CertDer, sizeof(_utAWSProvP256CertDer));
    at = (char *)_SSFAWSProvUTFind(_utDerTmp, sizeof(_utAWSProvP256CertDer),
                                   (const uint8_t *)"\x2A\x86\x48\xCE\x3D\x03\x01\x07", 8u);
    SSF_ASSERT(at != NULL);
    at[7] = 0x08;
    SSF_ASSERT(SSFPEMEncode("CERTIFICATE", _utDerTmp, sizeof(_utAWSProvP256CertDer), _utPemTmp,
                            sizeof(_utPemTmp), &need));
    _SSFAWSProvUTQuotePem(_utPemTmp);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    memcpy(_utDerTmp, _utAWSProvP256CertDer, sizeof(_utAWSProvP256CertDer));
    at = (char *)_SSFAWSProvUTFind(_utDerTmp, sizeof(_utAWSProvP256CertDer), _utPub, _utPubLen);
    SSF_ASSERT((at != NULL) && (at[-1] == 0) && (at[-3] == 0x03));
    at[-1] = 0x01;
    SSF_ASSERT(SSFPEMEncode("CERTIFICATE", _utDerTmp, sizeof(_utAWSProvP256CertDer), _utPemTmp,
                            sizeof(_utPemTmp), &need));
    _SSFAWSProvUTQuotePem(_utPemTmp);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));

    /* Certificate for another key, and for the other curve */
    _SSFAWSProvUTQuotePem(_utAWSProvOtherCertPem);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    _SSFAWSProvUTQuotePem(_utAWSProvP384CertPem);
    len = _SSFAWSProvUTAccJson(goodTok, goodId, _utVal);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    /* Payload: exact rx fit (payload, NUL, decoded PEM, NUL) passes, one byte less fails */
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    need = len + 1u + strlen(_utAWSProvP256CertPem) + 1u;
    _SSFAWSProvUTAccOk(_utJson, len, need, SSF_EC_CURVE_P256, _utAWSProvP256CertDer,
                       sizeof(_utAWSProvP256CertDer));
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, (need - 1u), SSF_EC_CURVE_P256));
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, len, SSF_EC_CURVE_P256));
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, (len + 1u), SSF_EC_CURVE_P256));

    /* Payload: embedded NUL, non-JSON, empty, truncated */
    _utJson[len - 1u] = 0;
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    _utJson[len - 1u] = '}';
    _utJson[1] = 0;
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    SSF_ASSERT(_SSFAWSProvUTAccRefused("hello", 5u, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    memcpy(&_utJson[len], "\0x", 3u);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, (len + 2u), sizeof(_utRx), SSF_EC_CURVE_P256));
    memcpy(&_utJson[len], " }", 3u);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, (len + 2u), sizeof(_utRx), SSF_EC_CURVE_P256));
    SSF_ASSERT(_SSFAWSProvUTAccRefused("", 0u, sizeof(_utRx), SSF_EC_CURVE_P256));
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, (len - 1u), sizeof(_utRx), SSF_EC_CURVE_P256));

    /* A duplicate member: the first occurrence is used */
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    _utJson[len - 1u] = 0;
    len--;
    _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len, ",\"certificateId\":\"0\"}");
    _SSFAWSProvUTAccOk(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256, _utAWSProvP256CertDer,
                       sizeof(_utAWSProvP256CertDer));

    /* A member only inside a nested object is not found */
    len = _SSFAWSProvUTAccJson(goodTok, "\"x\",\"n\":{\"certificateId\":\""
        "cf380f5f152eddf37cc7892f83607c2f4cb3b450cb27bbd31cc12d759a8d6e48\"}", _utPemText);
    at = strstr(_utJson, "\"certificateId\":\"x\"");
    SSF_ASSERT(at != NULL);
    at[13] = 'X';
    SSF_ASSERT(strlen(_utJson) == len);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));
    at[13] = 'd';
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256));

    /* Duplicate token and PEM members: the first occurrences are used */
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    _utJson[len - 1u] = 0;
    len--;
    _SSFAWSProvUTCat(_utJson, sizeof(_utJson), &len,
                     ",\"certificateOwnershipToken\":\"x\",\"certificatePem\":\"y\"}");
    _SSFAWSProvUTAccOk(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256, _utAWSProvP256CertDer,
                       sizeof(_utAWSProvP256CertDer));

    /* A PEM written with \/ escapes is accepted */
    SSF_ASSERT(strchr(_utAWSProvP256CertPem, '/') != NULL);
    _utEscSlash = true;
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    _utEscSlash = false;
    SSF_ASSERT(strstr(_utJson, "\\/") != NULL);
    _SSFAWSProvUTAccOk(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256, _utAWSProvP256CertDer,
                       sizeof(_utAWSProvP256CertDer));

    /* An undefined curve is a contract violation */
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx,
                                                     sizeof(_utRx), SSF_EC_CURVE_MAX, _utPub,
                                                     _utPubLen, &_utAcc));
}
#endif /* SSF_EC_CONFIG_ENABLE_P256, SSF_AWSPROV_UT_ACC_FULL */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a rejected response parses to statusCode and the two strings.                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTRej(const char *payload, size_t codeSize, size_t msgSize,
                             uint16_t status, const char *codeStr, const char *msgStr)
{
    static char code[64];
    static char msg[64];
    uint16_t sc = 1u;

    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE((codeSize <= sizeof(code)) && (msgSize <= sizeof(msg)));

    memset(code, 'x', sizeof(code));
    memset(msg, 'x', sizeof(msg));
    memset(_utRx, 0x5A, sizeof(_utRx));
    /* Is the response expected to be refused? */
    if (codeStr == NULL)
    {
        /* Yes, all outputs empty */
        if (SSFAWSProvParseRejected((const uint8_t *)payload, strlen(payload), _utRx,
                                    sizeof(_utRx), &sc, code, codeSize, msg, msgSize))
            return false;
        return ((sc == 0u) && _SSFAWSProvUTIsZero(code, codeSize) &&
                _SSFAWSProvUTIsZero(msg, msgSize) && _SSFAWSProvUTIsZero(_utRx, sizeof(_utRx)));
    }
    /* No, the outputs as given */
    if (SSFAWSProvParseRejected((const uint8_t *)payload, strlen(payload), _utRx, sizeof(_utRx),
                                &sc, code, codeSize, msg, msgSize) == false) return false;
    return ((sc == status) && (strcmp(code, codeStr) == 0) && (strcmp(msg, msgStr) == 0) &&
            _SSFAWSProvUTIsZero(_utRx, sizeof(_utRx)));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the rejected-response parser.                                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTRejected(void)
{
    static uint16_t rx16[8];
    uint16_t sc;
    char code[8];
    char msg[8];

    SSF_ASSERT(_SSFAWSProvUTRej(
        "{\"statusCode\":400,\"errorCode\":\"InvalidCSR\",\"errorMessage\":\"bad csr\"}",
        64u, 64u, 400u, "InvalidCSR", "bad csr"));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"errorCode\":\"Throttled\",\"statusCode\":429}", 64u, 64u,
                                429u, "Throttled", ""));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":100,\"errorCode\":\"a\"}", 64u, 64u, 100u, "a",
                                ""));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":599,\"errorCode\":\"a\"}", 64u, 64u, 599u, "a",
                                ""));

    /* errorMessage truncated to fit, errorCode must fit */
    SSF_ASSERT(_SSFAWSProvUTRej(
        "{\"statusCode\":500,\"errorCode\":\"ab\",\"errorMessage\":\"0123456789\"}", 3u, 5u,
        500u, "ab", "0123"));
    SSF_ASSERT(_SSFAWSProvUTRej(
        "{\"statusCode\":500,\"errorCode\":\"abc\",\"errorMessage\":\"x\"}", 3u, 5u, 0u, NULL,
        NULL));

    /* Bytes outside 0x20..0x7E become '?' */
    SSF_ASSERT(_SSFAWSProvUTRej(
        "{\"statusCode\":403,\"errorCode\":\"a\\tb\",\"errorMessage\":\"c\\u00e9d\\u0000e\"}",
        64u, 64u, 403u, "a?b", "c??d??e"));

    /* Sanitizer edges: 0x1F and 0x7F replaced, 0x20 and 0x7E kept; an escape cut at the end */
    SSF_ASSERT(_SSFAWSProvUTRej(
        "{\"statusCode\":403,\"errorCode\":\"a\",\"errorMessage\":\" ~\\u001f\\u007f\"}",
        64u, 64u, 403u, "a", " ~????"));
    SSF_ASSERT(_SSFAWSProvUTRej(
        "{\"statusCode\":403,\"errorCode\":\"a\",\"errorMessage\":\"ab\\u00e9\"}", 64u, 4u,
        403u, "a", "ab?"));

    /* Refused: status out of range or not an integer, required members missing or mistyped */
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":99,\"errorCode\":\"a\"}", 64u, 64u, 0u, NULL,
                                NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":600,\"errorCode\":\"a\"}", 64u, 64u, 0u, NULL,
                                NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":-400,\"errorCode\":\"a\"}", 64u, 64u, 0u, NULL,
                                NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":\"400\",\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"errorCode\":\"a\"}", 64u, 64u, 0u, NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":400.9,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":4e2,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":1e300,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":0400,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":40,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":099,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":1000,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":5x9,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":59x,\"errorCode\":\"a\"}", 64u, 64u, 0u,
                                NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":400}", 64u, 64u, 0u, NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":400,\"errorCode\":7}", 64u, 64u, 0u, NULL,
                                NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("{\"statusCode\":400,\"errorCode\":\"a\",\"errorMessage\":7}",
                                64u, 64u, 400u, "a", ""));
    SSF_ASSERT(_SSFAWSProvUTRej("[1]", 64u, 64u, 0u, NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRej("", 64u, 64u, 0u, NULL, NULL));

    /* DBC */
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected(NULL, 1u, _utRx, sizeof(_utRx), &sc, code,
                                                  sizeof(code), msg, sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, NULL, 1u, &sc, code,
                                                  sizeof(code), msg, sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, _utRx, 0u, &sc,
                                                  code, sizeof(code), msg, sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, _utRx,
                                                  sizeof(_utRx), NULL, code, sizeof(code), msg,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, _utRx,
                                                  sizeof(_utRx), &sc, NULL, sizeof(code), msg,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, _utRx,
                                                  sizeof(_utRx), &sc, code, 0u, msg,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, _utRx,
                                                  sizeof(_utRx), &sc, code, sizeof(code), NULL,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, _utRx,
                                                  sizeof(_utRx), &sc, code, sizeof(code), msg,
                                                  0u));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)&_utRx[4], 2u, _utRx,
                                                  sizeof(_utRx), &sc, code, sizeof(code), msg,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)code, 2u, _utRx,
                                                  sizeof(_utRx), &sc, code, sizeof(code), msg,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)msg, 2u, _utRx,
                                                  sizeof(_utRx), &sc, code, sizeof(code), msg,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)&sc, 2u, _utRx,
                                                  sizeof(_utRx), &sc, code, sizeof(code), msg,
                                                  sizeof(msg)));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRejected((const uint8_t *)"{}", 2u, (char *)rx16,
                                                  sizeof(rx16), &rx16[1], code, sizeof(code),
                                                  msg, sizeof(msg)));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the status code classification.                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTRetryable(void)
{
    static const uint16_t retry[] = { 429u, 500u, 503u, 504u, 599u };
    static const uint16_t fatal[] = { 0u, 99u, 100u, 200u, 399u, 400u, 401u, 403u, 404u, 408u,
                                      409u, 428u, 430u, 499u, 600u, 0xFFFFu };
    static const char throttled[] = "{\"statusCode\":429,\"errorCode\":\"Throttled\"}";
    static const char badCsr[] = "{\"statusCode\":400,\"errorCode\":\"InvalidCSR\"}";
    char code[16];
    char msg[16];
    uint16_t sc;
    uint32_t v;
    size_t i;

    for (i = 0; i < (sizeof(retry) / sizeof(retry[0])); i++)
    {
        SSF_ASSERT(SSFAWSProvIsRetryable(retry[i]));
    }
    for (i = 0; i < (sizeof(fatal) / sizeof(fatal[0])); i++)
    {
        SSF_ASSERT(SSFAWSProvIsRetryable(fatal[i]) == false);
    }

    /* Every value against the rule */
    for (v = 0; v <= 0xFFFFu; v++)
    {
        SSF_ASSERT(SSFAWSProvIsRetryable((uint16_t)v) ==
                   ((v == 429u) || ((v >= 500u) && (v <= 599u))));
    }

    /* End to end through the rejected-response parser */
    SSF_ASSERT(SSFAWSProvParseRejected((const uint8_t *)throttled, strlen(throttled), _utRx,
                                       sizeof(_utRx), &sc, code, sizeof(code), msg,
                                       sizeof(msg)));
    SSF_ASSERT(SSFAWSProvIsRetryable(sc));
    SSF_ASSERT(SSFAWSProvParseRejected((const uint8_t *)badCsr, strlen(badCsr), _utRx,
                                       sizeof(_utRx), &sc, code, sizeof(code), msg, sizeof(msg)));
    SSF_ASSERT(SSFAWSProvIsRetryable(sc) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the accepted-response parser on each built curve.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCsrAccepted(void)
{
    uint8_t *der;
    size_t len;

    memset(&_utAccZero, 0, sizeof(_utAccZero));
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                         sizeof(_utAWSProvP256Priv), _utPub, sizeof(_utPub),
                                         &_utPubLen));
    len = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
#if SSF_AWSPROV_UT_ACC_FULL == 1
    _SSFAWSProvUTAccOk(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P256, _utAWSProvP256CertDer,
                       sizeof(_utAWSProvP256CertDer));
    _SSFAWSProvUTAccRefusals();
#else
    _SSFAWSProvUTAccSized(len, SSF_EC_CURVE_P256, _utAWSProvP256CertPem, _utAWSProvP256CertDer,
                          sizeof(_utAWSProvP256CertDer));
#endif /* SSF_AWSPROV_UT_ACC_FULL */

    /* DBC */
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted(NULL, len, _utRx, sizeof(_utRx),
                                                     SSF_EC_CURVE_P256, _utPub, _utPubLen,
                                                     &_utAcc));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, NULL,
                                                     sizeof(_utRx), SSF_EC_CURVE_P256, _utPub,
                                                     _utPubLen, &_utAcc));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx, 0u,
                                                     SSF_EC_CURVE_P256, _utPub, _utPubLen,
                                                     &_utAcc));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx,
                                                     sizeof(_utRx), SSF_EC_CURVE_P256, NULL,
                                                     _utPubLen, &_utAcc));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx,
                                                     sizeof(_utRx), SSF_EC_CURVE_P256, _utPub,
                                                     (_utPubLen - 1u), &_utAcc));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx,
                                                     sizeof(_utRx), SSF_EC_CURVE_P256, _utPub,
                                                     _utPubLen, NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)&_utRx[8], len, _utRx,
                                                     sizeof(_utRx), SSF_EC_CURVE_P256, _utPub,
                                                     _utPubLen, &_utAcc));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len,
                                                     (char *)&_utAcc, 64u, SSF_EC_CURVE_P256,
                                                     _utPub, _utPubLen, &_utAcc));
    SSF_ASSERT_TEST((void)SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx,
                                                     sizeof(_utRx), SSF_EC_CURVE_P256,
                                                     _utAcc.certDer, _utPubLen, &_utAcc));
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P384, _utAWSProvP384Priv,
                                         sizeof(_utAWSProvP384Priv), _utPub, sizeof(_utPub),
                                         &_utPubLen));
    len = _SSFAWSProvUTAccGood(_utAWSProvP384CertPem);
#if SSF_AWSPROV_UT_ACC_FULL == 1
    _SSFAWSProvUTAccOk(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P384, _utAWSProvP384CertDer,
                       sizeof(_utAWSProvP384CertDer));
    memcpy(_utDerTmp, _utAWSProvP384CertDer, sizeof(_utAWSProvP384CertDer));
    der = _SSFAWSProvUTFind(_utDerTmp, sizeof(_utAWSProvP384CertDer),
                            (const uint8_t *)"\x2B\x81\x04\x00\x22", 5u);
    SSF_ASSERT(der != NULL);
    der[4] = 0x23;
    SSF_ASSERT(SSFPEMEncode("CERTIFICATE", _utDerTmp, sizeof(_utAWSProvP384CertDer), _utPemTmp,
                            sizeof(_utPemTmp), &len));
    len = _SSFAWSProvUTAccGood(_utPemTmp);
    SSF_ASSERT(_SSFAWSProvUTAccRefused(_utJson, len, sizeof(_utRx), SSF_EC_CURVE_P384));
#else
    _SSFAWSProvUTAccSized(len, SSF_EC_CURVE_P384, _utAWSProvP384CertPem, _utAWSProvP384CertDer,
                          sizeof(_utAWSProvP384CertDer));
#endif /* SSF_AWSPROV_UT_ACC_FULL */
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
    (void)len;
    (void)der;
}

/* --------------------------------------------------------------------------------------------- */
/* RegisterThing test data                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_UT_REG_SIZE (SSF_JSON_CONFIG_MAX_IN_LEN + 8u)

static char _utReg[SSF_AWSPROV_UT_REG_SIZE];
static char _utRegTok[SSF_AWSPROV_UT_REG_SIZE];
static char _utThing[SSF_AWSPROV_CONFIG_THING_NAME_SIZE + 8u];
static char _utCfg[256];
static size_t _utRxAligned[4];

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the request for the token and params equals expectStr exactly.                */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTRegIs(const char *tokenStr, const SSFAWSProvParam_t *paramsOpt,
                               size_t paramCount, const char *expectStr)
{
    size_t outLen = 0;
    size_t size;
    size_t n;

    SSF_REQUIRE(tokenStr != NULL);
    SSF_REQUIRE(expectStr != NULL);

    n = strlen(expectStr);
    memset(_utReg, 'x', sizeof(_utReg));
    if (SSFAWSProvBuildRegisterRequest(tokenStr, strlen(tokenStr), paramsOpt, paramCount, _utReg,
                                       sizeof(_utReg), &outLen) == false) return false;
    if ((outLen != n) || (strcmp(_utReg, expectStr) != 0)) return false;

    /* Exact fit passes; every smaller size fails, leaves "" and writes nothing past outSize */
    if (SSFAWSProvBuildRegisterRequest(tokenStr, strlen(tokenStr), paramsOpt, paramCount, _utReg,
                                       (n + 1u), &outLen) == false) return false;
    if (strcmp(_utReg, expectStr) != 0) return false;
    for (size = 1u; size <= n; size++)
    {
        memset(_utReg, 'x', sizeof(_utReg));
        outLen = 1u;
        if (SSFAWSProvBuildRegisterRequest(tokenStr, strlen(tokenStr), paramsOpt, paramCount,
                                           _utReg, size, &outLen)) return false;
        if ((outLen != 0u) || (_SSFAWSProvUTIsZero(_utReg, size) == false) ||
            (_utReg[size] != 'x')) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if building a request for tokenStr and params is refused with "" out.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTRegRefused(const char *tokenStr, size_t tokenLen,
                                    const SSFAWSProvParam_t *paramsOpt, size_t paramCount)
{
    size_t outLen = 1u;

    SSF_REQUIRE(tokenStr != NULL);

    memset(_utReg, 'x', sizeof(_utReg));
    if (SSFAWSProvBuildRegisterRequest(tokenStr, tokenLen, paramsOpt, paramCount, _utReg,
                                       sizeof(_utReg), &outLen)) return false;
    return ((outLen == 0u) && _SSFAWSProvUTIsZero(_utReg, sizeof(_utReg)));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the RegisterThing request builder.                                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTRegRequest(void)
{
    SSFAWSProvParam_t params[3];
    size_t overhead;
    size_t outLen;
    size_t n;

    /* No parameters, one, three that need escaping */
    SSF_ASSERT(_SSFAWSProvUTRegIs("abc", NULL, 0u, "{\"certificateOwnershipToken\":\"abc\"}"));
    params[0].keyStr = "SerialNumber";
    params[0].valueStr = "123";
    SSF_ASSERT(_SSFAWSProvUTRegIs("abc", params, 1u,
        "{\"certificateOwnershipToken\":\"abc\",\"parameters\":{\"SerialNumber\":\"123\"}}"));
    params[0].keyStr = "a\"b";
    params[0].valueStr = "c\\d\n";
    params[1].keyStr = "k2";
    params[1].valueStr = "\x01x\x7f";
    params[2].keyStr = "";
    params[2].valueStr = "";
    SSF_ASSERT(_SSFAWSProvUTRegIs("abc", params, 3u,
        "{\"certificateOwnershipToken\":\"abc\",\"parameters\":{\"a\\\"b\":\"c\\\\d\\n\","
        "\"k2\":\"\\u0001x\\u007F\",\"\":\"\"}}"));

    /* The M04 token, escapes included, goes back unchanged */
    memcpy(_utRegTok, "{\"certificateOwnershipToken\":\"", 31u);
    memcpy(&_utRegTok[30], _utAWSProvToken, sizeof(_utAWSProvToken));
    memcpy(&_utRegTok[30u + strlen(_utAWSProvToken)], "\"}", 3u);
    SSF_ASSERT(_SSFAWSProvUTRegIs(_utAWSProvToken, NULL, 0u, _utRegTok));
    SSF_ASSERT(_SSFAWSProvUTRegIs("a\\u0041\\/b", NULL, 0u,
                                  "{\"certificateOwnershipToken\":\"a\\u0041\\/b\"}"));

    /* Non-ASCII parameter bytes are refused */
    params[0].keyStr = "k";
    params[0].valueStr = "\xC3\xA9";
    SSF_ASSERT(_SSFAWSProvUTRegRefused("abc", 3u, params, 1u));
    params[0].keyStr = "\x80";
    params[0].valueStr = "v";
    SSF_ASSERT(_SSFAWSProvUTRegRefused("abc", 3u, params, 1u));

    /* Tokens that are not a clean JSON string body are refused */
    SSF_ASSERT(_SSFAWSProvUTRegRefused("a\"b", 3u, NULL, 0u));
    SSF_ASSERT(_SSFAWSProvUTRegRefused("ab\\", 3u, NULL, 0u));
    SSF_ASSERT(_SSFAWSProvUTRegRefused("a\\xb", 4u, NULL, 0u));
    SSF_ASSERT(_SSFAWSProvUTRegRefused("a\x01" "b", 3u, NULL, 0u));
    SSF_ASSERT(_SSFAWSProvUTRegRefused("x\",\"parameters\":{\"a\":\"b\"},\"z\":\"",
                                       strlen("x\",\"parameters\":{\"a\":\"b\"},\"z\":\""), NULL,
                                       0u));
    SSF_ASSERT(_SSFAWSProvUTRegRefused("a\0b", 3u, NULL, 0u));

    /* A request of exactly SSF_JSON_CONFIG_MAX_IN_LEN passes, one byte more is refused */
    overhead = strlen("{\"certificateOwnershipToken\":\"\"}");
    n = SSF_JSON_CONFIG_MAX_IN_LEN - overhead;
    memset(_utRegTok, 'T', n + 1u);
    _utRegTok[n] = 0;
    SSF_ASSERT(SSFAWSProvBuildRegisterRequest(_utRegTok, n, NULL, 0u, _utReg, sizeof(_utReg),
                                              &outLen));
    SSF_ASSERT(outLen == SSF_JSON_CONFIG_MAX_IN_LEN);
    _utRegTok[n] = 'T';
    _utRegTok[n + 1u] = 0;
    SSF_ASSERT(_SSFAWSProvUTRegRefused(_utRegTok, (n + 1u), NULL, 0u));

    /* DBC */
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest(NULL, 1u, NULL, 0u, _utReg,
                                                         sizeof(_utReg), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 0u, NULL, 0u, _utReg,
                                                         sizeof(_utReg), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, NULL, 1u, _utReg,
                                                         sizeof(_utReg), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, NULL, 0u, NULL,
                                                         sizeof(_utReg), &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, NULL, 0u, _utReg, 0u,
                                                         &outLen));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, NULL, 0u, _utReg,
                                                         sizeof(_utReg), NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest(&_utReg[4], 1u, NULL, 0u, _utReg,
                                                         sizeof(_utReg), &outLen));
    params[0].keyStr = NULL;
    params[0].valueStr = "v";
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, params, 1u, _utReg,
                                                         sizeof(_utReg), &outLen));
    params[0].keyStr = "k";
    params[0].valueStr = NULL;
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, params, 1u, _utReg,
                                                         sizeof(_utReg), &outLen));
    memcpy(&_utReg[8], "v", 2u);
    params[0].valueStr = &_utReg[8];
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, params, 1u, _utReg,
                                                         sizeof(_utReg), &outLen));
    params[0].keyStr = &_utReg[8];
    params[0].valueStr = "v";
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, params, 1u, _utReg,
                                                         sizeof(_utReg), &outLen));
    memcpy(_utRegTok, "abcdef", 7u);
    params[0].keyStr = _utRegTok;
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, params, 1u, &_utRegTok[3],
                                                         64u, &outLen));
    params[0].keyStr = "k";
    memcpy(_utReg, params, sizeof(params[0]));
    SSF_ASSERT_TEST((void)SSFAWSProvBuildRegisterRequest("a", 1u, (SSFAWSProvParam_t *)
                                                         (void *)_utRxAligned, 1u,
                                                         (char *)_utRxAligned,
                                                         sizeof(_utRxAligned), &outLen));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the response parses to thingStr and cfgStr, with the rx copy zeroed.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTRegAcc(const char *payload, size_t thingSize, size_t cfgSize,
                                const char *thingStr, const char *cfgStr)
{
    size_t cfgLen = 1u;
    size_t n;

    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE(thingSize <= sizeof(_utThing));
    SSF_REQUIRE(cfgSize <= sizeof(_utCfg));

    n = strlen(payload);
    memset(_utThing, 'x', sizeof(_utThing));
    memset(_utCfg, 'x', sizeof(_utCfg));
    memset(_utRx, 0x5A, sizeof(_utRx));
    /* Is the response expected to be refused? */
    if (thingStr == NULL)
    {
        /* Yes, every output zeroed */
        if (SSFAWSProvParseRegisterAccepted((const uint8_t *)payload, n, _utRx, sizeof(_utRx),
                                            _utThing, thingSize, _utCfg, cfgSize, &cfgLen))
            return false;
        return ((cfgLen == 0u) && _SSFAWSProvUTIsZero(_utThing, thingSize) &&
                _SSFAWSProvUTIsZero(_utCfg, cfgSize) && _SSFAWSProvUTIsZero(_utRx, sizeof(_utRx)));
    }
    /* No, the outputs as given */
    if (SSFAWSProvParseRegisterAccepted((const uint8_t *)payload, n, _utRx, sizeof(_utRx),
                                        _utThing, thingSize, _utCfg, cfgSize, &cfgLen) == false)
        return false;
    return ((strcmp(_utThing, thingStr) == 0) && (strcmp(_utCfg, cfgStr) == 0) &&
            (cfgLen == strlen(cfgStr)) && _SSFAWSProvUTIsZero(_utRx, sizeof(_utRx)));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the RegisterThing accepted-response parser.                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTRegAccepted(void)
{
    static const char *bad[] = { " ", "/", ".", "+", "#", "$", "\\u0041", "\\\"", "\\\\",
                                 "\\u00e9", "{", "`", "@", "[", ";", "\\u4142\\u3a3a",
                                 "\\u0041" };
    static char name[SSF_AWSPROV_CONFIG_THING_NAME_SIZE + 4u];
    static char js[512];
    size_t thingSize = sizeof(_utThing);
    size_t i;
    size_t len;
    char thing[2];
    char cfg[4];
    size_t cfgLen;

    SSF_ASSERT(_SSFAWSProvUTRegAcc(
        "{\"deviceConfiguration\":{\"Fallback\":\"5\",\"Port\":\"8883\",\"Mode\":\"a\"},"
        "\"thingName\":\"dev_1:A-z9\"}", thingSize, sizeof(_utCfg), "dev_1:A-z9",
        "{\"Fallback\":\"5\",\"Port\":\"8883\",\"Mode\":\"a\"}"));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\",\"deviceConfiguration\":{}}", thingSize,
                                   sizeof(_utCfg), "t", "{}"));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\"}", thingSize, sizeof(_utCfg), "t",
                                   "{}"));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\",\"deviceConfiguration\":{\"a\":\"b\"}}",
                                   thingSize, 10u, "t", "{\"a\":\"b\"}"));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\",\"deviceConfiguration\":{\"a\":\"b\"}}",
                                   thingSize, 9u, NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\"}", thingSize, 3u, "t", "{}"));
    SSF_ASSERT(_SSFAWSProvUTRegAcc(
        "{\"thingName\":\"t\",\"deviceConfiguration\":{\"a\":[\"x\",{\"b\":\"c\"}],\"d\":\"e\"}}",
        thingSize, sizeof(_utCfg), "t", "{\"a\":[\"x\",{\"b\":\"c\"}],\"d\":\"e\"}"));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\"}", thingSize, 2u, NULL, NULL));

    /* deviceConfiguration of the wrong type */
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\",\"deviceConfiguration\":\"x\"}",
                                   thingSize, sizeof(_utCfg), NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\",\"deviceConfiguration\":[]}", thingSize,
                                   sizeof(_utCfg), NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\",\"deviceConfiguration\":null}",
                                   thingSize, sizeof(_utCfg), NULL, NULL));

    /* thingName missing, mistyped, empty, nested only, duplicate (first wins) */
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"deviceConfiguration\":{}}", thingSize, sizeof(_utCfg),
                                   NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":5}", thingSize, sizeof(_utCfg), NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"\"}", thingSize, sizeof(_utCfg), NULL,
                                   NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"x\":{\"thingName\":\"t\"}}", thingSize, sizeof(_utCfg),
                                   NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"t\",\"thingName\":\"u\"}", thingSize,
                                   sizeof(_utCfg), "t", "{}"));

    /* thingName characters outside [a-zA-Z0-9:_-] */
    for (i = 0; i < (sizeof(bad) / sizeof(bad[0])); i++)
    {
        len = 0;
        _SSFAWSProvUTCat(js, sizeof(js), &len, "{\"thingName\":\"a");
        _SSFAWSProvUTCat(js, sizeof(js), &len, bad[i]);
        _SSFAWSProvUTCat(js, sizeof(js), &len, "b\"}");
        SSF_ASSERT(_SSFAWSProvUTRegAcc(js, thingSize, sizeof(_utCfg), NULL, NULL));
    }
    memcpy(js, "{\"thingName\":\"a\x80" "b\"}", 20u);
    SSF_ASSERT(_SSFAWSProvUTRegAcc(js, thingSize, sizeof(_utCfg), NULL, NULL));

    /* Longest thingName the build allows passes, one more is refused, and a small buffer */
    for (len = (SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 2u);
         len <= (SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 1u); len++)
    {
        memset(name, 'n', len);
        name[len] = 0;
        i = 0;
        _SSFAWSProvUTCat(js, sizeof(js), &i, "{\"thingName\":\"");
        _SSFAWSProvUTCat(js, sizeof(js), &i, name);
        _SSFAWSProvUTCat(js, sizeof(js), &i, "\"}");
        SSF_ASSERT(_SSFAWSProvUTRegAcc(js, thingSize, sizeof(_utCfg), name, "{}"));
        name[len] = 'n';
        name[len + 1u] = 0;
        i = 0;
        _SSFAWSProvUTCat(js, sizeof(js), &i, "{\"thingName\":\"");
        _SSFAWSProvUTCat(js, sizeof(js), &i, name);
        _SSFAWSProvUTCat(js, sizeof(js), &i, "\"}");
        if (len == (SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 1u))
        {
            SSF_ASSERT(_SSFAWSProvUTRegAcc(js, thingSize, sizeof(_utCfg), NULL, NULL));
        }
    }
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"abc\"}", 4u, sizeof(_utCfg), "abc", "{}"));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("{\"thingName\":\"abcd\"}", 4u, sizeof(_utCfg), NULL, NULL));

    /* No configuration buffer; non-JSON, empty, embedded NUL */
    memset(_utThing, 0, sizeof(_utThing));
    SSF_ASSERT(SSFAWSProvParseRegisterAccepted((const uint8_t *)"{\"thingName\":\"t\"}", 17u,
                                               _utRx, sizeof(_utRx), _utThing, sizeof(_utThing),
                                               NULL, 0u, NULL));
    SSF_ASSERT(strcmp(_utThing, "t") == 0);
    SSF_ASSERT(_SSFAWSProvUTRegAcc("hello", thingSize, sizeof(_utCfg), NULL, NULL));
    SSF_ASSERT(_SSFAWSProvUTRegAcc("", thingSize, sizeof(_utCfg), NULL, NULL));
    SSF_ASSERT(SSFAWSProvParseRegisterAccepted((const uint8_t *)"{\"thingName\":\"t\"}\0x", 19u,
                                               _utRx, sizeof(_utRx), _utThing, sizeof(_utThing),
                                               NULL, 0u, NULL) == false);

    /* Rejected responses share the M04 format */
    SSF_ASSERT(_SSFAWSProvUTRej(
        "{\"statusCode\":400,\"errorCode\":\"InvalidRequestException\","
        "\"errorMessage\":\"Invalid token\"}", 64u, 64u, 400u, "InvalidRequestException",
        "Invalid token"));

    /* DBC */
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted(NULL, 1u, _utRx, sizeof(_utRx), thing,
                                                          sizeof(thing), cfg, sizeof(cfg),
                                                          &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, NULL, 1u,
                                                          thing, sizeof(thing), cfg, sizeof(cfg),
                                                          &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx, 0u,
                                                          thing, sizeof(thing), cfg, sizeof(cfg),
                                                          &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx,
                                                          sizeof(_utRx), NULL, sizeof(thing),
                                                          cfg, sizeof(cfg), &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx,
                                                          sizeof(_utRx), thing, 1u, cfg,
                                                          sizeof(cfg), &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx,
                                                          sizeof(_utRx), thing, sizeof(thing),
                                                          cfg, 0u, &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)&_utRx[2], 2u, _utRx,
                                                          sizeof(_utRx), thing, sizeof(thing),
                                                          cfg, sizeof(cfg), &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx,
                                                          sizeof(_utRx), &_utRx[4],
                                                          sizeof(thing), cfg, sizeof(cfg),
                                                          &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx,
                                                          sizeof(_utRx), thing, sizeof(thing),
                                                          &_utRx[4], sizeof(cfg), &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx,
                                                          sizeof(_utRx), _utCfg, 8u, &_utCfg[4],
                                                          8u, &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u, _utRx,
                                                          sizeof(_utRx), thing, sizeof(thing),
                                                          NULL, 0u, &cfgLen));
    SSF_ASSERT_TEST((void)SSFAWSProvParseRegisterAccepted((const uint8_t *)"{}", 2u,
                                                          (char *)_utRxAligned,
                                                          sizeof(_utRxAligned), thing,
                                                          sizeof(thing), cfg, sizeof(cfg),
                                                          &_utRxAligned[1]));
}

#if (SSF_ECDSA_CONFIG_ENABLE_SIGN == 1) && (SSF_EC_CONFIG_ENABLE_P256 == 1) && \
    (SSF_AWSPROV_UT_ACC_FULL == 1)
/* --------------------------------------------------------------------------------------------- */
/* Provisioning state machine: mock transport and scripted broker                                */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_UT_BK_TX_SIZE   (4096u)
#define SSF_AWSPROV_UT_BK_RX_SIZE   (8192u)    /* Mock under 32 KB for 16-bit */
#define SSF_AWSPROV_UT_BK_REQ_SIZE  (2048u)
#define SSF_AWSPROV_UT_BK_SCRIPT    (8u)
#define SSF_AWSPROV_UT_BK_LOG       (8u)
#define SSF_AWSPROV_UT_TX_BLOCK     (2048u)
#define SSF_AWSPROV_UT_RX_BLOCK     (4096u)
#define SSF_AWSPROV_UT_TMPL         "tmpl-1"
#define SSF_AWSPROV_UT_PROV_REQ     SSF_AWSPROV_UT_PT_PREFIX SSF_AWSPROV_UT_TMPL \
                                    SSF_AWSPROV_UT_PT_REQ
#define SSF_AWSPROV_UT_PROV_ACC     SSF_AWSPROV_UT_PT_PREFIX SSF_AWSPROV_UT_TMPL \
                                    SSF_AWSPROV_UT_PT_ACCEPTED
#define SSF_AWSPROV_UT_PROV_REJ     SSF_AWSPROV_UT_PT_PREFIX SSF_AWSPROV_UT_TMPL \
                                    SSF_AWSPROV_UT_PT_REJECTED
#define SSF_AWSPROV_UT_REG_ACC      "{\"deviceConfiguration\":{\"a\":\"1\"}," \
                                    "\"thingName\":\"thing-1\"}"
#define SSF_AWSPROV_UT_REJ_429      "{\"statusCode\":429,\"errorCode\":\"Throttled\"," \
                                    "\"errorMessage\":\"slow down\"}"
#define SSF_AWSPROV_UT_REJ_400      "{\"statusCode\":400,\"errorCode\":\"InvalidRequest\"," \
                                    "\"errorMessage\":\"no\"}"
#define SSF_AWSPROV_UT_RESPONSE_TO  (150u)   /* Ticks; responses come within one pump */
#define SSF_AWSPROV_UT_RETRY_MIN    (20u)
#define SSF_AWSPROV_UT_RETRY_MAX    (40u)
#define SSF_AWSPROV_UT_LONG         (100000u)
#define SSF_AWSPROV_UT_SETTLE       (3000u)   /* Wait bound on a loaded host */

/* Broker replies to a request, one script entry per request; past the end: accepted */
typedef enum
{
    SSF_AWSPROV_UT_R_ACC = 0,     /* Accepted */
    SSF_AWSPROV_UT_R_REJ429,      /* Rejected 429 (retryable) */
    SSF_AWSPROV_UT_R_REJ400,      /* Rejected 400 (fatal) */
    SSF_AWSPROV_UT_R_BAD,         /* Accepted topic, payload that fails parsing */
    SSF_AWSPROV_UT_R_BADREJ,      /* Rejected topic, payload that fails parsing */
    SSF_AWSPROV_UT_R_NONE,        /* No reply */
    SSF_AWSPROV_UT_R_DROP,        /* No reply, the link drops */
    SSF_AWSPROV_UT_R_NOISE,       /* Unrelated topic, the other step's accepted, then accepted */
                                  /* twice */
    SSF_AWSPROV_UT_R_LATE,        /* Accepted, lateTicks after the request */
    SSF_AWSPROV_UT_R_RESUB,       /* The link drops; accepted right after the next SUBACK */
} SSFAWSProvUTReply_t;

typedef struct
{
    SSFNetTransport_t transport;  /* Must be first */
    bool openResult;
    bool isOpen;
    bool isPeerClosed;
    uint8_t connAckCode;          /* 0xFF => no CONNACK */
    uint8_t subResult[SSF_AWSPROV_SUB_COUNT];
    uint8_t csrScript[SSF_AWSPROV_UT_BK_SCRIPT];
    uint8_t regScript[SSF_AWSPROV_UT_BK_SCRIPT];
    SSFPortTick_t lateTicks;
    SSFPortTick_t lateDue;        /* 0 => no late reply pending */
    bool isLateCsr;
    bool isResubPending;
    uint32_t openCount;
    uint32_t connectCount;
    uint32_t subscribeCount;
    uint32_t csrCount;
    uint32_t regCount;
    SSFPortTick_t csrTick[SSF_AWSPROV_UT_BK_LOG];
    char clientId[SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE];
    char filters[SSF_AWSPROV_SUB_COUNT][SSF_AWSPROV_MAX_TOPIC_SIZE];
    uint8_t filterQos[SSF_AWSPROV_SUB_COUNT];
    uint8_t csrFirst[SSF_AWSPROV_UT_BK_REQ_SIZE];
    size_t csrFirstLen;
    uint8_t csrLast[SSF_AWSPROV_UT_BK_REQ_SIZE];
    size_t csrLastLen;
    uint8_t regLast[SSF_AWSPROV_UT_BK_REQ_SIZE];
    size_t regLastLen;
    uint8_t tx[SSF_AWSPROV_UT_BK_TX_SIZE];
    size_t txLen;
    uint8_t rx[SSF_AWSPROV_UT_BK_RX_SIZE];
    size_t rxLen;
    size_t rxPos;
} SSFAWSProvUTBroker_t;

typedef struct
{
    uint32_t count;
    bool isDone;
    SSFAWSProvReason_t reason;
    uint16_t statusCode;
    char errorCode[SSF_AWSPROV_ERROR_CODE_SIZE];
    char errorMessage[SSF_AWSPROV_ERROR_MESSAGE_SIZE];
    char thingName[SSF_AWSPROV_CONFIG_THING_NAME_SIZE];
    char deviceConfig[SSF_AWSPROV_CONFIG_DEVICE_CONFIG_SIZE];
    size_t deviceConfigLen;
    char certificateId[SSF_AWSPROV_CERT_ID_SIZE];
    size_t certDerLen;
    size_t tokenLen;
    bool wasWorkLive;             /* The work set still held the outcome during the callback */
} SSFAWSProvUTDone_t;

static SSFAWSProvUTBroker_t _utBk;
static SSFAWSProvUTDone_t _utDone;
static SSFAWSProvWork_t _utWork;
static SSFAWSProvOpts_t _utOpts;
static uint32_t _utAppEvents[SSF_MQTTC_EVENT_MAX];
static char _utCsrAcc[SSF_AWSPROV_UT_RX_SIZE];
static size_t _utCsrAccLen;
static uint8_t _utBkPkt[SSF_AWSPROV_UT_RX_BLOCK + 512u];
static const SSFX509GenName_t _utSubject = { "dev-1", "SSF", NULL, "US", NULL, NULL };
static const SSFAWSProvParam_t _utParams[] = { { "SerialNumber", "SN-1" } };
static char _utRegExpect[SSF_AWSPROV_CONFIG_REG_REQ_SIZE];
static size_t _utRegExpectLen;

/* --------------------------------------------------------------------------------------------- */
/* Mock transport callbacks.                                                                     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTBkOpen(SSFNetTransport_t *t, SSFCStrIn_t hostStr, size_t hostSize,
                                uint16_t port)
{
    SSF_REQUIRE(t == &_utBk.transport);
    SSF_REQUIRE(hostStr != NULL);
    (void)hostSize;
    (void)port;

    _utBk.openCount++;
    if (_utBk.openResult == false) return false;
    _utBk.isOpen = true;
    _utBk.isPeerClosed = false;
    _utBk.txLen = 0;
    _utBk.rxLen = 0;
    _utBk.rxPos = 0;
    return true;
}

static SSFNetIOResult_t _SSFAWSProvUTBkPollOpen(SSFNetTransport_t *t)
{
    SSF_REQUIRE(t == &_utBk.transport);
    return SSF_NET_IO_SUCCESS;
}

static SSFNetIOResult_t _SSFAWSProvUTBkSend(SSFNetTransport_t *t, const uint8_t *buf,
                                            size_t len, size_t *sentOut)
{
    SSF_REQUIRE(t == &_utBk.transport);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(sentOut != NULL);
    SSF_ASSERT(_utBk.isOpen);

    *sentOut = 0;
    if (_utBk.isPeerClosed) return SSF_NET_IO_CLOSED;
    SSF_ASSERT((_utBk.txLen + len) <= sizeof(_utBk.tx));
    memcpy(&_utBk.tx[_utBk.txLen], buf, len);
    _utBk.txLen += len;
    *sentOut = len;
    return SSF_NET_IO_SUCCESS;
}

static SSFNetIOResult_t _SSFAWSProvUTBkRecv(SSFNetTransport_t *t, uint8_t *buf, size_t size,
                                            size_t *gotOut)
{
    size_t n;

    SSF_REQUIRE(t == &_utBk.transport);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(gotOut != NULL);
    SSF_ASSERT(_utBk.isOpen);

    *gotOut = 0;
    if (_utBk.isPeerClosed) return SSF_NET_IO_CLOSED;
    n = _utBk.rxLen - _utBk.rxPos;
    if (n == 0) return SSF_NET_IO_WANT_READ;
    if (n > size) n = size;
    memcpy(buf, &_utBk.rx[_utBk.rxPos], n);
    _utBk.rxPos += n;
    *gotOut = n;
    return SSF_NET_IO_SUCCESS;
}

static SSFNetIOResult_t _SSFAWSProvUTBkShutdown(SSFNetTransport_t *t)
{
    SSF_REQUIRE(t == &_utBk.transport);
    return SSF_NET_IO_SUCCESS;
}

static void _SSFAWSProvUTBkClose(SSFNetTransport_t *t)
{
    SSF_REQUIRE(t == &_utBk.transport);
    _utBk.isOpen = false;
}

/* --------------------------------------------------------------------------------------------- */
/* Queues bytes for the client to receive.                                                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBkInject(const uint8_t *bytes, size_t len)
{
    SSF_REQUIRE(bytes != NULL);
    SSF_ASSERT((_utBk.rxLen + len) <= sizeof(_utBk.rx));

    memcpy(&_utBk.rx[_utBk.rxLen], bytes, len);
    _utBk.rxLen += len;
}

/* --------------------------------------------------------------------------------------------- */
/* Queues a QoS 0 PUBLISH of payloadStr on topicStr for the client.                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBkPublish(const char *topicStr, const char *payloadStr, size_t len)
{
    size_t pktLen;

    SSF_REQUIRE(topicStr != NULL);
    SSF_REQUIRE(payloadStr != NULL);

    SSFMQTTPktEncodePublish(_utBkPkt, sizeof(_utBkPkt), &pktLen, topicStr, strlen(topicStr) + 1u,
                            (const uint8_t *)payloadStr, len, SSF_MQTTC_QOS_0, false, 0);
    SSF_ASSERT(pktLen > 0);
    _SSFAWSProvUTBkInject(_utBkPkt, pktLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Answers one request per its script entry.                                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBkReply(bool isCsr, uint8_t reply)
{
    const char *accTopic = isCsr ? SSF_AWSPROV_UT_CSR_ACCEPTED : SSF_AWSPROV_UT_PROV_ACC;
    const char *rejTopic = isCsr ? SSF_AWSPROV_UT_CSR_REJECTED : SSF_AWSPROV_UT_PROV_REJ;
    const char *accStr = isCsr ? _utCsrAcc : SSF_AWSPROV_UT_REG_ACC;
    size_t accLen = isCsr ? _utCsrAccLen : SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_REG_ACC);

    switch (reply)
    {
    case SSF_AWSPROV_UT_R_ACC:
        _SSFAWSProvUTBkPublish(accTopic, accStr, accLen);
        break;
    case SSF_AWSPROV_UT_R_REJ429:
        _SSFAWSProvUTBkPublish(rejTopic, SSF_AWSPROV_UT_REJ_429,
                               SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_REJ_429));
        break;
    case SSF_AWSPROV_UT_R_REJ400:
        _SSFAWSProvUTBkPublish(rejTopic, SSF_AWSPROV_UT_REJ_400,
                               SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_REJ_400));
        break;
    case SSF_AWSPROV_UT_R_BAD:
        _SSFAWSProvUTBkPublish(accTopic, "{}", 2u);
        break;
    case SSF_AWSPROV_UT_R_BADREJ:
        _SSFAWSProvUTBkPublish(rejTopic, "{\"statusCode\":\"x\"}", 18u);
        break;
    case SSF_AWSPROV_UT_R_DROP:
        _utBk.isPeerClosed = true;
        break;
    case SSF_AWSPROV_UT_R_LATE:
        _utBk.lateDue = SSFPortGetTick64() + _utBk.lateTicks;
        _utBk.isLateCsr = isCsr;
        break;
    case SSF_AWSPROV_UT_R_RESUB:
        SSF_ASSERT(isCsr == false);
        _utBk.isPeerClosed = true;
        _utBk.isResubPending = true;
        break;
    case SSF_AWSPROV_UT_R_NOISE:
        _SSFAWSProvUTBkPublish("x/y", "{}", 2u);
        /* The other step's accepted, on its own topic */
        if (isCsr) _SSFAWSProvUTBkPublish(SSF_AWSPROV_UT_PROV_ACC, SSF_AWSPROV_UT_REG_ACC,
                                          SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_REG_ACC));
        else _SSFAWSProvUTBkPublish(SSF_AWSPROV_UT_CSR_ACCEPTED, _utCsrAcc, _utCsrAccLen);
        _SSFAWSProvUTBkPublish(accTopic, accStr, accLen);
        _SSFAWSProvUTBkPublish(accTopic, accStr, accLen);
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Reads a 2-byte length-prefixed string at p[*pos] into out; returns its length.                */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFAWSProvUTBkStr(const uint8_t *p, size_t *pos, char *out, size_t outSize)
{
    size_t n;

    SSF_REQUIRE((p != NULL) && (pos != NULL) && (out != NULL));

    n = (((size_t)p[*pos]) << 8) | p[*pos + 1u];
    SSF_ASSERT(n < outSize);
    memcpy(out, &p[*pos + 2u], n);
    out[n] = 0;
    *pos += n + 2u;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Handles one client PUBLISH: PUBACK, then the scripted reply.                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBkRxPublish(uint8_t b0, const uint8_t *v, size_t vLen)
{
    static char topic[SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE];
    uint8_t ack[4] = { 0x40, 0x02, 0, 0 };
    size_t pos = 0;
    size_t payLen;
    const uint8_t *pay;
    uint32_t i;

    (void)_SSFAWSProvUTBkStr(v, &pos, topic, sizeof(topic));
    /* Requests go out at QoS 1 */
    SSF_ASSERT(((b0 >> 1) & 3u) == 1u);
    {
        /* Yes, acknowledge */
        ack[2] = v[pos];
        ack[3] = v[pos + 1u];
        pos += 2u;
        _SSFAWSProvUTBkInject(ack, sizeof(ack));
    }
    pay = &v[pos];
    payLen = vLen - pos;
    SSF_ASSERT(payLen <= SSF_AWSPROV_UT_BK_REQ_SIZE);
    if (strcmp(topic, SSF_AWSPROV_UT_CSR_REQ) == 0)
    {
        i = _utBk.csrCount++;
        if (i < SSF_AWSPROV_UT_BK_LOG) _utBk.csrTick[i] = SSFPortGetTick64();
        if (i == 0) { memcpy(_utBk.csrFirst, pay, payLen); _utBk.csrFirstLen = payLen; }
        memcpy(_utBk.csrLast, pay, payLen);
        _utBk.csrLastLen = payLen;
        _SSFAWSProvUTBkReply(true, (i < SSF_AWSPROV_UT_BK_SCRIPT) ? _utBk.csrScript[i] :
                             (uint8_t)SSF_AWSPROV_UT_R_ACC);
    }
    else
    {
        SSF_ASSERT(strcmp(topic, SSF_AWSPROV_UT_PROV_REQ) == 0);
        i = _utBk.regCount++;
        memcpy(_utBk.regLast, pay, payLen);
        _utBk.regLastLen = payLen;
        _SSFAWSProvUTBkReply(false, (i < SSF_AWSPROV_UT_BK_SCRIPT) ? _utBk.regScript[i] :
                             (uint8_t)SSF_AWSPROV_UT_R_ACC);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Handles one client SUBSCRIBE: records the filters, answers per subResult.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBkRxSubscribe(const uint8_t *v, size_t vLen)
{
    uint8_t ack[4 + SSF_AWSPROV_SUB_COUNT];
    size_t pos = 2u;
    uint32_t n = 0;

    _utBk.subscribeCount++;
    ack[0] = 0x90;
    ack[2] = v[0];
    ack[3] = v[1];
    while (pos < vLen)
    {
        SSF_ASSERT(n < SSF_AWSPROV_SUB_COUNT);
        (void)_SSFAWSProvUTBkStr(v, &pos, _utBk.filters[n], sizeof(_utBk.filters[n]));
        _utBk.filterQos[n] = v[pos++];
        ack[4u + n] = _utBk.subResult[n];
        n++;
    }
    ack[1] = (uint8_t)(2u + n);
    _SSFAWSProvUTBkInject(ack, 4u + n);
    /* The answer to the request sent before the drop, in the same read as the SUBACK */
    if (_utBk.isResubPending)
    {
        _utBk.isResubPending = false;
        _SSFAWSProvUTBkPublish(SSF_AWSPROV_UT_PROV_ACC, SSF_AWSPROV_UT_REG_ACC,
                               SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_REG_ACC));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Takes every complete packet the client sent and answers it.                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBkRun(void)
{
    static const uint8_t pingResp[] = { 0xD0, 0x00 };
    size_t pos = 0;

    /* A late reply due? */
    if ((_utBk.lateDue != 0) && _utBk.isOpen && (_utBk.isPeerClosed == false) &&
        (SSFPortGetTick64() >= _utBk.lateDue))
    {
        /* Yes */
        _utBk.lateDue = 0;
        _SSFAWSProvUTBkReply(_utBk.isLateCsr, SSF_AWSPROV_UT_R_ACC);
    }

    while ((_utBk.isOpen) && (_utBk.isPeerClosed == false) && (pos < _utBk.txLen))
    {
        uint8_t b0 = _utBk.tx[pos];
        size_t rem = 0;
        size_t mul = 1;
        size_t hdr = 1;
        const uint8_t *v;

        /* Remaining length */
        for (;;)
        {
            SSF_ASSERT((pos + hdr) < _utBk.txLen);
            rem += (size_t)(_utBk.tx[pos + hdr] & 0x7Fu) * mul;
            mul <<= 7;
            if ((_utBk.tx[pos + hdr++] & 0x80u) == 0) break;
        }
        if ((pos + hdr + rem) > _utBk.txLen) break;
        v = &_utBk.tx[pos + hdr];
        switch (b0 >> 4)
        {
        case 1u:
        {
            uint8_t ack[4] = { 0x20, 0x02, 0x00, 0x00 };
            size_t p = 10u;
            _utBk.connectCount++;
            (void)_SSFAWSProvUTBkStr(v, &p, _utBk.clientId, sizeof(_utBk.clientId));
            ack[3] = _utBk.connAckCode;
            if (_utBk.connAckCode != 0xFFu) _SSFAWSProvUTBkInject(ack, sizeof(ack));
            break;
        }
        case 3u:
            _SSFAWSProvUTBkRxPublish(b0, v, rem);
            break;
        case 8u:
            _SSFAWSProvUTBkRxSubscribe(v, rem);
            break;
        case 12u:
            _SSFAWSProvUTBkInject(pingResp, sizeof(pingResp));
            break;
        default:
            break;
        }
        pos += hdr + rem;
    }
    /* Keep only what is not yet a whole packet */
    if (pos > 0)
    {
        memmove(_utBk.tx, &_utBk.tx[pos], _utBk.txLen - pos);
        _utBk.txLen -= pos;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* App callbacks.                                                                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTDoneFn(void *ctx, bool isDone, const SSFAWSProvResult_t *r)
{
    SSF_ASSERT(ctx == &_utDone);
    SSF_ASSERT(r != NULL);
    SSF_ASSERT(SSFAWSProvIsStarted() == false);
    SSF_ASSERT(isDone == (r->reason == SSF_AWSPROV_REASON_NONE));
    SSF_ASSERT((r->errorCode != NULL) && (r->errorMessage != NULL));

    _utDone.count++;
    _utDone.isDone = isDone;
    _utDone.reason = r->reason;
    _utDone.statusCode = r->statusCode;
    SSF_ASSERT(strlen(r->errorCode) < sizeof(_utDone.errorCode));
    SSF_ASSERT(strlen(r->errorMessage) < sizeof(_utDone.errorMessage));
    strcpy(_utDone.errorCode, r->errorCode);
    strcpy(_utDone.errorMessage, r->errorMessage);
    /* The result points into the work set, which is wiped only after the callback */
    _utDone.wasWorkLive = ((r->errorCode == _utWork.errorCode) &&
                           (r->errorMessage == _utWork.errorMessage) &&
                           ((isDone == false) || ((r->certOpt == &_utWork.acc) &&
                                                  (r->certOpt->tokenLen > 0u) &&
                                                  (r->thingNameOpt == _utWork.thingName))));
    /* Credentials only on success */
    if (isDone)
    {
        SSF_ASSERT((r->certOpt != NULL) && (r->thingNameOpt != NULL) &&
                   (r->deviceConfigOpt != NULL));
        strcpy(_utDone.thingName, r->thingNameOpt);
        memcpy(_utDone.deviceConfig, r->deviceConfigOpt, r->deviceConfigLen + 1u);
        _utDone.deviceConfigLen = r->deviceConfigLen;
        strcpy(_utDone.certificateId, r->certOpt->certificateId);
        _utDone.certDerLen = r->certOpt->certDerLen;
        _utDone.tokenLen = r->certOpt->tokenLen;
    }
    else
    {
        SSF_ASSERT((r->certOpt == NULL) && (r->thingNameOpt == NULL) &&
                   (r->deviceConfigOpt == NULL) && (r->deviceConfigLen == 0));
    }
}

static void _SSFAWSProvUTAppEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason)
{
    SSF_ASSERT(ctx == _utAppEvents);
    SSF_ASSERT((event > SSF_MQTTC_EVENT_MIN) && (event < SSF_MQTTC_EVENT_MAX));
    (void)reason;
    _utAppEvents[event]++;
}

/* --------------------------------------------------------------------------------------------- */
/* Runs ssfsm, ssfmqttc and the broker until event chains settle.                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTPump(void)
{
    uint32_t i;

    for (i = 0; i < 12u; i++)
    {
        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
        _SSFAWSProvUTBkRun();
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Pumps until the run has ended and ssfmqttc is STOPPED; asserts if that takes too long.        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTPumpUntilStopped(void)
{
    SSFPortTick_t end = SSFPortGetTick64() + SSF_AWSPROV_UT_SETTLE;

    for (;;)
    {
        bool isLate = (SSFPortGetTick64() > end);

        _SSFAWSProvUTPump();
        if ((SSFAWSProvIsStarted() == false) &&
            (SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED)) break;
        SSF_ASSERT(isLate == false);
    }
    _SSFAWSProvUTPump();
}

/* --------------------------------------------------------------------------------------------- */
/* Pumps for at least ticks.                                                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTPumpFor(SSFPortTick_t ticks)
{
    SSFPortTick_t end = SSFPortGetTick64() + ticks;

    while (SSFPortGetTick64() < end) _SSFAWSProvUTPump();
}

/* --------------------------------------------------------------------------------------------- */
/* Fresh ssfsm, broker, ssfmqttc (txBlockSize given) and provisioning; default options.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmBegin(uint32_t txBlockSize)
{
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    memset(&_utBk, 0, sizeof(_utBk));
    _utBk.transport.open = _SSFAWSProvUTBkOpen;
    _utBk.transport.pollOpen = _SSFAWSProvUTBkPollOpen;
    _utBk.transport.send = _SSFAWSProvUTBkSend;
    _utBk.transport.recv = _SSFAWSProvUTBkRecv;
    _utBk.transport.shutdown = _SSFAWSProvUTBkShutdown;
    _utBk.transport.close = _SSFAWSProvUTBkClose;
    _utBk.openResult = true;
    memset(_utBk.subResult, 0x01, sizeof(_utBk.subResult));
    memset(&_utDone, 0, sizeof(_utDone));
    memset(_utAppEvents, 0, sizeof(_utAppEvents));
    memset(&_utWork, 0x5A, sizeof(_utWork));

    SSFMQTTCInit(&_utBk.transport, 4u, txBlockSize, SSF_AWSPROV_UT_RX_BLOCK, SSFAWSProvRxPublish,
                 NULL, SSFAWSProvEvent, NULL);
    SSFAWSProvInit();

    memset(&_utOpts, 0, sizeof(_utOpts));
    _utOpts.mqtt.host = "mock";
    _utOpts.mqtt.port = 8883;
    _utOpts.mqtt.clientId = "claim-1";
    _utOpts.mqtt.keepAliveSec = 120;
    _utOpts.mqtt.connectTimeout = 100;
    _utOpts.mqtt.subscribeTimeout = 100;
    _utOpts.mqtt.txPublishTimeout = 500;
    _utOpts.mqtt.reconnectMinWait = 20;
    _utOpts.mqtt.reconnectMaxWait = 40;
    _utOpts.templateName = SSF_AWSPROV_UT_TMPL;
    _utOpts.curve = SSF_EC_CURVE_P256;
    _utOpts.privKey = _utAWSProvP256Priv;
    _utOpts.privKeyLen = sizeof(_utAWSProvP256Priv);
    _utOpts.subjectOpt = &_utSubject;
    _utOpts.paramsOpt = _utParams;
    _utOpts.paramCount = 1u;
    _utOpts.responseTimeout = SSF_AWSPROV_UT_RESPONSE_TO;
    _utOpts.retryMinWait = SSF_AWSPROV_UT_RETRY_MIN;
    _utOpts.retryMaxWait = SSF_AWSPROV_UT_RETRY_MAX;
    _utOpts.deadline = 0;
    _utOpts.tokenLifetime = SSF_AWSPROV_UT_LONG;
    _utOpts.maxAttempts = 4u;
}

/* --------------------------------------------------------------------------------------------- */
/* Tears down what _SSFAWSProvUTSmBegin built; the run must be over.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmEnd(void)
{
    SSF_ASSERT(SSFAWSProvIsStarted() == false);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSFAWSProvDeInit();
    SSFMQTTCDeInit();
    SSFSMDeInit();
}

/* --------------------------------------------------------------------------------------------- */
/* Starts with _utOpts, runs to the end, and checks the outcome and the scrub.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTRun(SSFAWSProvReason_t reason)
{
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, _SSFAWSProvUTAppEvent,
                    _utAppEvents);
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT(_utDone.count == 1u);
    SSF_ASSERT(_utDone.reason == reason);
    SSF_ASSERT(_utDone.wasWorkLive);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_STOPPED] == 1u);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts a successful outcome with the fixture credentials.                                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTExpectDone(void)
{
    SSF_ASSERT(_utDone.isDone);
    SSF_ASSERT(strcmp(_utDone.thingName, "thing-1") == 0);
    SSF_ASSERT(strcmp(_utDone.deviceConfig, "{\"a\":\"1\"}") == 0);
    SSF_ASSERT(_utDone.deviceConfigLen == 9u);
    SSF_ASSERT(strcmp(_utDone.certificateId, _utAWSProvCertId) == 0);
    SSF_ASSERT(_utDone.certDerLen == sizeof(_utAWSProvP256CertDer));
    SSF_ASSERT(_utDone.tokenLen == strlen(_utAWSProvToken));
    SSF_ASSERT((_utDone.statusCode == 0u) || (_utDone.statusCode == 429u));
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts every CSR request was the fixture's bytes (built once, never signed again).           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTExpectCsrBytes(void)
{
    size_t n = SSF_AWSPROV_UT_LIT_LEN(_utAWSProvP256CNOCJson);

    SSF_ASSERT((_utBk.csrFirstLen == n) &&
               (memcmp(_utBk.csrFirst, _utAWSProvP256CNOCJson, n) == 0));
    SSF_ASSERT((_utBk.csrLastLen == n) && (memcmp(_utBk.csrLast, _utAWSProvP256CNOCJson, n) == 0));
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts the last RegisterThing request was the token with the parameters.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTExpectRegBytes(void)
{
    SSF_ASSERT(_utBk.regLastLen == _utRegExpectLen);
    SSF_ASSERT(memcmp(_utBk.regLast, _utRegExpect, _utRegExpectLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Happy path, the wire, the scrub, restart after DONE.                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmHappy(void)
{
    static const char *const filters[SSF_AWSPROV_SUB_COUNT] =
    { SSF_AWSPROV_UT_CSR_ACCEPTED, SSF_AWSPROV_UT_CSR_REJECTED, SSF_AWSPROV_UT_PROV_ACC,
      SSF_AWSPROV_UT_PROV_REJ };
    uint32_t i;

    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, _SSFAWSProvUTAppEvent,
                    _utAppEvents);
    SSF_ASSERT(SSFAWSProvIsStarted());
    /* The private key is not kept */
    SSF_ASSERT(_utWork.opts.privKey == NULL);
    SSF_ASSERT(_SSFAWSProvUTContains((const uint8_t *)&_utWork, sizeof(_utWork),
                                     _utAWSProvP256Priv, sizeof(_utAWSProvP256Priv)) == false);
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT(_utDone.count == 1u);
    _SSFAWSProvUTExpectDone();
    SSF_ASSERT(_utDone.statusCode == 0u);
    SSF_ASSERT(_utDone.wasWorkLive);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));
    SSF_ASSERT(strcmp(_utBk.clientId, "claim-1") == 0);
    SSF_ASSERT(_utBk.connectCount == 1u);
    SSF_ASSERT(_utBk.subscribeCount == 1u);
    for (i = 0; i < SSF_AWSPROV_SUB_COUNT; i++)
    {
        SSF_ASSERT(strcmp(_utBk.filters[i], filters[i]) == 0);
        SSF_ASSERT(_utBk.filterQos[i] == 1u);
    }
    SSF_ASSERT((_utBk.csrCount == 1u) && (_utBk.regCount == 1u));
    _SSFAWSProvUTExpectCsrBytes();
    _SSFAWSProvUTExpectRegBytes();
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_CONNECTED] == 1u);
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_READY] == 1u);
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_STOPPED] == 1u);

    /* A second run on the same Init, no app event callback */
    memset(&_utDone, 0, sizeof(_utDone));
    memset(&_utBk.csrScript, 0, sizeof(_utBk.csrScript));
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT(_utDone.count == 1u);
    _SSFAWSProvUTExpectDone();
    SSF_ASSERT((_utBk.csrCount == 2u) && (_utBk.regCount == 2u));
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_STOPPED] == 1u);
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Runs one scripted scenario on a fresh setup and checks the outcome.                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmScript(const uint8_t *csr, size_t csrLen, const uint8_t *reg,
                                  size_t regLen, SSFAWSProvReason_t reason, uint32_t csrCount,
                                  uint32_t regCount)
{
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    SSF_ASSERT((csrLen <= SSF_AWSPROV_UT_BK_SCRIPT) && (regLen <= SSF_AWSPROV_UT_BK_SCRIPT));
    if (csrLen > 0) memcpy(_utBk.csrScript, csr, csrLen);
    if (regLen > 0) memcpy(_utBk.regScript, reg, regLen);
    _SSFAWSProvUTRun(reason);
    SSF_ASSERT(_utBk.csrCount == csrCount);
    SSF_ASSERT(_utBk.regCount == regCount);
    if (csrCount > 0) _SSFAWSProvUTExpectCsrBytes();
    if (regCount > 0) _SSFAWSProvUTExpectRegBytes();
    if (reason == SSF_AWSPROV_REASON_NONE) _SSFAWSProvUTExpectDone();
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Rejects, timeouts, bad responses, link drops and noise on each step.                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmSteps(void)
{
    static const uint8_t r429[] = { SSF_AWSPROV_UT_R_REJ429 };
    static const uint8_t r400[] = { SSF_AWSPROV_UT_R_REJ400 };
    static const uint8_t none[] = { SSF_AWSPROV_UT_R_NONE };
    static const uint8_t none4[] = { SSF_AWSPROV_UT_R_NONE, SSF_AWSPROV_UT_R_NONE,
                                     SSF_AWSPROV_UT_R_NONE, SSF_AWSPROV_UT_R_NONE };
    static const uint8_t r4294[] = { SSF_AWSPROV_UT_R_REJ429, SSF_AWSPROV_UT_R_REJ429,
                                     SSF_AWSPROV_UT_R_REJ429, SSF_AWSPROV_UT_R_REJ429 };
    static const uint8_t bad[] = { SSF_AWSPROV_UT_R_BAD, SSF_AWSPROV_UT_R_BADREJ };
    static const uint8_t bad4[] = { SSF_AWSPROV_UT_R_BADREJ, SSF_AWSPROV_UT_R_BAD,
                                    SSF_AWSPROV_UT_R_BAD, SSF_AWSPROV_UT_R_BAD };
    static const uint8_t drop[] = { SSF_AWSPROV_UT_R_DROP };
    static const uint8_t noise[] = { SSF_AWSPROV_UT_R_NOISE };
    static const uint8_t mixed[] = { SSF_AWSPROV_UT_R_NONE, SSF_AWSPROV_UT_R_REJ429,
                                     SSF_AWSPROV_UT_R_BAD };

    /* CreateCertificateFromCsr */
    _SSFAWSProvUTSmScript(r429, sizeof(r429), NULL, 0, SSF_AWSPROV_REASON_NONE, 2u, 1u);
    SSF_ASSERT(_utDone.statusCode == 429u);   /* The last reject is still reported */
    _SSFAWSProvUTSmScript(r400, sizeof(r400), NULL, 0, SSF_AWSPROV_REASON_REJECTED, 1u, 0);
    SSF_ASSERT(_utDone.statusCode == 400u);
    SSF_ASSERT(strcmp(_utDone.errorCode, "InvalidRequest") == 0);
    SSF_ASSERT(strcmp(_utDone.errorMessage, "no") == 0);
    _SSFAWSProvUTSmScript(none, sizeof(none), NULL, 0, SSF_AWSPROV_REASON_NONE, 2u, 1u);
    _SSFAWSProvUTSmScript(none4, sizeof(none4), NULL, 0, SSF_AWSPROV_REASON_ATTEMPTS, 4u, 0);
    _SSFAWSProvUTSmScript(r4294, sizeof(r4294), NULL, 0, SSF_AWSPROV_REASON_ATTEMPTS, 4u, 0);
    SSF_ASSERT(_utDone.statusCode == 429u);
    SSF_ASSERT(strcmp(_utDone.errorCode, "Throttled") == 0);
    _SSFAWSProvUTSmScript(bad, sizeof(bad), NULL, 0, SSF_AWSPROV_REASON_NONE, 3u, 1u);
    _SSFAWSProvUTSmScript(bad4, sizeof(bad4), NULL, 0, SSF_AWSPROV_REASON_BAD_RESPONSE, 4u, 0);
    _SSFAWSProvUTSmScript(mixed, sizeof(mixed), NULL, 0, SSF_AWSPROV_REASON_NONE, 4u, 1u);
    _SSFAWSProvUTSmScript(drop, sizeof(drop), NULL, 0, SSF_AWSPROV_REASON_NONE, 2u, 1u);
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_DISCONNECTED] == 1u);
    _SSFAWSProvUTSmScript(noise, sizeof(noise), NULL, 0, SSF_AWSPROV_REASON_NONE, 1u, 1u);

    /* RegisterThing */
    _SSFAWSProvUTSmScript(NULL, 0, r429, sizeof(r429), SSF_AWSPROV_REASON_NONE, 1u, 2u);
    _SSFAWSProvUTSmScript(NULL, 0, r400, sizeof(r400), SSF_AWSPROV_REASON_REJECTED, 1u, 1u);
    SSF_ASSERT(_utDone.statusCode == 400u);
    _SSFAWSProvUTSmScript(NULL, 0, none, sizeof(none), SSF_AWSPROV_REASON_NONE, 1u, 2u);
    _SSFAWSProvUTSmScript(NULL, 0, none4, sizeof(none4), SSF_AWSPROV_REASON_ATTEMPTS, 1u, 4u);
    _SSFAWSProvUTSmScript(NULL, 0, bad, sizeof(bad), SSF_AWSPROV_REASON_NONE, 1u, 3u);
    _SSFAWSProvUTSmScript(NULL, 0, bad4, sizeof(bad4), SSF_AWSPROV_REASON_BAD_RESPONSE, 1u, 4u);
    _SSFAWSProvUTSmScript(NULL, 0, drop, sizeof(drop), SSF_AWSPROV_REASON_NONE, 1u, 2u);
    _SSFAWSProvUTSmScript(NULL, 0, noise, sizeof(noise), SSF_AWSPROV_REASON_NONE, 1u, 1u);

    /* Retries start over for each step: three failures on each still succeed with 4 tries */
    _SSFAWSProvUTSmScript(r4294, 3u, none4, 3u, SSF_AWSPROV_REASON_NONE, 4u, 4u);

    /* maxAttempts 0 with a deadline: tries are unlimited */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    memset(_utBk.csrScript, SSF_AWSPROV_UT_R_REJ429, 6u);
    _utOpts.maxAttempts = 0;
    _utOpts.deadline = SSF_AWSPROV_UT_LONG;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT(_utBk.csrCount == 7u);
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Backoff: doubling from retryMinWait to retryMaxWait, each wait jittered within [w/2, w].      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmBackoff(void)
{
    static const SSFPortTick_t base[] = { 40u, 80u, 160u, 160u, 160u };
    SSFPortTick_t gap;
    uint32_t i;

    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    memset(_utBk.csrScript, SSF_AWSPROV_UT_R_REJ429, 5u);
    _utOpts.retryMinWait = 40u;
    _utOpts.retryMaxWait = 160u;
    _utOpts.maxAttempts = 6u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT(_utBk.csrCount == 6u);
    for (i = 0; i < 5u; i++)
    {
        gap = _utBk.csrTick[i + 1u] - _utBk.csrTick[i];
        SSF_ASSERT(gap >= (base[i] / 2u));
        SSF_ASSERT(gap <= (base[i] + SSF_AWSPROV_UT_SETTLE));
    }
    _SSFAWSProvUTSmEnd();

    /* An odd cap: past half of it the wait goes straight to the cap */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    memset(_utBk.csrScript, SSF_AWSPROV_UT_R_REJ429, 3u);
    _utOpts.retryMinWait = 30u;
    _utOpts.retryMaxWait = 45u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT(_utBk.csrCount == 4u);
    SSF_ASSERT((_utBk.csrTick[1] - _utBk.csrTick[0]) >= 15u);
    SSF_ASSERT((_utBk.csrTick[2] - _utBk.csrTick[1]) >= 22u);
    SSF_ASSERT((_utBk.csrTick[3] - _utBk.csrTick[2]) >= 22u);
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the backoff sequence for (minWait, maxWait) against expect[0..n).                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBackoffSeq(SSFPortTick_t minWait, SSFPortTick_t maxWait,
                                    const SSFPortTick_t *expect, size_t n)
{
    SSFPortTick_t t;
    size_t i;

    SSF_REQUIRE(expect != NULL);

    memset(&_utWork, 0, sizeof(_utWork));
    _utWork.opts.retryMinWait = minWait;
    _utWork.opts.retryMaxWait = maxWait;
    _utWork.jitter = 1u;
    for (i = 0; i < n; i++)
    {
        t = _SSFAWSProvUTNextBackoff(&_utWork);
        SSF_ASSERT(_utWork.wait == expect[i]);
        SSF_ASSERT((t >= (expect[i] - (expect[i] >> 1))) && (t <= expect[i]));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Backoff arithmetic: doubling, the cap, no overflow, jitter range.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmBackoffMath(void)
{
    static const SSFPortTick_t even[] = { 40u, 80u, 160u, 160u };
    static const SSFPortTick_t odd[] = { 30u, 45u, 45u };
    static const SSFPortTick_t odd2[] = { 22u, 44u, 45u };
    static const SSFPortTick_t one[] = { 1u, 1u };
    static SSFPortTick_t big[3];
    bool seen[5] = { false, false, false, false, false };
    SSFPortTick_t t;
    uint32_t i;

    _SSFAWSProvUTBackoffSeq(40u, 160u, even, 4u);
    _SSFAWSProvUTBackoffSeq(30u, 45u, odd, 3u);
    _SSFAWSProvUTBackoffSeq(22u, 45u, odd2, 3u);    /* At exactly half of an odd cap: doubles */
    _SSFAWSProvUTBackoffSeq(1u, 1u, one, 2u);
    /* Near the top of the tick range doubling must not wrap */
    big[0] = ((SSFPortTick_t)1u) << 62;
    big[1] = ((SSFPortTick_t)1u) << 63;
    big[2] = ~((SSFPortTick_t)0u);
    _SSFAWSProvUTBackoffSeq(big[0], big[2], big, 3u);

    /* Jitter covers all of [w/2, w] and nothing else */
    memset(&_utWork, 0, sizeof(_utWork));
    _utWork.opts.retryMinWait = 4u;
    _utWork.opts.retryMaxWait = 4u;
    _utWork.jitter = 12345u;
    for (i = 0; i < 1000u; i++)
    {
        t = _SSFAWSProvUTNextBackoff(&_utWork);
        SSF_ASSERT((t >= 2u) && (t <= 4u));
        seen[t] = true;
    }
    SSF_ASSERT(seen[2] && seen[3] && seen[4]);
    memset(&_utWork, 0, sizeof(_utWork));
}

/* --------------------------------------------------------------------------------------------- */
/* Connection: failures counted as tries, refusals, refused filters, the deadline, the token.    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmLink(void)
{
    static const uint8_t refused[] = { 1u, 2u, 4u, 5u };
    static const uint8_t connAck[] = { 0x20, 0x02, 0x00, 0x00 };
    static uint8_t key2[sizeof(_utAWSProvP256Priv)];
    uint32_t seed;
    size_t i;

    /* The jitter seed comes from the device key */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.connAckCode = 0xFFu;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    seed = _utWork.jitter;
    SSFAWSProvStop();
    _SSFAWSProvUTPumpUntilStopped();
    memcpy(key2, _utAWSProvP256Priv, sizeof(key2));
    key2[sizeof(key2) - 1u] ^= 1u;
    _utOpts.privKey = key2;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    SSF_ASSERT((_utWork.jitter != seed) && (_utWork.jitter != 0u));
    SSFAWSProvStop();
    _SSFAWSProvUTPumpUntilStopped();
    _SSFAWSProvUTSmEnd();

    /* RegisterThing starts with a fresh try count and backoff */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_REJ429;
    _utBk.regScript[0] = SSF_AWSPROV_UT_R_NONE;
    _utOpts.responseTimeout = SSF_AWSPROV_UT_LONG;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    while (_utBk.regCount < 1u) _SSFAWSProvUTPump();
    SSF_ASSERT((_utWork.step == 1u) && (_utWork.wait == 0) && (_utWork.tries[1] == 1u));
    SSF_ASSERT(_utWork.tries[0] == 2u);
    SSFAWSProvStop();
    _SSFAWSProvUTPumpUntilStopped();
    _SSFAWSProvUTSmEnd();

    /* Out of tries on a failure: ends at once, not after the (long) backoff */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_REJ429;
    _utOpts.maxAttempts = 1u;
    _utOpts.retryMinWait = SSF_AWSPROV_UT_LONG;
    _utOpts.retryMaxWait = SSF_AWSPROV_UT_LONG;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_ATTEMPTS);
    _SSFAWSProvUTSmEnd();

    /* A drop while waiting for the response: resent on reconnect, not after its timeout */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_DROP;
    _utOpts.responseTimeout = SSF_AWSPROV_UT_LONG;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT(_utBk.csrCount == 2u);
    _SSFAWSProvUTSmEnd();

    /* The link never comes up: four failed connects end the run */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.openResult = false;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_ATTEMPTS);
    SSF_ASSERT(_utBk.openCount == 4u);
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_CONNECT_FAILED] == 4u);
    _SSFAWSProvUTSmEnd();

    /* Never up, no try limit: the deadline (from Start) ends it */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.openResult = false;
    _utOpts.maxAttempts = 0;
    _utOpts.deadline = 150u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_DEADLINE);
    SSF_ASSERT(_utBk.openCount >= 2u);
    _SSFAWSProvUTSmEnd();

    /* Two failed connects, then up */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.openResult = false;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    while (_utBk.openCount < 2u) _SSFAWSProvUTPump();
    _utBk.openResult = true;
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT((_utDone.count == 1u) && _utDone.isDone);
    SSF_ASSERT(_utBk.openCount == 3u);
    _SSFAWSProvUTSmEnd();

    /* CONNACK 1, 2, 4, 5 end the run; 3 (server unavailable) is retried */
    for (i = 0; i < sizeof(refused); i++)
    {
        _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
        _utBk.connAckCode = refused[i];
        _SSFAWSProvUTRun(SSF_AWSPROV_REASON_CONNECT_REFUSED);
        SSF_ASSERT(_utBk.connectCount == 1u);
        _SSFAWSProvUTSmEnd();
    }
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.connAckCode = 3u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_ATTEMPTS);
    SSF_ASSERT(_utBk.connectCount == 4u);
    _SSFAWSProvUTSmEnd();

    /* A refused response filter: fail at READY, nothing published */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.subResult[SSF_AWSPROV_SUB_PROV_ACCEPTED] = 0x80u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_SUBSCRIBE_REFUSED);
    SSF_ASSERT(_utBk.csrCount == 0);
    _SSFAWSProvUTSmEnd();

    /* Deadline while waiting for a response, and in BACKOFF */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_NONE;
    _utOpts.responseTimeout = SSF_AWSPROV_UT_LONG;
    _utOpts.deadline = 100u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_DEADLINE);
    SSF_ASSERT(_utBk.csrCount == 1u);
    _SSFAWSProvUTSmEnd();
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_REJ429;
    _utOpts.retryMinWait = SSF_AWSPROV_UT_LONG;
    _utOpts.retryMaxWait = SSF_AWSPROV_UT_LONG;
    _utOpts.deadline = 100u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_DEADLINE);
    SSF_ASSERT(_utBk.csrCount == 1u);
    SSF_ASSERT(_utDone.statusCode == 429u);
    _SSFAWSProvUTSmEnd();

    /* The link drops during BACKOFF and comes back before it ends: the backoff runs out */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_REJ429;
    _utOpts.retryMinWait = 100u;
    _utOpts.retryMaxWait = 100u;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    while (_utBk.csrCount < 1u) _SSFAWSProvUTPump();
    _utBk.isPeerClosed = true;
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT((_utDone.count == 1u) && _utDone.isDone);
    SSF_ASSERT((_utBk.csrCount == 2u) && (_utBk.connectCount == 2u));
    SSF_ASSERT((_utBk.csrTick[1] - _utBk.csrTick[0]) >= 50u);
    _SSFAWSProvUTSmEnd();

    /* Still down when the backoff ends: no try spent, the resend waits for READY */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_REJ429;
    _utOpts.retryMinWait = 40u;
    _utOpts.retryMaxWait = 40u;
    _utOpts.mqtt.connectTimeout = SSF_AWSPROV_UT_LONG;   /* Down = CONNACK withheld */
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    while (_utBk.csrCount < 1u) _SSFAWSProvUTPump();
    _utBk.connAckCode = 0xFFu;
    _utBk.isPeerClosed = true;
    _SSFAWSProvUTPumpFor(150u);
    SSF_ASSERT((_utBk.csrCount == 1u) && (_utBk.connectCount == 2u));
    SSF_ASSERT(_utWork.tries[0] == 1u);
    _utBk.connAckCode = 0;
    _SSFAWSProvUTBkInject(connAck, sizeof(connAck));
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT((_utDone.count == 1u) && _utDone.isDone);
    SSF_ASSERT((_utBk.csrCount == 2u) && (_utBk.connectCount == 2u));
    _SSFAWSProvUTSmEnd();

    /* The token ages out across a link drop after RegisterThing: same CSR again */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.regScript[0] = SSF_AWSPROV_UT_R_DROP;
    _utOpts.tokenLifetime = 10u;                 /* reconnectMinWait is 20 */
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT((_utBk.csrCount == 2u) && (_utBk.regCount == 2u));
    _SSFAWSProvUTExpectCsrBytes();
    _SSFAWSProvUTExpectDone();
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Requests that can't be built or sent.                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmBuild(void)
{
    static char longCn[SSF_AWSPROV_CONFIG_CSR_REQ_SIZE];
    static const SSFAWSProvParam_t badParam[] = { { "k", "\xC3\xA9" } };
    SSFX509GenName_t subj;

    /* Invalid template name: done (BUILD) before Start returns, ssfmqttc never started */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utOpts.templateName = "bad name";
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    SSF_ASSERT((_utDone.count == 1u) && (_utDone.reason == SSF_AWSPROV_REASON_BUILD));
    SSF_ASSERT(SSFAWSProvIsStarted() == false);
    SSF_ASSERT(SSFMQTTCGetState() == SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));
    _SSFAWSProvUTPump();
    SSF_ASSERT((_utBk.openCount == 0) && (_utDone.count == 1u));

    /* The CSR request can't fit SSF_AWSPROV_CONFIG_CSR_REQ_SIZE */
    memset(&_utDone, 0, sizeof(_utDone));
    memset(longCn, 'a', sizeof(longCn) - 1u);
    memset(&subj, 0, sizeof(subj));
    subj.cn = longCn;
    _utOpts.templateName = SSF_AWSPROV_UT_TMPL;
    _utOpts.subjectOpt = &subj;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    SSF_ASSERT((_utDone.count == 1u) && (_utDone.reason == SSF_AWSPROV_REASON_BUILD));
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));

    /* An invalid private key (zero scalar) */
    memset(&_utDone, 0, sizeof(_utDone));
    _utOpts.subjectOpt = &_utSubject;
    _utOpts.privKey = (const uint8_t *)longCn + sizeof(longCn) - 1u - 32u;
    memset(longCn, 0, sizeof(longCn));
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    SSF_ASSERT((_utDone.count == 1u) && (_utDone.reason == SSF_AWSPROV_REASON_BUILD));
    _SSFAWSProvUTSmEnd();

    /* A RegisterThing parameter that can't be sent: BUILD after the certificate */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utOpts.paramsOpt = badParam;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_BUILD);
    SSF_ASSERT((_utBk.csrCount == 1u) && (_utBk.regCount == 0));
    _SSFAWSProvUTSmEnd();

    /* txBlockSize too small for the CSR request: every try refused */
    _SSFAWSProvUTSmBegin(256u);
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_TX_REFUSED);
    SSF_ASSERT(_utBk.csrCount == 0);
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Done callback that tries to start a new run from inside the callback.                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTDoneRestart(void *ctx, bool isDone, const SSFAWSProvResult_t *r)
{
    _SSFAWSProvUTDoneFn(ctx, isDone, r);
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL,
                                    NULL));
    SSF_ASSERT_TEST(SSFAWSProvStop());
}

/* --------------------------------------------------------------------------------------------- */
/* Late answers, stale responses across a step change, and the token-age loop bound.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmLate(void)
{
    static const uint8_t bad429[] = { SSF_AWSPROV_UT_R_REJ429, SSF_AWSPROV_UT_R_BADREJ };
    static const uint8_t badDrop[] = { SSF_AWSPROV_UT_R_BAD, SSF_AWSPROV_UT_R_DROP };

    /* An answer after its timeout, during the (long) backoff: taken */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_LATE;
    _utBk.lateTicks = SSF_AWSPROV_UT_RESPONSE_TO + 50u;
    _utOpts.retryMinWait = SSF_AWSPROV_UT_LONG;
    _utOpts.retryMaxWait = SSF_AWSPROV_UT_LONG;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT((_utBk.csrCount == 1u) && (_utBk.regCount == 1u));
    _SSFAWSProvUTSmEnd();

    /* The RegisterThing answer arrives with the SUBACK after a drop: taken, no resend */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.regScript[0] = SSF_AWSPROV_UT_R_RESUB;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT((_utBk.csrCount == 1u) && (_utBk.regCount == 1u));
    SSF_ASSERT(_utBk.subscribeCount == 2u);
    _SSFAWSProvUTSmEnd();

    /* Same, with the token aged out by then: the answer still completes the run */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.regScript[0] = SSF_AWSPROV_UT_R_RESUB;
    _utOpts.tokenLifetime = 10u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_NONE);
    SSF_ASSERT(_utBk.regCount == 1u);
    _SSFAWSProvUTSmEnd();

    /* Token always too old by the reconnect: each lap costs both steps a try, so it ends */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    memset(_utBk.regScript, SSF_AWSPROV_UT_R_DROP, sizeof(_utBk.regScript));
    _utOpts.tokenLifetime = 10u;
    _utOpts.maxAttempts = 2u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_ATTEMPTS);
    SSF_ASSERT((_utBk.csrCount == 2u) && (_utBk.regCount == 2u));
    _SSFAWSProvUTSmEnd();

    /* A response stored for RegisterThing whose event is still queued when an old token sends */
    /* the run back to the CSR step: dropped with the step change (thread support 0 can queue */
    /* READY ahead of it; ssfmqttc does not run there yet, so the state is set up directly) */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.regScript[0] = SSF_AWSPROV_UT_R_DROP;
    _utOpts.tokenLifetime = 10u;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    while (_utBk.regCount < 1u) _SSFAWSProvUTPump();
    SSF_ASSERT((_utWork.step == 1u) && (_utWork.response == 0));
    _utWork.response = 1u;                       /* ACCEPTED, for the old step */
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT((_utDone.count == 1u) && _utDone.isDone);
    SSF_ASSERT((_utBk.csrCount == 2u) && (_utBk.regCount == 2u));
    _SSFAWSProvUTSmEnd();

    /* A RESPONSE event with nothing stored (its response dropped that way): ignored */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = SSF_AWSPROV_UT_R_NONE;
    _utOpts.responseTimeout = SSF_AWSPROV_UT_LONG;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    while (_utBk.csrCount < 1u) _SSFAWSProvUTPump();
    SSFSMPutEvent(SSF_SM_AWSPROV, SSF_SM_EVENT_AWSPROV_RESPONSE);
    _SSFAWSProvUTPump();
    SSF_ASSERT(SSFAWSProvIsStarted() && (_utDone.count == 0) && (_utBk.csrCount == 1u));
    SSFAWSProvStop();
    _SSFAWSProvUTPumpUntilStopped();
    _SSFAWSProvUTSmEnd();

    /* An unparseable reject keeps the last good one for the result */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    memcpy(_utBk.csrScript, bad429, sizeof(bad429));
    _utOpts.maxAttempts = 2u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_BAD_RESPONSE);
    SSF_ASSERT((_utDone.statusCode == 429u) && (strcmp(_utDone.errorCode, "Throttled") == 0));
    SSF_ASSERT(strcmp(_utDone.errorMessage, "slow down") == 0);
    _SSFAWSProvUTSmEnd();

    /* Tries used up by a drop after a bad response: ATTEMPTS, not BAD_RESPONSE */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    memcpy(_utBk.csrScript, badDrop, sizeof(badDrop));
    _utOpts.maxAttempts = 2u;
    _SSFAWSProvUTRun(SSF_AWSPROV_REASON_ATTEMPTS);
    SSF_ASSERT(_utBk.csrCount == 2u);
    _SSFAWSProvUTSmEnd();

    /* No Start or Stop from inside the done callback */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utOpts.templateName = "bad name";
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneRestart, &_utDone, NULL, NULL);
    SSF_ASSERT((_utDone.count == 1u) && (_utDone.reason == SSF_AWSPROV_REASON_BUILD));
    SSF_ASSERT(SSFAWSProvIsStarted() == false);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));
    _utOpts.templateName = SSF_AWSPROV_UT_TMPL;
    memset(&_utDone, 0, sizeof(_utDone));
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneRestart, &_utDone, NULL, NULL);
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT((_utDone.count == 1u) && _utDone.isDone);

    /* No DeInit while a STOP is still queued */
    memset(&_utDone, 0, sizeof(_utDone));
    _utBk.connAckCode = 0xFFu;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    _SSFAWSProvUTPump();
    SSFAWSProvStop();
    SSF_ASSERT_TEST(SSFAWSProvDeInit());
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT(_utDone.count == 0);
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Stops a run once cond holds, then checks the stop and that a new run completes.               */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_UT_STOP_START    (0u)
#define SSF_AWSPROV_UT_STOP_CONNECT  (1u)
#define SSF_AWSPROV_UT_STOP_CSR      (2u)
#define SSF_AWSPROV_UT_STOP_BACKOFF  (3u)
#define SSF_AWSPROV_UT_STOP_REG      (4u)
#define SSF_AWSPROV_UT_STOP_COUNT    (5u)

static void _SSFAWSProvUTSmStopAt(uint32_t at)
{
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    _utBk.csrScript[0] = (at == SSF_AWSPROV_UT_STOP_BACKOFF) ? SSF_AWSPROV_UT_R_REJ429 :
                         SSF_AWSPROV_UT_R_NONE;
    _utBk.regScript[0] = SSF_AWSPROV_UT_R_NONE;
    if (at == SSF_AWSPROV_UT_STOP_CONNECT) _utBk.connAckCode = 0xFFu;
    if (at == SSF_AWSPROV_UT_STOP_REG) _utBk.csrScript[0] = SSF_AWSPROV_UT_R_ACC;
    _utOpts.retryMinWait = SSF_AWSPROV_UT_LONG;
    _utOpts.retryMaxWait = SSF_AWSPROV_UT_LONG;
    _utOpts.responseTimeout = SSF_AWSPROV_UT_LONG;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, _SSFAWSProvUTAppEvent,
                    _utAppEvents);
    switch (at)
    {
    case SSF_AWSPROV_UT_STOP_CONNECT:
        while (_utBk.connectCount < 1u) _SSFAWSProvUTPump();
        break;
    case SSF_AWSPROV_UT_STOP_CSR:
    case SSF_AWSPROV_UT_STOP_BACKOFF:
        while (_utBk.csrCount < 1u) _SSFAWSProvUTPump();
        _SSFAWSProvUTPump();
        break;
    case SSF_AWSPROV_UT_STOP_REG:
        while (_utBk.regCount < 1u) _SSFAWSProvUTPump();
        break;
    default:
        break;
    }
    SSF_ASSERT(SSFAWSProvIsStarted());
    SSFAWSProvStop();
    SSF_ASSERT(SSFAWSProvIsStarted() == false);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));
    _SSFAWSProvUTPumpUntilStopped();
    _SSFAWSProvUTPumpFor(50u);
    SSF_ASSERT(_utDone.count == 0);
    SSF_ASSERT(_utAppEvents[SSF_MQTTC_EVENT_STOPPED] == 1u);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));

    /* A new run after the stop completes */
    memset(_utBk.csrScript, 0, sizeof(_utBk.csrScript));
    memset(_utBk.regScript, 0, sizeof(_utBk.regScript));
    _utBk.connAckCode = 0;
    _utBk.csrCount = 0;
    _utBk.regCount = 0;
    _utOpts.responseTimeout = SSF_AWSPROV_UT_RESPONSE_TO;
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT(_utDone.count == 1u);
    _SSFAWSProvUTExpectDone();
    _SSFAWSProvUTSmEnd();
}

/* --------------------------------------------------------------------------------------------- */
/* Design by contract.                                                                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSmDbc(void)
{
    static const SSFAWSProvParam_t badKey[] = { { NULL, "v" } };
    static const SSFAWSProvParam_t badValue[] = { { "k", NULL } };
    const SSFPortTick_t maxTicks = ((SSFPortTick_t)1u) << 62;
    SSFAWSProvOpts_t o;
    SSFMQTTCRxPublish_t rx;

    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    SSF_ASSERT_TEST(SSFAWSProvInit());
    SSF_ASSERT_TEST(SSFAWSProvStop());
    SSF_ASSERT_TEST(SSFAWSProvStart(NULL, &_utOpts, _SSFAWSProvUTDoneFn, NULL, NULL, NULL));
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, NULL, _SSFAWSProvUTDoneFn, NULL, NULL, NULL));
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, &_utOpts, NULL, NULL, NULL, NULL));
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, NULL, NULL,
                                    _utAppEvents));
    SSF_ASSERT_TEST(SSFAWSProvStart((SSFAWSProvWork_t *)(void *)&_utOpts, &_utOpts,
                                    _SSFAWSProvUTDoneFn, NULL, NULL, NULL));
#define SSF_AWSPROV_UT_BAD_OPT(stmt) \
    memcpy(&o, &_utOpts, sizeof(o)); stmt; \
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, &o, _SSFAWSProvUTDoneFn, NULL, NULL, NULL))
    SSF_AWSPROV_UT_BAD_OPT(o.mqtt.subsOpt = _utWork.topics.subs);
    SSF_AWSPROV_UT_BAD_OPT(o.mqtt.subCount = 1u);
    SSF_AWSPROV_UT_BAD_OPT(o.mqtt.willOpt = (const SSFMQTTCWill_t *)(void *)&o);
    SSF_AWSPROV_UT_BAD_OPT(o.templateName = NULL);
    SSF_AWSPROV_UT_BAD_OPT(o.privKey = NULL);
    SSF_AWSPROV_UT_BAD_OPT(o.privKeyLen = 0);
    SSF_AWSPROV_UT_BAD_OPT(o.paramsOpt = NULL);
    SSF_AWSPROV_UT_BAD_OPT(o.responseTimeout = 0);
    SSF_AWSPROV_UT_BAD_OPT(o.retryMinWait = 0);
    SSF_AWSPROV_UT_BAD_OPT(o.retryMaxWait = o.retryMinWait - 1u);
    SSF_AWSPROV_UT_BAD_OPT(o.tokenLifetime = 0);
    SSF_AWSPROV_UT_BAD_OPT(o.maxAttempts = 0);
    SSF_AWSPROV_UT_BAD_OPT(o.paramsOpt = badKey);
    SSF_AWSPROV_UT_BAD_OPT(o.paramsOpt = badValue);
    SSF_AWSPROV_UT_BAD_OPT(o.responseTimeout = maxTicks + 1u);
    SSF_AWSPROV_UT_BAD_OPT(o.retryMaxWait = maxTicks + 1u);
    SSF_AWSPROV_UT_BAD_OPT(o.deadline = maxTicks + 1u);
    SSF_AWSPROV_UT_BAD_OPT(o.tokenLifetime = maxTicks + 1u);
#undef SSF_AWSPROV_UT_BAD_OPT
    /* The corner cases that are allowed */
    memcpy(&o, &_utOpts, sizeof(o));
    o.paramsOpt = NULL;
    o.paramCount = 0;
    o.retryMaxWait = o.retryMinWait;
    o.deadline = maxTicks;
    o.tokenLifetime = maxTicks;
    SSFAWSProvStart(&_utWork, &o, _SSFAWSProvUTDoneFn, &_utDone, NULL, NULL);
    /* Started: no second Start, no DeInit */
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, NULL, NULL, NULL));
    SSF_ASSERT_TEST(SSFAWSProvDeInit());
    memset(&rx, 0, sizeof(rx));
    SSF_ASSERT_TEST((void)SSFAWSProvRxPublish(NULL, NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvRxPublish(NULL, &rx));
    rx.topic = "a";
    rx.payloadLen = 1u;
    SSF_ASSERT_TEST((void)SSFAWSProvRxPublish(NULL, &rx));
    SSF_ASSERT_TEST(SSFAWSProvEvent(NULL, SSF_MQTTC_EVENT_MAX, SSF_MQTTC_REASON_NONE));
    SSF_ASSERT_TEST(SSFAWSProvEvent(NULL, SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_MAX));
    SSF_ASSERT_TEST(SSFAWSProvEvent(NULL, SSF_MQTTC_EVENT_MIN, SSF_MQTTC_REASON_NONE));
    SSF_ASSERT_TEST(SSFAWSProvEvent(NULL, SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_MIN));
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT((_utDone.count == 1u) && _utDone.isDone);
    /* ssfmqttc not STOPPED (Start only queues its event, so let it run) */
    SSFMQTTCStart(&_utOpts.mqtt);
    _SSFAWSProvUTPump();
    SSF_ASSERT(SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED);
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, NULL, NULL, NULL));
    SSFMQTTCStop();
    _SSFAWSProvUTPumpUntilStopped();
    _SSFAWSProvUTSmEnd();
    /* Not initialized */
    SSF_ASSERT_TEST(SSFAWSProvDeInit());
    SSF_ASSERT_TEST((void)SSFAWSProvIsStarted());
    SSF_ASSERT_TEST(SSFAWSProvStop());
    SSF_ASSERT_TEST((void)SSFAWSProvRxPublish(NULL, &rx));
    SSF_ASSERT_TEST(SSFAWSProvEvent(NULL, SSF_MQTTC_EVENT_READY, SSF_MQTTC_REASON_NONE));
    SSF_ASSERT_TEST(SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneFn, NULL, NULL, NULL));
}

/* --------------------------------------------------------------------------------------------- */
/* Operational credentials (M08)                                                                 */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_UT_BLOB_SIZE (SSF_AWSPROV_CRED_BLOB_MAX_SIZE + 8u)
#define SSF_AWSPROV_UT_CFG_ID    (0u)

static SSFAWSProvCred_t _utCred;
static SSFAWSProvCred_t _utCred2;
static uint8_t _utBlob[SSF_AWSPROV_UT_BLOB_SIZE];
static size_t _utBlobLen;
static uint8_t _utBlobExp[SSF_AWSPROV_UT_BLOB_SIZE];
static size_t _utBlobExpLen;
static uint8_t _utKey2[sizeof(_utAWSProvP256Priv)];
static bool _utCredOk;
static bool _utCredOtherOk;
static SSFTLSCSession_t _utTls;
static uint32_t _utRxCount;

/* --------------------------------------------------------------------------------------------- */
/* Writes the CRC32 of b[0..len-4) big-endian into its last 4 bytes.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTBlobCrc(uint8_t *b, size_t len)
{
    uint32_t crc;

    SSF_REQUIRE((b != NULL) && (len >= 4u));

    crc = SSFCRC32(b, (uint32_t)(len - 4u), SSF_CRC32_INITIAL);
    b[len - 4u] = (uint8_t)(crc >> 24);
    b[len - 3u] = (uint8_t)(crc >> 16);
    b[len - 2u] = (uint8_t)(crc >> 8);
    b[len - 1u] = (uint8_t)crc;
}

/* --------------------------------------------------------------------------------------------- */
/* Builds a v1 blob field by field (independent of the encoder) and returns its length.          */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFAWSProvUTBlobBuild(uint8_t *b, size_t size, uint8_t curveByte,
                                     const uint8_t *priv, size_t privLen, const uint8_t *der,
                                     size_t derLen, const char *name, const char *id)
{
    size_t n = 0;
    size_t nameLen;

    SSF_REQUIRE((b != NULL) && (priv != NULL) && (der != NULL) && (name != NULL) &&
                (id != NULL));

    nameLen = strlen(name);
    SSF_ASSERT((4u + 3u + privLen + 2u + derLen + 1u + nameLen + 64u + 4u) <= size);
    memcpy(&b[n], "AWSC", 4u); n += 4u;
    b[n++] = 1u;
    b[n++] = curveByte;
    b[n++] = (uint8_t)privLen;
    memcpy(&b[n], priv, privLen); n += privLen;
    b[n++] = (uint8_t)(derLen >> 8);
    b[n++] = (uint8_t)derLen;
    memcpy(&b[n], der, derLen); n += derLen;
    b[n++] = (uint8_t)nameLen;
    memcpy(&b[n], name, nameLen); n += nameLen;
    SSF_ASSERT(strlen(id) == 64u);
    memcpy(&b[n], id, 64u); n += 64u;
    n += 4u;
    _SSFAWSProvUTBlobCrc(b, n);
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts cred holds the fixture identity for priv/pub/der and name.                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCredExpect(const SSFAWSProvCred_t *cred, SSFPKeyType_t type,
                                    const uint8_t *priv, size_t privLen, const uint8_t *der,
                                    size_t derLen, const char *name)
{
    SSF_REQUIRE((cred != NULL) && (priv != NULL) && (der != NULL) && (name != NULL));

    SSF_ASSERT(cred->key.type == type);
    SSF_ASSERT((cred->key.privLen == privLen) && (memcmp(cred->key.priv, priv, privLen) == 0));
    SSF_ASSERT(cred->key.pubLen == ((type == SSF_PKEY_TYPE_P256) ? 65u : 97u));
    SSF_ASSERT((cred->certDerLen == derLen) && (memcmp(cred->certDer, der, derLen) == 0));
    SSF_ASSERT(cred->cert.notAfter == SSF_AWSPROV_UT_CERT_NOT_AFTER);
    SSF_ASSERT((cred->cert.pubKeyLen == cred->key.pubLen) &&
               (memcmp(cred->cert.pubKey, cred->key.pub, cred->key.pubLen) == 0));
    SSF_ASSERT(strcmp(cred->thingName, name) == 0);
    SSF_ASSERT(strcmp(cred->certificateId, _utAWSProvCertId) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts blob[0..len) is refused and leaves the output all zero.                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTDecodeRefused(const uint8_t *blob, size_t len)
{
    memset(&_utCred2, 0x5A, sizeof(_utCred2));
    SSF_ASSERT(SSFAWSProvCredDecode(blob, len, &_utCred2) == false);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utCred2, sizeof(_utCred2)));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks a DONE result with each field Decode refuses: CredFromResult refuses it too.           */
/* --------------------------------------------------------------------------------------------- */
static SSFAWSProvCsrAccepted_t _utAcc2;
static uint8_t _utKey48[48];

static void _SSFAWSProvUTFromResultRefused(const SSFAWSProvResult_t *r)
{
    static char longName[SSF_AWSPROV_CONFIG_THING_NAME_SIZE + 1u];
    static const char *const badNames[] = { "", "a b", "a/b", "a.b", "\xC3\xA9" };
    SSFAWSProvResult_t res;
    size_t i;

    SSF_REQUIRE(r != NULL);

#define SSF_AWSPROV_UT_FR_REFUSED() \
    memset(&_utCred2, 0x5A, sizeof(_utCred2)); \
    SSF_ASSERT(SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256, _utAWSProvP256Priv, \
                                        sizeof(_utAWSProvP256Priv), &_utCred2) == false); \
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utCred2, sizeof(_utCred2)))

    memcpy(&res, r, sizeof(res));
    for (i = 0; i < (sizeof(badNames) / sizeof(badNames[0])); i++)
    {
        res.thingNameOpt = badNames[i];
        SSF_AWSPROV_UT_FR_REFUSED();
    }
    memset(longName, 'n', sizeof(longName) - 1u);
    res.thingNameOpt = longName;                    /* THING_NAME_SIZE characters, unterminated */
    SSF_AWSPROV_UT_FR_REFUSED();                    /* within it */
    res.thingNameOpt = r->thingNameOpt;

    /* The certificate fields, on a copy (CredFromResult reads only certDer, its length, id) */
    memcpy(&_utAcc2, r->certOpt, sizeof(_utAcc2));
    res.certOpt = &_utAcc2;
    _utAcc2.certificateId[0] = 'A';
    SSF_AWSPROV_UT_FR_REFUSED();
    _utAcc2.certificateId[0] = r->certOpt->certificateId[0];
    _utAcc2.certificateId[63] = 0;
    SSF_AWSPROV_UT_FR_REFUSED();
    _utAcc2.certificateId[63] = r->certOpt->certificateId[63];
    _utAcc2.certificateId[64] = 'x';
    SSF_AWSPROV_UT_FR_REFUSED();
    _utAcc2.certificateId[64] = 0;
    _utAcc2.certDerLen = 0;
    SSF_AWSPROV_UT_FR_REFUSED();
    _utAcc2.certDerLen = r->certOpt->certDerLen;
    _utAcc2.certDer[0] = 0x31u;                     /* doesn't parse */
    SSF_AWSPROV_UT_FR_REFUSED();
    memset(&_utAcc2, 0, sizeof(_utAcc2));
#undef SSF_AWSPROV_UT_FR_REFUSED
}

/* --------------------------------------------------------------------------------------------- */
/* Done callback that keeps the credentials, and checks another key is refused.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTDoneCred(void *ctx, bool isDone, const SSFAWSProvResult_t *r)
{
    _SSFAWSProvUTDoneFn(ctx, isDone, r);
    SSF_ASSERT(isDone);
    memset(&_utCred2, 0x5A, sizeof(_utCred2));
    _utCredOtherOk = SSFAWSProvCredFromResult(r, SSF_EC_CURVE_P256, _utKey2, sizeof(_utKey2),
                                              &_utCred2);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utCred2, sizeof(_utCred2)));
#if SSF_EC_CONFIG_ENABLE_P384 == 0
    /* A curve that isn't built */
    SSF_ASSERT(SSFAWSProvCredFromResult(r, SSF_EC_CURVE_P384, _utKey48, sizeof(_utKey48),
                                        &_utCred2) == false);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utCred2, sizeof(_utCred2)));
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
    /* The fields Decode would refuse are refused here too */
    _SSFAWSProvUTFromResultRefused(r);
    _utCredOk = SSFAWSProvCredFromResult(r, SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                         sizeof(_utAWSProvP256Priv), &_utCred);
    SSF_ASSERT(_utCredOk);
    SSF_ASSERT(SSFAWSProvCredEncode(&_utCred, _utBlob, sizeof(_utBlob), &_utBlobLen));
}

/* --------------------------------------------------------------------------------------------- */
/* Rx callback for the operational connection.                                                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvUTOpRx(void *ctx, const SSFMQTTCRxPublish_t *rx)
{
    SSF_ASSERT(ctx == &_utRxCount);
    SSF_ASSERT(rx != NULL);
    _utRxCount++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Each field of a good blob made invalid, with its CRC recomputed: refused.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCredFields(void)
{
    static uint8_t b[SSF_AWSPROV_UT_BLOB_SIZE];
    static uint8_t der[sizeof(_utAWSProvP256CertDer)];
    static char name[SSF_AWSPROV_CONFIG_THING_NAME_SIZE + 1u];
    static char id[sizeof(_utAWSProvCertId)];
    const size_t pl = sizeof(_utAWSProvP256Priv);
    const size_t dl = sizeof(_utAWSProvP256CertDer);
    const size_t offCertLen = 7u + pl;
    const size_t offDer = offCertLen + 2u;
    const size_t offNameLen = offDer + dl;
    const size_t offName = offNameLen + 1u;
    const size_t offId = offName + 7u;              /* "thing-1" */
    size_t n;

#define SSF_AWSPROV_UT_GOOD() \
    n = _SSFAWSProvUTBlobBuild(b, sizeof(b), 1u, _utAWSProvP256Priv, pl, \
                               _utAWSProvP256CertDer, dl, "thing-1", _utAWSProvCertId)
#define SSF_AWSPROV_UT_PATCH(off, v) \
    SSF_AWSPROV_UT_GOOD(); b[off] = (uint8_t)(v); _SSFAWSProvUTBlobCrc(b, n); \
    _SSFAWSProvUTDecodeRefused(b, n)
#define SSF_AWSPROV_UT_PATCH2(off, v) \
    SSF_AWSPROV_UT_GOOD(); b[off] = (uint8_t)((v) >> 8); b[(off) + 1u] = (uint8_t)(v); \
    _SSFAWSProvUTBlobCrc(b, n); _SSFAWSProvUTDecodeRefused(b, n)

    /* The good blob decodes */
    SSF_AWSPROV_UT_GOOD();
    SSF_ASSERT(n == (offId + 64u + 4u));
    SSF_ASSERT(SSFAWSProvCredDecode(b, n, &_utCred2));
    SSFAWSProvCredWipe(&_utCred2);

    SSF_AWSPROV_UT_PATCH(0u, 'X');                  /* magic */
    SSF_AWSPROV_UT_PATCH(3u, 'c');
    SSF_AWSPROV_UT_PATCH(4u, 0u);                   /* version */
    SSF_AWSPROV_UT_PATCH(4u, 2u);
    SSF_AWSPROV_UT_PATCH(5u, 0u);                   /* curve */
    SSF_AWSPROV_UT_PATCH(5u, 3u);
    SSF_AWSPROV_UT_PATCH(5u, 2u);                   /* P-384 with a 32-byte scalar */
    SSF_AWSPROV_UT_PATCH(6u, pl - 1u);              /* privLen */
    SSF_AWSPROV_UT_PATCH(6u, pl + 1u);
    SSF_AWSPROV_UT_PATCH(6u, 0u);
    SSF_AWSPROV_UT_PATCH(6u, 0xFFu);
    SSF_AWSPROV_UT_PATCH(7u, 0u);                   /* a different scalar: not the cert's key */
    SSF_AWSPROV_UT_PATCH2(offCertLen, dl - 1u);     /* certLen */
    SSF_AWSPROV_UT_PATCH2(offCertLen, dl + 1u);
    SSF_AWSPROV_UT_PATCH2(offCertLen, SSF_AWSPROV_CONFIG_CERT_DER_SIZE + 1u);
    SSF_AWSPROV_UT_PATCH2(offCertLen, 0xFFFFu);
    SSF_AWSPROV_UT_PATCH(offDer, 0x31u);            /* certificate structure damaged; */
    SSF_AWSPROV_UT_PATCH(offDer + 3u, 0x00u);       /* (Decode checks the structure and the */
                                                    /* key, not the CA signature) */
    SSF_AWSPROV_UT_PATCH(offNameLen, 6u);           /* nameLen */
    SSF_AWSPROV_UT_PATCH(offNameLen, 8u);
    SSF_AWSPROV_UT_PATCH(offNameLen, 0u);
    SSF_AWSPROV_UT_PATCH(offName, ' ');             /* thingName characters */
    SSF_AWSPROV_UT_PATCH(offName, '/');
    SSF_AWSPROV_UT_PATCH(offName, 0u);
    SSF_AWSPROV_UT_PATCH(offName + 6u, 0x80u);
    SSF_AWSPROV_UT_PATCH(offId, 'A');               /* certificateId: lowercase hex only */
    SSF_AWSPROV_UT_PATCH(offId + 63u, 'g');
    SSF_AWSPROV_UT_PATCH(offId, 0u);

    /* An all-zero certificate length and an empty certificate */
    n = 7u + pl;
    memcpy(b, "AWSC\x01\x01", 6u);
    b[6] = (uint8_t)pl;
    memcpy(&b[7], _utAWSProvP256Priv, pl);
    b[n++] = 0; b[n++] = 0;
    b[n++] = 1u; b[n++] = 'a';
    memcpy(&b[n], _utAWSProvCertId, 64u); n += 64u;
    n += 4u;
    _SSFAWSProvUTBlobCrc(b, n);
    _SSFAWSProvUTDecodeRefused(b, n);

    /* Every length below the fixed fields, with a valid CRC and a plausible header: refused */
    memcpy(b, "AWSC\x01\x01\x20", 7u);
    memset(&b[7], 0, sizeof(b) - 7u);
    for (n = 4u; n < (4u + 3u + 2u + 1u + 64u + 4u); n++)
    {
        uint8_t *exact;

        if (n > 4u) memcpy(b, "AWSC\x01\x01\x20", ((n - 4u) < 7u) ? (n - 4u) : 7u);
        _SSFAWSProvUTBlobCrc(b, n);
        /* In a heap block of exactly n bytes, so ASan sees any read past the blob */
        exact = (uint8_t *)SSF_MALLOC(n);
        SSF_ASSERT(exact != NULL);
        memcpy(exact, b, n);
        _SSFAWSProvUTDecodeRefused(exact, n);
        SSF_FREE(exact);
    }

    /* An empty thingName, correctly sized (nameLen 0, no name bytes) */
    n = _SSFAWSProvUTBlobBuild(b, sizeof(b), 1u, _utAWSProvP256Priv, pl, _utAWSProvP256CertDer,
                               dl, "", _utAWSProvCertId);
    SSF_ASSERT(n == (offName + 64u + 4u));
    _SSFAWSProvUTDecodeRefused(b, n);

    /* The longest thingName (THING_NAME_SIZE - 1) is allowed, one more is not */
    memset(name, 'n', SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 1u);
    name[SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 1u] = 0;
    n = _SSFAWSProvUTBlobBuild(b, sizeof(b), 1u, _utAWSProvP256Priv, pl, _utAWSProvP256CertDer,
                               dl, name, _utAWSProvCertId);
    SSF_ASSERT(SSFAWSProvCredDecode(b, n, &_utCred2));
    SSF_ASSERT(strlen(_utCred2.thingName) == (SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 1u));
    SSFAWSProvCredWipe(&_utCred2);
    name[SSF_AWSPROV_CONFIG_THING_NAME_SIZE - 1u] = 'n';
    name[SSF_AWSPROV_CONFIG_THING_NAME_SIZE] = 0;
    n = _SSFAWSProvUTBlobBuild(b, sizeof(b), 1u, _utAWSProvP256Priv, pl, _utAWSProvP256CertDer,
                               dl, name, _utAWSProvCertId);
    _SSFAWSProvUTDecodeRefused(b, n);
    (void)der;
    (void)id;
#undef SSF_AWSPROV_UT_PATCH2
#undef SSF_AWSPROV_UT_PATCH
#undef SSF_AWSPROV_UT_GOOD
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the operational credentials: from DONE, the blob, TLS, the second connection.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTCred(void)
{
    static SSFAWSProvCsrAccepted_t acc;
    static uint8_t cfg[SSF_AWSPROV_UT_BLOB_SIZE];
    static uint8_t cfgBack[SSF_AWSPROV_UT_BLOB_SIZE];
    uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
    SSFAWSProvResult_t res;
    SSFMQTTCOpts_t op;
    uint16_t cfgLen;
    size_t pubLen;
    size_t len;
    size_t i;

    memcpy(_utKey2, _utAWSProvP256Priv, sizeof(_utKey2));
    _utKey2[sizeof(_utKey2) - 1u] ^= 1u;

    /* Provision on the mock broker; doneFn keeps the credentials and encodes them */
    _SSFAWSProvUTSmBegin(SSF_AWSPROV_UT_TX_BLOCK);
    SSFAWSProvStart(&_utWork, &_utOpts, _SSFAWSProvUTDoneCred, &_utDone, NULL, NULL);
    _SSFAWSProvUTPumpUntilStopped();
    SSF_ASSERT((_utDone.count == 1u) && _utDone.isDone && _utCredOk);
    SSF_ASSERT(_utCredOtherOk == false);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utWork, sizeof(_utWork)));
    _SSFAWSProvUTCredExpect(&_utCred, SSF_PKEY_TYPE_P256, _utAWSProvP256Priv,
                            sizeof(_utAWSProvP256Priv), _utAWSProvP256CertDer,
                            sizeof(_utAWSProvP256CertDer), "thing-1");

    /* The encoder writes the layout exactly */
    _utBlobExpLen = _SSFAWSProvUTBlobBuild(_utBlobExp, sizeof(_utBlobExp), 1u,
                                           _utAWSProvP256Priv, sizeof(_utAWSProvP256Priv),
                                           _utAWSProvP256CertDer, sizeof(_utAWSProvP256CertDer),
                                           "thing-1", _utAWSProvCertId);
    SSF_ASSERT((_utBlobLen == _utBlobExpLen) && (memcmp(_utBlob, _utBlobExp, _utBlobLen) == 0));
    SSF_ASSERT(_utBlobLen <= SSF_AWSPROV_CRED_BLOB_MAX_SIZE);

    /* Exact output size passes, one short fails with the output zeroed */
    memset(cfg, 0x5A, sizeof(cfg));
    SSF_ASSERT(SSFAWSProvCredEncode(&_utCred, cfg, _utBlobLen, &len) && (len == _utBlobLen));
    len = 1u;
    memset(cfg, 0x5A, sizeof(cfg));
    SSF_ASSERT(SSFAWSProvCredEncode(&_utCred, cfg, _utBlobLen - 1u, &len) == false);
    SSF_ASSERT((len == 0) && _SSFAWSProvUTIsZero(cfg, _utBlobLen - 1u) &&
               (cfg[_utBlobLen - 1u] == 0x5Au));

    /* Store it in ssfcfg (one record), wipe every copy, read it back, decode */
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSFCfgInit();                                /* Only built with thread support */
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
    SSF_ASSERT(SSFCfgWrite(_utBlob, (uint16_t)_utBlobLen, SSF_AWSPROV_UT_CFG_ID, 1));
    memset(_utBlob, 0, sizeof(_utBlob));
    SSFAWSProvCredWipe(&_utCred);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utCred, sizeof(_utCred)));
    cfgLen = 0;
    SSF_ASSERT(SSFCfgRead(cfgBack, &cfgLen, sizeof(cfgBack), SSF_AWSPROV_UT_CFG_ID) == 1);
    SSF_ASSERT(cfgLen == _utBlobExpLen);
    SSF_ASSERT(SSFAWSProvCredDecode(cfgBack, cfgLen, &_utCred));
    _SSFAWSProvUTCredExpect(&_utCred, SSF_PKEY_TYPE_P256, _utAWSProvP256Priv,
                            sizeof(_utAWSProvP256Priv), _utAWSProvP256CertDer,
                            sizeof(_utAWSProvP256CertDer), "thing-1");
    /* The largest blob fits one record too */
    memset(cfg, 0xA5, sizeof(cfg));
    SSF_ASSERT(SSFCfgWrite(cfg, (uint16_t)SSF_AWSPROV_CRED_BLOB_MAX_SIZE, SSF_AWSPROV_UT_CFG_ID,
                           2));
    memset(cfgBack, 0, sizeof(cfgBack));
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSFCfgDeInit();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

    /* Every byte flipped, every truncation and one extra byte: refused */
    for (i = 0; i < _utBlobExpLen; i++)
    {
        _utBlobExp[i] ^= 0x01u;
        _SSFAWSProvUTDecodeRefused(_utBlobExp, _utBlobExpLen);
        _utBlobExp[i] ^= 0x81u;
        _SSFAWSProvUTDecodeRefused(_utBlobExp, _utBlobExpLen);
        _utBlobExp[i] ^= 0x80u;
    }
    for (i = 0; i < _utBlobExpLen; i++) _SSFAWSProvUTDecodeRefused(_utBlobExp, i);
    memset(&_utBlobExp[_utBlobExpLen], 0, sizeof(_utBlobExp) - _utBlobExpLen);
    _SSFAWSProvUTDecodeRefused(_utBlobExp, SSF_AWSPROV_CRED_BLOB_MAX_SIZE + 1u);
    _utBlobExp[_utBlobExpLen] = 0;
    _SSFAWSProvUTDecodeRefused(_utBlobExp, _utBlobExpLen + 1u);
    SSF_ASSERT(SSFAWSProvCredDecode(_utBlobExp, _utBlobExpLen, &_utCred2));
    SSFAWSProvCredWipe(&_utCred2);
    _SSFAWSProvUTCredFields();

    /* TLS: the session holds the chain and key; a key that no longer matches is refused */
    SSFTLSCInit(&_utTls, &_utBk.transport, NULL);
    SSF_ASSERT(SSFAWSProvApplyTLS(&_utTls, &_utCred));
    SSF_ASSERT((_utTls.clientChainCount == 1u) && (_utTls.clientKey == &_utCred.key));
    SSF_ASSERT(_utTls.clientChainDer[0] == _utCred.certDer);
    SSF_ASSERT(_utTls.clientChainLens[0] == (uint32_t)_utCred.certDerLen);
    _utCred.key.pub[10] ^= 1u;
    SSF_ASSERT(SSFAWSProvApplyTLS(&_utTls, &_utCred) == false);
    _utCred.key.pub[10] ^= 1u;
    /* A wiped credential is refused */
    SSF_ASSERT(SSFAWSProvCredDecode(_utBlobExp, _utBlobExpLen, &_utCred2));
    SSFAWSProvCredWipe(&_utCred2);
    SSF_ASSERT(SSFAWSProvApplyTLS(&_utTls, &_utCred2) == false);
    /* Cleared from the session before the credentials go away */
    SSF_ASSERT(SSFTLSCSetClientCert(&_utTls, NULL, NULL, 0, NULL));
    SSF_ASSERT(_utTls.clientChainCount == 0);
    SSFTLSCDeInit(&_utTls);

    /* The operational connection: re-Init with app callbacks, clientId = thingName */
    SSFAWSProvDeInit();
    SSFMQTTCDeInit();
    SSFMQTTCInit(&_utBk.transport, 4u, SSF_AWSPROV_UT_TX_BLOCK, SSF_AWSPROV_UT_RX_BLOCK,
                 _SSFAWSProvUTOpRx, &_utRxCount, NULL, NULL);
    memcpy(&op, &_utOpts.mqtt, sizeof(op));
    op.clientId = _utCred.thingName;
    SSFMQTTCStart(&op);
    while (_utBk.connectCount < 2u) _SSFAWSProvUTPump();
    _SSFAWSProvUTPump();
    SSF_ASSERT(strcmp(_utBk.clientId, "thing-1") == 0);
    SSF_ASSERT(SSFMQTTCIsReady());
    SSFMQTTCStop();
    while (SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED) _SSFAWSProvUTPump();
    SSFMQTTCDeInit();
    SSFSMDeInit();
    SSFAWSProvCredWipe(&_utCred);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utCred, sizeof(_utCred)));

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* P-384: credentials from a result built around a parsed accepted response */
    len = _SSFAWSProvUTAccGood(_utAWSProvP384CertPem);
    SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P384, _utAWSProvP384Priv,
                                         sizeof(_utAWSProvP384Priv), pub, sizeof(pub),
                                         &pubLen));
    SSF_ASSERT(SSFAWSProvParseCsrAccepted((const uint8_t *)_utJson, len, _utRx, sizeof(_utRx),
                                          SSF_EC_CURVE_P384, pub, pubLen, &acc));
    memset(&res, 0, sizeof(res));
    res.reason = SSF_AWSPROV_REASON_NONE;
    res.errorCode = "";
    res.errorMessage = "";
    res.certOpt = &acc;
    res.thingNameOpt = "thing:384_x-y";
    res.deviceConfigOpt = "{}";
    res.deviceConfigLen = 2u;
    SSF_ASSERT(SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                        sizeof(_utAWSProvP256Priv), &_utCred) == false);
    SSF_ASSERT(_SSFAWSProvUTIsZero(&_utCred, sizeof(_utCred)));
    SSF_ASSERT(SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P384, _utAWSProvP384Priv,
                                        sizeof(_utAWSProvP384Priv), &_utCred));
    SSF_ASSERT(SSFAWSProvCredEncode(&_utCred, _utBlob, sizeof(_utBlob), &_utBlobLen));
    _utBlobExpLen = _SSFAWSProvUTBlobBuild(_utBlobExp, sizeof(_utBlobExp), 2u,
                                           _utAWSProvP384Priv, sizeof(_utAWSProvP384Priv),
                                           _utAWSProvP384CertDer, sizeof(_utAWSProvP384CertDer),
                                           "thing:384_x-y", _utAWSProvCertId);
    SSF_ASSERT((_utBlobLen == _utBlobExpLen) && (memcmp(_utBlob, _utBlobExp, _utBlobLen) == 0));
    SSFAWSProvCredWipe(&_utCred);
    SSF_ASSERT(SSFAWSProvCredDecode(_utBlob, _utBlobLen, &_utCred));
    _SSFAWSProvUTCredExpect(&_utCred, SSF_PKEY_TYPE_P384, _utAWSProvP384Priv,
                            sizeof(_utAWSProvP384Priv), _utAWSProvP384CertDer,
                            sizeof(_utAWSProvP384CertDer), "thing:384_x-y");
    /* A P-256 scalar against the P-384 certificate */
    _utBlobExpLen = _SSFAWSProvUTBlobBuild(_utBlobExp, sizeof(_utBlobExp), 1u,
                                           _utAWSProvP256Priv, sizeof(_utAWSProvP256Priv),
                                           _utAWSProvP384CertDer, sizeof(_utAWSProvP384CertDer),
                                           "t", _utAWSProvCertId);
    _SSFAWSProvUTDecodeRefused(_utBlobExp, _utBlobExpLen);
    SSFAWSProvCredWipe(&_utCred);
    memset(&acc, 0, sizeof(acc));
#else
    (void)acc; (void)res; (void)pub; (void)pubLen;
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    /* DBC */
    memset(&res, 0, sizeof(res));
    res.errorCode = "";
    res.errorMessage = "";
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(NULL, SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                                   32u, &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                                   32u, &_utCred));     /* not a DONE result */
    res.certOpt = &acc;
    res.thingNameOpt = "t";
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256, NULL, 32u,
                                                   &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                                   32u, NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_MAX, _utAWSProvP256Priv,
                                                   32u, &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256, _utKey48, 48u,
                                                   &_utCred));          /* size for the curve */
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P384, _utKey48, 32u,
                                                   &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256,
                                                   _utCred.key.priv, 32u, &_utCred));
    res.certOpt = (const SSFAWSProvCsrAccepted_t *)(const void *)&_utCred;
    SSF_ASSERT_TEST((void)SSFAWSProvCredFromResult(&res, SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                                   32u, &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvCredEncode(NULL, _utBlob, sizeof(_utBlob), &len));
    SSF_ASSERT_TEST((void)SSFAWSProvCredEncode(&_utCred, NULL, sizeof(_utBlob), &len));
    SSF_ASSERT_TEST((void)SSFAWSProvCredEncode(&_utCred, _utBlob, sizeof(_utBlob), NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvCredEncode(&_utCred, _utBlob, sizeof(_utBlob), &len));
                                                                       /* not a credential */
    SSF_ASSERT_TEST((void)SSFAWSProvCredEncode(&_utCred, (uint8_t *)&_utCred, 16u, &len));
    SSF_ASSERT_TEST((void)SSFAWSProvCredDecode(NULL, 1u, &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvCredDecode(_utBlob, 1u, NULL));
    SSF_ASSERT_TEST((void)SSFAWSProvCredDecode((const uint8_t *)&_utCred, 16u, &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvApplyTLS(NULL, &_utCred));
    SSF_ASSERT_TEST((void)SSFAWSProvApplyTLS(&_utTls, NULL));
    SSF_ASSERT_TEST(SSFAWSProvCredWipe(NULL));
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the provisioning state machine.                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTStateMachine(void)
{
    uint32_t i;

    /* The good accepted response and the expected RegisterThing request */
    _utCsrAccLen = _SSFAWSProvUTAccGood(_utAWSProvP256CertPem);
    SSF_ASSERT(_utCsrAccLen < sizeof(_utCsrAcc));
    memcpy(_utCsrAcc, _utJson, _utCsrAccLen + 1u);
    SSF_ASSERT(SSFAWSProvBuildRegisterRequest(_utAWSProvToken, strlen(_utAWSProvToken), _utParams,
                                              1u, _utRegExpect, sizeof(_utRegExpect),
                                              &_utRegExpectLen));

    _SSFAWSProvUTSmHappy();
    _SSFAWSProvUTSmSteps();
    _SSFAWSProvUTSmBackoff();
    _SSFAWSProvUTSmBackoffMath();
    _SSFAWSProvUTSmLink();
    _SSFAWSProvUTSmBuild();
    _SSFAWSProvUTSmLate();
    for (i = 0; i < SSF_AWSPROV_UT_STOP_COUNT; i++) _SSFAWSProvUTSmStopAt(i);
    _SSFAWSProvUTSmDbc();
    _SSFAWSProvUTCred();
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN, SSF_EC_CONFIG_ENABLE_P256, SSF_AWSPROV_UT_ACC_FULL */

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
    _SSFAWSProvUTCsrAccepted();
    _SSFAWSProvUTRejected();
    _SSFAWSProvUTRetryable();
    _SSFAWSProvUTRegRequest();
    _SSFAWSProvUTRegAccepted();
#if (SSF_ECDSA_CONFIG_ENABLE_SIGN == 1) && (SSF_EC_CONFIG_ENABLE_P256 == 1) && \
    (SSF_AWSPROV_UT_ACC_FULL == 1)
    _SSFAWSProvUTStateMachine();
#endif
}

#endif /* SSF_CONFIG_AWSPROV_UNIT_TEST */
