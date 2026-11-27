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
#include "ssfawsprov.h"

#if SSF_CONFIG_AWSPROV_UNIT_TEST == 1

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

/* --------------------------------------------------------------------------------------------- */
/* Runs the ssfawsprov unit test.                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFAWSProvUnitTest(void)
{
    _SSFAWSProvUTSizes();
    _SSFAWSProvUTConfig();
    _SSFAWSProvUTNameIsValid();
    _SSFAWSProvUTTopicsInit();
}

#endif /* SSF_CONFIG_AWSPROV_UNIT_TEST */
