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
#define SSF_AWSPROV_UT_LIT_LEN(s)    (sizeof(s) - 1u)
#define SSF_AWSPROV_UT_PT_SIZE(s)    (SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_PT_PREFIX) + \
                                      SSF_AWSPROV_UT_NAME_MAX_LEN + sizeof(s))

static char _utTopic[SSF_AWSPROV_UT_PT_SIZE(SSF_AWSPROV_UT_PT_REJECTED) + 1u];

/* --------------------------------------------------------------------------------------------- */
/* Builds a template topic with a longest legal name and returns its size with NUL.              */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFAWSProvUTTemplateTopicSize(const char *suffixStr)
{
    size_t prefixLen = SSF_AWSPROV_UT_LIT_LEN(SSF_AWSPROV_UT_PT_PREFIX);
    size_t suffixLen;

    SSF_REQUIRE(suffixStr != NULL);
    suffixLen = strlen(suffixStr);
    SSF_REQUIRE((prefixLen + SSF_AWSPROV_UT_NAME_MAX_LEN + suffixLen) < sizeof(_utTopic));

    memcpy(_utTopic, SSF_AWSPROV_UT_PT_PREFIX, prefixLen);
    memset(&_utTopic[prefixLen], 'n', SSF_AWSPROV_UT_NAME_MAX_LEN);
    memcpy(&_utTopic[prefixLen + SSF_AWSPROV_UT_NAME_MAX_LEN], suffixStr, (suffixLen + 1u));
    return (strlen(_utTopic) + 1u);
}

/* --------------------------------------------------------------------------------------------- */
/* Checks the protocol size constants against the AWS topic strings.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTSizes(void)
{
    SSF_ASSERT(SSF_AWSPROV_TEMPLATE_NAME_SIZE == (SSF_AWSPROV_UT_NAME_MAX_LEN + 1u));

    SSF_ASSERT(_SSFAWSProvUTTemplateTopicSize(SSF_AWSPROV_UT_PT_REJECTED) ==
               SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(_SSFAWSProvUTTemplateTopicSize(SSF_AWSPROV_UT_PT_ACCEPTED) ==
               SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(_SSFAWSProvUTTemplateTopicSize(SSF_AWSPROV_UT_PT_REQ) <
               SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(sizeof(SSF_AWSPROV_UT_CSR_REQ) < SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(sizeof(SSF_AWSPROV_UT_CSR_ACCEPTED) < SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(sizeof(SSF_AWSPROV_UT_CSR_REJECTED) < SSF_AWSPROV_MAX_TOPIC_SIZE);
}

/* --------------------------------------------------------------------------------------------- */
/* Checks at run time the configuration relations that ssfawsprov.h enforces at build.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvUTConfig(void)
{
    SSF_ASSERT(SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE >= SSF_AWSPROV_MAX_TOPIC_SIZE);
    SSF_ASSERT(SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE >= SSF_AWSPROV_CONFIG_THING_NAME_SIZE);
    SSF_ASSERT(SSF_JSON_CONFIG_MAX_IN_LEN >= (SSF_AWSPROV_CONFIG_RX_SIZE - 1u));
    SSF_ASSERT((SSF_AWSPROV_CONFIG_RX_SIZE >= 2u) && (SSF_AWSPROV_CONFIG_RX_SIZE <= 65536ul));
    SSF_ASSERT((SSF_AWSPROV_CONFIG_THING_NAME_SIZE >= 2u) &&
               (SSF_AWSPROV_CONFIG_THING_NAME_SIZE <= 129u));
}

/* --------------------------------------------------------------------------------------------- */
/* Runs the ssfawsprov unit test.                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFAWSProvUnitTest(void)
{
    _SSFAWSProvUTSizes();
    _SSFAWSProvUTConfig();
}

#endif /* SSF_CONFIG_AWSPROV_UNIT_TEST */
