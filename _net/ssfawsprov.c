/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfawsprov.c                                                                                  */
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
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfawsprov.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_PT_PREFIX   "$aws/provisioning-templates/"
#define SSF_AWSPROV_PT_REQ      "/provision/json"
#define SSF_AWSPROV_PT_ACCEPTED "/provision/json/accepted"
#define SSF_AWSPROV_PT_REJECTED "/provision/json/rejected"

/* --------------------------------------------------------------------------------------------- */
/* Returns true if c is one of [0-9A-Za-z_-].                                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvIsNameChar(char c)
{
    return (((c >= '0') && (c <= '9')) || ((c >= 'A') && (c <= 'Z')) ||
            ((c >= 'a') && (c <= 'z')) || (c == '_') || (c == '-'));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if prefix, name and suffixStr fit in outStr as one NUL-terminated topic.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvBuildTopic(char *outStr, size_t outSize, SSFCStrIn_t nameStr,
                                  size_t nameSize, SSFCStrIn_t suffixStr)
{
    SSF_REQUIRE(outStr != NULL);
    SSF_REQUIRE(nameStr != NULL);
    SSF_REQUIRE(suffixStr != NULL);

    if (SSFStrCpy(outStr, outSize, NULL, SSF_AWSPROV_PT_PREFIX,
                  sizeof(SSF_AWSPROV_PT_PREFIX)) == false) return false;
    if (SSFStrCat(outStr, outSize, NULL, nameStr, nameSize) == false) return false;
    return SSFStrCat(outStr, outSize, NULL, suffixStr, SSF_AWSPROV_MAX_TOPIC_SIZE);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if nameStr is a valid provisioning template name, else false.                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvTemplateNameIsValid(SSFCStrIn_t nameStr, size_t nameSize)
{
    size_t len;
    size_t i;

    SSF_REQUIRE(nameStr != NULL);

    if (SSFStrLen(nameStr, nameSize, &len) == false) return false;
    if ((len < 1u) || (len >= SSF_AWSPROV_TEMPLATE_NAME_SIZE)) return false;
    for (i = 0; i < len; i++)
    {
        if (_SSFAWSProvIsNameChar(nameStr[i]) == false) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the template topics and subscription set are built, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvTopicsInit(SSFAWSProvTopics_t *topicsOut, SSFCStrIn_t templateNameStr,
                          size_t templateNameSize)
{
    bool ok;

    SSF_REQUIRE(topicsOut != NULL);
    SSF_REQUIRE(templateNameStr != NULL);

    if (SSFAWSProvTemplateNameIsValid(templateNameStr, templateNameSize) == false) return false;

    ok = _SSFAWSProvBuildTopic(topicsOut->provReq, sizeof(topicsOut->provReq), templateNameStr,
                               templateNameSize, SSF_AWSPROV_PT_REQ);
    SSF_ENSURE(ok);
    ok = _SSFAWSProvBuildTopic(topicsOut->provAccepted, sizeof(topicsOut->provAccepted),
                               templateNameStr, templateNameSize, SSF_AWSPROV_PT_ACCEPTED);
    SSF_ENSURE(ok);
    ok = _SSFAWSProvBuildTopic(topicsOut->provRejected, sizeof(topicsOut->provRejected),
                               templateNameStr, templateNameSize, SSF_AWSPROV_PT_REJECTED);
    SSF_ENSURE(ok);

    topicsOut->subs[SSF_AWSPROV_SUB_CSR_ACCEPTED].filter = SSF_AWSPROV_TOPIC_CSR_ACCEPTED;
    topicsOut->subs[SSF_AWSPROV_SUB_CSR_REJECTED].filter = SSF_AWSPROV_TOPIC_CSR_REJECTED;
    topicsOut->subs[SSF_AWSPROV_SUB_PROV_ACCEPTED].filter = topicsOut->provAccepted;
    topicsOut->subs[SSF_AWSPROV_SUB_PROV_REJECTED].filter = topicsOut->provRejected;
    topicsOut->subs[SSF_AWSPROV_SUB_CSR_ACCEPTED].qos = SSF_MQTTC_QOS_1;
    topicsOut->subs[SSF_AWSPROV_SUB_CSR_REJECTED].qos = SSF_MQTTC_QOS_1;
    topicsOut->subs[SSF_AWSPROV_SUB_PROV_ACCEPTED].qos = SSF_MQTTC_QOS_1;
    topicsOut->subs[SSF_AWSPROV_SUB_PROV_REJECTED].qos = SSF_MQTTC_QOS_1;
    return true;
}
