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
#include <string.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfsha2.h"
#include "ssfpem.h"
#include "ssfjson.h"
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

/* --------------------------------------------------------------------------------------------- */
/* CreateCertificateFromCsr responses: defines                                                   */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_CERT_LABEL     "CERTIFICATE"
#define SSF_AWSPROV_CERT_ID_LEN    (SSF_AWSPROV_CERT_ID_SIZE - 1u)
#define SSF_AWSPROV_STATUS_LEN     (3u)

/* id-ecPublicKey */
static const uint8_t _ssfAWSProvOidEC[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

/* --------------------------------------------------------------------------------------------- */
/* Returns true if [a, a + aLen) and [b, b + bLen) do not overlap.                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvIsDisjoint(const void *a, size_t aLen, const void *b, size_t bLen)
{
    return ((((uintptr_t)a + aLen) <= (uintptr_t)b) || ((uintptr_t)a >= ((uintptr_t)b + bLen)));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if payload is copied to rxBuf with a NUL and is valid JSON, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvRxCopy(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                              size_t rxSize)
{
    size_t i;

    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE(rxBuf != NULL);

    if (payloadLen >= rxSize) return false;
    for (i = 0; i < payloadLen; i++)
    {
        if (payload[i] == 0u) return false;
        rxBuf[i] = (char)payload[i];
    }
    rxBuf[payloadLen] = 0;
    return SSFJsonIsValid(rxBuf);
}

/* --------------------------------------------------------------------------------------------- */
/* Sets path to the single top-level member keyStr.                                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvPath(SSFGPath_t *path, size_t pathSize, const char *keyStr)
{
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(pathSize == (sizeof(SSFGPath_t) * (SSF_JSON_CONFIG_MAX_IN_DEPTH + 1u)));
    SSF_REQUIRE(keyStr != NULL);

    memset((void *)path, 0, pathSize);
    SSF_GPATH_SET_KEY(path[0], keyStr);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with the span of top-level string member keyStr, quotes excluded.                */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvStrSpan(const char *jsStr, const char *keyStr, size_t *startOut,
                               size_t *lenOut)
{
    SSFGPath_t path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
    SSFJsonType_t jt;
    size_t index;
    size_t start;
    size_t end;

    SSF_REQUIRE(jsStr != NULL);
    SSF_REQUIRE(keyStr != NULL);
    SSF_REQUIRE(startOut != NULL);
    SSF_REQUIRE(lenOut != NULL);

    _SSFAWSProvPath(path, sizeof(path), keyStr);
    if (SSFJsonMessage(jsStr, &index, &start, &end, path, 0, &jt) == false) return false;
    if (jt != SSF_JSON_TYPE_STRING) return false;
    SSF_ASSERT(end > start);
    *startOut = start + 1u;
    *lenOut = (end - start) - 1u;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str[0..len) is lowercase hexadecimal.                                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvIsLowerHex(const char *str, size_t len)
{
    size_t i;

    SSF_REQUIRE(str != NULL);

    for (i = 0; i < len; i++)
    {
        if (((str[i] < '0') || (str[i] > '9')) && ((str[i] < 'a') || (str[i] > 'f')))
        {
            return false;
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the certificate is on curve and its public key equals pubKey.                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvCertKeyIs(const SSFX509Cert_t *cert, SSFECCurve_t curve,
                                 const uint8_t *pubKey, size_t pubKeyLen)
{
    SSF_REQUIRE(cert != NULL);
    SSF_REQUIRE(pubKey != NULL);

    /* Is the certificate key on the device key's curve? */
    if (curve == SSF_EC_CURVE_P384)
    {
        /* Yes if it is a P-384 key */
        if (SSFX509IsKeyP384(cert) == false) return false;
    }
    else
    {
        /* Yes if it is a P-256 key */
        if (SSFX509IsKeyP256(cert) == false) return false;
    }
    if ((cert->pubKeyAlgOidRawLen != sizeof(_ssfAWSProvOidEC)) ||
        (memcmp(cert->pubKeyAlgOidRaw, _ssfAWSProvOidEC, sizeof(_ssfAWSProvOidEC)) != 0))
    {
        return false;
    }
    if ((cert->pubKeyUnusedBits != 0u) || (cert->pubKeyLen != pubKeyLen)) return false;
    return (memcmp(cert->pubKey, pubKey, pubKeyLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the accepted fields are taken from rxBuf into out, else false.                */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvCsrAcceptedFields(char *rxBuf, size_t rxSize, size_t payloadLen,
                                         SSFECCurve_t curve, const uint8_t *pubKey,
                                         size_t pubKeyLen, SSFAWSProvCsrAccepted_t *out)
{
    SSFGPath_t path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
    SSFPEMResult_t pr;
    const char *label;
    char *pemStr;
    size_t labelLen;
    size_t pemSize;
    size_t pemLen;
    size_t start;
    size_t len;
    size_t pos;

    SSF_REQUIRE(rxBuf != NULL);
    SSF_REQUIRE(payloadLen < rxSize);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(out != NULL);

    /* certificateId: exactly 64 lowercase hex characters */
    if (_SSFAWSProvStrSpan(rxBuf, "certificateId", &start, &len) == false) return false;
    if ((len != SSF_AWSPROV_CERT_ID_LEN) || (_SSFAWSProvIsLowerHex(&rxBuf[start], len) == false))
    {
        return false;
    }
    memcpy(out->certificateId, &rxBuf[start], len);
    out->certificateId[len] = 0;

    /* certificateOwnershipToken: kept as its raw escaped JSON text */
    if (_SSFAWSProvStrSpan(rxBuf, "certificateOwnershipToken", &start, &len) == false)
    {
        return false;
    }
    if ((len == 0u) || (len >= sizeof(out->token))) return false;
    memcpy(out->token, &rxBuf[start], len);
    out->token[len] = 0;
    out->tokenLen = len;

    /* certificatePem: unescaped into rxBuf after the payload, one CERTIFICATE block */
    pemStr = &rxBuf[payloadLen + 1u];
    pemSize = rxSize - (payloadLen + 1u);
    if (pemSize == 0u) return false;
    _SSFAWSProvPath(path, sizeof(path), "certificatePem");
    if (SSFJsonGetString(rxBuf, path, pemStr, pemSize, &pemLen) == false) return false;
    pos = 0;
    pr = SSFPEMDecodeNext(pemStr, pemLen, &pos, &label, &labelLen, out->certDer,
                          sizeof(out->certDer), &out->certDerLen);
    if (pr != SSF_PEM_BLOCK) return false;
    if (SSFPEMLabelIs(label, labelLen, SSF_AWSPROV_CERT_LABEL) == false) return false;
    if (SSFPEMDecodeNext(pemStr, pemLen, &pos, &label, &labelLen, NULL, 0, &len) !=
        SSF_PEM_END) return false;

    /* The certificate parses and holds the device public key */
    if (SSFX509Parse(out->certDer, (uint32_t)out->certDerLen, &out->cert) == false) return false;
    return _SSFAWSProvCertKeyIs(&out->cert, curve, pubKey, pubKeyLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a CreateCertificateFromCsr accepted response is parsed into out.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvParseCsrAccepted(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                                size_t rxSize, SSFECCurve_t curve, const uint8_t *pubKey,
                                size_t pubKeyLen, SSFAWSProvCsrAccepted_t *out)
{
    const SSFECCurveParams_t *c;
    bool ok = false;

    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE(rxBuf != NULL);
    SSF_REQUIRE(rxSize > 0u);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(payload, payloadLen, rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(payload, payloadLen, out, sizeof(*out)));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(rxBuf, rxSize, out, sizeof(*out)));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(pubKey, pubKeyLen, rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(pubKey, pubKeyLen, out, sizeof(*out)));
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));

    memset(out, 0, sizeof(*out));
    c = SSFECGetCurveParams(curve);
    /* Is the curve built? */
    if (c != NULL)
    {
        /* Yes, parse the copy */
        SSF_REQUIRE(pubKeyLen == (1u + (2u * (size_t)c->bytes)));
        ok = (_SSFAWSProvRxCopy(payload, payloadLen, rxBuf, rxSize) &&
              _SSFAWSProvCsrAcceptedFields(rxBuf, rxSize, payloadLen, curve, pubKey, pubKeyLen,
                                           out));
    }
    memset(rxBuf, 0, rxSize);
    /* Did any step fail? */
    if (ok == false)
    {
        /* Yes, leave nothing behind, the token included */
        memset(out, 0, sizeof(*out));
    }
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* RegisterThing request and response: defines and types                                         */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_TOKEN_KEY  "certificateOwnershipToken"
#define SSF_AWSPROV_EMPTY_CFG  "{}"

typedef struct
{
    const char *tokenStr;
    size_t tokenLen;
    const SSFAWSProvParam_t *params;
    size_t count;
} _SSFAWSProvRegReq_t;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if no byte of str is 0x80 or above.                                              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvIsAscii(const char *str)
{
    SSF_REQUIRE(str != NULL);

    while (*str != 0)
    {
        if ((uint8_t)*str >= 0x80u) return false;
        str++;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the parameters object members fit in js, else false.                          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvRegParamsFn(char *js, size_t jsSize, size_t start, size_t *end, void *in)
{
    const _SSFAWSProvRegReq_t *r = (const _SSFAWSProvRegReq_t *)in;
    bool comma = false;
    size_t i;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(r != NULL);

    for (i = 0; i < r->count; i++)
    {
        if (SSFJsonPrintLabel(js, jsSize, start, &start, r->params[i].keyStr, &comma) == false)
        {
            return false;
        }
        if (SSFJsonPrintString(js, jsSize, start, &start, r->params[i].valueStr, NULL) == false)
        {
            return false;
        }
    }
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the request members, the token written as is, fit in js, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvRegFn(char *js, size_t jsSize, size_t start, size_t *end, void *in)
{
    const _SSFAWSProvRegReq_t *r = (const _SSFAWSProvRegReq_t *)in;
    bool comma = true;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(r != NULL);

    if (SSFJsonPrintLabel(js, jsSize, start, &start, SSF_AWSPROV_TOKEN_KEY, NULL) == false)
    {
        return false;
    }
    if (((jsSize - start) < 2u) || (r->tokenLen > ((jsSize - start) - 2u))) return false;
    js[start] = '"';
    memcpy(&js[start + 1u], r->tokenStr, r->tokenLen);
    start += r->tokenLen + 1u;
    js[start] = '"';
    start++;
    /* Are there template parameters? */
    if (r->count > 0u)
    {
        /* Yes, add the parameters object */
        if (SSFJsonPrintLabel(js, jsSize, start, &start, "parameters", &comma) == false)
        {
            return false;
        }
        if (SSFJsonPrintObject(js, jsSize, start, &start, _SSFAWSProvRegParamsFn, (void *)r,
                               NULL) == false) return false;
    }
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if no parameter string starts inside [buf, buf + bufSize).                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvParamsOutside(const SSFAWSProvParam_t *paramsOpt, size_t paramCount,
                                     const void *buf, size_t bufSize)
{
    size_t i;

    for (i = 0; i < paramCount; i++)
    {
        if ((_SSFAWSProvIsDisjoint(paramsOpt[i].keyStr, (strlen(paramsOpt[i].keyStr) + 1u), buf,
                                   bufSize) == false) ||
            (_SSFAWSProvIsDisjoint(paramsOpt[i].valueStr, (strlen(paramsOpt[i].valueStr) + 1u),
                                   buf, bufSize) == false))
        {
            return false;
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the RegisterThing request JSON is built in outStr, else false.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvBuildRegisterRequest(const char *tokenStr, size_t tokenLen,
                                    const SSFAWSProvParam_t *paramsOpt, size_t paramCount,
                                    char *outStr, size_t outSize, size_t *outLen)
{
    _SSFAWSProvRegReq_t r;
    size_t end;
    size_t start;
    size_t len;
    size_t i;
    bool ok = false;

    SSF_REQUIRE(tokenStr != NULL);
    SSF_REQUIRE(tokenLen > 0u);
    SSF_REQUIRE((paramsOpt != NULL) || (paramCount == 0u));
    SSF_REQUIRE(outStr != NULL);
    SSF_REQUIRE(outSize > 0u);
    SSF_REQUIRE(outLen != NULL);
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(tokenStr, tokenLen, outStr, outSize));
    SSF_REQUIRE((paramCount == 0u) ||
                _SSFAWSProvIsDisjoint(paramsOpt, (paramCount * sizeof(*paramsOpt)), outStr,
                                      outSize));
    for (i = 0; i < paramCount; i++)
    {
        SSF_REQUIRE(paramsOpt[i].keyStr != NULL);
        SSF_REQUIRE(paramsOpt[i].valueStr != NULL);
    }
    SSF_REQUIRE(_SSFAWSProvParamsOutside(paramsOpt, paramCount, outStr, outSize));

    *outLen = 0;
    outStr[0] = 0;
    for (i = 0; i < tokenLen; i++)
    {
        if ((uint8_t)tokenStr[i] < 0x20u) goto done;
    }
    for (i = 0; i < paramCount; i++)
    {
        if ((_SSFAWSProvIsAscii(paramsOpt[i].keyStr) == false) ||
            (_SSFAWSProvIsAscii(paramsOpt[i].valueStr) == false)) goto done;
    }
    r.tokenStr = tokenStr;
    r.tokenLen = tokenLen;
    r.params = paramsOpt;
    r.count = paramCount;
    if (SSFJsonPrintObject(outStr, outSize, 0, &end, _SSFAWSProvRegFn, &r, NULL) == false)
    {
        goto done;
    }

    /* The result must be valid JSON whose token member is exactly tokenStr */
    if (_SSFAWSProvStrSpan(outStr, SSF_AWSPROV_TOKEN_KEY, &start, &len) == false) goto done;
    if ((len != tokenLen) || (memcmp(&outStr[start], tokenStr, tokenLen) != 0)) goto done;
    *outLen = end;
    ok = true;

done:
    /* Did any step fail? */
    if (ok == false)
    {
        /* Yes, leave nothing of the token behind */
        memset(outStr, 0, outSize);
    }
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if every character of str[0..len) is one of [a-zA-Z0-9:_-].                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvIsThingName(const char *str, size_t len)
{
    size_t i;
    char c;

    SSF_REQUIRE(str != NULL);

    for (i = 0; i < len; i++)
    {
        c = str[i];
        if (((c < 'a') || (c > 'z')) && ((c < 'A') || (c > 'Z')) && ((c < '0') || (c > '9')) &&
            (c != ':') && (c != '_') && (c != '-')) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the RegisterThing accepted fields are taken from rxBuf, else false.           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvRegAcceptedFields(const char *rxBuf, char *thingNameOut,
                                         size_t thingNameSize, char *cfgOutOpt, size_t cfgSize,
                                         size_t *cfgLenOutOpt)
{
    SSFGPath_t path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
    SSFJsonType_t jt;
    size_t index;
    size_t start;
    size_t end;
    size_t len;

    SSF_REQUIRE(rxBuf != NULL);
    SSF_REQUIRE(thingNameOut != NULL);

    /* thingName: 1..THING_NAME_SIZE - 1 raw characters of [a-zA-Z0-9:_-], so no escapes */
    if (_SSFAWSProvStrSpan(rxBuf, "thingName", &start, &len) == false) return false;
    if ((len == 0u) || (len >= SSF_AWSPROV_CONFIG_THING_NAME_SIZE) || (len >= thingNameSize))
    {
        return false;
    }
    if (_SSFAWSProvIsThingName(&rxBuf[start], len) == false) return false;
    memcpy(thingNameOut, &rxBuf[start], len);
    thingNameOut[len] = 0;

    /* deviceConfiguration: an object, or "{}" when absent */
    _SSFAWSProvPath(path, sizeof(path), "deviceConfiguration");
    if (SSFJsonMessage(rxBuf, &index, &start, &end, path, 0, &jt) == false) return false;
    /* Is deviceConfiguration present? */
    if (jt != SSF_JSON_TYPE_ERROR)
    {
        /* Yes, it must be an object */
        if (jt != SSF_JSON_TYPE_OBJECT) return false;
        len = (end - start) + 1u;
    }
    else
    {
        /* No, an empty object */
        rxBuf = SSF_AWSPROV_EMPTY_CFG;
        start = 0;
        len = sizeof(SSF_AWSPROV_EMPTY_CFG) - 1u;
    }
    if (cfgOutOpt == NULL) return true;
    if (len >= cfgSize) return false;
    memcpy(cfgOutOpt, &rxBuf[start], len);
    cfgOutOpt[len] = 0;
    if (cfgLenOutOpt != NULL) *cfgLenOutOpt = len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a RegisterThing accepted response gives thingName and the configuration.      */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvParseRegisterAccepted(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                                     size_t rxSize, char *thingNameOut, size_t thingNameSize,
                                     char *cfgOutOpt, size_t cfgSize, size_t *cfgLenOutOpt)
{
    bool ok;

    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE(rxBuf != NULL);
    SSF_REQUIRE(rxSize > 0u);
    SSF_REQUIRE(thingNameOut != NULL);
    SSF_REQUIRE(thingNameSize >= 2u);
    SSF_REQUIRE((cfgOutOpt == NULL) || (cfgSize > 0u));
    SSF_REQUIRE((cfgOutOpt != NULL) || (cfgLenOutOpt == NULL));
    SSF_REQUIRE((cfgLenOutOpt == NULL) ||
                _SSFAWSProvIsDisjoint(cfgLenOutOpt, sizeof(*cfgLenOutOpt), rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(payload, payloadLen, rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(thingNameOut, thingNameSize, rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(thingNameOut, thingNameSize, payload, payloadLen));
    SSF_REQUIRE((cfgOutOpt == NULL) || _SSFAWSProvIsDisjoint(cfgOutOpt, cfgSize, rxBuf, rxSize));
    SSF_REQUIRE((cfgOutOpt == NULL) ||
                _SSFAWSProvIsDisjoint(cfgOutOpt, cfgSize, payload, payloadLen));
    SSF_REQUIRE((cfgOutOpt == NULL) ||
                _SSFAWSProvIsDisjoint(cfgOutOpt, cfgSize, thingNameOut, thingNameSize));

    if (cfgLenOutOpt != NULL) *cfgLenOutOpt = 0;
    ok = (_SSFAWSProvRxCopy(payload, payloadLen, rxBuf, rxSize) &&
          _SSFAWSProvRegAcceptedFields(rxBuf, thingNameOut, thingNameSize, cfgOutOpt, cfgSize,
                                       cfgLenOutOpt));
    memset(rxBuf, 0, rxSize);
    /* Did any step fail? */
    if (ok == false)
    {
        /* Yes, every output zeroed */
        memset(thingNameOut, 0, thingNameSize);
        if (cfgOutOpt != NULL) memset(cfgOutOpt, 0, cfgSize);
        if (cfgLenOutOpt != NULL) *cfgLenOutOpt = 0;
    }
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Replaces every byte of str[0..len) outside 0x20..0x7E with a question mark.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvSanitize(char *str, size_t len)
{
    size_t i;

    SSF_REQUIRE(str != NULL);

    for (i = 0; i < len; i++)
    {
        if (((uint8_t)str[i] < 0x20u) || ((uint8_t)str[i] > 0x7Eu)) str[i] = '?';
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the rejected fields are taken from rxBuf, else false.                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvRejectedFields(const char *rxBuf, uint16_t *statusCodeOut,
                                      char *errorCodeOut, size_t errorCodeSize,
                                      char *errorMessageOut, size_t errorMessageSize)
{
    SSFGPath_t path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
    SSFJsonType_t jt;
    size_t index;
    size_t start;
    size_t end;
    size_t len;
    const char *d;

    SSF_REQUIRE(rxBuf != NULL);
    SSF_REQUIRE(statusCodeOut != NULL);
    SSF_REQUIRE(errorCodeOut != NULL);
    SSF_REQUIRE(errorCodeSize > 0u);
    SSF_REQUIRE(errorMessageOut != NULL);
    SSF_REQUIRE(errorMessageSize > 0u);

    /* statusCode: exactly three digits, 100..599, no sign, fraction or exponent */
    _SSFAWSProvPath(path, sizeof(path), "statusCode");
    if (SSFJsonMessage(rxBuf, &index, &start, &end, path, 0, &jt) == false) return false;
    if ((jt != SSF_JSON_TYPE_NUMBER) || (((end - start) + 1u) != SSF_AWSPROV_STATUS_LEN))
    {
        return false;
    }
    d = &rxBuf[start];
    if ((d[0] < '1') || (d[0] > '5') || (d[1] < '0') || (d[1] > '9') || (d[2] < '0') ||
        (d[2] > '9')) return false;

    /* errorCode: a string that must fit */
    _SSFAWSProvPath(path, sizeof(path), "errorCode");
    if (SSFJsonGetString(rxBuf, path, errorCodeOut, errorCodeSize, &len) == false) return false;
    _SSFAWSProvSanitize(errorCodeOut, len);

    /* errorMessage: optional, as much as fits; a cut escape leaves zeros, sanitized below */
    memset(errorMessageOut, 0, errorMessageSize);
    _SSFAWSProvPath(path, sizeof(path), "errorMessage");
    len = 0;
    (void)SSFJsonGetString(rxBuf, path, errorMessageOut, errorMessageSize, &len);
    SSF_ASSERT(len < errorMessageSize);
    errorMessageOut[len] = 0;
    _SSFAWSProvSanitize(errorMessageOut, len);
    *statusCodeOut = (uint16_t)((((uint16_t)(d[0] - '0')) * 100u) +
                                (((uint16_t)(d[1] - '0')) * 10u) + ((uint16_t)(d[2] - '0')));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a rejected response is parsed: statusCode, errorCode, errorMessage.           */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvParseRejected(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                             size_t rxSize, uint16_t *statusCodeOut, char *errorCodeOut,
                             size_t errorCodeSize, char *errorMessageOut,
                             size_t errorMessageSize)
{
    bool ok;

    SSF_REQUIRE(payload != NULL);
    SSF_REQUIRE(rxBuf != NULL);
    SSF_REQUIRE(rxSize > 0u);
    SSF_REQUIRE(statusCodeOut != NULL);
    SSF_REQUIRE(errorCodeOut != NULL);
    SSF_REQUIRE(errorCodeSize > 0u);
    SSF_REQUIRE(errorMessageOut != NULL);
    SSF_REQUIRE(errorMessageSize > 0u);
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(payload, payloadLen, rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(errorCodeOut, errorCodeSize, rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(errorMessageOut, errorMessageSize, rxBuf, rxSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(errorCodeOut, errorCodeSize, errorMessageOut,
                                      errorMessageSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(payload, payloadLen, errorCodeOut, errorCodeSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(payload, payloadLen, errorMessageOut, errorMessageSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(payload, payloadLen, statusCodeOut,
                                      sizeof(*statusCodeOut)));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(statusCodeOut, sizeof(*statusCodeOut), rxBuf, rxSize));

    *statusCodeOut = 0;
    errorCodeOut[0] = 0;
    errorMessageOut[0] = 0;
    ok = (_SSFAWSProvRxCopy(payload, payloadLen, rxBuf, rxSize) &&
          _SSFAWSProvRejectedFields(rxBuf, statusCodeOut, errorCodeOut, errorCodeSize,
                                    errorMessageOut, errorMessageSize));
    memset(rxBuf, 0, rxSize);
    /* Did any step fail? */
    if (ok == false)
    {
        /* Yes, all outputs empty */
        memset(errorCodeOut, 0, errorCodeSize);
        memset(errorMessageOut, 0, errorMessageSize);
    }
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a rejected statusCode may clear on retry (429, 500..599), else false.         */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvIsRetryable(uint16_t statusCode)
{
    return ((statusCode == 429u) || ((statusCode >= 500u) && (statusCode <= 599u)));
}

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
/* --------------------------------------------------------------------------------------------- */
/* CreateCertificateFromCsr request: defines and data                                            */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AWSPROV_CSR_LABEL          "CERTIFICATE REQUEST"
#define SSF_AWSPROV_CSR_LABEL_LEN      (sizeof(SSF_AWSPROV_CSR_LABEL) - 1u)
#define SSF_AWSPROV_CSR_KEY            "certificateSigningRequest"
#define SSF_AWSPROV_CSR_JSON_OVERHEAD  (sizeof("{\"" SSF_AWSPROV_CSR_KEY "\":\"\"}"))
#define SSF_AWSPROV_PEM_FIXED_LINES    (2u)
#define SSF_AWSPROV_SIG_MAX_LEN(bytes) (8u + (2u * (size_t)(bytes)))

#if (SSF_X509_CONFIG_MAX_CERT_SIZE * 3u) >= SIZE_MAX
#error SSF_X509_CONFIG_MAX_CERT_SIZE is too large for this size_t to hold the CSR request sizes.
#endif

#define SSF_AWSPROV_MEASURE_SIZE \
    ((SSF_ECDSA_MAX_SIG_SIZE > SSF_ECDSA_MAX_PUB_KEY_SIZE) ? SSF_ECDSA_MAX_SIG_SIZE : \
     SSF_ECDSA_MAX_PUB_KEY_SIZE)

/* Stand-in public key and signature for measuring; only their lengths matter */
static const uint8_t _ssfAWSProvMeasure[SSF_AWSPROV_MEASURE_SIZE] = { 0 };
#if SSF_EC_CONFIG_ENABLE_P256 == 1
static const uint8_t _ssfAWSProvOidP256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t _ssfAWSProvOidSHA256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
static const uint8_t _ssfAWSProvOidP384[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t _ssfAWSProvOidSHA384[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

/* --------------------------------------------------------------------------------------------- */
/* Fills p with the CSR parameters of a built curve for pub.                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAWSProvCsrParams(SSFECCurve_t curve, const SSFX509GenName_t *subjectOpt,
                                 const uint8_t *pub, size_t pubLen, SSFX509CSRParams_t *p)
{
    SSF_REQUIRE(pub != NULL);
    SSF_REQUIRE(p != NULL);

    memset(p, 0, sizeof(*p));
    if (subjectOpt != NULL) p->subject = *subjectOpt;
    p->pubKeyAlgOidRaw = _ssfAWSProvOidEC;
    p->pubKeyAlgOidRawLen = (uint32_t)sizeof(_ssfAWSProvOidEC);
    p->pubKey = pub;
    p->pubKeyLen = (uint32_t)pubLen;
    switch (curve)
    {
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    case SSF_EC_CURVE_P256:
        p->ecCurveOidRaw = _ssfAWSProvOidP256;
        p->ecCurveOidRawLen = (uint32_t)sizeof(_ssfAWSProvOidP256);
        p->sigAlgOidRaw = _ssfAWSProvOidSHA256;
        p->sigAlgOidRawLen = (uint32_t)sizeof(_ssfAWSProvOidSHA256);
        break;
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    case SSF_EC_CURVE_P384:
        p->ecCurveOidRaw = _ssfAWSProvOidP384;
        p->ecCurveOidRawLen = (uint32_t)sizeof(_ssfAWSProvOidP384);
        p->sigAlgOidRaw = _ssfAWSProvOidSHA384;
        p->sigAlgOidRawLen = (uint32_t)sizeof(_ssfAWSProvOidSHA384);
        break;
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
    default: SSF_ERROR(); break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if no subject string starts inside [buf, buf + bufSize).                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvSubjectOutside(const SSFX509GenName_t *subjectOpt, const void *buf,
                                      size_t bufSize)
{
    const char *f[6];
    size_t i;

    if (subjectOpt == NULL) return true;
    f[0] = subjectOpt->cn;
    f[1] = subjectOpt->o;
    f[2] = subjectOpt->ou;
    f[3] = subjectOpt->c;
    f[4] = subjectOpt->st;
    f[5] = subjectOpt->l;
    for (i = 0; i < (sizeof(f) / sizeof(f[0])); i++)
    {
        if ((f[i] != NULL) && (_SSFAWSProvIsDisjoint(f[i], 1u, buf, bufSize) == false))
        {
            return false;
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the scratch size (DER then PEM with NUL) needed for a CSR of derLen bytes.            */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFAWSProvCsrScratchSize(size_t derLen)
{
    return (derLen + SSF_PEM_ENCODE_SIZE(SSF_AWSPROV_CSR_LABEL_LEN, derLen));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the JSON size with NUL for a CSR of derLen bytes; each PEM newline adds one byte.     */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFAWSProvCsrOutSize(size_t derLen)
{
    return (SSF_AWSPROV_CSR_JSON_OVERHEAD +
            (SSF_PEM_ENCODE_SIZE(SSF_AWSPROV_CSR_LABEL_LEN, derLen) - 1u) +
            SSF_AWSPROV_PEM_FIXED_LINES + ((derLen + 47u) / 48u));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the request object member fits in js, else false.                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvCsrJsonFn(char *js, size_t jsSize, size_t start, size_t *end, void *in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    if (SSFJsonPrintLabel(js, jsSize, start, &start, SSF_AWSPROV_CSR_KEY, NULL) == false)
    {
        return false;
    }
    return SSFJsonPrintString(js, jsSize, start, end, (const char *)in, NULL);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with upper bounds for the scratch and out sizes of a CSR request, else false.    */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvCsrRequestSizes(SSFECCurve_t curve, const SSFX509GenName_t *subjectOpt,
                               size_t *scratchSizeOut, size_t *outSizeOut)
{
    const SSFECCurveParams_t *c;
    SSFX509CSRParams_t p;
    uint32_t derLen;

    SSF_REQUIRE(scratchSizeOut != NULL);
    SSF_REQUIRE(outSizeOut != NULL);

    *scratchSizeOut = 0;
    *outSizeOut = 0;
    c = SSFECGetCurveParams(curve);
    if (c == NULL) return false;
    SSF_ASSERT(SSF_AWSPROV_SIG_MAX_LEN(c->bytes) <= sizeof(_ssfAWSProvMeasure));
    SSF_ASSERT((1u + (2u * (size_t)c->bytes)) <= sizeof(_ssfAWSProvMeasure));
    _SSFAWSProvCsrParams(curve, subjectOpt, _ssfAWSProvMeasure, (1u + (2u * (size_t)c->bytes)),
                         &p);
    if (SSFX509EncodeCSR(NULL, 0, &p, _ssfAWSProvMeasure,
                         (uint32_t)SSF_AWSPROV_SIG_MAX_LEN(c->bytes),
                         &derLen) == false) return false;
    *scratchSizeOut = _SSFAWSProvCsrScratchSize(derLen);
    *outSizeOut = _SSFAWSProvCsrOutSize(derLen);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the CreateCertificateFromCsr request JSON is built in outStr, else false.     */
/* --------------------------------------------------------------------------------------------- */
bool SSFAWSProvBuildCsrRequest(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                               const SSFX509GenName_t *subjectOpt, uint8_t *scratch,
                               size_t scratchSize, char *outStr, size_t outSize, size_t *outLen)
{
    uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    uint8_t hash[SSF_SHA2_384_BYTE_SIZE];
    const SSFECCurveParams_t *c;
    SSFX509CSRParams_t p;
    uint32_t scratch32;
    uint32_t criLen;
    uint32_t derLen;
    size_t pubLen;
    size_t sigLen;
    size_t hashLen;
    size_t pemLen;
    size_t end;
    bool ok = false;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(scratch != NULL);
    SSF_REQUIRE(outStr != NULL);
    SSF_REQUIRE(outSize > 0u);
    SSF_REQUIRE(outLen != NULL);
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(outStr, outSize, scratch, scratchSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(privKey, privKeyLen, scratch, scratchSize));
    SSF_REQUIRE(_SSFAWSProvIsDisjoint(privKey, privKeyLen, outStr, outSize));
    SSF_REQUIRE(_SSFAWSProvSubjectOutside(subjectOpt, scratch, scratchSize));
    SSF_REQUIRE(_SSFAWSProvSubjectOutside(subjectOpt, outStr, outSize));

    *outLen = 0;
    outStr[0] = 0;
#if SIZE_MAX > UINT32_MAX
    scratch32 = (scratchSize > UINT32_MAX) ? UINT32_MAX : (uint32_t)scratchSize;
#else
    scratch32 = (uint32_t)scratchSize;
#endif

    c = SSFECGetCurveParams(curve);
    if (c == NULL) goto done;
    if (privKeyLen != c->bytes) goto done;
    if (SSFECDSAPubKeyFromPrivKey(curve, privKey, privKeyLen, pub, sizeof(pub), &pubLen) == false)
    {
        goto done;
    }
    _SSFAWSProvCsrParams(curve, subjectOpt, pub, pubLen, &p);

    /* Sign the CertificationRequestInfo with the curve's hash */
    if (SSFX509EncodeCSRInfo(scratch, scratch32, &p, &criLen) == false) goto done;
    /* Is the curve P-384? */
    if (curve == SSF_EC_CURVE_P384)
    {
        /* Yes, ecdsa-with-SHA384 */
        hashLen = SSF_SHA2_384_BYTE_SIZE;
        SSFSHA384(scratch, criLen, hash, (uint32_t)hashLen);
    }
    else
    {
        /* No, ecdsa-with-SHA256 */
        hashLen = SSF_SHA2_256_BYTE_SIZE;
        SSFSHA256(scratch, criLen, hash, (uint32_t)hashLen);
    }
    if (SSFECDSASign(curve, privKey, privKeyLen, hash, hashLen, sig, sizeof(sig), &sigLen) ==
        false) goto done;

    /* DER at the start of scratch, its PEM right after it, then the JSON in outStr */
    if (SSFX509EncodeCSR(scratch, scratch32, &p, sig, (uint32_t)sigLen, &derLen) == false)
    {
        goto done;
    }
    if (SSFPEMEncode(SSF_AWSPROV_CSR_LABEL, scratch, derLen, (char *)&scratch[derLen],
                     (scratchSize - derLen), &pemLen) == false) goto done;
    if (SSFJsonPrintObject(outStr, outSize, 0, &end, _SSFAWSProvCsrJsonFn,
                           (void *)&scratch[derLen], NULL) == false) goto done;
    *outLen = end;
    ok = true;

done:
    /* Did any step fail? */
    if (ok == false)
    {
        /* Yes, leave an empty string */
        outStr[0] = 0;
    }
    return ok;
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */
