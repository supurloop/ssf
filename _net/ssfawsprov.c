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
static const uint8_t _ssfAWSProvOidEC[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
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
/* Returns true if [a, a + aLen) and [b, b + bLen) do not overlap.                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFAWSProvIsDisjoint(const void *a, size_t aLen, const void *b, size_t bLen)
{
    return ((((uintptr_t)a + aLen) <= (uintptr_t)b) || ((uintptr_t)a >= ((uintptr_t)b + bLen)));
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
