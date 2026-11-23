/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcms.h                                                                                      */
/* Provides RFC 5652 CMS SignedData parsing and signature verification interface.                */
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
/* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_CMS_H_INCLUDE
#define SSF_CMS_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfx509.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
/* Digest algorithms a signer may use (RFC 5754) */
typedef enum SSFCMSDigestAlg
{
    SSF_CMS_DIGEST_MIN = -1,
    SSF_CMS_DIGEST_SHA256,
    SSF_CMS_DIGEST_SHA384,
    SSF_CMS_DIGEST_SHA512,
    SSF_CMS_DIGEST_MAX
} SSFCMSDigestAlg_t;

/* One embedded certificate as a DER span */
typedef struct SSFCMSCert
{
    const uint8_t *der;
    uint32_t derLen;
} SSFCMSCert_t;

/* One SignerInfo; every pointer is a view into the caller's CMS DER */
typedef struct SSFCMSSignerInfo
{
    uint8_t version;                   /* 1 = issuerAndSerialNumber, 3 = subjectKeyIdentifier */
    const uint8_t *sidIssuerRaw;       /* v1: issuer Name DER */
    uint32_t sidIssuerRawLen;
    const uint8_t *sidSerial;          /* v1: serial content */
    uint32_t sidSerialLen;
    const uint8_t *sidSkid;            /* v3: key identifier */
    uint32_t sidSkidLen;
    const uint8_t *digestAlgOidRaw;
    uint32_t digestAlgOidRawLen;
    const uint8_t *signedAttrs;        /* whole [0] TLV, NULL if absent */
    uint32_t signedAttrsLen;
    const uint8_t *contentTypeOidRaw;
    uint32_t contentTypeOidRawLen;
    const uint8_t *messageDigest;
    uint32_t messageDigestLen;
    bool hasSigningTime;
    uint64_t signingTime;              /* Unix seconds */
    bool hasAlgProtection;             /* RFC 6211 CMSAlgorithmProtection attribute */
    const uint8_t *apDigestAlgOidRaw;
    uint32_t apDigestAlgOidRawLen;
    const uint8_t *apSigAlgOidRaw;
    uint32_t apSigAlgOidRawLen;
    const uint8_t *apSigAlgParams;
    uint32_t apSigAlgParamsLen;
    const uint8_t *sigAlgOidRaw;
    uint32_t sigAlgOidRawLen;
    const uint8_t *sigAlgParams;
    uint32_t sigAlgParamsLen;
    const uint8_t *signature;
    uint32_t signatureLen;
} SSFCMSSignerInfo_t;

/* Parsed SignedData; every pointer is a view into the caller's CMS DER */
typedef struct SSFCMSSignedData
{
    uint8_t version;
    const uint8_t *digestAlgOidRaw[SSF_CMS_CONFIG_MAX_DIGEST_ALGS];
    uint32_t digestAlgOidRawLen[SSF_CMS_CONFIG_MAX_DIGEST_ALGS];
    uint8_t digestAlgsLen;
    const uint8_t *eContentTypeOidRaw;
    uint32_t eContentTypeOidRawLen;
    bool hasEContent;
    const uint8_t *eContent;
    uint32_t eContentLen;
    SSFCMSCert_t certs[SSF_CMS_CONFIG_MAX_CERTS];
    uint8_t certsLen;
    SSFCMSSignerInfo_t signers[SSF_CMS_CONFIG_MAX_SIGNERS];
    uint8_t signersLen;
} SSFCMSSignedData_t;

/* Which signer verified and what it asserted */
typedef struct SSFCMSVerifyResult
{
    uint8_t signerIndex;
    SSFX509Name_t signerSubject;       /* views into the signer certificate DER */
    bool hasSigningTime;
    uint64_t signingTime;
} SSFCMSVerifyResult_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFCMSParse(const uint8_t *der, uint32_t derLen, SSFCMSSignedData_t *sdOut);
bool SSFCMSGetDigestAlg(const SSFCMSSignedData_t *sd, uint8_t signerIndex,
                        SSFCMSDigestAlg_t *algOut);
bool SSFCMSVerifyDigest(const SSFCMSSignedData_t *sd, const uint8_t *digest, uint32_t digestLen,
                        SSFCMSDigestAlg_t digestAlg, const uint8_t **trustDer,
                        const uint32_t *trustDerLen, uint8_t trustCount, uint64_t nowUnixSec,
                        SSFCMSVerifyResult_t *resultOut);
bool SSFCMSVerifyAttached(const SSFCMSSignedData_t *sd, const uint8_t **trustDer,
                          const uint32_t *trustDerLen, uint8_t trustCount, uint64_t nowUnixSec,
                          SSFCMSVerifyResult_t *resultOut);
#if SSF_TLS_CONFIG_ENABLE_TRACE == 1
void SSFCMSSetTraceCtx(void (*fnOpt)(int, int, const char *, void *), void *userCtxOpt);
#else
/* Tracing compiled out: calls still compile but do nothing */
#define SSFCMSSetTraceCtx(fnOpt, userCtxOpt) do { (void)(fnOpt); (void)(userCtxOpt); } while (0)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_CMS_UNIT_TEST == 1
void SSFCMSUnitTest(void);
#endif /* SSF_CONFIG_CMS_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_CMS_H_INCLUDE */
