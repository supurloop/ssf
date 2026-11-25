/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcms.c                                                                                      */
/* Provides RFC 5652 CMS SignedData parsing and signature verification.                          */
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
#include "ssfassert.h"
#include "ssfcms.h"
#include "ssfasn1.h"
#include "ssfx509.h"
#include "ssfsha2.h"
#include "ssfcrypt.h"
#include "ssftls.h"

#if SSF_X509_CONFIG_MAX_CHAIN_DEPTH < (SSF_CMS_CONFIG_MAX_CERTS + 1u)
#error SSF_X509_CONFIG_MAX_CHAIN_DEPTH must be >= SSF_CMS_CONFIG_MAX_CERTS + 1.
#endif

#if SSF_TLS_CONFIG_ENABLE_TRACE == 1
/* Module-scope trace context for verification diagnostics */
static SSFTLSTraceCtx_t _ssfcmsTraceCtx;
#define _SSF_CMS_TRACE_CTX (&_ssfcmsTraceCtx)

/* Caller trace callback that _SSFCMSTraceAdapter() forwards each message to */
static void (*_ssfcmsTraceFn)(int, int, const char *, void *);
#else
/* Tracing compiled out: the trace macros discard this NULL context */
#define _SSF_CMS_TRACE_CTX ((SSFTLSTraceCtx_t *)NULL)
#endif

/* --------------------------------------------------------------------------------------------- */
/* OID constants (raw DER content bytes)                                                         */
/* --------------------------------------------------------------------------------------------- */
/* id-signedData 1.2.840.113549.1.7.2 */
static const uint8_t _oidSignedData[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x07u, 0x02u
};
/* id-data 1.2.840.113549.1.7.1 */
static const uint8_t _oidData[] = { 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x07u, 0x01u };
/* id-contentType 1.2.840.113549.1.9.3 */
static const uint8_t _oidAttrContentType[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x03u
};
/* id-messageDigest 1.2.840.113549.1.9.4 */
static const uint8_t _oidAttrMessageDigest[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x04u
};
/* id-signingTime 1.2.840.113549.1.9.5 */
static const uint8_t _oidAttrSigningTime[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x05u
};
/* id-aa-CMSAlgorithmProtection 1.2.840.113549.1.9.52 (RFC 6211) */
static const uint8_t _oidAttrAlgProtection[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x34u
};
/* id-sha256 / id-sha384 / id-sha512 (RFC 5754) */
static const uint8_t _oidSHA256[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u
};
static const uint8_t _oidSHA384[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u
};
static const uint8_t _oidSHA512[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u
};

/* DER NULL, the one parameter encoding RFC 5754 tolerates on a digest AlgorithmIdentifier */
static const uint8_t _derNull[] = { 0x05u, 0x00u };

/* Context tags used by SignedData and SignerInfo */
#define _TAG_CTX0_CONSTRUCTED   ((uint16_t)0xA0u)
#define _TAG_CTX1_CONSTRUCTED   ((uint16_t)0xA1u)
#define _TAG_CTX0_PRIMITIVE     ((uint16_t)0x80u)

#if SSF_TLS_CONFIG_ENABLE_TRACE == 1
/* --------------------------------------------------------------------------------------------- */
/* Delivers a trace message to the installed int-signature callback.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFCMSTraceAdapter(SSFTLSTraceLevel_t level, SSFTLSTraceCategory_t category,
                                const char *msgStr, void *userCtxOpt)
{
    SSF_REQUIRE(level <= SSF_TLS_TRACE_DEBUG);
    SSF_REQUIRE(category <= SSF_TLS_TRACE_ALERT);
    SSF_REQUIRE(msgStr != NULL);
    SSF_REQUIRE(_ssfcmsTraceFn != NULL);

    _ssfcmsTraceFn((int)level, (int)category, msgStr, userCtxOpt);
}

/* --------------------------------------------------------------------------------------------- */
/* Installs the module-wide verification trace callback; a NULL fnOpt disables tracing.          */
/* --------------------------------------------------------------------------------------------- */
void SSFCMSSetTraceCtx(void (*fnOpt)(int, int, const char *, void *), void *userCtxOpt)
{
    _ssfcmsTraceFn = fnOpt;
    _ssfcmsTraceCtx.fn = (fnOpt != NULL) ? _SSFCMSTraceAdapter : NULL;
    _ssfcmsTraceCtx.userCtx = userCtxOpt;
}
#endif /* SSF_TLS_CONFIG_ENABLE_TRACE */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if two byte spans are identical, else false.                                     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSSpanEquals(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen)
{
    SSF_REQUIRE((a != NULL) || (aLen == 0u));
    SSF_REQUIRE((b != NULL) || (bLen == 0u));

    if (aLen != bLen) return false;
    if (aLen == 0u) return true;
    return (memcmp(a, b, aLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if oid names SHA-256, SHA-384 or SHA-512 with *algOut set, else false.           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSDigestAlgFromOID(const uint8_t *oid, uint32_t oidLen, SSFCMSDigestAlg_t *algOut)
{
    SSF_REQUIRE((oid != NULL) || (oidLen == 0u));
    SSF_REQUIRE(algOut != NULL);

    if (_SSFCMSSpanEquals(oid, oidLen, _oidSHA256, sizeof(_oidSHA256)))
    {
        *algOut = SSF_CMS_DIGEST_SHA256;
    }
    else if (_SSFCMSSpanEquals(oid, oidLen, _oidSHA384, sizeof(_oidSHA384)))
    {
        *algOut = SSF_CMS_DIGEST_SHA384;
    }
    else if (_SSFCMSSpanEquals(oid, oidLen, _oidSHA512, sizeof(_oidSHA512)))
    {
        *algOut = SSF_CMS_DIGEST_SHA512;
    }
    else return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the output size in bytes of a digest algorithm.                                       */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFCMSDigestLen(SSFCMSDigestAlg_t alg)
{
    SSF_REQUIRE((alg > SSF_CMS_DIGEST_MIN) && (alg < SSF_CMS_DIGEST_MAX));

    if (alg == SSF_CMS_DIGEST_SHA384) return SSF_SHA2_384_BYTE_SIZE;
    if (alg == SSF_CMS_DIGEST_SHA512) return SSF_SHA2_512_BYTE_SIZE;
    return SSF_SHA2_256_BYTE_SIZE;
}

/* --------------------------------------------------------------------------------------------- */
/* Digests data with alg into out of at least _SSFCMSDigestLen(alg) bytes.                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFCMSDigest(SSFCMSDigestAlg_t alg, const uint8_t *data, uint32_t dataLen,
                          uint8_t *out, uint32_t outSize)
{
    SSF_REQUIRE((alg > SSF_CMS_DIGEST_MIN) && (alg < SSF_CMS_DIGEST_MAX));
    SSF_REQUIRE((data != NULL) || (dataLen == 0u));
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outSize >= _SSFCMSDigestLen(alg));

    if (alg == SSF_CMS_DIGEST_SHA384) SSFSHA384(data, dataLen, out, outSize);
    else if (alg == SSF_CMS_DIGEST_SHA512) SSFSHA512(data, dataLen, out, outSize);
    else SSFSHA256(data, dataLen, out, outSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if AlgorithmIdentifier parameters are absent or a DER NULL, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSParamsAbsentOrNull(const uint8_t *paramsOpt, uint32_t paramsLen)
{
    SSF_REQUIRE((paramsOpt != NULL) || (paramsLen == 0u));

    if (paramsLen == 0u) return true;
    return _SSFCMSSpanEquals(paramsOpt, paramsLen, _derNull, sizeof(_derNull));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if two parameter encodings agree, treating absent and DER NULL as equal.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSParamsEquivalent(const uint8_t *aOpt, uint32_t aLen, const uint8_t *bOpt,
                                    uint32_t bLen)
{
    SSF_REQUIRE((aOpt != NULL) || (aLen == 0u));
    SSF_REQUIRE((bOpt != NULL) || (bLen == 0u));

    /* Do both sides carry no parameters, in either spelling? */
    if ((_SSFCMSParamsAbsentOrNull(aOpt, aLen)) && (_SSFCMSParamsAbsentOrNull(bOpt, bLen)))
    {
        /* Yes, equivalent */
        return true;
    }

    /* No, they must be byte-identical */
    return _SSFCMSSpanEquals(aOpt, aLen, bOpt, bLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if an AlgorithmIdentifier SEQUENCE { OID, params } is read at *pos, else false.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSParseAlgId(SSFASN1Cursor_t *pos, const uint8_t **oidRawOut,
                              uint32_t *oidRawLenOut, const uint8_t **paramsOut,
                              uint32_t *paramsLenOut)
{
    SSFASN1Cursor_t inner;

    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE(oidRawOut != NULL);
    SSF_REQUIRE(oidRawLenOut != NULL);
    SSF_REQUIRE(paramsOut != NULL);
    SSF_REQUIRE(paramsLenOut != NULL);

    if (!SSFASN1DecOpenConstructed(pos, SSF_ASN1_TAG_SEQUENCE, &inner, pos)) return false;
    if (!SSFASN1DecGetOIDRaw(&inner, oidRawOut, oidRawLenOut, &inner)) return false;

    /* Whatever follows the OID is the parameters, kept raw */
    *paramsOut = (inner.bufLen > 0u) ? inner.buf : NULL;
    *paramsLenOut = inner.bufLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the CMSAlgorithmProtection value at *pos is read into si, else false.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSParseAlgProtection(SSFASN1Cursor_t *pos, SSFCMSSignerInfo_t *si)
{
    SSFASN1Cursor_t inner;
    SSFASN1Cursor_t sigInner;
    uint16_t tag;
    const uint8_t *digestParams;
    uint32_t digestParamsLen;

    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE(si != NULL);

    /* CMSAlgorithmProtection ::= SEQUENCE { digestAlgorithm, signatureAlgorithm [1] IMPLICIT } */
    if (!SSFASN1DecOpenConstructed(pos, SSF_ASN1_TAG_SEQUENCE, &inner, pos)) return false;
    if (!_SSFCMSParseAlgId(&inner, &si->apDigestAlgOidRaw, &si->apDigestAlgOidRawLen,
                           &digestParams, &digestParamsLen)) return false;

    /* Are the digest params other than absent or NULL, as the SignerInfo's must be (RFC 6211)? */
    if (!_SSFCMSParamsAbsentOrNull(digestParams, digestParamsLen))
    {
        /* Yes, the protected digestAlgorithm cannot match the SignerInfo's */
        return false;
    }

    /* Is signatureAlgorithm absent (RFC 6211 Sec. 2 requires it for a SignerInfo)? */
    if ((!SSFASN1DecPeekTag(&inner, &tag)) || (tag != _TAG_CTX1_CONSTRUCTED))
    {
        /* Yes */
        return false;
    }
    if (!SSFASN1DecOpenConstructed(&inner, _TAG_CTX1_CONSTRUCTED, &sigInner, &inner)) return false;
    if (!SSFASN1DecGetOIDRaw(&sigInner, &si->apSigAlgOidRaw, &si->apSigAlgOidRawLen, &sigInner))
    {
        return false;
    }
    si->apSigAlgParams = (sigInner.bufLen > 0u) ? sigInner.buf : NULL;
    si->apSigAlgParamsLen = sigInner.bufLen;
    si->hasAlgProtection = true;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signed attributes in attrs are read into si, else false.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSParseSignedAttrs(const SSFASN1Cursor_t *attrs, SSFCMSSignerInfo_t *si)
{
    SSFASN1Cursor_t pos;
    SSFASN1Cursor_t attr;
    SSFASN1Cursor_t vals;
    const uint8_t *typeOid;
    uint32_t typeOidLen;

    SSF_REQUIRE(attrs != NULL);
    SSF_REQUIRE(si != NULL);

    pos = *attrs;
    while (!SSFASN1DecIsEmpty(&pos))
    {
        /* Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY } */
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &attr, &pos)) return false;
        if (!SSFASN1DecGetOIDRaw(&attr, &typeOid, &typeOidLen, &attr)) return false;
        if (!SSFASN1DecOpenConstructed(&attr, SSF_ASN1_TAG_SET, &vals, &attr)) return false;

        /* content-type: exactly one OID, at most one instance (RFC 5652 Sec. 11.1) */
        if (_SSFCMSSpanEquals(typeOid, typeOidLen, _oidAttrContentType,
                              sizeof(_oidAttrContentType)))
        {
            if (si->contentTypeOidRaw != NULL) return false;
            if (!SSFASN1DecGetOIDRaw(&vals, &si->contentTypeOidRaw, &si->contentTypeOidRawLen,
                                     &vals)) return false;
            if (!SSFASN1DecIsEmpty(&vals)) return false;
        }
        /* message-digest: exactly one OCTET STRING, at most one instance (Sec. 11.2) */
        else if (_SSFCMSSpanEquals(typeOid, typeOidLen, _oidAttrMessageDigest,
                                   sizeof(_oidAttrMessageDigest)))
        {
            if (si->messageDigest != NULL) return false;
            if (!SSFASN1DecGetOctetString(&vals, &si->messageDigest, &si->messageDigestLen,
                                          &vals)) return false;
            if (!SSFASN1DecIsEmpty(&vals)) return false;
        }
        /* signing-time: exactly one Time, at most one instance (Sec. 11.3) */
        else if (_SSFCMSSpanEquals(typeOid, typeOidLen, _oidAttrSigningTime,
                                   sizeof(_oidAttrSigningTime)))
        {
            if (si->hasSigningTime) return false;
            if (!SSFASN1DecGetTime(&vals, &si->signingTime, &vals)) return false;
            if (!SSFASN1DecIsEmpty(&vals)) return false;
            si->hasSigningTime = true;
        }
        /* CMSAlgorithmProtection: exactly one value, at most one instance (RFC 6211) */
        else if (_SSFCMSSpanEquals(typeOid, typeOidLen, _oidAttrAlgProtection,
                                   sizeof(_oidAttrAlgProtection)))
        {
            if (si->hasAlgProtection) return false;
            if (!_SSFCMSParseAlgProtection(&vals, si)) return false;
            if (!SSFASN1DecIsEmpty(&vals)) return false;
        }
        /* Anything else, such as S/MIME capabilities, is left unread */
    }

    /* Is either mandatory attribute missing (Sec. 5.3)? */
    if ((si->contentTypeOidRaw == NULL) || (si->messageDigest == NULL))
    {
        /* Yes */
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if one SignerInfo is read from *pos into si, else false.                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSParseSignerInfo(SSFASN1Cursor_t *pos, SSFCMSSignerInfo_t *si)
{
    SSFASN1Cursor_t inner;
    SSFASN1Cursor_t ias;
    SSFASN1Cursor_t nameInner;
    SSFASN1Cursor_t attrs;
    const uint8_t *start;
    const uint8_t *digestParams;
    uint32_t digestParamsLen;
    uint64_t version;
    uint16_t tag;

    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE(si != NULL);

    memset(si, 0, sizeof(*si));
    if (!SSFASN1DecOpenConstructed(pos, SSF_ASN1_TAG_SEQUENCE, &inner, pos)) return false;

    if (!SSFASN1DecGetIntU64(&inner, &version, &inner)) return false;

    /* Is the version other than 1 (issuerAndSerialNumber) or 3 (subjectKeyIdentifier, Sec. 5.3)? */
    if ((version != 1u) && (version != 3u))
    {
        /* Yes */
        return false;
    }
    si->version = (uint8_t)version;

    /* SignerIdentifier CHOICE: SEQUENCE for issuerAndSerialNumber, [0] for the key identifier */
    if (!SSFASN1DecPeekTag(&inner, &tag)) return false;
    if (tag == SSF_ASN1_TAG_SEQUENCE)
    {
        if (version != 1u) return false;
        if (!SSFASN1DecOpenConstructed(&inner, SSF_ASN1_TAG_SEQUENCE, &ias, &inner)) return false;
        start = ias.buf;
        if (!SSFASN1DecOpenConstructed(&ias, SSF_ASN1_TAG_SEQUENCE, &nameInner, &ias))
        {
            return false;
        }
        si->sidIssuerRaw = start;
        si->sidIssuerRawLen = (uint32_t)(ias.buf - start);
        if (!SSFASN1DecGetInt(&ias, &si->sidSerial, &si->sidSerialLen, &ias)) return false;
        if (!SSFASN1DecIsEmpty(&ias)) return false;
    }
    else if (tag == _TAG_CTX0_PRIMITIVE)
    {
        if (version != 3u) return false;
        if (!SSFASN1DecGetTLV(&inner, &tag, &si->sidSkid, &si->sidSkidLen, &inner)) return false;
        if (si->sidSkidLen == 0u) return false;
    }
    else return false;

    /* digestAlgorithm with parameters absent or NULL (RFC 5754 Sec. 2) */
    if (!_SSFCMSParseAlgId(&inner, &si->digestAlgOidRaw, &si->digestAlgOidRawLen, &digestParams,
                           &digestParamsLen)) return false;
    if (!_SSFCMSParamsAbsentOrNull(digestParams, digestParamsLen)) return false;

    /* Is signedAttrs [0] IMPLICIT SET OF Attribute present? */
    if ((SSFASN1DecPeekTag(&inner, &tag)) && (tag == _TAG_CTX0_CONSTRUCTED))
    {
        /* Yes, keep the whole TLV so the verifier can re-tag it as a SET */
        start = inner.buf;
        if (!SSFASN1DecOpenConstructed(&inner, _TAG_CTX0_CONSTRUCTED, &attrs, &inner)) return false;
        si->signedAttrs = start;
        si->signedAttrsLen = (uint32_t)(inner.buf - start);
        if (!_SSFCMSParseSignedAttrs(&attrs, si)) return false;
    }

    /* signatureAlgorithm and signature */
    if (!_SSFCMSParseAlgId(&inner, &si->sigAlgOidRaw, &si->sigAlgOidRawLen, &si->sigAlgParams,
                           &si->sigAlgParamsLen)) return false;
    if (!SSFASN1DecGetOctetString(&inner, &si->signature, &si->signatureLen, &inner)) return false;
    if (si->signatureLen == 0u) return false;

    /* Is unsignedAttrs [1] IMPLICIT present? */
    if ((SSFASN1DecPeekTag(&inner, &tag)) && (tag == _TAG_CTX1_CONSTRUCTED))
    {
        /* Yes, the signature does not cover it, so it is skipped unread */
        if (!SSFASN1DecSkip(&inner, &inner)) return false;
    }
    return SSFASN1DecIsEmpty(&inner);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the CertificateSet at certs is read into sd, else false.                      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSParseCertificates(const SSFASN1Cursor_t *certs, SSFCMSSignedData_t *sd)
{
    SSFASN1Cursor_t pos;
    const uint8_t *start;
    const uint8_t *val;
    uint32_t valLen;
    uint16_t tag;

    SSF_REQUIRE(certs != NULL);
    SSF_REQUIRE(sd != NULL);

    pos = *certs;
    while (!SSFASN1DecIsEmpty(&pos))
    {
        if (!SSFASN1DecPeekTag(&pos, &tag)) return false;

        /* CertificateChoices: a SEQUENCE is an X.509 certificate, anything tagged is skipped */
        if (tag != SSF_ASN1_TAG_SEQUENCE)
        {
            if (!SSFASN1DecSkip(&pos, &pos)) return false;
            continue;
        }

        /* Is there no room to retain it (an unretained certificate would be invisible)? */
        if (sd->certsLen >= SSF_CMS_CONFIG_MAX_CERTS)
        {
            /* Yes */
            return false;
        }
        start = pos.buf;
        if (!SSFASN1DecGetTLV(&pos, &tag, &val, &valLen, &pos)) return false;
        sd->certs[sd->certsLen].der = start;
        sd->certs[sd->certsLen].derLen = (uint32_t)(pos.buf - start);
        sd->certsLen++;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if der holds a ContentInfo carrying SignedData parsed into *sdOut, else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFCMSParse(const uint8_t *der, uint32_t derLen, SSFCMSSignedData_t *sdOut)
{
    SSFASN1Cursor_t cursor;
    SSFASN1Cursor_t ci;
    SSFASN1Cursor_t wrap;
    SSFASN1Cursor_t sd;
    SSFASN1Cursor_t set;
    SSFASN1Cursor_t eci;
    SSFASN1Cursor_t econt;
    const uint8_t *oid;
    uint32_t oidLen;
    const uint8_t *params;
    uint32_t paramsLen;
    uint64_t version;
    uint16_t tag;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(sdOut != NULL);

    memset(sdOut, 0, sizeof(*sdOut));

    /* Is the DER over the configured bound? */
    if (derLen > SSF_CMS_CONFIG_MAX_DER_LEN)
    {
        /* Yes */
        return false;
    }
    cursor.buf = der;
    cursor.bufLen = derLen;

    /* ContentInfo ::= SEQUENCE { contentType id-signedData, content [0] EXPLICIT SignedData } */
    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &ci, &cursor)) return false;
    if (!SSFASN1DecIsEmpty(&cursor)) return false;
    if (!SSFASN1DecGetOIDRaw(&ci, &oid, &oidLen, &ci)) return false;
    if (!_SSFCMSSpanEquals(oid, oidLen, _oidSignedData, sizeof(_oidSignedData))) return false;
    if (!SSFASN1DecOpenConstructed(&ci, _TAG_CTX0_CONSTRUCTED, &wrap, &ci)) return false;
    if (!SSFASN1DecIsEmpty(&ci)) return false;
    if (!SSFASN1DecOpenConstructed(&wrap, SSF_ASN1_TAG_SEQUENCE, &sd, &wrap)) return false;
    if (!SSFASN1DecIsEmpty(&wrap)) return false;

    if (!SSFASN1DecGetIntU64(&sd, &version, &sd)) return false;

    /* Is the version other than 1 or 3, the values this profile accepts (Sec. 5.1)? */
    if ((version != 1u) && (version != 3u))
    {
        /* Yes */
        return false;
    }
    sdOut->version = (uint8_t)version;

    /* digestAlgorithms SET OF AlgorithmIdentifier */
    if (!SSFASN1DecOpenConstructed(&sd, SSF_ASN1_TAG_SET, &set, &sd)) return false;
    while (!SSFASN1DecIsEmpty(&set))
    {
        if (sdOut->digestAlgsLen >= SSF_CMS_CONFIG_MAX_DIGEST_ALGS) return false;
        if (!_SSFCMSParseAlgId(&set, &sdOut->digestAlgOidRaw[sdOut->digestAlgsLen],
                               &sdOut->digestAlgOidRawLen[sdOut->digestAlgsLen], &params,
                               &paramsLen)) return false;
        if (!_SSFCMSParamsAbsentOrNull(params, paramsLen)) return false;
        sdOut->digestAlgsLen++;
    }

    /* EncapsulatedContentInfo ::= SEQUENCE { eContentType, eContent [0] EXPLICIT OPTIONAL } */
    if (!SSFASN1DecOpenConstructed(&sd, SSF_ASN1_TAG_SEQUENCE, &eci, &sd)) return false;
    if (!SSFASN1DecGetOIDRaw(&eci, &sdOut->eContentTypeOidRaw, &sdOut->eContentTypeOidRawLen,
                             &eci)) return false;
    if (!SSFASN1DecIsEmpty(&eci))
    {
        if (!SSFASN1DecOpenConstructed(&eci, _TAG_CTX0_CONSTRUCTED, &econt, &eci)) return false;
        if (!SSFASN1DecGetOctetString(&econt, &sdOut->eContent, &sdOut->eContentLen, &econt))
        {
            return false;
        }
        if (!SSFASN1DecIsEmpty(&econt)) return false;
        if (!SSFASN1DecIsEmpty(&eci)) return false;
        sdOut->hasEContent = true;
    }

    /* Is certificates [0] IMPLICIT CertificateSet present? */
    if ((SSFASN1DecPeekTag(&sd, &tag)) && (tag == _TAG_CTX0_CONSTRUCTED))
    {
        /* Yes */
        if (!SSFASN1DecOpenConstructed(&sd, _TAG_CTX0_CONSTRUCTED, &set, &sd)) return false;
        if (!_SSFCMSParseCertificates(&set, sdOut)) return false;
    }

    /* Is crls [1] IMPLICIT RevocationInfoChoices present? */
    if ((SSFASN1DecPeekTag(&sd, &tag)) && (tag == _TAG_CTX1_CONSTRUCTED))
    {
        /* Yes, revocation is not implemented, so it is skipped unread */
        if (!SSFASN1DecSkip(&sd, &sd)) return false;
    }

    /* signerInfos SET OF SignerInfo */
    if (!SSFASN1DecOpenConstructed(&sd, SSF_ASN1_TAG_SET, &set, &sd)) return false;
    while (!SSFASN1DecIsEmpty(&set))
    {
        if (sdOut->signersLen >= SSF_CMS_CONFIG_MAX_SIGNERS) return false;
        if (!_SSFCMSParseSignerInfo(&set, &sdOut->signers[sdOut->signersLen])) return false;
        sdOut->signersLen++;
    }
    return SSFASN1DecIsEmpty(&sd);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if signer signerIndex uses a supported digest algorithm, set in *algOut.         */
/* --------------------------------------------------------------------------------------------- */
bool SSFCMSGetDigestAlg(const SSFCMSSignedData_t *sd, uint8_t signerIndex,
                        SSFCMSDigestAlg_t *algOut)
{
    SSF_REQUIRE(sd != NULL);
    SSF_REQUIRE(signerIndex < sd->signersLen);
    SSF_REQUIRE(algOut != NULL);

    return _SSFCMSDigestAlgFromOID(sd->signers[signerIndex].digestAlgOidRaw,
                                   sd->signers[signerIndex].digestAlgOidRawLen, algOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if cert is the one si identifies by issuer and serial or by SKID, else false.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSCertMatchesSigner(const SSFX509Cert_t *cert, const SSFCMSSignerInfo_t *si)
{
    SSF_REQUIRE(cert != NULL);
    SSF_REQUIRE(si != NULL);

    /* Is the signer identified by issuer and serial? */
    if (si->version == 1u)
    {
        /* Yes, both must match */
        return (_SSFCMSSpanEquals(cert->issuer.raw, cert->issuer.rawLen, si->sidIssuerRaw,
                                  si->sidIssuerRawLen)) &&
               (_SSFCMSSpanEquals(cert->serial, cert->serialLen, si->sidSerial, si->sidSerialLen));
    }

    /* No, by subject key identifier */
    return _SSFCMSSpanEquals(cert->skid, cert->skidLen, si->sidSkid, si->sidSkidLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if si's certificate is found in sd or the anchors, parsed with its DER span.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSFindSignerCert(const SSFCMSSignedData_t *sd, const SSFCMSSignerInfo_t *si,
                                  const uint8_t **trustDer, const uint32_t *trustDerLen,
                                  uint8_t trustCount, SSFX509Cert_t *certOut,
                                  const uint8_t **derOut, uint32_t *derLenOut)
{
    uint8_t i;

    SSF_REQUIRE(sd != NULL);
    SSF_REQUIRE(si != NULL);
    SSF_REQUIRE(trustDer != NULL);
    SSF_REQUIRE(trustDerLen != NULL);
    SSF_REQUIRE(certOut != NULL);
    SSF_REQUIRE(derOut != NULL);
    SSF_REQUIRE(derLenOut != NULL);

    for (i = 0; i < sd->certsLen; i++)
    {
        if (!SSFX509Parse(sd->certs[i].der, sd->certs[i].derLen, certOut)) continue;
        if (_SSFCMSCertMatchesSigner(certOut, si))
        {
            *derOut = sd->certs[i].der;
            *derLenOut = sd->certs[i].derLen;
            return true;
        }
    }
    for (i = 0; i < trustCount; i++)
    {
        SSF_REQUIRE(trustDer[i] != NULL);
        if (!SSFX509Parse(trustDer[i], trustDerLen[i], certOut)) continue;
        if (_SSFCMSCertMatchesSigner(certOut, si))
        {
            *derOut = trustDer[i];
            *derLenOut = trustDerLen[i];
            return true;
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signer certificate is found, with its DER in derOut / derLenOut. The      */
/* parsed certificate lives only in this frame, not across chain verification (OPTIMIZE CMS-01). */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static bool _SSFCMSFindSignerDer(const SSFCMSSignedData_t *sd, const SSFCMSSignerInfo_t *si,
                                 const uint8_t **trustDer, const uint32_t *trustDerLen,
                                 uint8_t trustCount, const uint8_t **derOut, uint32_t *derLenOut)
{
    SSFX509Cert_t cert;

    return _SSFCMSFindSignerCert(sd, si, trustDer, trustDerLen, trustCount, &cert, derOut,
                                 derLenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if signer idx's signature verifies with the key of the chain-verified signer     */
/* certificate signerDer, filling resultOut, else false. Parses signerDer again (fails closed)   */
/* and re-tags the signed attributes; both live only in this frame (OPTIMIZE CMS-01).            */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static bool _SSFCMSVerifySignerSig(const SSFCMSSignedData_t *sd, uint8_t idx,
                                   const uint8_t *signerDer, uint32_t signerDerLen,
                                   SSFCMSVerifyResult_t *resultOut)
{
    const SSFCMSSignerInfo_t *si = &sd->signers[idx];
    SSFX509Cert_t signerCert;
    uint8_t attrs[SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN];
    const uint8_t *covered;
    uint32_t coveredLen;

    /* Does the chain-verified signer certificate fail to parse again? */
    if (!SSFX509Parse(signerDer, signerDerLen, &signerCert))
    {
        /* Yes, fail closed */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: signer[%u] certificate re-parse failed",
                                 idx);
        return false;
    }

    /* Are signed attributes present? */
    if (si->signedAttrs != NULL)
    {
        /* Yes, the signature covers them re-tagged as a SET (length checked by the caller) */
        SSF_ASSERT(si->signedAttrsLen <= sizeof(attrs));
        memcpy(attrs, si->signedAttrs, si->signedAttrsLen);
        attrs[0] = (uint8_t)SSF_ASN1_TAG_SET;
        covered = attrs;
        coveredLen = si->signedAttrsLen;
    }
    else
    {
        /* No, the signature covers the attached content itself (checked by the caller) */
        covered = sd->eContent;
        coveredLen = sd->eContentLen;
    }

    /* Does the signature fail with the signer's key under the declared algorithms? */
    if (!SSFX509VerifySignature(&signerCert, si->sigAlgOidRaw, si->sigAlgOidRawLen,
                                si->sigAlgParams, si->sigAlgParamsLen, si->digestAlgOidRaw,
                                si->digestAlgOidRawLen, covered, coveredLen, si->signature,
                                si->signatureLen))
    {
        /* Yes */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: signer[%u] signature FAILED", idx);
        return false;
    }

    resultOut->signerIndex = idx;
    resultOut->signerSubject = signerCert.subject;
    resultOut->hasSigningTime = si->hasSigningTime;
    resultOut->signingTime = si->signingTime;
    SSF_TLS_TRACE_CERT_DEBUG(_SSF_CMS_TRACE_CTX, "CMS: signer[%u] verified", idx);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if signer idx verifies against the content digest and the trust anchors.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFCMSVerifySigner(const SSFCMSSignedData_t *sd, uint8_t idx, const uint8_t *digestOpt,
                                uint32_t digestLen, SSFCMSDigestAlg_t digestAlg,
                                const uint8_t **trustDer, const uint32_t *trustDerLen,
                                uint8_t trustCount, uint64_t nowUnixSec,
                                SSFCMSVerifyResult_t *resultOut)
{
    const SSFCMSSignerInfo_t *si;
    SSFCMSDigestAlg_t alg;
    uint8_t computed[SSF_SHA2_512_BYTE_SIZE];
    const uint8_t *contentDigest;
    const uint8_t *signerDer;
    uint32_t signerDerLen;
    const uint8_t *chain[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    uint32_t chainLen[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    uint8_t chainN;
    SSFX509VerifyErr_t verifyErr;
    uint32_t hashLen;
    uint8_t i;
    bool listed = false;

    SSF_REQUIRE(sd != NULL);
    SSF_REQUIRE(idx < sd->signersLen);
    SSF_REQUIRE((digestOpt != NULL) || (digestLen == 0u));
    SSF_REQUIRE(trustDer != NULL);
    SSF_REQUIRE(trustDerLen != NULL);
    SSF_REQUIRE(resultOut != NULL);

    si = &sd->signers[idx];

    /* Is the signer's digest algorithm unsupported? */
    if (!_SSFCMSDigestAlgFromOID(si->digestAlgOidRaw, si->digestAlgOidRawLen, &alg))
    {
        /* Yes */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: signer[%u] digest algorithm unsupported",
                                 idx);
        return false;
    }
    for (i = 0; i < sd->digestAlgsLen; i++)
    {
        if (_SSFCMSSpanEquals(sd->digestAlgOidRaw[i], sd->digestAlgOidRawLen[i],
                              si->digestAlgOidRaw, si->digestAlgOidRawLen)) listed = true;
    }
    /* Is it missing from SignedData.digestAlgorithms? */
    if (!listed)
    {
        /* Yes */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                                 "CMS: signer[%u] digest algorithm not in digestAlgorithms", idx);
        return false;
    }
    hashLen = _SSFCMSDigestLen(alg);

    /* Did the caller supply the content digest? */
    if (digestOpt != NULL)
    {
        /* Yes, is it for another algorithm or length than this signer's? */
        if ((digestAlg != alg) || (digestLen != hashLen))
        {
            /* Yes */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                "CMS: signer[%u] digest algorithm %d does not match the supplied digest", idx,
                (int)alg);
            return false;
        }
        contentDigest = digestOpt;
    }
    else if (sd->hasEContent)
    {
        /* No, compute it from the attached content */
        _SSFCMSDigest(alg, sd->eContent, sd->eContentLen, computed, sizeof(computed));
        contentDigest = computed;
    }
    else
    {
        /* No, and the content is detached */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: detached content with no digest supplied");
        return false;
    }

    /* Does a CMSAlgorithmProtection attribute name other algorithms than in use (RFC 6211)? */
    if ((si->hasAlgProtection) &&
        ((!_SSFCMSSpanEquals(si->apDigestAlgOidRaw, si->apDigestAlgOidRawLen, si->digestAlgOidRaw,
                             si->digestAlgOidRawLen)) ||
         (!_SSFCMSSpanEquals(si->apSigAlgOidRaw, si->apSigAlgOidRawLen, si->sigAlgOidRaw,
                             si->sigAlgOidRawLen)) ||
         (!_SSFCMSParamsEquivalent(si->apSigAlgParams, si->apSigAlgParamsLen, si->sigAlgParams,
                                   si->sigAlgParamsLen))))
    {
        /* Yes, an algorithm was substituted after signing */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                                 "CMS: signer[%u] CMSAlgorithmProtection disagrees with SignerInfo",
                                 idx);
        return false;
    }

    /* Are signed attributes present? */
    if (si->signedAttrs != NULL)
    {
        /* Yes, they bind the content type and digest, and the signature covers them as a SET */
        if (!_SSFCMSSpanEquals(si->contentTypeOidRaw, si->contentTypeOidRawLen,
                               sd->eContentTypeOidRaw, sd->eContentTypeOidRawLen))
        {
            SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                                     "CMS: signer[%u] content-type attribute != eContentType", idx);
            return false;
        }

        /* Does the message-digest attribute differ from the content digest (constant time)? */
        if ((si->messageDigestLen != hashLen) ||
            (!SSFCryptCTMemEq(si->messageDigest, contentDigest, hashLen)))
        {
            /* Yes */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                                     "CMS: signer[%u] message-digest does not match the content",
                                     idx);
            return false;
        }

        /* Are the attributes too long for the re-tagging buffer? */
        if (si->signedAttrsLen > (uint32_t)SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN)
        {
            /* Yes */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                                     "CMS: signer[%u] signedAttrs %lu bytes exceed limit %u", idx,
                                     (unsigned long)si->signedAttrsLen,
                                     (unsigned int)SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN);
            return false;
        }
    }
    else
    {
        /* No, the signature covers the content itself; is it other than attached id-data? */
        if ((!_SSFCMSSpanEquals(sd->eContentTypeOidRaw, sd->eContentTypeOidRawLen, _oidData,
                                sizeof(_oidData))) || (!sd->hasEContent))
        {
            /* Yes */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                "CMS: signer[%u] has no signedAttrs and the content is not attached id-data", idx);
            return false;
        }

        /* Was a digest supplied as well? It must match the attached content, never be ignored */
        if (digestOpt != NULL)
        {
            /* Yes */
            _SSFCMSDigest(alg, sd->eContent, sd->eContentLen, computed, sizeof(computed));
            if (!SSFCryptCTMemEq(digestOpt, computed, hashLen))
            {
                SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                    "CMS: signer[%u] supplied digest does not match the attached content", idx);
                return false;
            }
        }
    }

    /* Is the signer certificate missing? */
    if (!_SSFCMSFindSignerDer(sd, si, trustDer, trustDerLen, trustCount, &signerDer,
                              &signerDerLen))
    {
        /* Yes */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: signer[%u] certificate not found", idx);
        return false;
    }

    /* The signer first, then every other embedded certificate in any order: the verifier builds */
    /* the path (ssfx509), choosing each issuer by name, key identifier and signature. At most   */
    /* SSF_CMS_CONFIG_MAX_CERTS + 1 entries, which the chain depth #error above guarantees fit.  */
    chain[0] = signerDer;
    chainLen[0] = signerDerLen;
    chainN = 1u;
    for (i = 0; i < sd->certsLen; i++)
    {
        if (sd->certs[i].der == signerDer) continue;
        chain[chainN] = sd->certs[i].der;
        chainLen[chainN] = sd->certs[i].derLen;
        chainN++;
    }
    /* Is the signer chain untrusted (checked before the signer key is used)? */
    if (!SSFX509VerifyChainPurpose(chain, chainLen, chainN, trustDer, trustDerLen, trustCount,
                                   SSF_X509_PURPOSE_CODE_SIGNING, NULL, nowUnixSec, &verifyErr))
    {
        /* Yes */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX,
                                 "CMS: signer[%u] certificate chain FAILED (code %d, cert[%u])",
                                 idx, (int)verifyErr.code, verifyErr.certIdx);
        return false;
    }

    /* Does the signature fail with the chain-verified signer's key? */
    return _SSFCMSVerifySignerSig(sd, idx, signerDer, signerDerLen, resultOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if some signer of sd verifies the content whose digest the caller supplies.      */
/* --------------------------------------------------------------------------------------------- */
bool SSFCMSVerifyDigest(const SSFCMSSignedData_t *sd, const uint8_t *digest, uint32_t digestLen,
                        SSFCMSDigestAlg_t digestAlg, const uint8_t **trustDer,
                        const uint32_t *trustDerLen, uint8_t trustCount, uint64_t nowUnixSec,
                        SSFCMSVerifyResult_t *resultOut)
{
    uint8_t i;

    SSF_REQUIRE(sd != NULL);
    SSF_REQUIRE(digest != NULL);
    SSF_REQUIRE(digestLen > 0u);
    SSF_REQUIRE((digestAlg > SSF_CMS_DIGEST_MIN) && (digestAlg < SSF_CMS_DIGEST_MAX));
    SSF_REQUIRE(trustDer != NULL);
    SSF_REQUIRE(trustDerLen != NULL);
    SSF_REQUIRE(trustCount >= 1u);
    SSF_REQUIRE(resultOut != NULL);

    memset(resultOut, 0, sizeof(*resultOut));
    for (i = 0; i < sd->signersLen; i++)
    {
        if (_SSFCMSVerifySigner(sd, i, digest, digestLen, digestAlg, trustDer, trustDerLen,
                                trustCount, nowUnixSec, resultOut)) return true;
    }
    SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: no signer verified (%u present)",
                             sd->signersLen);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if some signer of sd verifies the content attached in eContent.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFCMSVerifyAttached(const SSFCMSSignedData_t *sd, const uint8_t **trustDer,
                          const uint32_t *trustDerLen, uint8_t trustCount, uint64_t nowUnixSec,
                          SSFCMSVerifyResult_t *resultOut)
{
    uint8_t i;

    SSF_REQUIRE(sd != NULL);
    SSF_REQUIRE(trustDer != NULL);
    SSF_REQUIRE(trustDerLen != NULL);
    SSF_REQUIRE(trustCount >= 1u);
    SSF_REQUIRE(resultOut != NULL);

    memset(resultOut, 0, sizeof(*resultOut));

    /* Is the content detached? */
    if (!sd->hasEContent)
    {
        /* Yes, nothing to digest */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: content is detached, supply its digest");
        return false;
    }
    for (i = 0; i < sd->signersLen; i++)
    {
        if (_SSFCMSVerifySigner(sd, i, NULL, 0u, SSF_CMS_DIGEST_SHA256, trustDer, trustDerLen,
                                trustCount, nowUnixSec, resultOut)) return true;
    }
    SSF_TLS_TRACE_CERT_ERROR(_SSF_CMS_TRACE_CTX, "CMS: no signer verified (%u present)",
                             sd->signersLen);
    return false;
}
