/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfx509.c                                                                                     */
/* Provides X.509 v3 certificate parsing implementation (RFC 5280).                              */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#include "ssfx509.h"
#include "ssfasn1.h"
#include "ssftls.h"
#include "ssfsha2.h"
#include "ssfecdsa.h"
#include "ssfrsa.h"
#include "ssfed25519.h"
#include "ssfmatch.h"

/* Module-scope trace context for chain verification (set by caller before SSFVerifyChain) */
static SSFTLSTraceCtx_t _ssfx509TraceCtx;

void SSFX509SetTraceCtx(void (*fn)(int, int, const char *, void *), void *userCtx)
{
    _ssfx509TraceCtx.fn = (SSFTLSTraceFn_t)fn;
    _ssfx509TraceCtx.userCtx = userCtx;
}

/* --------------------------------------------------------------------------------------------- */
/* OID constant tables (raw DER-encoded content bytes)                                           */
/* --------------------------------------------------------------------------------------------- */

/* DN attribute OIDs (2.5.4.x) */
static const uint8_t _oidCN[]  = { 0x55u, 0x04u, 0x03u }; /* 2.5.4.3 commonName */
static const uint8_t _oidC[]   = { 0x55u, 0x04u, 0x06u }; /* 2.5.4.6 countryName */
static const uint8_t _oidL[]   = { 0x55u, 0x04u, 0x07u }; /* 2.5.4.7 localityName */
static const uint8_t _oidST[]  = { 0x55u, 0x04u, 0x08u }; /* 2.5.4.8 stateOrProvinceName */
static const uint8_t _oidO[]   = { 0x55u, 0x04u, 0x0Au }; /* 2.5.4.10 organizationName */
static const uint8_t _oidOU[]  = { 0x55u, 0x04u, 0x0Bu }; /* 2.5.4.11 organizationalUnitName */

/* Algorithm OIDs */
static const uint8_t _oidEcPubKey[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u };
static const uint8_t _oidRSA[] = { 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u };
static const uint8_t _oidP256[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u };
static const uint8_t _oidEcdsaSHA256[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u };

/* P-384 curve: 1.3.132.0.34 */
static const uint8_t _oidP384[] = { 0x2Bu, 0x81u, 0x04u, 0x00u, 0x22u };

/* ecdsa-with-SHA384: 1.2.840.10045.4.3.3 */
static const uint8_t _oidEcdsaSHA384[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x03u };

/* sha256WithRSAEncryption: 1.2.840.113549.1.1.11 */
static const uint8_t _oidRSAPKCS1SHA256[] = { 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu };

/* sha384WithRSAEncryption: 1.2.840.113549.1.1.12 */
static const uint8_t _oidRSAPKCS1SHA384[] = { 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Cu };

/* sha512WithRSAEncryption: 1.2.840.113549.1.1.13 */
static const uint8_t _oidRSAPKCS1SHA512[] = { 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Du };

/* id-RSASSA-PSS: 1.2.840.113549.1.1.10 */
static const uint8_t _oidRSAPSS[] = { 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au };

/* id-Ed25519 (RFC 8410): 1.3.101.112 — used for both SubjectPublicKeyInfo algorithm and        */
/* signatureAlgorithm. No parameters.                                                            */
static const uint8_t _oidEd25519[] = { 0x2Bu, 0x65u, 0x70u };

/* Hash algorithm OIDs for PSS parameter parsing (RFC 4055) */
/* id-sha256: 2.16.840.1.101.3.4.2.1 */
static const uint8_t _oidSHA256[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u
};
/* id-sha384: 2.16.840.1.101.3.4.2.2 */
static const uint8_t _oidSHA384[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u
};
/* id-sha512: 2.16.840.1.101.3.4.2.3 */
static const uint8_t _oidSHA512[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u
};

/* Extended Key Usage OIDs (RFC 5280 Section 4.2.1.12) */
/* id-kp-serverAuth: 1.3.6.1.5.5.7.3.1 */
static const uint8_t _oidEkuServerAuth[] = {
    0x2Bu, 0x06u, 0x01u, 0x05u, 0x05u, 0x07u, 0x03u, 0x01u
};
/* id-kp-clientAuth: 1.3.6.1.5.5.7.3.2 */
static const uint8_t _oidEkuClientAuth[] = {
    0x2Bu, 0x06u, 0x01u, 0x05u, 0x05u, 0x07u, 0x03u, 0x02u
};

/* Extension OIDs (2.5.29.x) */
static const uint8_t _oidBasicConstraints[] = { 0x55u, 0x1Du, 0x13u }; /* 2.5.29.19 */
static const uint8_t _oidKeyUsage[]         = { 0x55u, 0x1Du, 0x0Fu }; /* 2.5.29.15 */
static const uint8_t _oidSAN[]              = { 0x55u, 0x1Du, 0x11u }; /* 2.5.29.17 */
static const uint8_t _oidSKID[]             = { 0x55u, 0x1Du, 0x0Eu }; /* 2.5.29.14 */
static const uint8_t _oidAKID[]             = { 0x55u, 0x1Du, 0x23u }; /* 2.5.29.35 */
static const uint8_t _oidEKU[]              = { 0x55u, 0x1Du, 0x25u }; /* 2.5.29.37 */
static const uint8_t _oidNameConstraints[]  = { 0x55u, 0x1Du, 0x1Eu }; /* 2.5.29.30 */

/* --------------------------------------------------------------------------------------------- */
/* Helper: compare raw OID bytes.                                                                */
/* --------------------------------------------------------------------------------------------- */
static bool _OIDMatch(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen)
{
    if (aLen != bLen) return false;
    return (memcmp(a, b, aLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: determine RSA-PSS hash algorithm from sigAlg parameters (RFC 4055 Section 3.1).       */
/* RSASSA-PSS-params ::= SEQUENCE {                                                              */
/*     hashAlgorithm      [0] HashAlgorithm DEFAULT sha1,                                       */
/*     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,                                */
/*     saltLength         [2] INTEGER DEFAULT 20                                                 */
/* }                                                                                             */
/* Returns the RSA hash enum. If params are absent or unparseable, defaults to SHA-256.          */
/* --------------------------------------------------------------------------------------------- */
static SSFRSAHash_t _ParsePSSHashAlg(const uint8_t *params, uint32_t paramsLen)
{
    SSFASN1Cursor_t cursor;
    SSFASN1Cursor_t seqInner;
    SSFASN1Cursor_t hashAlgInner;
    SSFASN1Cursor_t algIdInner;
    const uint8_t *hashOidRaw;
    uint32_t hashOidRawLen;
    uint16_t tag;

    if (params == NULL || paramsLen == 0) return SSF_RSA_HASH_SHA256;

    cursor.buf = params;
    cursor.bufLen = paramsLen;

    /* PSS params is a SEQUENCE */
    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &seqInner, &cursor))
    {
        return SSF_RSA_HASH_SHA256;
    }

    /* Look for [0] EXPLICIT hashAlgorithm */
    if (!SSFASN1DecPeekTag(&seqInner, &tag)) return SSF_RSA_HASH_SHA256;
    if (tag != SSF_ASN1_CONTEXT_EXPLICIT(0)) return SSF_RSA_HASH_SHA256; /* No hash param → default */

    if (!SSFASN1DecOpenConstructed(&seqInner, SSF_ASN1_CONTEXT_EXPLICIT(0),
                                    &hashAlgInner, &seqInner))
    {
        return SSF_RSA_HASH_SHA256;
    }

    /* HashAlgorithm is AlgorithmIdentifier: SEQUENCE { OID, params } */
    if (!SSFASN1DecOpenConstructed(&hashAlgInner, SSF_ASN1_TAG_SEQUENCE,
                                    &algIdInner, &hashAlgInner))
    {
        return SSF_RSA_HASH_SHA256;
    }

    if (!SSFASN1DecGetOIDRaw(&algIdInner, &hashOidRaw, &hashOidRawLen, &algIdInner))
    {
        return SSF_RSA_HASH_SHA256;
    }

    /* Match against known hash OIDs */
    if (_OIDMatch(hashOidRaw, hashOidRawLen, _oidSHA256, sizeof(_oidSHA256)))
    {
        return SSF_RSA_HASH_SHA256;
    }
    if (_OIDMatch(hashOidRaw, hashOidRawLen, _oidSHA384, sizeof(_oidSHA384)))
    {
        return SSF_RSA_HASH_SHA384;
    }
    if (_OIDMatch(hashOidRaw, hashOidRawLen, _oidSHA512, sizeof(_oidSHA512)))
    {
        return SSF_RSA_HASH_SHA512;
    }

    /* Unknown hash OID — default to SHA-256 */
    return SSF_RSA_HASH_SHA256;
}

/* --------------------------------------------------------------------------------------------- */
/* Parses a Distinguished Name (SEQUENCE of SET of SEQUENCE of {OID, value}).                     */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseDN(const SSFASN1Cursor_t *nameCursor, SSFX509Name_t *name)
{
    SSFASN1Cursor_t setInner;
    SSFASN1Cursor_t attrInner;
    SSFASN1Cursor_t pos;
    const uint8_t *oidRaw;
    uint32_t oidRawLen;
    const uint8_t *val;
    uint32_t valLen;
    uint16_t strTag;

    /* Name is a SEQUENCE of RelativeDistinguishedName (SET) */
    pos = *nameCursor;
    while (!SSFASN1DecIsEmpty(&pos))
    {
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SET, &setInner, &pos)) return false;

        /* Each SET contains one or more AttributeTypeAndValue SEQUENCEs */
        while (!SSFASN1DecIsEmpty(&setInner))
        {
            if (!SSFASN1DecOpenConstructed(&setInner, SSF_ASN1_TAG_SEQUENCE, &attrInner, &setInner))
                return false;

            if (!SSFASN1DecGetOIDRaw(&attrInner, &oidRaw, &oidRawLen, &attrInner)) return false;
            if (!SSFASN1DecGetString(&attrInner, &val, &valLen, &strTag, &attrInner)) return false;

            /* Match OID to DN field */
            if (_OIDMatch(oidRaw, oidRawLen, _oidCN, sizeof(_oidCN)))
            { name->cn = val; name->cnLen = valLen; }
            else if (_OIDMatch(oidRaw, oidRawLen, _oidC, sizeof(_oidC)))
            { name->c = val; name->cLen = valLen; }
            else if (_OIDMatch(oidRaw, oidRawLen, _oidST, sizeof(_oidST)))
            { name->st = val; name->stLen = valLen; }
            else if (_OIDMatch(oidRaw, oidRawLen, _oidL, sizeof(_oidL)))
            { name->l = val; name->lLen = valLen; }
            else if (_OIDMatch(oidRaw, oidRawLen, _oidO, sizeof(_oidO)))
            { name->o = val; name->oLen = valLen; }
            else if (_OIDMatch(oidRaw, oidRawLen, _oidOU, sizeof(_oidOU)))
            { name->ou = val; name->ouLen = valLen; }
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Parses the Extensions SEQUENCE.                                                               */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseExtensions(const SSFASN1Cursor_t *extsCursor, SSFX509Cert_t *cert)
{
    SSFASN1Cursor_t pos;
    SSFASN1Cursor_t extInner;
    const uint8_t *oidRaw;
    uint32_t oidRawLen;
    bool critical;
    const uint8_t *extValue;
    uint32_t extValueLen;
    uint16_t tag;

    pos = *extsCursor;
    while (!SSFASN1DecIsEmpty(&pos))
    {
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &extInner, &pos)) return false;

        if (!SSFASN1DecGetOIDRaw(&extInner, &oidRaw, &oidRawLen, &extInner)) return false;

        /* RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of a           */
        /* particular extension." Reject any cert that contains a duplicate extension OID.      */
        {
            uint8_t dup;
            for (dup = 0; dup < cert->extsLen; dup++)
            {
                if (_OIDMatch(cert->exts[dup].oidRaw, cert->exts[dup].oidRawLen,
                              oidRaw, oidRawLen))
                {
                    return false;
                }
            }
        }

        /* Optional critical BOOLEAN (default false) */
        critical = false;
        if (!SSFASN1DecIsEmpty(&extInner))
        {
            if (SSFASN1DecPeekTag(&extInner, &tag) && tag == SSF_ASN1_TAG_BOOLEAN)
            {
                SSFASN1DecGetBool(&extInner, &critical, &extInner);
            }
        }

        /* Extension value is an OCTET STRING wrapping the actual value */
        if (!SSFASN1DecGetOctetString(&extInner, &extValue, &extValueLen, &extInner)) return false;

        /* Store in extension array */
        if (cert->extsLen < SSF_X509_CONFIG_MAX_EXTENSIONS)
        {
            cert->exts[cert->extsLen].oidRaw = oidRaw;
            cert->exts[cert->extsLen].oidRawLen = oidRawLen;
            cert->exts[cert->extsLen].critical = critical;
            cert->exts[cert->extsLen].value = extValue;
            cert->exts[cert->extsLen].valueLen = extValueLen;
            cert->extsLen++;
        }

        /* Parse known extensions */
        if (_OIDMatch(oidRaw, oidRawLen, _oidBasicConstraints, sizeof(_oidBasicConstraints)))
        {
            SSFASN1Cursor_t bcCursor = { extValue, extValueLen };
            SSFASN1Cursor_t bcInner;
            cert->hasBasicConstraints = true;
            cert->isCA = false;
            cert->pathLenConstraint = -1;
            if (SSFASN1DecOpenConstructed(&bcCursor, SSF_ASN1_TAG_SEQUENCE, &bcInner, &bcCursor))
            {
                if (!SSFASN1DecIsEmpty(&bcInner))
                {
                    if (SSFASN1DecPeekTag(&bcInner, &tag) && tag == SSF_ASN1_TAG_BOOLEAN)
                    {
                        SSFASN1DecGetBool(&bcInner, &cert->isCA, &bcInner);
                    }
                    if (!SSFASN1DecIsEmpty(&bcInner))
                    {
                        uint64_t pl;
                        if (SSFASN1DecGetIntU64(&bcInner, &pl, &bcInner))
                        {
                            cert->pathLenConstraint = (int8_t)pl;
                        }
                    }
                }
            }
        }
        else if (_OIDMatch(oidRaw, oidRawLen, _oidKeyUsage, sizeof(_oidKeyUsage)))
        {
            SSFASN1Cursor_t kuCursor = { extValue, extValueLen };
            const uint8_t *kuBits;
            uint32_t kuBitsLen;
            uint8_t kuUnused;
            cert->hasKeyUsage = true;
            if (SSFASN1DecGetBitString(&kuCursor, &kuBits, &kuBitsLen, &kuUnused, &kuCursor))
            {
                cert->keyUsageBits = 0;
                if (kuBitsLen >= 1u) cert->keyUsageBits = (uint16_t)kuBits[0] << 8;
                if (kuBitsLen >= 2u) cert->keyUsageBits |= (uint16_t)kuBits[1];
            }
        }
        else if (_OIDMatch(oidRaw, oidRawLen, _oidSAN, sizeof(_oidSAN)))
        {
            SSFASN1Cursor_t sanCursor = { extValue, extValueLen };
            SSFASN1Cursor_t sanInner;
            if (SSFASN1DecOpenConstructed(&sanCursor, SSF_ASN1_TAG_SEQUENCE, &sanInner, &sanCursor))
            {
                while (!SSFASN1DecIsEmpty(&sanInner) && cert->sanLen < SSF_X509_CONFIG_MAX_SAN_ENTRIES)
                {
                    const uint8_t *sanVal;
                    uint32_t sanValLen;
                    if (SSFASN1DecPeekTag(&sanInner, &tag))
                    {
                        uint8_t sanType = tag & 0x1Fu;
                        if (SSFASN1DecGetTLV(&sanInner, &tag, &sanVal, &sanValLen, &sanInner))
                        {
                            cert->san[cert->sanLen].type = sanType;
                            cert->san[cert->sanLen].val = sanVal;
                            cert->san[cert->sanLen].valLen = sanValLen;
                            cert->sanLen++;
                        }
                    }
                    else break;
                }
            }
        }
        else if (_OIDMatch(oidRaw, oidRawLen, _oidSKID, sizeof(_oidSKID)))
        {
            SSFASN1Cursor_t skidCursor = { extValue, extValueLen };
            SSFASN1DecGetOctetString(&skidCursor, &cert->skid, &cert->skidLen, &skidCursor);
        }
        else if (_OIDMatch(oidRaw, oidRawLen, _oidAKID, sizeof(_oidAKID)))
        {
            SSFASN1Cursor_t akidCursor = { extValue, extValueLen };
            SSFASN1Cursor_t akidInner;
            if (SSFASN1DecOpenConstructed(&akidCursor, SSF_ASN1_TAG_SEQUENCE, &akidInner, &akidCursor))
            {
                if (!SSFASN1DecIsEmpty(&akidInner) && SSFASN1DecPeekTag(&akidInner, &tag))
                {
                    if (tag == SSF_ASN1_CONTEXT_IMPLICIT(0))
                    {
                        SSFASN1DecGetTLV(&akidInner, &tag, &cert->akid, &cert->akidLen, &akidInner);
                    }
                }
            }
        }
        else if (_OIDMatch(oidRaw, oidRawLen, _oidEKU, sizeof(_oidEKU)))
        {
            /* Extended Key Usage: SEQUENCE OF OID (RFC 5280 Section 4.2.1.12) */
            SSFASN1Cursor_t ekuCursor = { extValue, extValueLen };
            SSFASN1Cursor_t ekuInner;
            cert->hasExtKeyUsage = true;
            if (SSFASN1DecOpenConstructed(&ekuCursor, SSF_ASN1_TAG_SEQUENCE,
                                          &ekuInner, &ekuCursor))
            {
                while (!SSFASN1DecIsEmpty(&ekuInner))
                {
                    const uint8_t *ekuOid;
                    uint32_t ekuOidLen;
                    if (!SSFASN1DecGetOIDRaw(&ekuInner, &ekuOid, &ekuOidLen, &ekuInner)) break;
                    if (_OIDMatch(ekuOid, ekuOidLen, _oidEkuServerAuth,
                                  sizeof(_oidEkuServerAuth)))
                    {
                        cert->ekuServerAuth = true;
                    }
                    else if (_OIDMatch(ekuOid, ekuOidLen, _oidEkuClientAuth,
                                       sizeof(_oidEkuClientAuth)))
                    {
                        cert->ekuClientAuth = true;
                    }
                }
            }
        }
        else if (_OIDMatch(oidRaw, oidRawLen, _oidNameConstraints,
                            sizeof(_oidNameConstraints)))
        {
            /* Name Constraints (RFC 5280 Section 4.2.1.10).                                    */
            /* NameConstraints ::= SEQUENCE { permittedSubtrees [0] IMPLICIT OPTIONAL,          */
            /*                                 excludedSubtrees  [1] IMPLICIT OPTIONAL }        */
            /* GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree                     */
            /* GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0,           */
            /*                                maximum [1] OPTIONAL }                             */
            SSFASN1Cursor_t ncCursor = { extValue, extValueLen };
            SSFASN1Cursor_t ncInner;
            cert->hasNameConstraints = true;
            if (SSFASN1DecOpenConstructed(&ncCursor, SSF_ASN1_TAG_SEQUENCE,
                                          &ncInner, &ncCursor))
            {
                uint8_t subtreeIdx;
                for (subtreeIdx = 0; subtreeIdx < 2u; subtreeIdx++)
                {
                    SSFASN1Cursor_t subtreesOuter;
                    SSFASN1Cursor_t subtreesInner;
                    uint16_t expectTag = (subtreeIdx == 0u) ?
                        (uint16_t)(SSF_ASN1_CONTEXT_EXPLICIT(0)) :
                        (uint16_t)(SSF_ASN1_CONTEXT_EXPLICIT(1));
                    SSFX509NameConstraint_t *dest = (subtreeIdx == 0u) ?
                        cert->permittedSubtrees : cert->excludedSubtrees;
                    uint8_t *destLen = (subtreeIdx == 0u) ?
                        &cert->permittedLen : &cert->excludedLen;

                    if (SSFASN1DecIsEmpty(&ncInner)) break;
                    if (!SSFASN1DecPeekTag(&ncInner, &tag)) break;
                    if (tag != expectTag) continue;
                    if (!SSFASN1DecOpenConstructed(&ncInner, expectTag, &subtreesOuter,
                                                   &ncInner)) break;

                    /* subtreesOuter is already the implicit SEQUENCE content (GeneralSubtree*) */
                    subtreesInner = subtreesOuter;
                    while (!SSFASN1DecIsEmpty(&subtreesInner) &&
                           *destLen < SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS)
                    {
                        SSFASN1Cursor_t gsInner;
                        uint16_t gnTag;
                        const uint8_t *gnVal;
                        uint32_t gnValLen;

                        if (!SSFASN1DecOpenConstructed(&subtreesInner, SSF_ASN1_TAG_SEQUENCE,
                                                        &gsInner, &subtreesInner)) break;
                        if (!SSFASN1DecPeekTag(&gsInner, &gnTag)) continue;
                        if (!SSFASN1DecGetTLV(&gsInner, &gnTag, &gnVal, &gnValLen,
                                               &gsInner)) continue;

                        /* Tags: [2] IMPLICIT dNSName = 0x82, [7] IMPLICIT iPAddress = 0x87.    */
                        /* Other GeneralName types are not enforced (constraints on unsupported  */
                        /* types are ignored; since we also do not parse those SAN types, this   */
                        /* is consistent behavior for dNSName/iPAddress-only deployments).        */
                        if (gnTag == 0x82u || gnTag == 0x87u)
                        {
                            dest[*destLen].type = (gnTag == 0x82u) ? SSF_X509_SAN_DNS :
                                                                      SSF_X509_SAN_IP;
                            dest[*destLen].val = gnVal;
                            dest[*destLen].valLen = gnValLen;
                            (*destLen)++;
                        }
                    }
                }
            }
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Parse a DER-encoded X.509 certificate.                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509Parse(const uint8_t *der, uint32_t derLen, SSFX509Cert_t *cert)
{
    SSFASN1Cursor_t cursor;
    SSFASN1Cursor_t certInner;
    SSFASN1Cursor_t tbsInner;
    SSFASN1Cursor_t pos;
    SSFASN1Cursor_t algInner;
    SSFASN1Cursor_t spkiInner;
    SSFASN1Cursor_t validityInner;
    SSFASN1Cursor_t nameSeq;
    uint16_t tag;
    const uint8_t *tbsStart;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(cert != NULL);

    memset(cert, 0, sizeof(SSFX509Cert_t));
    cert->pathLenConstraint = -1;

    cursor.buf = der;
    cursor.bufLen = derLen;

    /* Certificate SEQUENCE */
    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &certInner, &cursor))
        return false;

    /* TBSCertificate SEQUENCE — record the raw bytes for signature verification */
    tbsStart = certInner.buf;
    if (!SSFASN1DecOpenConstructed(&certInner, SSF_ASN1_TAG_SEQUENCE, &tbsInner, &certInner))
        return false;
    cert->tbsRaw = tbsStart;
    cert->tbsRawLen = (uint32_t)(certInner.buf - tbsStart);

    pos = tbsInner;

    /* Version [0] EXPLICIT INTEGER (OPTIONAL, default v1=0) */
    cert->version = 0;
    if (SSFASN1DecPeekTag(&pos, &tag) && tag == SSF_ASN1_CONTEXT_EXPLICIT(0))
    {
        SSFASN1Cursor_t verInner;
        uint64_t ver;
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_CONTEXT_EXPLICIT(0), &verInner, &pos))
            return false;
        if (!SSFASN1DecGetIntU64(&verInner, &ver, &verInner)) return false;
        cert->version = (uint8_t)ver;
    }

    /* Serial number */
    if (!SSFASN1DecGetInt(&pos, &cert->serial, &cert->serialLen, &pos)) return false;

    /* RFC 5280 §4.1.2.2: serial number MUST be a non-negative integer. Conforming CAs MUST NOT */
    /* emit serials longer than 20 octets; verifiers MUST handle up to 20 octets. Reject:        */
    /*   - zero-length content (malformed DER INTEGER)                                            */
    /*   - lengths exceeding 20 octets                                                            */
    /*   - negative values (high bit of first raw byte set — DER signed two's-complement)         */
    /* Serial value of zero (single 0x00 byte) is accepted; RFC says verifiers SHOULD gracefully */
    /* handle it even though conforming CAs MUST NOT emit it.                                     */
    if (cert->serialLen == 0u || cert->serialLen > 20u) return false;
    if ((cert->serial[0] & 0x80u) != 0u) return false;

    /* Signature algorithm (in TBS) — extract OID and optional parameters */
    if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &algInner, &pos)) return false;
    if (!SSFASN1DecGetOIDRaw(&algInner, &cert->sigAlgOidRaw, &cert->sigAlgOidRawLen, &algInner))
        return false;
    /* Remaining bytes in algInner are the algorithm parameters (e.g., PSS params) */
    if (algInner.bufLen > 0)
    {
        cert->sigAlgParams = algInner.buf;
        cert->sigAlgParamsLen = algInner.bufLen;
    }

    /* Issuer Name */
    {
        const uint8_t *issuerStart = pos.buf;
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &nameSeq, &pos)) return false;
        cert->issuer.raw = issuerStart;
        cert->issuer.rawLen = (uint32_t)(pos.buf - issuerStart);
        if (!_ParseDN(&nameSeq, &cert->issuer)) return false;
    }

    /* Validity */
    if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &validityInner, &pos))
        return false;
    if (!SSFASN1DecGetTime(&validityInner, &cert->notBefore, &validityInner)) return false;
    if (!SSFASN1DecGetTime(&validityInner, &cert->notAfter, &validityInner)) return false;

    /* Subject Name */
    {
        const uint8_t *subjectStart = pos.buf;
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &nameSeq, &pos)) return false;
        cert->subject.raw = subjectStart;
        cert->subject.rawLen = (uint32_t)(pos.buf - subjectStart);
        if (!_ParseDN(&nameSeq, &cert->subject)) return false;
    }

    /* Subject Public Key Info */
    if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &spkiInner, &pos)) return false;
    {
        SSFASN1Cursor_t pkAlgInner;
        if (!SSFASN1DecOpenConstructed(&spkiInner, SSF_ASN1_TAG_SEQUENCE, &pkAlgInner, &spkiInner))
            return false;
        if (!SSFASN1DecGetOIDRaw(&pkAlgInner, &cert->pubKeyAlgOidRaw, &cert->pubKeyAlgOidRawLen,
                                  &pkAlgInner))
            return false;
        /* EC curve OID (parameter of the algorithm) */
        if (!SSFASN1DecIsEmpty(&pkAlgInner))
        {
            if (SSFASN1DecPeekTag(&pkAlgInner, &tag) && tag == SSF_ASN1_TAG_OID)
            {
                SSFASN1DecGetOIDRaw(&pkAlgInner, &cert->ecCurveOidRaw, &cert->ecCurveOidRawLen,
                                     &pkAlgInner);
            }
        }
    }
    /* Public key BIT STRING */
    if (!SSFASN1DecGetBitString(&spkiInner, &cert->pubKey, &cert->pubKeyLen,
                                &cert->pubKeyUnusedBits, &spkiInner))
        return false;

    /* Optional: issuerUniqueID [1], subjectUniqueID [2] — skip if present */
    while (SSFASN1DecPeekTag(&pos, &tag) &&
           (tag == SSF_ASN1_CONTEXT_IMPLICIT(1) || tag == SSF_ASN1_CONTEXT_IMPLICIT(2)))
    {
        SSFASN1DecSkip(&pos, &pos);
    }

    /* Extensions [3] EXPLICIT (OPTIONAL, v3 only) */
    if (SSFASN1DecPeekTag(&pos, &tag) && tag == SSF_ASN1_CONTEXT_EXPLICIT(3))
    {
        SSFASN1Cursor_t extsOuter;
        SSFASN1Cursor_t extsSeq;
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_CONTEXT_EXPLICIT(3), &extsOuter, &pos))
            return false;
        if (!SSFASN1DecOpenConstructed(&extsOuter, SSF_ASN1_TAG_SEQUENCE, &extsSeq, &extsOuter))
            return false;
        if (!_ParseExtensions(&extsSeq, cert)) return false;
    }

    /* After TBS: signatureAlgorithm SEQUENCE (outer copy) */
    if (!SSFASN1DecOpenConstructed(&certInner, SSF_ASN1_TAG_SEQUENCE, &algInner, &certInner))
        return false;
    if (!SSFASN1DecGetOIDRaw(&algInner, &cert->outerSigAlgOidRaw,
                              &cert->outerSigAlgOidRawLen, &algInner))
        return false;

    /* signatureValue BIT STRING */
    if (!SSFASN1DecGetBitString(&certInner, &cert->signature, &cert->signatureLen,
                                &cert->signatureUnusedBits, &certInner))
        return false;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsValid(const SSFX509Cert_t *cert, uint64_t nowUnixSec)
{
    SSF_REQUIRE(cert != NULL);
    return (nowUnixSec >= cert->notBefore && nowUnixSec < cert->notAfter);
}

bool SSFX509IsECDSA(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidEcdsaSHA256, sizeof(_oidEcdsaSHA256));
}

bool SSFX509IsRSA(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->pubKeyAlgOidRaw, cert->pubKeyAlgOidRawLen,
                     _oidRSA, sizeof(_oidRSA));
}

bool SSFX509IsP256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->ecCurveOidRaw, cert->ecCurveOidRawLen,
                     _oidP256, sizeof(_oidP256));
}

/* ========================================================================================== */
/* CERTIFICATE GENERATION                                                                     */
/* ========================================================================================== */

/* --------------------------------------------------------------------------------------------- */
/* Helper: returns strlen of a C string, or 0 if NULL.                                           */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _StrLen(SSFCStrIn_t s)
{
    uint32_t len = 0;
    if (s == NULL) return 0;
    while (s[len] != '\0') len++;
    return len;
}

/* Upstream ssfasn1 encoder API moved from `uint32_t f(...)` to `bool f(..., uint32_t *bytesWritten)`. */
/* These thin wrappers preserve the call shape used throughout this file: returns 0 on failure  */
/* (including buffer-too-small), bytes written/needed otherwise.                                 */
static uint32_t _EncWrap(uint8_t *buf, uint32_t bufSize, uint16_t tag,
                         const uint8_t *content, uint32_t contentLen)
{
    uint32_t n;
    /* Legacy sizing pattern: callers pass (NULL, 0, tag, NULL, contentLen) to ask for the    */
    /* total size of a wrap whose content has already been measured separately. The new       */
    /* upstream contract rejects content==NULL with contentLen!=0, so route those calls       */
    /* through SSFASN1EncTagLen (header bytes) and add contentLen ourselves.                  */
    if (content == NULL && contentLen != 0u)
    {
        if (!SSFASN1EncTagLen(NULL, 0, tag, contentLen, &n)) return 0;
        return n + contentLen;
    }
    if (!SSFASN1EncWrap(buf, bufSize, tag, content, contentLen, &n)) return 0;
    return n;
}

static uint32_t _EncOIDRaw(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw,
                           uint32_t oidRawLen)
{
    uint32_t n;
    if (!SSFASN1EncOIDRaw(buf, bufSize, oidRaw, oidRawLen, &n)) return 0;
    return n;
}

static uint32_t _EncString(uint8_t *buf, uint32_t bufSize, uint16_t strTag,
                           const uint8_t *str, uint32_t strLen)
{
    uint32_t n;
    if (!SSFASN1EncString(buf, bufSize, strTag, str, strLen, &n)) return 0;
    return n;
}

static uint32_t _EncBool(uint8_t *buf, uint32_t bufSize, bool val)
{
    uint32_t n;
    if (!SSFASN1EncBool(buf, bufSize, val, &n)) return 0;
    return n;
}

static uint32_t _EncInt(uint8_t *buf, uint32_t bufSize, const uint8_t *intBuf, uint32_t intLen)
{
    uint32_t n;
    if (!SSFASN1EncInt(buf, bufSize, intBuf, intLen, &n)) return 0;
    return n;
}

static uint32_t _EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val)
{
    uint32_t n;
    if (!SSFASN1EncIntU64(buf, bufSize, val, &n)) return 0;
    return n;
}

static uint32_t _EncBitString(uint8_t *buf, uint32_t bufSize, const uint8_t *bits,
                              uint32_t bitsLen, uint8_t unusedBits)
{
    uint32_t n;
    if (!SSFASN1EncBitString(buf, bufSize, bits, bitsLen, unusedBits, &n)) return 0;
    return n;
}

static uint32_t _EncOctetString(uint8_t *buf, uint32_t bufSize, const uint8_t *octets,
                                uint32_t octetsLen)
{
    uint32_t n;
    /* See _EncWrap: route legacy NULL-content sizing through SSFASN1EncTagLen + contentLen. */
    if (octets == NULL && octetsLen != 0u)
    {
        if (!SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_OCTET_STRING, octetsLen, &n)) return 0;
        return n + octetsLen;
    }
    if (!SSFASN1EncOctetString(buf, bufSize, octets, octetsLen, &n)) return 0;
    return n;
}

static uint32_t _EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec)
{
    uint32_t n;
    if (!SSFASN1EncUTCTime(buf, bufSize, unixSec, &n)) return 0;
    return n;
}

static uint32_t _EncTagLen(uint8_t *buf, uint32_t bufSize, uint16_t tag, uint32_t contentLen)
{
    uint32_t n;
    if (!SSFASN1EncTagLen(buf, bufSize, tag, contentLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: encode a single DN attribute (SET { SEQUENCE { OID, UTF8String } }).                  */
/* Returns bytes written/needed. buf may be NULL for measuring.                                  */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _EncDNAttr(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw,
                           uint32_t oidRawLen, SSFCStrIn_t value)
{
    uint32_t valLen = _StrLen(value);
    uint32_t oidEnc = _EncOIDRaw(NULL, 0, oidRaw, oidRawLen);
    uint32_t strEnc = _EncString(NULL, 0, SSF_ASN1_TAG_UTF8_STRING,
                                       (const uint8_t *)value, valLen);
    uint32_t seqContent = oidEnc + strEnc;
    uint32_t seqEnc = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, seqContent);
    uint32_t setEnc = _EncWrap(NULL, 0, SSF_ASN1_TAG_SET, NULL, seqEnc);

    if (buf == NULL) return setEnc;
    if (bufSize < setEnc) return 0;

    {
        uint32_t pos = 0;
        uint8_t seqBuf[128];
        uint32_t seqPos = 0;

        /* Build inner SEQUENCE content */
        seqPos += _EncOIDRaw(&seqBuf[seqPos], sizeof(seqBuf) - seqPos, oidRaw, oidRawLen);
        seqPos += _EncString(&seqBuf[seqPos], sizeof(seqBuf) - seqPos,
                                   SSF_ASN1_TAG_UTF8_STRING, (const uint8_t *)value, valLen);

        /* Wrap in SEQUENCE, then in SET */
        {
            uint8_t setContentBuf[130];
            uint32_t setContentLen;
            setContentLen = _EncWrap(setContentBuf, sizeof(setContentBuf),
                                           SSF_ASN1_TAG_SEQUENCE, seqBuf, seqPos);
            pos = _EncWrap(buf, bufSize, SSF_ASN1_TAG_SET, setContentBuf, setContentLen);
        }
        return pos;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: encode a Distinguished Name SEQUENCE.                                                 */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _EncDN(uint8_t *buf, uint32_t bufSize, const SSFX509GenName_t *name)
{
    /* Measure inner content */
    uint32_t innerLen = 0;

    if (name->c != NULL) innerLen += _EncDNAttr(NULL, 0, _oidC, sizeof(_oidC), name->c);
    if (name->st != NULL) innerLen += _EncDNAttr(NULL, 0, _oidST, sizeof(_oidST), name->st);
    if (name->l != NULL) innerLen += _EncDNAttr(NULL, 0, _oidL, sizeof(_oidL), name->l);
    if (name->o != NULL) innerLen += _EncDNAttr(NULL, 0, _oidO, sizeof(_oidO), name->o);
    if (name->ou != NULL) innerLen += _EncDNAttr(NULL, 0, _oidOU, sizeof(_oidOU), name->ou);
    if (name->cn != NULL) innerLen += _EncDNAttr(NULL, 0, _oidCN, sizeof(_oidCN), name->cn);

    {
        uint32_t total = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, innerLen);
        if (buf == NULL) return total;
        if (bufSize < total) return 0;
    }

    /* Write: SEQUENCE header, then each attribute */
    {
        uint8_t innerBuf[256];
        uint32_t pos = 0;

        if (name->c != NULL)
            pos += _EncDNAttr(&innerBuf[pos], sizeof(innerBuf) - pos, _oidC, sizeof(_oidC), name->c);
        if (name->st != NULL)
            pos += _EncDNAttr(&innerBuf[pos], sizeof(innerBuf) - pos, _oidST, sizeof(_oidST), name->st);
        if (name->l != NULL)
            pos += _EncDNAttr(&innerBuf[pos], sizeof(innerBuf) - pos, _oidL, sizeof(_oidL), name->l);
        if (name->o != NULL)
            pos += _EncDNAttr(&innerBuf[pos], sizeof(innerBuf) - pos, _oidO, sizeof(_oidO), name->o);
        if (name->ou != NULL)
            pos += _EncDNAttr(&innerBuf[pos], sizeof(innerBuf) - pos, _oidOU, sizeof(_oidOU), name->ou);
        if (name->cn != NULL)
            pos += _EncDNAttr(&innerBuf[pos], sizeof(innerBuf) - pos, _oidCN, sizeof(_oidCN), name->cn);

        return _EncWrap(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, innerBuf, pos);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: encode the AlgorithmIdentifier SEQUENCE { OID, params }.                              */
/* For ECDSA: SEQUENCE { OID }, for RSA: SEQUENCE { OID, NULL }.                                 */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _EncAlgId(uint8_t *buf, uint32_t bufSize,
                          const uint8_t *algOidRaw, uint32_t algOidRawLen)
{
    uint32_t innerLen = _EncOIDRaw(NULL, 0, algOidRaw, algOidRawLen);
    uint32_t total = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, innerLen);

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    {
        uint8_t innerBuf[32];
        uint32_t pos = 0;
        pos += _EncOIDRaw(innerBuf, sizeof(innerBuf), algOidRaw, algOidRawLen);
        return _EncWrap(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, innerBuf, pos);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: encode AlgorithmIdentifier with optional parameters.                                  */
/* SEQUENCE { OID, params... }                                                                   */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _EncAlgIdWithParams(uint8_t *buf, uint32_t bufSize,
                                     const uint8_t *algOidRaw, uint32_t algOidRawLen,
                                     const uint8_t *params, uint32_t paramsLen)
{
    uint32_t innerLen;

    if (params == NULL || paramsLen == 0)
    {
        return _EncAlgId(buf, bufSize, algOidRaw, algOidRawLen);
    }

    innerLen = _EncOIDRaw(NULL, 0, algOidRaw, algOidRawLen) + paramsLen;
    {
    uint32_t total = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, innerLen);

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    {
        uint8_t innerBuf[64];
        uint32_t pos = 0;
        if (innerLen > sizeof(innerBuf)) return 0;
        pos += _EncOIDRaw(innerBuf, sizeof(innerBuf), algOidRaw, algOidRawLen);
        memcpy(&innerBuf[pos], params, paramsLen);
        pos += paramsLen;
        return _EncWrap(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, innerBuf, pos);
    }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a TBSCertificate.                                                                     */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFX509EncodeTBS(uint8_t *buf, uint32_t bufSize, const SSFX509GenParams_t *params)
{
    uint32_t innerLen = 0;
    uint32_t total;
    uint8_t innerBuf[SSF_X509_CONFIG_MAX_CERT_SIZE];
    uint32_t pos;

    SSF_REQUIRE(params != NULL);

    /* Measure inner content */

    /* version [0] EXPLICIT INTEGER */
    if (params->version >= 1u)
    {
        uint32_t verInt = _EncIntU64(NULL, 0, params->version);
        innerLen += _EncWrap(NULL, 0, SSF_ASN1_CONTEXT_EXPLICIT(0), NULL, verInt);
    }

    /* serial */
    innerLen += _EncInt(NULL, 0, params->serial, params->serialLen);

    /* signature algorithm (with optional PSS parameters) */
    innerLen += _EncAlgIdWithParams(NULL, 0, params->sigAlgOidRaw, params->sigAlgOidRawLen,
                                     params->sigAlgParams, params->sigAlgParamsLen);

    /* issuer */
    innerLen += _EncDN(NULL, 0, &params->issuer);

    /* validity: SEQUENCE { notBefore, notAfter } */
    {
        uint32_t nb = _EncUTCTime(NULL, 0, params->notBefore);
        uint32_t na = _EncUTCTime(NULL, 0, params->notAfter);
        innerLen += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, nb + na);
    }

    /* subject */
    innerLen += _EncDN(NULL, 0, &params->subject);

    /* subjectPublicKeyInfo: SEQUENCE { algorithm, BIT STRING } */
    {
        uint32_t algLen;
        if (params->ecCurveOidRaw != NULL)
        {
            /* EC: algorithm = SEQUENCE { OID(ecPublicKey), OID(curve) } */
            uint32_t algInner = _EncOIDRaw(NULL, 0, params->pubKeyAlgOidRaw,
                                                  params->pubKeyAlgOidRawLen) +
                                _EncOIDRaw(NULL, 0, params->ecCurveOidRaw,
                                                  params->ecCurveOidRawLen);
            algLen = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, algInner);
        }
        else
        {
            algLen = _EncAlgId(NULL, 0, params->pubKeyAlgOidRaw, params->pubKeyAlgOidRawLen);
        }
        uint32_t bsLen = _EncBitString(NULL, 0, params->pubKey, params->pubKeyLen, 0);
        innerLen += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, algLen + bsLen);
    }

    /* extensions [3] EXPLICIT SEQUENCE { ... } */
    if (params->version >= 2u && (params->addBasicConstraints || params->addKeyUsage ||
                                   params->addExtKeyUsage || params->addRawExt ||
                                   params->sanDNSNames != NULL || params->sanIPAddrs != NULL ||
                                   params->skid != NULL || params->akid != NULL ||
                                   params->addNameConstraints))
    {
        uint32_t extsInner = 0;

        if (params->addBasicConstraints)
        {
            /* basicConstraints: SEQUENCE { OID, critical, OCTET STRING { SEQUENCE { BOOL, INT? } } } */
            uint32_t bcSeqContent = 0;
            uint32_t bcSeq;
            if (params->isCA) bcSeqContent += _EncBool(NULL, 0, true);
            if (params->pathLenConstraint >= 0)
            {
                uint8_t plVal = (uint8_t)params->pathLenConstraint;
                bcSeqContent += _EncInt(NULL, 0, &plVal, 1u);
            }
            bcSeq = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, bcSeqContent);
            {
            uint32_t bcOctet = _EncOctetString(NULL, 0, NULL, bcSeq);
            uint32_t extInner = _EncOIDRaw(NULL, 0, _oidBasicConstraints,
                                                  sizeof(_oidBasicConstraints)) +
                                _EncBool(NULL, 0, true) + bcOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
            }
        }

        if (params->addKeyUsage)
        {
            uint8_t kuByte = (uint8_t)(params->keyUsageBits >> 8);
            uint32_t bsLen = _EncBitString(NULL, 0, &kuByte, 1, 0);
            uint32_t kuOctet = _EncOctetString(NULL, 0, NULL, bsLen);
            uint32_t extInner = _EncOIDRaw(NULL, 0, _oidKeyUsage, sizeof(_oidKeyUsage)) +
                                _EncBool(NULL, 0, true) + kuOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
        }

        if (params->addExtKeyUsage)
        {
            /* extKeyUsage: SEQUENCE { OID, OCTET STRING { SEQUENCE OF OID } } */
            uint32_t ekuSeqContent = 0;
            uint32_t ekuSeq;
            uint32_t ekuOctet;
            uint32_t extInner;
            if (params->ekuServerAuth)
                ekuSeqContent += _EncOIDRaw(NULL, 0, _oidEkuServerAuth,
                                                   sizeof(_oidEkuServerAuth));
            if (params->ekuClientAuth)
                ekuSeqContent += _EncOIDRaw(NULL, 0, _oidEkuClientAuth,
                                                   sizeof(_oidEkuClientAuth));
            ekuSeq = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, ekuSeqContent);
            ekuOctet = _EncOctetString(NULL, 0, NULL, ekuSeq);
            extInner = _EncOIDRaw(NULL, 0, _oidEKU, sizeof(_oidEKU)) + ekuOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
        }

        if (params->addRawExt)
        {
            uint32_t rawOctet = _EncOctetString(NULL, 0, NULL, params->rawExtValueLen);
            uint32_t extInner = _EncOIDRaw(NULL, 0, params->rawExtOid,
                                                  params->rawExtOidLen);
            if (params->rawExtCritical) extInner += _EncBool(NULL, 0, true);
            extInner += rawOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
        }

        if (params->sanDNSNames != NULL || params->sanIPAddrs != NULL)
        {
            uint32_t sanSeqContent = 0;
            /* Count DNS names */
            if (params->sanDNSNames != NULL)
            {
                const char **dns = params->sanDNSNames;
                while (*dns != NULL)
                {
                    uint32_t dnsLen = 0;
                    while ((*dns)[dnsLen] != '\0') dnsLen++;
                    /* [2] IMPLICIT: _EncTagLen measures tag + multi-byte length correctly */
                    sanSeqContent += _EncTagLen(NULL, 0, 0x82u, dnsLen) + dnsLen;
                    dns++;
                }
            }
            /* Count IP addresses */
            if (params->sanIPAddrs != NULL)
            {
                const uint8_t **ip = params->sanIPAddrs;
                while (*ip != NULL)
                {
                    sanSeqContent += _EncTagLen(NULL, 0, 0x87u, 4u) + 4u;
                    ip++;
                }
            }
            {
            uint32_t sanSeq = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, sanSeqContent);
            uint32_t sanOctet = _EncOctetString(NULL, 0, NULL, sanSeq);
            uint32_t extInner = _EncOIDRaw(NULL, 0, _oidSAN, sizeof(_oidSAN)) + sanOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
            }
        }

        if (params->skid != NULL && params->skidLen > 0)
        {
            uint32_t skidInnerOctet = _EncOctetString(NULL, 0, NULL, params->skidLen);
            uint32_t skidOctet = _EncOctetString(NULL, 0, NULL, skidInnerOctet);
            uint32_t extInner = _EncOIDRaw(NULL, 0, _oidSKID, sizeof(_oidSKID)) + skidOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
        }

        if (params->akid != NULL && params->akidLen > 0)
        {
            /* [0] IMPLICIT: tag(0x80) + multi-byte length + akidLen. _EncTagLen measures */
            /* the tag + length header correctly for payload sizes beyond 127 bytes.             */
            uint32_t akidTagged = _EncTagLen(NULL, 0, 0x80u, params->akidLen) +
                                   params->akidLen;
            uint32_t akidSeq = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, akidTagged);
            uint32_t akidOctet = _EncOctetString(NULL, 0, NULL, akidSeq);
            uint32_t extInner = _EncOIDRaw(NULL, 0, _oidAKID, sizeof(_oidAKID)) + akidOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
        }

        if (params->addNameConstraints)
        {
            /* Name Constraints (RFC 5280 §4.2.1.10) — always emitted as critical.               */
            uint32_t ncContent = 0;
            uint8_t pIdx;
            for (pIdx = 0; pIdx < 2u; pIdx++)
            {
                const char **dns = (pIdx == 0u) ? params->ncPermittedDNS : params->ncExcludedDNS;
                const uint8_t **ips = (pIdx == 0u) ? params->ncPermittedIPs : params->ncExcludedIPs;
                uint32_t subtreesLen = 0;
                bool hasAny = false;
                if (dns != NULL)
                {
                    while (*dns != NULL)
                    {
                        uint32_t dLen = 0;
                        while ((*dns)[dLen] != '\0') dLen++;
                        /* GeneralSubtree SEQUENCE { [2] 0x82 DNS } */
                        {
                        uint32_t gnLen = _EncTagLen(NULL, 0, 0x82u, dLen) + dLen;
                        subtreesLen += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, gnLen);
                        }
                        hasAny = true;
                        dns++;
                    }
                }
                if (ips != NULL)
                {
                    while (*ips != NULL)
                    {
                        /* GeneralSubtree SEQUENCE { [7] 0x87 IP(4)+Mask(4) = 8 bytes } */
                        uint32_t gnLen = _EncTagLen(NULL, 0, 0x87u, 8u) + 8u;
                        subtreesLen += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, gnLen);
                        hasAny = true;
                        ips++;
                    }
                }
                if (hasAny)
                {
                    /* [0] or [1] IMPLICIT GeneralSubtrees — replaces the SEQUENCE tag. */
                    uint8_t ctxTag = (pIdx == 0u) ?
                        (uint8_t)(SSF_ASN1_CONTEXT_EXPLICIT(0)) :
                        (uint8_t)(SSF_ASN1_CONTEXT_EXPLICIT(1));
                    ncContent += _EncWrap(NULL, 0, ctxTag, NULL, subtreesLen);
                }
            }
            {
            uint32_t ncSeq = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, ncContent);
            uint32_t ncOctet = _EncOctetString(NULL, 0, NULL, ncSeq);
            uint32_t extInner = _EncOIDRaw(NULL, 0, _oidNameConstraints,
                                                  sizeof(_oidNameConstraints)) +
                                _EncBool(NULL, 0, true) + ncOctet;
            extsInner += _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extInner);
            }
        }

        {
        uint32_t extsSeq = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, extsInner);
        innerLen += _EncWrap(NULL, 0, SSF_ASN1_CONTEXT_EXPLICIT(3), NULL, extsSeq);
        }
    }

    total = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, innerLen);
    if (buf == NULL) return total;
    if (bufSize < total || total > SSF_X509_CONFIG_MAX_CERT_SIZE) return 0;

    /* Second pass: actually encode into innerBuf, then wrap */
    pos = 0;

    /* version */
    if (params->version >= 1u)
    {
        uint8_t verBuf[8];
        uint32_t verLen = _EncIntU64(verBuf, sizeof(verBuf), params->version);
        pos += _EncWrap(&innerBuf[pos], sizeof(innerBuf) - pos,
                              SSF_ASN1_CONTEXT_EXPLICIT(0), verBuf, verLen);
    }

    /* serial */
    pos += _EncInt(&innerBuf[pos], sizeof(innerBuf) - pos, params->serial, params->serialLen);

    /* signature algorithm (with optional PSS parameters) */
    pos += _EncAlgIdWithParams(&innerBuf[pos], sizeof(innerBuf) - pos,
                                params->sigAlgOidRaw, params->sigAlgOidRawLen,
                                params->sigAlgParams, params->sigAlgParamsLen);

    /* issuer */
    pos += _EncDN(&innerBuf[pos], sizeof(innerBuf) - pos, &params->issuer);

    /* validity */
    {
        uint8_t valBuf[64];
        uint32_t valPos = 0;
        valPos += _EncUTCTime(&valBuf[valPos], sizeof(valBuf) - valPos, params->notBefore);
        valPos += _EncUTCTime(&valBuf[valPos], sizeof(valBuf) - valPos, params->notAfter);
        pos += _EncWrap(&innerBuf[pos], sizeof(innerBuf) - pos,
                              SSF_ASN1_TAG_SEQUENCE, valBuf, valPos);
    }

    /* subject */
    pos += _EncDN(&innerBuf[pos], sizeof(innerBuf) - pos, &params->subject);

    /* subjectPublicKeyInfo */
    {
        uint8_t spkiBuf[512];
        uint32_t spkiPos = 0;

        if (params->ecCurveOidRaw != NULL)
        {
            uint8_t algBuf[32];
            uint32_t algPos = 0;
            algPos += _EncOIDRaw(&algBuf[algPos], sizeof(algBuf) - algPos,
                                       params->pubKeyAlgOidRaw, params->pubKeyAlgOidRawLen);
            algPos += _EncOIDRaw(&algBuf[algPos], sizeof(algBuf) - algPos,
                                       params->ecCurveOidRaw, params->ecCurveOidRawLen);
            spkiPos += _EncWrap(&spkiBuf[spkiPos], sizeof(spkiBuf) - spkiPos,
                                      SSF_ASN1_TAG_SEQUENCE, algBuf, algPos);
        }
        else
        {
            spkiPos += _EncAlgId(&spkiBuf[spkiPos], sizeof(spkiBuf) - spkiPos,
                                 params->pubKeyAlgOidRaw, params->pubKeyAlgOidRawLen);
        }
        spkiPos += _EncBitString(&spkiBuf[spkiPos], sizeof(spkiBuf) - spkiPos,
                                       params->pubKey, params->pubKeyLen, 0);
        pos += _EncWrap(&innerBuf[pos], sizeof(innerBuf) - pos,
                              SSF_ASN1_TAG_SEQUENCE, spkiBuf, spkiPos);
    }

    /* extensions */
    if (params->version >= 2u && (params->addBasicConstraints || params->addKeyUsage ||
                                   params->addExtKeyUsage || params->addRawExt ||
                                   params->sanDNSNames != NULL || params->sanIPAddrs != NULL ||
                                   params->skid != NULL || params->akid != NULL ||
                                   params->addNameConstraints))
    {
        /* Extensions aggregate buffer. Sized for worst-case SAN extension (~3.1 KB for 12 x   */
        /* 253-byte DNS names) plus fixed-size extensions (BC, KU, EKU, SKID, AKID, rawExt,    */
        /* nameConstraints).                                                                     */
        uint8_t extsBuf[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t extsPos = 0;

        if (params->addBasicConstraints)
        {
            uint8_t extBuf[64];
            uint32_t extPos = 0;
            uint8_t bcSeqBuf[8];
            uint32_t bcSeqPos = 0;
            uint8_t bcOctetBuf[16];
            uint32_t bcOctetLen;

            if (params->isCA) bcSeqPos += _EncBool(&bcSeqBuf[bcSeqPos],
                                                          sizeof(bcSeqBuf) - bcSeqPos, true);
            if (params->pathLenConstraint >= 0)
            {
                uint8_t plBuf[4];
                uint8_t plVal = (uint8_t)params->pathLenConstraint;
                uint32_t plLen = _EncInt(&bcSeqBuf[bcSeqPos],
                                               sizeof(bcSeqBuf) - bcSeqPos, &plVal, 1u);
                bcSeqPos += plLen;
                (void)plBuf;
            }
            {
                uint8_t bcSeqWrapped[16];
                uint32_t bcSeqWrappedLen = _EncWrap(bcSeqWrapped, sizeof(bcSeqWrapped),
                                                           SSF_ASN1_TAG_SEQUENCE, bcSeqBuf, bcSeqPos);
                bcOctetLen = _EncOctetString(bcOctetBuf, sizeof(bcOctetBuf),
                                                    bcSeqWrapped, bcSeqWrappedLen);
            }
            extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                       _oidBasicConstraints, sizeof(_oidBasicConstraints));
            extPos += _EncBool(&extBuf[extPos], sizeof(extBuf) - extPos, true);
            memcpy(&extBuf[extPos], bcOctetBuf, bcOctetLen);
            extPos += bcOctetLen;
            extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                      SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
        }

        if (params->addKeyUsage)
        {
            uint8_t extBuf[32];
            uint32_t extPos = 0;
            uint8_t kuByte = (uint8_t)(params->keyUsageBits >> 8);
            uint8_t bsBuf[8];
            uint32_t bsLen = _EncBitString(bsBuf, sizeof(bsBuf), &kuByte, 1, 0);
            uint8_t octetBuf[16];
            uint32_t octetLen = _EncOctetString(octetBuf, sizeof(octetBuf), bsBuf, bsLen);

            extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                       _oidKeyUsage, sizeof(_oidKeyUsage));
            extPos += _EncBool(&extBuf[extPos], sizeof(extBuf) - extPos, true);
            memcpy(&extBuf[extPos], octetBuf, octetLen);
            extPos += octetLen;
            extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                      SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
        }

        if (params->addExtKeyUsage)
        {
            uint8_t extBuf[48];
            uint32_t extPos = 0;
            uint8_t ekuSeqBuf[32];
            uint32_t ekuSeqPos = 0;
            uint8_t ekuSeqWrapped[40];
            uint32_t ekuSeqWrappedLen;
            uint8_t octetBuf[48];
            uint32_t octetLen;

            if (params->ekuServerAuth)
            {
                ekuSeqPos += _EncOIDRaw(&ekuSeqBuf[ekuSeqPos],
                    sizeof(ekuSeqBuf) - ekuSeqPos,
                    _oidEkuServerAuth, sizeof(_oidEkuServerAuth));
            }
            if (params->ekuClientAuth)
            {
                ekuSeqPos += _EncOIDRaw(&ekuSeqBuf[ekuSeqPos],
                    sizeof(ekuSeqBuf) - ekuSeqPos,
                    _oidEkuClientAuth, sizeof(_oidEkuClientAuth));
            }

            ekuSeqWrappedLen = _EncWrap(ekuSeqWrapped, sizeof(ekuSeqWrapped),
                                               SSF_ASN1_TAG_SEQUENCE, ekuSeqBuf, ekuSeqPos);
            octetLen = _EncOctetString(octetBuf, sizeof(octetBuf),
                                              ekuSeqWrapped, ekuSeqWrappedLen);
            extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                       _oidEKU, sizeof(_oidEKU));
            memcpy(&extBuf[extPos], octetBuf, octetLen);
            extPos += octetLen;
            extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                      SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
        }

        if (params->addRawExt)
        {
            uint8_t extBuf[64];
            uint32_t extPos = 0;
            uint8_t octetBuf[48];
            uint32_t octetLen;

            extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                       params->rawExtOid, params->rawExtOidLen);
            if (params->rawExtCritical)
            {
                extPos += _EncBool(&extBuf[extPos], sizeof(extBuf) - extPos, true);
            }
            octetLen = _EncOctetString(octetBuf, sizeof(octetBuf),
                                              params->rawExtValue, params->rawExtValueLen);
            memcpy(&extBuf[extPos], octetBuf, octetLen);
            extPos += octetLen;
            extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                      SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
        }

        if (params->sanDNSNames != NULL || params->sanIPAddrs != NULL)
        {
            /* Buffers sized for SSF_X509_CONFIG_MAX_SAN_ENTRIES × 260 bytes each (DNS name      */
            /* max 253 + 7 bytes DER tag/len overhead) + wrap headroom. DER length encoding is   */
            /* multi-byte for lengths > 127 and must use _EncTagLen.                        */
            #define _UT_SAN_CONTENT_MAX  ((SSF_X509_CONFIG_MAX_SAN_ENTRIES) * 260u)
            uint8_t sanSeqBuf[_UT_SAN_CONTENT_MAX];
            uint32_t sanSeqPos = 0;
            uint8_t sanSeqWrapped[_UT_SAN_CONTENT_MAX + 8u];
            uint32_t sanSeqWrappedLen;
            uint8_t octetBuf[_UT_SAN_CONTENT_MAX + 16u];
            uint32_t octetLen;
            uint8_t extBuf[_UT_SAN_CONTENT_MAX + 32u];
            uint32_t extPos = 0;

            /* Encode DNS names as [2] IMPLICIT IA5String (0x82 primitive context tag) */
            if (params->sanDNSNames != NULL)
            {
                const char **dns = params->sanDNSNames;
                while (*dns != NULL)
                {
                    uint32_t dnsLen = 0;
                    while ((*dns)[dnsLen] != '\0') dnsLen++;
                    sanSeqPos += _EncTagLen(&sanSeqBuf[sanSeqPos],
                                                   sizeof(sanSeqBuf) - sanSeqPos,
                                                   0x82u, dnsLen);
                    if (sanSeqPos + dnsLen > sizeof(sanSeqBuf)) return 0;
                    memcpy(&sanSeqBuf[sanSeqPos], *dns, dnsLen);
                    sanSeqPos += dnsLen;
                    dns++;
                }
            }
            /* Encode IP addresses as [7] IMPLICIT OCTET STRING */
            if (params->sanIPAddrs != NULL)
            {
                const uint8_t **ip = params->sanIPAddrs;
                while (*ip != NULL)
                {
                    sanSeqPos += _EncTagLen(&sanSeqBuf[sanSeqPos],
                                                   sizeof(sanSeqBuf) - sanSeqPos,
                                                   0x87u, 4u);
                    if (sanSeqPos + 4u > sizeof(sanSeqBuf)) return 0;
                    memcpy(&sanSeqBuf[sanSeqPos], *ip, 4u);
                    sanSeqPos += 4u;
                    ip++;
                }
            }

            /* Wrap in SEQUENCE, then OCTET STRING */
            sanSeqWrappedLen = _EncWrap(sanSeqWrapped, sizeof(sanSeqWrapped),
                                               SSF_ASN1_TAG_SEQUENCE, sanSeqBuf, sanSeqPos);
            octetLen = _EncOctetString(octetBuf, sizeof(octetBuf),
                                              sanSeqWrapped, sanSeqWrappedLen);
            extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                       _oidSAN, sizeof(_oidSAN));
            if (extPos + octetLen > sizeof(extBuf)) return 0;
            memcpy(&extBuf[extPos], octetBuf, octetLen);
            extPos += octetLen;
            extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                      SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
            #undef _UT_SAN_CONTENT_MAX
        }

        if (params->skid != NULL && params->skidLen > 0)
        {
            /* Sized for keyIdentifiers up to 64 bytes (SHA-512 per RFC 7093). Each OCTET STRING */
            /* wrap adds 2-4 bytes of DER overhead. The original `innerOctetBuf[32]` silently    */
            /* truncated keyIdentifiers of 31+ bytes because _EncOctetString returned 0    */
            /* when over-capacity, emitting a cert with an empty SKID value.                     */
            #define _UT_KID_MAX 64u
            uint8_t extBuf[_UT_KID_MAX + 32u];
            uint32_t extPos = 0;
            uint8_t innerOctetBuf[_UT_KID_MAX + 8u];
            uint32_t innerOctetLen;
            uint8_t octetBuf[_UT_KID_MAX + 16u];
            uint32_t octetLen;

            if (params->skidLen > _UT_KID_MAX) return 0;

            innerOctetLen = _EncOctetString(innerOctetBuf, sizeof(innerOctetBuf),
                                                   params->skid, params->skidLen);
            octetLen = _EncOctetString(octetBuf, sizeof(octetBuf),
                                              innerOctetBuf, innerOctetLen);
            extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                       _oidSKID, sizeof(_oidSKID));
            if (extPos + octetLen > sizeof(extBuf)) return 0;
            memcpy(&extBuf[extPos], octetBuf, octetLen);
            extPos += octetLen;
            #undef _UT_KID_MAX

            extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                      SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
        }

        if (params->akid != NULL && params->akidLen > 0)
        {
            /* Buffers sized for keyIdentifiers up to 64 bytes (RFC 7093 SHA-256/SHA-384/SHA-512 */
            /* are 32/48/64 bytes respectively). Each wrapping layer adds ≤4 bytes of DER        */
            /* tag+length overhead. _EncTagLen emits the proper multi-byte length form for */
            /* payload sizes beyond 127 bytes — the old single-byte `(uint8_t)akidLen` produced  */
            /* invalid DER and an unbounded memcpy that could overflow the 32-byte scratch buf.   */
            #define _UT_KID_MAX 64u
            uint8_t akidSeqBuf[_UT_KID_MAX + 8u];
            uint32_t akidSeqPos = 0;
            uint8_t akidSeqWrapped[_UT_KID_MAX + 16u];
            uint32_t akidSeqWrappedLen;
            uint8_t octetBuf[_UT_KID_MAX + 20u];
            uint32_t octetLen;
            uint8_t extBuf[_UT_KID_MAX + 32u];
            uint32_t extPos = 0;

            if (params->akidLen > _UT_KID_MAX) return 0;

            /* [0] IMPLICIT: tag 0x80, multi-byte length (_EncTagLen), content */
            akidSeqPos += _EncTagLen(&akidSeqBuf[akidSeqPos],
                                            sizeof(akidSeqBuf) - akidSeqPos,
                                            0x80u, params->akidLen);
            if (akidSeqPos + params->akidLen > sizeof(akidSeqBuf)) return 0;
            memcpy(&akidSeqBuf[akidSeqPos], params->akid, params->akidLen);
            akidSeqPos += params->akidLen;

            akidSeqWrappedLen = _EncWrap(akidSeqWrapped, sizeof(akidSeqWrapped),
                                                SSF_ASN1_TAG_SEQUENCE,
                                                akidSeqBuf, akidSeqPos);
            octetLen = _EncOctetString(octetBuf, sizeof(octetBuf),
                                              akidSeqWrapped, akidSeqWrappedLen);
            extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                       _oidAKID, sizeof(_oidAKID));
            if (extPos + octetLen > sizeof(extBuf)) return 0;
            memcpy(&extBuf[extPos], octetBuf, octetLen);
            extPos += octetLen;
            #undef _UT_KID_MAX

            extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                      SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
        }

        if (params->addNameConstraints)
        {
            /* Sized for up to SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS × (~260) per subtree × 2    */
            /* subtrees + headers. Using a generous 512 × 8 = 4 KB pair of scratch buffers.     */
            #define _UT_NC_SUBTREE_MAX  (SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS * 260u + 16u)
            uint8_t subtreesBuf[_UT_NC_SUBTREE_MAX];
            uint8_t ncContentBuf[(_UT_NC_SUBTREE_MAX + 8u) * 2u + 8u];
            uint32_t ncContentPos = 0;
            uint8_t pIdx;

            for (pIdx = 0; pIdx < 2u; pIdx++)
            {
                const char **dns = (pIdx == 0u) ? params->ncPermittedDNS : params->ncExcludedDNS;
                const uint8_t **ips = (pIdx == 0u) ? params->ncPermittedIPs : params->ncExcludedIPs;
                uint32_t subtreesPos = 0;
                bool hasAny = false;

                /* Build GeneralSubtree SEQUENCE entries inside subtreesBuf. */
                if (dns != NULL)
                {
                    while (*dns != NULL)
                    {
                        uint32_t dLen = 0;
                        uint8_t gnBuf[260];
                        uint32_t gnPos = 0;
                        while ((*dns)[dLen] != '\0') dLen++;
                        gnPos += _EncTagLen(&gnBuf[gnPos], sizeof(gnBuf) - gnPos,
                                                   0x82u, dLen);
                        if (gnPos + dLen > sizeof(gnBuf)) return 0;
                        memcpy(&gnBuf[gnPos], *dns, dLen);
                        gnPos += dLen;
                        subtreesPos += _EncWrap(&subtreesBuf[subtreesPos],
                                                      sizeof(subtreesBuf) - subtreesPos,
                                                      SSF_ASN1_TAG_SEQUENCE, gnBuf, gnPos);
                        hasAny = true;
                        dns++;
                    }
                }
                if (ips != NULL)
                {
                    while (*ips != NULL)
                    {
                        uint8_t gnBuf[16];
                        uint32_t gnPos = 0;
                        gnPos += _EncTagLen(&gnBuf[gnPos], sizeof(gnBuf) - gnPos,
                                                   0x87u, 8u);
                        memcpy(&gnBuf[gnPos], *ips, 8u);
                        gnPos += 8u;
                        subtreesPos += _EncWrap(&subtreesBuf[subtreesPos],
                                                      sizeof(subtreesBuf) - subtreesPos,
                                                      SSF_ASN1_TAG_SEQUENCE, gnBuf, gnPos);
                        hasAny = true;
                        ips++;
                    }
                }
                if (hasAny)
                {
                    uint8_t ctxTag = (pIdx == 0u) ?
                        (uint8_t)(SSF_ASN1_CONTEXT_EXPLICIT(0)) :
                        (uint8_t)(SSF_ASN1_CONTEXT_EXPLICIT(1));
                    ncContentPos += _EncWrap(&ncContentBuf[ncContentPos],
                                                    sizeof(ncContentBuf) - ncContentPos,
                                                    ctxTag, subtreesBuf, subtreesPos);
                }
            }

            {
                uint8_t ncSeqBuf[sizeof(ncContentBuf) + 8u];
                uint32_t ncSeqLen = _EncWrap(ncSeqBuf, sizeof(ncSeqBuf),
                                                    SSF_ASN1_TAG_SEQUENCE,
                                                    ncContentBuf, ncContentPos);
                uint8_t octetBuf[sizeof(ncSeqBuf) + 8u];
                uint32_t octetLen = _EncOctetString(octetBuf, sizeof(octetBuf),
                                                           ncSeqBuf, ncSeqLen);
                uint8_t extBuf[sizeof(octetBuf) + 16u];
                uint32_t extPos = 0;
                extPos += _EncOIDRaw(&extBuf[extPos], sizeof(extBuf) - extPos,
                                           _oidNameConstraints, sizeof(_oidNameConstraints));
                extPos += _EncBool(&extBuf[extPos], sizeof(extBuf) - extPos, true);
                if (extPos + octetLen > sizeof(extBuf)) return 0;
                memcpy(&extBuf[extPos], octetBuf, octetLen);
                extPos += octetLen;
                extsPos += _EncWrap(&extsBuf[extsPos], sizeof(extsBuf) - extsPos,
                                          SSF_ASN1_TAG_SEQUENCE, extBuf, extPos);
            }
            #undef _UT_NC_SUBTREE_MAX
        }

        {
            /* extsSeqBuf wraps the entire extensions block. Sized to match extsBuf above plus */
            /* SEQUENCE header. */
            uint8_t extsSeqBuf[SSF_X509_CONFIG_MAX_CERT_SIZE + 8u];
            uint32_t extsSeqLen = _EncWrap(extsSeqBuf, sizeof(extsSeqBuf),
                                                  SSF_ASN1_TAG_SEQUENCE, extsBuf, extsPos);
            pos += _EncWrap(&innerBuf[pos], sizeof(innerBuf) - pos,
                                  SSF_ASN1_CONTEXT_EXPLICIT(3), extsSeqBuf, extsSeqLen);
        }
    }

    return _EncWrap(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, innerBuf, pos);
}

/* --------------------------------------------------------------------------------------------- */
/* Encodes a complete Certificate: SEQUENCE { TBS, signatureAlgorithm, signatureValue }.          */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFX509EncodeCert(uint8_t *buf, uint32_t bufSize, const SSFX509GenParams_t *params,
                           const uint8_t *signature, uint32_t signatureLen)
{
    uint32_t tbsLen;
    uint32_t algLen;
    uint32_t sigLen;
    uint32_t innerLen;
    uint32_t total;

    SSF_REQUIRE(params != NULL);
    SSF_REQUIRE(signature != NULL);

    tbsLen = SSFX509EncodeTBS(NULL, 0, params);
    algLen = _EncAlgIdWithParams(NULL, 0, params->sigAlgOidRaw, params->sigAlgOidRawLen,
                                  params->sigAlgParams, params->sigAlgParamsLen);
    sigLen = _EncBitString(NULL, 0, signature, signatureLen, 0);
    innerLen = tbsLen + algLen + sigLen;
    total = _EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, NULL, innerLen);

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    {
        uint8_t innerBuf[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t pos = 0;

        pos += SSFX509EncodeTBS(&innerBuf[pos], sizeof(innerBuf) - pos, params);
        pos += _EncAlgIdWithParams(&innerBuf[pos], sizeof(innerBuf) - pos,
                                    params->sigAlgOidRaw, params->sigAlgOidRawLen,
                                    params->sigAlgParams, params->sigAlgParamsLen);
        pos += _EncBitString(&innerBuf[pos], sizeof(innerBuf) - pos,
                                   signature, signatureLen, 0);

        return _EncWrap(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, innerBuf, pos);
    }
}

/* ========================================================================================== */
/* ADDITIONAL OID HELPERS                                                                     */
/* ========================================================================================== */

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsP384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->ecCurveOidRaw, cert->ecCurveOidRawLen,
                     _oidP384, sizeof(_oidP384));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsECDSASHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidEcdsaSHA384, sizeof(_oidEcdsaSHA384));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPSSSHA256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPSS, sizeof(_oidRSAPSS));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPSSSHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPSS, sizeof(_oidRSAPSS));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPKCS1SHA256, sizeof(_oidRSAPKCS1SHA256));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPKCS1SHA384, sizeof(_oidRSAPKCS1SHA384));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA512(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPKCS1SHA512, sizeof(_oidRSAPKCS1SHA512));
}

/* --------------------------------------------------------------------------------------------- */
/* SSFX509IsEd25519                                                                              */
/* Returns true if cert signature algorithm is Ed25519 (RFC 8410, OID 1.3.101.112).              */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsEd25519(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidEd25519, sizeof(_oidEd25519));
}

/* ========================================================================================== */
/* CHAIN VERIFICATION                                                                         */
/* ========================================================================================== */

/* --------------------------------------------------------------------------------------------- */
/* Helper: match a hostname against a SAN dNSName entry.                                         */
/* Simple case-insensitive comparison (no wildcard support).                                      */
/* --------------------------------------------------------------------------------------------- */
static bool _HostnameMatch(const char *hostname, const uint8_t *sanVal, uint32_t sanValLen)
{
    uint32_t hostLen;

    SSF_ASSERT(hostname != NULL);
    SSF_ASSERT(sanVal != NULL);

    hostLen = 0;
    while (hostname[hostLen] != '\0') hostLen++;

    /* Wildcard matching: *.example.com matches www.example.com (RFC 6125 Section 6.4.3).        */
    /* Additional guard (CA/Browser Forum BRs §3.2.2.6): the base domain after "*." must contain */
    /* at least one interior '.' so that the wildcard sits below a reasonably specific label.    */
    /* This rejects "*.com", "*.net", etc. which would otherwise match any second-level domain.  */
    /* Multi-label public suffixes (e.g. "*.co.uk") are not covered by this heuristic and remain */
    /* accepted; a Public Suffix List integration would close that remaining gap.                 */
    if (sanValLen >= 2u && sanVal[0] == '*' && sanVal[1] == '.')
    {
        /* Find the first '.' in the hostname */
        const char *dot = hostname;
        while (*dot != '\0' && *dot != '.') dot++;
        if (*dot == '.')
        {
            /* Compare the domain part after the first dot */
            uint32_t domainLen = hostLen - (uint32_t)(dot - hostname);
            uint32_t sanDomainLen = sanValLen - 2u; /* skip "*." */
            if (domainLen == sanDomainLen + 1u) /* +1 for the dot */
            {
                /* Label-count floor: the SAN's base (bytes after "*.") must contain a dot. */
                uint32_t b;
                bool baseHasDot = false;
                for (b = 2u; b < sanValLen; b++)
                {
                    if (sanVal[b] == (uint8_t)'.') { baseHasDot = true; break; }
                }
                if (!baseHasDot) return false;
                return SSFMatchStrNI(dot, (SSFCStrIn_t)&sanVal[1], sanDomainLen + 1u);
            }
        }
        return false;
    }

    /* Exact match (case-insensitive) */
    if (hostLen != sanValLen) return false;
    return SSFMatchStrNI(hostname, (SSFCStrIn_t)sanVal, hostLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: parse an IPv4 dotted-decimal string into 4 bytes. Returns true if valid.              */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseIPv4(const char *str, uint8_t ipOut[4])
{
    uint32_t octet;
    uint32_t i;
    uint32_t digitCount;

    for (i = 0; i < 4u; i++)
    {
        octet = 0;
        digitCount = 0;
        while (*str >= '0' && *str <= '9')
        {
            octet = octet * 10u + (uint32_t)(*str - '0');
            if (octet > 255u) return false;
            str++;
            digitCount++;
        }
        if (digitCount == 0u) return false;
        ipOut[i] = (uint8_t)octet;
        if (i < 3u)
        {
            if (*str != '.') return false;
            str++;
        }
    }
    return (*str == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: match a hostname string against a SAN iPAddress entry (RFC 5280 Section 4.2.1.6).     */
/* --------------------------------------------------------------------------------------------- */
static bool _IPAddressMatch(const char *hostname, const uint8_t *sanIP, uint32_t sanIPLen)
{
    uint8_t parsedIP[4];

    /* Only support IPv4 (4 bytes) */
    if (sanIPLen != 4u) return false;

    /* Try to parse hostname as IPv4 */
    if (!_ParseIPv4(hostname, parsedIP)) return false;

    return (memcmp(parsedIP, sanIP, 4u) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Public wrapper for IP address SAN matching.                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509MatchIPAddress(const char *hostname, const uint8_t *sanIP, uint32_t sanIPLen)
{
    SSF_REQUIRE(hostname != NULL);
    SSF_REQUIRE(sanIP != NULL);
    return _IPAddressMatch(hostname, sanIP, sanIPLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Verify the signature on cert using issuer's public key.                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifyCertSignature(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer)
{
    SSF_REQUIRE(cert != NULL);
    SSF_REQUIRE(issuer != NULL);
    SSF_REQUIRE(cert->tbsRaw != NULL);
    SSF_REQUIRE(cert->signature != NULL);

    /* Determine signature algorithm and hash the TBS */
    if (SSFX509IsECDSA(cert) || SSFX509IsECDSASHA384(cert))
    {
        /* ECDSA signature. Per RFC 5758 §3.2: the sigAlg OID specifies the HASH; the curve    */
        /* comes from the ISSUER's SubjectPublicKeyInfo. The two are independent — e.g.         */
        /* ecdsa-with-SHA256 may pair with a P-384 public key (real-world example: SSL.com Root */
        /* Certification Authority ECC).                                                          */
        SSFECCurve_t curve;
        uint8_t hash[SSF_SHA2_384_BYTE_SIZE];
        size_t hashLen;

        /* Hash from sigAlg */
        if (SSFX509IsECDSA(cert))
        {
            hashLen = SSF_SHA2_256_BYTE_SIZE;
            SSFSHA256(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
        }
        else
        {
            hashLen = SSF_SHA2_384_BYTE_SIZE;
            SSFSHA384(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
        }

        /* Curve from the issuer's SPKI (ecCurveOidRaw is the parameter of id-ecPublicKey). */
        if (SSFX509IsP256(issuer))
        {
            curve = SSF_EC_CURVE_P256;
        }
        else if (SSFX509IsP384(issuer))
        {
            curve = SSF_EC_CURVE_P384;
        }
        else
        {
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "VerifyCertSig: ECDSA issuer curve OID not recognized (%u bytes)",
                issuer->ecCurveOidRawLen);
            return false;
        }

        /* The issuer's pubKey is the BIT STRING content (unused-bits byte already stripped by    */
        /* parser). It is SEC 1 uncompressed: 0x04 || X || Y.                                    */
        {
            bool ok = SSFECDSAVerify(curve, issuer->pubKey, (size_t)issuer->pubKeyLen,
                                     hash, hashLen, cert->signature, (size_t)cert->signatureLen);
            SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx, "VerifyCertSig: ECDSA curve=%d pubKeyLen=%u sigLen=%u -> %s",
                          curve, issuer->pubKeyLen, cert->signatureLen, ok ? "OK" : "FAIL");
            return ok;
        }
    }
    else if (SSFX509IsRSAPKCS1SHA256(cert) || SSFX509IsRSAPKCS1SHA384(cert) ||
             SSFX509IsRSAPKCS1SHA512(cert))
    {
        /* RSA PKCS#1 v1.5 signature */
        SSFRSAHash_t rsaHash;
        uint8_t hash[SSF_SHA2_512_BYTE_SIZE];
        size_t hashLen;

        if (SSFX509IsRSAPKCS1SHA256(cert))
        {
            rsaHash = SSF_RSA_HASH_SHA256;
            hashLen = SSF_SHA2_256_BYTE_SIZE;
            SSFSHA256(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
        }
        else if (SSFX509IsRSAPKCS1SHA384(cert))
        {
            rsaHash = SSF_RSA_HASH_SHA384;
            hashLen = SSF_SHA2_384_BYTE_SIZE;
            SSFSHA384(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
        }
        else
        {
            rsaHash = SSF_RSA_HASH_SHA512;
            hashLen = SSF_SHA2_512_BYTE_SIZE;
            SSFSHA512(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
        }

        /* The issuer's pubKey is the BIT STRING content of the SPKI, which for RSA is the       */
        /* DER-encoded RSAPublicKey (SEQUENCE { INTEGER n, INTEGER e }).                          */
        {
            bool ok = SSFRSAVerifyPKCS1(issuer->pubKey, (size_t)issuer->pubKeyLen,
                                        rsaHash, hash, hashLen,
                                        cert->signature, (size_t)cert->signatureLen);
            SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx, "VerifyCertSig: RSA-PKCS1 hash=%d pubKeyLen=%u sigLen=%u -> %s",
                          rsaHash, issuer->pubKeyLen, cert->signatureLen, ok ? "OK" : "FAIL");
            return ok;
        }
    }
    else if (SSFX509IsRSAPSSSHA256(cert))
    {
        /* RSA-PSS signature — determine hash algorithm from PSS parameters (RFC 4055).          */
        SSFRSAHash_t rsaHash;
        uint8_t hash[SSF_SHA2_512_BYTE_SIZE];
        size_t hashLen;

        rsaHash = _ParsePSSHashAlg(cert->sigAlgParams, cert->sigAlgParamsLen);

        switch (rsaHash)
        {
            case SSF_RSA_HASH_SHA256:
                hashLen = SSF_SHA2_256_BYTE_SIZE;
                SSFSHA256(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
                break;
            case SSF_RSA_HASH_SHA384:
                hashLen = SSF_SHA2_384_BYTE_SIZE;
                SSFSHA384(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
                break;
            case SSF_RSA_HASH_SHA512:
                hashLen = SSF_SHA2_512_BYTE_SIZE;
                SSFSHA512(cert->tbsRaw, cert->tbsRawLen, hash, (uint32_t)hashLen);
                break;
            default:
                return false;
        }

        {
            bool ok = SSFRSAVerifyPSS(issuer->pubKey, (size_t)issuer->pubKeyLen,
                                       rsaHash, hash, hashLen,
                                       cert->signature, (size_t)cert->signatureLen);
            SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx, "VerifyCertSig: RSA-PSS hash=%d pubKeyLen=%u sigLen=%u -> %s",
                          rsaHash, issuer->pubKeyLen, cert->signatureLen, ok ? "OK" : "FAIL");
            return ok;
        }
    }

    else if (SSFX509IsEd25519(cert))
    {
        /* Ed25519 signs the raw message (TBS), not a pre-hash. RFC 8410.                         */
        /* The issuer's subjectPublicKey (BIT STRING content) is the 32-byte compressed Edwards   */
        /* point. Signature is 64 bytes.                                                          */
        bool ok;
        if (issuer->pubKeyLen != SSF_ED25519_PUB_KEY_SIZE ||
            cert->signatureLen != SSF_ED25519_SIG_SIZE)
        {
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                          "VerifyCertSig: Ed25519 bad key/sig size (pubKey=%u sig=%u)",
                          issuer->pubKeyLen, cert->signatureLen);
            return false;
        }
        ok = SSFEd25519Verify(issuer->pubKey, cert->tbsRaw, cert->tbsRawLen, cert->signature);
        SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx, "VerifyCertSig: Ed25519 pubKeyLen=%u sigLen=%u -> %s",
                      issuer->pubKeyLen, cert->signatureLen, ok ? "OK" : "FAIL");
        return ok;
    }

    /* Unsupported signature algorithm */
    SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "VerifyCertSig: unsupported sigAlg OID (%u bytes)",
                  cert->sigAlgOidRawLen);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Check SKID/AKID consistency. Returns true if consistent (match or either absent).             */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509CheckSKIDAKID(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer)
{
    SSF_REQUIRE(cert != NULL);
    SSF_REQUIRE(issuer != NULL);

    if (cert->akid == NULL || cert->akidLen == 0) return true;
    if (issuer->skid == NULL || issuer->skidLen == 0) return true;

    if (cert->akidLen != issuer->skidLen) return false;
    return (memcmp(cert->akid, issuer->skid, cert->akidLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Name Constraints matching helpers (RFC 5280 Section 4.2.1.10)                                 */
/* --------------------------------------------------------------------------------------------- */

/* Match a DNS name against a dNSName constraint per RFC 5280 §4.2.1.10.                         */
/* Constraint "example.com" matches "example.com" and "*.example.com" sub-labels (e.g.            */
/* "foo.example.com") but not "notexample.com". Empty constraint matches any name.                */
static bool _NCDNSMatch(const uint8_t *name, uint32_t nameLen,
                         const uint8_t *constraint, uint32_t constraintLen)
{
    if (constraintLen == 0u) return true;
    if (nameLen < constraintLen) return false;
    {
        uint32_t offset = nameLen - constraintLen;
        /* Exact match: offset == 0. Otherwise the char before the suffix must be '.' so that    */
        /* the constraint applies at a label boundary (prevents "notexample.com" matching        */
        /* "example.com").                                                                        */
        if (offset != 0u && name[offset - 1u] != (uint8_t)'.') return false;
        return SSFMatchStrNI((const char *)&name[offset],
                              (SSFCStrIn_t)constraint, constraintLen);
    }
}

/* Match an IPv4 address against an iPAddress constraint (8 bytes: addr(4) || mask(4)).          */
static bool _NCIPMatch(const uint8_t *ip, uint32_t ipLen,
                        const uint8_t *constraint, uint32_t constraintLen)
{
    if (ipLen == 4u && constraintLen == 8u)
    {
        uint32_t i;
        for (i = 0; i < 4u; i++)
        {
            if ((ip[i] & constraint[4u + i]) != (constraint[i] & constraint[4u + i]))
                return false;
        }
        return true;
    }
    /* IPv6 (16 + 16 bytes) support could be added when IPv6 SANs are supported. */
    return false;
}

/* Validate that a subordinate cert's SANs conform to the NC of an ancestor cert.                */
/* Returns true if the cert is acceptable; false if any SAN violates permitted or excluded.      */
/* The ancestor's name-constraint arrays must describe valid (type, val, valLen) entries.         */
static bool _NCValidateCert(const SSFX509Cert_t *subCert, const SSFX509Cert_t *ncCert)
{
    uint8_t s;

    for (s = 0; s < subCert->sanLen; s++)
    {
        const SSFX509SAN_t *san = &subCert->san[s];
        uint8_t k;

        /* Check excluded: any match means reject. */
        for (k = 0; k < ncCert->excludedLen; k++)
        {
            const SSFX509NameConstraint_t *c = &ncCert->excludedSubtrees[k];
            if (c->type != san->type) continue;
            if (c->type == SSF_X509_SAN_DNS)
            {
                if (_NCDNSMatch(san->val, san->valLen, c->val, c->valLen)) return false;
            }
            else if (c->type == SSF_X509_SAN_IP)
            {
                if (_NCIPMatch(san->val, san->valLen, c->val, c->valLen)) return false;
            }
        }

        /* Check permitted: if any permitted entry of the SAN's type exists, at least one must  */
        /* match. If no permitted entry of the SAN's type exists, that type is unrestricted.     */
        {
            bool typeHasPermitted = false;
            bool typeMatched = false;
            for (k = 0; k < ncCert->permittedLen; k++)
            {
                const SSFX509NameConstraint_t *c = &ncCert->permittedSubtrees[k];
                if (c->type != san->type) continue;
                typeHasPermitted = true;
                if (c->type == SSF_X509_SAN_DNS)
                {
                    if (_NCDNSMatch(san->val, san->valLen, c->val, c->valLen))
                    {
                        typeMatched = true;
                        break;
                    }
                }
                else if (c->type == SSF_X509_SAN_IP)
                {
                    if (_NCIPMatch(san->val, san->valLen, c->val, c->valLen))
                    {
                        typeMatched = true;
                        break;
                    }
                }
            }
            if (typeHasPermitted && !typeMatched) return false;
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Verify a certificate chain.                                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifyChain(const uint8_t **chainDer, const uint32_t *chainDerLen,
                        uint8_t chainLen,
                        const uint8_t **trustDer, const uint32_t *trustDerLen,
                        uint8_t trustCount,
                        const char *hostname, uint64_t nowUnixSec)
{
    SSFX509Cert_t certs[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    uint8_t i;
    uint8_t j;

    SSF_REQUIRE(chainDer != NULL);
    SSF_REQUIRE(chainDerLen != NULL);
    SSF_REQUIRE(chainLen >= 1u);
    SSF_REQUIRE(chainLen <= SSF_X509_CONFIG_MAX_CHAIN_DEPTH);
    SSF_REQUIRE(trustDer != NULL);
    SSF_REQUIRE(trustDerLen != NULL);
    SSF_REQUIRE(trustCount >= 1u);
    SSF_REQUIRE(hostname != NULL);

    /* Parse all chain certificates */
    for (i = 0; i < chainLen; i++)
    {
        SSF_REQUIRE(chainDer[i] != NULL);
        if (!SSFX509Parse(chainDer[i], chainDerLen[i], &certs[i]))
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: parse cert[%u] failed (%u bytes)", i, chainDerLen[i]);
          return false; }
    }

    /* Reject v1/v2 certificates (RFC 5280 Section 6.1.1(c): all certs must be v3) */
    for (i = 0; i < chainLen; i++)
    {
        if (certs[i].version < 2u)
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: cert[%u] is v%u (must be v3)",
                        i, certs[i].version + 1u);
          return false; }
    }

    /* Verify signature algorithm consistency (RFC 5280 Section 4.1.2.3) */
    for (i = 0; i < chainLen; i++)
    {
        if (certs[i].outerSigAlgOidRaw != NULL && certs[i].sigAlgOidRaw != NULL)
        {
            if (certs[i].sigAlgOidRawLen != certs[i].outerSigAlgOidRawLen ||
                memcmp(certs[i].sigAlgOidRaw, certs[i].outerSigAlgOidRaw,
                       certs[i].sigAlgOidRawLen) != 0)
            { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                  "Chain: cert[%u] TBS sigAlg OID (%u bytes) != outer sigAlg OID (%u bytes)",
                  i, certs[i].sigAlgOidRawLen, certs[i].outerSigAlgOidRawLen);
              return false; }
        }
    }

    /* Verify temporal validity of each certificate */
    for (i = 0; i < chainLen; i++)
    {
        if (!SSFX509IsValid(&certs[i], nowUnixSec))
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: cert[%u] not valid at time %llu (notBefore=%llu notAfter=%llu)",
                        i, (unsigned long long)nowUnixSec,
                        (unsigned long long)certs[i].notBefore,
                        (unsigned long long)certs[i].notAfter);
          return false; }
    }

    /* Verify signature chain: cert[i] signed by cert[i+1] */
    for (i = 0; i < (uint8_t)(chainLen - 1u); i++)
    {
        if (!SSFX509VerifyCertSignature(&certs[i], &certs[i + 1u]))
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: cert[%u] signature by cert[%u] FAILED", i, i + 1u);
          return false; }

        /* RFC 5280 Section 4.2.1.1: SKID/AKID cross-check.                                    */
        /* If cert[i] has AKID and cert[i+1] has SKID, they must match.                         */
        if (certs[i].akid != NULL && certs[i].akidLen > 0 &&
            certs[i + 1u].skid != NULL && certs[i + 1u].skidLen > 0)
        {
            if (certs[i].akidLen != certs[i + 1u].skidLen ||
                memcmp(certs[i].akid, certs[i + 1u].skid, certs[i].akidLen) != 0)
            { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                  "Chain: cert[%u] AKID (%u bytes) does not match cert[%u] SKID (%u bytes)",
                  i, certs[i].akidLen, i + 1u, certs[i + 1u].skidLen);
              return false; }
        }
    }

    /* Also cross-check AKID/SKID between last chain cert and trust anchor */

    /* Verify the last chain cert against a trust anchor */
    {
        bool trusted = false;
        SSFX509Cert_t trustCert;

        for (j = 0; j < trustCount; j++)
        {
            SSF_REQUIRE(trustDer[j] != NULL);
            if (!SSFX509Parse(trustDer[j], trustDerLen[j], &trustCert)) continue;

            /* Match by subject name (raw DER comparison) */
            if (certs[chainLen - 1u].issuer.raw == NULL || trustCert.subject.raw == NULL) continue;
            if (certs[chainLen - 1u].issuer.rawLen != trustCert.subject.rawLen) continue;
            if (memcmp(certs[chainLen - 1u].issuer.raw, trustCert.subject.raw,
                       trustCert.subject.rawLen) != 0) continue;

            /* Verify validity of the trust anchor */
            if (!SSFX509IsValid(&trustCert, nowUnixSec)) continue;

            /* SKID/AKID cross-check between last chain cert and trust anchor */
            if (certs[chainLen - 1u].akid != NULL && certs[chainLen - 1u].akidLen > 0 &&
                trustCert.skid != NULL && trustCert.skidLen > 0)
            {
                if (certs[chainLen - 1u].akidLen != trustCert.skidLen ||
                    memcmp(certs[chainLen - 1u].akid, trustCert.skid,
                           certs[chainLen - 1u].akidLen) != 0)
                {
                    continue; /* AKID/SKID mismatch — try next trust anchor */
                }
            }

            /* Verify the last chain cert's signature using the trust anchor's public key */
            if (SSFX509VerifyCertSignature(&certs[chainLen - 1u], &trustCert))
            {
                trusted = true;
                break;
            }
        }
        if (!trusted)
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: no trust anchor found for issuer of cert[%u] (%u CAs checked)",
                        chainLen - 1u, trustCount);
          return false; }
    }

    /* Verify intermediate certificates have isCA=true and pathLenConstraint */
    for (i = 1; i < chainLen; i++)
    {
        if (!certs[i].hasBasicConstraints || !certs[i].isCA)
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: cert[%u] not a CA (hasBC=%d isCA=%d)",
                        i, certs[i].hasBasicConstraints, certs[i].isCA);
          return false; }

        /* RFC 5280 Section 6.1.4(h): if Key Usage present, keyCertSign required */
        if (certs[i].hasKeyUsage &&
            (certs[i].keyUsageBits & SSF_X509_KU_KEY_CERT_SIGN) == 0)
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
              "Chain: cert[%u] is CA but Key Usage lacks keyCertSign (KU=0x%04X)",
              i, certs[i].keyUsageBits);
          return false; }

        /* RFC 5280 Section 6.1.4(k): path length constraint enforcement.       */
        /* cert[i] is a CA at position i. Below it are CAs cert[1]..cert[i-1].  */
        /* The number of subordinate CAs below cert[i] is (i - 1).              */
        if (certs[i].pathLenConstraint >= 0)
        {
            if ((int8_t)(i - 1u) > certs[i].pathLenConstraint)
            { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                  "Chain: cert[%u] pathLenConstraint=%d but %u subordinate CAs present",
                  i, certs[i].pathLenConstraint, i - 1u);
              return false; }
        }
    }

    /* Also check the trust anchor's pathLenConstraint against the full chain */
    {
        SSFX509Cert_t trustCertCheck;
        for (j = 0; j < trustCount; j++)
        {
            if (!SSFX509Parse(trustDer[j], trustDerLen[j], &trustCertCheck)) continue;
            if (trustCertCheck.issuer.raw == NULL || certs[chainLen - 1u].issuer.raw == NULL)
                continue;
            if (trustCertCheck.subject.rawLen != certs[chainLen - 1u].issuer.rawLen) continue;
            if (memcmp(trustCertCheck.subject.raw, certs[chainLen - 1u].issuer.raw,
                       trustCertCheck.subject.rawLen) != 0) continue;

            /* This is the matching trust anchor — check its pathLenConstraint   */
            /* The number of subordinate CAs below the trust anchor is chainLen-1*/
            /* (all chain certs except the leaf are CAs).                        */
            if (trustCertCheck.pathLenConstraint >= 0)
            {
                uint8_t numSubCAs = (chainLen >= 2u) ? (uint8_t)(chainLen - 1u) : 0u;
                if ((int8_t)numSubCAs > trustCertCheck.pathLenConstraint)
                { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                      "Chain: trust anchor pathLenConstraint=%d but %u subordinate CAs in chain",
                      trustCertCheck.pathLenConstraint, numSubCAs);
                  return false; }
            }
            break;
        }
    }

    /* Verify Extended Key Usage on leaf cert (RFC 5280 Section 4.2.1.12) */
    /* If EKU is present, it must include serverAuth for server verification.                    */
    /* If EKU is absent, the cert is unrestricted and allowed for any purpose.                   */
    if (certs[0].hasExtKeyUsage && !certs[0].ekuServerAuth)
    { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
          "Chain: leaf cert has EKU but lacks serverAuth (serverAuth=%d clientAuth=%d)",
          certs[0].ekuServerAuth, certs[0].ekuClientAuth);
      return false; }

    /* RFC 5280 Section 6.1.4(g): enforce Name Constraints across the chain.                     */
    /* For each cert with a nameConstraints extension, all subordinate certs (those below it in  */
    /* the chain) must have SANs that fall within permittedSubtrees and outside excludedSubtrees.*/
    for (i = 1; i < chainLen; i++)
    {
        uint8_t jj;
        if (!certs[i].hasNameConstraints) continue;
        for (jj = 0; jj < i; jj++)
        {
            if (!_NCValidateCert(&certs[jj], &certs[i]))
            { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                  "Chain: cert[%u] SAN violates nameConstraints of cert[%u]", jj, i);
              return false; }
        }
    }

    /* Also enforce the trust anchor's nameConstraints against the entire chain. */
    {
        SSFX509Cert_t trustCertNC;
        for (j = 0; j < trustCount; j++)
        {
            if (!SSFX509Parse(trustDer[j], trustDerLen[j], &trustCertNC)) continue;
            if (trustCertNC.subject.raw == NULL || certs[chainLen - 1u].issuer.raw == NULL)
                continue;
            if (trustCertNC.subject.rawLen != certs[chainLen - 1u].issuer.rawLen) continue;
            if (memcmp(trustCertNC.subject.raw, certs[chainLen - 1u].issuer.raw,
                       trustCertNC.subject.rawLen) != 0) continue;

            /* Matching trust anchor — enforce its name constraints against every chain cert. */
            if (trustCertNC.hasNameConstraints)
            {
                uint8_t jj;
                for (jj = 0; jj < chainLen; jj++)
                {
                    if (!_NCValidateCert(&certs[jj], &trustCertNC))
                    { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                          "Chain: cert[%u] SAN violates nameConstraints of trust anchor", jj);
                      return false; }
                }
            }
            break;
        }
    }

    /* Reject certificates with unrecognized critical extensions (RFC 5280 Section 4.2) */
    for (i = 0; i < chainLen; i++)
    {
        uint8_t e;
        for (e = 0; e < certs[i].extsLen; e++)
        {
            if (!certs[i].exts[e].critical) continue;

            /* Check if OID matches any recognized extension */
            if (_OIDMatch(certs[i].exts[e].oidRaw, certs[i].exts[e].oidRawLen,
                          _oidBasicConstraints, sizeof(_oidBasicConstraints))) continue;
            if (_OIDMatch(certs[i].exts[e].oidRaw, certs[i].exts[e].oidRawLen,
                          _oidKeyUsage, sizeof(_oidKeyUsage))) continue;
            if (_OIDMatch(certs[i].exts[e].oidRaw, certs[i].exts[e].oidRawLen,
                          _oidSAN, sizeof(_oidSAN))) continue;
            if (_OIDMatch(certs[i].exts[e].oidRaw, certs[i].exts[e].oidRawLen,
                          _oidSKID, sizeof(_oidSKID))) continue;
            if (_OIDMatch(certs[i].exts[e].oidRaw, certs[i].exts[e].oidRawLen,
                          _oidAKID, sizeof(_oidAKID))) continue;
            if (_OIDMatch(certs[i].exts[e].oidRaw, certs[i].exts[e].oidRawLen,
                          _oidEKU, sizeof(_oidEKU))) continue;
            if (_OIDMatch(certs[i].exts[e].oidRaw, certs[i].exts[e].oidRawLen,
                          _oidNameConstraints, sizeof(_oidNameConstraints))) continue;

            /* Unknown critical extension — reject */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] has unrecognized critical extension (OID %u bytes)",
                i, certs[i].exts[e].oidRawLen);
            return false;
        }
    }

    /* Match hostname against the leaf certificate's SAN entries (DNS and IP) */
    {
        bool matched = false;
        for (i = 0; i < certs[0].sanLen; i++)
        {
            if (certs[0].san[i].type == SSF_X509_SAN_DNS)
            {
                if (_HostnameMatch(hostname, certs[0].san[i].val, certs[0].san[i].valLen))
                {
                    matched = true;
                    break;
                }
            }
            else if (certs[0].san[i].type == SSF_X509_SAN_IP)
            {
                if (_IPAddressMatch(hostname, certs[0].san[i].val, certs[0].san[i].valLen))
                {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched)
        { SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: hostname '%s' not matched in SAN (sanLen=%u)", hostname,
                        certs[0].sanLen);
          return false; }
    }

    return true;
}
