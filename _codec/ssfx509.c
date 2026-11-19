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
#include "ssfstr.h"

/* Module-scope trace context for chain verification (set by caller before SSFVerifyChain) */
static SSFTLSTraceCtx_t _ssfx509TraceCtx;

/* --------------------------------------------------------------------------------------------- */
/* Installs the module-wide verification trace callback; a NULL fnOpt disables tracing.          */
/* --------------------------------------------------------------------------------------------- */
void SSFX509SetTraceCtx(void (*fnOpt)(int, int, const char *, void *), void *userCtxOpt)
{
    _ssfx509TraceCtx.fn = (SSFTLSTraceFn_t)fnOpt;
    _ssfx509TraceCtx.userCtx = userCtxOpt;
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
static const uint8_t _oidRSAPKCS1SHA256[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
};

/* sha384WithRSAEncryption: 1.2.840.113549.1.1.12 */
static const uint8_t _oidRSAPKCS1SHA384[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Cu
};

/* sha512WithRSAEncryption: 1.2.840.113549.1.1.13 */
static const uint8_t _oidRSAPKCS1SHA512[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Du
};

/* id-RSASSA-PSS: 1.2.840.113549.1.1.10 */
static const uint8_t _oidRSAPSS[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
};

/* id-Ed25519 (RFC 8410): 1.3.101.112 - used for both SubjectPublicKeyInfo algorithm and        */
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
/* id-kp-codeSigning: 1.3.6.1.5.5.7.3.3 */
static const uint8_t _oidEkuCodeSigning[] = {
    0x2Bu, 0x06u, 0x01u, 0x05u, 0x05u, 0x07u, 0x03u, 0x03u
};
/* anyExtendedKeyUsage: 2.5.29.37.0 */
static const uint8_t _oidEkuAny[] = { 0x55u, 0x1Du, 0x25u, 0x00u };

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
static bool _SSFX509OIDMatch(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen)
{
    SSF_REQUIRE((a != NULL) || (aLen == 0u));
    SSF_REQUIRE((b != NULL) || (bLen == 0u));

    if (aLen != bLen) return false;
    return (memcmp(a, b, aLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes RSASSA-PSS-params (RFC 4055 Section 3.1) into the hash and salt length to verify with. */
/* --------------------------------------------------------------------------------------------- */
static void _SSFX509ParsePSSParams(const uint8_t *params, uint32_t paramsLen, SSFRSAHash_t *hashOut,
                            uint32_t *saltLenOut)
{
    SSFASN1Cursor_t cursor;
    SSFASN1Cursor_t seqInner;
    SSFASN1Cursor_t fieldInner;
    SSFASN1Cursor_t algIdInner;
    const uint8_t *hashOidRaw;
    uint32_t hashOidRawLen;
    uint64_t saltLen;
    uint16_t tag;

    SSF_REQUIRE((params != NULL) || (paramsLen == 0u));
    SSF_REQUIRE(hashOut != NULL);
    SSF_REQUIRE(saltLenOut != NULL);

    /* RFC 4055 DEFAULTs, which DER omits: hashAlgorithm sha1 (unsupported, so SHA-256 is used  */
    /* and verification fails closed) and saltLength 20                                          */
    *hashOut = SSF_RSA_HASH_SHA256;
    *saltLenOut = 20u;

    /* Parameters present? */
    if ((params == NULL) || (paramsLen == 0u))
    {
        /* No, every field takes its default */
        return;
    }
    cursor.buf = params;
    cursor.bufLen = paramsLen;
    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &seqInner, &cursor)) return;

    /* [0] hashAlgorithm present? */
    if (SSFASN1DecPeekTag(&seqInner, &tag) && (tag == SSF_ASN1_CONTEXT_EXPLICIT(0)))
    {
        /* Yes, map its OID; an unknown OID keeps SHA-256 so verification fails closed */
        if (!SSFASN1DecOpenConstructed(&seqInner, SSF_ASN1_CONTEXT_EXPLICIT(0), &fieldInner,
                                       &seqInner)) return;
        if (!SSFASN1DecOpenConstructed(&fieldInner, SSF_ASN1_TAG_SEQUENCE, &algIdInner,
                                       &fieldInner)) return;
        if (!SSFASN1DecGetOIDRaw(&algIdInner, &hashOidRaw, &hashOidRawLen, &algIdInner)) return;
        if (_SSFX509OIDMatch(hashOidRaw, hashOidRawLen, _oidSHA384, sizeof(_oidSHA384)))
        {
            *hashOut = SSF_RSA_HASH_SHA384;
        }
        else if (_SSFX509OIDMatch(hashOidRaw, hashOidRawLen, _oidSHA512, sizeof(_oidSHA512)))
        {
            *hashOut = SSF_RSA_HASH_SHA512;
        }
    }

    /* [1] maskGenAlgorithm present? */
    if (SSFASN1DecPeekTag(&seqInner, &tag) && (tag == SSF_ASN1_CONTEXT_EXPLICIT(1)))
    {
        /* Yes, skip it; MGF1 over the same hash is the only form supported */
        if (!SSFASN1DecSkip(&seqInner, &seqInner)) return;
    }

    /* [2] saltLength present? */
    if (SSFASN1DecPeekTag(&seqInner, &tag) && (tag == SSF_ASN1_CONTEXT_EXPLICIT(2)))
    {
        /* Yes, take the declared value; oversize values are capped and rejected by the caller */
        if (!SSFASN1DecOpenConstructed(&seqInner, SSF_ASN1_CONTEXT_EXPLICIT(2), &fieldInner,
                                       &seqInner)) return;
        /* Is the saltLength a valid unsigned INTEGER (AUDIT ASN1-1)? */
        if (SSFASN1DecGetIntU64(&fieldInner, &saltLen, &fieldInner))
        {
            /* Yes */
            *saltLenOut = (saltLen > 255u) ? 255u : (uint32_t)saltLen;
        }
        else
        {
            /* No, never fall back to the default; 255 exceeds every hash and is rejected */
            *saltLenOut = 255u;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Parses a Distinguished Name (SEQUENCE of SET of SEQUENCE of {OID, value}).                     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509ParseDN(const SSFASN1Cursor_t *nameCursor, SSFX509Name_t *name)
{
    SSFASN1Cursor_t setInner;
    SSFASN1Cursor_t attrInner;
    SSFASN1Cursor_t pos;
    const uint8_t *oidRaw;
    uint32_t oidRawLen;
    const uint8_t *val;
    uint32_t valLen;
    uint16_t strTag;

    SSF_REQUIRE(nameCursor != NULL);
    SSF_REQUIRE(name != NULL);

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

            /* Attribute value is one of the supported string types? */
            if (!SSFASN1DecGetString(&attrInner, &val, &valLen, &strTag, &attrInner))
            {
                /* No, leave it unnamed; the raw DN still serves name comparison */
                continue;
            }

            /* Match OID to DN field */
            if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidCN, sizeof(_oidCN)))
            { name->cn = val; name->cnLen = valLen; }
            else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidC, sizeof(_oidC)))
            { name->c = val; name->cLen = valLen; }
            else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidST, sizeof(_oidST)))
            { name->st = val; name->stLen = valLen; }
            else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidL, sizeof(_oidL)))
            { name->l = val; name->lLen = valLen; }
            else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidO, sizeof(_oidO)))
            { name->o = val; name->oLen = valLen; }
            else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidOU, sizeof(_oidOU)))
            { name->ou = val; name->ouLen = valLen; }
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Parses the Extensions SEQUENCE.                                                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509ParseExtensions(const SSFASN1Cursor_t *extsCursor, SSFX509Cert_t *cert)
{
    SSFASN1Cursor_t pos;
    SSFASN1Cursor_t extInner;
    const uint8_t *oidRaw;
    uint32_t oidRawLen;
    bool critical;
    const uint8_t *extValue;
    uint32_t extValueLen;
    uint16_t tag;

    SSF_REQUIRE(extsCursor != NULL);
    SSF_REQUIRE(cert != NULL);

    pos = *extsCursor;
    while (!SSFASN1DecIsEmpty(&pos))
    {
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_TAG_SEQUENCE, &extInner, &pos)) return false;

        if (!SSFASN1DecGetOIDRaw(&extInner, &oidRaw, &oidRawLen, &extInner)) return false;

        /* Duplicate of an extension already seen, which RFC 5280 Sec. 4.2 forbids? */
        {
            uint8_t dup;
            for (dup = 0; dup < cert->extsLen; dup++)
            {
                if (_SSFX509OIDMatch(cert->exts[dup].oidRaw, cert->exts[dup].oidRawLen,
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
                /* Does the critical flag decode (AUDIT X509-6)? */
                if (!SSFASN1DecGetBool(&extInner, &critical, &extInner))
                {
                    /* No, it must never silently read as non-critical */
                    return false;
                }
                /* Yes */
            }
        }

        /* Extension value is an OCTET STRING wrapping the actual value */
        if (!SSFASN1DecGetOctetString(&extInner, &extValue, &extValueLen, &extInner)) return false;

        /* Room to retain this extension? */
        if (cert->extsLen >= SSF_X509_CONFIG_MAX_EXTENSIONS)
        {
            /* No, an unretained extension would escape the critical and duplicate checks */
            return false;
        }

        /* Yes, store in extension array */
        {
            cert->exts[cert->extsLen].oidRaw = oidRaw;
            cert->exts[cert->extsLen].oidRawLen = oidRawLen;
            cert->exts[cert->extsLen].critical = critical;
            cert->exts[cert->extsLen].value = extValue;
            cert->exts[cert->extsLen].valueLen = extValueLen;
            cert->extsLen++;
        }

        /* Parse known extensions */
        if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidBasicConstraints, sizeof(_oidBasicConstraints)))
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
                        /* Does the cA flag decode (AUDIT X509-6)? */
                        if (!SSFASN1DecGetBool(&bcInner, &cert->isCA, &bcInner))
                        {
                            /* No, malformed */
                            return false;
                        }
                        /* Yes */
                    }
                    if (!SSFASN1DecIsEmpty(&bcInner))
                    {
                        uint64_t pl;

                        /* Is the pathLenConstraint a valid unsigned INTEGER (AUDIT ASN1-1)? */
                        if (!SSFASN1DecGetIntU64(&bcInner, &pl, &bcInner))
                        {
                            /* No, a CA constraint that cannot be read must not become unlimited */
                            return false;
                        }
                        /* Yes, clamp so a large value stays a constraint instead of wrapping */
                        cert->pathLenConstraint = (pl > 127u) ? (int8_t)127 : (int8_t)pl;
                    }
                }
            }
        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidKeyUsage, sizeof(_oidKeyUsage)))
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
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidSAN, sizeof(_oidSAN)))
        {
            SSFASN1Cursor_t sanCursor = { extValue, extValueLen };
            SSFASN1Cursor_t sanInner;
            if (SSFASN1DecOpenConstructed(&sanCursor, SSF_ASN1_TAG_SEQUENCE, &sanInner, &sanCursor))
            {
                while (!SSFASN1DecIsEmpty(&sanInner) &&
                       (cert->sanLen < SSF_X509_CONFIG_MAX_SAN_ENTRIES))
                {
                    const uint8_t *sanVal;
                    uint32_t sanValLen;
                    uint8_t sanType;

                    /* GeneralName header readable and its content within the SEQUENCE? */
                    if ((!SSFASN1DecPeekTag(&sanInner, &tag)) ||
                        (!SSFASN1DecGetTLV(&sanInner, &tag, &sanVal, &sanValLen, &sanInner)))
                    {
                        /* No, structural DER error; the cursor could never advance past it */
                        return false;
                    }

                    /* Yes, the low tag bits are the GeneralName choice */
                    sanType = tag & 0x1Fu;

                    /* dNSName that is empty or embeds a NUL byte? */
                    if ((sanType == SSF_X509_SAN_DNS) &&
                        ((sanValLen == 0u) || (memchr(sanVal, 0, sanValLen) != NULL)))
                    {
                        /* Yes, drop it since no hostname can match it safely */
                        continue;
                    }
                    cert->san[cert->sanLen].type = sanType;
                    cert->san[cert->sanLen].val = sanVal;
                    cert->san[cert->sanLen].valLen = sanValLen;
                    cert->sanLen++;
                }
            }
        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidSKID, sizeof(_oidSKID)))
        {
            SSFASN1Cursor_t skidCursor = { extValue, extValueLen };

            /* SubjectKeyIdentifier body is an OCTET STRING? */
            if (!SSFASN1DecGetOctetString(&skidCursor, &cert->skid, &cert->skidLen, &skidCursor))
            {
                /* No, the decoder fills its outputs before checking the tag, so read as absent */
                cert->skid = NULL;
                cert->skidLen = 0;
            }
        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidAKID, sizeof(_oidAKID)))
        {
            SSFASN1Cursor_t akidCursor = { extValue, extValueLen };
            SSFASN1Cursor_t akidInner;
            if (SSFASN1DecOpenConstructed(&akidCursor, SSF_ASN1_TAG_SEQUENCE, &akidInner,
                                          &akidCursor))
            {
                if (!SSFASN1DecIsEmpty(&akidInner) && SSFASN1DecPeekTag(&akidInner, &tag))
                {
                    if (tag == SSF_ASN1_CONTEXT_IMPLICIT(0))
                    {
                        /* Does the keyIdentifier decode (AUDIT X509-6)? */
                        if (!SSFASN1DecGetTLV(&akidInner, &tag, &cert->akid, &cert->akidLen,
                                              &akidInner))
                        {
                            /* No, malformed */
                            return false;
                        }
                        /* Yes */
                    }
                }
            }
        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidEKU, sizeof(_oidEKU)))
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
                    if (_SSFX509OIDMatch(ekuOid, ekuOidLen, _oidEkuServerAuth,
                                  sizeof(_oidEkuServerAuth)))
                    {
                        cert->ekuServerAuth = true;
                    }
                    else if (_SSFX509OIDMatch(ekuOid, ekuOidLen, _oidEkuClientAuth,
                                       sizeof(_oidEkuClientAuth)))
                    {
                        cert->ekuClientAuth = true;
                    }
                    else if (_SSFX509OIDMatch(ekuOid, ekuOidLen, _oidEkuCodeSigning,
                                       sizeof(_oidEkuCodeSigning)))
                    {
                        cert->ekuCodeSigning = true;
                    }
                    else if (_SSFX509OIDMatch(ekuOid, ekuOidLen, _oidEkuAny, sizeof(_oidEkuAny)))
                    {
                        cert->ekuAnyPurpose = true;
                    }
                }
            }
        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidNameConstraints,
                            sizeof(_oidNameConstraints)))
        {
            /* NameConstraints { permittedSubtrees [0], excludedSubtrees [1] }, RFC 5280 4.2.1.10 */
            SSFASN1Cursor_t ncCursor = { extValue, extValueLen };
            SSFASN1Cursor_t ncInner;
            SSFASN1Cursor_t ncAfter;
            uint8_t subtreeIdx;

            cert->hasNameConstraints = true;

            /* Is the body exactly one non-empty SEQUENCE (AUDIT X509-3)? */
            if ((!SSFASN1DecOpenConstructed(&ncCursor, SSF_ASN1_TAG_SEQUENCE, &ncInner,
                                            &ncAfter)) || (!SSFASN1DecIsEmpty(&ncAfter)) ||
                (SSFASN1DecIsEmpty(&ncInner)))
            {
                /* No, constraints that cannot be read must not be ignored */
                return false;
            }
            /* Yes, read permittedSubtrees [0] then excludedSubtrees [1] */

            for (subtreeIdx = 0; subtreeIdx < 2u; subtreeIdx++)
            {
                SSFASN1Cursor_t subtreesInner;
                uint16_t expectTag = (subtreeIdx == 0u) ?
                    (uint16_t)(SSF_ASN1_CONTEXT_EXPLICIT(0)) :
                    (uint16_t)(SSF_ASN1_CONTEXT_EXPLICIT(1));
                SSFX509NameConstraint_t *dest = (subtreeIdx == 0u) ?
                    cert->permittedSubtrees : cert->excludedSubtrees;
                uint8_t *destLen = (subtreeIdx == 0u) ?
                    &cert->permittedLen : &cert->excludedLen;

                /* Is this subtree list next? */
                if ((SSFASN1DecIsEmpty(&ncInner)) || (!SSFASN1DecPeekTag(&ncInner, &tag)) ||
                    (tag != expectTag))
                {
                    /* No, it is absent; anything left over is rejected below */
                    continue;
                }
                /* Yes, is it a well-formed, non-empty GeneralSubtrees (SIZE (1..MAX))? */
                if ((!SSFASN1DecOpenConstructed(&ncInner, expectTag, &subtreesInner,
                                                &ncInner)) || (SSFASN1DecIsEmpty(&subtreesInner)))
                {
                    /* No */
                    return false;
                }
                /* Yes */

                while (!SSFASN1DecIsEmpty(&subtreesInner))
                {
                    SSFASN1Cursor_t gsInner;
                    uint16_t gnTag;
                    const uint8_t *gnVal;
                    uint32_t gnValLen;

                    /* Is the GeneralSubtree a SEQUENCE that starts with a GeneralName? */
                    if ((!SSFASN1DecOpenConstructed(&subtreesInner, SSF_ASN1_TAG_SEQUENCE,
                                                    &gsInner, &subtreesInner)) ||
                        (!SSFASN1DecGetTLV(&gsInner, &gnTag, &gnVal, &gnValLen, &gsInner)))
                    {
                        /* No, a subtree that cannot be read must not be dropped */
                        return false;
                    }
                    /* Yes */

                    /* Is it a dNSName [2] or iPAddress [7], the forms that are enforced? */
                    if ((gnTag == 0x82u) || (gnTag == 0x87u))
                    {
                        /* Yes, is there room to keep it? */
                        if (*destLen >= SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS)
                        {
                            /* No, dropping it would loosen the constraint */
                            return false;
                        }
                        /* Yes */
                        dest[*destLen].type = (gnTag == 0x82u) ? SSF_X509_SAN_DNS :
                                                                  SSF_X509_SAN_IP;
                        dest[*destLen].val = gnVal;
                        dest[*destLen].valLen = gnValLen;
                        (*destLen)++;
                    }
                    /* No, other name forms are not enforced (AUDIT X509-4) */
                }
            }

            /* Is anything left after the subtree lists (unknown or out-of-order field)? */
            if (!SSFASN1DecIsEmpty(&ncInner))
            {
                /* Yes */
                return false;
            }
            /* No, the whole extension was read */
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

    /* TBSCertificate SEQUENCE - record the raw bytes for signature verification */
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

        /* Version defined by RFC 5280 Section 4.1.2.1 (v1, v2, v3)? */
        if (ver > 2u)
        {
            /* No, malformed certificate */
            return false;
        }
        cert->version = (uint8_t)ver;
    }

    /* Serial number */
    if (!SSFASN1DecGetInt(&pos, &cert->serial, &cert->serialLen, &pos)) return false;

    /* Serial 1 to 20 octets and non-negative as RFC 5280 Sec. 4.1.2.2 requires (zero allowed)? */
    if ((cert->serialLen == 0u) || (cert->serialLen > 20u) || ((cert->serial[0] & 0x80u) != 0u))
    {
        /* No, malformed */
        return false;
    }

    /* Signature algorithm (in TBS) - extract OID and optional parameters */
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
        if (!_SSFX509ParseDN(&nameSeq, &cert->issuer)) return false;
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
        if (!_SSFX509ParseDN(&nameSeq, &cert->subject)) return false;
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
                /* Does the curve OID decode (AUDIT X509-6)? */
                if (!SSFASN1DecGetOIDRaw(&pkAlgInner, &cert->ecCurveOidRaw,
                                         &cert->ecCurveOidRawLen, &pkAlgInner))
                {
                    /* No, malformed */
                    return false;
                }
                /* Yes */
            }
        }
    }
    /* Public key BIT STRING */
    if (!SSFASN1DecGetBitString(&spkiInner, &cert->pubKey, &cert->pubKeyLen,
                                &cert->pubKeyUnusedBits, &spkiInner))
        return false;

    /* Is the public key a partial octet (no supported key format is, AUDIT ASN1-5)? */
    if (cert->pubKeyUnusedBits != 0u)
    {
        /* Yes, malformed */
        return false;
    }
    /* No */

    /* Optional: issuerUniqueID [1], subjectUniqueID [2] - skip if present */
    while (SSFASN1DecPeekTag(&pos, &tag) &&
           (tag == SSF_ASN1_CONTEXT_IMPLICIT(1) || tag == SSF_ASN1_CONTEXT_IMPLICIT(2)))
    {
        /* Does the unique ID's encoded length overrun the TBSCertificate (AUDIT X509-1)? */
        if (!SSFASN1DecSkip(&pos, &pos))
        {
            /* Yes, malformed; a failed skip leaves pos unchanged, so stop rather than spin */
            return false;
        }
        /* No, pos is past the unique ID */
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
        if (!_SSFX509ParseExtensions(&extsSeq, cert)) return false;
    }

    /* After TBS: signatureAlgorithm SEQUENCE (outer copy) */
    if (!SSFASN1DecOpenConstructed(&certInner, SSF_ASN1_TAG_SEQUENCE, &algInner, &certInner))
        return false;
    if (!SSFASN1DecGetOIDRaw(&algInner, &cert->outerSigAlgOidRaw,
                              &cert->outerSigAlgOidRawLen, &algInner))
        return false;

    /* Outer algorithm parameters present? */
    if (algInner.bufLen > 0)
    {
        /* Yes, keep them so the verifier can compare against the signed TBS copy */
        cert->outerSigAlgParams = algInner.buf;
        cert->outerSigAlgParamsLen = algInner.bufLen;
    }

    /* signatureValue BIT STRING */
    if (!SSFASN1DecGetBitString(&certInner, &cert->signature, &cert->signatureLen,
                                &cert->signatureUnusedBits, &certInner))
        return false;

    /* Is the signature a partial octet (no supported scheme is, AUDIT ASN1-5)? */
    if (cert->signatureUnusedBits != 0u)
    {
        /* Yes, malformed */
        return false;
    }
    /* No */

    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsValid(const SSFX509Cert_t *cert, uint64_t nowUnixSec)
{
    SSF_REQUIRE(cert != NULL);

    /* RFC 5280 Section 4.1.2.5: the period is inclusive at both ends */
    return (nowUnixSec >= cert->notBefore) && (nowUnixSec <= cert->notAfter);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is ecdsa-with-SHA256, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsECDSA(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidEcdsaSHA256, sizeof(_oidEcdsaSHA256));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the public key algorithm is rsaEncryption, else false.                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSA(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->pubKeyAlgOidRaw, cert->pubKeyAlgOidRawLen,
                     _oidRSA, sizeof(_oidRSA));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the EC public key is on P-256, else false.                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsP256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->ecCurveOidRaw, cert->ecCurveOidRawLen,
                     _oidP256, sizeof(_oidP256));
}

/* ========================================================================================== */
/* CERTIFICATE GENERATION                                                                     */
/* ========================================================================================== */

/* RFC 5280 Appendix A upper bounds on DN attribute values and a dNSName (RFC 1035 Sec. 2.3.4). */
#define _UB_COMMON_NAME             (64u)
#define _UB_ORGANIZATION_NAME       (64u)
#define _UB_ORGANIZATIONAL_UNIT     (64u)
#define _UB_STATE_NAME              (128u)
#define _UB_LOCALITY_NAME           (128u)
#define _UB_COUNTRY_NAME            (2u)
#define _UB_DNS_NAME                (253u)
/* Longest RFC 7093 key identifier method is SHA-512 */
#define _UB_KEY_IDENTIFIER          (64u)

/* Content emitter: writes, or only measures when buf is NULL, the content octets of one DER     */
/* element. Returns true with *lenOut set to the octets written or needed, else false.           */
typedef bool (*_EncContentFn_t)(uint8_t *buf, uint32_t bufSize, const void *arg, uint32_t *lenOut);

/* Arguments for the generic content emitters below. */
typedef struct
{
    uint16_t tag;
    _EncContentFn_t fn;
    const void *arg;
} _EncNested_t;

typedef struct
{
    uint16_t tag;
    const uint8_t *data;
    uint32_t len;
} _EncTagged_t;

typedef struct
{
    const uint8_t *data;
    uint32_t len;
} _EncBytes_t;

typedef struct
{
    const uint8_t *oid;
    uint32_t oidLen;
    SSFCStrIn_t valueStr;
    uint32_t valueLen;
} _EncDNAttr_t;

typedef struct
{
    const uint8_t *oid;
    uint32_t oidLen;
    const uint8_t *params;
    uint32_t paramsLen;
} _EncAlgId_t;

typedef struct
{
    const uint8_t *oid;
    uint32_t oidLen;
    bool critical;
    _EncContentFn_t valueFn;
    const void *valueArg;
} _EncExt_t;

typedef struct
{
    const char **dns;
    const uint8_t **ips;
} _EncSubtrees_t;

typedef struct
{
    const SSFX509GenParams_t *params;
    const uint8_t *sig;
    uint32_t sigLen;
} _EncCert_t;

/* --------------------------------------------------------------------------------------------- */
/* Leaf encoders: return bytes written, or needed when buf is NULL, else 0 on failure.           */
/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for tag wrapping content, or bytes needed when buf is NULL, else 0.            */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncWrap(uint8_t *buf, uint32_t bufSize, uint16_t tag,
                                const uint8_t *content,
                         uint32_t contentLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncWrap(buf, bufSize, tag, content, contentLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for an OBJECT IDENTIFIER, or bytes needed when buf is NULL, else 0.           */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncOIDRaw(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw,
                           uint32_t oidRawLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncOIDRaw(buf, bufSize, oidRaw, oidRawLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a string of type strTag, or bytes needed when buf is NULL, else 0.         */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncString(uint8_t *buf, uint32_t bufSize, uint16_t strTag,
                                  const uint8_t *str,
                           uint32_t strLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncString(buf, bufSize, strTag, str, strLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a BOOLEAN, or bytes needed when buf is NULL, else 0.                      */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncBool(uint8_t *buf, uint32_t bufSize, bool val)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncBool(buf, bufSize, val, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for an INTEGER from raw octets, or bytes needed when buf is NULL, else 0.      */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncInt(uint8_t *buf, uint32_t bufSize, const uint8_t *intBuf,
                               uint32_t intLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncInt(buf, bufSize, intBuf, intLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a positive INTEGER from a magnitude, or bytes needed if buf NULL, else 0.  */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncUInt(uint8_t *buf, uint32_t bufSize, const uint8_t *magBuf,
                                uint32_t magLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncUInt(buf, bufSize, magBuf, magLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for an INTEGER from a uint64_t, or bytes needed when buf is NULL, else 0.      */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncIntU64(buf, bufSize, val, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a BIT STRING, or bytes needed when buf is NULL, else 0.                   */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncBitString(uint8_t *buf, uint32_t bufSize, const uint8_t *bits,
                              uint32_t bitsLen, uint8_t unusedBits)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncBitString(buf, bufSize, bits, bitsLen, unusedBits, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for an OCTET STRING, or bytes needed when buf is NULL, else 0.                */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncOctetString(uint8_t *buf, uint32_t bufSize, const uint8_t *octets,
                                uint32_t octetsLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncOctetString(buf, bufSize, octets, octetsLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a UTCTime, or bytes needed when buf is NULL, else 0.                      */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncUTCTime(buf, bufSize, unixSec, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a tag and length header, or bytes needed when buf is NULL, else 0.        */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncTagLen(uint8_t *buf, uint32_t bufSize, uint16_t tag, uint32_t contentLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncTagLen(buf, bufSize, tag, contentLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns buf + pos, or NULL when only measuring.                                               */
/* --------------------------------------------------------------------------------------------- */
static uint8_t *_SSFX509At(uint8_t *buf, uint32_t pos)
{
    return (buf == NULL) ? NULL : &buf[pos];
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the bytes remaining in buf after pos, or 0 when only measuring.                       */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509Rem(const uint8_t *buf, uint32_t bufSize, uint32_t pos)
{
    SSF_REQUIRE((buf == NULL) || (pos <= bufSize));

    return (buf == NULL) ? 0u : (bufSize - pos);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a child element produced n bytes and advances *pos by n, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509Add(uint32_t *pos, uint32_t n)
{
    SSF_REQUIRE(pos != NULL);

    if (n == 0u) return false;
    *pos += n;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if len raw bytes fit at *pos, copying them when writing, and advances *pos.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509AddBytes(uint8_t *buf, uint32_t bufSize, uint32_t *pos, const uint8_t *data,
                      uint32_t len)
{
    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE((data != NULL) || (len == 0u));

    /* Writing? */
    if (buf != NULL)
    {
        /* Yes, the bytes must fit */
        if (_SSFX509Rem(buf, bufSize, *pos) < len) return false;
        if (len > 0u) memcpy(&buf[*pos], data, len);
    }
    *pos += len;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes written or needed for tag wrapping the content fn emits, else 0 on failure.     */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncConstructed(uint8_t *buf, uint32_t bufSize, uint16_t tag,
                                _EncContentFn_t fn, const void *arg)
{
    uint32_t innerLen;
    uint32_t hdrLen;
    uint32_t total;
    uint32_t written;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));
    SSF_REQUIRE(fn != NULL);

    /* Content measurable? */
    if (!fn(NULL, 0, arg, &innerLen))
    {
        /* No, propagate the failure */
        return 0;
    }
    hdrLen = _SSFX509EncTagLen(NULL, 0, tag, innerLen);
    if (hdrLen == 0u) return 0;
    total = hdrLen + innerLen;

    /* Only measuring? */
    if (buf == NULL) return total;

    /* Header and content fit? */
    if (bufSize < total)
    {
        /* No, caller's buffer too small */
        return 0;
    }

    /* Yes, header first since its length octets need the measured content size */
    if (_SSFX509EncTagLen(buf, bufSize, tag, innerLen) != hdrLen) return 0;
    if (!fn(&buf[hdrLen], bufSize - hdrLen, arg, &written)) return 0;
    SSF_ENSURE(written == innerLen);
    return total;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: one nested constructed element described by an _EncNested_t.                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncNestedContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                     uint32_t *lenOut)
{
    const _EncNested_t *n = (const _EncNested_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(n != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncConstructed(buf, bufSize, n->tag, n->fn,
                                                  n->arg))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: one tagged primitive described by an _EncTagged_t.                                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncTaggedContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                     uint32_t *lenOut)
{
    const _EncTagged_t *t = (const _EncTagged_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncWrap(buf, bufSize, t->tag, t->data, t->len))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: raw bytes described by an _EncBytes_t.                                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncBytesContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                    uint32_t *lenOut)
{
    const _EncBytes_t *b = (const _EncBytes_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509AddBytes(buf, bufSize, &pos, b->data, b->len)) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: AttributeTypeAndValue { OID, UTF8String }.                                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncDNAttrSeqContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                 uint32_t *lenOut)
{
    const _EncDNAttr_t *a = (const _EncDNAttr_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             a->oid, a->oidLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncString(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             SSF_ASN1_TAG_UTF8_STRING,
                               (const uint8_t *)a->valueStr, a->valueLen))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for one RDN SET { SEQUENCE { OID, UTF8String } }, else 0 if over its bound.     */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncDNAttr(uint8_t *buf, uint32_t bufSize, const uint8_t *oid,
                                  uint32_t oidLen,
                           SSFCStrIn_t valueStr, uint32_t upperBound)
{
    _EncDNAttr_t attr;
    _EncNested_t seq;
    size_t valueLen;

    SSF_REQUIRE(oid != NULL);
    SSF_REQUIRE(valueStr != NULL);

    /* Value terminated within the RFC 5280 upper bound for this attribute? */
    if (!SSFStrLen(valueStr, upperBound + 1u, &valueLen))
    {
        /* No, refuse to emit a non-conforming name */
        return 0;
    }
    attr.oid = oid;
    attr.oidLen = oidLen;
    attr.valueStr = valueStr;
    attr.valueLen = (uint32_t)valueLen;
    seq.tag = SSF_ASN1_TAG_SEQUENCE;
    seq.fn = _SSFX509EncDNAttrSeqContent;
    seq.arg = &attr;
    return _SSFX509EncConstructed(buf, bufSize, SSF_ASN1_TAG_SET, _SSFX509EncNestedContent, &seq);
}

/* --------------------------------------------------------------------------------------------- */
/* Content: Name as a sequence of RDNs in C, ST, L, O, OU, CN order.                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncDNContent(uint8_t *buf, uint32_t bufSize, const void *arg, uint32_t *lenOut)
{
    const SSFX509GenName_t *name = (const SSFX509GenName_t *)arg;
    uint32_t pos = 0;
    size_t cLen;

    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE(lenOut != NULL);

    /* countryName present but not exactly two letters (RFC 5280 Appendix A)? */
    if ((name->c != NULL) &&
        (!SSFStrLen(name->c, _UB_COUNTRY_NAME + 1u, &cLen) || (cLen != _UB_COUNTRY_NAME)))
    {
        /* Yes, malformed */
        return false;
    }

    if ((name->c != NULL) && !_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos),
                                                                  _SSFX509Rem(buf, bufSize, pos),
        _oidC, sizeof(_oidC), name->c, _UB_COUNTRY_NAME))) return false;
    if ((name->st != NULL) && !_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos),
                                                                   _SSFX509Rem(buf, bufSize, pos),
        _oidST, sizeof(_oidST), name->st, _UB_STATE_NAME))) return false;
    if ((name->l != NULL) && !_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos),
                                                                  _SSFX509Rem(buf, bufSize, pos),
        _oidL, sizeof(_oidL), name->l, _UB_LOCALITY_NAME))) return false;
    if ((name->o != NULL) && !_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos),
                                                                  _SSFX509Rem(buf, bufSize, pos),
        _oidO, sizeof(_oidO), name->o, _UB_ORGANIZATION_NAME))) return false;
    if ((name->ou != NULL) && !_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos),
                                                                   _SSFX509Rem(buf, bufSize, pos),
        _oidOU, sizeof(_oidOU), name->ou, _UB_ORGANIZATIONAL_UNIT))) return false;
    if ((name->cn != NULL) && !_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos),
                                                                   _SSFX509Rem(buf, bufSize, pos),
        _oidCN, sizeof(_oidCN), name->cn, _UB_COMMON_NAME))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a Name SEQUENCE, else 0 on failure.                                         */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncDN(uint8_t *buf, uint32_t bufSize, const SSFX509GenName_t *name)
{
    SSF_REQUIRE(name != NULL);

    return _SSFX509EncConstructed(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncDNContent, name);
}

/* --------------------------------------------------------------------------------------------- */
/* Content: AlgorithmIdentifier { OID, params... } with optional raw DER parameters.             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncAlgIdContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                    uint32_t *lenOut)
{
    const _EncAlgId_t *a = (const _EncAlgId_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             a->oid, a->oidLen)))
        return false;
    if (!_SSFX509AddBytes(buf, bufSize, &pos, a->params, a->paramsLen)) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for AlgorithmIdentifier SEQUENCE { OID, params }, else 0 on failure.            */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncAlgIdWithParams(uint8_t *buf, uint32_t bufSize, const uint8_t *algOidRaw,
                                    uint32_t algOidRawLen, const uint8_t *params,
                                    uint32_t paramsLen)
{
    _EncAlgId_t a;

    SSF_REQUIRE(algOidRaw != NULL);

    a.oid = algOidRaw;
    a.oidLen = algOidRawLen;
    a.params = params;
    a.paramsLen = (params == NULL) ? 0u : paramsLen;
    return _SSFX509EncConstructed(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncAlgIdContent, &a);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for AlgorithmIdentifier SEQUENCE { OID }, else 0 on failure.                    */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncAlgId(uint8_t *buf, uint32_t bufSize, const uint8_t *algOidRaw,
                          uint32_t algOidRawLen)
{
    return _SSFX509EncAlgIdWithParams(buf, bufSize, algOidRaw, algOidRawLen, NULL, 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Content: [0] EXPLICIT Version INTEGER.                                                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncVersionContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                      uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncIntU64(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             p->version))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: Validity { notBefore UTCTime, notAfter UTCTime }.                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncValidityContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncUTCTime(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              p->notBefore)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncUTCTime(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              p->notAfter)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: EC AlgorithmIdentifier { OID id-ecPublicKey, OID namedCurve }.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncECAlgContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                    uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             p->pubKeyAlgOidRaw,
                               p->pubKeyAlgOidRawLen))) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             p->ecCurveOidRaw,
                               p->ecCurveOidRawLen))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: SubjectPublicKeyInfo { algorithm, subjectPublicKey BIT STRING }.                     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncSPKIContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                   uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;
    uint32_t n;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    /* EC key? */
    if (p->ecCurveOidRaw != NULL)
    {
        /* Yes, the algorithm carries the named curve as its parameter */
        n = _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                   SSF_ASN1_TAG_SEQUENCE,
                            _SSFX509EncECAlgContent, p);
    }
    else
    {
        /* No, bare algorithm identifier */
        n = _SSFX509EncAlgId(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                             p->pubKeyAlgOidRaw,
                      p->pubKeyAlgOidRawLen);
    }
    if (!_SSFX509Add(&pos, n)) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncBitString(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
        pos), p->pubKey, p->pubKeyLen,
                                  0u))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: Extension { OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }.                */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncExtContent(uint8_t *buf, uint32_t bufSize, const void *arg, uint32_t *lenOut)
{
    const _EncExt_t *e = (const _EncExt_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             e->oid, e->oidLen)))
        return false;
    if (e->critical && !_SSFX509Add(&pos, _SSFX509EncBool(_SSFX509At(buf, pos), _SSFX509Rem(buf,
        bufSize, pos), true)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
                                                                                    pos),
                                    SSF_ASN1_TAG_OCTET_STRING, e->valueFn, e->valueArg)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for one Extension SEQUENCE, else 0 on failure.                                  */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncExtension(uint8_t *buf, uint32_t bufSize, const _EncExt_t *e)
{
    SSF_REQUIRE(e != NULL);

    return _SSFX509EncConstructed(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncExtContent, e);
}

/* --------------------------------------------------------------------------------------------- */
/* Content: BasicConstraints { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncBCSeqContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                    uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;
    uint8_t plVal;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (p->isCA && !_SSFX509Add(&pos, _SSFX509EncBool(_SSFX509At(buf, pos), _SSFX509Rem(buf,
        bufSize, pos), true)))
        return false;

    /* Path length constraint present? */
    if (p->pathLenConstraint >= 0)
    {
        /* Yes, single octet INTEGER */
        plVal = (uint8_t)p->pathLenConstraint;
        if (!_SSFX509Add(&pos, _SSFX509EncInt(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              &plVal, 1u))) return false;
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: KeyUsage BIT STRING as a DER named bit list, trailing zero bits trimmed.             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncKUValueContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                      uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;
    uint8_t kuBytes[2];
    uint32_t kuLen;
    uint8_t lastByte;
    uint8_t unused = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    kuBytes[0] = (uint8_t)(p->keyUsageBits >> 8);
    kuBytes[1] = (uint8_t)(p->keyUsageBits & 0xFFu);

    /* DER drops trailing all-zero octets and counts the trailing zero bits of the last octet */
    kuLen = (kuBytes[1] != 0u) ? 2u : ((kuBytes[0] != 0u) ? 1u : 0u);
    if (kuLen > 0u)
    {
        lastByte = kuBytes[kuLen - 1u];
        while ((lastByte & 0x01u) == 0u)
        {
            lastByte >>= 1;
            unused++;
        }
    }
    if (!_SSFX509Add(&pos, _SSFX509EncBitString(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
        pos), kuBytes, kuLen, unused)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: ExtKeyUsageSyntax SEQUENCE OF KeyPurposeId.                                          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncEKUSeqContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                     uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (p->ekuServerAuth && !_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos),
                                                                 _SSFX509Rem(buf, bufSize, pos),
        _oidEkuServerAuth, sizeof(_oidEkuServerAuth)))) return false;
    if (p->ekuClientAuth && !_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos),
                                                                 _SSFX509Rem(buf, bufSize, pos),
        _oidEkuClientAuth, sizeof(_oidEkuClientAuth)))) return false;
    if (p->ekuCodeSigning && !_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos),
                                                                  _SSFX509Rem(buf, bufSize, pos),
        _oidEkuCodeSigning, sizeof(_oidEkuCodeSigning)))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: GeneralNames with [2] dNSName and [7] iPAddress entries.                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncSANSeqContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                     uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    const char **dns = p->sanDNSNames;
    const uint8_t **ip = p->sanIPAddrs;
    uint32_t pos = 0;
    size_t dnsLen;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    while ((dns != NULL) && (*dns != NULL))
    {
        /* dNSName terminated within the DNS name length bound? */
        if (!SSFStrLen(*dns, _UB_DNS_NAME + 1u, &dnsLen))
        {
            /* No, refuse to emit it */
            return false;
        }
        if (!_SSFX509Add(&pos, _SSFX509EncWrap(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                               0x82u,
                                 (const uint8_t *)*dns, (uint32_t)dnsLen))) return false;
        dns++;
    }
    while ((ip != NULL) && (*ip != NULL))
    {
        if (!_SSFX509Add(&pos, _SSFX509EncWrap(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                               0x87u, *ip, 4u)))
            return false;
        ip++;
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: SubjectKeyIdentifier OCTET STRING.                                                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncSKIDValueContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                 uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    /* Key identifier within the supported bound? */
    if (p->skidLen > _UB_KEY_IDENTIFIER)
    {
        /* No, refuse to emit it */
        return false;
    }
    if (!_SSFX509Add(&pos, _SSFX509EncOctetString(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
        pos), p->skid, p->skidLen)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: AuthorityKeyIdentifier { keyIdentifier [0] IMPLICIT OCTET STRING }.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncAKIDSeqContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                      uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    /* Key identifier within the supported bound? */
    if (p->akidLen > _UB_KEY_IDENTIFIER)
    {
        /* No, refuse to emit it */
        return false;
    }
    if (!_SSFX509Add(&pos, _SSFX509EncWrap(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                           0x80u, p->akid, p->akidLen)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: GeneralSubtrees, each SEQUENCE { base GeneralName } for the DNS and IP lists.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncSubtreesContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                uint32_t *lenOut)
{
    const _EncSubtrees_t *s = (const _EncSubtrees_t *)arg;
    const char **dns = s->dns;
    const uint8_t **ips = s->ips;
    _EncTagged_t gn;
    uint32_t pos = 0;
    size_t dnsLen;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(lenOut != NULL);

    while ((dns != NULL) && (*dns != NULL))
    {
        /* dNSName terminated within the DNS name length bound? */
        if (!SSFStrLen(*dns, _UB_DNS_NAME + 1u, &dnsLen))
        {
            /* No, refuse to emit it */
            return false;
        }
        gn.tag = 0x82u;
        gn.data = (const uint8_t *)*dns;
        gn.len = (uint32_t)dnsLen;
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf,
            bufSize, pos),
                                        SSF_ASN1_TAG_SEQUENCE, _SSFX509EncTaggedContent, &gn)))
            return false;
        dns++;
    }
    while ((ips != NULL) && (*ips != NULL))
    {
        gn.tag = 0x87u;
        gn.data = *ips;
        gn.len = 8u;
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf,
            bufSize, pos),
                                        SSF_ASN1_TAG_SEQUENCE, _SSFX509EncTaggedContent, &gn)))
            return false;
        ips++;
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: NameConstraints { permittedSubtrees [0] OPTIONAL, excludedSubtrees [1] OPTIONAL }.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncNCSeqContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                    uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    _EncSubtrees_t sub;
    uint32_t pos = 0;
    uint8_t idx;
    uint16_t tag;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    for (idx = 0; idx < 2u; idx++)
    {
        sub.dns = (idx == 0u) ? p->ncPermittedDNS : p->ncExcludedDNS;
        sub.ips = (idx == 0u) ? p->ncPermittedIPs : p->ncExcludedIPs;
        tag = (idx == 0u) ? SSF_ASN1_CONTEXT_EXPLICIT(0) : SSF_ASN1_CONTEXT_EXPLICIT(1);

        /* Any subtree in this list? */
        if (((sub.dns != NULL) && (*sub.dns != NULL)) || ((sub.ips != NULL) && (*sub.ips != NULL)))
        {
            /* Yes, emit the [n] IMPLICIT GeneralSubtrees */
            if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf,
                bufSize, pos), tag,
                                            _SSFX509EncSubtreesContent, &sub))) return false;
        }
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: the Extensions SEQUENCE OF Extension in BC, KU, EKU, raw, SAN, SKID, AKID, NC order. */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncExtListContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                      uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    _EncNested_t seq;
    _EncBytes_t raw;
    _EncExt_t e;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    seq.tag = SSF_ASN1_TAG_SEQUENCE;
    seq.arg = p;

    if (p->addBasicConstraints)
    {
        seq.fn = _SSFX509EncBCSeqContent;
        e.oid = _oidBasicConstraints; e.oidLen = sizeof(_oidBasicConstraints);
        e.critical = true; e.valueFn = _SSFX509EncNestedContent; e.valueArg = &seq;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    if (p->addKeyUsage)
    {
        e.oid = _oidKeyUsage; e.oidLen = sizeof(_oidKeyUsage);
        e.critical = true; e.valueFn = _SSFX509EncKUValueContent; e.valueArg = p;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    if (p->addExtKeyUsage)
    {
        seq.fn = _SSFX509EncEKUSeqContent;
        e.oid = _oidEKU; e.oidLen = sizeof(_oidEKU);
        e.critical = false; e.valueFn = _SSFX509EncNestedContent; e.valueArg = &seq;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    if (p->addRawExt)
    {
        raw.data = p->rawExtValue; raw.len = p->rawExtValueLen;
        e.oid = p->rawExtOid; e.oidLen = p->rawExtOidLen;
        e.critical = p->rawExtCritical; e.valueFn = _SSFX509EncBytesContent; e.valueArg = &raw;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    if ((p->sanDNSNames != NULL) || (p->sanIPAddrs != NULL))
    {
        seq.fn = _SSFX509EncSANSeqContent;
        e.oid = _oidSAN; e.oidLen = sizeof(_oidSAN);
        e.critical = false; e.valueFn = _SSFX509EncNestedContent; e.valueArg = &seq;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    if ((p->skid != NULL) && (p->skidLen > 0u))
    {
        e.oid = _oidSKID; e.oidLen = sizeof(_oidSKID);
        e.critical = false; e.valueFn = _SSFX509EncSKIDValueContent; e.valueArg = p;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    if ((p->akid != NULL) && (p->akidLen > 0u))
    {
        seq.fn = _SSFX509EncAKIDSeqContent;
        e.oid = _oidAKID; e.oidLen = sizeof(_oidAKID);
        e.critical = false; e.valueFn = _SSFX509EncNestedContent; e.valueArg = &seq;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    if (p->addNameConstraints)
    {
        seq.fn = _SSFX509EncNCSeqContent;
        e.oid = _oidNameConstraints; e.oidLen = sizeof(_oidNameConstraints);
        e.critical = true; e.valueFn = _SSFX509EncNestedContent; e.valueArg = &seq;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if params request at least one extension, else false.                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509HasExtensions(const SSFX509GenParams_t *p)
{
    SSF_REQUIRE(p != NULL);

    return (p->version >= 2u) && (p->addBasicConstraints || p->addKeyUsage || p->addExtKeyUsage ||
                                   p->addRawExt || (p->sanDNSNames != NULL) ||
                                   (p->sanIPAddrs != NULL) || (p->skid != NULL) ||
                                   (p->akid != NULL) || p->addNameConstraints);
}

/* --------------------------------------------------------------------------------------------- */
/* Content: TBSCertificate fields in RFC 5280 Section 4.1 order.                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncTBSContent(uint8_t *buf, uint32_t bufSize, const void *arg, uint32_t *lenOut)
{
    const SSFX509GenParams_t *p = (const SSFX509GenParams_t *)arg;
    _EncNested_t exts;
    uint32_t pos = 0;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(lenOut != NULL);

    /* Version present (v1 omits the field)? */
    if (p->version >= 1u)
    {
        /* Yes, [0] EXPLICIT INTEGER */
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf,
            bufSize, pos),
                                        SSF_ASN1_CONTEXT_EXPLICIT(0),
                                        _SSFX509EncVersionContent, p)))
            return false;
    }
    /* The serial is an unsigned magnitude; encode it as a positive INTEGER (AUDIT ASN1-6) */
    if (!_SSFX509Add(&pos, _SSFX509EncUInt(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                           p->serial, p->serialLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncAlgIdWithParams(_SSFX509At(buf, pos), _SSFX509Rem(buf,
        bufSize, pos), p->sigAlgOidRaw,
                                        p->sigAlgOidRawLen, p->sigAlgParams, p->sigAlgParamsLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncDN(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                         &p->issuer))) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
        pos), SSF_ASN1_TAG_SEQUENCE,
                                    _SSFX509EncValidityContent, p))) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncDN(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                         &p->subject))) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
        pos), SSF_ASN1_TAG_SEQUENCE,
                                    _SSFX509EncSPKIContent, p))) return false;

    /* Extensions requested? */
    if (_SSFX509HasExtensions(p))
    {
        /* Yes, [3] EXPLICIT SEQUENCE OF Extension */
        exts.tag = SSF_ASN1_TAG_SEQUENCE;
        exts.fn = _SSFX509EncExtListContent;
        exts.arg = p;
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf,
            bufSize, pos),
                                        SSF_ASN1_CONTEXT_EXPLICIT(3),
                                        _SSFX509EncNestedContent, &exts)))
            return false;
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if TBSCertificate encoded, or measured when bufOpt is NULL, with *lenOut set.    */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509EncodeTBS(uint8_t *bufOpt, uint32_t bufOptSize, const SSFX509GenParams_t *params,
                      uint32_t *lenOut)
{
    uint32_t total;

    SSF_REQUIRE((bufOpt != NULL) || (bufOptSize == 0u));
    SSF_REQUIRE(params != NULL);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    total = _SSFX509EncConstructed(NULL, 0, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncTBSContent, params);

    /* Encodable and within the configured certificate size? */
    if ((total == 0u) || (total > SSF_X509_CONFIG_MAX_CERT_SIZE))
    {
        /* No, both passes report failure */
        return false;
    }

    /* Only measuring? */
    if (bufOpt == NULL)
    {
        /* Yes, report the size needed */
        *lenOut = total;
        return true;
    }
    *lenOut = _SSFX509EncConstructed(bufOpt, bufOptSize, SSF_ASN1_TAG_SEQUENCE,
                                     _SSFX509EncTBSContent, params);
    return (*lenOut != 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Content: Certificate { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }.       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncCertContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                   uint32_t *lenOut)
{
    const _EncCert_t *c = (const _EncCert_t *)arg;
    uint32_t pos = 0;
    uint32_t tbsLen;

    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!SSFX509EncodeTBS(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos), c->params,
                          &tbsLen)) return false;
    pos += tbsLen;
    if (!_SSFX509Add(&pos, _SSFX509EncAlgIdWithParams(_SSFX509At(buf, pos), _SSFX509Rem(buf,
        bufSize, pos),
                                        c->params->sigAlgOidRaw, c->params->sigAlgOidRawLen,
                                        c->params->sigAlgParams, c->params->sigAlgParamsLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncBitString(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
        pos), c->sig, c->sigLen, 0u)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if Certificate encoded, or measured when bufOpt is NULL, with *lenOut set.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509EncodeCert(uint8_t *bufOpt, uint32_t bufOptSize, const SSFX509GenParams_t *params,
                       const uint8_t *signature, uint32_t signatureLen, uint32_t *lenOut)
{
    _EncCert_t c;
    uint32_t total;

    SSF_REQUIRE((bufOpt != NULL) || (bufOptSize == 0u));
    SSF_REQUIRE(params != NULL);
    SSF_REQUIRE(signature != NULL);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    c.params = params;
    c.sig = signature;
    c.sigLen = signatureLen;
    total = _SSFX509EncConstructed(NULL, 0, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncCertContent, &c);

    /* Encodable and within the configured certificate size? */
    if ((total == 0u) || (total > SSF_X509_CONFIG_MAX_CERT_SIZE))
    {
        /* No, both passes report failure */
        return false;
    }

    /* Only measuring? */
    if (bufOpt == NULL)
    {
        /* Yes, report the size needed */
        *lenOut = total;
        return true;
    }
    *lenOut = _SSFX509EncConstructed(bufOpt, bufOptSize, SSF_ASN1_TAG_SEQUENCE,
                                     _SSFX509EncCertContent, &c);
    return (*lenOut != 0u);
}

/* ========================================================================================== */
/* ADDITIONAL OID HELPERS                                                                     */
/* ========================================================================================== */

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsP384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->ecCurveOidRaw, cert->ecCurveOidRawLen,
                     _oidP384, sizeof(_oidP384));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsECDSASHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidEcdsaSHA384, sizeof(_oidEcdsaSHA384));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPSSSHA256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPSS, sizeof(_oidRSAPSS));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPSSSHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPSS, sizeof(_oidRSAPSS));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPKCS1SHA256, sizeof(_oidRSAPKCS1SHA256));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPKCS1SHA384, sizeof(_oidRSAPKCS1SHA384));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA512(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidRSAPKCS1SHA512, sizeof(_oidRSAPKCS1SHA512));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is id-Ed25519 (RFC 8410), else false.                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsEd25519(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                     _oidEd25519, sizeof(_oidEd25519));
}

/* ========================================================================================== */
/* CHAIN VERIFICATION                                                                         */
/* ========================================================================================== */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if hostnameStr matches a dNSName SAN value per RFC 6125 Sec. 6.4.3, else false.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509HostnameMatch(const char *hostnameStr, const uint8_t *sanVal,
                                  uint32_t sanValLen)
{
    const char *dot;
    size_t hostLenSz;
    uint32_t hostLen;
    uint32_t domainLen;
    uint32_t sanDomainLen;
    uint32_t b;
    bool baseHasDot = false;

    SSF_REQUIRE(hostnameStr != NULL);
    SSF_REQUIRE(sanVal != NULL);

    /* Hostname terminated within the longest possible DNS name? */
    if (!SSFStrLen(hostnameStr, _UB_DNS_NAME + 1u, &hostLenSz))
    {
        /* No, nothing that long can match a dNSName */
        return false;
    }
    hostLen = (uint32_t)hostLenSz;

    /* Wildcard SAN of the form "*.base"? */
    if ((sanValLen >= 2u) && (sanVal[0] == (uint8_t)'*') && (sanVal[1] == (uint8_t)'.'))
    {
        /* Yes, the wildcard stands for exactly the leftmost hostname label */
        dot = hostnameStr;
        while ((*dot != '\0') && (*dot != '.')) dot++;

        /* Leftmost label is non-empty and followed by a dot? */
        if ((*dot != '.') || (dot == hostnameStr))
        {
            /* No, nothing for the wildcard to match */
            return false;
        }

        /* Rest of the hostname is exactly ".base"? */
        domainLen = hostLen - (uint32_t)(dot - hostnameStr);
        sanDomainLen = sanValLen - 2u;
        if (domainLen != (sanDomainLen + 1u)) return false;

        /* Base has an interior dot, so "*.com" wildcards never match (CA/B Forum BR 3.2.2.6)? */
        for (b = 2u; b < sanValLen; b++)
        {
            if (sanVal[b] == (uint8_t)'.')
            {
                baseHasDot = true;
                break;
            }
        }
        if (!baseHasDot) return false;
        return SSFMatchStrNI(dot, (SSFCStrIn_t)&sanVal[1], sanDomainLen + 1u);
    }

    /* No, exact match ignoring ASCII case */
    if (hostLen != sanValLen) return false;
    return SSFMatchStrNI(hostnameStr, (SSFCStrIn_t)sanVal, hostLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if str is a dotted-decimal IPv4 address written into ipOut, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509ParseIPv4(const char *str, uint8_t ipOut[4])
{
    uint32_t octet;
    uint32_t i;
    uint32_t digitCount;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(ipOut != NULL);

    for (i = 0; i < 4u; i++)
    {
        octet = 0;
        digitCount = 0;
        while ((*str >= '0') && (*str <= '9'))
        {
            octet = (octet * 10u) + (uint32_t)(*str - '0');
            if (octet > 255u) return false;
            str++;
            digitCount++;
        }
        if (digitCount == 0u) return false;
        ipOut[i] = (uint8_t)octet;

        /* More octets to come? */
        if (i < 3u)
        {
            /* Yes, a dot must separate them */
            if (*str != '.') return false;
            str++;
        }
    }
    return (*str == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if hostnameStr is an IPv4 literal equal to a 4-byte iPAddress SAN, else false.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509IPAddressMatch(const char *hostnameStr, const uint8_t *sanIP, uint32_t sanIPLen)
{
    uint8_t parsedIP[4];

    SSF_REQUIRE(hostnameStr != NULL);
    SSF_REQUIRE(sanIP != NULL);

    /* Only IPv4 SAN entries are supported */
    if (sanIPLen != 4u) return false;
    if (!_SSFX509ParseIPv4(hostnameStr, parsedIP)) return false;
    return (memcmp(parsedIP, sanIP, 4u) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if hostnameStr is an IPv4 literal equal to the iPAddress SAN value, else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509MatchIPAddress(const char *hostnameStr, const uint8_t *sanIP, uint32_t sanIPLen)
{
    SSF_REQUIRE(hostnameStr != NULL);
    SSF_REQUIRE(sanIP != NULL);

    return _SSFX509IPAddressMatch(hostnameStr, sanIP, sanIPLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if digestOidOpt is absent or is exactly expectedOid, else false.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509DigestAgrees(const uint8_t *digestOidOpt, uint32_t digestOidLen,
                          const uint8_t *expectedOid, uint32_t expectedOidLen)
{
    SSF_REQUIRE((digestOidOpt != NULL) || (digestOidLen == 0u));
    SSF_REQUIRE(expectedOid != NULL);

    /* No digest algorithm given? */
    if ((digestOidOpt == NULL) || (digestOidLen == 0u))
    {
        /* Yes, nothing to disagree with */
        return true;
    }

    /* No, it must be the expected one */
    return _SSFX509OIDMatch(digestOidOpt, digestOidLen, expectedOid, expectedOidLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if oid names SHA-256, SHA-384 or SHA-512 with *hashOut set, else false.           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509HashFromOID(const uint8_t *oid, uint32_t oidLen, SSFRSAHash_t *hashOut)
{
    SSF_REQUIRE((oid != NULL) || (oidLen == 0u));
    SSF_REQUIRE(hashOut != NULL);

    if (_SSFX509OIDMatch(oid, oidLen, _oidSHA256,
                         sizeof(_oidSHA256))) *hashOut = SSF_RSA_HASH_SHA256;
    else if (_SSFX509OIDMatch(oid, oidLen, _oidSHA384,
                              sizeof(_oidSHA384))) *hashOut = SSF_RSA_HASH_SHA384;
    else if (_SSFX509OIDMatch(oid, oidLen, _oidSHA512,
                              sizeof(_oidSHA512))) *hashOut = SSF_RSA_HASH_SHA512;
    else return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the SHA-2 OID naming hashId with *lenOut set.                                          */
/* --------------------------------------------------------------------------------------------- */
static const uint8_t *_SSFX509OIDForHash(SSFRSAHash_t hashId, uint32_t *lenOut)
{
    SSF_REQUIRE(lenOut != NULL);

    if (hashId == SSF_RSA_HASH_SHA384)
    {
        *lenOut = sizeof(_oidSHA384);
        return _oidSHA384;
    }
    if (hashId == SSF_RSA_HASH_SHA512)
    {
        *lenOut = sizeof(_oidSHA512);
        return _oidSHA512;
    }
    *lenOut = sizeof(_oidSHA256);
    return _oidSHA256;
}

/* --------------------------------------------------------------------------------------------- */
/* Digests data with the SHA-2 hash hashId selects into hash, setting *hashLenOut.                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFX509Digest(SSFRSAHash_t hashId, const uint8_t *data, uint32_t dataLen,
                           uint8_t *hash,
                    size_t *hashLenOut)
{
    SSF_REQUIRE((data != NULL) || (dataLen == 0u));
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(hashLenOut != NULL);

    if (hashId == SSF_RSA_HASH_SHA384)
    {
        *hashLenOut = SSF_SHA2_384_BYTE_SIZE;
        SSFSHA384(data, dataLen, hash, SSF_SHA2_384_BYTE_SIZE);
    }
    else if (hashId == SSF_RSA_HASH_SHA512)
    {
        *hashLenOut = SSF_SHA2_512_BYTE_SIZE;
        SSFSHA512(data, dataLen, hash, SSF_SHA2_512_BYTE_SIZE);
    }
    else
    {
        *hashLenOut = SSF_SHA2_256_BYTE_SIZE;
        SSFSHA256(data, dataLen, hash, SSF_SHA2_256_BYTE_SIZE);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sig over data verifies with keyCert's public key under sigAlg, else false.     */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifySignature(const SSFX509Cert_t *keyCert, const uint8_t *sigAlgOidRaw,
                            uint32_t sigAlgOidRawLen, const uint8_t *sigAlgParamsOpt,
                            uint32_t sigAlgParamsLen, const uint8_t *digestAlgOidRawOpt,
                            uint32_t digestAlgOidRawLen, const uint8_t *data, uint32_t dataLen,
                            const uint8_t *sig, uint32_t sigLen)
{
    SSFECCurve_t curve;
    SSFRSAHash_t hashId;
    const uint8_t *impliedOid;
    uint32_t impliedOidLen;
    uint8_t hash[SSF_SHA2_512_BYTE_SIZE];
    size_t hashLen;
    uint32_t saltLen;
    bool isEcdsa256;
    bool isRsaPlain;
    bool ok;

    SSF_REQUIRE(keyCert != NULL);
    SSF_REQUIRE(sigAlgOidRaw != NULL);
    SSF_REQUIRE((sigAlgParamsOpt != NULL) || (sigAlgParamsLen == 0u));
    SSF_REQUIRE((digestAlgOidRawOpt != NULL) || (digestAlgOidRawLen == 0u));
    SSF_REQUIRE((data != NULL) || (dataLen == 0u));
    SSF_REQUIRE(sig != NULL);

    /* Is the key empty (an untrusted issuer's key reaches here, AUDIT X509-2)? */
    if ((keyCert->pubKey == NULL) || (keyCert->pubKeyLen == 0u))
    {
        /* Yes, nothing to verify with; the verifiers would trap on it */
        SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "VerifySig: empty public key");
        return false;
    }
    /* No, hand the key to the scheme the signature algorithm selects */

    /* ECDSA with SHA-256 or SHA-384 (the OID selects the hash, the key its curve, RFC 5758)? */
    isEcdsa256 = _SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidEcdsaSHA256,
                                  sizeof(_oidEcdsaSHA256));
    if ((isEcdsa256) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidEcdsaSHA384, sizeof(_oidEcdsaSHA384))))
    {
        /* Yes */
        hashId = isEcdsa256 ? SSF_RSA_HASH_SHA256 : SSF_RSA_HASH_SHA384;

        /* Digest algorithm, when given, is the one the signature algorithm implies? */
        impliedOid = _SSFX509OIDForHash(hashId, &impliedOidLen);
        if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, impliedOid,
                                  impliedOidLen))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "VerifySig: digest algorithm disagrees with ECDSA signature algorithm");
            return false;
        }
        _SSFX509Digest(hashId, data, dataLen, hash, &hashLen);

        /* Is the key on a curve compiled into this build (AUDIT CFG-1)? */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
        if (SSFX509IsP256(keyCert))
        {
            /* Yes, P-256 */
            curve = SSF_EC_CURVE_P256;
        }
        else
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
        /* Is the key on P-384? */
        if (SSFX509IsP384(keyCert))
        {
            /* Yes, P-384 */
            curve = SSF_EC_CURVE_P384;
        }
        else
#endif
        {
            /* No, unknown curve or one compiled out of this build; nothing to verify with */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "VerifySig: ECDSA key curve OID not recognized or not enabled (%u bytes)",
                keyCert->ecCurveOidRawLen);
            return false;
        }

        /* ssfecdsa truncates a digest longer than the curve order (AUDIT ECDSA-3) */

        /* keyCert's pubKey is the SEC 1 uncompressed point held in the SPKI BIT STRING */
        ok = SSFECDSAVerify(curve, keyCert->pubKey, (size_t)keyCert->pubKeyLen, hash, hashLen, sig,
                            (size_t)sigLen);
        SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx,
            "VerifySig: ECDSA curve=%d pubKeyLen=%u sigLen=%u -> %s", curve, keyCert->pubKeyLen,
            sigLen, ok ? "OK" : "FAIL");
        return ok;
    }

    /* RSA PKCS#1 v1.5, by a hashed-with-RSA OID or plain rsaEncryption (RFC 3370 Sec. 3.2)? */
    isRsaPlain = _SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSA, sizeof(_oidRSA));
    if ((isRsaPlain) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA256,
                   sizeof(_oidRSAPKCS1SHA256))) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA384,
                   sizeof(_oidRSAPKCS1SHA384))) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA512,
                   sizeof(_oidRSAPKCS1SHA512))))
    {
        /* Yes, plain rsaEncryption? */
        if (isRsaPlain)
        {
            /* Yes, the digest algorithm alone names the hash and must be a supported one */
            if (!_SSFX509HashFromOID(digestAlgOidRawOpt, digestAlgOidRawLen, &hashId))
            {
                SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                    "VerifySig: rsaEncryption needs a SHA-2 digest algorithm (%u bytes given)",
                    digestAlgOidRawLen);
                return false;
            }
        }
        else
        {
            /* No, the OID names the hash and the digest algorithm, when given, must agree */
            if (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA256,
                          sizeof(_oidRSAPKCS1SHA256)))
            {
                hashId = SSF_RSA_HASH_SHA256;
            }
            else if (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA384,
                               sizeof(_oidRSAPKCS1SHA384)))
            {
                hashId = SSF_RSA_HASH_SHA384;
            }
            else
            {
                hashId = SSF_RSA_HASH_SHA512;
            }
            impliedOid = _SSFX509OIDForHash(hashId, &impliedOidLen);
            if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, impliedOid,
                                      impliedOidLen))
            {
                SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                    "VerifySig: digest algorithm disagrees with RSA signature algorithm");
                return false;
            }
        }
        _SSFX509Digest(hashId, data, dataLen, hash, &hashLen);

        /* keyCert's pubKey is the DER RSAPublicKey held in the SPKI BIT STRING */
        ok = SSFRSAVerifyPKCS1(keyCert->pubKey, (size_t)keyCert->pubKeyLen, hashId, hash, hashLen,
                               sig, (size_t)sigLen);
        SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx,
            "VerifySig: RSA-PKCS1 hash=%d pubKeyLen=%u sigLen=%u -> %s", hashId,
            keyCert->pubKeyLen, sigLen, ok ? "OK" : "FAIL");
        return ok;
    }

    /* RSA-PSS, whose parameters select the hash and salt length (RFC 4055)? */
    if (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPSS, sizeof(_oidRSAPSS)))
    {
        /* Yes */
        _SSFX509ParsePSSParams(sigAlgParamsOpt, sigAlgParamsLen, &hashId, &saltLen);

        /* Digest algorithm, when given, is the hash the parameters select? */
        impliedOid = _SSFX509OIDForHash(hashId, &impliedOidLen);
        if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, impliedOid,
                                  impliedOidLen))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "VerifySig: digest algorithm disagrees with RSA-PSS parameters");
            return false;
        }
        _SSFX509Digest(hashId, data, dataLen, hash, &hashLen);

        /* Salt length within what the verifier supports? */
        if (saltLen > hashLen)
        {
            /* No, longer than the hash is never issued and is not accepted */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "VerifySig: RSA-PSS saltLength %u exceeds hash length %u", saltLen,
                (unsigned int)hashLen);
            return false;
        }
        ok = SSFRSAVerifyPSS(keyCert->pubKey, (size_t)keyCert->pubKeyLen, hashId, hash, hashLen,
                             (size_t)saltLen, sig, (size_t)sigLen);
        SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx,
            "VerifySig: RSA-PSS hash=%d pubKeyLen=%u sigLen=%u -> %s", hashId, keyCert->pubKeyLen,
            sigLen, ok ? "OK" : "FAIL");
        return ok;
    }

    /* Ed25519, which signs the data itself (RFC 8410)? */
    if (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidEd25519, sizeof(_oidEd25519)))
    {
        /* Yes; RFC 8419 pairs it only with SHA-512, so a given digest algorithm is SHA-512? */
        if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, _oidSHA512,
                                  sizeof(_oidSHA512)))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "VerifySig: Ed25519 requires the SHA-512 digest algorithm");
            return false;
        }

        /* Key and signature the sizes Ed25519 defines? */
        if ((keyCert->pubKeyLen != SSF_ED25519_PUB_KEY_SIZE) || (sigLen != SSF_ED25519_SIG_SIZE))
        {
            /* No, malformed */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "VerifySig: Ed25519 bad key/sig size (pubKey=%u sig=%u)", keyCert->pubKeyLen,
                sigLen);
            return false;
        }
        ok = SSFEd25519Verify(keyCert->pubKey, data, dataLen, sig);
        SSF_TLS_TRACE_CERT_DEBUG(&_ssfx509TraceCtx,
            "VerifySig: Ed25519 pubKeyLen=%u sigLen=%u -> %s", keyCert->pubKeyLen, sigLen,
            ok ? "OK" : "FAIL");
        return ok;
    }

    SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "VerifySig: unsupported sigAlg OID (%u bytes)",
                             sigAlgOidRawLen);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if cert's signature over its TBS verifies with issuer's public key, else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifyCertSignature(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer)
{
    SSF_REQUIRE(cert != NULL);
    SSF_REQUIRE(issuer != NULL);
    SSF_REQUIRE(cert->tbsRaw != NULL);
    SSF_REQUIRE(cert->signature != NULL);

    /* The signed TBS copy of the algorithm identifier is the one that selects the scheme */
    return SSFX509VerifySignature(issuer, cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                                  cert->sigAlgParams, cert->sigAlgParamsLen, NULL, 0u, cert->tbsRaw,
                                  cert->tbsRawLen, cert->signature, cert->signatureLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if cert's AKID and issuer's SKID match or either is absent, else false.          */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509CheckSKIDAKID(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer)
{
    SSF_REQUIRE(cert != NULL);
    SSF_REQUIRE(issuer != NULL);

    if ((cert->akid == NULL) || (cert->akidLen == 0u)) return true;
    if ((issuer->skid == NULL) || (issuer->skidLen == 0u)) return true;
    if (cert->akidLen != issuer->skidLen) return false;
    return (memcmp(cert->akid, issuer->skid, cert->akidLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if issuer and subject Names are byte-identical raw DER, else false.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NameEquals(const SSFX509Name_t *issuer, const SSFX509Name_t *subject)
{
    SSF_REQUIRE(issuer != NULL);
    SSF_REQUIRE(subject != NULL);

    if ((issuer->raw == NULL) || (subject->raw == NULL)) return false;
    if (issuer->rawLen != subject->rawLen) return false;
    return (memcmp(issuer->raw, subject->raw, issuer->rawLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a dNSName satisfies a dNSName constraint (RFC 5280 Sec. 4.2.1.10), else false. */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NCDNSMatch(const uint8_t *name, uint32_t nameLen, const uint8_t *constraint,
                        uint32_t constraintLen)
{
    uint32_t offset;

    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE((constraint != NULL) || (constraintLen == 0u));

    /* An empty constraint matches every name */
    if (constraintLen == 0u) return true;

    /* Leading-dot form used by some CAs, meaning proper subdomains only? */
    if (constraint[0] == (uint8_t)'.')
    {
        /* Yes, the name must be longer than the constraint and end with it */
        if (nameLen <= constraintLen) return false;
        return SSFMatchStrNI((const char *)&name[nameLen - constraintLen],
                             (SSFCStrIn_t)constraint, constraintLen);
    }

    /* No, the name is the constraint itself or ends with "." followed by the constraint */
    if (nameLen < constraintLen) return false;
    offset = nameLen - constraintLen;
    if ((offset != 0u) && (name[offset - 1u] != (uint8_t)'.')) return false;
    return SSFMatchStrNI((const char *)&name[offset], (SSFCStrIn_t)constraint, constraintLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a 4-byte IPv4 SAN lies within an 8-byte address plus mask constraint.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NCIPMatch(const uint8_t *ip, uint32_t ipLen, const uint8_t *constraint,
                       uint32_t constraintLen)
{
    uint32_t i;

    SSF_REQUIRE(ip != NULL);
    SSF_REQUIRE(constraint != NULL);

    /* Only IPv4 constraints are supported */
    if ((ipLen != 4u) || (constraintLen != 8u)) return false;
    for (i = 0; i < 4u; i++)
    {
        if ((ip[i] & constraint[4u + i]) != (constraint[i] & constraint[4u + i])) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if one SAN entry matches one Name Constraints subtree of the same type.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NCSubtreeMatch(const SSFX509SAN_t *san, const SSFX509NameConstraint_t *subtree)
{
    SSF_REQUIRE(san != NULL);
    SSF_REQUIRE(subtree != NULL);

    if (subtree->type != san->type) return false;
    if (subtree->type == SSF_X509_SAN_DNS)
    {
        return _SSFX509NCDNSMatch(san->val, san->valLen, subtree->val, subtree->valLen);
    }
    if (subtree->type == SSF_X509_SAN_IP)
    {
        return _SSFX509NCIPMatch(san->val, san->valLen, subtree->val, subtree->valLen);
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if every SAN of subCert satisfies ncCert's Name Constraints, else false.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NCValidateCert(const SSFX509Cert_t *subCert, const SSFX509Cert_t *ncCert)
{
    const SSFX509SAN_t *san;
    bool typeHasPermitted;
    bool typeMatched;
    uint8_t s;
    uint8_t k;

    SSF_REQUIRE(subCert != NULL);
    SSF_REQUIRE(ncCert != NULL);

    for (s = 0; s < subCert->sanLen; s++)
    {
        san = &subCert->san[s];

        /* Any excluded subtree matching this SAN rejects the certificate */
        for (k = 0; k < ncCert->excludedLen; k++)
        {
            if (_SSFX509NCSubtreeMatch(san, &ncCert->excludedSubtrees[k])) return false;
        }

        /* With permitted subtrees of this SAN's type present, one of them must match */
        typeHasPermitted = false;
        typeMatched = false;
        for (k = 0; k < ncCert->permittedLen; k++)
        {
            if (ncCert->permittedSubtrees[k].type != san->type) continue;
            typeHasPermitted = true;
            if (_SSFX509NCSubtreeMatch(san, &ncCert->permittedSubtrees[k]))
            {
                typeMatched = true;
                break;
            }
        }
        if (typeHasPermitted && !typeMatched) return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a critical extension OID is one this verifier understands, else false.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509IsKnownExtension(const uint8_t *oidRaw, uint32_t oidRawLen)
{
    SSF_REQUIRE(oidRaw != NULL);

    return _SSFX509OIDMatch(oidRaw, oidRawLen, _oidBasicConstraints,
                            sizeof(_oidBasicConstraints)) ||
           _SSFX509OIDMatch(oidRaw, oidRawLen, _oidKeyUsage, sizeof(_oidKeyUsage)) ||
           _SSFX509OIDMatch(oidRaw, oidRawLen, _oidSAN, sizeof(_oidSAN)) ||
           _SSFX509OIDMatch(oidRaw, oidRawLen, _oidSKID, sizeof(_oidSKID)) ||
           _SSFX509OIDMatch(oidRaw, oidRawLen, _oidAKID, sizeof(_oidAKID)) ||
           _SSFX509OIDMatch(oidRaw, oidRawLen, _oidEKU, sizeof(_oidEKU)) ||
           _SSFX509OIDMatch(oidRaw, oidRawLen, _oidNameConstraints, sizeof(_oidNameConstraints));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if chainDer[0] validates to a trust anchor for purpose, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifyChainPurpose(const uint8_t **chainDer, const uint32_t *chainDerLen,
                               uint8_t chainLen,
                               const uint8_t **trustDer, const uint32_t *trustDerLen,
                               uint8_t trustCount, SSFX509Purpose_t purpose,
                               const char *hostnameStrOpt, uint64_t nowUnixSec)
{
    SSFX509Cert_t certs[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    SSFX509Cert_t anchor;
    const SSFX509Cert_t *last;
    bool trusted = false;
    bool matched = false;
    uint8_t numSubCAs;
    uint8_t i;
    uint8_t j;
    uint8_t e;

    SSF_REQUIRE(chainDer != NULL);
    SSF_REQUIRE(chainDerLen != NULL);
    SSF_REQUIRE(chainLen >= 1u);
    SSF_REQUIRE(chainLen <= SSF_X509_CONFIG_MAX_CHAIN_DEPTH);
    SSF_REQUIRE(trustDer != NULL);
    SSF_REQUIRE(trustDerLen != NULL);
    SSF_REQUIRE(trustCount >= 1u);
    SSF_REQUIRE((purpose > SSF_X509_PURPOSE_MIN) && (purpose < SSF_X509_PURPOSE_MAX));
    SSF_REQUIRE((purpose != SSF_X509_PURPOSE_SERVER_AUTH) ||
                ((hostnameStrOpt != NULL) && (hostnameStrOpt[0] != '\0')));

    for (i = 0; i < chainLen; i++)
    {
        SSF_REQUIRE(chainDer[i] != NULL);

        /* Chain certificate parses? */
        if (!SSFX509Parse(chainDer[i], chainDerLen[i], &certs[i]))
        {
            /* No, malformed */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: parse cert[%u] failed (%u bytes)",
                                     i, chainDerLen[i]);
            return false;
        }

        /* Version 3 as RFC 5280 Sec. 6.1.1 (c) requires of every chain certificate? */
        if (certs[i].version != 2u)
        {
            /* No, v1 and v2 certificates cannot carry the extensions this path relies on */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx, "Chain: cert[%u] is v%u (must be v3)", i,
                                     certs[i].version + 1u);
            return false;
        }

        /* TBS signature algorithm OID equals the outer signatureAlgorithm OID (Sec. 4.1.2.3)? */
        if ((certs[i].sigAlgOidRawLen != certs[i].outerSigAlgOidRawLen) ||
            (memcmp(certs[i].sigAlgOidRaw, certs[i].outerSigAlgOidRaw,
                    certs[i].sigAlgOidRawLen) != 0))
        {
            /* No, the unsigned outer copy disagrees with the signed one */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] TBS sigAlg OID (%u bytes) != outer sigAlg OID (%u bytes)", i,
                certs[i].sigAlgOidRawLen, certs[i].outerSigAlgOidRawLen);
            return false;
        }

        /* Signature algorithm parameters identical as well (Sec. 4.1.1.2)? */
        if ((certs[i].sigAlgParamsLen != certs[i].outerSigAlgParamsLen) ||
            ((certs[i].sigAlgParamsLen > 0u) &&
             (memcmp(certs[i].sigAlgParams, certs[i].outerSigAlgParams,
                     certs[i].sigAlgParamsLen) != 0)))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] TBS sigAlg params (%u bytes) != outer params (%u bytes)", i,
                certs[i].sigAlgParamsLen, certs[i].outerSigAlgParamsLen);
            return false;
        }

        /* Within its validity period at nowUnixSec? */
        if (!SSFX509IsValid(&certs[i], nowUnixSec))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] not valid at time %llu (notBefore=%llu notAfter=%llu)", i,
                (unsigned long long)nowUnixSec, (unsigned long long)certs[i].notBefore,
                (unsigned long long)certs[i].notAfter);
            return false;
        }
    }
    last = &certs[chainLen - 1u];

    /* Each cert[i] is named for, signed by, and key-linked to cert[i + 1] */
    for (i = 0; i < (uint8_t)(chainLen - 1u); i++)
    {
        /* Issuer name of cert[i] is the subject name of cert[i + 1] (Sec. 6.1.3 (a)(4))? */
        if (!_SSFX509NameEquals(&certs[i].issuer, &certs[i + 1u].subject))
        {
            /* No, the chain is not linked by name even if the key happens to verify */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] issuer name does not match cert[%u] subject name", i, i + 1u);
            return false;
        }

        /* Signature of cert[i] verifies with the key of cert[i + 1]? */
        if (!SSFX509VerifyCertSignature(&certs[i], &certs[i + 1u]))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] signature by cert[%u] FAILED", i, i + 1u);
            return false;
        }

        /* AKID of cert[i] agrees with the SKID of cert[i + 1] when both are present (4.2.1.1)? */
        if (!SSFX509CheckSKIDAKID(&certs[i], &certs[i + 1u]))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] AKID (%u bytes) does not match cert[%u] SKID (%u bytes)", i,
                certs[i].akidLen, i + 1u, certs[i + 1u].skidLen);
            return false;
        }
    }

    /* Some trust anchor names, is valid for, key-links to, and signs the last chain cert */
    memset(&anchor, 0, sizeof(anchor));
    for (j = 0; (j < trustCount) && !trusted; j++)
    {
        SSF_REQUIRE(trustDer[j] != NULL);
        if (!SSFX509Parse(trustDer[j], trustDerLen[j], &anchor)) continue;
        if (!_SSFX509NameEquals(&last->issuer, &anchor.subject)) continue;
        if (!SSFX509IsValid(&anchor, nowUnixSec)) continue;
        if (!SSFX509CheckSKIDAKID(last, &anchor)) continue;
        trusted = SSFX509VerifyCertSignature(last, &anchor);
    }

    /* Anchored? */
    if (!trusted)
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
            "Chain: no trust anchor found for issuer of cert[%u] (%u CAs checked)", chainLen - 1u,
            trustCount);
        return false;
    }

    /* Every intermediate is a CA allowed to sign, within its path length (Sec. 6.1.4 (h), (k)) */
    for (i = 1; i < chainLen; i++)
    {
        /* Basic Constraints present with cA TRUE? */
        if (!certs[i].hasBasicConstraints || !certs[i].isCA)
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] not a CA (hasBC=%d isCA=%d)",
                i, certs[i].hasBasicConstraints, certs[i].isCA);
            return false;
        }

        /* Key Usage, when present, includes keyCertSign? */
        if (certs[i].hasKeyUsage && ((certs[i].keyUsageBits & SSF_X509_KU_KEY_CERT_SIGN) == 0u))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] is CA but Key Usage lacks keyCertSign (KU=0x%04X)", i,
                certs[i].keyUsageBits);
            return false;
        }

        /* Subordinate CA count below cert[i], which is (i - 1), within its pathLenConstraint? */
        if ((certs[i].pathLenConstraint >= 0) && ((int8_t)(i - 1u) > certs[i].pathLenConstraint))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] pathLenConstraint=%d but %u subordinate CAs present", i,
                certs[i].pathLenConstraint, i - 1u);
            return false;
        }
    }

    /* anchor is the one whose key verified the last chain cert; only its constraints apply */
    numSubCAs = (chainLen >= 2u) ? (uint8_t)(chainLen - 1u) : 0u;

    /* Subordinate CAs in the chain within the anchor's pathLenConstraint (Sec. 6.1.4 (k))? */
    if ((anchor.pathLenConstraint >= 0) && ((int8_t)numSubCAs > anchor.pathLenConstraint))
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
            "Chain: trust anchor pathLenConstraint=%d but %u subordinate CAs in chain",
            anchor.pathLenConstraint, numSubCAs);
        return false;
    }

    /* Every chain cert's SANs satisfy the anchor's Name Constraints (Sec. 6.1.4 (g))? */
    for (i = 0; (anchor.hasNameConstraints) && (i < chainLen); i++)
    {
        if (!_SSFX509NCValidateCert(&certs[i], &anchor))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] SAN violates nameConstraints of trust anchor", i);
            return false;
        }
    }

    /* Leaf EKU, when present, includes the purpose or anyExtendedKeyUsage (Sec. 4.2.1.12)? */
    if ((certs[0].hasExtKeyUsage) && (!certs[0].ekuAnyPurpose) &&
        (((purpose == SSF_X509_PURPOSE_SERVER_AUTH) && (!certs[0].ekuServerAuth)) ||
         ((purpose == SSF_X509_PURPOSE_CODE_SIGNING) && (!certs[0].ekuCodeSigning))))
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
            "Chain: leaf EKU lacks the purpose %d (serverAuth=%d clientAuth=%d codeSigning=%d)",
            purpose, certs[0].ekuServerAuth, certs[0].ekuClientAuth, certs[0].ekuCodeSigning);
        return false;
    }

    /* Code signing: leaf Key Usage, when present, includes digitalSignature or nonRepudiation? */
    if ((purpose == SSF_X509_PURPOSE_CODE_SIGNING) && (certs[0].hasKeyUsage) &&
        ((certs[0].keyUsageBits &
          (SSF_X509_KU_DIGITAL_SIGNATURE | SSF_X509_KU_NON_REPUDIATION)) == 0u))
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
            "Chain: leaf Key Usage lacks digitalSignature and nonRepudiation (KU=0x%04X)",
            certs[0].keyUsageBits);
        return false;
    }

    /* Every subordinate of a constrained intermediate satisfies its Name Constraints (6.1.4 (g)) */
    for (i = 1; i < chainLen; i++)
    {
        for (j = 0; certs[i].hasNameConstraints && (j < i); j++)
        {
            if (!_SSFX509NCValidateCert(&certs[j], &certs[i]))
            {
                SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                    "Chain: cert[%u] SAN violates nameConstraints of cert[%u]", j, i);
                return false;
            }
        }
    }

    /* No chain cert carries a critical extension this verifier does not understand (Sec. 4.2) */
    for (i = 0; i < chainLen; i++)
    {
        for (e = 0; e < certs[i].extsLen; e++)
        {
            if (!certs[i].exts[e].critical) continue;
            if (_SSFX509IsKnownExtension(certs[i].exts[e].oidRaw,
                                         certs[i].exts[e].oidRawLen)) continue;
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: cert[%u] has unrecognized critical extension (OID %u bytes)", i,
                certs[i].exts[e].oidRawLen);
            return false;
        }
    }

    /* Server authentication: the leaf names hostnameStrOpt in a dNSName or iPAddress SAN */
    if (purpose == SSF_X509_PURPOSE_SERVER_AUTH)
    {
        for (i = 0; (i < certs[0].sanLen) && (!matched); i++)
        {
            if (certs[0].san[i].type == SSF_X509_SAN_DNS)
            {
                matched = _SSFX509HostnameMatch(hostnameStrOpt, certs[0].san[i].val,
                                         certs[0].san[i].valLen);
            }
            else if (certs[0].san[i].type == SSF_X509_SAN_IP)
            {
                matched = _SSFX509IPAddressMatch(hostnameStrOpt, certs[0].san[i].val,
                                          certs[0].san[i].valLen);
            }
        }

        /* Hostname matched? */
        if (!matched)
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(&_ssfx509TraceCtx,
                "Chain: hostname '%s' not matched in SAN (sanLen=%u)", hostnameStrOpt,
                certs[0].sanLen);
            return false;
        }
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if chainDer[0] validates to a trust anchor and is issued for hostnameStr.        */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifyChain(const uint8_t **chainDer, const uint32_t *chainDerLen, uint8_t chainLen,
                        const uint8_t **trustDer, const uint32_t *trustDerLen, uint8_t trustCount,
                        const char *hostnameStr, uint64_t nowUnixSec)
{
    SSF_REQUIRE(hostnameStr != NULL);
    SSF_REQUIRE(hostnameStr[0] != '\0');

    return SSFX509VerifyChainPurpose(chainDer, chainDerLen, chainLen, trustDer, trustDerLen,
                                     trustCount, SSF_X509_PURPOSE_SERVER_AUTH, hostnameStr,
                                     nowUnixSec);
}
