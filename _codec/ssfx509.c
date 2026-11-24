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
#include "ssfstr.h"

#if SSF_X509_CONFIG_RSA_MIN_BITS < 1024u
#error SSF_X509_CONFIG_RSA_MIN_BITS must be >= 1024.
#endif

/* RSA signature schemes this build verifies (each also needs an RSA key size enabled) */
#if (SSF_RSA_ANY_ENABLED == 1) && (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1)
#define _SSF_X509_RSA_PKCS1 (1u)
#else
#define _SSF_X509_RSA_PKCS1 (0u)
#endif
#if (SSF_RSA_ANY_ENABLED == 1) && (SSF_RSA_CONFIG_ENABLE_PSS == 1)
#define _SSF_X509_RSA_PSS (1u)
#else
#define _SSF_X509_RSA_PSS (0u)
#endif

#if SSF_TLS_CONFIG_ENABLE_TRACE == 1
/* Module-scope trace context for chain verification, installed by SSFX509SetTraceCtx() */
static SSFTLSTraceCtx_t _ssfx509TraceCtx;
#define _SSF_X509_TRACE_CTX (&_ssfx509TraceCtx)

/* Caller trace callback that _SSFX509TraceAdapter() forwards each message to */
static void (*_ssfx509TraceFn)(int, int, const char *, void *);
#else
/* Tracing compiled out: the trace macros discard this NULL context */
#define _SSF_X509_TRACE_CTX ((SSFTLSTraceCtx_t *)NULL)
#endif

#if SSF_TLS_CONFIG_ENABLE_TRACE == 1
/* --------------------------------------------------------------------------------------------- */
/* Delivers a trace message to the installed int-signature callback.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFX509TraceAdapter(SSFTLSTraceLevel_t level, SSFTLSTraceCategory_t category,
                                 const char *msgStr, void *userCtxOpt)
{
    SSF_REQUIRE(level <= SSF_TLS_TRACE_DEBUG);
    SSF_REQUIRE(category <= SSF_TLS_TRACE_ALERT);
    SSF_REQUIRE(msgStr != NULL);
    SSF_REQUIRE(_ssfx509TraceFn != NULL);

    _ssfx509TraceFn((int)level, (int)category, msgStr, userCtxOpt);
}

/* --------------------------------------------------------------------------------------------- */
/* Installs the module-wide verification trace callback; a NULL fnOpt disables tracing.          */
/* --------------------------------------------------------------------------------------------- */
void SSFX509SetTraceCtx(void (*fnOpt)(int, int, const char *, void *), void *userCtxOpt)
{
    _ssfx509TraceFn = fnOpt;
    _ssfx509TraceCtx.fn = (fnOpt != NULL) ? _SSFX509TraceAdapter : NULL;
    _ssfx509TraceCtx.userCtx = userCtxOpt;
}
#endif /* SSF_TLS_CONFIG_ENABLE_TRACE */

/* --------------------------------------------------------------------------------------------- */
/* OID constant tables (raw DER-encoded content bytes)                                           */
/* --------------------------------------------------------------------------------------------- */

/* DN attribute OIDs (2.5.4.x) */
static const uint8_t _oidCN[]  = { 0x55u, 0x04u, 0x03u }; /* 2.5.4.3 commonName */
static const uint8_t _oidEmailAddress[] = {                 /* 1.2.840.113549.1.9.1 */
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x01u
};
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

/* id-Ed25519 (RFC 8410): 1.3.101.112, for both the SPKI and signature algorithm, no parameters */
static const uint8_t _oidEd25519[] = { 0x2Bu, 0x65u, 0x70u };

/* id-sha256: 2.16.840.1.101.3.4.2.1 (RFC 4055 hash algorithm OIDs follow) */
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
#if _SSF_X509_RSA_PSS == 1
/* id-mgf1: 1.2.840.113549.1.1.8 */
static const uint8_t _oidMGF1[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u
};
#endif /* _SSF_X509_RSA_PSS == 1 */

/* id-kp-serverAuth: 1.3.6.1.5.5.7.3.1 (RFC 5280 Section 4.2.1.12 EKU OIDs follow) */
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
/* Returns true if raw OID a equals raw OID b, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509OIDMatch(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen)
{
    SSF_REQUIRE((a != NULL) || (aLen == 0u));
    SSF_REQUIRE((b != NULL) || (bLen == 0u));

    if (aLen != bLen) return false;
    return (memcmp(a, b, aLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a and b hold len equal bytes ignoring ASCII case; NUL is an ordinary byte.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509MemEqI(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t k;

    SSF_REQUIRE((a != NULL) || (len == 0u));
    SSF_REQUIRE((b != NULL) || (len == 0u));

    for (k = 0; k < len; k++)
    {
        /* Do the bytes differ even after ASCII case folding? */
        if (SSFStrCharToLower((char)a[k]) != SSFStrCharToLower((char)b[k]))
        {
            /* Yes */
            return false;
        }
        /* No */
    }
    return true;
}

#if _SSF_X509_RSA_PSS == 1
/* --------------------------------------------------------------------------------------------- */
/* Returns true if cursor holds exactly one SHA-2 AlgorithmIdentifier, setting *hashOut.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509PSSHashAlgId(const SSFASN1Cursor_t *cursor, SSFRSAHash_t *hashOut)
{
    SSFASN1Cursor_t algIdInner;
    SSFASN1Cursor_t after;
    const uint8_t *oidRaw;
    uint32_t oidRawLen;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(hashOut != NULL);

    /* Is it one AlgorithmIdentifier SEQUENCE starting with an OID, and nothing after it? */
    if ((!SSFASN1DecOpenConstructed(cursor, SSF_ASN1_TAG_SEQUENCE, &algIdInner, &after)) ||
        (!SSFASN1DecIsEmpty(&after)) ||
        (!SSFASN1DecGetOIDRaw(&algIdInner, &oidRaw, &oidRawLen, &algIdInner)))
    {
        /* No */
        return false;
    }
    /* Yes, are parameters present that are anything other than a lone NULL? */
    if ((!SSFASN1DecIsEmpty(&algIdInner)) &&
        ((!SSFASN1DecGetNull(&algIdInner, &algIdInner)) || (!SSFASN1DecIsEmpty(&algIdInner))))
    {
        /* Yes */
        return false;
    }
    /* No, absent or NULL; is the OID a supported SHA-2 hash? */
    if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidSHA256, sizeof(_oidSHA256)))
    {
        /* Yes, SHA-256 */
        *hashOut = SSF_RSA_HASH_SHA256;
    }
    else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidSHA384, sizeof(_oidSHA384)))
    {
        /* Yes, SHA-384 */
        *hashOut = SSF_RSA_HASH_SHA384;
    }
    else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidSHA512, sizeof(_oidSHA512)))
    {
        /* Yes, SHA-512 */
        *hashOut = SSF_RSA_HASH_SHA512;
    }
    else
    {
        /* No, SHA-1 or unknown */
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if paramsOpt are supported RSASSA-PSS-params (RFC 4055 3.1), setting hash/salt.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509ParsePSSParams(const uint8_t *paramsOpt, uint32_t paramsLen,
                                   SSFRSAHash_t *hashOut, uint32_t *saltLenOut)
{
    SSFASN1Cursor_t cursor;
    SSFASN1Cursor_t seqInner;
    SSFASN1Cursor_t fieldInner;
    SSFASN1Cursor_t mgfInner;
    SSFASN1Cursor_t after;
    const uint8_t *oidRaw;
    uint32_t oidRawLen;
    SSFRSAHash_t mgfHash;
    uint64_t val;
    uint16_t tag;

    SSF_REQUIRE((paramsOpt != NULL) || (paramsLen == 0u));
    SSF_REQUIRE(hashOut != NULL);
    SSF_REQUIRE(saltLenOut != NULL);

    /* Are the parameters absent? */
    if ((paramsOpt == NULL) || (paramsLen == 0u))
    {
        /* Yes, the RFC 4055 defaults select SHA-1, which is not supported */
        return false;
    }
    /* No, are they exactly one SEQUENCE? */
    cursor.buf = paramsOpt;
    cursor.bufLen = paramsLen;
    if ((!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &seqInner, &after)) ||
        (!SSFASN1DecIsEmpty(&after)))
    {
        /* No */
        return false;
    }
    /* Yes */

    /* Is [0] hashAlgorithm present and a supported SHA-2 hash (its default SHA-1 is not)? */
    if ((!SSFASN1DecOpenConstructed(&seqInner, SSF_ASN1_CONTEXT_EXPLICIT(0), &fieldInner,
                                    &seqInner)) || (!_SSFX509PSSHashAlgId(&fieldInner, hashOut)))
    {
        /* No */
        return false;
    }
    /* Yes */

    /* Is [1] maskGenAlgorithm present as MGF1 over that same hash (default MGF1-SHA-1 is not)? */
    if ((!SSFASN1DecOpenConstructed(&seqInner, SSF_ASN1_CONTEXT_EXPLICIT(1), &fieldInner,
                                    &seqInner)) ||
        (!SSFASN1DecOpenConstructed(&fieldInner, SSF_ASN1_TAG_SEQUENCE, &mgfInner, &after)) ||
        (!SSFASN1DecIsEmpty(&after)) ||
        (!SSFASN1DecGetOIDRaw(&mgfInner, &oidRaw, &oidRawLen, &mgfInner)) ||
        (!_SSFX509OIDMatch(oidRaw, oidRawLen, _oidMGF1, sizeof(_oidMGF1))) ||
        (!_SSFX509PSSHashAlgId(&mgfInner, &mgfHash)) || (mgfHash != *hashOut))
    {
        /* No */
        return false;
    }
    /* Yes */

    *saltLenOut = 20u;

    /* Is [2] saltLength present? */
    if ((SSFASN1DecPeekTag(&seqInner, &tag)) && (tag == SSF_ASN1_CONTEXT_EXPLICIT(2)))
    {
        /* Yes, is it exactly one valid unsigned INTEGER? */
        if ((!SSFASN1DecOpenConstructed(&seqInner, SSF_ASN1_CONTEXT_EXPLICIT(2), &fieldInner,
                                        &seqInner)) ||
            (!SSFASN1DecGetIntU64(&fieldInner, &val, &fieldInner)) ||
            (!SSFASN1DecIsEmpty(&fieldInner)))
        {
            /* No */
            return false;
        }
        /* Yes, oversize values are capped and rejected by the caller */
        *saltLenOut = (val > 255u) ? 255u : (uint32_t)val;
    }
    /* No, the default 20 applies */

    /* Is [3] trailerField present? */
    if ((SSFASN1DecPeekTag(&seqInner, &tag)) && (tag == SSF_ASN1_CONTEXT_EXPLICIT(3)))
    {
        /* Yes, it must be exactly INTEGER 1 (trailerFieldBC) */
        if ((!SSFASN1DecOpenConstructed(&seqInner, SSF_ASN1_CONTEXT_EXPLICIT(3), &fieldInner,
                                        &seqInner)) ||
            (!SSFASN1DecGetIntU64(&fieldInner, &val, &fieldInner)) ||
            (!SSFASN1DecIsEmpty(&fieldInner)) || (val != 1u))
        {
            /* No */
            return false;
        }
        /* Yes */
    }
    /* No, the default 1 applies */

    /* Is anything left: an unknown, repeated or out-of-order field? */
    if (!SSFASN1DecIsEmpty(&seqInner))
    {
        /* Yes */
        return false;
    }
    /* No */
    return true;
}
#endif /* _SSF_X509_RSA_PSS == 1 */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if nameCursor holds a well-formed Name, setting name's attributes, else false.   */
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

            /* Is it an emailAddress, an rfc822Name instance for Name Constraints? */
            if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidEmailAddress, sizeof(_oidEmailAddress)))
            {
                /* Yes, recorded before the value is read so any string type counts */
                name->hasEmailAddress = true;
            }
            /* No */

            /* Is the attribute value one of the supported string types? */
            if (!SSFASN1DecGetString(&attrInner, &val, &valLen, &strTag, &attrInner))
            {
                /* No, it must still be one TLV; leave it unnamed, the raw DN serves comparison */
                if (!SSFASN1DecGetTLV(&attrInner, &strTag, &val, &valLen, &attrInner)) return false;
                if (!SSFASN1DecIsEmpty(&attrInner)) return false;
                continue;
            }
            /* Yes, is anything left after the attribute value? */
            if (!SSFASN1DecIsEmpty(&attrInner))
            {
                /* Yes, malformed */
                return false;
            }
            /* No */

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
/* Returns true if extsCursor holds well-formed Extensions, recorded into cert, else false.      */
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

        {
            uint8_t dup;
            for (dup = 0; dup < cert->extsLen; dup++)
            {
                /* Is it a duplicate of an extension already seen (RFC 5280 Sec. 4.2 forbids)? */
                if (_SSFX509OIDMatch(cert->exts[dup].oidRaw, cert->exts[dup].oidRawLen,
                                     oidRaw, oidRawLen))
                {
                    /* Yes */
                    return false;
                }
                /* No */
            }
        }

        /* critical BOOLEAN is optional (default false) */
        critical = false;
        if (!SSFASN1DecIsEmpty(&extInner))
        {
            /* Is the next field the optional critical BOOLEAN? */
            if ((SSFASN1DecPeekTag(&extInner, &tag)) && (tag == SSF_ASN1_TAG_BOOLEAN))
            {
                /* Yes, does the critical flag decode? */
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
        /* Is anything left after the extension value? */
        if (!SSFASN1DecIsEmpty(&extInner))
        {
            /* Yes */
            return false;
        }
        /* No */

        /* Is there room to retain this extension? */
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
                    /* Is the next field the optional cA BOOLEAN? */
                    if ((SSFASN1DecPeekTag(&bcInner, &tag)) && (tag == SSF_ASN1_TAG_BOOLEAN))
                    {
                        /* Yes, does the cA flag decode? */
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

                        /* Is the pathLenConstraint a valid unsigned INTEGER? */
                        if (!SSFASN1DecGetIntU64(&bcInner, &pl, &bcInner))
                        {
                            /* No, a CA constraint that cannot be read must not become unlimited */
                            return false;
                        }
                        /* Yes, clamp so a large value stays a constraint instead of wrapping */
                        cert->pathLenConstraint = (pl > 127u) ? (int8_t)127 : (int8_t)pl;
                    }
                }

                /* Is anything left after pathLen, or after the SEQUENCE? */
                if ((!SSFASN1DecIsEmpty(&bcInner)) || (!SSFASN1DecIsEmpty(&bcCursor)))
                {
                    /* Yes, not the BasicConstraints DER structure */
                    return false;
                }
                /* No */
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
                if (kuBitsLen >= 1u) cert->keyUsageBits = ((uint16_t)kuBits[0]) << 8;
                if (kuBitsLen >= 2u) cert->keyUsageBits |= (uint16_t)kuBits[1];
                /* Is anything left after the Key Usage BIT STRING? */
                if (!SSFASN1DecIsEmpty(&kuCursor))
                {
                    /* Yes */
                    return false;
                }
                /* No */
            }
        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidSAN, sizeof(_oidSAN)))
        {
            SSFASN1Cursor_t sanCursor = { extValue, extValueLen };
            SSFASN1Cursor_t sanInner;
            if (SSFASN1DecOpenConstructed(&sanCursor, SSF_ASN1_TAG_SEQUENCE, &sanInner, &sanCursor))
            {
                while (!SSFASN1DecIsEmpty(&sanInner))
                {
                    const uint8_t *sanVal;
                    uint32_t sanValLen;
                    uint8_t sanType;

                    /* Is the GeneralName header readable with its content inside the SEQUENCE? */
                    if ((!SSFASN1DecPeekTag(&sanInner, &tag)) ||
                        (!SSFASN1DecGetTLV(&sanInner, &tag, &sanVal, &sanValLen, &sanInner)))
                    {
                        /* No, structural DER error; the cursor could never advance past it */
                        return false;
                    }

                    /* Yes, the low tag bits are the GeneralName choice */
                    sanType = (uint8_t)(tag & 0x1Fu);

                    /* Is it a GeneralName [0]..[8], constructed exactly for choices 0, 3, 4, 5? */
                    if (((tag & 0xFFC0u) != 0x0080u) || (sanType > 8u) ||
                        (((tag & SSF_ASN1_CONSTRUCTED) != 0u) !=
                         ((sanType == 0u) || (sanType == 3u) || (sanType == 4u) ||
                          (sanType == 5u))))
                    {
                        /* No, not a GeneralName */
                        return false;
                    }
                    /* Yes */

                    /* Record every form present, kept or not, for Name Constraints */
                    if (sanType < 16u) cert->sanForms |= (uint16_t)(1u << sanType);

                    /* Is the SAN table full? */
                    if (cert->sanLen >= SSF_X509_CONFIG_MAX_SAN_ENTRIES)
                    {
                        /* Yes, a dropped SAN would escape the Name Constraints check */
                        return false;
                    }
                    /* No */

                    /* Is it a dNSName that is empty or embeds a NUL byte? */
                    if ((sanType == SSF_X509_SAN_DNS) &&
                        ((sanValLen == 0u) || (memchr(sanVal, 0, sanValLen) != NULL)))
                    {
                        /* Yes, drop it since no hostname can match it safely */
                        continue;
                    }
                    /* No, retain it */
                    cert->san[cert->sanLen].type = sanType;
                    cert->san[cert->sanLen].val = sanVal;
                    cert->san[cert->sanLen].valLen = sanValLen;
                    cert->sanLen++;
                }
                /* Is anything left after the SAN SEQUENCE? */
                if (!SSFASN1DecIsEmpty(&sanCursor))
                {
                    /* Yes */
                    return false;
                }
                /* No */
            }
        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidSKID, sizeof(_oidSKID)))
        {
            SSFASN1Cursor_t skidCursor = { extValue, extValueLen };

            /* Is the SubjectKeyIdentifier body an OCTET STRING? */
            if (!SSFASN1DecGetOctetString(&skidCursor, &cert->skid, &cert->skidLen, &skidCursor))
            {
                /* No, the decoder fills its outputs before checking the tag, so read as absent */
                cert->skid = NULL;
                cert->skidLen = 0;
            }
            /* Yes, is anything left after it? */
            else if (!SSFASN1DecIsEmpty(&skidCursor))
            {
                /* Yes */
                return false;
            }
            /* No */

        }
        else if (_SSFX509OIDMatch(oidRaw, oidRawLen, _oidAKID, sizeof(_oidAKID)))
        {
            SSFASN1Cursor_t akidCursor = { extValue, extValueLen };
            SSFASN1Cursor_t akidInner;
            if (SSFASN1DecOpenConstructed(&akidCursor, SSF_ASN1_TAG_SEQUENCE, &akidInner,
                                          &akidCursor))
            {
                const uint8_t *akidVal;
                uint32_t akidValLen;

                /* Is there a first field with a readable tag? */
                if ((!SSFASN1DecIsEmpty(&akidInner)) && (SSFASN1DecPeekTag(&akidInner, &tag)))
                {
                    /* Yes, is it keyIdentifier [0]? */
                    if (tag == SSF_ASN1_CONTEXT_IMPLICIT(0))
                    {
                        /* Yes, does the keyIdentifier decode? */
                        if (!SSFASN1DecGetTLV(&akidInner, &tag, &cert->akid, &cert->akidLen,
                                              &akidInner))
                        {
                            /* No, malformed */
                            return false;
                        }
                        /* Yes */
                    }
                }
                /* Is the next field authorityCertIssuer [1]? */
                if ((SSFASN1DecPeekTag(&akidInner, &tag)) && (tag == 0xA1u))
                {
                    /* Yes, skip it */
                    if (!SSFASN1DecGetTLV(&akidInner, &tag, &akidVal, &akidValLen, &akidInner))
                        return false;
                }
                /* No, is the next field authorityCertSerialNumber [2]? */
                if ((SSFASN1DecPeekTag(&akidInner, &tag)) && (tag == 0x82u))
                {
                    /* Yes, skip it */
                    if (!SSFASN1DecGetTLV(&akidInner, &tag, &akidVal, &akidValLen, &akidInner))
                        return false;
                }
                /* Is anything else, or anything out of order, in the SEQUENCE? */
                if (!SSFASN1DecIsEmpty(&akidInner))
                {
                    /* Yes, malformed */
                    return false;
                }
                /* No, is anything left after the AuthorityKeyIdentifier SEQUENCE? */
                if (!SSFASN1DecIsEmpty(&akidCursor))
                {
                    /* Yes */
                    return false;
                }
                /* No */
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
                    /* A non-OID element is malformed, not the end of the list */
                    if (!SSFASN1DecGetOIDRaw(&ekuInner, &ekuOid, &ekuOidLen, &ekuInner))
                        return false;
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
                /* Is anything left after the EKU SEQUENCE? */
                if (!SSFASN1DecIsEmpty(&ekuCursor))
                {
                    /* Yes */
                    return false;
                }
                /* No */
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

            /* Is the body exactly one non-empty SEQUENCE? */
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
                    /* Yes, is minimum (DEFAULT 0) or maximum encoded? */
                    if (!SSFASN1DecIsEmpty(&gsInner))
                    {
                        /* Yes, RFC 5280 forbids both, so the subtree is malformed */
                        return false;
                    }
                    /* No */

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
                    /* No, is it a context-specific GeneralName choice [0]..[8]? */
                    else if (((gnTag & 0xC0u) == 0x80u) && ((gnTag & 0x1Fu) <= 8u))
                    {
                        /* Yes, not enforced; subordinates using this form are rejected */
                        cert->ncUnenforcedForms |= (uint16_t)(1u << (gnTag & 0x1Fu));
                    }
                    else
                    {
                        /* No, not a GeneralName */
                        return false;
                    }
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
/* Returns true if der is one well-formed X.509 certificate, parsed into cert, else false.       */
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

    cert->version = 0;

    /* Is the optional [0] EXPLICIT version present (default v1 = 0)? */
    if ((SSFASN1DecPeekTag(&pos, &tag)) && (tag == SSF_ASN1_CONTEXT_EXPLICIT(0)))
    {
        SSFASN1Cursor_t verInner;
        uint64_t ver;

        /* Yes, decode it */
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_CONTEXT_EXPLICIT(0), &verInner, &pos))
            return false;
        if (!SSFASN1DecGetIntU64(&verInner, &ver, &verInner)) return false;

        /* Is it v2 or v3 with nothing after it (DER omits the DEFAULT v1)? */
        if ((ver == 0u) || (ver > 2u) || (!SSFASN1DecIsEmpty(&verInner)))
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

    /* Is anything left after notAfter? */
    if (!SSFASN1DecIsEmpty(&validityInner))
    {
        /* Yes, malformed */
        return false;
    }
    /* No */

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
            /* Is the parameter an EC curve OID? */
            if ((SSFASN1DecPeekTag(&pkAlgInner, &tag)) && (tag == SSF_ASN1_TAG_OID))
            {
                /* Yes, does the curve OID decode? */
                if (!SSFASN1DecGetOIDRaw(&pkAlgInner, &cert->ecCurveOidRaw,
                                         &cert->ecCurveOidRawLen, &pkAlgInner))
                {
                    /* No, malformed */
                    return false;
                }
                /* Yes */
            }
            else
            {
                const uint8_t *pkParam;
                uint32_t pkParamLen;

                /* No, it must be one other parameter TLV (RSA NULL, RSA-PSS SEQUENCE) */
                if (!SSFASN1DecGetTLV(&pkAlgInner, &tag, &pkParam, &pkParamLen, &pkAlgInner))
                    return false;
            }
            /* Is anything left after the algorithm parameter? */
            if (!SSFASN1DecIsEmpty(&pkAlgInner))
            {
                /* Yes, malformed */
                return false;
            }
            /* No */
        }
    }
    /* Public key BIT STRING */
    if (!SSFASN1DecGetBitString(&spkiInner, &cert->pubKey, &cert->pubKeyLen,
                                &cert->pubKeyUnusedBits, &spkiInner))
        return false;

    /* Is anything left after the public key BIT STRING? */
    if (!SSFASN1DecIsEmpty(&spkiInner))
    {
        /* Yes, malformed */
        return false;
    }
    /* No */

    /* Is the public key a partial octet (no supported key format is)? */
    if (cert->pubKeyUnusedBits != 0u)
    {
        /* Yes, malformed */
        return false;
    }
    /* No */

    /* Is an optional issuerUniqueID [1] or subjectUniqueID [2] next? */
    while ((SSFASN1DecPeekTag(&pos, &tag)) &&
           ((tag == SSF_ASN1_CONTEXT_IMPLICIT(1)) || (tag == SSF_ASN1_CONTEXT_IMPLICIT(2))))
    {
        /* Yes, does its encoded length overrun the TBSCertificate? */
        if (!SSFASN1DecSkip(&pos, &pos))
        {
            /* Yes, malformed; a failed skip leaves pos unchanged, so stop rather than spin */
            return false;
        }
        /* No, pos is past the unique ID */
    }

    /* Are the optional Extensions [3] EXPLICIT present? */
    if ((SSFASN1DecPeekTag(&pos, &tag)) && (tag == SSF_ASN1_CONTEXT_EXPLICIT(3)))
    {
        SSFASN1Cursor_t extsOuter;
        SSFASN1Cursor_t extsSeq;

        /* Yes, is this a v1 or v2 certificate, which may not carry them (RFC 5280 4.1.2.9)? */
        if (cert->version != 2u)
        {
            /* Yes */
            return false;
        }
        /* No */
        if (!SSFASN1DecOpenConstructed(&pos, SSF_ASN1_CONTEXT_EXPLICIT(3), &extsOuter, &pos))
            return false;
        if (!SSFASN1DecOpenConstructed(&extsOuter, SSF_ASN1_TAG_SEQUENCE, &extsSeq, &extsOuter))
            return false;

        /* Is anything left after the Extensions SEQUENCE? */
        if (!SSFASN1DecIsEmpty(&extsOuter))
        {
            /* Yes */
            return false;
        }
        /* No */
        if (!_SSFX509ParseExtensions(&extsSeq, cert)) return false;
    }

    /* Is anything left in the TBSCertificate after its last field? */
    if (!SSFASN1DecIsEmpty(&pos))
    {
        /* Yes */
        return false;
    }
    /* No */

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

    /* Is anything left after the signature, or after the Certificate? */
    if ((!SSFASN1DecIsEmpty(&certInner)) || (!SSFASN1DecIsEmpty(&cursor)))
    {
        /* Yes, bytes the signature does not cover */
        return false;
    }
    /* No */

    /* Is the signature a partial octet (no supported scheme is)? */
    if (cert->signatureUnusedBits != 0u)
    {
        /* Yes, malformed */
        return false;
    }
    /* No */

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if nowUnixSec is within cert's validity period, else false.                      */
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

/* --------------------------------------------------------------------------------------------- */
/* CERTIFICATE GENERATION                                                                        */
/* --------------------------------------------------------------------------------------------- */

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

/* Content emitter: true with *lenOut = content octets written, or needed when buf is NULL */
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
/* Returns bytes for tag wrapping content, or bytes needed when buf is NULL, else 0.             */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncWrap(uint8_t *buf, uint32_t bufSize, uint16_t tag,
                                const uint8_t *content, uint32_t contentLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncWrap(buf, bufSize, tag, content, contentLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for an OBJECT IDENTIFIER, or bytes needed when buf is NULL, else 0.             */
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
/* Returns bytes for a string of type strTag, or bytes needed when buf is NULL, else 0.          */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncString(uint8_t *buf, uint32_t bufSize, uint16_t strTag,
                                  const uint8_t *str, uint32_t strLen)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncString(buf, bufSize, strTag, str, strLen, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a BOOLEAN, or bytes needed when buf is NULL, else 0.                        */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncBool(uint8_t *buf, uint32_t bufSize, bool val)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncBool(buf, bufSize, val, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for an INTEGER from raw octets, or bytes needed when buf is NULL, else 0.       */
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
/* Returns bytes for a positive INTEGER from a magnitude, or bytes needed if buf NULL, else 0.   */
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
/* Returns bytes for an INTEGER from a uint64_t, or bytes needed when buf is NULL, else 0.       */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncIntU64(buf, bufSize, val, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a BIT STRING, or bytes needed when buf is NULL, else 0.                     */
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
/* Returns bytes for an OCTET STRING, or bytes needed when buf is NULL, else 0.                  */
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
/* Returns bytes for a UTCTime, or bytes needed when buf is NULL, else 0.                        */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec)
{
    uint32_t n;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));

    if (!SSFASN1EncUTCTime(buf, bufSize, unixSec, &n)) return 0;
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a tag and length header, or bytes needed when buf is NULL, else 0.          */
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

    /* Is the content measurable? */
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

    /* Do the header and content fit? */
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
/* Returns true if the nested constructed element arg describes is emitted, else false.          */
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
/* Returns true if the tagged primitive arg describes is emitted, else false.                    */
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
/* Returns true if the raw bytes arg describes are emitted, else false.                          */
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
/* Returns true if ch is in the ASN.1 PrintableString character set, else false.                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509IsPrintableChar(char ch)
{
    /* Is it a letter or a digit? */
    if (((ch >= 'A') && (ch <= 'Z')) || ((ch >= 'a') && (ch <= 'z')) ||
        ((ch >= '0') && (ch <= '9')))
    {
        /* Yes */
        return true;
    }
    /* No, is it a PrintableString punctuation character? */
    return ((ch != '\0') && (strchr(" '()+,-./:=?", ch) != NULL));
}

/* --------------------------------------------------------------------------------------------- */
/* Content: AttributeTypeAndValue { OID, PrintableString for countryName else UTF8String }.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509EncDNAttrSeqContent(uint8_t *buf, uint32_t bufSize, const void *arg,
                                        uint32_t *lenOut)
{
    const _EncDNAttr_t *a = (const _EncDNAttr_t *)arg;
    uint32_t pos = 0;
    uint16_t strTag;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(lenOut != NULL);

    if (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             a->oid, a->oidLen)))
        return false;
    /* Is it countryName, which RFC 5280 Appendix A defines as PrintableString? */
    if (_SSFX509OIDMatch(a->oid, a->oidLen, _oidC, sizeof(_oidC)))
    {
        /* Yes */
        strTag = SSF_ASN1_TAG_PRINTABLE_STRING;
    }
    else
    {
        /* No */
        strTag = SSF_ASN1_TAG_UTF8_STRING;
    }
    if (!_SSFX509Add(&pos, _SSFX509EncString(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             strTag, (const uint8_t *)a->valueStr,
                                             a->valueLen))) return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for one RDN SET { SEQUENCE { OID, UTF8String } }, else 0 if over its bound.     */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncDNAttr(uint8_t *buf, uint32_t bufSize, const uint8_t *oid,
                                  uint32_t oidLen, SSFCStrIn_t valueStr, uint32_t upperBound)
{
    _EncDNAttr_t attr;
    _EncNested_t seq;
    size_t valueLen;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));
    SSF_REQUIRE(oid != NULL);
    SSF_REQUIRE(valueStr != NULL);

    /* Is the value terminated within the RFC 5280 upper bound for this attribute? */
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

    /* Is countryName present but not exactly two letters (RFC 5280 Appendix A)? */
    if ((name->c != NULL) &&
        ((!SSFStrLen(name->c, _UB_COUNTRY_NAME + 1u, &cLen)) || (cLen != _UB_COUNTRY_NAME)))
    {
        /* Yes, malformed */
        return false;
    }

    /* Is countryName present with a character outside PrintableString? */
    if ((name->c != NULL) &&
        ((!_SSFX509IsPrintableChar(name->c[0])) || (!_SSFX509IsPrintableChar(name->c[1]))))
    {
        /* Yes, malformed */
        return false;
    }
    /* No */

    /* Is countryName present and not encodable? */
    if ((name->c != NULL) &&
        (!_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidC, sizeof(_oidC), name->c, _UB_COUNTRY_NAME))))
    {
        /* Yes */
        return false;
    }
    /* Is stateOrProvinceName present and not encodable? */
    if ((name->st != NULL) &&
        (!_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidST, sizeof(_oidST), name->st, _UB_STATE_NAME))))
    {
        /* Yes */
        return false;
    }
    /* Is localityName present and not encodable? */
    if ((name->l != NULL) &&
        (!_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidL, sizeof(_oidL), name->l, _UB_LOCALITY_NAME))))
    {
        /* Yes */
        return false;
    }
    /* Is organizationName present and not encodable? */
    if ((name->o != NULL) &&
        (!_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidO, sizeof(_oidO), name->o,
                                              _UB_ORGANIZATION_NAME))))
    {
        /* Yes */
        return false;
    }
    /* Is organizationalUnitName present and not encodable? */
    if ((name->ou != NULL) &&
        (!_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidOU, sizeof(_oidOU), name->ou,
                                              _UB_ORGANIZATIONAL_UNIT))))
    {
        /* Yes */
        return false;
    }
    /* Is commonName present and not encodable? */
    if ((name->cn != NULL) &&
        (!_SSFX509Add(&pos, _SSFX509EncDNAttr(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidCN, sizeof(_oidCN), name->cn, _UB_COMMON_NAME))))
    {
        /* Yes */
        return false;
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for a Name SEQUENCE, else 0 on failure.                                         */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncDN(uint8_t *buf, uint32_t bufSize, const SSFX509GenName_t *name)
{
    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));
    SSF_REQUIRE(name != NULL);

    return _SSFX509EncConstructed(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncDNContent, name);
}

/* --------------------------------------------------------------------------------------------- */
/* Content: AlgorithmIdentifier { OID, params } with optional raw DER parameters.                */
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
                                           uint32_t algOidRawLen, const uint8_t *paramsOpt,
                                           uint32_t paramsLen)
{
    _EncAlgId_t a;

    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));
    SSF_REQUIRE(algOidRaw != NULL);

    a.oid = algOidRaw;
    a.oidLen = algOidRawLen;
    a.params = paramsOpt;
    a.paramsLen = (paramsOpt == NULL) ? 0u : paramsLen;
    return _SSFX509EncConstructed(buf, bufSize, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncAlgIdContent, &a);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for AlgorithmIdentifier SEQUENCE { OID }, else 0 on failure.                    */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncAlgId(uint8_t *buf, uint32_t bufSize, const uint8_t *algOidRaw,
                                 uint32_t algOidRawLen)
{
    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));
    SSF_REQUIRE(algOidRaw != NULL);

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
                                             p->pubKeyAlgOidRaw, p->pubKeyAlgOidRawLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                             p->ecCurveOidRaw, p->ecCurveOidRawLen)))
        return false;
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

    /* Is it an EC key? */
    if (p->ecCurveOidRaw != NULL)
    {
        /* Yes, the algorithm carries the named curve as its parameter */
        n = _SSFX509EncConstructed(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                   SSF_ASN1_TAG_SEQUENCE, _SSFX509EncECAlgContent, p);
    }
    else
    {
        /* No, bare algorithm identifier */
        n = _SSFX509EncAlgId(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                             p->pubKeyAlgOidRaw, p->pubKeyAlgOidRawLen);
    }
    if (!_SSFX509Add(&pos, n)) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncBitString(_SSFX509At(buf, pos),
                                                _SSFX509Rem(buf, bufSize, pos), p->pubKey,
                                                p->pubKeyLen, 0u))) return false;
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
    /* Is the extension critical and its BOOLEAN not encodable? */
    if ((e->critical) &&
        (!_SSFX509Add(&pos, _SSFX509EncBool(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                            true))))
    {
        /* Yes */
        return false;
    }
    if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                  _SSFX509Rem(buf, bufSize, pos),
                                                  SSF_ASN1_TAG_OCTET_STRING, e->valueFn,
                                                  e->valueArg)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes for one Extension SEQUENCE, else 0 on failure.                                  */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFX509EncExtension(uint8_t *buf, uint32_t bufSize, const _EncExt_t *e)
{
    SSF_REQUIRE((buf != NULL) || (bufSize == 0u));
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

    /* Is it a CA and its cA BOOLEAN not encodable? */
    if ((p->isCA) &&
        (!_SSFX509Add(&pos, _SSFX509EncBool(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                            true))))
    {
        /* Yes */
        return false;
    }

    /* Is a path length constraint present? */
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
    if (!_SSFX509Add(&pos, _SSFX509EncBitString(_SSFX509At(buf, pos),
                                                _SSFX509Rem(buf, bufSize, pos), kuBytes, kuLen,
                                                unused)))
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

    /* Is serverAuth requested and not encodable? */
    if ((p->ekuServerAuth) &&
        (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidEkuServerAuth, sizeof(_oidEkuServerAuth)))))
    {
        /* Yes */
        return false;
    }
    /* Is clientAuth requested and not encodable? */
    if ((p->ekuClientAuth) &&
        (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidEkuClientAuth, sizeof(_oidEkuClientAuth)))))
    {
        /* Yes */
        return false;
    }
    /* Is codeSigning requested and not encodable? */
    if ((p->ekuCodeSigning) &&
        (!_SSFX509Add(&pos, _SSFX509EncOIDRaw(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                              _oidEkuCodeSigning, sizeof(_oidEkuCodeSigning)))))
    {
        /* Yes */
        return false;
    }
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

    /* Is there another dNSName to emit? */
    while ((dns != NULL) && (*dns != NULL))
    {
        /* Yes, is it terminated within the DNS name length bound? */
        if (!SSFStrLen(*dns, _UB_DNS_NAME + 1u, &dnsLen))
        {
            /* No, refuse to emit it */
            return false;
        }
        if (!_SSFX509Add(&pos, _SSFX509EncWrap(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                               0x82u, (const uint8_t *)*dns, (uint32_t)dnsLen)))
            return false;
        dns++;
    }
    /* Is there another iPAddress to emit? */
    while ((ip != NULL) && (*ip != NULL))
    {
        /* Yes */
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

    /* Is the key identifier beyond the supported bound? */
    if (p->skidLen > _UB_KEY_IDENTIFIER)
    {
        /* Yes, refuse to emit it */
        return false;
    }
    if (!_SSFX509Add(&pos, _SSFX509EncOctetString(_SSFX509At(buf, pos),
                                                  _SSFX509Rem(buf, bufSize, pos), p->skid,
                                                  p->skidLen)))
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

    /* Is the key identifier beyond the supported bound? */
    if (p->akidLen > _UB_KEY_IDENTIFIER)
    {
        /* Yes, refuse to emit it */
        return false;
    }
    if (!_SSFX509Add(&pos, _SSFX509EncWrap(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                           0x80u, p->akid, p->akidLen)))
        return false;
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Content: GeneralSubtrees, each SEQUENCE { base GeneralName }, for the DNS and IP lists.       */
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

    /* Is there another dNSName subtree to emit? */
    while ((dns != NULL) && (*dns != NULL))
    {
        /* Yes, is it terminated within the DNS name length bound? */
        if (!SSFStrLen(*dns, _UB_DNS_NAME + 1u, &dnsLen))
        {
            /* No, refuse to emit it */
            return false;
        }
        gn.tag = 0x82u;
        gn.data = (const uint8_t *)*dns;
        gn.len = (uint32_t)dnsLen;
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                      _SSFX509Rem(buf, bufSize, pos),
                                                      SSF_ASN1_TAG_SEQUENCE,
                                                      _SSFX509EncTaggedContent, &gn)))
            return false;
        dns++;
    }
    /* Is there another iPAddress subtree to emit? */
    while ((ips != NULL) && (*ips != NULL))
    {
        /* Yes */
        gn.tag = 0x87u;
        gn.data = *ips;
        gn.len = 8u;
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                      _SSFX509Rem(buf, bufSize, pos),
                                                      SSF_ASN1_TAG_SEQUENCE,
                                                      _SSFX509EncTaggedContent, &gn)))
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

        /* Is there any subtree in this list? */
        if (((sub.dns != NULL) && (*sub.dns != NULL)) || ((sub.ips != NULL) && (*sub.ips != NULL)))
        {
            /* Yes, emit the [n] IMPLICIT GeneralSubtrees */
            if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                          _SSFX509Rem(buf, bufSize, pos), tag,
                                                          _SSFX509EncSubtreesContent, &sub)))
                return false;

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
    /* Is a Subject Alternative Name requested? */
    if ((p->sanDNSNames != NULL) || (p->sanIPAddrs != NULL))
    {
        /* Yes */
        seq.fn = _SSFX509EncSANSeqContent;
        e.oid = _oidSAN; e.oidLen = sizeof(_oidSAN);
        e.critical = false; e.valueFn = _SSFX509EncNestedContent; e.valueArg = &seq;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    /* Is a Subject Key Identifier requested? */
    if ((p->skid != NULL) && (p->skidLen > 0u))
    {
        /* Yes */
        e.oid = _oidSKID; e.oidLen = sizeof(_oidSKID);
        e.critical = false; e.valueFn = _SSFX509EncSKIDValueContent; e.valueArg = p;
        if (!_SSFX509Add(&pos, _SSFX509EncExtension(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize,
            pos), &e))) return false;
    }
    /* Is an Authority Key Identifier requested? */
    if ((p->akid != NULL) && (p->akidLen > 0u))
    {
        /* Yes */
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
/* Returns true if p requests at least one extension in a v3 certificate, else false.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509HasExtensions(const SSFX509GenParams_t *p)
{
    SSF_REQUIRE(p != NULL);

    return ((p->version >= 2u) &&
            ((p->addBasicConstraints) || (p->addKeyUsage) || (p->addExtKeyUsage) ||
             (p->addRawExt) || (p->sanDNSNames != NULL) || (p->sanIPAddrs != NULL) ||
             (p->skid != NULL) || (p->akid != NULL) || (p->addNameConstraints)));
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

    /* Is the version present (v1 omits the field)? */
    if (p->version >= 1u)
    {
        /* Yes, [0] EXPLICIT INTEGER */
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                      _SSFX509Rem(buf, bufSize, pos),
                                                      SSF_ASN1_CONTEXT_EXPLICIT(0),
                                                      _SSFX509EncVersionContent, p)))
            return false;
    }
    /* The serial is an unsigned magnitude; encode it as a positive INTEGER */
    if (!_SSFX509Add(&pos, _SSFX509EncUInt(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                           p->serial, p->serialLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncAlgIdWithParams(_SSFX509At(buf, pos),
                                                      _SSFX509Rem(buf, bufSize, pos),
                                                      p->sigAlgOidRaw, p->sigAlgOidRawLen,
                                                      p->sigAlgParams, p->sigAlgParamsLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncDN(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                         &p->issuer))) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                  _SSFX509Rem(buf, bufSize, pos),
                                                  SSF_ASN1_TAG_SEQUENCE,
                                                  _SSFX509EncValidityContent, p))) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncDN(_SSFX509At(buf, pos), _SSFX509Rem(buf, bufSize, pos),
                                         &p->subject))) return false;
    if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                  _SSFX509Rem(buf, bufSize, pos),
                                                  SSF_ASN1_TAG_SEQUENCE,
                                                  _SSFX509EncSPKIContent, p))) return false;

    /* Are extensions requested? */
    if (_SSFX509HasExtensions(p))
    {
        /* Yes, [3] EXPLICIT SEQUENCE OF Extension */
        exts.tag = SSF_ASN1_TAG_SEQUENCE;
        exts.fn = _SSFX509EncExtListContent;
        exts.arg = p;
        if (!_SSFX509Add(&pos, _SSFX509EncConstructed(_SSFX509At(buf, pos),
                                                      _SSFX509Rem(buf, bufSize, pos),
                                                      SSF_ASN1_CONTEXT_EXPLICIT(3),
                                                      _SSFX509EncNestedContent, &exts)))
            return false;
    }
    *lenOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that p only asks for structures RFC 5280 allows.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFX509RequireGenParams(const SSFX509GenParams_t *p)
{
    const char **dns;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE((p->version == 0u) || (p->version == 2u));
    SSF_REQUIRE((p->skid == NULL) == (p->skidLen == 0u));
    SSF_REQUIRE((p->akid == NULL) == (p->akidLen == 0u));
    SSF_REQUIRE((!p->addExtKeyUsage) || (p->ekuServerAuth) || (p->ekuClientAuth) ||
                (p->ekuCodeSigning));
    SSF_REQUIRE(((p->sanDNSNames == NULL) && (p->sanIPAddrs == NULL)) ||
                ((p->sanDNSNames != NULL) && (p->sanDNSNames[0] != NULL)) ||
                ((p->sanIPAddrs != NULL) && (p->sanIPAddrs[0] != NULL)));
    for (dns = p->sanDNSNames; (dns != NULL) && (*dns != NULL); dns++)
    {
        SSF_REQUIRE((*dns)[0] != '\0');
    }
    SSF_REQUIRE((!p->addNameConstraints) ||
                ((p->ncPermittedDNS != NULL) && (p->ncPermittedDNS[0] != NULL)) ||
                ((p->ncPermittedIPs != NULL) && (p->ncPermittedIPs[0] != NULL)) ||
                ((p->ncExcludedDNS != NULL) && (p->ncExcludedDNS[0] != NULL)) ||
                ((p->ncExcludedIPs != NULL) && (p->ncExcludedIPs[0] != NULL)));
    SSF_REQUIRE((p->pathLenConstraint < 0) || ((p->addBasicConstraints) && (p->isCA)));
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
    _SSFX509RequireGenParams(params);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    total = _SSFX509EncConstructed(NULL, 0, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncTBSContent, params);

    /* Is it unencodable or over the configured certificate size? */
    if ((total == 0u) || (total > SSF_X509_CONFIG_MAX_CERT_SIZE))
    {
        /* Yes, both passes report failure */
        return false;
    }

    /* No, only measuring? */
    if (bufOpt == NULL)
    {
        /* Yes, report the size needed */
        *lenOut = total;
        return true;
    }
    /* No, write it */
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
    if (!_SSFX509Add(&pos, _SSFX509EncAlgIdWithParams(_SSFX509At(buf, pos),
                                                      _SSFX509Rem(buf, bufSize, pos),
                                                      c->params->sigAlgOidRaw,
                                                      c->params->sigAlgOidRawLen,
                                                      c->params->sigAlgParams,
                                                      c->params->sigAlgParamsLen)))
        return false;
    if (!_SSFX509Add(&pos, _SSFX509EncBitString(_SSFX509At(buf, pos),
                                                _SSFX509Rem(buf, bufSize, pos), c->sig, c->sigLen,
                                                0u)))
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
    _SSFX509RequireGenParams(params);
    SSF_REQUIRE(signature != NULL);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    c.params = params;
    c.sig = signature;
    c.sigLen = signatureLen;
    total = _SSFX509EncConstructed(NULL, 0, SSF_ASN1_TAG_SEQUENCE, _SSFX509EncCertContent, &c);

    /* Is it unencodable or over the configured certificate size? */
    if ((total == 0u) || (total > SSF_X509_CONFIG_MAX_CERT_SIZE))
    {
        /* Yes, both passes report failure */
        return false;
    }

    /* No, only measuring? */
    if (bufOpt == NULL)
    {
        /* Yes, report the size needed */
        *lenOut = total;
        return true;
    }
    /* No, write it */
    *lenOut = _SSFX509EncConstructed(bufOpt, bufOptSize, SSF_ASN1_TAG_SEQUENCE,
                                     _SSFX509EncCertContent, &c);
    return (*lenOut != 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* ADDITIONAL OID HELPERS                                                                        */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the EC public key is on P-384, else false.                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsP384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->ecCurveOidRaw, cert->ecCurveOidRawLen,
                            _oidP384, sizeof(_oidP384));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is ecdsa-with-SHA384, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsECDSASHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                            _oidEcdsaSHA384, sizeof(_oidEcdsaSHA384));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is id-RSASSA-PSS with hash, else false.               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509IsRSAPSSHash(const SSFX509Cert_t *cert, SSFRSAHash_t hash)
{
#if _SSF_X509_RSA_PSS == 1
    SSFRSAHash_t pssHash;
    uint32_t saltLen;
#endif /* _SSF_X509_RSA_PSS == 1 */

    SSF_REQUIRE(cert != NULL);
    SSF_REQUIRE((hash > SSF_RSA_HASH_MIN) && (hash < SSF_RSA_HASH_MAX));

    /* Is the signature algorithm id-RSASSA-PSS? */
    if (!_SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen, _oidRSAPSS,
                          sizeof(_oidRSAPSS)))
    {
        /* No */
        return false;
    }
#if _SSF_X509_RSA_PSS == 1
    /* Yes, do the PSS parameters parse and name this hash? */
    if (!_SSFX509ParsePSSParams(cert->sigAlgParams, cert->sigAlgParamsLen, &pssHash, &saltLen))
    {
        /* No, the parameters are absent, malformed or unsupported */
        return false;
    }
    return (pssHash == hash);
#else /* _SSF_X509_RSA_PSS == 1 */
    /* Yes, PSS is compiled out so only the OID can be checked */
    return true;
#endif /* _SSF_X509_RSA_PSS == 1 */
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is RSA-PSS with SHA-256, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPSSSHA256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509IsRSAPSSHash(cert, SSF_RSA_HASH_SHA256);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is RSA-PSS with SHA-384, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPSSSHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509IsRSAPSSHash(cert, SSF_RSA_HASH_SHA384);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is sha256WithRSAEncryption, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA256(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                            _oidRSAPKCS1SHA256, sizeof(_oidRSAPKCS1SHA256));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is sha384WithRSAEncryption, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsRSAPKCS1SHA384(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);
    return _SSFX509OIDMatch(cert->sigAlgOidRaw, cert->sigAlgOidRawLen,
                            _oidRSAPKCS1SHA384, sizeof(_oidRSAPKCS1SHA384));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signature algorithm is sha512WithRSAEncryption, else false.               */
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

/* --------------------------------------------------------------------------------------------- */
/* CHAIN VERIFICATION                                                                            */
/* --------------------------------------------------------------------------------------------- */

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

    /* Is the hostname terminated within the longest possible DNS name? */
    if (!SSFStrLen(hostnameStr, _UB_DNS_NAME + 1u, &hostLenSz))
    {
        /* No, nothing that long can match a dNSName */
        return false;
    }
    hostLen = (uint32_t)hostLenSz;

    /* Is it a wildcard SAN of the form "*.base"? */
    if ((sanValLen >= 2u) && (sanVal[0] == (uint8_t)'*') && (sanVal[1] == (uint8_t)'.'))
    {
        /* Yes, the wildcard stands for exactly the leftmost hostname label */
        dot = hostnameStr;

        /* Is dot still inside the leftmost label? */
        while ((*dot != '\0') && (*dot != '.'))
        {
            /* Yes */
            dot++;
        }

        /* Is the leftmost label non-empty and followed by a dot? */
        if ((*dot != '.') || (dot == hostnameStr))
        {
            /* No, nothing for the wildcard to match */
            return false;
        }

        /* Is the rest of the hostname exactly as long as ".base"? */
        domainLen = hostLen - (uint32_t)(dot - hostnameStr);
        sanDomainLen = sanValLen - 2u;
        if (domainLen != (sanDomainLen + 1u)) return false;

        /* Does base have an interior dot, so "*.com" never matches (CA/B Forum BR 3.2.2.6)? */
        for (b = 2u; b < sanValLen; b++)
        {
            if (sanVal[b] == (uint8_t)'.')
            {
                baseHasDot = true;
                break;
            }
        }
        if (!baseHasDot) return false;
        return _SSFX509MemEqI((const uint8_t *)dot, &sanVal[1], sanDomainLen + 1u);
    }

    /* No, exact match ignoring ASCII case */
    if (hostLen != sanValLen) return false;
    return _SSFX509MemEqI((const uint8_t *)hostnameStr, sanVal, hostLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if ipStr is a dotted-decimal IPv4 address written into ipOut, else false.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509ParseIPv4(const char *ipStr, uint8_t ipOut[4])
{
    uint32_t octet;
    uint32_t i;
    uint32_t digitCount;

    SSF_REQUIRE(ipStr != NULL);
    SSF_REQUIRE(ipOut != NULL);

    for (i = 0; i < 4u; i++)
    {
        octet = 0;
        digitCount = 0;

        /* Is the next character a decimal digit? */
        while ((*ipStr >= '0') && (*ipStr <= '9'))
        {
            /* Yes, is it a second digit after a leading zero, which inet_aton reads as octal? */
            if ((digitCount == 1u) && (octet == 0u))
            {
                /* Yes, "010" is ambiguous, so it is not an IPv4 literal */
                return false;
            }
            /* No */
            octet = (octet * 10u) + (uint32_t)(*ipStr - '0');
            if (octet > 255u) return false;
            ipStr++;
            digitCount++;
        }
        if (digitCount == 0u) return false;
        ipOut[i] = (uint8_t)octet;

        /* Are more octets to come? */
        if (i < 3u)
        {
            /* Yes, a dot must separate them */
            if (*ipStr != '.') return false;
            ipStr++;
        }
    }
    return (*ipStr == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if hostStr is only ASCII digits and dots (no DNS name is all-numeric).           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509IsNumericHost(const char *hostStr)
{
    uint32_t n;

    SSF_REQUIRE(hostStr != NULL);

    for (n = 0; (hostStr[n] != '\0') && (n <= _UB_DNS_NAME); n++)
    {
        /* Is this character something other than a digit or a dot? */
        if (((hostStr[n] < '0') || (hostStr[n] > '9')) && (hostStr[n] != '.'))
        {
            /* Yes */
            return false;
        }
        /* No */
    }
    return (n > 0u);
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
/* Returns true if hostnameStr is an IPv4 literal equal to the iPAddress SAN value, else false.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509MatchIPAddress(const char *hostnameStr, const uint8_t *sanIP, uint32_t sanIPLen)
{
    SSF_REQUIRE(hostnameStr != NULL);
    SSF_REQUIRE(sanIP != NULL);

    return _SSFX509IPAddressMatch(hostnameStr, sanIP, sanIPLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if digestOidOpt is absent or is exactly expectedOid, else false.                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509DigestAgrees(const uint8_t *digestOidOpt, uint32_t digestOidLen,
                                 const uint8_t *expectedOid, uint32_t expectedOidLen)
{
    SSF_REQUIRE((digestOidOpt != NULL) || (digestOidLen == 0u));
    SSF_REQUIRE(expectedOid != NULL);

    /* Is no digest algorithm given? */
    if ((digestOidOpt == NULL) || (digestOidLen == 0u))
    {
        /* Yes, nothing to disagree with */
        return true;
    }

    /* No, it must be the expected one */
    return _SSFX509OIDMatch(digestOidOpt, digestOidLen, expectedOid, expectedOidLen);
}

#if (_SSF_X509_RSA_PKCS1 == 1) || (_SSF_X509_RSA_PSS == 1)
/* --------------------------------------------------------------------------------------------- */
/* Returns true if RSAPublicKey der has n of at least the minimum size and an odd e >= 3.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509RSAKeyPolicyOK(const uint8_t *der, uint32_t derLen)
{
    SSFASN1Cursor_t cursor;
    SSFASN1Cursor_t inner;
    SSFASN1Cursor_t next;
    const uint8_t *n;
    uint32_t nLen;
    const uint8_t *e;
    uint32_t eLen;
    uint32_t nBits;
    uint8_t top;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(derLen > 0u);

    cursor.buf = der;
    cursor.bufLen = derLen;
    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &inner, &next)) return false;
    if (!SSFASN1DecGetUInt(&inner, &n, &nLen, &inner)) return false;
    if (!SSFASN1DecGetUInt(&inner, &e, &eLen, &inner)) return false;

    /* Is a leading zero (INTEGER sign) byte left on the modulus? */
    while ((nLen > 0u) && (*n == 0u))
    {
        /* Yes, drop it */
        n++;
        nLen--;
    }
    /* Is a leading zero (INTEGER sign) byte left on the exponent? */
    while ((eLen > 0u) && (*e == 0u))
    {
        /* Yes, drop it */
        e++;
        eLen--;
    }

    /* Is either value zero? */
    if ((nLen == 0u) || (eLen == 0u))
    {
        /* Yes, not a usable RSA key */
        return false;
    }
    /* No, measure the modulus */
    nBits = (nLen - 1u) * 8u;
    top = n[0];
    while (top != 0u)
    {
        nBits++;
        top >>= 1;
    }

    /* Is the modulus smaller than the configured minimum? */
    if (nBits < SSF_X509_CONFIG_RSA_MIN_BITS)
    {
        /* Yes, a key this short may be factorable */
        return false;
    }
    /* No, is the exponent even, or 1 (a signature that anyone can produce)? */
    if (((e[eLen - 1u] & 1u) == 0u) || ((eLen == 1u) && (e[0] < 3u)))
    {
        /* Yes, refuse it */
        return false;
    }
    /* No, the key meets the policy */
    return true;
}
#endif /* (_SSF_X509_RSA_PKCS1 == 1) || (_SSF_X509_RSA_PSS == 1) */

#if _SSF_X509_RSA_PKCS1 == 1
/* --------------------------------------------------------------------------------------------- */
/* Returns true if oid names SHA-256, SHA-384 or SHA-512 with *hashOut set, else false.          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509HashFromOID(const uint8_t *oid, uint32_t oidLen, SSFRSAHash_t *hashOut)
{
    SSF_REQUIRE((oid != NULL) || (oidLen == 0u));
    SSF_REQUIRE(hashOut != NULL);

    if (_SSFX509OIDMatch(oid, oidLen, _oidSHA256, sizeof(_oidSHA256)))
    {
        *hashOut = SSF_RSA_HASH_SHA256;
    }
    else if (_SSFX509OIDMatch(oid, oidLen, _oidSHA384, sizeof(_oidSHA384)))
    {
        *hashOut = SSF_RSA_HASH_SHA384;
    }
    else if (_SSFX509OIDMatch(oid, oidLen, _oidSHA512, sizeof(_oidSHA512)))
    {
        *hashOut = SSF_RSA_HASH_SHA512;
    }
    else
    {
        return false;
    }
    return true;
}
#endif /* _SSF_X509_RSA_PKCS1 == 1 */

/* --------------------------------------------------------------------------------------------- */
/* Returns the SHA-2 OID naming hashId with *lenOut set.                                         */
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
/* Digests data with the SHA-2 hash hashId selects into hash, setting *hashLenOut.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFX509Digest(SSFRSAHash_t hashId, const uint8_t *data, uint32_t dataLen,
                           uint8_t *hash, size_t *hashLenOut)
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
/* Returns true if keyCert's SubjectPublicKeyInfo algorithm OID is oid, else false.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509KeyAlgIs(const SSFX509Cert_t *keyCert, const uint8_t *oid, uint32_t oidLen)
{
    SSF_REQUIRE(keyCert != NULL);
    SSF_REQUIRE(oid != NULL);

    return _SSFX509OIDMatch(keyCert->pubKeyAlgOidRaw, keyCert->pubKeyAlgOidRawLen, oid, oidLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sig over data verifies with keyCert's public key under sigAlg, else false.    */
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
#if _SSF_X509_RSA_PSS == 1
    uint32_t saltLen;
#endif /* _SSF_X509_RSA_PSS == 1 */
    bool isEcdsa256;
#if _SSF_X509_RSA_PKCS1 == 1
    bool isRsaPlain;
#endif /* _SSF_X509_RSA_PKCS1 == 1 */
    bool ok;

    SSF_REQUIRE(keyCert != NULL);
    SSF_REQUIRE(sigAlgOidRaw != NULL);
    SSF_REQUIRE((sigAlgParamsOpt != NULL) || (sigAlgParamsLen == 0u));
    SSF_REQUIRE((digestAlgOidRawOpt != NULL) || (digestAlgOidRawLen == 0u));
    SSF_REQUIRE((data != NULL) || (dataLen == 0u));
    SSF_REQUIRE(sig != NULL);

    /* Is the key empty (an untrusted issuer's key can reach here)? */
    if ((keyCert->pubKey == NULL) || (keyCert->pubKeyLen == 0u))
    {
        /* Yes, nothing to verify with; the verifiers would trap on it */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX, "VerifySig: empty public key");
        return false;
    }
    /* No, hand the key to the scheme the signature algorithm selects */

    /* ECDSA with SHA-256 or SHA-384 (the OID selects the hash, the key its curve, RFC 5758)? */
    isEcdsa256 = _SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidEcdsaSHA256,
                                  sizeof(_oidEcdsaSHA256));
    if ((isEcdsa256) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidEcdsaSHA384, sizeof(_oidEcdsaSHA384))))
    {
        /* Yes, is the key an EC key and are the parameters absent (RFC 5758 3.2)? */
        if ((!_SSFX509KeyAlgIs(keyCert, _oidEcPubKey, sizeof(_oidEcPubKey))) ||
            (sigAlgParamsLen != 0u))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: ECDSA needs an id-ecPublicKey key and absent parameters");
            return false;
        }
        /* Yes */
        hashId = isEcdsa256 ? SSF_RSA_HASH_SHA256 : SSF_RSA_HASH_SHA384;

        /* Is the digest algorithm, when given, the one the signature algorithm implies? */
        impliedOid = _SSFX509OIDForHash(hashId, &impliedOidLen);
        if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, impliedOid,
                                  impliedOidLen))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: digest algorithm disagrees with ECDSA signature algorithm");
            return false;
        }
        _SSFX509Digest(hashId, data, dataLen, hash, &hashLen);

#if SSF_EC_CONFIG_ENABLE_P256 == 1
        /* Is the key on P-256? */
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
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: ECDSA key curve OID not recognized or not enabled (%lu bytes)",
                (unsigned long)keyCert->ecCurveOidRawLen);
            return false;
        }

        /* keyCert's pubKey is the SEC 1 point; ssfecdsa truncates a long digest (RFC 5758 3.2) */
        ok = SSFECDSAVerify(curve, keyCert->pubKey, (size_t)keyCert->pubKeyLen, hash, hashLen, sig,
                            (size_t)sigLen);
        SSF_TLS_TRACE_CERT_DEBUG(_SSF_X509_TRACE_CTX,
            "VerifySig: ECDSA curve=%d pubKeyLen=%lu sigLen=%lu -> %s", curve,
            (unsigned long)keyCert->pubKeyLen, (unsigned long)sigLen, ok ? "OK" : "FAIL");
        return ok;
    }

    /* Compiled out schemes fall through to the unsupported-algorithm rejection below */
#if _SSF_X509_RSA_PKCS1 == 1
    /* Is it RSA PKCS#1 v1.5, by a hashed-with-RSA OID or plain rsaEncryption (RFC 3370 3.2)? */
    isRsaPlain = _SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSA, sizeof(_oidRSA));
    if ((isRsaPlain) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA256,
                          sizeof(_oidRSAPKCS1SHA256))) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA384,
                          sizeof(_oidRSAPKCS1SHA384))) ||
        (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPKCS1SHA512,
                          sizeof(_oidRSAPKCS1SHA512))))
    {
        /* Yes, is the key an rsaEncryption key? */
        if (!_SSFX509KeyAlgIs(keyCert, _oidRSA, sizeof(_oidRSA)))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: RSA PKCS#1 v1.5 needs an rsaEncryption key");
            return false;
        }
        /* Yes, plain rsaEncryption? */
        if (isRsaPlain)
        {
            /* Yes, does the digest algorithm, which alone names the hash, name a supported one? */
            if (!_SSFX509HashFromOID(digestAlgOidRawOpt, digestAlgOidRawLen, &hashId))
            {
                /* No */
                SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                    "VerifySig: rsaEncryption needs a SHA-2 digest algorithm (%lu bytes given)",
                    (unsigned long)digestAlgOidRawLen);
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

            /* Does the digest algorithm, when given, agree with the OID's hash? */
            if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, impliedOid,
                                      impliedOidLen))
            {
                /* No */
                SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                    "VerifySig: digest algorithm disagrees with RSA signature algorithm");
                return false;
            }
        }
        _SSFX509Digest(hashId, data, dataLen, hash, &hashLen);

        /* Does the RSA key meet the size and exponent policy? */
        if (!_SSFX509RSAKeyPolicyOK(keyCert->pubKey, keyCert->pubKeyLen))
        {
            /* No, refuse it even if the signature would verify */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: RSA key below policy (min %u bits, odd e >= 3)",
                (unsigned int)SSF_X509_CONFIG_RSA_MIN_BITS);
            return false;
        }
        /* Yes, verify with keyCert's pubKey, the DER RSAPublicKey from the SPKI BIT STRING */
        ok = SSFRSAVerifyPKCS1(keyCert->pubKey, (size_t)keyCert->pubKeyLen, hashId, hash, hashLen,
                               sig, (size_t)sigLen);
        SSF_TLS_TRACE_CERT_DEBUG(_SSF_X509_TRACE_CTX,
            "VerifySig: RSA-PKCS1 hash=%d pubKeyLen=%lu sigLen=%lu -> %s", hashId,
            (unsigned long)keyCert->pubKeyLen, (unsigned long)sigLen, ok ? "OK" : "FAIL");
        return ok;
    }
#endif /* _SSF_X509_RSA_PKCS1 == 1 */

#if _SSF_X509_RSA_PSS == 1
    /* Is it RSA-PSS, whose parameters select the hash and salt length (RFC 4055)? */
    if (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidRSAPSS, sizeof(_oidRSAPSS)))
    {
        /* Yes, is the key rsaEncryption or id-RSASSA-PSS (RFC 4055 1.2)? */
        if ((!_SSFX509KeyAlgIs(keyCert, _oidRSA, sizeof(_oidRSA))) &&
            (!_SSFX509KeyAlgIs(keyCert, _oidRSAPSS, sizeof(_oidRSAPSS))))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: RSA-PSS needs an rsaEncryption or id-RSASSA-PSS key");
            return false;
        }
        /* Yes, are the RSASSA-PSS-params well formed and supported? */
        if (!_SSFX509ParsePSSParams(sigAlgParamsOpt, sigAlgParamsLen, &hashId, &saltLen))
        {
            /* No, never verify under substituted defaults */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: RSA-PSS parameters absent, malformed or unsupported");
            return false;
        }
        /* Yes */

        /* Is the digest algorithm, when given, the hash the parameters select? */
        impliedOid = _SSFX509OIDForHash(hashId, &impliedOidLen);
        if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, impliedOid,
                                  impliedOidLen))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: digest algorithm disagrees with RSA-PSS parameters");
            return false;
        }
        _SSFX509Digest(hashId, data, dataLen, hash, &hashLen);

        /* Is the salt length longer than the hash, which the verifier does not support? */
        if (saltLen > hashLen)
        {
            /* Yes, longer than the hash is never issued and is not accepted */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: RSA-PSS saltLength %lu exceeds hash length %u", (unsigned long)saltLen,
                (unsigned int)hashLen);
            return false;
        }
        /* No, does the RSA key meet the size and exponent policy? */
        if (!_SSFX509RSAKeyPolicyOK(keyCert->pubKey, keyCert->pubKeyLen))
        {
            /* No, refuse it even if the signature would verify */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: RSA key below policy (min %u bits, odd e >= 3)",
                (unsigned int)SSF_X509_CONFIG_RSA_MIN_BITS);
            return false;
        }
        /* Yes, verify the signature */
        ok = SSFRSAVerifyPSS(keyCert->pubKey, (size_t)keyCert->pubKeyLen, hashId, hash, hashLen,
                             (size_t)saltLen, sig, (size_t)sigLen);
        SSF_TLS_TRACE_CERT_DEBUG(_SSF_X509_TRACE_CTX,
            "VerifySig: RSA-PSS hash=%d pubKeyLen=%lu sigLen=%lu -> %s", hashId,
            (unsigned long)keyCert->pubKeyLen, (unsigned long)sigLen, ok ? "OK" : "FAIL");
        return ok;
    }
#endif /* _SSF_X509_RSA_PSS == 1 */

    /* Is it Ed25519, which signs the data itself (RFC 8410)? */
    if (_SSFX509OIDMatch(sigAlgOidRaw, sigAlgOidRawLen, _oidEd25519, sizeof(_oidEd25519)))
    {
        /* Yes, is the key id-Ed25519 and are the parameters absent (RFC 8410 3)? */
        if ((!_SSFX509KeyAlgIs(keyCert, _oidEd25519, sizeof(_oidEd25519))) ||
            (sigAlgParamsLen != 0u))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: Ed25519 needs an id-Ed25519 key and absent parameters");
            return false;
        }
        /* Yes; RFC 8419 pairs it only with SHA-512, so a given digest algorithm is SHA-512? */
        if (!_SSFX509DigestAgrees(digestAlgOidRawOpt, digestAlgOidRawLen, _oidSHA512,
                                  sizeof(_oidSHA512)))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: Ed25519 requires the SHA-512 digest algorithm");
            return false;
        }

        /* Are the key and signature the sizes Ed25519 defines? */
        if ((keyCert->pubKeyLen != SSF_ED25519_PUB_KEY_SIZE) || (sigLen != SSF_ED25519_SIG_SIZE))
        {
            /* No, malformed */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "VerifySig: Ed25519 bad key/sig size (pubKey=%lu sig=%lu)",
                (unsigned long)keyCert->pubKeyLen, (unsigned long)sigLen);
            return false;
        }
        ok = SSFEd25519Verify(keyCert->pubKey, data, dataLen, sig);
        SSF_TLS_TRACE_CERT_DEBUG(_SSF_X509_TRACE_CTX,
            "VerifySig: Ed25519 pubKeyLen=%lu sigLen=%lu -> %s",
            (unsigned long)keyCert->pubKeyLen, (unsigned long)sigLen, ok ? "OK" : "FAIL");
        return ok;
    }

    SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX, "VerifySig: unsupported sigAlg OID (%lu bytes)",
                             (unsigned long)sigAlgOidRawLen);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if cert's signature over its TBS verifies with issuer's public key, else false.  */
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

    /* Is cert's AKID absent? */
    if ((cert->akid == NULL) || (cert->akidLen == 0u))
    {
        /* Yes, nothing to compare */
        return true;
    }
    /* No, is issuer's SKID absent? */
    if ((issuer->skid == NULL) || (issuer->skidLen == 0u))
    {
        /* Yes, nothing to compare */
        return true;
    }
    /* No, they must be identical */
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

    /* Is either raw Name missing? */
    if ((issuer->raw == NULL) || (subject->raw == NULL))
    {
        /* Yes */
        return false;
    }
    /* No */
    if (issuer->rawLen != subject->rawLen) return false;
    return (memcmp(issuer->raw, subject->raw, issuer->rawLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a dNSName satisfies a dNSName constraint (RFC 5280 4.2.1.10), else false.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NCDNSMatch(const uint8_t *name, uint32_t nameLen, const uint8_t *constraint,
                               uint32_t constraintLen)
{
    uint32_t offset;

    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE((constraint != NULL) || (constraintLen == 0u));

    /* An empty constraint matches every name */
    if (constraintLen == 0u) return true;

    /* Is it the leading-dot form some CAs use, meaning proper subdomains only? */
    if (constraint[0] == (uint8_t)'.')
    {
        /* Yes, the name must be longer than the constraint and end with it */
        if (nameLen <= constraintLen) return false;
        return _SSFX509MemEqI(&name[nameLen - constraintLen], constraint, constraintLen);
    }

    /* No, the name is the constraint itself or ends with "." followed by the constraint */
    if (nameLen < constraintLen) return false;
    offset = nameLen - constraintLen;

    /* Is the name longer than the constraint without a "." before the suffix? */
    if ((offset != 0u) && (name[offset - 1u] != (uint8_t)'.'))
    {
        /* Yes */
        return false;
    }
    /* No */
    return _SSFX509MemEqI(&name[offset], constraint, constraintLen);
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

    /* Is it other than an IPv4 SAN against an IPv4 constraint, the only form supported? */
    if ((ipLen != 4u) || (constraintLen != 8u))
    {
        /* Yes */
        return false;
    }
    /* No */
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
/* Returns true if an excluded iPAddress subtree cannot be evaluated against san, else false.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NCIPExclUnchecked(const SSFX509SAN_t *san,
                                      const SSFX509NameConstraint_t *subtree)
{
    bool sanIsV4;
    bool sanIsV6;

    SSF_REQUIRE(san != NULL);
    SSF_REQUIRE(subtree != NULL);

    /* Is this anything other than an iPAddress subtree against an iPAddress SAN? */
    if ((subtree->type != SSF_X509_SAN_IP) || (san->type != SSF_X509_SAN_IP))
    {
        /* Yes, not an iPAddress pairing */
        return false;
    }
    /* No */
    sanIsV4 = (san->valLen == 4u);
    sanIsV6 = (san->valLen == 16u);

    /* Is the subtree an IPv4 address and mask, which _SSFX509NCIPMatch evaluates? */
    if (subtree->valLen == 8u)
    {
        /* Yes, only a malformed SAN length escapes it */
        return ((!sanIsV4) && (!sanIsV6));
    }
    /* No, is it IPv6-sized (32-byte address and mask, or a 16-byte address)? */
    if ((subtree->valLen == 32u) || (subtree->valLen == 16u))
    {
        /* Yes, it cannot be evaluated for any SAN that is not IPv4 */
        return (!sanIsV4);
    }
    /* No, a malformed length could cover any address */
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if every SAN of subCert satisfies ncCert's Name Constraints, else false.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFX509NCValidateCert(const SSFX509Cert_t *subCert, const SSFX509Cert_t *ncCert)
{
    const SSFX509SAN_t *san;
    uint16_t forms;
    bool typeHasPermitted;
    bool typeMatched;
    uint8_t s;
    uint8_t k;

    SSF_REQUIRE(subCert != NULL);
    SSF_REQUIRE(ncCert != NULL);

    /* Collect subCert's name forms: SANs, a non-empty subject (directoryName), rfc822Name */
    forms = subCert->sanForms;
    if (subCert->subject.rawLen > 2u) forms |= (uint16_t)(1u << 4);
    if (subCert->subject.hasEmailAddress) forms |= (uint16_t)(1u << 1);

    /* Does subCert carry an instance of a constrained form that is not enforced? */
    if ((ncCert->ncUnenforcedForms & forms) != 0u)
    {
        /* Yes, RFC 5280 4.2.1.10: process the constraint or reject the certificate */
        return false;
    }
    /* No */

    for (s = 0; s < subCert->sanLen; s++)
    {
        san = &subCert->san[s];

        /* Any excluded subtree matching this SAN rejects the certificate */
        for (k = 0; k < ncCert->excludedLen; k++)
        {
            if (_SSFX509NCSubtreeMatch(san, &ncCert->excludedSubtrees[k])) return false;
            /* An exclusion that cannot be evaluated for this SAN rejects it */
            if (_SSFX509NCIPExclUnchecked(san, &ncCert->excludedSubtrees[k])) return false;
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
        /* Do permitted subtrees of this type exist with none matching? */
        if ((typeHasPermitted) && (!typeMatched))
        {
            /* Yes */
            return false;
        }
        /* No */
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

/* Records why chain verification failed: the check's code and the chain index it rejected. */
#define _SSF_X509_VERIFY_FAIL(errOut, failCode, failIdx) do { \
    (errOut)->code = (failCode); \
    (errOut)->certIdx = (uint8_t)(failIdx); } while (0)

/* Stack use is sized by SSF_X509_CONFIG_MAX_CHAIN_DEPTH; see ssfx509.md */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
/* --------------------------------------------------------------------------------------------- */
/* Returns true if chainDer[0] validates to a trust anchor for purpose, else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifyChainPurpose(const uint8_t **chainDer, const uint32_t *chainDerLen,
                               uint8_t chainLen,
                               const uint8_t **trustDer, const uint32_t *trustDerLen,
                               uint8_t trustCount, SSFX509Purpose_t purpose,
                               const char *hostnameStrOpt, uint64_t nowUnixSec,
                               SSFX509VerifyErr_t *errOut)
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
    SSF_REQUIRE(errOut != NULL);

    errOut->code = SSF_X509_VERIFY_OK;
    errOut->certIdx = 0;

    for (i = 0; i < chainLen; i++)
    {
        SSF_REQUIRE(chainDer[i] != NULL);

        /* Does the chain certificate parse? */
        if (!SSFX509Parse(chainDer[i], chainDerLen[i], &certs[i]))
        {
            /* No, malformed */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX, "Chain: parse cert[%u] failed (%lu bytes)",
                                     i, (unsigned long)chainDerLen[i]);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_PARSE, i);
            return false;
        }

        /* Is it v3, as RFC 5280 Sec. 6.1.1 (c) requires of every chain certificate? */
        if (certs[i].version != 2u)
        {
            /* No, v1 and v2 certificates cannot carry the extensions this path relies on */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX, "Chain: cert[%u] is v%u (must be v3)", i,
                                     certs[i].version + 1u);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_VERSION, i);
            return false;
        }

        /* Does the TBS signature algorithm OID equal the outer one (Sec. 4.1.2.3)? */
        if ((certs[i].sigAlgOidRawLen != certs[i].outerSigAlgOidRawLen) ||
            (memcmp(certs[i].sigAlgOidRaw, certs[i].outerSigAlgOidRaw,
                    certs[i].sigAlgOidRawLen) != 0))
        {
            /* No, the unsigned outer copy disagrees with the signed one */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] TBS sigAlg OID (%lu bytes) != outer sigAlg OID (%lu bytes)", i,
                (unsigned long)certs[i].sigAlgOidRawLen,
                (unsigned long)certs[i].outerSigAlgOidRawLen);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_SIG_ALG_MISMATCH, i);
            return false;
        }

        /* Are the signature algorithm parameters identical as well (Sec. 4.1.1.2)? */
        if ((certs[i].sigAlgParamsLen != certs[i].outerSigAlgParamsLen) ||
            ((certs[i].sigAlgParamsLen > 0u) &&
             (memcmp(certs[i].sigAlgParams, certs[i].outerSigAlgParams,
                     certs[i].sigAlgParamsLen) != 0)))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] TBS sigAlg params (%lu bytes) != outer params (%lu bytes)", i,
                (unsigned long)certs[i].sigAlgParamsLen,
                (unsigned long)certs[i].outerSigAlgParamsLen);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_SIG_ALG_MISMATCH, i);
            return false;
        }

        /* Is it within its validity period at nowUnixSec? */
        if (!SSFX509IsValid(&certs[i], nowUnixSec))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] not valid at time %llu (notBefore=%llu notAfter=%llu)", i,
                (unsigned long long)nowUnixSec, (unsigned long long)certs[i].notBefore,
                (unsigned long long)certs[i].notAfter);
            _SSF_X509_VERIFY_FAIL(errOut, (nowUnixSec < certs[i].notBefore) ?
                                  SSF_X509_VERIFY_ERR_NOT_YET_VALID : SSF_X509_VERIFY_ERR_EXPIRED,
                                  i);
            return false;
        }
    }
    last = &certs[chainLen - 1u];

    /* Each cert[i] is named for, signed by, and key-linked to cert[i + 1] */
    for (i = 0; i < (uint8_t)(chainLen - 1u); i++)
    {
        /* Is the issuer name of cert[i] the subject name of cert[i + 1] (Sec. 6.1.3 (a)(4))? */
        if (!_SSFX509NameEquals(&certs[i].issuer, &certs[i + 1u].subject))
        {
            /* No, the chain is not linked by name even if the key happens to verify */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] issuer name does not match cert[%u] subject name", i, i + 1u);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_ISSUER_MISMATCH, i);
            return false;
        }

        /* Does the signature of cert[i] verify with the key of cert[i + 1]? */
        if (!SSFX509VerifyCertSignature(&certs[i], &certs[i + 1u]))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] signature by cert[%u] FAILED", i, i + 1u);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_SIGNATURE, i);
            return false;
        }

        /* Does cert[i]'s AKID agree with cert[i + 1]'s SKID when both are present (4.2.1.1)? */
        if (!SSFX509CheckSKIDAKID(&certs[i], &certs[i + 1u]))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] AKID (%lu bytes) does not match cert[%u] SKID (%lu bytes)", i,
                (unsigned long)certs[i].akidLen, i + 1u, (unsigned long)certs[i + 1u].skidLen);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_KEY_ID_MISMATCH, i);
            return false;
        }
    }

    /* Some trust anchor names, is valid for, key-links to, and signs the last chain cert */
    memset(&anchor, 0, sizeof(anchor));
    for (j = 0; (j < trustCount) && (!trusted); j++)
    {
        SSF_REQUIRE(trustDer[j] != NULL);
        if (!SSFX509Parse(trustDer[j], trustDerLen[j], &anchor)) continue;
        if (!_SSFX509NameEquals(&last->issuer, &anchor.subject)) continue;
        if (!SSFX509IsValid(&anchor, nowUnixSec)) continue;
        if (!SSFX509CheckSKIDAKID(last, &anchor)) continue;
        trusted = SSFX509VerifyCertSignature(last, &anchor);
    }

    /* Is the chain anchored? */
    if (!trusted)
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
            "Chain: no trust anchor found for issuer of cert[%u] (%u CAs checked)", chainLen - 1u,
            trustCount);
        _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_UNKNOWN_CA, (uint8_t)(chainLen - 1u));
        return false;
    }

    /* Every intermediate is a CA allowed to sign, within its path length (Sec. 6.1.4 (h), (k)) */
    for (i = 1; i < chainLen; i++)
    {
        /* Are Basic Constraints present with cA TRUE? */
        if ((!certs[i].hasBasicConstraints) || (!certs[i].isCA))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] not a CA (hasBC=%d isCA=%d)",
                i, certs[i].hasBasicConstraints, certs[i].isCA);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_NOT_CA, i);
            return false;
        }

        /* Does Key Usage, when present, include keyCertSign? */
        if ((certs[i].hasKeyUsage) && ((certs[i].keyUsageBits & SSF_X509_KU_KEY_CERT_SIGN) == 0u))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] is CA but Key Usage lacks keyCertSign (KU=0x%04X)", i,
                certs[i].keyUsageBits);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_CA_KEY_USAGE, i);
            return false;
        }

        /* Is the subordinate CA count below cert[i], (i - 1), within its pathLenConstraint? */
        if ((certs[i].pathLenConstraint >= 0) && ((int8_t)(i - 1u) > certs[i].pathLenConstraint))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] pathLenConstraint=%d but %u subordinate CAs present", i,
                certs[i].pathLenConstraint, i - 1u);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_PATH_LEN, i);
            return false;
        }
    }

    /* anchor is the one whose key verified the last chain cert; only its constraints apply */
    numSubCAs = (chainLen >= 2u) ? (uint8_t)(chainLen - 1u) : 0u;

    /* Is the last chain cert the anchor itself, as servers that send the root do? */
    if ((numSubCAs > 0u) && (chainDerLen[chainLen - 1u] == trustDerLen[j - 1u]) &&
        (memcmp(chainDer[chainLen - 1u], trustDer[j - 1u], trustDerLen[j - 1u]) == 0))
    {
        /* Yes, it is not a subordinate of itself */
        numSubCAs--;
    }
    /* No */

    /* Are the chain's subordinate CAs within the anchor's pathLenConstraint (Sec. 6.1.4 (k))? */
    if ((anchor.pathLenConstraint >= 0) && ((int8_t)numSubCAs > anchor.pathLenConstraint))
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
            "Chain: trust anchor pathLenConstraint=%d but %u subordinate CAs in chain",
            anchor.pathLenConstraint, numSubCAs);
        _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_PATH_LEN, chainLen);
        return false;
    }

    /* Every chain cert's SANs must satisfy the anchor's Name Constraints (Sec. 6.1.4 (g)) */
    for (i = 0; (anchor.hasNameConstraints) && (i < chainLen); i++)
    {
        /* Does cert[i] satisfy them? */
        if (!_SSFX509NCValidateCert(&certs[i], &anchor))
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] SAN violates nameConstraints of trust anchor", i);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_NAME_CONSTRAINTS, i);
            return false;
        }
    }

    /* Does leaf EKU, when present, include the purpose or anyExtendedKeyUsage (Sec. 4.2.1.12)? */
    if ((certs[0].hasExtKeyUsage) && (!certs[0].ekuAnyPurpose) &&
        (((purpose == SSF_X509_PURPOSE_SERVER_AUTH) && (!certs[0].ekuServerAuth)) ||
         ((purpose == SSF_X509_PURPOSE_CODE_SIGNING) && (!certs[0].ekuCodeSigning))))
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
            "Chain: leaf EKU lacks the purpose %d (serverAuth=%d clientAuth=%d codeSigning=%d)",
            purpose, certs[0].ekuServerAuth, certs[0].ekuClientAuth, certs[0].ekuCodeSigning);
        _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_EKU, 0u);
        return false;
    }

    /* Code signing: does leaf KU, when present, include digitalSignature or nonRepudiation? */
    if ((purpose == SSF_X509_PURPOSE_CODE_SIGNING) && (certs[0].hasKeyUsage) &&
        ((certs[0].keyUsageBits &
          (SSF_X509_KU_DIGITAL_SIGNATURE | SSF_X509_KU_NON_REPUDIATION)) == 0u))
    {
        /* No */
        SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
            "Chain: leaf Key Usage lacks digitalSignature and nonRepudiation (KU=0x%04X)",
            certs[0].keyUsageBits);
        _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_LEAF_KEY_USAGE, 0u);
        return false;
    }

    /* Every subordinate of a constrained intermediate satisfies its Name Constraints (6.1.4 (g)) */
    for (i = 1; i < chainLen; i++)
    {
        for (j = 0; (certs[i].hasNameConstraints) && (j < i); j++)
        {
            /* Does cert[j] violate them? */
            if (!_SSFX509NCValidateCert(&certs[j], &certs[i]))
            {
                /* Yes */
                SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                    "Chain: cert[%u] SAN violates nameConstraints of cert[%u]", j, i);
                _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_NAME_CONSTRAINTS, j);
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
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: cert[%u] has unrecognized critical extension (OID %lu bytes)", i,
                (unsigned long)certs[i].exts[e].oidRawLen);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_CRITICAL_EXT, i);
            return false;
        }
    }

    /* Server authentication: the leaf names hostnameStrOpt in a dNSName or iPAddress SAN */
    if (purpose == SSF_X509_PURPOSE_SERVER_AUTH)
    {
        uint8_t hostIP[4];
        size_t hostLen;
        bool hostIsIPv4;
        bool hostIsIPv6;
        bool hostIsNumeric;

        /* The reference identity type picks the one SAN type it may match (RFC 9525 6.3) */
        hostIsIPv4 = _SSFX509ParseIPv4(hostnameStrOpt, hostIP);
        /* A ':' (IPv6, unsupported) or an over-long hostname matches nothing */
        hostIsIPv6 = ((!SSFStrLen(hostnameStrOpt, _UB_DNS_NAME + 1u, &hostLen)) ||
                      (memchr(hostnameStrOpt, ':', hostLen) != NULL));
        /* A non-canonical numeric host ("010.0.0.1") matches nothing */
        hostIsNumeric = _SSFX509IsNumericHost(hostnameStrOpt);

        for (i = 0; (i < certs[0].sanLen) && (!matched); i++)
        {
            /* Is the hostname a DNS name and this SAN a dNSName? */
            if ((!hostIsIPv4) && (!hostIsIPv6) && (!hostIsNumeric) &&
                (certs[0].san[i].type == SSF_X509_SAN_DNS))
            {
                /* Yes */
                matched = _SSFX509HostnameMatch(hostnameStrOpt, certs[0].san[i].val,
                                                certs[0].san[i].valLen);
            }
            /* No, is the hostname an IPv4 literal and this SAN an iPAddress? */
            else if ((hostIsIPv4) && (certs[0].san[i].type == SSF_X509_SAN_IP))
            {
                /* Yes */
                matched = _SSFX509IPAddressMatch(hostnameStrOpt, certs[0].san[i].val,
                                                 certs[0].san[i].valLen);
            }
            /* No, the types differ, or an IPv6 literal, which is not supported, never matches */
        }

        /* Was the hostname matched? */

        if (!matched)
        {
            /* No */
            SSF_TLS_TRACE_CERT_ERROR(_SSF_X509_TRACE_CTX,
                "Chain: hostname '%s' not matched in SAN (sanLen=%u)", hostnameStrOpt,
                certs[0].sanLen);
            _SSF_X509_VERIFY_FAIL(errOut, SSF_X509_VERIFY_ERR_HOSTNAME, 0u);
            return false;
        }
    }
    return true;
}
#ifdef _WIN32
#pragma warning(pop)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Returns true if chainDer[0] validates to a trust anchor and is issued for hostnameStr.        */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509VerifyChain(const uint8_t **chainDer, const uint32_t *chainDerLen, uint8_t chainLen,
                        const uint8_t **trustDer, const uint32_t *trustDerLen, uint8_t trustCount,
                        const char *hostnameStr, uint64_t nowUnixSec,
                        SSFX509VerifyErr_t *errOut)
{
    SSF_REQUIRE(hostnameStr != NULL);
    SSF_REQUIRE(hostnameStr[0] != '\0');

    return SSFX509VerifyChainPurpose(chainDer, chainDerLen, chainLen, trustDer, trustDerLen,
                                     trustCount, SSF_X509_PURPOSE_SERVER_AUTH, hostnameStr,
                                     nowUnixSec, errOut);
}
