/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcms_ut.c                                                                                   */
/* Provides RFC 5652 CMS SignedData unit test.                                                   */
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
#include "ssfx509.h"
#include "ssfasn1.h"
#include "ssfsha2.h"
#include "ssfecdsa.h"
#include "ssfed25519.h"
#include "ssftls.h"
#include "ssfport.h"

#if SSF_CONFIG_CMS_UNIT_TEST == 1

/* Fixtures generated with OpenSSL 3.2.4 by the gen.sh script recorded in ssfcms.md: a P-256     */
/* root -> intermediate -> signer chain, an RSA-2048 self-signed signer, and a 24-byte content.   */
/* Every CMS fixture is DER with definite lengths (-noindef) except the one marked Ber.          */
#include "ssfcms_ut_fix.h"

/* OIDs the tests compare against */
static const uint8_t _utOidData[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x07u, 0x01u
};
static const uint8_t _utOidSha256[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u
};
static const uint8_t _utOidSha384[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u
};
static const uint8_t _utOidEcdsaSha256[] = {
    0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u
};
static const uint8_t _utOidRsaEncryption[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
};
static const uint8_t _utOidRsaPss[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
};

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the span a is byte-identical to the span b, else false.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _utSpanEq(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen)
{
    SSF_REQUIRE((a != NULL) || (aLen == 0u));
    SSF_REQUIRE((b != NULL) || (bLen == 0u));

    if (aLen != bLen) return false;
    if (aLen == 0u) return true;
    return (memcmp(a, b, aLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the span p lies entirely inside the buffer base, else false.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _utSpanIn(const uint8_t *p, uint32_t len, const uint8_t *base, uint32_t baseLen)
{
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(base != NULL);

    return (p >= base) && ((p + len) <= (base + baseLen));
}

/* --------------------------------------------------------------------------------------------- */
/* Verifier trace callback: counts calls and keeps the last level and message.                   */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _utTraceCount;
static uint32_t _utTraceErrors;
static int _utTraceLastLevel;
static int _utTraceLastCategory;
static void *_utTraceLastCtx;
static char _utTraceLastMsg[256];
static char _utTraceFirstMsg[256];

static void _utTrace(int level, int category, const char *msgStr, void *ctxOpt)
{
    size_t n = 0;

    SSF_REQUIRE(msgStr != NULL);

    _utTraceLastCategory = category;
    _utTraceLastCtx = ctxOpt;
    _utTraceCount++;
    if (level == (int)SSF_TLS_TRACE_ERROR) _utTraceErrors++;
    _utTraceLastLevel = level;
    while ((msgStr[n] != '\0') && (n < (sizeof(_utTraceLastMsg) - 1u)))
    {
        _utTraceLastMsg[n] = msgStr[n];
        n++;
    }
    _utTraceLastMsg[n] = '\0';
    if (_utTraceCount == 1u) memcpy(_utTraceFirstMsg, _utTraceLastMsg, n + 1u);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if needleStr occurs in hayStr, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
static bool _utContains(const char *hayStr, const char *needleStr)
{
    size_t i;
    size_t j;

    SSF_REQUIRE(hayStr != NULL);
    SSF_REQUIRE(needleStr != NULL);

    for (i = 0; hayStr[i] != '\0'; i++)
    {
        for (j = 0; (needleStr[j] != '\0') && (hayStr[i + j] != '\0') &&
                    (hayStr[i + j] == needleStr[j]); j++)
        {
        }
        if (needleStr[j] == '\0') return true;
    }
    return (needleStr[0] == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with *atOut set to the offset of the first pat in buf, else false if absent.      */
/* --------------------------------------------------------------------------------------------- */
static bool _utFind(const uint8_t *buf, uint32_t bufLen, const uint8_t *pat, uint32_t patLen,
                    uint32_t *atOut)
{
    uint32_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(pat != NULL);
    SSF_REQUIRE(patLen > 0u);
    SSF_REQUIRE(atOut != NULL);

    for (i = 0; (i + patLen) <= bufLen; i++)
    {
        if (memcmp(&buf[i], pat, patLen) == 0)
        {
            *atOut = i;
            return true;
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Test-only CMS builder: Ed25519 signers, CMSAlgorithmProtection, over-limit counts, bad attrs  */
/* --------------------------------------------------------------------------------------------- */
static const uint8_t _utOidSignedData[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x07u, 0x02u
};
static const uint8_t _utOidSha512[] = {
    0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u
};
static const uint8_t _utOidEcdsaSha384[] = {
    0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x03u
};
static const uint8_t _utOidEd25519[] = { 0x2Bu, 0x65u, 0x70u };
static const uint8_t _utOidEcPubKey[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u };
static const uint8_t _utOidP256[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u };
static const uint8_t _utOidAttrContentType[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x03u
};
static const uint8_t _utOidAttrMessageDigest[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x04u
};
static const uint8_t _utOidAttrSigningTime[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x05u
};
static const uint8_t _utOidAttrAlgProt[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x34u
};
static const uint8_t _utOidAttrUnknown[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x09u, 0x0Fu
};
static const uint8_t _utOidOtherContent[] = {
    0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x07u, 0x05u
};
static const uint8_t _utDerNull[] = { 0x05u, 0x00u };

/* Everything the builder can vary; zero means the conforming default */
typedef struct
{
    bool ed25519;                       /* Ed25519 signer, else P-256 ECDSA */
    const uint8_t *priv;                /* P-256 private key or Ed25519 seed */
    const uint8_t *pub;                 /* Ed25519 public key, unused for ECDSA */
    const uint8_t *certDer;             /* signer certificate */
    uint32_t certDerLen;
    bool omitCert;                      /* leave the signer certificate out of the message */
    const uint8_t *extraDer[4];         /* further certificates to embed */
    uint32_t extraDerLen[4];
    uint8_t extraCount;
    bool taggedCertChoice;              /* add a [0]-tagged CertificateChoices entry */
    bool crls;                          /* add an empty crls [1] */
    bool useSkid;                       /* identify the signer by SKID (version 3) */
    uint8_t siVersionOverride;          /* nonzero replaces the SignerInfo version */
    uint8_t sdVersion;                  /* zero means 1 */
    const uint8_t *digestOid;           /* SignerInfo digestAlgorithm, zero means SHA-256 */
    uint32_t digestOidLen;
    bool digestParamsBad;               /* INTEGER parameters on the digest algorithm */
    const uint8_t *setDigestOid;        /* digestAlgorithms entry when it should differ */
    uint32_t setDigestOidLen;
    uint8_t extraDigestAlgs;            /* dummy digestAlgorithms entries */
    const uint8_t *sigOid;              /* zero means ecdsa-with-SHA256 or id-Ed25519 */
    uint32_t sigOidLen;
    const uint8_t *eContentType;        /* zero means id-data */
    uint32_t eContentTypeLen;
    const uint8_t *content;
    uint32_t contentLen;
    bool attached;
    bool constructedEContent;           /* BER constructed OCTET STRING tag */
    bool noAttrs;                       /* omit signedAttrs */
    bool omitContentType;
    bool omitMessageDigest;
    bool dupContentType;
    const uint8_t *attrContentType;     /* content-type attribute value when it should differ */
    uint32_t attrContentTypeLen;
    bool wrongMessageDigest;
    bool signingTime;
    bool algProt;                       /* add CMSAlgorithmProtection */
    const uint8_t *apDigestOid;         /* zero means the SignerInfo digest algorithm */
    uint32_t apDigestOidLen;
    const uint8_t *apSigOid;            /* zero means the SignerInfo signature algorithm */
    uint32_t apSigOidLen;
    const uint8_t *apSigParams;
    uint32_t apSigParamsLen;
    bool apOmitSig;                     /* leave out the [1] signatureAlgorithm */
    uint32_t padAttrLen;                /* add an unknown attribute carrying this many bytes */
    bool unsignedAttrs;
    uint8_t signerCopies;               /* zero means 1 */
    uint8_t trailingSi;                 /* junk bytes appended inside the SignerInfo */
    bool wrongContentInfoOid;           /* ContentInfo names id-data instead of id-signedData */
    bool junkInCi;                      /* a NULL after the [0] inside the ContentInfo */
    bool junkInWrap;                    /* a NULL after SignedData inside the [0] */
    bool junkInEcont;                   /* a NULL after the OCTET STRING inside eContent [0] */
    bool noDigestAlgs;                  /* empty digestAlgorithms SET */
    bool noSigners;                     /* empty signerInfos SET */
    bool setDigestParamsBad;            /* INTEGER parameters on the digestAlgorithms entry */
    bool sidBadTag;                     /* SignerIdentifier is an OCTET STRING */
    bool skidEmpty;                     /* zero-length [0] subjectKeyIdentifier */
    bool emptySig;                      /* zero-length signature OCTET STRING */
    bool dupContentTypeValue;           /* two OIDs inside the content-type attribute's SET */
    bool dupSigningTime;                /* two signing-time attributes */
    bool dupAlgProt;                    /* two CMSAlgorithmProtection attributes */
    bool apMac;                         /* a trailing [2] macAlgorithm inside the protection */
    bool shortMessageDigest;            /* 20-byte message-digest attribute */
} _utCmsSpec_t;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if an AlgorithmIdentifier is written to out with *wOut set, else false.           */
/* --------------------------------------------------------------------------------------------- */
static bool _utEncAlgId(uint8_t *out, uint32_t outSize, const uint8_t *oid, uint32_t oidLen,
                        const uint8_t *paramsOpt, uint32_t paramsLen, uint32_t *wOut)
{
    uint8_t tmp[64];
    uint32_t n;
    uint32_t w;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(oid != NULL);
    SSF_REQUIRE((paramsOpt != NULL) || (paramsLen == 0u));
    SSF_REQUIRE(wOut != NULL);

    if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), oid, oidLen, &w)) return false;
    n = w;
    if ((paramsLen + n) > sizeof(tmp)) return false;
    if (paramsLen > 0u) memcpy(&tmp[n], paramsOpt, paramsLen);
    n += paramsLen;
    return SSFASN1EncWrap(out, outSize, SSF_ASN1_TAG_SEQUENCE, tmp, n, wOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if Attribute { type, SET { value } } is written to out with *wOut set.            */
/* --------------------------------------------------------------------------------------------- */
static bool _utEncAttr(uint8_t *out, uint32_t outSize, const uint8_t *typeOid, uint32_t typeOidLen,
                       const uint8_t *val, uint32_t valLen, uint32_t *wOut)
{
    static uint8_t tmp[7900];
    uint32_t n;
    uint32_t w;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(typeOid != NULL);
    SSF_REQUIRE(val != NULL);
    SSF_REQUIRE(wOut != NULL);

    if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), typeOid, typeOidLen, &w)) return false;
    n = w;
    if (!SSFASN1EncWrap(&tmp[n], sizeof(tmp) - n, SSF_ASN1_TAG_SET, val, valLen, &w)) return false;
    n += w;
    return SSFASN1EncWrap(out, outSize, SSF_ASN1_TAG_SEQUENCE, tmp, n, wOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the digest algorithm the spec selects for the signer.                                 */
/* --------------------------------------------------------------------------------------------- */
static void _utSpecDigest(const _utCmsSpec_t *s, const uint8_t **oidOut, uint32_t *oidLenOut,
                          SSFCMSDigestAlg_t *algOut)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(oidOut != NULL);
    SSF_REQUIRE(oidLenOut != NULL);
    SSF_REQUIRE(algOut != NULL);

    if (s->digestOid != NULL)
    {
        *oidOut = s->digestOid;
        *oidLenOut = s->digestOidLen;
    }
    else if (s->ed25519)
    {
        *oidOut = _utOidSha512;
        *oidLenOut = sizeof(_utOidSha512);
    }
    else
    {
        *oidOut = _utOidSha256;
        *oidLenOut = sizeof(_utOidSha256);
    }
    if (_utSpanEq(*oidOut, *oidLenOut, _utOidSha384, sizeof(_utOidSha384)))
    {
        *algOut = SSF_CMS_DIGEST_SHA384;
    }
    else if (_utSpanEq(*oidOut, *oidLenOut, _utOidSha512, sizeof(_utOidSha512)))
    {
        *algOut = SSF_CMS_DIGEST_SHA512;
    }
    else *algOut = SSF_CMS_DIGEST_SHA256;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the signed attributes SET content is written to out with *wOut set.           */
/* --------------------------------------------------------------------------------------------- */
static bool _utEncAttrsContent(const _utCmsSpec_t *s, const uint8_t *digest, uint32_t digestLen,
                               uint8_t *out, uint32_t outSize, uint32_t *wOut)
{
    static uint8_t val[7800];
    static uint8_t pad[7700];
    static const uint8_t macAlg[] = { 0xA2u, 0x07u, 0x06u, 0x05u, 0x2Bu, 0x0Eu, 0x03u, 0x02u,
                                      0x1Au };
    uint8_t md[SSF_SHA2_512_BYTE_SIZE];
    const uint8_t *ct;
    uint32_t ctLen;
    const uint8_t *dOid;
    uint32_t dOidLen;
    const uint8_t *sOid;
    uint32_t sOidLen;
    SSFCMSDigestAlg_t alg;
    uint32_t pos = 0;
    uint32_t n;
    uint32_t w;
    uint8_t copies;
    uint8_t c;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(digest != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(wOut != NULL);

    /* content-type */
    ct = (s->attrContentType != NULL) ? s->attrContentType :
         ((s->eContentType != NULL) ? s->eContentType : _utOidData);
    ctLen = (s->attrContentType != NULL) ? s->attrContentTypeLen :
            ((s->eContentType != NULL) ? s->eContentTypeLen : sizeof(_utOidData));
    if (!s->omitContentType)
    {
        if (!SSFASN1EncOIDRaw(val, sizeof(val), ct, ctLen, &w)) return false;
        n = w;
        if (s->dupContentTypeValue)
        {
            if (!SSFASN1EncOIDRaw(&val[n], sizeof(val) - n, ct, ctLen, &w)) return false;
            n += w;
        }
        if (!_utEncAttr(&out[pos], outSize - pos, _utOidAttrContentType,
                        sizeof(_utOidAttrContentType), val, n, &w)) return false;
        pos += w;
        if (s->dupContentType)
        {
            if (!SSFASN1EncOIDRaw(val, sizeof(val), ct, ctLen, &w)) return false;
            if (!_utEncAttr(&out[pos], outSize - pos, _utOidAttrContentType,
                            sizeof(_utOidAttrContentType), val, w, &w)) return false;
            pos += w;
        }
    }

    /* signing-time, once or twice */
    copies = s->signingTime ? (s->dupSigningTime ? 2u : 1u) : 0u;
    for (c = 0; c < copies; c++)
    {
        if (!SSFASN1EncUTCTime(val, sizeof(val), 1795000000ull, &w)) return false;
        if (!_utEncAttr(&out[pos], outSize - pos, _utOidAttrSigningTime,
                        sizeof(_utOidAttrSigningTime), val, w, &w)) return false;
        pos += w;
    }

    /* CMSAlgorithmProtection { digestAlgorithm, signatureAlgorithm [1] IMPLICIT }, once or twice */
    copies = s->algProt ? (s->dupAlgProt ? 2u : 1u) : 0u;
    for (c = 0; c < copies; c++)
    {
        _utSpecDigest(s, &dOid, &dOidLen, &alg);
        if (s->apDigestOid != NULL)
        {
            dOid = s->apDigestOid;
            dOidLen = s->apDigestOidLen;
        }
        sOid = (s->apSigOid != NULL) ? s->apSigOid :
               ((s->sigOid != NULL) ? s->sigOid :
                (s->ed25519 ? _utOidEd25519 : _utOidEcdsaSha256));
        sOidLen = (s->apSigOid != NULL) ? s->apSigOidLen :
                  ((s->sigOid != NULL) ? s->sigOidLen :
                   (s->ed25519 ? sizeof(_utOidEd25519) : sizeof(_utOidEcdsaSha256)));
        if (!_utEncAlgId(pad, sizeof(pad), dOid, dOidLen, NULL, 0u, &w)) return false;
        n = w;
        if (!s->apOmitSig)
        {
            uint8_t inner[64];
            uint32_t m;

            if (!SSFASN1EncOIDRaw(inner, sizeof(inner), sOid, sOidLen, &m)) return false;
            if ((m + s->apSigParamsLen) > sizeof(inner)) return false;
            if (s->apSigParamsLen > 0u) memcpy(&inner[m], s->apSigParams, s->apSigParamsLen);
            m += s->apSigParamsLen;
            if (!SSFASN1EncWrap(&pad[n], sizeof(pad) - n, 0xA1u, inner, m, &w)) return false;
            n += w;
        }
        if (s->apMac)
        {
            memcpy(&pad[n], macAlg, sizeof(macAlg));
            n += (uint32_t)sizeof(macAlg);
        }
        if (!SSFASN1EncWrap(val, sizeof(val), SSF_ASN1_TAG_SEQUENCE, pad, n, &w)) return false;
        if (!_utEncAttr(&out[pos], outSize - pos, _utOidAttrAlgProt, sizeof(_utOidAttrAlgProt),
                        val, w, &w)) return false;
        pos += w;
    }

    /* message-digest */
    if (!s->omitMessageDigest)
    {
        memcpy(md, digest, digestLen);
        if (s->wrongMessageDigest) md[0] ^= 0x01u;
        if (s->shortMessageDigest) digestLen = 20u;
        if (!SSFASN1EncOctetString(val, sizeof(val), md, digestLen, &w)) return false;
        if (!_utEncAttr(&out[pos], outSize - pos, _utOidAttrMessageDigest,
                        sizeof(_utOidAttrMessageDigest), val, w, &w)) return false;
        pos += w;
    }

    /* An unknown attribute of a chosen size, to grow the set past the configured limit */
    if (s->padAttrLen > 0u)
    {
        if (s->padAttrLen > sizeof(pad)) return false;
        memset(pad, 0x41u, s->padAttrLen);
        if (!SSFASN1EncOctetString(val, sizeof(val), pad, s->padAttrLen, &w)) return false;
        if (!_utEncAttr(&out[pos], outSize - pos, _utOidAttrUnknown, sizeof(_utOidAttrUnknown),
                        val, w, &w)) return false;
        pos += w;
    }
    *wOut = pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the spec's SignedData is built into out as a ContentInfo with *lenOut set.     */
/* --------------------------------------------------------------------------------------------- */
static bool _utBuildCms(const _utCmsSpec_t *s, uint8_t *out, uint32_t outSize, uint32_t *lenOut)
{
    static uint8_t attrs[8000];
    static uint8_t signedBytes[8004];
    static uint8_t si[8600];
    static uint8_t sis[8700];
    static uint8_t certs[5000];
    static uint8_t sd[SSF_CMS_CONFIG_MAX_DER_LEN + 1400u];
    static uint8_t wrap[SSF_CMS_CONFIG_MAX_DER_LEN + 1408u];
    uint8_t tmp[160];
    uint8_t tmp2[80];
    uint8_t digest[SSF_SHA2_512_BYTE_SIZE];
    uint8_t hash[SSF_SHA2_512_BYTE_SIZE];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t sigLen;
    SSFX509Cert_t cert;
    SSFCMSDigestAlg_t alg;
    const uint8_t *dOid;
    uint32_t dOidLen;
    const uint8_t *sOid;
    uint32_t sOidLen;
    const uint8_t *ct;
    uint32_t ctLen;
    const uint8_t *signedPtr;
    uint32_t signedLen;
    uint32_t attrsLen = 0;
    uint32_t digestLen;
    uint32_t pos;
    uint32_t n;
    uint32_t w;
    uint8_t i;
    uint8_t copies;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(s->priv != NULL);
    SSF_REQUIRE(s->certDer != NULL);
    SSF_REQUIRE(s->content != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    if (!SSFX509Parse(s->certDer, s->certDerLen, &cert)) return false;
    _utSpecDigest(s, &dOid, &dOidLen, &alg);
    sOid = (s->sigOid != NULL) ? s->sigOid : (s->ed25519 ? _utOidEd25519 : _utOidEcdsaSha256);
    sOidLen = (s->sigOid != NULL) ? s->sigOidLen :
              (s->ed25519 ? sizeof(_utOidEd25519) : sizeof(_utOidEcdsaSha256));
    ct = (s->eContentType != NULL) ? s->eContentType : _utOidData;
    ctLen = (s->eContentType != NULL) ? s->eContentTypeLen : sizeof(_utOidData);

    /* Content digest */
    if (alg == SSF_CMS_DIGEST_SHA384)
    {
        digestLen = SSF_SHA2_384_BYTE_SIZE;
        SSFSHA384(s->content, s->contentLen, digest, digestLen);
    }
    else if (alg == SSF_CMS_DIGEST_SHA512)
    {
        digestLen = SSF_SHA2_512_BYTE_SIZE;
        SSFSHA512(s->content, s->contentLen, digest, digestLen);
    }
    else
    {
        digestLen = SSF_SHA2_256_BYTE_SIZE;
        SSFSHA256(s->content, s->contentLen, digest, digestLen);
    }

    /* Signed attributes, and what the signature covers */
    if (!s->noAttrs)
    {
        if (!_utEncAttrsContent(s, digest, digestLen, attrs, sizeof(attrs), &attrsLen))
        {
            return false;
        }
        if (!SSFASN1EncWrap(signedBytes, sizeof(signedBytes), SSF_ASN1_TAG_SET, attrs, attrsLen,
                            &w)) return false;
        signedPtr = signedBytes;
        signedLen = w;
    }
    else
    {
        signedPtr = s->content;
        signedLen = s->contentLen;
    }

    /* Signature */
    if (s->ed25519)
    {
        SSF_REQUIRE(s->pub != NULL);
        if (!SSFEd25519Sign(s->priv, s->pub, signedPtr, signedLen, sig)) return false;
        sigLen = SSF_ED25519_SIG_SIZE;
    }
    else
    {
        SSFSHA256(signedPtr, signedLen, hash, SSF_SHA2_256_BYTE_SIZE);
        if (!SSFECDSASign(SSF_EC_CURVE_P256, s->priv, 32u, hash, SSF_SHA2_256_BYTE_SIZE, sig,
                          sizeof(sig), &sigLen)) return false;
    }

    /* SignerInfo */
    pos = 0;
    if (!SSFASN1EncIntU64(&si[pos], sizeof(si) - pos,
                          (s->siVersionOverride != 0u) ? s->siVersionOverride :
                          (s->useSkid ? 3u : 1u), &w)) return false;
    pos += w;
    if (s->sidBadTag)
    {
        if (!SSFASN1EncOctetString(&si[pos], sizeof(si) - pos, cert.skid, cert.skidLen, &w))
        {
            return false;
        }
        pos += w;
    }
    else if (s->useSkid)
    {
        if (!SSFASN1EncWrap(&si[pos], sizeof(si) - pos, 0x80u, cert.skid,
                            s->skidEmpty ? 0u : cert.skidLen, &w))
        {
            return false;
        }
        pos += w;
    }
    else
    {
        if ((cert.issuer.rawLen + 24u) > sizeof(tmp)) return false;
        memcpy(tmp, cert.issuer.raw, cert.issuer.rawLen);
        n = cert.issuer.rawLen;
        if (!SSFASN1EncInt(&tmp[n], sizeof(tmp) - n, cert.serial, cert.serialLen, &w)) return false;
        n += w;
        if (!SSFASN1EncWrap(&si[pos], sizeof(si) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, n, &w))
        {
            return false;
        }
        pos += w;
    }
    if (s->digestParamsBad)
    {
        if (!SSFASN1EncIntU64(tmp2, sizeof(tmp2), 7u, &w)) return false;
        if (!_utEncAlgId(&si[pos], sizeof(si) - pos, dOid, dOidLen, tmp2, w, &w)) return false;
    }
    else
    {
        if (!_utEncAlgId(&si[pos], sizeof(si) - pos, dOid, dOidLen, NULL, 0u, &w)) return false;
    }
    pos += w;
    if (!s->noAttrs)
    {
        if (!SSFASN1EncWrap(&si[pos], sizeof(si) - pos, 0xA0u, attrs, attrsLen, &w)) return false;
        pos += w;
    }
    if (!_utEncAlgId(&si[pos], sizeof(si) - pos, sOid, sOidLen, NULL, 0u, &w)) return false;
    pos += w;
    if (!SSFASN1EncOctetString(&si[pos], sizeof(si) - pos, sig, s->emptySig ? 0u : (uint32_t)sigLen,
                               &w)) return false;
    pos += w;
    if (s->unsignedAttrs)
    {
        if (!SSFASN1EncOctetString(tmp2, sizeof(tmp2), (const uint8_t *)"ts", 2u, &w)) return false;
        if (!_utEncAttr(tmp, sizeof(tmp), _utOidAttrUnknown, sizeof(_utOidAttrUnknown), tmp2, w,
                        &w)) return false;
        if (!SSFASN1EncWrap(&si[pos], sizeof(si) - pos, 0xA1u, tmp, w, &w)) return false;
        pos += w;
    }
    for (i = 0; i < s->trailingSi; i++)
    {
        si[pos++] = 0x00u;
    }

    /* signerInfos SET OF, with the SignerInfo repeated as requested */
    n = 0;
    copies = (s->signerCopies == 0u) ? 1u : s->signerCopies;
    for (i = 0; i < copies; i++)
    {
        if (!SSFASN1EncWrap(&sis[n], sizeof(sis) - n, SSF_ASN1_TAG_SEQUENCE, si, pos, &w))
        {
            return false;
        }
        n += w;
    }

    /* SignedData content */
    pos = 0;
    if (!SSFASN1EncIntU64(&sd[pos], sizeof(sd) - pos, (s->sdVersion == 0u) ? 1u : s->sdVersion,
                          &w)) return false;
    pos += w;
    {
        static uint8_t algs[200];
        uint32_t a = 0;

        if (s->setDigestParamsBad)
        {
            if (!SSFASN1EncIntU64(tmp2, sizeof(tmp2), 7u, &w)) return false;
            if (!_utEncAlgId(&algs[a], sizeof(algs) - a, dOid, dOidLen, tmp2, w, &w)) return false;
        }
        else if (!s->noDigestAlgs)
        {
            if (!_utEncAlgId(&algs[a], sizeof(algs) - a,
                             (s->setDigestOid != NULL) ? s->setDigestOid : dOid,
                             (s->setDigestOid != NULL) ? s->setDigestOidLen : dOidLen, NULL, 0u,
                             &w)) return false;
        }
        else w = 0;
        a += w;
        for (i = 0; i < s->extraDigestAlgs; i++)
        {
            if (!_utEncAlgId(&algs[a], sizeof(algs) - a, _utOidSha384, sizeof(_utOidSha384), NULL,
                             0u, &w)) return false;
            a += w;
        }
        if (!SSFASN1EncWrap(&sd[pos], sizeof(sd) - pos, SSF_ASN1_TAG_SET, algs, a, &w))
        {
            return false;
        }
        pos += w;
    }
    {
        static uint8_t eci[1200];
        uint32_t e;

        if (!SSFASN1EncOIDRaw(eci, sizeof(eci), ct, ctLen, &w)) return false;
        e = w;
        if (s->attached)
        {
            static uint8_t oct[1100];

            if (!SSFASN1EncWrap(oct, sizeof(oct),
                                s->constructedEContent ? 0x24u : SSF_ASN1_TAG_OCTET_STRING,
                                s->content, s->contentLen, &w)) return false;
            if (s->junkInEcont)
            {
                memcpy(&oct[w], _utDerNull, sizeof(_utDerNull));
                w += (uint32_t)sizeof(_utDerNull);
            }
            if (!SSFASN1EncWrap(&eci[e], sizeof(eci) - e, 0xA0u, oct, w, &w)) return false;
            e += w;
        }
        if (!SSFASN1EncWrap(&sd[pos], sizeof(sd) - pos, SSF_ASN1_TAG_SEQUENCE, eci, e, &w))
        {
            return false;
        }
        pos += w;
    }
    n = 0;
    if (s->taggedCertChoice)
    {
        if (!SSFASN1EncWrap(&certs[n], sizeof(certs) - n, 0xA0u, _utDerNull, sizeof(_utDerNull),
                            &w)) return false;
        n += w;
    }
    if (!s->omitCert)
    {
        if ((n + s->certDerLen) > sizeof(certs)) return false;
        memcpy(&certs[n], s->certDer, s->certDerLen);
        n += s->certDerLen;
    }
    for (i = 0; i < s->extraCount; i++)
    {
        if ((n + s->extraDerLen[i]) > sizeof(certs)) return false;
        memcpy(&certs[n], s->extraDer[i], s->extraDerLen[i]);
        n += s->extraDerLen[i];
    }
    if (n > 0u)
    {
        if (!SSFASN1EncWrap(&sd[pos], sizeof(sd) - pos, 0xA0u, certs, n, &w)) return false;
        pos += w;
    }
    if (s->crls)
    {
        if (!SSFASN1EncWrap(&sd[pos], sizeof(sd) - pos, 0xA1u, NULL, 0u, &w)) return false;
        pos += w;
    }
    n = 0;
    copies = s->noSigners ? 0u : ((s->signerCopies == 0u) ? 1u : s->signerCopies);
    {
        uint32_t sisLen = 0;

        for (i = 0; i < copies; i++)
        {
            uint16_t t;
            const uint8_t *v;
            uint32_t vl;
            SSFASN1Cursor_t c = { &sis[sisLen], sizeof(sis) - sisLen };
            SSFASN1Cursor_t nx;

            if (!SSFASN1DecGetTLV(&c, &t, &v, &vl, &nx)) return false;
            sisLen += (uint32_t)(nx.buf - c.buf);
        }
        if (!SSFASN1EncWrap(&sd[pos], sizeof(sd) - pos, SSF_ASN1_TAG_SET, sis, sisLen, &w))
        {
            return false;
        }
        pos += w;
    }

    /* ContentInfo */
    if (!SSFASN1EncWrap(wrap, sizeof(wrap), SSF_ASN1_TAG_SEQUENCE, sd, pos, &w)) return false;
    if (s->junkInWrap)
    {
        memcpy(&wrap[w], _utDerNull, sizeof(_utDerNull));
        w += (uint32_t)sizeof(_utDerNull);
    }
    if (!SSFASN1EncWrap(sd, sizeof(sd), 0xA0u, wrap, w, &w)) return false;
    n = w;
    if (s->junkInCi)
    {
        memcpy(&sd[n], _utDerNull, sizeof(_utDerNull));
        n += (uint32_t)sizeof(_utDerNull);
    }
    ct = s->wrongContentInfoOid ? _utOidData : _utOidSignedData;
    ctLen = s->wrongContentInfoOid ? (uint32_t)sizeof(_utOidData) :
                                     (uint32_t)sizeof(_utOidSignedData);
    if (!SSFASN1EncOIDRaw(wrap, sizeof(wrap), ct, ctLen, &w)) return false;
    if ((w + n) > sizeof(wrap)) return false;
    memcpy(&wrap[w], sd, n);
    n += w;
    return SSFASN1EncWrap(out, outSize, SSF_ASN1_TAG_SEQUENCE, wrap, n, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a certificate for a fresh key is built, self-signed or P-256 issued by a CA.   */
/* --------------------------------------------------------------------------------------------- */
static bool _utMakeCert(bool ed25519, bool isCA, const char *cnStr, const char *issuerCnStrOpt,
                        const uint8_t *issuerPrivOpt, uint8_t *priv, uint8_t *pub, uint8_t *out,
                        uint32_t outSize, uint32_t *lenOut)
{
    static uint8_t tbs[SSF_X509_CONFIG_MAX_CERT_SIZE];
    static const uint8_t skid[20] = { 0x5Au, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
                                      0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
                                      0x10u, 0x11u, 0x12u, 0x13u };
    uint8_t serial[] = { 0x42u };
    uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t sigLen;
    size_t pubLen;
    SSFX509GenParams_t p;
    uint32_t tbsLen;

    SSF_REQUIRE(cnStr != NULL);
    SSF_REQUIRE((issuerCnStrOpt == NULL) == (issuerPrivOpt == NULL));
    SSF_REQUIRE((!ed25519) || (issuerPrivOpt == NULL));
    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(pub != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    memset(&p, 0, sizeof(p));
    p.version = 2u;
    p.serial = serial;
    p.serialLen = sizeof(serial);
    p.issuer.cn = (issuerCnStrOpt != NULL) ? issuerCnStrOpt : cnStr;
    p.subject.cn = cnStr;
    p.notBefore = 1700000000ull;
    p.notAfter = 2000000000ull;
    p.pathLenConstraint = -1;
    p.addBasicConstraints = true;
    p.isCA = isCA;
    p.addKeyUsage = true;
    p.keyUsageBits = isCA ? SSF_X509_KU_KEY_CERT_SIGN : SSF_X509_KU_DIGITAL_SIGNATURE;
    p.skid = skid;
    p.skidLen = sizeof(skid);
    if (ed25519)
    {
        if (!SSFEd25519KeyGen(priv, pub)) return false;
        p.sigAlgOidRaw = _utOidEd25519;
        p.sigAlgOidRawLen = sizeof(_utOidEd25519);
        p.pubKeyAlgOidRaw = _utOidEd25519;
        p.pubKeyAlgOidRawLen = sizeof(_utOidEd25519);
        p.pubKey = pub;
        p.pubKeyLen = SSF_ED25519_PUB_KEY_SIZE;
        if (!SSFX509EncodeTBS(tbs, sizeof(tbs), &p, &tbsLen)) return false;
        if (!SSFEd25519Sign(priv, pub, tbs, tbsLen, sig)) return false;
        sigLen = SSF_ED25519_SIG_SIZE;
    }
    else
    {
        if (!SSFECDSAKeyGen(SSF_EC_CURVE_P256, priv, SSF_ECDSA_MAX_PRIV_KEY_SIZE, pub,
                            SSF_ECDSA_MAX_PUB_KEY_SIZE, &pubLen)) return false;
        p.sigAlgOidRaw = _utOidEcdsaSha256;
        p.sigAlgOidRawLen = sizeof(_utOidEcdsaSha256);
        p.pubKeyAlgOidRaw = _utOidEcPubKey;
        p.pubKeyAlgOidRawLen = sizeof(_utOidEcPubKey);
        p.ecCurveOidRaw = _utOidP256;
        p.ecCurveOidRawLen = sizeof(_utOidP256);
        p.pubKey = pub;
        p.pubKeyLen = (uint32_t)pubLen;
        if (!SSFX509EncodeTBS(tbs, sizeof(tbs), &p, &tbsLen)) return false;
        SSFSHA256(tbs, tbsLen, hash, sizeof(hash));
        if (!SSFECDSASign(SSF_EC_CURVE_P256, (issuerPrivOpt != NULL) ? issuerPrivOpt : priv, 32u,
                          hash, sizeof(hash), sig, sizeof(sig), &sigLen)) return false;
    }
    return SSFX509EncodeCert(out, outSize, &p, sig, (uint32_t)sigLen, lenOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a self-signed signer certificate for a fresh key is built with *lenOut set.    */
/* --------------------------------------------------------------------------------------------- */
static bool _utMakeSigner(bool ed25519, const char *cnStr, uint8_t *priv, uint8_t *pub,
                          uint8_t *out, uint32_t outSize, uint32_t *lenOut)
{
    SSF_REQUIRE(cnStr != NULL);
    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(pub != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(lenOut != NULL);

    return _utMakeCert(ed25519, false, cnStr, NULL, NULL, priv, pub, out, outSize, lenOut);
}

void SSFCMSUnitTest(void)
{
    static uint8_t buf[SSF_CMS_CONFIG_MAX_DER_LEN + 1u];
    uint8_t sha256[SSF_SHA2_256_BYTE_SIZE];
    uint8_t sha384[SSF_SHA2_384_BYTE_SIZE];
    uint8_t bad[SSF_SHA2_256_BYTE_SIZE];
    SSFCMSSignedData_t sd;
    SSFCMSVerifyResult_t res;
    SSFCMSDigestAlg_t alg;
    SSFX509Cert_t cert;
    const SSFCMSSignerInfo_t *si;
    const uint8_t *trust[2];
    uint32_t trustLen[2];
    const uint64_t now = 1800000000ull;
    uint32_t at;
    uint32_t i;
    uint32_t n;

    SSFSHA256(_utFixContent, sizeof(_utFixContent), sha256, sizeof(sha256));
    SSFSHA384(_utFixContent, sizeof(_utFixContent), sha384, sizeof(sha384));

    /* ---- Parse: P-256 three-level chain, detached content, default OpenSSL attributes ---- */
    n = sizeof(_utFixEcdsaChainDetached);
    SSF_ASSERT(SSFCMSParse(_utFixEcdsaChainDetached, n, &sd) == true);
    SSF_ASSERT(sd.version == 1u);
    SSF_ASSERT(sd.digestAlgsLen == 1u);
    SSF_ASSERT(_utSpanEq(sd.digestAlgOidRaw[0], sd.digestAlgOidRawLen[0], _utOidSha256,
                         sizeof(_utOidSha256)) == true);
    SSF_ASSERT(_utSpanEq(sd.eContentTypeOidRaw, sd.eContentTypeOidRawLen, _utOidData,
                         sizeof(_utOidData)) == true);
    SSF_ASSERT((sd.hasEContent == false) && (sd.eContent == NULL) && (sd.eContentLen == 0u));
    SSF_ASSERT(sd.certsLen == 2u);
    for (i = 0; i < sd.certsLen; i++)
    {
        SSF_ASSERT(_utSpanIn(sd.certs[i].der, sd.certs[i].derLen, _utFixEcdsaChainDetached,
                             n) == true);
        SSF_ASSERT(SSFX509Parse(sd.certs[i].der, sd.certs[i].derLen, &cert) == true);
    }
    SSF_ASSERT(sd.signersLen == 1u);
    si = &sd.signers[0];
    SSF_ASSERT(si->version == 1u);
    SSF_ASSERT((si->sidSkid == NULL) && (si->sidSkidLen == 0u));

    /* The signer identifier names the intermediate as issuer and serial 3 as set at generation */
    SSF_ASSERT(SSFX509Parse(_utFixIntDer, sizeof(_utFixIntDer), &cert) == true);
    SSF_ASSERT(_utSpanEq(si->sidIssuerRaw, si->sidIssuerRawLen, cert.subject.raw,
                         cert.subject.rawLen) == true);
    SSF_ASSERT((si->sidSerialLen == 1u) && (si->sidSerial[0] == 0x03u));
    SSF_ASSERT(_utSpanEq(si->digestAlgOidRaw, si->digestAlgOidRawLen, _utOidSha256,
                         sizeof(_utOidSha256)) == true);

    /* Signed attributes: whole [0] TLV retained, content-type and message-digest decoded */
    SSF_ASSERT((si->signedAttrs != NULL) && (si->signedAttrsLen > 0u));
    SSF_ASSERT(_utSpanIn(si->signedAttrs, si->signedAttrsLen, _utFixEcdsaChainDetached, n) == true);
    SSF_ASSERT(si->signedAttrs[0] == 0xA0u);
    SSF_ASSERT(_utSpanEq(si->contentTypeOidRaw, si->contentTypeOidRawLen, _utOidData,
                         sizeof(_utOidData)) == true);
    SSF_ASSERT(si->messageDigestLen == SSF_SHA2_256_BYTE_SIZE);
    SSF_ASSERT(memcmp(si->messageDigest, sha256, SSF_SHA2_256_BYTE_SIZE) == 0);
    SSF_ASSERT(si->hasSigningTime == true);
    SSF_ASSERT((si->signingTime > 1700000000ull) && (si->signingTime < 2000000000ull));
    SSF_ASSERT(si->hasAlgProtection == false);
    SSF_ASSERT(_utSpanEq(si->sigAlgOidRaw, si->sigAlgOidRawLen, _utOidEcdsaSha256,
                         sizeof(_utOidEcdsaSha256)) == true);
    SSF_ASSERT((si->sigAlgParams == NULL) && (si->sigAlgParamsLen == 0u));
    SSF_ASSERT((si->signatureLen >= 70u) && (si->signatureLen <= 72u));
    SSF_ASSERT(si->signature[0] == 0x30u);
    SSF_ASSERT(_utSpanIn(si->signature, si->signatureLen, _utFixEcdsaChainDetached, n) == true);
    SSF_ASSERT(SSFCMSGetDigestAlg(&sd, 0u, &alg) == true);
    SSF_ASSERT(alg == SSF_CMS_DIGEST_SHA256);

    /* ---- Verify with the file digest supplied, anchored at the root ---- */
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(res.signerIndex == 0u);
    SSF_ASSERT((res.hasSigningTime == true) && (res.signingTime == si->signingTime));
    SSF_ASSERT(res.signerSubject.cnLen == 15u);
    SSF_ASSERT(memcmp(res.signerSubject.cn, "SSF Test Signer", 15u) == 0);

    /* Anchored at the intermediate, or at both in either order */
    trust[0] = _utFixIntDer;
    trustLen[0] = sizeof(_utFixIntDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    trust[1] = _utFixRootDer;
    trustLen[1] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 2u, now, &res) == true);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    trust[1] = _utFixIntDer;
    trustLen[1] = sizeof(_utFixIntDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 2u, now, &res) == true);

    /* An unrelated anchor, or the RSA signer's certificate, anchors nothing */
    trust[0] = _utFixOtherDer;
    trustLen[0] = sizeof(_utFixOtherDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    trust[0] = _utFixRsaDer;
    trustLen[0] = sizeof(_utFixRsaDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);

    /* A wrong digest, a digest of the wrong algorithm, or the wrong length never verifies */
    memcpy(bad, sha256, sizeof(bad));
    bad[31] ^= 0x01u;
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                  1u, now, &res) == false);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha384, sizeof(sha384), SSF_CMS_DIGEST_SHA384, trust,
                                  trustLen, 1u, now, &res) == false);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256) - 1u, SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA384, trust,
                                  trustLen, 1u, now, &res) == false);

    /* Outside the signer certificate's validity, before and after */
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, 1700000000ull, &res) == false);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, 2500000000ull, &res) == false);

    /* Detached content cannot be verified as attached */
    SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);

    /* ---- Mutations of the same message ---- */
    memcpy(buf, _utFixEcdsaChainDetached, n);

    /* One bit of the signature */
    at = (uint32_t)(si->signature - _utFixEcdsaChainDetached) + 5u;
    buf[at] ^= 0x01u;
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    buf[at] ^= 0x01u;

    /* One bit of the message-digest attribute: the digest check fails before any signature */
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
    at = (uint32_t)(sd.signers[0].messageDigest - buf);
    buf[at] ^= 0x01u;
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    buf[at] ^= 0x01u;

    /* One bit of the signing-time attribute: the digest still matches, the signature does not */
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
    at = (uint32_t)(sd.signers[0].signedAttrs - buf) + 2u;
    while ((at < n) && (buf[at] != 0x17u)) at++;    /* first UTCTime inside signedAttrs */
    SSF_ASSERT(at < n);
    buf[at + 3u] ^= 0x01u;
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    buf[at + 3u] ^= 0x01u;

    /* One byte inside the signer certificate: its own signature breaks or it fails to parse */
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
    for (i = 0; i < sd.certsLen; i++)
    {
        SSF_ASSERT(SSFX509Parse(sd.certs[i].der, sd.certs[i].derLen, &cert) == true);
        if (_utSpanEq(cert.subject.raw, cert.subject.rawLen, sd.signers[0].sidIssuerRaw,
                      sd.signers[0].sidIssuerRawLen)) continue;
        at = (uint32_t)(cert.subject.cn - buf);
        buf[at] ^= 0x01u;
        if (SSFCMSParse(buf, n, &sd))
        {
            SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                          trustLen, 1u, now, &res) == false);
        }
        buf[at] ^= 0x01u;
        break;
    }

    /* SignedData version: 1 and 3 parse, anything else does not; it is unsigned so verify holds */
    {
        static const uint8_t ver1[] = { 0x02u, 0x01u, 0x01u };
        SSF_ASSERT(_utFind(buf, n, ver1, sizeof(ver1), &at) == true);
        buf[at + 2u] = 0x02u;
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == false);
        buf[at + 2u] = 0x04u;
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == false);
        buf[at + 2u] = 0x03u;
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
        SSF_ASSERT(sd.version == 3u);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == true);
        buf[at + 2u] = 0x01u;
    }

    /* Every truncation fails to parse and none hangs; a trailing byte fails too */
    for (i = 0; i < n; i++)
    {
        SSF_ASSERT(SSFCMSParse(buf, i, &sd) == false);
    }
    buf[n] = 0x00u;
    SSF_ASSERT(SSFCMSParse(buf, n + 1u, &sd) == false);
    SSF_ASSERT(SSFCMSParse(buf, SSF_CMS_CONFIG_MAX_DER_LEN + 1u, &sd) == false);
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);

    /* ---- RSA PKCS#1 v1.5 with rsaEncryption as the signature algorithm (RFC 3370) ---- */
    n = sizeof(_utFixRsaPkcs1Detached);
    SSF_ASSERT(SSFCMSParse(_utFixRsaPkcs1Detached, n, &sd) == true);
    SSF_ASSERT((sd.signersLen == 1u) && (sd.certsLen == 1u));
    si = &sd.signers[0];
    SSF_ASSERT(_utSpanEq(si->sigAlgOidRaw, si->sigAlgOidRawLen, _utOidRsaEncryption,
                         sizeof(_utOidRsaEncryption)) == true);
    SSF_ASSERT((si->sigAlgParamsLen == 2u) && (si->sigAlgParams[0] == 0x05u));
    SSF_ASSERT(si->signatureLen == 256u);
    trust[0] = _utFixRsaDer;
    trustLen[0] = sizeof(_utFixRsaDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(res.signerSubject.cnLen == 14u);
    SSF_ASSERT(memcmp(res.signerSubject.cn, "SSF RSA Signer", 14u) == 0);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);

    /* ---- RSA-PSS with SHA-256 parameters and a 32-byte salt (RFC 4056) ---- */
    n = sizeof(_utFixRsaPssDetached);
    SSF_ASSERT(SSFCMSParse(_utFixRsaPssDetached, n, &sd) == true);
    si = &sd.signers[0];
    SSF_ASSERT(_utSpanEq(si->sigAlgOidRaw, si->sigAlgOidRawLen, _utOidRsaPss,
                         sizeof(_utOidRsaPss)) == true);
    SSF_ASSERT((si->sigAlgParams != NULL) && (si->sigAlgParams[0] == 0x30u));
    trust[0] = _utFixRsaDer;
    trustLen[0] = sizeof(_utFixRsaDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);

    /* ---- Version 3 signer identified by SubjectKeyIdentifier, content attached ---- */
    n = sizeof(_utFixEcdsaSkidAttached);
    SSF_ASSERT(SSFCMSParse(_utFixEcdsaSkidAttached, n, &sd) == true);
    SSF_ASSERT(sd.version == 3u);
    si = &sd.signers[0];
    SSF_ASSERT(si->version == 3u);
    SSF_ASSERT((si->sidIssuerRaw == NULL) && (si->sidSerial == NULL));
    SSF_ASSERT((si->sidSkid != NULL) && (si->sidSkidLen == 20u));
    SSF_ASSERT((sd.hasEContent == true) && (sd.eContentLen == sizeof(_utFixContent)));
    SSF_ASSERT(memcmp(sd.eContent, _utFixContent, sizeof(_utFixContent)) == 0);
    for (i = 0; i < sd.certsLen; i++)
    {
        SSF_ASSERT(SSFX509Parse(sd.certs[i].der, sd.certs[i].derLen, &cert) == true);
        if (_utSpanEq(cert.skid, cert.skidLen, si->sidSkid, si->sidSkidLen)) break;
    }
    SSF_ASSERT(i < sd.certsLen);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == true);
    SSF_ASSERT(res.signerSubject.cnLen == 15u);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    trust[0] = _utFixOtherDer;
    trustLen[0] = sizeof(_utFixOtherDer);
    SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);

    /* Attached content tampered: the message-digest attribute no longer matches */
    memcpy(buf, _utFixEcdsaSkidAttached, n);
    at = (uint32_t)(sd.eContent - _utFixEcdsaSkidAttached);
    buf[at] ^= 0x01u;
    SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);

    /* ---- Two signers: whichever one the trust store anchors verifies ---- */
    n = sizeof(_utFixTwoSignersDetached);
    SSF_ASSERT(SSFCMSParse(_utFixTwoSignersDetached, n, &sd) == true);
    SSF_ASSERT((sd.signersLen == 2u) && (sd.certsLen == 3u));
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(res.signerIndex == 0u);
    trust[0] = _utFixRsaDer;
    trustLen[0] = sizeof(_utFixRsaDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(res.signerIndex == 1u);
    SSF_ASSERT(memcmp(res.signerSubject.cn, "SSF RSA Signer", 14u) == 0);
    trust[0] = _utFixOtherDer;
    trustLen[0] = sizeof(_utFixOtherDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    trust[1] = _utFixRsaDer;
    trustLen[1] = sizeof(_utFixRsaDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 2u, now, &res) == true);
    SSF_ASSERT(res.signerIndex == 1u);

    /* ---- RSA signer issued by the P-256 intermediate: an RSA leaf on an ECDSA chain ---- */
    n = sizeof(_utFixRsaChainDetached);
    SSF_ASSERT(SSFCMSParse(_utFixRsaChainDetached, n, &sd) == true);
    SSF_ASSERT((sd.signersLen == 1u) && (sd.certsLen == 2u));
    si = &sd.signers[0];
    SSF_ASSERT(_utSpanEq(si->sigAlgOidRaw, si->sigAlgOidRawLen, _utOidRsaEncryption,
                         sizeof(_utOidRsaEncryption)) == true);
    SSF_ASSERT(si->signatureLen == 256u);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(res.signerSubject.cnLen == 20u);
    SSF_ASSERT(memcmp(res.signerSubject.cn, "SSF RSA Chain Signer", 20u) == 0);
    trust[0] = _utFixIntDer;
    trustLen[0] = sizeof(_utFixIntDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    trust[0] = _utFixRsaDer;
    trustLen[0] = sizeof(_utFixRsaDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    trust[0] = _utFixOtherDer;
    trustLen[0] = sizeof(_utFixOtherDer);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);

    /* ---- No signed attributes: the signature covers the attached content directly ---- */
    n = sizeof(_utFixEcdsaNoattrAttached);
    SSF_ASSERT(SSFCMSParse(_utFixEcdsaNoattrAttached, n, &sd) == true);
    si = &sd.signers[0];
    SSF_ASSERT((si->signedAttrs == NULL) && (si->messageDigest == NULL));
    SSF_ASSERT((si->contentTypeOidRaw == NULL) && (si->hasSigningTime == false));

    /* This message embeds only the signer, so the root cannot anchor it but its issuer can */
    SSF_ASSERT(sd.certsLen == 1u);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);
    SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);
    trust[0] = _utFixIntDer;
    trustLen[0] = sizeof(_utFixIntDer);
    SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == true);
    SSF_ASSERT(res.hasSigningTime == false);
    /* A supplied digest must agree with the attached content the signature actually covers */
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                  1u, now, &res) == false);
    trust[0] = _utFixRootDer;
    trustLen[0] = sizeof(_utFixRootDer);

    /* ---- SHA-384 digest, P-384 signer with the codeSigning EKU under the P-256 CA ---- */
    n = sizeof(_utFixEcdsaCsSha384Detached);
    SSF_ASSERT(SSFCMSParse(_utFixEcdsaCsSha384Detached, n, &sd) == true);
    SSF_ASSERT(SSFCMSGetDigestAlg(&sd, 0u, &alg) == true);
    SSF_ASSERT(alg == SSF_CMS_DIGEST_SHA384);
    SSF_ASSERT(_utSpanEq(sd.digestAlgOidRaw[0], sd.digestAlgOidRawLen[0], _utOidSha384,
                         sizeof(_utOidSha384)) == true);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha384, sizeof(sha384), SSF_CMS_DIGEST_SHA384, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(memcmp(res.signerSubject.cn, "SSF Code Signer", 15u) == 0);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == false);
    SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);

    /* ---- The BER streaming form OpenSSL emits by default is rejected ---- */
    SSF_ASSERT(SSFCMSParse(_utFixEcdsaChainDetachedBer, sizeof(_utFixEcdsaChainDetachedBer),
                           &sd) == false);

    /* ---- Trace callback reports the reason for a failure and is silent once disabled ---- */
    n = sizeof(_utFixEcdsaChainDetached);
    SSF_ASSERT(SSFCMSParse(_utFixEcdsaChainDetached, n, &sd) == true);
    _utTraceCount = 0;
    _utTraceErrors = 0;
    _utTraceLastMsg[0] = '\0';
    SSFCMSSetTraceCtx(_utTrace, NULL);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                  1u, now, &res) == false);
    SSF_ASSERT(_utTraceErrors >= 1u);
    SSF_ASSERT(_utTraceLastLevel == (int)SSF_TLS_TRACE_ERROR);
    SSF_ASSERT(_utContains(_utTraceLastMsg, "CMS:") == true);
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                  trustLen, 1u, now, &res) == true);
    SSF_ASSERT(_utTraceLastLevel == (int)SSF_TLS_TRACE_DEBUG);
    SSFCMSSetTraceCtx(NULL, NULL);
    i = _utTraceCount;
    SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                  1u, now, &res) == false);
    SSF_ASSERT(_utTraceCount == i);

    /* ---- Preconditions ---- */
    SSF_ASSERT_TEST(SSFCMSParse(NULL, n, &sd));
    SSF_ASSERT_TEST(SSFCMSParse(_utFixEcdsaChainDetached, n, NULL));
    SSF_ASSERT_TEST(SSFCMSGetDigestAlg(NULL, 0u, &alg));
    SSF_ASSERT_TEST(SSFCMSGetDigestAlg(&sd, sd.signersLen, &alg));
    SSF_ASSERT_TEST(SSFCMSGetDigestAlg(&sd, 0u, NULL));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(NULL, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                       trustLen, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, NULL, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                       trustLen, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, sha256, 0u, SSF_CMS_DIGEST_SHA256, trust, trustLen, 1u,
                                       now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_MIN, trust,
                                       trustLen, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_MAX, trust,
                                       trustLen, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, NULL,
                                       trustLen, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                       NULL, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                       trustLen, 0u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                       trustLen, 1u, now, NULL));
    SSF_ASSERT_TEST(SSFCMSVerifyAttached(NULL, trust, trustLen, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyAttached(&sd, NULL, trustLen, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyAttached(&sd, trust, NULL, 1u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyAttached(&sd, trust, trustLen, 0u, now, &res));
    SSF_ASSERT_TEST(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, NULL));

    /* ---- Built messages: CMSAlgorithmProtection guard, Ed25519, limits, attribute rules ---- */
    {
        static uint8_t ecCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t edCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caACert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caBCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t issCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caAPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t caBPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t issPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t caAPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t caBPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t issPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const uint8_t sha1Oid[] = { 0x2Bu, 0x0Eu, 0x03u, 0x02u, 0x1Au };
        static const uint8_t bogusCert[] = { 0x30u, 0x03u, 0x02u, 0x01u, 0x01u };
        uint32_t caALen;
        uint32_t caBLen;
        uint32_t issLen;
        int marker = 0;
        static uint8_t ecPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t ecPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t edSeed[SSF_ED25519_SEED_SIZE];
        static uint8_t edPub[SSF_ED25519_PUB_KEY_SIZE];
        static uint8_t msg[SSF_CMS_CONFIG_MAX_DER_LEN + 64u];
        static const uint8_t content[] = "built by the test";
        uint8_t sha512[SSF_SHA2_512_BYTE_SIZE];
        uint32_t ecCertLen;
        uint32_t edCertLen;
        uint32_t len;
        _utCmsSpec_t s;

        SSF_ASSERT(_utMakeSigner(false, "ec signer", ecPriv, ecPub, ecCert, sizeof(ecCert),
                                 &ecCertLen) == true);
        SSF_ASSERT(_utMakeSigner(true, "ed signer", edSeed, edPub, edCert, sizeof(edCert),
                                 &edCertLen) == true);
        SSFSHA256(content, sizeof(content), sha256, sizeof(sha256));
        SSFSHA384(content, sizeof(content), sha384, sizeof(sha384));
        SSFSHA512(content, sizeof(content), sha512, sizeof(sha512));
        memcpy(bad, sha256, sizeof(bad));
        bad[0] ^= 0x01u;

        /* Helper: a conforming ECDSA detached message anchored at its own self-signed signer */
        #define _SPEC_RESET() do { \
            memset(&s, 0, sizeof(s)); \
            s.priv = ecPriv; s.pub = ecPub; s.certDer = ecCert; s.certDerLen = ecCertLen; \
            s.content = content; s.contentLen = sizeof(content); \
            trust[0] = ecCert; trustLen[0] = ecCertLen; \
        } while (0)
        #define _BUILD() SSF_ASSERT(_utBuildCms(&s, msg, sizeof(msg), &len) == true)
        #define _VERIFY256() SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), \
                                                SSF_CMS_DIGEST_SHA256, trust, trustLen, 1u, now, \
                                                &res)

        /* Baseline: the builder's output parses and verifies like the OpenSSL fixtures do */
        _SPEC_RESET();
        s.signingTime = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT((sd.signersLen == 1u) && (sd.certsLen == 1u) && (sd.hasEContent == false));
        SSF_ASSERT(_VERIFY256() == true);
        SSF_ASSERT((res.hasSigningTime == true) && (res.signingTime == 1795000000ull));
        SSF_ASSERT(memcmp(res.signerSubject.cn, "ec signer", 9u) == 0);

        /* CMSAlgorithmProtection that agrees with the SignerInfo passes */
        _SPEC_RESET();
        s.algProt = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.signers[0].hasAlgProtection == true);
        SSF_ASSERT(_utSpanEq(sd.signers[0].apDigestAlgOidRaw, sd.signers[0].apDigestAlgOidRawLen,
                             _utOidSha256, sizeof(_utOidSha256)) == true);
        SSF_ASSERT(_utSpanEq(sd.signers[0].apSigAlgOidRaw, sd.signers[0].apSigAlgOidRawLen,
                             _utOidEcdsaSha256, sizeof(_utOidEcdsaSha256)) == true);
        SSF_ASSERT(_VERIFY256() == true);

        /* Its signatureAlgorithm parameters may be absent or NULL while the SignerInfo's are */
        /* absent; anything else must match byte for byte */
        s.apSigParams = _utDerNull;
        s.apSigParamsLen = sizeof(_utDerNull);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == true);
        {
            static const uint8_t oddParams[] = { 0x02u, 0x01u, 0x20u };
            s.apSigParams = oddParams;
            s.apSigParamsLen = sizeof(oddParams);
            _BUILD();
            SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
            SSF_ASSERT(_VERIFY256() == false);
        }

        /* A protection attribute naming a different digest or signature algorithm is a */
        /* substitution and is rejected before any signature check */
        _SPEC_RESET();
        s.algProt = true;
        s.apDigestOid = _utOidSha384;
        s.apDigestOidLen = sizeof(_utOidSha384);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        _utTraceCount = 0;
        _utTraceErrors = 0;
        _utTraceFirstMsg[0] = '\0';
        SSFCMSSetTraceCtx(_utTrace, NULL);
        SSF_ASSERT(_VERIFY256() == false);
        SSF_ASSERT(_utContains(_utTraceFirstMsg, "CMSAlgorithmProtection") == true);
        SSFCMSSetTraceCtx(NULL, NULL);
        _SPEC_RESET();
        s.algProt = true;
        s.apSigOid = _utOidEcdsaSha384;
        s.apSigOidLen = sizeof(_utOidEcdsaSha384);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == false);

        /* A protection attribute without its signatureAlgorithm is malformed for a SignerInfo */
        _SPEC_RESET();
        s.algProt = true;
        s.apOmitSig = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* Ed25519 with SHA-512 as RFC 8419 requires; any other digest is refused */
        _SPEC_RESET();
        s.ed25519 = true;
        s.priv = edSeed;
        s.pub = edPub;
        s.certDer = edCert;
        s.certDerLen = edCertLen;
        s.algProt = true;
        trust[0] = edCert;
        trustLen[0] = edCertLen;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(SSFCMSGetDigestAlg(&sd, 0u, &alg) == true);
        SSF_ASSERT(alg == SSF_CMS_DIGEST_SHA512);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha512, sizeof(sha512), SSF_CMS_DIGEST_SHA512, trust,
                                      trustLen, 1u, now, &res) == true);
        SSF_ASSERT(memcmp(res.signerSubject.cn, "ed signer", 9u) == 0);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == false);
        s.digestOid = _utOidSha256;
        s.digestOidLen = sizeof(_utOidSha256);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == false);
        /* Ed25519 over attached content with no attributes needs the content, which it has */
        s.digestOid = NULL;
        s.digestOidLen = 0u;
        s.noAttrs = true;
        s.attached = true;
        s.algProt = false;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == true);

        /* Limits: one more signer, certificate or digest algorithm than configured fails */
        _SPEC_RESET();
        s.signerCopies = SSF_CMS_CONFIG_MAX_SIGNERS;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.signersLen == SSF_CMS_CONFIG_MAX_SIGNERS);
        SSF_ASSERT(_VERIFY256() == true);
        s.signerCopies = SSF_CMS_CONFIG_MAX_SIGNERS + 1u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        for (i = 0; i < (SSF_CMS_CONFIG_MAX_CERTS - 1u); i++)
        {
            s.extraDer[i] = edCert;
            s.extraDerLen[i] = edCertLen;
        }
        s.extraCount = SSF_CMS_CONFIG_MAX_CERTS - 1u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.certsLen == SSF_CMS_CONFIG_MAX_CERTS);
        SSF_ASSERT(_VERIFY256() == true);
        s.extraDer[s.extraCount] = edCert;
        s.extraDerLen[s.extraCount] = edCertLen;
        s.extraCount++;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.extraDigestAlgs = SSF_CMS_CONFIG_MAX_DIGEST_ALGS - 1u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.digestAlgsLen == SSF_CMS_CONFIG_MAX_DIGEST_ALGS);
        SSF_ASSERT(_VERIFY256() == true);
        s.extraDigestAlgs = SSF_CMS_CONFIG_MAX_DIGEST_ALGS;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* Signed attributes past the re-tagging limit parse but cannot be verified */
        _SPEC_RESET();
        s.padAttrLen = SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.signers[0].signedAttrsLen > SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN);
        SSF_ASSERT(_VERIFY256() == false);
        s.padAttrLen = 100u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == true);

        /* Attribute rules of RFC 5652 Sec. 5.3 and 11: both mandatory, neither duplicated */
        _SPEC_RESET();
        s.omitContentType = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.omitMessageDigest = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.dupContentType = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* A content-type attribute that disagrees with eContentType is rejected */
        _SPEC_RESET();
        s.attrContentType = _utOidOtherContent;
        s.attrContentTypeLen = sizeof(_utOidOtherContent);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == false);

        /* A message-digest attribute that disagrees with the content is rejected */
        _SPEC_RESET();
        s.wrongMessageDigest = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == false);

        /* Another content type verifies through signed attributes, never without them */
        _SPEC_RESET();
        s.eContentType = _utOidOtherContent;
        s.eContentTypeLen = sizeof(_utOidOtherContent);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == true);
        s.noAttrs = true;
        s.attached = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);

        /* Version and identifier form must agree (Sec. 5.3) */
        _SPEC_RESET();
        s.siVersionOverride = 3u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.useSkid = true;
        s.siVersionOverride = 1u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.useSkid = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT((sd.signers[0].version == 3u) && (sd.signers[0].sidSkidLen == 20u));
        SSF_ASSERT(_VERIFY256() == true);
        _SPEC_RESET();
        s.siVersionOverride = 2u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* The signer's digest algorithm must be listed in digestAlgorithms (Sec. 5.1) */
        _SPEC_RESET();
        s.setDigestOid = _utOidSha384;
        s.setDigestOidLen = sizeof(_utOidSha384);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == false);

        /* Digest algorithm parameters other than absent or NULL fail the parse (RFC 5754) */
        _SPEC_RESET();
        s.digestParamsBad = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* Unsigned attributes, CRLs and tagged certificate choices are skipped unread */
        _SPEC_RESET();
        s.unsignedAttrs = true;
        s.crls = true;
        s.taggedCertChoice = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.certsLen == 1u);
        SSF_ASSERT(_VERIFY256() == true);

        /* A BER constructed OCTET STRING for eContent is rejected */
        _SPEC_RESET();
        s.attached = true;
        s.constructedEContent = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* Junk after the SignerInfo fields fails the parse */
        _SPEC_RESET();
        s.trailingSi = 2u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* The signer certificate may live only in the trust store; absent from both, no verify */
        _SPEC_RESET();
        s.omitCert = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.certsLen == 0u);
        SSF_ASSERT(_VERIFY256() == true);
        trust[0] = edCert;
        trustLen[0] = edCertLen;
        SSF_ASSERT(_VERIFY256() == false);

        /* SignedData version 3 is accepted alongside version 1 */
        _SPEC_RESET();
        s.sdVersion = 3u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.version == 3u);
        SSF_ASSERT(_VERIFY256() == true);

        /* A ContentInfo whose contentType is not id-signedData */
        _SPEC_RESET();
        s.wrongContentInfoOid = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* Junk after the last element inside each of the three wrappers */
        _SPEC_RESET();
        s.junkInCi = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.junkInWrap = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.attached = true;
        s.junkInEcont = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* An empty digestAlgorithms set parses, but then no signer's algorithm is listed */
        _SPEC_RESET();
        s.noDigestAlgs = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.digestAlgsLen == 0u);
        SSF_ASSERT(_VERIFY256() == false);

        /* An empty signerInfos set parses, and there is nothing to verify or to ask about */
        _SPEC_RESET();
        s.noSigners = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.signersLen == 0u);
        SSF_ASSERT(_VERIFY256() == false);
        SSF_ASSERT_TEST(SSFCMSGetDigestAlg(&sd, 0u, &alg));

        /* INTEGER parameters on the digestAlgorithms entry, as already tested on the signer's */
        _SPEC_RESET();
        s.setDigestParamsBad = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* Identifier that is neither form, an empty SKID, and an empty signature */
        _SPEC_RESET();
        s.sidBadTag = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.useSkid = true;
        s.skidEmpty = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.emptySig = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* Exactly one value per attribute and at most one instance of each (Sec. 11) */
        _SPEC_RESET();
        s.dupContentTypeValue = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.signingTime = true;
        s.dupSigningTime = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        _SPEC_RESET();
        s.algProt = true;
        s.dupAlgProt = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);

        /* A trailing [2] macAlgorithm inside the protection attribute is tolerated unread */
        _SPEC_RESET();
        s.algProt = true;
        s.apMac = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.signers[0].hasAlgProtection == true);
        SSF_ASSERT(_VERIFY256() == true);

        /* Exactly the configured maximum length parses; one byte more does not. The Ed25519 */
        /* signer is used because its signature length is fixed, so the padding converges. */
        {
            int32_t pad = 4000;
            uint32_t k;

            _SPEC_RESET();
            s.ed25519 = true;
            s.priv = edSeed;
            s.pub = edPub;
            s.certDer = edCert;
            s.certDerLen = edCertLen;
            for (k = 0; k < 8u; k++)
            {
                s.padAttrLen = (uint32_t)pad;
                _BUILD();
                if (len == SSF_CMS_CONFIG_MAX_DER_LEN) break;
                pad += ((int32_t)SSF_CMS_CONFIG_MAX_DER_LEN - (int32_t)len);
            }
            SSF_ASSERT(len == SSF_CMS_CONFIG_MAX_DER_LEN);
            SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
            s.padAttrLen = (uint32_t)pad + 1u;
            _BUILD();
            SSF_ASSERT(len == (SSF_CMS_CONFIG_MAX_DER_LEN + 1u));
            SSF_ASSERT(SSFCMSParse(msg, len, &sd) == false);
        }

        /* A SHA-1 signer parses, reports no supported digest algorithm, and never verifies */
        _SPEC_RESET();
        s.digestOid = sha1Oid;
        s.digestOidLen = sizeof(sha1Oid);
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(SSFCMSGetDigestAlg(&sd, 0u, &alg) == false);
        SSF_ASSERT(_VERIFY256() == false);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha384, sizeof(sha384), SSF_CMS_DIGEST_SHA384, trust,
                                      trustLen, 1u, now, &res) == false);

        /* A message-digest attribute of the wrong length takes the length branch */
        _SPEC_RESET();
        s.shortMessageDigest = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.signers[0].messageDigestLen == 20u);
        SSF_ASSERT(_VERIFY256() == false);

        /* With signed attributes the digest attribute binds the content: a supplied digest */
        /* that matches it verifies even when the attached copy of the content was altered,  */
        /* while verifying the attached copy itself fails */
        _SPEC_RESET();
        s.attached = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        at = (uint32_t)(sd.eContent - msg);
        msg[at] ^= 0x01u;
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == true);
        SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);

        /* Both verify functions zero the result on failure */
        _SPEC_RESET();
        s.signingTime = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == true);
        SSF_ASSERT((res.signerSubject.cn != NULL) && (res.hasSigningTime == true));
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                      1u, now, &res) == false);
        SSF_ASSERT((res.signerIndex == 0u) && (res.signerSubject.cn == NULL));
        SSF_ASSERT((res.hasSigningTime == false) && (res.signingTime == 0u));
        SSF_ASSERT(_VERIFY256() == true);
        SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);
        SSF_ASSERT((res.signerSubject.cn == NULL) && (res.hasSigningTime == false));

        /* Chain assembly: a duplicated certificate and an unparseable one are both harmless */
        _SPEC_RESET();
        s.extraDer[0] = ecCert;
        s.extraDerLen[0] = ecCertLen;
        s.extraCount = 1u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.certsLen == 2u);
        SSF_ASSERT(_VERIFY256() == true);
        _SPEC_RESET();
        s.extraDer[0] = bogusCert;
        s.extraDerLen[0] = sizeof(bogusCert);
        s.extraCount = 1u;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.certsLen == 2u);
        SSF_ASSERT(_VERIFY256() == true);

        /* A signer issued by a CA: embedded it chains to the CA anchor; absent from the message */
        /* it is found only when the trust store holds it, and anchors only through the CA */
        SSF_ASSERT(_utMakeCert(false, true, "ec ca", NULL, NULL, caAPriv, caAPub, caACert,
                               sizeof(caACert), &caALen) == true);
        SSF_ASSERT(_utMakeCert(false, false, "issued signer", "ec ca", caAPriv, issPriv, issPub,
                               issCert, sizeof(issCert), &issLen) == true);
        _SPEC_RESET();
        s.priv = issPriv;
        s.certDer = issCert;
        s.certDerLen = issLen;
        trust[0] = caACert;
        trustLen[0] = caALen;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(_VERIFY256() == true);
        SSF_ASSERT(memcmp(res.signerSubject.cn, "issued signer", 13u) == 0);
        s.omitCert = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT(sd.certsLen == 0u);
        SSF_ASSERT(_VERIFY256() == false);                       /* signer not found anywhere */
        trust[0] = issCert;
        trustLen[0] = issLen;
        SSF_ASSERT(_VERIFY256() == false);                       /* found, but not self-signed */
        trust[1] = caACert;
        trustLen[1] = caALen;
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 2u, now, &res) == true);   /* found and anchored */

        /* Two anchors sharing the subject "ec ca": the one whose key signed the signer decides */
        SSF_ASSERT(_utMakeCert(false, true, "ec ca", NULL, NULL, caBPriv, caBPub, caBCert,
                               sizeof(caBCert), &caBLen) == true);
        SSF_ASSERT(_utMakeCert(false, false, "issued signer", "ec ca", caBPriv, issPriv, issPub,
                               issCert, sizeof(issCert), &issLen) == true);
        _SPEC_RESET();
        s.priv = issPriv;
        s.certDer = issCert;
        s.certDerLen = issLen;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        trust[0] = caACert;
        trustLen[0] = caALen;
        trust[1] = caBCert;
        trustLen[1] = caBLen;
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 2u, now, &res) == true);
        trust[0] = caBCert;
        trustLen[0] = caBLen;
        trust[1] = caACert;
        trustLen[1] = caALen;
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha256, sizeof(sha256), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 2u, now, &res) == true);
        trust[0] = caACert;
        trustLen[0] = caALen;
        SSF_ASSERT(_VERIFY256() == false);

        /* Empty attached content digests the empty string */
        _SPEC_RESET();
        s.contentLen = 0u;
        s.attached = true;
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        SSF_ASSERT((sd.hasEContent == true) && (sd.eContentLen == 0u));
        SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == true);
        SSFSHA256(content, 0u, bad, sizeof(bad));
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                      1u, now, &res) == true);
        memcpy(bad, sha256, sizeof(bad));
        bad[0] ^= 0x01u;

        /* The trace callback receives the certificate category and the caller's context */
        _SPEC_RESET();
        _BUILD();
        SSF_ASSERT(SSFCMSParse(msg, len, &sd) == true);
        _utTraceLastCategory = -1;
        _utTraceLastCtx = NULL;
        SSFCMSSetTraceCtx(_utTrace, &marker);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                      1u, now, &res) == false);
        SSF_ASSERT(_utTraceLastCategory == (int)SSF_TLS_TRACE_CERT);
        SSF_ASSERT(_utTraceLastCtx == (void *)&marker);
        SSFCMSSetTraceCtx(NULL, NULL);

        #undef _VERIFY256
        #undef _BUILD
        #undef _SPEC_RESET
    }

    /* ---- Modeled firmware signature, the production shape: root not embedded, two CA ---- */
    /* ---- levels with 19-byte serials, policies, CRL and AIA pointers and expiry in 2075, a */
    /* ---- leaf with a 20-byte serial and CN-first subject, CMSAlgorithmProtection among the  */
    /* ---- signed attributes, and an RFC 3161 timestamp token in the unsigned attributes.    */
    {
        static const uint8_t apDigestPattern[] = {
            0x06u, 0x09u, 0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u,
            0x05u, 0x00u, 0xA1u
        };
        uint8_t fwDigest[SSF_SHA2_256_BYTE_SIZE];
        const uint8_t *leafDer;
        uint32_t leafDerLen;

        n = sizeof(_utFixModeledCms);
        SSFSHA256(_utFixFwContent, sizeof(_utFixFwContent), fwDigest, sizeof(fwDigest));
        SSF_ASSERT(SSFCMSParse(_utFixModeledCms, n, &sd) == true);
        SSF_ASSERT((sd.version == 1u) && (sd.digestAlgsLen == 1u) && (sd.hasEContent == false));
        SSF_ASSERT(_utSpanEq(sd.digestAlgOidRaw[0], sd.digestAlgOidRawLen[0], _utOidSha256,
                             sizeof(_utOidSha256)) == true);

        /* Embedded order is issuing CAs first and the signer last; the verifier must reorder */
        SSF_ASSERT(sd.certsLen == 3u);
        SSF_ASSERT(SSFX509Parse(sd.certs[0].der, sd.certs[0].derLen, &cert) == true);
        SSF_ASSERT((cert.subject.cnLen == 23u) &&
                   (memcmp(cert.subject.cn, "SSF Firmware Signing CA", 23u) == 0));
        SSF_ASSERT((cert.isCA == true) && (cert.serialLen == 19u) && (cert.serial[0] == 0x33u));
        SSF_ASSERT(cert.notAfter > 3300000000ull);              /* GeneralizedTime, 2075 */
        SSF_ASSERT(SSFX509Parse(sd.certs[1].der, sd.certs[1].derLen, &cert) == true);
        SSF_ASSERT((cert.subject.cnLen == 19u) &&
                   (memcmp(cert.subject.cn, "SSF Firmware Master", 19u) == 0));
        SSF_ASSERT((cert.isCA == true) && (cert.pathLenConstraint == 0));
        SSF_ASSERT(SSFX509Parse(sd.certs[2].der, sd.certs[2].derLen, &cert) == true);
        SSF_ASSERT((cert.subject.cnLen == 22u) &&
                   (memcmp(cert.subject.cn, "SSF Firmware Signature", 22u) == 0));
        SSF_ASSERT((cert.isCA == false) && (cert.serialLen == 20u) && (cert.serial[0] == 0x4Au));
        SSF_ASSERT((cert.hasKeyUsage == true) &&
                   ((cert.keyUsageBits & SSF_X509_KU_DIGITAL_SIGNATURE) != 0u));
        SSF_ASSERT(cert.hasExtKeyUsage == false);
        leafDer = sd.certs[2].der;
        leafDerLen = sd.certs[2].derLen;

        /* The signer is named by the Firmware Master's name and the leaf's 20-byte serial */
        SSF_ASSERT(sd.signersLen == 1u);
        si = &sd.signers[0];
        SSF_ASSERT(si->version == 1u);
        SSF_ASSERT((si->sidSerialLen == 20u) && (si->sidSerial[0] == 0x4Au));
        SSF_ASSERT(SSFX509Parse(sd.certs[1].der, sd.certs[1].derLen, &cert) == true);
        SSF_ASSERT(_utSpanEq(si->sidIssuerRaw, si->sidIssuerRawLen, cert.subject.raw,
                             cert.subject.rawLen) == true);
        SSF_ASSERT(_utSpanEq(si->digestAlgOidRaw, si->digestAlgOidRawLen, _utOidSha256,
                             sizeof(_utOidSha256)) == true);

        /* Signed attributes: content-type, signing-time, CMSAlgorithmProtection, message-digest */
        SSF_ASSERT(si->signedAttrs != NULL);
        SSF_ASSERT(_utSpanEq(si->contentTypeOidRaw, si->contentTypeOidRawLen, _utOidData,
                             sizeof(_utOidData)) == true);
        SSF_ASSERT((si->messageDigestLen == sizeof(fwDigest)) &&
                   (memcmp(si->messageDigest, fwDigest, sizeof(fwDigest)) == 0));
        SSF_ASSERT((si->hasSigningTime == true) && (si->signingTime == 1794908631ull));
        SSF_ASSERT(si->hasAlgProtection == true);
        SSF_ASSERT(_utSpanEq(si->apDigestAlgOidRaw, si->apDigestAlgOidRawLen, _utOidSha256,
                             sizeof(_utOidSha256)) == true);
        SSF_ASSERT(_utSpanEq(si->apSigAlgOidRaw, si->apSigAlgOidRawLen, _utOidEcdsaSha256,
                             sizeof(_utOidEcdsaSha256)) == true);
        SSF_ASSERT((si->apSigAlgParams == NULL) && (si->apSigAlgParamsLen == 0u));
        SSF_ASSERT(_utSpanEq(si->sigAlgOidRaw, si->sigAlgOidRawLen, _utOidEcdsaSha256,
                             sizeof(_utOidEcdsaSha256)) == true);
        SSF_ASSERT((si->signatureLen >= 70u) && (si->signatureLen <= 72u));
        SSF_ASSERT(SSFCMSGetDigestAlg(&sd, 0u, &alg) == true);
        SSF_ASSERT(alg == SSF_CMS_DIGEST_SHA256);

        /* Verify with the firmware digest, anchored at the root the message does not carry */
        trust[0] = _utFixModRootDer;
        trustLen[0] = sizeof(_utFixModRootDer);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == true);
        SSF_ASSERT(res.signerIndex == 0u);
        SSF_ASSERT((res.signerSubject.cnLen == 22u) &&
                   (memcmp(res.signerSubject.cn, "SSF Firmware Signature", 22u) == 0));
        SSF_ASSERT((res.hasSigningTime == true) && (res.signingTime == 1794908631ull));

        /* Either embedded CA also anchors it; the signer alone and unrelated roots do not */
        trust[0] = _utFixModFscaDer;
        trustLen[0] = sizeof(_utFixModFscaDer);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == true);
        trust[0] = _utFixModFmDer;
        trustLen[0] = sizeof(_utFixModFmDer);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == true);
        trust[0] = leafDer;
        trustLen[0] = leafDerLen;
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == false);
        trust[0] = _utFixOtherDer;
        trustLen[0] = sizeof(_utFixOtherDer);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == false);
        trust[0] = _utFixRootDer;
        trustLen[0] = sizeof(_utFixRootDer);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == false);
        trust[0] = _utFixModRootDer;
        trustLen[0] = sizeof(_utFixModRootDer);

        /* Wrong digest or algorithm, a time before the signer's notBefore or after its notAfter */
        memcpy(bad, fwDigest, sizeof(bad));
        bad[5] ^= 0x01u;
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, bad, sizeof(bad), SSF_CMS_DIGEST_SHA256, trust, trustLen,
                                      1u, now, &res) == false);
        SSFSHA384(_utFixFwContent, sizeof(_utFixFwContent), sha384, sizeof(sha384));
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, sha384, sizeof(sha384), SSF_CMS_DIGEST_SHA384, trust,
                                      trustLen, 1u, now, &res) == false);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, 1790000000ull, &res) == false);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, 2800000000ull, &res) == false);
        SSF_ASSERT(SSFCMSVerifyAttached(&sd, trust, trustLen, 1u, now, &res) == false);

        /* The unsigned attributes are outside the signature: altering the token changes nothing */
        memcpy(buf, _utFixModeledCms, n);
        at = (uint32_t)(si->signature - _utFixModeledCms) + si->signatureLen + 40u;
        buf[at] ^= 0xFFu;
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == true);
        buf[at] ^= 0xFFu;

        /* Substituting the digest algorithm named inside CMSAlgorithmProtection is caught by the */
        /* guard before the signature is even checked */
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
        SSF_ASSERT(_utFind(sd.signers[0].signedAttrs, sd.signers[0].signedAttrsLen, apDigestPattern,
                           sizeof(apDigestPattern), &at) == true);
        at += (uint32_t)(sd.signers[0].signedAttrs - buf) + 10u;
        SSF_ASSERT(buf[at] == 0x01u);
        buf[at] = 0x02u;
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
        SSF_ASSERT(_utSpanEq(sd.signers[0].apDigestAlgOidRaw, sd.signers[0].apDigestAlgOidRawLen,
                             _utOidSha384, sizeof(_utOidSha384)) == true);
        _utTraceCount = 0;
        _utTraceFirstMsg[0] = '\0';
        SSFCMSSetTraceCtx(_utTrace, NULL);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == false);
        SSF_ASSERT(_utContains(_utTraceFirstMsg, "CMSAlgorithmProtection") == true);
        SSFCMSSetTraceCtx(NULL, NULL);
        buf[at] = 0x01u;

        /* One bit of the signature, and every truncation */
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
        at = (uint32_t)(sd.signers[0].signature - buf) + 9u;
        buf[at] ^= 0x01u;
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == false);
        buf[at] ^= 0x01u;
        for (i = 0; i < n; i++)
        {
            SSF_ASSERT(SSFCMSParse(buf, i, &sd) == false);
        }
        SSF_ASSERT(SSFCMSParse(buf, n, &sd) == true);
        SSF_ASSERT(SSFCMSVerifyDigest(&sd, fwDigest, sizeof(fwDigest), SSF_CMS_DIGEST_SHA256, trust,
                                      trustLen, 1u, now, &res) == true);
    }
}
#endif /* SSF_CONFIG_CMS_UNIT_TEST */
