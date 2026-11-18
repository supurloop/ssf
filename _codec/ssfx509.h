/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfx509.h                                                                                     */
/* Provides X.509 v3 certificate parsing interface (RFC 5280).                                   */
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
#ifndef SSF_X509_H_INCLUDE
#define SSF_X509_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Maximum certificate DER size is SSF_X509_CONFIG_MAX_CERT_SIZE bytes.                          */
/* Maximum parsed extensions is SSF_X509_CONFIG_MAX_EXTENSIONS.                                  */
/* Maximum SAN entries is SSF_X509_CONFIG_MAX_SAN_ENTRIES.                                       */
/* All pointer fields in SSFX509Cert_t point into the original DER buffer (zero-copy).           */
/* The DER buffer must remain valid for the lifetime of the parsed structure.                     */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* SAN entry types (GeneralName tag values) */
#define SSF_X509_SAN_DNS   ((uint8_t)2u)
#define SSF_X509_SAN_IP    ((uint8_t)7u)

/* Key usage bits (RFC 5280 section 4.2.1.3) */
#define SSF_X509_KU_DIGITAL_SIGNATURE  ((uint16_t)0x8000u)
#define SSF_X509_KU_NON_REPUDIATION    ((uint16_t)0x4000u)
#define SSF_X509_KU_KEY_ENCIPHERMENT   ((uint16_t)0x2000u)
#define SSF_X509_KU_DATA_ENCIPHERMENT  ((uint16_t)0x1000u)
#define SSF_X509_KU_KEY_AGREEMENT      ((uint16_t)0x0800u)
#define SSF_X509_KU_KEY_CERT_SIGN      ((uint16_t)0x0400u)
#define SSF_X509_KU_CRL_SIGN           ((uint16_t)0x0200u)

/* Distinguished Name */
typedef struct SSFX509Name
{
    const uint8_t *cn;  uint32_t cnLen;    /* Common Name */
    const uint8_t *o;   uint32_t oLen;     /* Organization */
    const uint8_t *ou;  uint32_t ouLen;    /* Organizational Unit */
    const uint8_t *c;   uint32_t cLen;     /* Country */
    const uint8_t *st;  uint32_t stLen;    /* State/Province */
    const uint8_t *l;   uint32_t lLen;     /* Locality */
    const uint8_t *raw; uint32_t rawLen;   /* Raw DER of the entire Name SEQUENCE */
} SSFX509Name_t;

/* Extension */
typedef struct SSFX509Ext
{
    const uint8_t *oidRaw;  uint32_t oidRawLen;
    bool critical;
    const uint8_t *value;   uint32_t valueLen;
} SSFX509Ext_t;

/* SAN entry */
typedef struct SSFX509SAN
{
    uint8_t type;             /* SSF_X509_SAN_DNS, SSF_X509_SAN_IP, etc. */
    const uint8_t *val;
    uint32_t valLen;
} SSFX509SAN_t;

/* Name Constraints subtree entry (RFC 5280 Section 4.2.1.10).                                   */
/* For SSF_X509_SAN_DNS: val is a UTF-8/ASCII DNS name suffix (e.g., "example.com").             */
/* For SSF_X509_SAN_IP: val is 8 bytes (IPv4 addr(4) || mask(4)) or 32 bytes (IPv6).             */
typedef struct SSFX509NameConstraint
{
    uint8_t type;             /* SSF_X509_SAN_DNS or SSF_X509_SAN_IP */
    const uint8_t *val;
    uint32_t valLen;
} SSFX509NameConstraint_t;

/* Parsed certificate (all pointers into the original DER buffer) */
typedef struct SSFX509Cert
{
    uint8_t version;                /* 0=v1, 1=v2, 2=v3 */

    const uint8_t *serial;         uint32_t serialLen;

    const uint8_t *sigAlgOidRaw;   uint32_t sigAlgOidRawLen;   /* From TBS */
    const uint8_t *sigAlgParams;   uint32_t sigAlgParamsLen;  /* Raw DER of algorithm parameters */
    const uint8_t *outerSigAlgOidRaw; uint32_t outerSigAlgOidRawLen; /* From Certificate */
    const uint8_t *outerSigAlgParams; uint32_t outerSigAlgParamsLen; /* Raw DER, Certificate */

    SSFX509Name_t issuer;
    SSFX509Name_t subject;

    uint64_t notBefore;            /* Unix seconds */
    uint64_t notAfter;             /* Unix seconds */

    /* Subject Public Key Info */
    const uint8_t *pubKeyAlgOidRaw; uint32_t pubKeyAlgOidRawLen;
    const uint8_t *pubKey;          uint32_t pubKeyLen;
    uint8_t pubKeyUnusedBits;
    const uint8_t *ecCurveOidRaw;   uint32_t ecCurveOidRawLen;

    /* Extensions */
    SSFX509Ext_t exts[SSF_X509_CONFIG_MAX_EXTENSIONS];
    uint8_t extsLen;

    /* Parsed common extensions */
    bool hasBasicConstraints;
    bool isCA;
    int8_t pathLenConstraint;      /* -1 = absent */
    bool hasKeyUsage;
    uint16_t keyUsageBits;
    bool hasExtKeyUsage;
    bool ekuServerAuth;            /* 1.3.6.1.5.5.7.3.1 */
    bool ekuClientAuth;            /* 1.3.6.1.5.5.7.3.2 */
    bool ekuCodeSigning;           /* 1.3.6.1.5.5.7.3.3 */
    bool ekuAnyPurpose;            /* 2.5.29.37.0 anyExtendedKeyUsage */

    SSFX509SAN_t san[SSF_X509_CONFIG_MAX_SAN_ENTRIES];
    uint8_t sanLen;

    const uint8_t *skid;           uint32_t skidLen;
    const uint8_t *akid;           uint32_t akidLen;

    /* Name Constraints (RFC 5280 Section 4.2.1.10). Read from every cert.                       */
    bool hasNameConstraints;
    SSFX509NameConstraint_t permittedSubtrees[SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS];
    uint8_t permittedLen;
    SSFX509NameConstraint_t excludedSubtrees[SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS];
    uint8_t excludedLen;

    /* TBSCertificate raw DER (for signature verification) */
    const uint8_t *tbsRaw;         uint32_t tbsRawLen;

    /* Signature */
    const uint8_t *signature;      uint32_t signatureLen;
    uint8_t signatureUnusedBits;
} SSFX509Cert_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Parse a DER-encoded X.509 certificate. All pointer fields in cert point into der[].           */
bool SSFX509Parse(const uint8_t *der, uint32_t derLen, SSFX509Cert_t *cert);

/* Validity check: returns true if notBefore <= nowUnixSec < notAfter. */
bool SSFX509IsValid(const SSFX509Cert_t *cert, uint64_t nowUnixSec);

/* OID comparison helpers */
bool SSFX509IsECDSA(const SSFX509Cert_t *cert);
bool SSFX509IsRSA(const SSFX509Cert_t *cert);
bool SSFX509IsP256(const SSFX509Cert_t *cert);

/* --------------------------------------------------------------------------------------------- */
/* Certificate generation                                                                        */
/* --------------------------------------------------------------------------------------------- */

/* Generation parameters for building a TBSCertificate / Certificate */
typedef struct SSFX509GenName
{
    SSFCStrIn_t cn;               /* Common Name (NULL if absent) */
    SSFCStrIn_t o;                /* Organization */
    SSFCStrIn_t ou;               /* Organizational Unit */
    SSFCStrIn_t c;                /* Country (2-letter code) */
    SSFCStrIn_t st;               /* State/Province */
    SSFCStrIn_t l;                /* Locality */
} SSFX509GenName_t;

typedef struct SSFX509GenParams
{
    uint8_t version;              /* 0=v1, 2=v3 (typically 2) */
    const uint8_t *serial;        /* Serial number bytes (big-endian) */
    uint32_t serialLen;
    const uint8_t *sigAlgOidRaw;  /* Signature algorithm OID (raw DER content) */
    uint32_t sigAlgOidRawLen;
    const uint8_t *sigAlgParams;  /* Optional algorithm parameters (e.g., PSS params) */
    uint32_t sigAlgParamsLen;
    SSFX509GenName_t issuer;
    SSFX509GenName_t subject;
    uint64_t notBefore;           /* Unix seconds */
    uint64_t notAfter;            /* Unix seconds */
    const uint8_t *pubKeyAlgOidRaw; /* Public key algorithm OID */
    uint32_t pubKeyAlgOidRawLen;
    const uint8_t *ecCurveOidRaw; /* EC curve OID (NULL for non-EC) */
    uint32_t ecCurveOidRawLen;
    const uint8_t *pubKey;        /* Public key bytes (for BIT STRING) */
    uint32_t pubKeyLen;
    bool isCA;
    int8_t pathLenConstraint;     /* -1 = absent, 0+ = max subordinate CAs */
    bool addBasicConstraints;
    bool addKeyUsage;
    uint16_t keyUsageBits;
    bool addExtKeyUsage;
    bool ekuServerAuth;
    bool ekuClientAuth;
    bool ekuCodeSigning;
    const char **sanDNSNames;          /* NULL-terminated array of DNS name strings */
    const uint8_t **sanIPAddrs;        /* Array of 4-byte IPv4 addresses (NULL-terminated) */
    const uint8_t *skid;               /* Subject Key Identifier bytes (NULL if absent) */
    uint32_t skidLen;
    const uint8_t *akid;               /* Authority Key Identifier bytes (NULL if absent) */
    uint32_t akidLen;
    bool addRawExt;                   /* Add one raw extension (for testing) */
    const uint8_t *rawExtOid;
    uint32_t rawExtOidLen;
    const uint8_t *rawExtValue;       /* Pre-encoded OCTET STRING content */
    uint32_t rawExtValueLen;
    bool rawExtCritical;
    /* Name Constraints (RFC 5280 Section 4.2.1.10). Extension is always emitted as critical.   */
    /* All arrays are NULL-terminated. IPs use 8-byte format: 4-byte addr + 4-byte mask.         */
    bool addNameConstraints;
    const char **ncPermittedDNS;
    const uint8_t **ncPermittedIPs;
    const char **ncExcludedDNS;
    const uint8_t **ncExcludedIPs;
} SSFX509GenParams_t;

/* Encode a TBSCertificate into bufOpt, or measure it when bufOpt is NULL; *lenOut gets the size. */
bool SSFX509EncodeTBS(uint8_t *bufOpt, uint32_t bufOptSize, const SSFX509GenParams_t *params,
                      uint32_t *lenOut);

/* Encode a Certificate around a precomputed signature over the TBS; NULL bufOpt measures.       */
bool SSFX509EncodeCert(uint8_t *bufOpt, uint32_t bufOptSize, const SSFX509GenParams_t *params,
                       const uint8_t *signature, uint32_t signatureLen, uint32_t *lenOut);

/* --------------------------------------------------------------------------------------------- */
/* Additional OID comparison helpers                                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFX509IsP384(const SSFX509Cert_t *cert);
bool SSFX509IsECDSASHA384(const SSFX509Cert_t *cert);
bool SSFX509IsRSAPSSSHA256(const SSFX509Cert_t *cert);
bool SSFX509IsRSAPSSSHA384(const SSFX509Cert_t *cert);
bool SSFX509IsRSAPKCS1SHA256(const SSFX509Cert_t *cert);
bool SSFX509IsRSAPKCS1SHA384(const SSFX509Cert_t *cert);
bool SSFX509IsRSAPKCS1SHA512(const SSFX509Cert_t *cert);
bool SSFX509IsEd25519(const SSFX509Cert_t *cert);

/* --------------------------------------------------------------------------------------------- */
/* Chain verification                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* What a chain is being validated for; selects the leaf checks SSFX509VerifyChainPurpose runs.   */
typedef enum SSFX509Purpose
{
    SSF_X509_PURPOSE_MIN = -1,
    SSF_X509_PURPOSE_SERVER_AUTH,   /* TLS server: hostname must match a SAN, EKU serverAuth */
    SSF_X509_PURPOSE_CODE_SIGNING,  /* Signed data: no hostname, EKU codeSigning, KU digitalSig */
    SSF_X509_PURPOSE_MAX
} SSFX509Purpose_t;

/* Verify sig over data with keyCert's public key; sigAlg selects the scheme, digestAlgOpt the   */
/* hash when sigAlg does not imply one (rsaEncryption) and must agree with it when it does.      */
bool SSFX509VerifySignature(const SSFX509Cert_t *keyCert, const uint8_t *sigAlgOidRaw,
                            uint32_t sigAlgOidRawLen, const uint8_t *sigAlgParamsOpt,
                            uint32_t sigAlgParamsLen, const uint8_t *digestAlgOidRawOpt,
                            uint32_t digestAlgOidRawLen, const uint8_t *data, uint32_t dataLen,
                            const uint8_t *sig, uint32_t sigLen);

/* Verify cert's signature with issuer's public key; ECDSA, RSA PKCS#1 v1.5, RSA-PSS, Ed25519.   */
bool SSFX509VerifyCertSignature(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer);

/* Verify chainDer[0] (leaf) up to a trust anchor and match its SAN against hostnameStr.         */
bool SSFX509VerifyChain(const uint8_t **chainDer, const uint32_t *chainDerLen,
                        uint8_t chainLen,
                        const uint8_t **trustDer, const uint32_t *trustDerLen,
                        uint8_t trustCount,
                        const char *hostnameStr, uint64_t nowUnixSec);

/* Verify chainDer[0] up to a trust anchor for purpose; hostnameStrOpt is required for           */
/* SSF_X509_PURPOSE_SERVER_AUTH and ignored otherwise.                                           */
bool SSFX509VerifyChainPurpose(const uint8_t **chainDer, const uint32_t *chainDerLen,
                               uint8_t chainLen,
                               const uint8_t **trustDer, const uint32_t *trustDerLen,
                               uint8_t trustCount, SSFX509Purpose_t purpose,
                               const char *hostnameStrOpt, uint64_t nowUnixSec);

/* Set trace callback for chain verification; fnOpt is a SSFTLSTraceFn_t, NULL disables.        */
void SSFX509SetTraceCtx(void (*fnOpt)(int, int, const char *, void *), void *userCtxOpt);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
/* Match an IPv4 address string against a SAN iPAddress entry (4-byte raw). */
bool SSFX509MatchIPAddress(const char *hostnameStr, const uint8_t *sanIP, uint32_t sanIPLen);

/* Returns true if cert's AKID and issuer's SKID match or either is absent, else false.          */
bool SSFX509CheckSKIDAKID(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer);

#if SSF_CONFIG_X509_UNIT_TEST == 1
void SSFX509UnitTest(void);
#endif /* SSF_CONFIG_X509_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_X509_H_INCLUDE */
