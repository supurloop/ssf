/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfx509 configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_X509_OPT_H_INCLUDE
#define SSF_X509_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum DER-encoded certificate size in bytes accepted by the parser and emitted by the        */
/* encoder; also sizes the on-stack scratch buffers used during parsing and encoding.             */
#define SSF_X509_CONFIG_MAX_CERT_SIZE        (4096u)

/* Maximum number of certificates in a chain passed to SSFX509VerifyChain (leaf + intermediates, */
/* + any root sent). Sizes an on-stack array of parsed certificates (about 1.5 KB each). It is    */
/* also the TLS client's chain limit: ssftlsc keeps this many from a server's Certificate        */
/* message and drops the rest (traced if verification then fails). 6 covers leaf, two            */
/* intermediates, a cross-signed root and the root. With ssfcms it must be at least              */
/* SSF_CMS_CONFIG_MAX_CERTS + 1.                                                                 */
#define SSF_X509_CONFIG_MAX_CHAIN_DEPTH      (6u)

/* Maximum number of extensions retained in SSFX509Cert_t.exts; extras are skipped.              */
#define SSF_X509_CONFIG_MAX_EXTENSIONS       (16u)

/* Maximum permitted and maximum excluded Name Constraints subtrees retained per certificate.    */
#define SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS (8u)

/* Maximum Subject Alternative Name entries retained in SSFX509Cert_t.san; extras are skipped.   */
#define SSF_X509_CONFIG_MAX_SAN_ENTRIES      (8u)

/* Minimum RSA modulus size in bits for any RSA key used to verify a signature (certificates,   */
/* chains, CMS signers). Smaller keys are refused even when the signature is mathematically     */
/* valid, as are keys whose public exponent is even or below 3 (AUDIT RSA-10). Must be >= 1024. */
#ifndef SSF_X509_CONFIG_RSA_MIN_BITS
#define SSF_X509_CONFIG_RSA_MIN_BITS         (2048u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_X509_OPT_H_INCLUDE */
