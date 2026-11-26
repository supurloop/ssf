/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfx509 configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_X509_OPT_H_INCLUDE
#define SSF_X509_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Largest DER TBSCertificate or Certificate in bytes the encoder will produce */
#define SSF_X509_CONFIG_MAX_CERT_SIZE        (4096u)

/* Maximum certificates in a chain passed to SSFX509VerifyChain() and kept by ssftlsc, 1..255 */
#ifndef SSF_X509_CONFIG_MAX_CHAIN_DEPTH
#define SSF_X509_CONFIG_MAX_CHAIN_DEPTH      (6u)
#endif

/* Maximum extensions retained in SSFX509Cert_t.exts; a certificate with more fails to parse */
#define SSF_X509_CONFIG_MAX_EXTENSIONS       (16u)

/* Maximum permitted and maximum excluded Name Constraints subtrees retained per certificate */
#define SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS (8u)

/* Maximum SAN entries retained in SSFX509Cert_t.san; a certificate with more fails to parse */
#define SSF_X509_CONFIG_MAX_SAN_ENTRIES      (8u)

/* Minimum RSA modulus size in bits for any RSA key used to verify a signature, >= 1024 */
#ifndef SSF_X509_CONFIG_RSA_MIN_BITS
#define SSF_X509_CONFIG_RSA_MIN_BITS         (2048u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_X509_OPT_H_INCLUDE */
