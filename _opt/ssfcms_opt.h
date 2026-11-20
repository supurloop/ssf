/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfcms configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_CMS_OPT_H_INCLUDE
#define SSF_CMS_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Longest CMS ContentInfo DER SSFCMSParse accepts, in bytes; longer inputs fail to parse.        */
#define SSF_CMS_CONFIG_MAX_DER_LEN           (8192u)

/* Maximum SignerInfo entries retained; a SignedData with more fails to parse.                   */
#define SSF_CMS_CONFIG_MAX_SIGNERS           (2u)

/* Maximum embedded certificates retained; a SignedData with more fails to parse.                */
/* SSF_X509_CONFIG_MAX_CHAIN_DEPTH must be at least this + 1 (enforced by ssfcms.c).             */
#define SSF_CMS_CONFIG_MAX_CERTS             (4u)

/* Maximum digestAlgorithms entries retained; a SignedData with more fails to parse.             */
#define SSF_CMS_CONFIG_MAX_DIGEST_ALGS       (2u)

/* Largest signedAttrs encoding, header included, that can be re-tagged for signature checking;  */
/* a signer with a longer one fails verification. Sizes an on-stack buffer in the verifier.       */
#define SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN  (512u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_CMS_OPT_H_INCLUDE */
