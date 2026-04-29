/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfecdsa configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_ECDSA_OPT_H_INCLUDE
#define SSF_ECDSA_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* SSF_ECDSA_CONFIG_ENABLE_SIGN — controls whether SSFECDSASign and the DER-encode helper it    */
/* depends on are compiled. The verify path was refactored so that DER-input parsing is now     */
/* purely byte-level (no ssfasn1 calls), so a verify-only target can set this to 0 and drop    */
/* the entire ssfasn1 module from its build — the only remaining ssfasn1 reference in          */
/* ssfecdsa.c (the #include and the SSFASN1Enc* calls) is gated by this flag.                  */
/*                                                                                              */
/* SSFECDSAKeyGen, SSFECDHComputeSecret, and SSFECDSAVerify do not depend on Sign and remain   */
/* available regardless of this flag's value.                                                   */
/*                                                                                              */
/* The SSF_CRYPT_PROFILE_MIN_MEMORY profile defaults this to 0 — suited to verify-only firmware*/
/* update receivers where the producer signs offline.                                           */
#ifndef SSF_ECDSA_CONFIG_ENABLE_SIGN
#define SSF_ECDSA_CONFIG_ENABLE_SIGN         (1u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_ECDSA_OPT_H_INCLUDE */
