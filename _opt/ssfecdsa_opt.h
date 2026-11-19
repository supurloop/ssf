/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfecdsa configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_ECDSA_OPT_H_INCLUDE
#define SSF_ECDSA_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* SSF_ECDSA_CONFIG_ENABLE_SIGN -- controls whether SSFECDSASign and the DER-encode helper it   */
/* depends on are compiled. The verify path was refactored so that DER-input parsing is now     */
/* purely byte-level (no ssfasn1 calls), so a verify-only target can set this to 0 and drop    */
/* the entire ssfasn1 module from its build -- the only remaining ssfasn1 reference in         */
/* ssfecdsa.c (the #include and the SSFASN1Enc* calls) is gated by this flag.                  */
/*                                                                                              */
/* SSFECDSAKeyGen, SSFECDHComputeSecret, and SSFECDSAVerify do not depend on Sign and remain   */
/* available regardless of this flag's value.                                                   */
/*                                                                                              */
/* The SSF_CRYPT_PROFILE_MIN_MEMORY profile defaults this to 0 -- suited to verify-only firmware*/
/* update receivers where the producer signs offline.                                           */
#ifndef SSF_ECDSA_CONFIG_ENABLE_SIGN
#define SSF_ECDSA_CONFIG_ENABLE_SIGN         (1u)
#endif

/* SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN -- when 1, SSFECDSASign verifies every signature it       */
/* produces before releasing it, under a public key derived from a fresh import of privKey and  */
/* a recomputed digest integer. A fault during signing (glitch, brownout, bit flip) then makes  */
/* Sign return false instead of emitting a faulty signature, which together with a correct      */
/* signature of the same hash would reveal the private key (RFC 6979 nonces are                 */
/* deterministic). Costs one fixed-base scalar multiplication and one verify per signature,     */
/* making signing about 5x slower, so it is off by default. Set to 1 on targets an attacker can */
/* physically glitch and that may sign the same hash more than once (AUDIT ECDSA-5).            */
#ifndef SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN
#define SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN   (0u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_ECDSA_OPT_H_INCLUDE */
