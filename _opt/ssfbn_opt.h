/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfbn configuration                                                   */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_BN_OPT_H_INCLUDE
#define SSF_BN_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssfbn maximum bignum width in bits.                                                          */
/*                                                                                              */
/* RSA-N keygen, CRT private op, and ModInvExt run intermediate products at up to 2·N bits      */
/* (full-width n × n recombination, λ(n) inversion). The cap therefore needs to be at least     */
/* twice the largest supported RSA modulus: 4096-bit RSA → 8192. Setting MAX_BITS = 8192 lets   */
/* SSFRSAKeyGen / SSFRSASign* run end-to-end at all three documented sizes (2048, 3072, 4096)   */
/* on the host build. Cost is doubled SSFBN_t footprint (~1 KB per BN at the new cap) and       */
/* roughly doubled stack pressure in the deep BN call chain — fine on hosted, may be tight on   */
/* cortex-M class targets that pin the stack.                                                    */
#define SSF_BN_CONFIG_MAX_BITS               (8192u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_OPT_H_INCLUDE */
