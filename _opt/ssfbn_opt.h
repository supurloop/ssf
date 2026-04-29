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
/* By default this is auto-derived in ssfbn.h from the enabled algorithm flags                  */
/* (SSF_EC_CONFIG_ENABLE_P256/P384, SSF_RSA_CONFIG_ENABLE_2048/3072/4096) — pick the largest    */
/* enabled operand width × 2, since RSA keygen, CRT recombine, ModInvExt over λ(n), and ECC's   */
/* SSFBNModMulNIST all run intermediate products at up to 2·N bits (full-width n × n).          */
/*                                                                                              */
/* Override here only if you have an unusual workload that needs more headroom than the         */
/* derivation provides (e.g. an out-of-tree consumer of ssfbn that uses a wider modulus). To    */
/* override, define SSF_BN_CONFIG_MAX_BITS to a multiple of 32 (the limb width).                */
/*                                                                                              */
/* Example: force 8192 even on an ECC-only build.                                                */
/*   #define SSF_BN_CONFIG_MAX_BITS               (8192u)                                       */

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_OPT_H_INCLUDE */
