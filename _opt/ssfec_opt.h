/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfec configuration                                                 */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_EC_OPT_H_INCLUDE
#define SSF_EC_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssfec curves enabled */
#define SSF_EC_CONFIG_ENABLE_P256            (1u)
#define SSF_EC_CONFIG_ENABLE_P384            (1u)

/* ssfec fixed-base scalar-mul tables. Default to whichever of ENABLE_P256 / ENABLE_P384 is on  */
/* -- the comb table is useless without the curve and SSFECScalarMulBaseP{256,384} would deref */
/* a NULL curve-params struct at runtime if the curve were disabled. Override either flag to 0 */
/* to skip the comb table (saves ~1.5 KB P-256 / ~2.3 KB P-384 of rodata; ~3-4x slower keygen  */
/* / sign / fixed-base verify). Setting to 1 for a disabled curve is a compile error.          */
#ifndef SSF_EC_CONFIG_FIXED_BASE_P256
#define SSF_EC_CONFIG_FIXED_BASE_P256        SSF_EC_CONFIG_ENABLE_P256
#endif
#ifndef SSF_EC_CONFIG_FIXED_BASE_P384
#define SSF_EC_CONFIG_FIXED_BASE_P384        SSF_EC_CONFIG_ENABLE_P384
#endif

/* SSF_EC_FIXED_BASE_COMB_H -- fixed-base Lim-Lee comb window size for SSFECScalarMulBaseP256/ */
/* P384. Larger h shrinks the per-call iteration count from d=ceil(n/h) to d=ceil(n/h+1) at   */
/* the cost of a 2x-larger precomputed table in .rodata. RAM/stack and .text are unchanged.   */
/*                                                                                            */
/*   4 -- minimal Flash, slowest. Tables ~2.6 KB total.       Baseline.                       */
/*   5 -- balanced.            Tables ~5.6 KB total (+~3 KB).  ~15-17% faster [k]G.           */
/*   6 -- maximum perf.        Tables ~12.0 KB total (+~9 KB). ~22-25% faster [k]G.           */
/*                                                                                            */
/* Affects: SSFECScalarMulBaseP256, SSFECScalarMulBaseP384, SSFECScalarMulDualBase, ECDSA     */
/* KeyGen and Sign (which use the comb internally). Verify is mostly variable-base so gain   */
/* there is smaller. Only one setting compiles in.                                            */
#ifndef SSF_EC_FIXED_BASE_COMB_H
#define SSF_EC_FIXED_BASE_COMB_H             (6u)
#endif

/* Compile-time validation: a fixed-base table for a disabled curve would link to absent       */
/* curve constants and segfault at first use. Trap the misconfiguration up-front instead.      */
#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) && (SSF_EC_CONFIG_ENABLE_P256 == 0)
#error SSF_EC_CONFIG_FIXED_BASE_P256 requires SSF_EC_CONFIG_ENABLE_P256 to be 1.
#endif
#if (SSF_EC_CONFIG_FIXED_BASE_P384 == 1) && (SSF_EC_CONFIG_ENABLE_P384 == 0)
#error SSF_EC_CONFIG_FIXED_BASE_P384 requires SSF_EC_CONFIG_ENABLE_P384 to be 1.
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_EC_OPT_H_INCLUDE */
