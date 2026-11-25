/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfbn configuration                                                 */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_BN_OPT_H_INCLUDE
#define SSF_BN_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssfbn maximum bignum width in bits.                                                          */
/*                                                                                              */
/* By default this is auto-derived in ssfbn.h from the enabled algorithm flags                  */
/* (SSF_EC_CONFIG_ENABLE_P256/P384, SSF_RSA_CONFIG_ENABLE_2048/3072/4096) -- pick the largest   */
/* enabled operand width x 2, since RSA keygen, CRT recombine, ModInvExt over lambda(n), and ECC's*/
/* SSFBNModMulNIST all run intermediate products at up to 2*N bits (full-width n x n).          */
/*                                                                                              */
/* Override here only if you have an unusual workload that needs more headroom than the         */
/* derivation provides (e.g. an out-of-tree consumer of ssfbn that uses a wider modulus). To    */
/* override, define SSF_BN_CONFIG_MAX_BITS to a multiple of 32 (the limb width).                */
/*                                                                                              */
/* Example: force 8192 even on an ECC-only build.                                                */
/*   #define SSF_BN_CONFIG_MAX_BITS               (8192u)                                       */

/* ssfbn maximum modulus limb count.                                                             */
/*                                                                                               */
/* By default this is auto-derived in ssfbn.h as (SSF_BN_MAX_LIMBS + 1) / 2, which is exactly    */
/* the largest possible modulus for any auto-derived configuration (the 2N derivation of         */
/* SSF_BN_CONFIG_MAX_BITS makes MAX_LIMBS / 2 the modulus ceiling). Sized this way to keep        */
/* SSFBNModExpMont's stack frame compact. See ssfbn.md "Configuration" for the full rationale.   */
/*                                                                                               */
/* Override only when pinning SSF_BN_CONFIG_MAX_BITS to a non-2N value. Per-algorithm static     */
/* asserts in ssfbn.h plus a runtime SSF_REQUIRE in SSFBNModExpMont catch a too-small override. */
/*                                                                                               */
/* Example: out-of-tree consumer with a 1024-bit modulus (no algorithm flags enabled).           */
/*   #define SSF_BN_CONFIG_MAX_BITS               (1024u)                                       */
/*   #define SSF_BN_MAX_MOD_LIMBS                 (32u)                                          */

/* SSFBNMul Karatsuba dispatch threshold (limbs). Operands at or above this -- same length, even */
/* length -- go through one-level Karatsuba; below it, schoolbook. Both code paths always link; */
/* the threshold only steers the runtime dispatch. Default is 32 (RSA-1024 boundary); the       */
/* MAX_PERF profile lowers this to 16 so RSA-2048 multiplies enter Karatsuba sooner. Must be  */
/* >= 4: ssfbn.c rejects smaller values at compile time (the step-7 add needs n >= 4).          */
#ifndef SSF_BN_KARATSUBA_THRESHOLD
#define SSF_BN_KARATSUBA_THRESHOLD           (32u)
#endif

/* SSFBNModExp fixed-window size in bits, 1 to 8 (ssfbn.c rejects others). The constant-time     */
/* Montgomery exponentiation precomputes a 2^k-entry table of Montgomery powers, then squares    */
/* and multiplies through the exponent in k-bit windows; any k works (the top window may be      */
/* partial, SAFE-03). Each step of k halves or doubles the stack-resident table. Measured, RSA   */
/* at the 4096 cap (Cortex-M4 -Os stack; host -O2 time, RSA-2048 / 4096 sign):                   */
/*   k = 3: keygen peak -4.2 KB, sign peak -1.1 KB, sign +5% (SSF_CRYPT_PROFILE_MIN_MEMORY)      */
/*   k = 4: the default (CUSTOM)                                                                 */
/*   k = 5: keygen peak +8.3 KB, sign peak +4.2 KB, sign 0 to -3% (SSF_CRYPT_PROFILE_MAX_PERF)   */
/*   k = 2: keygen peak -6.2 KB, sign peak -1.1 KB, sign +16 to +19%                             */
#ifndef SSF_BN_MODEXP_WIN_K
#define SSF_BN_MODEXP_WIN_K                  (4u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_OPT_H_INCLUDE */
