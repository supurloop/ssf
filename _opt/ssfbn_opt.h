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

/* SSFBNMul Karatsuba dispatch threshold (limbs). Operands at or above this — same length, even */
/* length — go through one-level Karatsuba; below it, schoolbook. Both code paths always link;  */
/* the threshold only steers the runtime dispatch. Default is 32 (RSA-1024 boundary); the       */
/* MAX_PERF profile lowers this to 16 so RSA-2048 multiplies enter Karatsuba sooner.            */
#ifndef SSF_BN_KARATSUBA_THRESHOLD
#define SSF_BN_KARATSUBA_THRESHOLD           (32u)
#endif

/* SSFBNModExp fixed-window size in bits. The constant-time Montgomery exponentiation          */
/* precomputes a 2^k entry table of Montgomery powers, then squares-and-multiplies through the  */
/* exponent in k-bit windows.                                                                    */
/*                                                                                              */
/* Currently WIN_K must DIVIDE SSF_BN_LIMB_BITS (32): valid values are 1, 2, 4, 8, 16, 32.      */
/* The windowing computes nWindows = expLen * 32 / WIN_K; non-divisor values silently truncate  */
/* the iteration count and corrupt results (visible downstream through SSFBNModInv → Fermat →   */
/* SSFECPointToAffine). The default 4 (16-entry table) is the practical sweet spot. Larger k    */
/* means fewer MontMuls per bit at the cost of a 2x-larger stack-resident table per call.       */
#ifndef SSF_BN_MODEXP_WIN_K
#define SSF_BN_MODEXP_WIN_K                  (4u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_OPT_H_INCLUDE */
