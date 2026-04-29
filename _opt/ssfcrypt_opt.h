/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — _crypto-wide configuration profile                                    */
/*                                                                                               */
/* Selects defaults for the cross-module performance / memory knobs in ssfbn and ssfec. Each     */
/* per-module opt file (ssfbn_opt.h, ssfec_opt.h) processes its own knobs through #ifndef so any */
/* default this file picks can still be overridden by the user. Three profiles are supported:    */
/*                                                                                               */
/*   SSF_CRYPT_PROFILE_MIN_MEMORY                                                                 */
/*     Smallest flash + RAM. Drops the fixed-base Lim-Lee comb tables (~12 KB rodata at the      */
/*     default COMB_H) and shrinks the ModExp window table (3-bit window, 8 entries instead of   */
/*     16). Cost: [k]G is ~3-4x slower (Montgomery ladder fallback); RSA private ops are ~25 %  */
/*     slower. Suited to verify-only signers on cortex-M0/M3-class targets.                      */
/*                                                                                               */
/*   SSF_CRYPT_PROFILE_CUSTOM (default)                                                           */
/*     Today's defaults. Intended for networked 32-bit MCUs in the ~512 KB-RAM range. Both       */
/*     curves enabled, both fixed-base tables on, COMB_H = 6 (12 KB rodata), 4-bit ModExp        */
/*     window. Reflects a balance: comb tables are paid for in flash, but private-op latency is  */
/*     visible to the user only for RSA-3072+ and the table cost is fixed regardless of usage.   */
/*                                                                                               */
/*   SSF_CRYPT_PROFILE_MAX_PERF                                                                   */
/*     Maximum throughput. Lowers the Karatsuba dispatch threshold so RSA-2048+ multiplies       */
/*     enter Karatsuba sooner; widens the ModExp window to 5 bits (32-entry table) so RSA        */
/*     private ops run roughly 1/2 as many MontMuls per exponent bit. Cost: ModExp's stack-      */
/*     resident table doubles. Suited to host / server builds where RAM and flash are not the    */
/*     constraint.                                                                                */
/*                                                                                               */
/* The compiler's dead-code elimination handles the rest: unreferenced KeyGen / PSS / RSA-3072+ */
/* / unused curve code paths get stripped at link without per-profile flag gating, so the        */
/* profile only touches knobs DCE cannot reach (lookup-table sizes, dispatch thresholds).       */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_CRYPT_OPT_H_INCLUDE
#define SSF_CRYPT_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#define SSF_CRYPT_PROFILE_MIN_MEMORY  (0u)
#define SSF_CRYPT_PROFILE_CUSTOM      (1u)
#define SSF_CRYPT_PROFILE_MAX_PERF    (2u)

#ifndef SSF_CRYPT_CONFIG_PROFILE
#define SSF_CRYPT_CONFIG_PROFILE  SSF_CRYPT_PROFILE_CUSTOM
#endif

#if (SSF_CRYPT_CONFIG_PROFILE != SSF_CRYPT_PROFILE_MIN_MEMORY) && \
    (SSF_CRYPT_CONFIG_PROFILE != SSF_CRYPT_PROFILE_CUSTOM) && \
    (SSF_CRYPT_CONFIG_PROFILE != SSF_CRYPT_PROFILE_MAX_PERF)
#error SSF_CRYPT_CONFIG_PROFILE must be SSF_CRYPT_PROFILE_MIN_MEMORY / CUSTOM / MAX_PERF
#endif

/* --------------------------------------------------------------------------------------------- */
/* Profile-driven defaults. Each #ifndef guard means the user can still override any individual  */
/* knob from the command line or from a project-local opt file processed before this one.        */
/* --------------------------------------------------------------------------------------------- */

#if SSF_CRYPT_CONFIG_PROFILE == SSF_CRYPT_PROFILE_MIN_MEMORY

/* Drop the comb tables. SSFECScalarMulDualBase auto-falls-back to the Shamir's-trick path. */
#ifndef SSF_EC_CONFIG_FIXED_BASE_P256
#define SSF_EC_CONFIG_FIXED_BASE_P256        (0u)
#endif
#ifndef SSF_EC_CONFIG_FIXED_BASE_P384
#define SSF_EC_CONFIG_FIXED_BASE_P384        (0u)
#endif

/* Drop SSFECDSASign and the DER-encode helper. The verify path is now ssfasn1-free, so a    */
/* MIN_MEMORY build with this default can omit the entire ssfasn1 module. Targets that need  */
/* on-device signing (rare for MIN_MEMORY — typical use case is firmware-update verifiers)   */
/* override this back to 1.                                                                  */
#ifndef SSF_ECDSA_CONFIG_ENABLE_SIGN
#define SSF_ECDSA_CONFIG_ENABLE_SIGN         (0u)
#endif

#elif SSF_CRYPT_CONFIG_PROFILE == SSF_CRYPT_PROFILE_MAX_PERF

/* Karatsuba dispatch sooner — wins for RSA-2048+ multiplies. */
#ifndef SSF_BN_KARATSUBA_THRESHOLD
#define SSF_BN_KARATSUBA_THRESHOLD           (16u)
#endif

#endif /* CUSTOM picks no profile-set defaults — per-module opts pick their own. */

/* SSF_BN_MODEXP_WIN_K is intentionally NOT profile-controlled: the windowed Montgomery        */
/* exponentiation in SSFBNModExpMont assumes the window size cleanly divides SSF_BN_LIMB_BITS  */
/* (32) when computing nWindows = expLen * 32 / WIN_K. Setting WIN_K to a non-divisor (3, 5,   */
/* 6, 7) silently truncates the iteration count and corrupts results — most visibly through    */
/* SSFBNModInv (Fermat) and downstream SSFECPointToAffine. Keep WIN_K = 4 until ModExp is      */
/* generalised to handle a partial top window.                                                  */

#ifdef __cplusplus
}
#endif

#endif /* SSF_CRYPT_OPT_H_INCLUDE */
