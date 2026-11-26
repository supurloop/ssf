/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfbn configuration                                                 */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_BN_OPT_H_INCLUDE
#define SSF_BN_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* SSF_BN_CONFIG_MAX_BITS and SSF_BN_MAX_MOD_LIMBS are auto-derived in ssfbn.h; see ssfbn.md */

/* SSFBNMul limb count at or above which Karatsuba is used, must be >= 4 */
#ifndef SSF_BN_KARATSUBA_THRESHOLD
#define SSF_BN_KARATSUBA_THRESHOLD           (32u)
#endif

/* SSFBNModExp fixed-window size in bits, 1 to 8 */
#ifndef SSF_BN_MODEXP_WIN_K
#define SSF_BN_MODEXP_WIN_K                  (4u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_OPT_H_INCLUDE */
