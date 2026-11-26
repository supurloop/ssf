/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- _crypto-wide configuration profile; see ssfcrypt.md                 */
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

/* Profile-driven defaults; each #ifndef guard lets an individual override win */

#if SSF_CRYPT_CONFIG_PROFILE == SSF_CRYPT_PROFILE_MIN_MEMORY

/* Drop the comb tables. SSFECScalarMulDualBase auto-falls-back to the Shamir's-trick path. */
#ifndef SSF_EC_CONFIG_FIXED_BASE_P256
#define SSF_EC_CONFIG_FIXED_BASE_P256        (0u)
#endif
#ifndef SSF_EC_CONFIG_FIXED_BASE_P384
#define SSF_EC_CONFIG_FIXED_BASE_P384        (0u)
#endif

/* Drop SSFECDSASign and the DER-encode helper so a verify-only build can omit ssfasn1 */
#ifndef SSF_ECDSA_CONFIG_ENABLE_SIGN
#define SSF_ECDSA_CONFIG_ENABLE_SIGN         (0u)
#endif

/* 3-bit ModExp window: an 8-entry table instead of 16 */
#ifndef SSF_BN_MODEXP_WIN_K
#define SSF_BN_MODEXP_WIN_K                  (3u)
#endif

#elif SSF_CRYPT_CONFIG_PROFILE == SSF_CRYPT_PROFILE_MAX_PERF

/* Karatsuba dispatch sooner -- wins for RSA-2048+ multiplies. */
#ifndef SSF_BN_KARATSUBA_THRESHOLD
#define SSF_BN_KARATSUBA_THRESHOLD           (16u)
#endif

/* 5-bit ModExp window: a 32-entry table instead of 16 */
#ifndef SSF_BN_MODEXP_WIN_K
#define SSF_BN_MODEXP_WIN_K                  (5u)
#endif

#endif /* CUSTOM sets no defaults; per-module opt files pick their own */

#ifdef __cplusplus
}
#endif

#endif /* SSF_CRYPT_OPT_H_INCLUDE */
