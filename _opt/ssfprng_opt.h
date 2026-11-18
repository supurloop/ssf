/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfprng configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_PRNG_OPT_H_INCLUDE
#define SSF_PRNG_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Requested PRNG AES key size in bits: 128 or 256. This is a minimum, not a cap: ssfprng.h   */
/* forces 256 whenever SSF_EC_CONFIG_ENABLE_P384 or SSF_RSA_CONFIG_ENABLE_4096 is 1, because   */
/* key generation for those sizes needs more than 128 bits of seed entropy. The effective     */
/* size is SSF_PRNG_KEY_BITS and the seed size is SSF_PRNG_ENTROPY_SIZE (16 or 32 bytes).      */
#define SSF_PRNG_CONFIG_KEY_BITS (128u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_PRNG_OPT_H_INCLUDE */
