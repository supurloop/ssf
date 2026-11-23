/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfprng configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_PRNG_OPT_H_INCLUDE
#define SSF_PRNG_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Minimum PRNG key bits, 128 or 256; P-384 / RSA-4096 force 256 (see ssfprng.md) */
#define SSF_PRNG_CONFIG_KEY_BITS (128u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_PRNG_OPT_H_INCLUDE */
