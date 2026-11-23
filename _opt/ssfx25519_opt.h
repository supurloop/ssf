/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfx25519 configuration                                             */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_X25519_OPT_H_INCLUDE
#define SSF_X25519_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssfx25519 enabled */
#define SSF_X25519_CONFIG_ENABLE             (1u)

/* 1 scrubs ladder residue from the stack after each call, 0 skips it (ssfx25519.md) */
#define SSF_X25519_CONFIG_ENABLE_STACK_SCRUB (1u)

/* Bytes the scrub zeroes; must cover the ladder call chain (see ssfx25519.md) */
#define SSF_X25519_CONFIG_STACK_SCRUB_SIZE   (1536u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_X25519_OPT_H_INCLUDE */
