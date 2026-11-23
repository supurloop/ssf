/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfed25519 configuration                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_ED25519_OPT_H_INCLUDE
#define SSF_ED25519_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 scrubs secret residue from the stack after Sign, 0 skips it (see ssfed25519.md) */
#define SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB (1u)

/* Bytes the scrub zeroes; must cover Sign's secret call chain (see ssfed25519.md) */
#define SSF_ED25519_CONFIG_STACK_SCRUB_SIZE   (1536u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_ED25519_OPT_H_INCLUDE */
