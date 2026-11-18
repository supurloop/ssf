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

/* 1 to zero a deep stack region after each scalar multiply so ladder residue derived from the */
/* private key does not survive in freed frames; 0 to skip the scrub (no extra stack or time). */
#define SSF_X25519_CONFIG_ENABLE_STACK_SCRUB (1u)

/* Bytes zeroed by the scrub. Must cover the deepest call chain below the public entry points */
/* (measured 0.8-1.2 KB with gcc -O0..-O3 on x86-64); 1536 leaves margin for other compilers.  */
#define SSF_X25519_CONFIG_STACK_SCRUB_SIZE   (1536u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_X25519_OPT_H_INCLUDE */
