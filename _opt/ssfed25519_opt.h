/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfed25519 configuration                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_ED25519_OPT_H_INCLUDE
#define SSF_ED25519_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 to zero a deep stack region at the end of SSFEd25519Sign so scalar-multiply residue        */
/* derived from the secret scalar does not survive in freed frames; 0 to skip the scrub.        */
#define SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB (1u)

/* Bytes zeroed by the scrub. Must cover the deepest secret-bearing call chain below Sign      */
/* (measured 0.8-1.2 KB with gcc -O0..-O3 on x86-64); 1536 leaves margin for other compilers.  */
#define SSF_ED25519_CONFIG_STACK_SCRUB_SIZE   (1536u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_ED25519_OPT_H_INCLUDE */
