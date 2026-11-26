/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfrsa configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_RSA_OPT_H_INCLUDE
#define SSF_RSA_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssfrsa key sizes -- at least one must be 1u. Each size requires SSF_BN_CONFIG_MAX_BITS to be  */
/* at least twice the modulus width (the CRT recombine and ModInvExt over lambda(n) run a 2N-limb*/
/* product through SSFBNMul). Disabling unused sizes shrinks the public-key validator's accepted */
/* set and lets the linker drop unused KeyGen retry-budget code on size-restricted builds.       */
#define SSF_RSA_CONFIG_ENABLE_2048           (1u)
#define SSF_RSA_CONFIG_ENABLE_3072           (1u)
#define SSF_RSA_CONFIG_ENABLE_4096           (1u)

/* ssfrsa features */
#define SSF_RSA_CONFIG_ENABLE_KEYGEN         (1u)
#define SSF_RSA_CONFIG_ENABLE_PKCS1_V15      (1u)
#define SSF_RSA_CONFIG_ENABLE_PSS            (1u)
#define SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS   (5u)

/* Bytes added to the stack scrub at the end of each sign / keygen entry point. The            */
/* scrub is sized to the stack the ssfbn calls below the entry point use, as measured with      */
/* Cortex-M4 GCC -Os; other compilers and flags can use a little more (M4 -O2: 64-80 B, M0+    */
/* -Os: 96-112 B), so set 128u there to scrub it all, at the cost of that much more peak stack. */
#ifndef SSF_RSA_CONFIG_STACK_SCRUB_MARGIN
#define SSF_RSA_CONFIG_STACK_SCRUB_MARGIN    (0u)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_RSA_OPT_H_INCLUDE */
