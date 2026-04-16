/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfrsa configuration                                                  */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_RSA_OPT_H_INCLUDE
#define SSF_RSA_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssfrsa features */
#define SSF_RSA_CONFIG_ENABLE_KEYGEN         (1u)
#define SSF_RSA_CONFIG_ENABLE_PKCS1_V15      (1u)
#define SSF_RSA_CONFIG_ENABLE_PSS            (1u)
#define SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS   (5u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_RSA_OPT_H_INCLUDE */
