/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssftls configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_TLS_OPT_H_INCLUDE
#define SSF_TLS_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssftls capacities */
#define SSF_TLS_CONFIG_MAX_TRUSTED_CAS       (8u)
#define SSF_TLS_CONFIG_PSK_ENABLE            (1u)
#define SSF_TLS_CONFIG_TICKET_LIFETIME_SEC   (3600u)
#define SSF_TLS_CONFIG_MAX_ALPN_LEN          (32u)

/* 1 compiles in the ssfx509 / ssfcms trace messages; see ssftls.md */
#ifndef SSF_TLS_CONFIG_ENABLE_TRACE
#if (SSF_CONFIG_X509_UNIT_TEST == 1) || (SSF_CONFIG_CMS_UNIT_TEST == 1)
#define SSF_TLS_CONFIG_ENABLE_TRACE          (1u)
#else
#define SSF_TLS_CONFIG_ENABLE_TRACE          (0u)
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLS_OPT_H_INCLUDE */
