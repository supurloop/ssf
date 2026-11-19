/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssftls configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_TLS_OPT_H_INCLUDE
#define SSF_TLS_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* ssftls capacities */
#define SSF_TLS_CONFIG_MAX_RECORD_SIZE       (8192u)
#define SSF_TLS_CONFIG_MAX_CHAIN_DEPTH       (4u)
#define SSF_TLS_CONFIG_MAX_TRUSTED_CAS       (8u)
#define SSF_TLS_CONFIG_PSK_ENABLE            (1u)
#define SSF_TLS_CONFIG_TICKET_LIFETIME_SEC   (3600u)
#define SSF_TLS_CONFIG_MAX_ALPN_LEN          (32u)

/* SSF_TLS_CONFIG_ENABLE_TRACE -- 1 compiles in the ssfx509 / ssfcms diagnostic trace messages  */
/* delivered through SSFX509SetTraceCtx / SSFCMSSetTraceCtx. 0 (default) compiles them out:     */
/* about 5 KB less flash on Cortex-M, no snprintf dependency, and a 256-byte buffer less in    */
/* each tracing function's frame; the SetTraceCtx calls remain but no message is ever sent.    */
/* The x509 and CMS unit tests check trace messages, so their builds default it to 1.          */
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
