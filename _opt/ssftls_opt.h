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

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLS_OPT_H_INCLUDE */
