/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfnetsock configuration                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_NETSOCK_OPT_H_INCLUDE
#define SSF_NETSOCK_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Max host string size passed to open(), including the NUL terminator, 2..256 */
#define SSF_NETSOCK_CONFIG_MAX_HOST_SIZE        (256u)

/* Max resolved addresses kept per open() and tried in order, 1..255 */
#define SSF_NETSOCK_CONFIG_MAX_ADDRS            (4u)

/* Max name lookups in progress at once across all instances, 1..255 */
#define SSF_NETSOCK_CONFIG_MAX_LOOKUPS          (2u)

/* Max bytes close() reads and discards before closing a connected socket, 0 disables */
#define SSF_NETSOCK_CONFIG_CLOSE_DRAIN_MAX      (65536u)

#if (SSF_NETSOCK_CONFIG_MAX_HOST_SIZE < 2) || (SSF_NETSOCK_CONFIG_MAX_HOST_SIZE > 256)
#error SSF_NETSOCK_CONFIG_MAX_HOST_SIZE must be 2..256.
#endif
#if (SSF_NETSOCK_CONFIG_MAX_ADDRS < 1) || (SSF_NETSOCK_CONFIG_MAX_ADDRS > 255)
#error SSF_NETSOCK_CONFIG_MAX_ADDRS must be 1..255.
#endif
#if (SSF_NETSOCK_CONFIG_MAX_LOOKUPS < 1) || (SSF_NETSOCK_CONFIG_MAX_LOOKUPS > 255)
#error SSF_NETSOCK_CONFIG_MAX_LOOKUPS must be 1..255.
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_NETSOCK_OPT_H_INCLUDE */
