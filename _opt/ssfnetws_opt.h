/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfnetws configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_NETWS_OPT_H_INCLUDE
#define SSF_NETWS_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum host name size passed to open(), including the NUL terminator, 2..256 */
#ifndef SSF_NETWS_CONFIG_MAX_HOST_SIZE
#define SSF_NETWS_CONFIG_MAX_HOST_SIZE          (256u)
#endif

/* Handshake and receive staging buffer size, 256..65535; see ssfnetws.md */
#ifndef SSF_NETWS_CONFIG_HS_BUF_SIZE
#define SSF_NETWS_CONFIG_HS_BUF_SIZE            (1024u)
#endif

/* Largest payload of one outbound frame, 1..65535 */
#ifndef SSF_NETWS_CONFIG_TX_FRAME_SIZE
#define SSF_NETWS_CONFIG_TX_FRAME_SIZE          (256u)
#endif

#if (SSF_NETWS_CONFIG_MAX_HOST_SIZE < 2) || (SSF_NETWS_CONFIG_MAX_HOST_SIZE > 256)
#error SSF_NETWS_CONFIG_MAX_HOST_SIZE must be 2..256.
#endif
#if (SSF_NETWS_CONFIG_HS_BUF_SIZE < 256) || (SSF_NETWS_CONFIG_HS_BUF_SIZE > 65535)
#error SSF_NETWS_CONFIG_HS_BUF_SIZE must be 256..65535.
#endif
#if (SSF_NETWS_CONFIG_TX_FRAME_SIZE < 1) || (SSF_NETWS_CONFIG_TX_FRAME_SIZE > 65535)
#error SSF_NETWS_CONFIG_TX_FRAME_SIZE must be 1..65535.
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_NETWS_OPT_H_INCLUDE */
