/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfnetws configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_NETWS_OPT_H_INCLUDE
#define SSF_NETWS_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Host names passed to open(), including the NUL terminator. 2..256. A longer host makes open() */
/* return false.                                                                                 */
#ifndef SSF_NETWS_CONFIG_MAX_HOST_SIZE
#define SSF_NETWS_CONFIG_MAX_HOST_SIZE          (256u)
#endif

/* Handshake buffer: holds the HTTP Upgrade request (path and extra fields included), then the   */
/* server's response head, then serves as the receive staging buffer once the connection is      */
/* open. A request that does not fit makes open() return false; a response head that does not    */
/* fit fails the handshake. 256..65535.                                                          */
#ifndef SSF_NETWS_CONFIG_HS_BUF_SIZE
#define SSF_NETWS_CONFIG_HS_BUF_SIZE            (1024u)
#endif

/* Largest payload of one outbound frame. Each send() call frames at most this many bytes; a     */
/* larger write is split across calls. Frame overhead is 6 bytes up to 125, else 8. 1..65535.    */
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
