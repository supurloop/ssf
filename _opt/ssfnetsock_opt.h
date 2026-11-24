/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfnetsock configuration                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_NETSOCK_OPT_H_INCLUDE
#define SSF_NETSOCK_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Host names passed to open(), including the NUL terminator. 2..256. A DNS name is at most 253  */
/* characters; a longer host makes open() return false.                                          */
#define SSF_NETSOCK_CONFIG_MAX_HOST_SIZE        (256u)

/* Resolved addresses kept per open(). Connect attempts walk them in order, moving to the next   */
/* when one fails. 1..255. Addresses beyond this are ignored.                                    */
#define SSF_NETSOCK_CONFIG_MAX_ADDRS            (4u)

/* Name lookups that may be in progress at once across all instances, including lookups still    */
/* finishing after close() abandoned them because the OS could not cancel them. When all are in  */
/* use, open() of a host name returns false. 1..255.                                             */
#define SSF_NETSOCK_CONFIG_MAX_LOOKUPS          (2u)

/* Bytes close() reads and discards, without blocking, before closing a connected socket. A     */
/* socket closed with received data unread is reset (RST) rather than closed (FIN), and the     */
/* peer may then drop the last bytes sent, such as a TLS alert. 0 disables the drain.          */
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
