/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfbase64url configuration                                          */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_BASE64URL_OPT_H_INCLUDE
#define SSF_BASE64URL_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Size in bytes of the on-stack scratch buffer SSFBase64URLDecode uses to re-pad input before   */
/* handing it to the standard Base64 decoder. Bounds the longest decodable Base64URL string to   */
/* SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 5 characters; longer inputs return false. Must be >= 8. */
#define SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN (1024u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_BASE64URL_OPT_H_INCLUDE */
