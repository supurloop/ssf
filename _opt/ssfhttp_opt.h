/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- HTTP (ssfhttphdr and its users) configuration                       */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_HTTP_OPT_H_INCLUDE
#define SSF_HTTP_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum fields a parsed response head may hold, 1..255 */
#ifndef SSF_HTTP_CONFIG_MAX_FIELDS
#define SSF_HTTP_CONFIG_MAX_FIELDS              (24u)
#endif

#if (SSF_HTTP_CONFIG_MAX_FIELDS < 1) || (SSF_HTTP_CONFIG_MAX_FIELDS > 255)
#error SSF_HTTP_CONFIG_MAX_FIELDS must be 1..255.
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_HTTP_OPT_H_INCLUDE */
