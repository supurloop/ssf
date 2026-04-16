/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfubjson configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_UBJSON_OPT_H_INCLUDE
#define SSF_UBJSON_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Define the maximum parse depth, each opening { or [ starts a new depth level. */
#define SSF_UBJSON_CONFIG_MAX_IN_DEPTH (4u)

/* Define the maximum JSON string length to be parsed. */
#define SSF_UBJSON_CONFIG_MAX_IN_LEN  (2047u)

#define SSF_UBJSON_TYPEDEF_STRUCT typedef struct /* Optionally add packed struct attribute here */

/* Allow parser to return HPN type as a string instead of considering parse invalid. */
#define SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING (1u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_UBJSON_OPT_H_INCLUDE */
