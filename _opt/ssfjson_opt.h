/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfjson configuration                                                 */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_JSON_OPT_H_INCLUDE
#define SSF_JSON_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Define the maximum parse depth, each opening { or [ starts a new depth level. */
#define SSF_JSON_CONFIG_MAX_IN_DEPTH (4u)

/* Define the maximum JSON string length to be parsed. */
#define SSF_JSON_CONFIG_MAX_IN_LEN  (2047u)

/* Allow parser to use floating point to convert numbers. */
#define SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE (0u)

/* Allow generator to print floats. */
#define SSF_JSON_CONFIG_ENABLE_FLOAT_GEN (1u)

/* 1 to enable JSON to/from gobj conversion interface, else 0. */
#define SSF_JSON_GOBJ_ENABLE (1u)

/* Define the maximum string size for object keys and string values during JSON to gobj          */
/* conversion.                                                                                   */
#define SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE (256u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_JSON_OPT_H_INCLUDE */
