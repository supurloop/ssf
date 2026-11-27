/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfjson configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_JSON_OPT_H_INCLUDE
#define SSF_JSON_OPT_H_INCLUDE

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Define the maximum parse depth, each opening { or [ starts a new depth level; 1..254. */
#ifndef SSF_JSON_CONFIG_MAX_IN_DEPTH
#define SSF_JSON_CONFIG_MAX_IN_DEPTH (4u)
#endif
#if (SSF_JSON_CONFIG_MAX_IN_DEPTH < 1u) || (SSF_JSON_CONFIG_MAX_IN_DEPTH > 254u)
#error SSF_JSON_CONFIG_MAX_IN_DEPTH must be 1..254.
#endif

/* Define the maximum JSON string length to be parsed in bytes; 1..SIZE_MAX / 2, <= 2^31 - 1. */
#ifndef SSF_JSON_CONFIG_MAX_IN_LEN
#define SSF_JSON_CONFIG_MAX_IN_LEN  (2047u)
#endif
#if (SSF_JSON_CONFIG_MAX_IN_LEN < 1u) || (SSF_JSON_CONFIG_MAX_IN_LEN > (SIZE_MAX / 2u)) || \
    (SSF_JSON_CONFIG_MAX_IN_LEN > 0x7FFFFFFFul)
#error SSF_JSON_CONFIG_MAX_IN_LEN must be 1..SIZE_MAX / 2 and at most 2^31 - 1.
#endif

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
