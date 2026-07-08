/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfini configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_INI_OPT_H_INCLUDE
#define SSF_INI_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum length in bytes (excluding the NULL terminator) of an INI string the parser will      */
/* accept. This bounds how far the parser scans: an INI whose NULL terminator is not found within */
/* this many bytes is rejected (lookups return false / SSFINIGObjCreate returns false), capping   */
/* the read even if the caller's buffer is not NULL terminated. Tune to the largest INI expected. */
#define SSF_INI_CONFIG_MAX_IN_LEN (2047u)

/* 1 to enable INI to/from gobj conversion interface, else 0. */
#define SSF_INI_GOBJ_ENABLE (1u)

/* Define the maximum string size for section names, key names, and values during INI to gobj    */
/* conversion.                                                                                   */
#define SSF_INI_GOBJ_CONFIG_MAX_STR_SIZE (256u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_INI_OPT_H_INCLUDE */
