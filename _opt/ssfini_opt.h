/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfini configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_INI_OPT_H_INCLUDE
#define SSF_INI_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 to enable INI to/from gobj conversion interface, else 0. */
#define SSF_INI_GOBJ_ENABLE (1u)

/* Define the maximum string size for section names, key names, and values during INI to gobj    */
/* conversion.                                                                                   */
#define SSF_INI_GOBJ_CONFIG_MAX_STR_SIZE (256u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_INI_OPT_H_INCLUDE */
