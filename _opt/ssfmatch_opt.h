/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfmatch configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_MATCH_OPT_H_INCLUDE
#define SSF_MATCH_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of '*' wildcards (a run of consecutive '*' counts as one) allowed in a glob    */
/* pattern. Patterns with more never match. Bounds glob worst-case time and recursion depth.      */
#define SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS  (4u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_MATCH_OPT_H_INCLUDE */
