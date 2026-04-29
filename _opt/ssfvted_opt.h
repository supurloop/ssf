/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfvted configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_VTED_OPT_H_INCLUDE
#define SSF_VTED_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Define the line ending style */
#define SSF_VTED_LINE_ENDING "\r\n"
#define SSF_VTED_LINE_ENDING_SIZE (sizeof(SSF_VTED_LINE_ENDING_SIZE) - 1)

/* Define the prompt for the VT100 line editor. Leading "\r\n" guarantees the prompt starts on  */
/* a fresh line. Length is computed at compile time via sizeof - 1.                             */
#define SSF_VTED_PROMPT_BASE_STR "# "
#define SSF_VTED_PROMPT_BASE_STR_SIZE (sizeof(SSF_VTED_PROMPT_BASE_STR) - 1)
#define SSF_VTED_PROMPT_STR SSF_VTED_LINE_ENDING SSF_VTED_PROMPT_BASE_STR
#define SSF_VTED_PROMPT_STR_SIZE (sizeof(SSF_VTED_PROMPT_STR) - 1)

#ifdef __cplusplus
}
#endif

#endif /* SSF_VTED_OPT_H_INCLUDE */
