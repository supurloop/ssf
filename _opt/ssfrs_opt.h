/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfrs Reed-Solomon configuration                                      */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_RS_OPT_H_INCLUDE
#define SSF_RS_OPT_H_INCLUDE

#include "ssfport.h"        /* SSF_CONFIG_RS_UNIT_TEST */

#ifdef __cplusplus
extern "C" {
#endif

/* 1 to enable Reed-Solomon encoding interface, else 0. */
#define SSF_RS_ENABLE_ENCODING (1u)

/* 1 to enable Reed-Solomon decoding interface, else 0. */
#define SSF_RS_ENABLE_DECODING (1u)

/* Determine if we can run unit test */
#if SSF_CONFIG_RS_UNIT_TEST == 1
#if SSF_RS_ENABLE_ENCODING != 1 || SSF_RS_ENABLE_DECODING != 1
#undef SSF_CONFIG_RS_UNIT_TEST
#define SSF_CONFIG_RS_UNIT_TEST (0u)
#endif
#endif

/* The maximum total size in bytes of a message to be encoded or decoded */
#define SSF_RS_MAX_MESSAGE_SIZE (1024)
#if SSF_RS_MAX_MESSAGE_SIZE > 2048
#error SSFRS invalid SSF_RS_MAX_MESSAGE_SIZE.
#endif

/* The maximum number of bytes that will be encoded with up to SSF_RS_MAX_SYMBOLS bytes */
#define SSF_RS_MAX_CHUNK_SIZE (127u)
#if SSF_RS_MAX_CHUNK_SIZE > 253
#error SSFRS invalid SSF_RS_MAX_CHUNK_SIZE.
#endif

/* The maximum number of chunks that a message will be broken up into for encoding and decoding */
#if SSF_RS_MAX_MESSAGE_SIZE % SSF_RS_MAX_CHUNK_SIZE == 0
#define SSF_RS_MAX_CHUNKS (SSF_RS_MAX_MESSAGE_SIZE / SSF_RS_MAX_CHUNK_SIZE)
#else
#define SSF_RS_MAX_CHUNKS ((SSF_RS_MAX_MESSAGE_SIZE / SSF_RS_MAX_CHUNK_SIZE) + 1)
#endif

/* The maximum number of symbols in bytes that will encode up to SSF_RS_MAX_CHUNK_SIZE bytes */
/* Reed-Solomon can correct SSF_RS_MAX_SYMBOLS/2 bytes with errors in a message */
#define SSF_RS_MAX_SYMBOLS (8ul)
#if (SSF_RS_MAX_SYMBOLS < 2) || (SSF_RS_MAX_SYMBOLS > 254) || ((SSF_RS_MAX_SYMBOLS & 0x01) != 0)
#error SSFRS Invalid SSF_RS_MAX_SYMBOLS.
#endif

/* For now we are limiting the total of chunk bytes and symbols to 254 max */
#if SSF_RS_MAX_CHUNK_SIZE + SSF_RS_MAX_SYMBOLS > 254
#error SSFRS total of SSF_RS_MAX_CHUNK_SIZE + SSF_RS_MAX_SYMBOLS not supported.
#endif

/* For now we are limiting the total encoded msg + ecc to 61440 (60KiB) */
#if (SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS) + SSF_RS_MAX_MESSAGE_SIZE > 61440ul
#error SSFRS total of SSF_RS_MAX_CHUNK_SIZE + SSF_RS_MAX_SYMBOLS not supported.
#endif

/* 1 to enable GF_MUL optimization, else 0 to reduce code space. */
#define SSF_RS_ENABLE_GF_MUL_OPT (1u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_RS_OPT_H_INCLUDE */
