/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssftlsc configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_TLSC_OPT_H_INCLUDE
#define SSF_TLSC_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 compiles in SSFTLSCSetUnauthenticated(), 0 compiles it out; defaults to 1 only for unit test */
#ifndef SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
#define SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED (1u)
#else
#define SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED (0u)
#endif
#endif

/* Largest record plaintext received in bytes, advertised as record_size_limit, 64..16384 */
#ifndef SSF_TLSC_CONFIG_MAX_RECV_RECORD
#define SSF_TLSC_CONFIG_MAX_RECV_RECORD (16384u)
#endif

/* Largest record plaintext sent in bytes, 768..16384 */
#ifndef SSF_TLSC_CONFIG_MAX_SEND_RECORD
#define SSF_TLSC_CONFIG_MAX_SEND_RECORD (8192u)
#endif

#if (SSF_TLSC_CONFIG_MAX_RECV_RECORD < 64u) || (SSF_TLSC_CONFIG_MAX_RECV_RECORD > 16384u)
#error SSF_TLSC_CONFIG_MAX_RECV_RECORD must be 64..16384.
#endif
#if (SSF_TLSC_CONFIG_MAX_SEND_RECORD < 768u) || (SSF_TLSC_CONFIG_MAX_SEND_RECORD > 16384u)
#error SSF_TLSC_CONFIG_MAX_SEND_RECORD must be 768..16384.
#endif

/* Records sent under one application traffic key before a KeyUpdate, 1..2^24 */
#ifndef SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS
#define SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS (16777216ul)
#endif
#if (SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS < 1u) || (SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS > 16777216ul)
#error SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS must be 1..2^24.
#endif

/* Earliest Unix time in seconds trusted for certificate validity, default 2025-01-01T00:00:00Z */
#ifndef SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC
#define SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC (1735689600ull)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLSC_OPT_H_INCLUDE */
