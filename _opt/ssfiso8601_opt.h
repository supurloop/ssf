/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfiso8601 configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_ISO8601_OPT_H_INCLUDE
#define SSF_ISO8601_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* A failed conversion to ISO string format will return SSF_ISO8601_ERR_STR in user buffer */
#define SSF_ISO8601_ERR_STR "0000-00-00T00:00:00"

/* 1 == Truncate if the fractional ISO sec precision > system precision; 0 == Fail conversion */
#define SSF_ISO8601_ALLOW_FSEC_TRUNC (1u)

/* 1 == Allow valid ISO string without a zone to convert to "unixSys" time; 0 == Fail conversion */
/* When 1 zoneOffsetMin returned by SSFISO8601ISOToUnix is set to SSFISO8601_INVALID_ZONE_OFFSET */
/* and unixSys time may not be UTC based, as is required by SSF time interfaces. */
#define SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX (1u)

/* 1 == Performs a lengthy exhausive unit test for every possible second; 0 == Reduced test */
#define SSF_ISO8601_EXHAUSTIVE_UNIT_TEST (0u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_ISO8601_OPT_H_INCLUDE */
