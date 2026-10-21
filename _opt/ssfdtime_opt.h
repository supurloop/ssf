/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfdtime configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_DTIME_OPT_H_INCLUDE
#define SSF_DTIME_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 == Time struct modifications by application code detected; 0 == app changes not detected */
#define SSF_DTIME_STRUCT_STRICT_CHECK (1u)

/* 1 == Performs a lengthy exhausive unit test for every possible second; 0 == Reduced test */
#define SSF_DTIME_EXHAUSTIVE_UNIT_TEST (0u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_DTIME_OPT_H_INCLUDE */
