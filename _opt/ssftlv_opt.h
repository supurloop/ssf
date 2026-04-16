/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssftlv configuration                                                  */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_TLV_OPT_H_INCLUDE
#define SSF_TLV_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 to use 1 byte TAG and LEN fields, else 0 for variable 1-4 byte TAG and LEN fields */
/* 1 allows 2^8 unique TAGs and VALUE fields < 2^8 bytes in length */
/* 0 allows 2^30 unique TAGs and VALUE fields < 2^30 bytes in length */
#define SSF_TLV_ENABLE_FIXED_MODE (0u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLV_OPT_H_INCLUDE */
