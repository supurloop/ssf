/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssftlsc configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_TLSC_OPT_H_INCLUDE
#define SSF_TLSC_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 compiles in SSFTLSCSetUnauthenticated(), which lets a session with no trust anchors connect */
/* WITHOUT authenticating the server. 0 (production) compiles the mode out entirely: a call to  */
/* SSFTLSCSetUnauthenticated() fails to compile, and a session with no trust anchors can never  */
/* connect. Defaults to 1 only when the ssftlsc unit test is built. Override with -D.          */
#ifndef SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
#define SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED (1u)
#else
#define SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED (0u)
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLSC_OPT_H_INCLUDE */
