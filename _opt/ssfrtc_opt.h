/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssfrtc configuration                                                  */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_RTC_OPT_H_INCLUDE
#define SSF_RTC_OPT_H_INCLUDE

#include <stdint.h>
#include "ssfport.h"        /* SSF_CONFIG_ENABLE_THREAD_SUPPORT, SSF_MUTEX_* */

#ifdef __cplusplus
extern "C" {
#endif

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#define SSF_RTC_THREAD_SYNC_DECLARATION SSF_MUTEX_DECLARATION(_ssfrtcSyncMutex)
#define SSF_RTC_THREAD_SYNC_INIT() SSF_MUTEX_INIT(_ssfrtcSyncMutex)
#define SSF_RTC_THREAD_SYNC_DEINIT() SSF_MUTEX_DEINIT(_ssfrtcSyncMutex)
#define SSF_RTC_THREAD_SYNC_ACQUIRE() SSF_MUTEX_ACQUIRE(_ssfrtcSyncMutex)
#define SSF_RTC_THREAD_SYNC_RELEASE() SSF_MUTEX_RELEASE(_ssfrtcSyncMutex)
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

/* 1 == Use a simulated RTC device; 0 == Interface to real RTC device */
#define SSF_RTC_ENABLE_SIM (1u)

/* Configure access to the RTC */
#if SSF_RTC_ENABLE_SIM == 1
    extern uint64_t _ssfRTCSimUnixSec;
    #define SSF_RTC_WRITE(unixSec) _SSFRTCSimWrite(unixSec)
    #define SSF_RTC_READ(unixSec) _SSFRTCSimRead(unixSec)
#else /* SSF_RTC_ENABLE_SIM */
    /* Map to function that writes 64-bit Unix time in seconds to RTC */
    /* bool (*write)(uint64_t unixSec) */
    #define SSF_RTC_WRITE(unixSec)

    /* Map to function that returns 64-bit Unix time in seconds from RTC */
    /* bool (*read)(uint64_t *unixSec) */
    #define SSF_RTC_READ(unixSec)
#endif /* SSF_RTC_ENABLE_SIM */

#ifdef __cplusplus
}
#endif

#endif /* SSF_RTC_OPT_H_INCLUDE */
