/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfsm state machine configuration                                   */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_SM_OPT_H_INCLUDE
#define SSF_SM_OPT_H_INCLUDE

#include "ssfport.h"        /* SSF_CONFIG_ENABLE_THREAD_SUPPORT, SSF_TICKS_PER_SEC, etc. */
#include "ssfassert.h"

#ifdef __cplusplus
extern "C" {
#endif

/* To synchronize event signals from other contexts the following macros must be implemented. */
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#define SSF_SM_THREAD_SYNC_DECLARATION SSF_MUTEX_DECLARATION(_ssfsmSyncMutex)
#define SSF_SM_THREAD_SYNC_INIT() SSF_MUTEX_INIT(_ssfsmSyncMutex)
#define SSF_SM_THREAD_SYNC_DEINIT() SSF_MUTEX_DEINIT(_ssfsmSyncMutex)
#define SSF_SM_THREAD_SYNC_ACQUIRE() SSF_MUTEX_ACQUIRE(_ssfsmSyncMutex)
#define SSF_SM_THREAD_SYNC_RELEASE() SSF_MUTEX_RELEASE(_ssfsmSyncMutex)

#ifdef _WIN32
#define SSF_SM_THREAD_WAKE_DECLARATION HANDLE gssfsmWakeSem
#define SSF_SM_THREAD_WAKE_INIT() { \
    gssfsmWakeSem = CreateSemaphore(NULL, 0, 1, NULL); \
    SSF_ASSERT(gssfsmWakeSem != NULL); \
}
#define SSF_SM_THREAD_WAKE_DEINIT() { \
    CloseHandle(gssfsmWakeSem); \
    gssfsmWakeSem = NULL; \
}
#define SSF_SM_THREAD_WAKE_POST() { ReleaseSemaphore(gssfsmWakeSem, 1, NULL); }
#define SSF_SM_THREAD_WAKE_WAIT(timeout) { \
    DWORD waitResult; \
    waitResult = WaitForSingleObject(gssfsmWakeSem, timeout); \
    SSF_ASSERT((waitResult == WAIT_OBJECT_0) || (waitResult == WAIT_TIMEOUT)); \
}
extern HANDLE gssfsmWakeSem;
#else /* WIN32 */
#define SSF_SM_THREAD_WAKE_DECLARATION \
    bool gssfsmIsWakeSignalled; pthread_cond_t gssfsmWakeCond; pthread_mutex_t gssfsmWakeMutex
extern bool gssfsmIsWakeSignalled;
extern pthread_cond_t gssfsmWakeCond;
extern pthread_mutex_t gssfsmWakeMutex;

#if SSF_SM_THREAD_PTHREAD_CLOCK_MONOTONIC == 1
#define SSF_SM_THREAD_PTHREAD_CLOCK CLOCK_MONOTONIC
#define SSF_SM_THREAD_WAKE_INIT() { \
    pthread_condattr_t attr; \
    SSF_ASSERT(pthread_condattr_init(&attr) == 0); \
    SSF_ASSERT(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0); \
    SSF_ASSERT(pthread_cond_init(&gssfsmWakeCond, &attr) == 0); \
    SSF_ASSERT(pthread_mutex_init(&gssfsmWakeMutex, NULL) == 0); \
}
#else
#define SSF_SM_THREAD_PTHREAD_CLOCK CLOCK_REALTIME
#define SSF_SM_THREAD_WAKE_INIT() { \
    SSF_ASSERT(pthread_cond_init(&gssfsmWakeCond, NULL) == 0); \
    SSF_ASSERT(pthread_mutex_init(&gssfsmWakeMutex, NULL) == 0); \
}
#endif
#define SSF_SM_THREAD_WAKE_DEINIT() { \
    SSF_ASSERT(pthread_mutex_destroy(&gssfsmWakeMutex) == 0); \
    SSF_ASSERT(pthread_cond_destroy(&gssfsmWakeCond) == 0); \
}
#define SSF_SM_THREAD_WAKE_POST() { \
    SSF_ASSERT(pthread_mutex_lock(&gssfsmWakeMutex) == 0); \
    gssfsmIsWakeSignalled = true; \
    SSF_ASSERT(pthread_cond_signal(&gssfsmWakeCond) == 0); \
    SSF_ASSERT(pthread_mutex_unlock(&gssfsmWakeMutex) == 0); \
}

/* On a cond_timedwait() timeout OS X has errno set to ETIMEDOUT + 256! */
/* On a cond_timedwait() timeout a recent version of Debian Linux has errno set to 0! */
/* Based on documentation a cond_timedwait() timeout should set errno to ETIMEDOUT. */
#define SSF_SM_THREAD_WAKE_WAIT(timeout) { \
    SSF_ASSERT(pthread_mutex_lock(&gssfsmWakeMutex) == 0); \
    if (gssfsmIsWakeSignalled == false) { \
        uint64_t ns; \
        struct timespec ts; \
        SSF_ASSERT(clock_gettime(SSF_SM_THREAD_PTHREAD_CLOCK, &ts) == 0); \
        ns = ((uint64_t) ts.tv_nsec) + (((timeout * 1000ul) / SSF_TICKS_PER_SEC) * 1000000ul); \
        while (ns >= 1000000000l) { \
            ns -= 1000000000l; \
            ts.tv_sec++; } \
        ts.tv_nsec = (long int) ns; \
        if (pthread_cond_timedwait(&gssfsmWakeCond, &gssfsmWakeMutex, &ts) != 0) { \
            SSF_ASSERT(((errno & 0xff) == ETIMEDOUT) || (errno == 0)); } } \
    gssfsmIsWakeSignalled = false; \
    SSF_ASSERT(pthread_mutex_unlock(&gssfsmWakeMutex) == 0); \
}
#endif /* WIN32 */
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

/* Maximum number of simultaneously queued events for all state machines. */
#define SSF_SM_MAX_ACTIVE_EVENTS (3u)

/* Maximum number of simultaneously running timers for all state machines. */
#define SSF_SM_MAX_ACTIVE_TIMERS (3u)

/* Defines the state machine identifers. */
typedef enum
{
    SSF_SM_MIN = -1,
#if SSF_CONFIG_SM_UNIT_TEST == 1
    SSF_SM_UNIT_TEST_1,
    SSF_SM_UNIT_TEST_2,
    SSF_SM_UNIT_TEST_3,
    SSF_SM_UNIT_TEST_4,
#else /* SSF_CONFIG_SM_UNIT_TEST */
    SSF_SM_USER_1,
#endif /* SSF_CONFIG_SM_UNIT_TEST */
    SSF_SM_MAX
} SSFSMList_t;

/* Defines the event identifiers for all state machines. */
typedef enum
{
    SSF_SM_EVENT_MIN = -1,
    /* Required SSF events */
    SSF_SM_EVENT_ENTRY,  /* Signalled on entry to state handler */
    SSF_SM_EVENT_EXIT,   /* Signalled on exit of state handler */
    SSF_SM_EVENT_SUPER,  /* Signalled to determine parent of current state handler */
                         /* Usually handled in default case with SSF_SM_SUPER() */
                         /* macro. If no parent then SSF_SM_SUPER() is not */
                         /* required or must be called with NULL */
                         /* Super states may not have a parent super state */
    /* User defined events */
#if SSF_CONFIG_SM_UNIT_TEST == 1
    SSF_SM_EVENT_UT1_1,
    SSF_SM_EVENT_UT1_2,
    SSF_SM_EVENT_UT2_1,
    SSF_SM_EVENT_UT2_2,
    SSF_SM_EVENT_UTX_1,
    SSF_SM_EVENT_UTX_2,
    SSF_SM_EVENT_UNIT_TEST_1,
    SSF_SM_EVENT_UNIT_TEST_2,
    SSF_SM_EVENT_ABORT_UT4,
    SSF_SM_EVENT_STATE_TIMER_UT4,
#endif /* SSF_CONFIG_SM_UNIT_TEST */
    SSF_SM_EVENT_MAX
} SSFSMEventList_t;

#ifdef __cplusplus
}
#endif

#endif /* SSF_SM_OPT_H_INCLUDE */
