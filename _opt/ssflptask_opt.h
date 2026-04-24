/* --------------------------------------------------------------------------------------------- */
/* Small System Framework — ssflptask configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_LPTASK_OPT_H_INCLUDE
#define SSF_LPTASK_OPT_H_INCLUDE

#include <stdbool.h>
#include "ssfport.h"        /* SSF_CONFIG_ENABLE_THREAD_SUPPORT, SSF_MUTEX_*, pthread, etc. */
#include "ssfassert.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Low-priority task queue depth. */
#define SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH    (8u)

/* Enable lifecycle trace output for low-priority task requests (1 = enabled, 0 = disabled). */
#define SSF_LPTASK_CONFIG_ENABLE_TRACE       (1u)

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1

/* Low-priority task queue mutex and condition variable macros */
#define SSF_LPTASK_THREAD_SYNC_DECLARATION SSF_MUTEX_DECLARATION(_ssflptaskSyncMutex)
#define SSF_LPTASK_THREAD_SYNC_INIT() SSF_MUTEX_INIT(_ssflptaskSyncMutex)
#define SSF_LPTASK_THREAD_SYNC_DEINIT() SSF_MUTEX_DEINIT(_ssflptaskSyncMutex)
#define SSF_LPTASK_THREAD_SYNC_ACQUIRE() SSF_MUTEX_ACQUIRE(_ssflptaskSyncMutex)
#define SSF_LPTASK_THREAD_SYNC_RELEASE() SSF_MUTEX_RELEASE(_ssflptaskSyncMutex)

#ifdef _WIN32
#define SSF_LPTASK_THREAD_WAKE_DECLARATION HANDLE _ssflptaskWakeSem
#define SSF_LPTASK_THREAD_WAKE_INIT() { \
    _ssflptaskWakeSem = CreateSemaphore(NULL, 0, SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH, NULL); \
    SSF_ASSERT(_ssflptaskWakeSem != NULL); \
}
#define SSF_LPTASK_THREAD_WAKE_DEINIT() { \
    CloseHandle(_ssflptaskWakeSem); \
    _ssflptaskWakeSem = NULL; \
}
#define SSF_LPTASK_THREAD_WAKE_POST() { ReleaseSemaphore(_ssflptaskWakeSem, 1, NULL); }
#define SSF_LPTASK_THREAD_WAKE_WAIT() { \
    WaitForSingleObject(_ssflptaskWakeSem, INFINITE); \
}
#else /* _WIN32 */
#define SSF_LPTASK_THREAD_WAKE_DECLARATION \
    bool _ssflptaskIsWakeSignalled; \
    pthread_cond_t _ssflptaskWakeCond; \
    pthread_mutex_t _ssflptaskWakeMutex
#define SSF_LPTASK_THREAD_WAKE_INIT() { \
    SSF_ASSERT(pthread_cond_init(&_ssflptaskWakeCond, NULL) == 0); \
    SSF_ASSERT(pthread_mutex_init(&_ssflptaskWakeMutex, NULL) == 0); \
    _ssflptaskIsWakeSignalled = false; \
}
#define SSF_LPTASK_THREAD_WAKE_DEINIT() { \
    SSF_ASSERT(pthread_cond_destroy(&_ssflptaskWakeCond) == 0); \
    SSF_ASSERT(pthread_mutex_destroy(&_ssflptaskWakeMutex) == 0); \
}
#define SSF_LPTASK_THREAD_WAKE_POST() { \
    SSF_ASSERT(pthread_mutex_lock(&_ssflptaskWakeMutex) == 0); \
    _ssflptaskIsWakeSignalled = true; \
    SSF_ASSERT(pthread_cond_signal(&_ssflptaskWakeCond) == 0); \
    SSF_ASSERT(pthread_mutex_unlock(&_ssflptaskWakeMutex) == 0); \
}
#define SSF_LPTASK_THREAD_WAKE_WAIT() { \
    SSF_ASSERT(pthread_mutex_lock(&_ssflptaskWakeMutex) == 0); \
    while (_ssflptaskIsWakeSignalled == false) { \
        SSF_ASSERT(pthread_cond_wait(&_ssflptaskWakeCond, &_ssflptaskWakeMutex) == 0); \
    } \
    _ssflptaskIsWakeSignalled = false; \
    SSF_ASSERT(pthread_mutex_unlock(&_ssflptaskWakeMutex) == 0); \
}
#endif /* _WIN32 */

/* Main loop wake mechanism — signalled by LP task completion, interrupts, etc. */
/* Uses self-pipe so it integrates with select()-based main loops. */
#ifdef _WIN32
#define SSF_MAIN_THREAD_WAKE_DECLARATION HANDLE _ssfMainWakeEvent; bool _ssfMainWakeInited
#define SSF_MAIN_THREAD_WAKE_INIT() { \
    _ssfMainWakeEvent = CreateEvent(NULL, FALSE, FALSE, NULL); \
    SSF_ASSERT(_ssfMainWakeEvent != NULL); \
    _ssfMainWakeInited = true; \
}
#define SSF_MAIN_THREAD_WAKE_DEINIT() { \
    _ssfMainWakeInited = false; \
    CloseHandle(_ssfMainWakeEvent); \
    _ssfMainWakeEvent = NULL; \
}
#define SSF_MAIN_THREAD_WAKE_POST() { if (_ssfMainWakeInited) SetEvent(_ssfMainWakeEvent); }
extern HANDLE _ssfMainWakeEvent;
extern bool _ssfMainWakeInited;
#else /* _WIN32 */
#define SSF_MAIN_THREAD_WAKE_DECLARATION \
    int _ssfMainWakePipe[2]; bool _ssfMainWakeInited
extern int _ssfMainWakePipe[2];
extern bool _ssfMainWakeInited;
#define SSF_MAIN_THREAD_WAKE_INIT() { SSF_ASSERT(pipe(_ssfMainWakePipe) == 0); \
    { int flags = fcntl(_ssfMainWakePipe[0], F_GETFL, 0); \
      fcntl(_ssfMainWakePipe[0], F_SETFL, flags | O_NONBLOCK); } \
    _ssfMainWakeInited = true; \
}
#define SSF_MAIN_THREAD_WAKE_DEINIT() { \
    _ssfMainWakeInited = false; \
    close(_ssfMainWakePipe[0]); close(_ssfMainWakePipe[1]); \
}
#define SSF_MAIN_THREAD_WAKE_POST() { \
    if (_ssfMainWakeInited) { \
        uint8_t _b = 1; \
        (void)write(_ssfMainWakePipe[1], &_b, 1); \
    } \
}
#define SSF_MAIN_THREAD_WAKE_DRAIN() { \
    uint8_t _b; \
    while (read(_ssfMainWakePipe[0], &_b, 1) > 0) {} \
}
#define SSF_MAIN_THREAD_WAKE_FD() (_ssfMainWakePipe[0])
#endif /* _WIN32 */

#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

#ifdef __cplusplus
}
#endif

#endif /* SSF_LPTASK_OPT_H_INCLUDE */
