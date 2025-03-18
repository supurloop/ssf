/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfoptions.h                                                                                  */
/* Provides compile-time options for SSF interfaces.                                             */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
/*                                                                                               */
/* Redistribution and use in source and binary forms, with or without modification, are          */
/* permitted provided that the following conditions are met:                                     */
/*                                                                                               */
/* 1. Redistributions of source code must retain the above copyright notice, this list of        */
/* conditions and the following disclaimer.                                                      */
/* 2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/* conditions and the following disclaimer in the documentation and/or other materials provided  */
/* with the distribution.                                                                        */
/* 3. Neither the name of the copyright holder nor the names of its contributors may be used to  */
/* endorse or promote products derived from this software without specific prior written         */
/* permission.                                                                                   */
/*                                                                                               */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE    */
/* COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL      */
/* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_OPTIONS_H_INCLUDE
#define SSF_OPTIONS_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include "ssfport.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfbfifo's byte fifo interface                                                      */
/* --------------------------------------------------------------------------------------------- */

/* Define the maximum fifo size. */
#define SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE (255UL)

#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY         (0u)
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255         (1u)
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1 (2u)

/* Define the allowed runtime fifo size. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY allows any fifo size up to
   SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255 allows only fifo sizes of 255. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1 allows fifo sizes that are power of 2 minus 1
   up to SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE. */
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE (SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255)

/* Enable or disable the multi-byte fifo interface. */
#define SSF_BFIFO_MULTI_BYTE_ENABLE                     (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfmpool's memory pool interface                                                    */
/* --------------------------------------------------------------------------------------------- */
/* Enable pool debug struct that tracks all blocks and who allocated them                        */
#define SSF_MPOOL_DEBUG (0u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfjson's parser limits                                                             */
/* --------------------------------------------------------------------------------------------- */
/* Define the maximum parse depth, each opening { or [ starts a new depth level. */
#define SSF_JSON_CONFIG_MAX_IN_DEPTH (4u)

/* Define the maximum JSON string length to be parsed. */
#define SSF_JSON_CONFIG_MAX_IN_LEN  (2047u)

/* Allow parser to use floating point to convert numbers. */
#define SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE (0u)

/* Allow generator to print floats. */
#define SSF_JSON_CONFIG_ENABLE_FLOAT_GEN (1u)

/* Enable interface that can update specific fields in a JSON string. */
#define SSF_JSON_CONFIG_ENABLE_UPDATE (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfsm's state machine interface                                                     */
/* --------------------------------------------------------------------------------------------- */
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
#endif /* SSF_CONFIG_SM_UNIT_TEST */
    SSF_SM_EVENT_MAX
} SSFSMEventList_t;

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfrs's Reed-Solomon interface                                                      */
/* --------------------------------------------------------------------------------------------- */
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

/* --------------------------------------------------------------------------------------------- */
/* Configure ssftlv interface                                                                    */
/* --------------------------------------------------------------------------------------------- */
/* 1 to use 1 byte TAG and LEN fields, else 0 for variable 1-4 byte TAG and LEN fields */
/* 1 allows 2^8 unique TAGs and VALUE fields < 2^8 bytes in length */
/* 0 allows 2^30 unique TAGs and VALUE fields < 2^30 bytes in length */
#define SSF_TLV_ENABLE_FIXED_MODE (0u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfcfg interface                                                                    */
/* --------------------------------------------------------------------------------------------- */
#define SSF_CFG_TYPEDEF_STRUCT typedef struct /* Optionally add packed struct attribute here */
#define SSF_CFG_MAX_STORAGE_SIZE (4096u) /* Max size of erasable NV storage sector */
#define SSF_MAX_CFG_DATA_SIZE_LIMIT (32u) /* Max size of data */
#define SSF_CFG_WRITE_CHECK_CHUNK_SIZE (32u) /* Max size of tmp stack buffer for write checking */

/* 1 to use RAM as storage, 0 to specify another storage interface */
#define SSF_CFG_ENABLE_STORAGE_RAM (1u)
#if SSF_CFG_ENABLE_STORAGE_RAM == 0
#define SSF_CFG_ERASE_STORAGE(dataId)
#define SSF_CFG_WRITE_STORAGE(data, dataSize, dataId, dataOffset)
#define SSF_CFG_READ_STORAGE(data, dataSize, dataId, dataOffset)
#else
#define SSF_MAX_CFG_RAM_SECTORS (3u)
#define SSF_MAX_CFG_RAM_SECTOR_SIZE (SSF_MAX_CFG_DATA_SIZE_LIMIT + 32u)
#define SSF_CFG_ERASE_STORAGE(dataId) { \
    memset(&_ssfCfgStorageRAM[dataId], 0xff, SSF_MAX_CFG_RAM_SECTOR_SIZE); \
}
#define SSF_CFG_WRITE_STORAGE(data, dataLen, dataId, dataOffset) { \
    memcpy(&_ssfCfgStorageRAM[dataId][dataOffset], data, dataLen); \
}
#define SSF_CFG_READ_STORAGE(data, dataSize, dataId, dataOffset) { \
    memcpy(data, &_ssfCfgStorageRAM[dataId][dataOffset], dataSize); \
}
#endif

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#define SSF_CFG_THREAD_SYNC_DECLARATION SSF_MUTEX_DECLARATION(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_INIT() SSF_MUTEX_INIT(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_DEINIT() SSF_MUTEX_DEINIT(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_ACQUIRE() SSF_MUTEX_ACQUIRE(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_RELEASE() SSF_MUTEX_RELEASE(_ssfcfgSyncMutex)
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfubjson's parser limits                                                           */
/* --------------------------------------------------------------------------------------------- */
/* Define the maximum parse depth, each opening { or [ starts a new depth level. */
#define SSF_UBJSON_CONFIG_MAX_IN_DEPTH (4u)

/* Define the maximum JSON string length to be parsed. */
#define SSF_UBJSON_CONFIG_MAX_IN_LEN  (2047u)

#define SSF_UBJSON_TYPEDEF_STRUCT typedef struct /* Optionally add packed struct attribute here */

/* Allow parser to return HPN type as a string instead of considering parse invalid. */
#define SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfrtc's interface                                                                  */
/* --------------------------------------------------------------------------------------------- */
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

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfdtime's interface                                                                */
/* --------------------------------------------------------------------------------------------- */
/* 1 == Time struct modifications by application code detected; 0 == app changes not detected */
#define SSF_DTIME_STRUCT_STRICT_CHECK (1u)

/* 1 == Performs a lengthy exhausive unit test for every possible second; 0 == Reduced test */
#define SSF_DTIME_EXHAUSTIVE_UNIT_TEST (0u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfiso8601's interface                                                              */
/* --------------------------------------------------------------------------------------------- */
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

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfheap's interface                                                                 */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#define SSF_HEAP_SYNC_DECLARATION SSF_MUTEX_DECLARATION(mutex)
#define SSF_HEAP_SYNC_INIT() SSF_MUTEX_INIT((ph->mutex))
#define SSF_HEAP_SYNC_DEINIT() SSF_MUTEX_DEINIT((ph->mutex))
#define SSF_HEAP_SYNC_ACQUIRE() SSF_MUTEX_ACQUIRE((ph->mutex))
#define SSF_HEAP_SYNC_RELEASE() SSF_MUTEX_RELEASE((ph->mutex))
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

#if UINTPTR_MAX == UINT16_MAX
    typedef uint16_t SSF_PTR_CAST_TYPE;
#elif UINTPTR_MAX == UINT32_MAX
    typedef uint32_t SSF_PTR_CAST_TYPE;
#elif UINTPTR_MAX == UINT64_MAX
    typedef uint64_t SSF_PTR_CAST_TYPE;
#else
#error SSF pointer size not determined.
#endif

/* 1 == Extra heap block check after heap code changes a block; 0(default) == Disable check. */
/* Useful if debugging problems on port to new architecture. */
#define SSF_HEAP_SET_BLOCK_CHECK (0u)

/* Sets the maximum size of the heap for unit test. */
#define SSF_HEAP_MAX_SIZE_FOR_UNIT_TEST (4224u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfgobj's interface                                                                 */
/* --------------------------------------------------------------------------------------------- */
/* Define the maximum parse depth, each nexted object or array starts a new depth level. */
#define SSF_GOBJ_CONFIG_MAX_IN_DEPTH (4u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_OPTIONS_H_INCLUDE */
