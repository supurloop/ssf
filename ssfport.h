/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfport.h                                                                                     */
/* Provides port interface.                                                                      */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#ifndef SSF_PORT_H_INCLUDE
#define SSF_PORT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#include "Windows.h"
#else /* _WIN32 */
#include <time.h>
#endif /* _WIN32 */
#include "ssfassert.h"
/* --------------------------------------------------------------------------------------------- */
/* Enable/disable unit tests                                                                     */
/* --------------------------------------------------------------------------------------------- */
#define SSF_CONFIG_BFIFO_UNIT_TEST (1u)
#define SSF_CONFIG_LL_UNIT_TEST (1u)
#define SSF_CONFIG_MPOOL_UNIT_TEST (1u)
#define SSF_CONFIG_JSON_UNIT_TEST (1u)
#define SSF_CONFIG_BASE64_UNIT_TEST (1u)
#define SSF_CONFIG_HEX_UNIT_TEST (1u)
#define SSF_CONFIG_FCSUM_UNIT_TEST (1u)
#define SSF_CONFIG_SM_UNIT_TEST (1u)
#define SSF_CONFIG_RS_UNIT_TEST (1u)
#define SSF_CONFIG_CRC16_UNIT_TEST (1u)
#define SSF_CONFIG_CRC32_UNIT_TEST (1u)
#define SSF_CONFIG_SHA2_UNIT_TEST (1u)
#define SSF_CONFIG_TLV_UNIT_TEST (1u)
#define SSF_CONFIG_AES_UNIT_TEST (1u)
#define SSF_CONFIG_AESGCM_UNIT_TEST (1u)
#define SSF_CONFIG_CFG_UNIT_TEST (1u)
#define SSF_CONFIG_PRNG_UNIT_TEST (1u)
#define SSF_CONFIG_INI_UNIT_TEST (1u)
#define SSF_CONFIG_UBJSON_UNIT_TEST (1u)
#define SSF_CONFIG_DTIME_UNIT_TEST (1u)
#define SSF_CONFIG_RTC_UNIT_TEST (1u)
#define SSF_CONFIG_ISO8601_UNIT_TEST (1u)
#define SSF_CONFIG_DEC_UNIT_TEST (1u)
#define SSF_CONFIG_STR_UNIT_TEST (1u)
#define SSF_CONFIG_STRB_UNIT_TEST (1u)
#define SSF_CONFIG_HEAP_UNIT_TEST (1u)
#define SSF_CONFIG_GOBJ_UNIT_TEST (1u)

/* If any unit test is enabled then enable unit test mode */
#if SSF_CONFIG_BFIFO_UNIT_TEST == 1 || \
    SSF_CONFIG_LL_UNIT_TEST == 1 || \
    SSF_CONFIG_MPOOL_UNIT_TEST == 1 || \
    SSF_CONFIG_JSON_UNIT_TEST == 1 || \
    SSF_CONFIG_BASE64_UNIT_TEST == 1 || \
    SSF_CONFIG_HEX_UNIT_TEST == 1 || \
    SSF_CONFIG_FCSUM_UNIT_TEST == 1 || \
    SSF_CONFIG_SM_UNIT_TEST == 1 || \
    SSF_CONFIG_RS_UNIT_TEST == 1 || \
    SSF_CONFIG_CRC16_UNIT_TEST == 1 || \
    SSF_CONFIG_CRC32_UNIT_TEST == 1 || \
    SSF_CONFIG_SHA2_UNIT_TEST == 1 || \
    SSF_CONFIG_TLV_UNIT_TEST == 1 || \
    SSF_CONFIG_AES_UNIT_TEST == 1 || \
    SSF_CONFIG_AESGCM_UNIT_TEST == 1 || \
    SSF_CONFIG_CFG_UNIT_TEST == 1 || \
    SSF_CONFIG_PRNG_UNIT_TEST == 1 || \
    SSF_CONFIG_INI_UNIT_TEST == 1 || \
    SSF_CONFIG_UBJSON_UNIT_TEST == 1 || \
    SSF_CONFIG_DTIME_UNIT_TEST == 1 || \
    SSF_CONFIG_RTC_UNIT_TEST == 1 || \
    SSF_CONFIG_ISO8601_UNIT_TEST == 1 || \
    SSF_CONFIG_DEC_UNIT_TEST == 1 || \
    SSF_CONFIG_STR_UNIT_TEST == 1 || \
    SSF_CONFIG_STRB_UNIT_TEST == 1 || \
    SSF_CONFIG_HEAP_UNIT_TEST == 1 || \
    SSF_CONFIG_GOBJ_UNIT_TEST == 1
#define SSF_CONFIG_UNIT_TEST (1u)
#else
#define SSF_CONFIG_UNIT_TEST (0u)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Platform specific tick configuration                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Define SSFPortTick_t as unsigned 64-bit integer */
typedef uint64_t SSFPortTick_t;

/* Define the number of system ticks per second */
#define SSF_TICKS_PER_SEC (1000ull)

/* --------------------------------------------------------------------------------------------- */
/* Platform specific heap configuration                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MALLOC malloc
#define SSF_FREE free

/* --------------------------------------------------------------------------------------------- */
/* Platform specific byte swapping macros                                                        */
/* --------------------------------------------------------------------------------------------- */
/* If your platform has byte order macros include the header file here and set */
/* SSF_CONFIG_BYTE_ORDER_MACROS to 0. Else set SSF_CONFIG_BYTE_ORDER_MACROS to 1 and set */
/* SSF_CONFIG_LITTLE_ENDIAN to 1 for little endian systems, else 0. */
#ifdef __APPLE__
#include <arpa/inet.h>
#define SSF_CONFIG_BYTE_ORDER_MACROS (0u)
#define SSF_CONFIG_LITTLE_ENDIAN (1u)
#else
#define SSF_CONFIG_BYTE_ORDER_MACROS (1u)
#define SSF_CONFIG_LITTLE_ENDIAN (1u)
#endif

#if SSF_CONFIG_BYTE_ORDER_MACROS == 1
#if SSF_CONFIG_LITTLE_ENDIAN == 0
    #define htons(x) (x)
    #define ntohs(x) htons(x)

    #define htonl(x) (x)
    #define ntohl(x) htonl(x)

    #define htonll(x) (x)
    #define ntohll(x) htonll(x)
#else /* SSF_CONFIG_LITTLE_ENDIAN */
    #define htons(x) ((((x) & 0xff00u) >> 8) | \
                      (((x) & 0x00ffu) << 8))
    #define ntohs(x) htons(x)

    #define htonl(x) ((((x) & 0xff000000u) >> 24) | \
                      (((x) & 0x00ff0000u) >> 8) | \
                      (((x) & 0x0000ff00u) << 8) | \
                      (((x) & 0x000000ffu) << 24))
    #define ntohl(x) htonl(x)

    #define htonll(x) ((((x) & 0xff00000000000000u) >> 56) | \
                       (((x) & 0x00ff000000000000u) >> 40) | \
                       (((x) & 0x0000ff0000000000u) >> 24) | \
                       (((x) & 0x000000ff00000000u) >> 8) | \
                       (((x) & 0x00000000ff000000u) << 8) | \
                       (((x) & 0x0000000000ff0000u) << 24) | \
                       (((x) & 0x000000000000ff00u) << 40) | \
                       (((x) & 0x00000000000000ffu) << 56))
    #define ntohll(x) htonll(x)
#endif /* SSF_CONFIG_LITTLE_ENDIAN */
#endif /* SSF_CONFIG_BYTE_ORDER_MACROS */

/* SSF_CONFIG_ENABLE_THREAD_SUPPORT allows ssfsm events to be safely signalled from mulitple */
/* contexts and optimizes when the state machine thread runs. */
/* SSF_CONFIG_ENABLE_THREAD_SUPPORT allows the ssfcfg module to be safely called from multiple
   contexts. */
/* 0, disable thread synchronization; 1, enable thread synchronization. */
#define SSF_CONFIG_ENABLE_THREAD_SUPPORT (1u)

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#ifdef _WIN32
#define SSF_MUTEX_DECLARATION(mutex) HANDLE mutex
#define SSF_MUTEX_INIT(mutex) { \
    mutex = CreateMutex(NULL, FALSE, NULL); \
    SSF_ASSERT(mutex != NULL); \
}
#define SSF_MUTEX_DEINIT(mutex) { \
    SSF_ASSERT(mutex != NULL); \
    CloseHandle(mutex); \
    mutex = NULL; \
}
#define SSF_MUTEX_ACQUIRE(mutex) { \
    SSF_ASSERT(WaitForSingleObject(mutex, INFINITE) == WAIT_OBJECT_0); \
}
#define SSF_MUTEX_RELEASE(mutex) { SSF_ASSERT(ReleaseMutex(mutex)); }
#else /* _WIN32 */
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

#define SSF_MUTEX_DECLARATION(mutex) pthread_mutex_t mutex
#define SSF_MUTEX_INIT(mutex) { \
    pthread_mutexattr_t attr; \
    SSF_ASSERT(pthread_mutexattr_init(&attr) == 0); \
    SSF_ASSERT(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0); \
    SSF_ASSERT(pthread_mutex_init(&mutex, &attr) == 0); \
}
#define SSF_MUTEX_DEINIT(mutex) { \
    SSF_ASSERT(pthread_mutex_destroy(&mutex) == 0); \
}
#define SSF_MUTEX_ACQUIRE(mutex) { SSF_ASSERT(pthread_mutex_lock(&mutex) == 0); }
#define SSF_MUTEX_RELEASE(mutex) { SSF_ASSERT(pthread_mutex_unlock(&mutex) == 0); }
#endif /* _WIN32 */
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
__declspec(noreturn)
#endif
void SSFPortAssert(const char *file, unsigned int line);

#ifdef _WIN32
#define SSFPortGetTick64() GetTickCount64()
#else /* _WIN32 */
SSFPortTick_t SSFPortGetTick64(void);
#endif /* _WIN32 */

#include "ssf.h"
#include "ssfoptions.h"

#ifdef __cplusplus
}
#endif

#endif /* SSF_PORT_H_INCLUDE */
