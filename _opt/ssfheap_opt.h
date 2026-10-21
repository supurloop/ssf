/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfheap configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_HEAP_OPT_H_INCLUDE
#define SSF_HEAP_OPT_H_INCLUDE

#include <stdint.h>
#include "ssfport.h"        /* SSF_CONFIG_ENABLE_THREAD_SUPPORT, SSF_MUTEX_* */

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif /* SSF_HEAP_OPT_H_INCLUDE */
