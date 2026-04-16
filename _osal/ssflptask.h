/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssflptask.h                                                                                   */
/* Provides a low-priority background task queue for offloading blocking or CPU-intensive work.   */
/*                                                                                               */
/* Work functions are queued from the main loop and executed FIFO by a background thread.         */
/* Each work item has an optional completion callback invoked when the work function returns.     */
/* The caller MUST NOT read or write data used by the work function until the completion          */
/* callback fires. The completion callback runs in the background thread context.                 */
/*                                                                                               */
/* The queue is protected by a mutex (threaded architecture required).                            */
/* The background thread implementation is platform-dependent.                                    */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
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
#ifndef SSF_LPTASK_H_INCLUDE
#define SSF_LPTASK_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Queue depth is fixed at compile time via SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH.                   */
/* Work functions execute sequentially (single background thread, no parallelism).                */
/* Completion callbacks run in the background thread context, not the main loop.                  */
/* Requires SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1.                                               */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Work function: performs the actual work in the background thread. */
typedef void (*SSFLPTaskWorkFn_t)(void *ctx);

/* Completion function: called after the work function returns, in background thread context. */
typedef void (*SSFLPTaskCompleteFn_t)(void *ctx);

/* Queue entry handle (for cancel support) */
typedef uint32_t SSFLPTaskHandle_t;
#define SSF_LPTASK_HANDLE_INVALID ((SSFLPTaskHandle_t)0xFFFFFFFFu)

/* Queue status */
typedef struct SSFLPTaskStatus
{
    uint32_t queueDepth;
    uint32_t maxQueueDepth;
    uint32_t totalQueued;
    uint32_t totalCompleted;
    bool threadRunning;
} SSFLPTaskStatus_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Initialize: starts the background thread. */
void SSFLPTaskInit(void);

/* Deinitialize: waits for in-progress work, stops the background thread. */
void SSFLPTaskDeInit(void);

/* Returns true if initialized and background thread running. */
bool SSFLPTaskIsInited(void);

/* Queue a work item. Returns handle or SSF_LPTASK_HANDLE_INVALID if queue full.                 */
/* description is an optional label for lifecycle tracing (NULL to omit).                        */
/* IMPORTANT: Caller MUST NOT access *ctx until completeFn fires.                                */
SSFLPTaskHandle_t SSFLPTaskQueue(SSFLPTaskWorkFn_t workFn,
                                 SSFLPTaskCompleteFn_t completeFn,
                                 void *ctx,
                                 const char *description);

/* Cancel a queued item not yet started. Returns true if removed. */
bool SSFLPTaskCancel(SSFLPTaskHandle_t handle);

/* Query queue and thread status. */
bool SSFLPTaskGetStatus(SSFLPTaskStatus_t *statusOut);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_LPTASK_UNIT_TEST == 1
void SSFLPTaskUnitTest(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_LPTASK_H_INCLUDE */
