/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssflptask.c                                                                                   */
/* Provides a low-priority background task queue (macOS/POSIX pthread implementation).            */
/* Uses ssfll for FIFO queue management.                                                         */
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
#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "ssfassert.h"
#include "ssflptask.h"
#include "ssfll.h"

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1

#ifndef _WIN32
#include <pthread.h>
#endif

/* --------------------------------------------------------------------------------------------- */
/* Module defines                                                                                */
/* --------------------------------------------------------------------------------------------- */
#define SSF_LPTASK_INIT_MAGIC (0x4C505451ul)

/* --------------------------------------------------------------------------------------------- */
/* Module types                                                                                  */
/* --------------------------------------------------------------------------------------------- */
typedef struct SSFLPTaskEntry
{
    SSFLLItem_t llItem;             /* Must be first field for ssfll cast compatibility */
    SSFLPTaskWorkFn_t workFn;
    SSFLPTaskCompleteFn_t completeFn;
    void *ctx;
    SSFLPTaskHandle_t handle;
    const char *description;        /* Optional lifecycle trace label */
} SSFLPTaskEntry_t;

/* --------------------------------------------------------------------------------------------- */
/* Module data                                                                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFLPTaskEntry_t _entries[SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH];
static SSFLL_t _freeList;           /* Pool of unused entries */
static SSFLL_t _workQueue;          /* FIFO queue of pending work */
static uint32_t _nextHandle;
static uint32_t _totalQueued;
static uint32_t _totalCompleted;
static volatile bool _running;
static uint32_t _magic;

/* Thread synchronization (SSF pattern from ssfoptions.h) */
SSF_LPTASK_THREAD_SYNC_DECLARATION;
SSF_LPTASK_THREAD_WAKE_DECLARATION;
SSF_MAIN_THREAD_WAKE_DECLARATION;

#ifndef _WIN32
static pthread_t _thread;
#endif

/* --------------------------------------------------------------------------------------------- */
/* Background worker thread.                                                                     */
/* --------------------------------------------------------------------------------------------- */
#ifndef _WIN32
static void *_SSFLPTaskThread(void *arg)
{
    (void)arg;

    while (_running)
    {
        /* Wait for work (blocks until signalled or shutdown) */
        SSF_LPTASK_THREAD_WAKE_WAIT();

        if (!_running) break;

        /* Drain all available work items before waiting again.                                  */
        /* Multiple Queue calls may signal before the thread wakes; the boolean wake flag         */
        /* only records one signal, so process everything available.                             */
        for (;;)
        {
            SSFLPTaskEntry_t *entry = NULL;
            SSFLPTaskWorkFn_t workFn;
            SSFLPTaskCompleteFn_t completeFn;
            void *ctx;

            /* Dequeue one item under lock */
            SSF_LPTASK_THREAD_SYNC_ACQUIRE();
            if (!SSFLLIsEmpty(&_workQueue))
            {
                SSF_LL_FIFO_POP(&_workQueue, &entry);
            }
            SSF_LPTASK_THREAD_SYNC_RELEASE();

            if (entry == NULL) break; /* Queue drained — go back to waiting */

            /* Copy fields before returning entry to free list */
            workFn = entry->workFn;
            completeFn = entry->completeFn;
            ctx = entry->ctx;
            {
                const char *desc = entry->description;

                /* Return entry to free list */
                SSF_LPTASK_THREAD_SYNC_ACQUIRE();
                SSF_LL_FIFO_PUSH(&_freeList, entry);
                SSF_LPTASK_THREAD_SYNC_RELEASE();

#if SSF_LPTASK_CONFIG_ENABLE_TRACE == 1
                if (desc != NULL)
                {
                    fprintf(stdout, "[LPTask] START: %s\n", desc);
                    fflush(stdout);
                }
#endif

                /* Execute work function (outside lock) */
                if (workFn != NULL)
                {
                    workFn(ctx);
                }

#if SSF_LPTASK_CONFIG_ENABLE_TRACE == 1
                if (desc != NULL)
                {
                    fprintf(stdout, "[LPTask] DONE:  %s\n", desc);
                    fflush(stdout);
                }
#endif

                /* Invoke completion callback */
                if (completeFn != NULL)
                {
                    completeFn(ctx);
                }
            }

            SSF_LPTASK_THREAD_SYNC_ACQUIRE();
            _totalCompleted++;
            SSF_LPTASK_THREAD_SYNC_RELEASE();

            /* Wake the main loop so it can process the completed work */
            SSF_MAIN_THREAD_WAKE_POST();
        }
    }
    return NULL;
}
#endif /* _WIN32 */

/* --------------------------------------------------------------------------------------------- */
/* Initializes the low-priority task module and starts the background thread.                     */
/* --------------------------------------------------------------------------------------------- */
void SSFLPTaskInit(void)
{
    uint32_t i;

    SSF_REQUIRE(_magic != SSF_LPTASK_INIT_MAGIC);

    /* Initialize the two linked lists: free pool and work queue */
    SSFLLInit(&_freeList, SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH);
    SSFLLInit(&_workQueue, SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH);

    /* Populate the free list with all entry slots */
    memset(_entries, 0, sizeof(_entries));
    for (i = 0; i < SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH; i++)
    {
        SSF_LL_FIFO_PUSH(&_freeList, &_entries[i]);
    }

    _nextHandle = 1;
    _totalQueued = 0;
    _totalCompleted = 0;
    _running = true;

    SSF_LPTASK_THREAD_SYNC_INIT();
    SSF_LPTASK_THREAD_WAKE_INIT();

#ifndef _WIN32
    SSF_ASSERT(pthread_create(&_thread, NULL, _SSFLPTaskThread, NULL) == 0);
#endif

    _magic = SSF_LPTASK_INIT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes the module. Waits for in-progress work, then stops the background thread.       */
/* --------------------------------------------------------------------------------------------- */
void SSFLPTaskDeInit(void)
{
    SSF_REQUIRE(_magic == SSF_LPTASK_INIT_MAGIC);

    _running = false;
    SSF_LPTASK_THREAD_WAKE_POST();

#ifndef _WIN32
    pthread_join(_thread, NULL);
#endif

    SSF_LPTASK_THREAD_SYNC_DEINIT();
    SSF_LPTASK_THREAD_WAKE_DEINIT();

    /* Drain both lists before deinit (SSFLLDeInit requires empty list) */
    {
        SSFLPTaskEntry_t *entry;
        while (!SSFLLIsEmpty(&_workQueue))
        {
            SSF_LL_FIFO_POP(&_workQueue, &entry);
        }
        while (!SSFLLIsEmpty(&_freeList))
        {
            SSF_LL_FIFO_POP(&_freeList, &entry);
        }
    }
    SSFLLDeInit(&_workQueue);
    SSFLLDeInit(&_freeList);

    memset(_entries, 0, sizeof(_entries));
    _magic = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the module is initialized.                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFLPTaskIsInited(void)
{
    return (_magic == SSF_LPTASK_INIT_MAGIC && _running);
}

/* --------------------------------------------------------------------------------------------- */
/* Queues a work item for execution by the background thread.                                    */
/* --------------------------------------------------------------------------------------------- */
SSFLPTaskHandle_t SSFLPTaskQueue(SSFLPTaskWorkFn_t workFn,
                                 SSFLPTaskCompleteFn_t completeFn,
                                 void *ctx,
                                 const char *description)
{
    SSFLPTaskEntry_t *entry = NULL;
    SSFLPTaskHandle_t handle;

    SSF_REQUIRE(workFn != NULL);
    SSF_REQUIRE(_magic == SSF_LPTASK_INIT_MAGIC);

    SSF_LPTASK_THREAD_SYNC_ACQUIRE();

    /* Get a free entry from the pool */
    if (SSFLLIsEmpty(&_freeList))
    {
        SSF_LPTASK_THREAD_SYNC_RELEASE();
        return SSF_LPTASK_HANDLE_INVALID;
    }
    SSF_LL_FIFO_POP(&_freeList, &entry);
    SSF_ASSERT(entry != NULL);

    /* Assign handle */
    handle = _nextHandle++;
    if (_nextHandle == SSF_LPTASK_HANDLE_INVALID) _nextHandle = 1;

    /* Fill entry */
    entry->workFn = workFn;
    entry->completeFn = completeFn;
    entry->ctx = ctx;
    entry->handle = handle;
    entry->description = description;

    /* Push to work queue (FIFO: push to head, pop from tail) */
    SSF_LL_FIFO_PUSH(&_workQueue, entry);
    _totalQueued++;

    SSF_LPTASK_THREAD_SYNC_RELEASE();

#if SSF_LPTASK_CONFIG_ENABLE_TRACE == 1
    if (description != NULL)
    {
        fprintf(stdout, "[LPTask] QUEUED: %s (handle=%u)\n", description, (unsigned)handle);
        fflush(stdout);
    }
#endif

    /* Wake the background thread */
    SSF_LPTASK_THREAD_WAKE_POST();

    return handle;
}

/* --------------------------------------------------------------------------------------------- */
/* Cancels a queued item that has not yet started executing.                                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFLPTaskCancel(SSFLPTaskHandle_t handle)
{
    SSFLLItem_t *item;
    bool found = false;

    SSF_REQUIRE(handle != SSF_LPTASK_HANDLE_INVALID);
    SSF_REQUIRE(_magic == SSF_LPTASK_INIT_MAGIC);

    SSF_LPTASK_THREAD_SYNC_ACQUIRE();

    /* Walk the work queue looking for the matching handle */
    item = _workQueue.head;
    while (item != NULL)
    {
        SSFLPTaskEntry_t *entry = (SSFLPTaskEntry_t *)item;
        SSFLLItem_t *next = item->next;

        if (entry->handle == handle)
        {
            /* Remove from work queue and return to free list */
            SSF_LL_GET(&_workQueue, &entry, entry);
            SSF_LL_FIFO_PUSH(&_freeList, entry);
            found = true;
            break;
        }
        item = next;
    }

    SSF_LPTASK_THREAD_SYNC_RELEASE();

    return found;
}

/* --------------------------------------------------------------------------------------------- */
/* Queries the current queue and thread status.                                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFLPTaskGetStatus(SSFLPTaskStatus_t *statusOut)
{
    SSF_REQUIRE(statusOut != NULL);
    SSF_REQUIRE(_magic == SSF_LPTASK_INIT_MAGIC);

    SSF_LPTASK_THREAD_SYNC_ACQUIRE();

    statusOut->queueDepth = SSFLLLen(&_workQueue);
    statusOut->maxQueueDepth = SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH;
    statusOut->totalQueued = _totalQueued;
    statusOut->totalCompleted = _totalCompleted;
    statusOut->threadRunning = _running;

    SSF_LPTASK_THREAD_SYNC_RELEASE();

    return true;
}

#else /* SSF_CONFIG_ENABLE_THREAD_SUPPORT != 1 */

/* Stubs when thread support is disabled — these should never be called */
void SSFLPTaskInit(void) { SSF_ERROR(); }
void SSFLPTaskDeInit(void) { SSF_ERROR(); }
bool SSFLPTaskIsInited(void) { return false; }
SSFLPTaskHandle_t SSFLPTaskQueue(SSFLPTaskWorkFn_t w, SSFLPTaskCompleteFn_t c, void *x,
                                 const char *d)
{ (void)w; (void)c; (void)x; (void)d; SSF_ERROR(); return SSF_LPTASK_HANDLE_INVALID; }
bool SSFLPTaskCancel(SSFLPTaskHandle_t h) { (void)h; return false; }
bool SSFLPTaskGetStatus(SSFLPTaskStatus_t *s) { (void)s; return false; }

#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
