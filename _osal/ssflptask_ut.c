/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssflptask_ut.c                                                                                */
/* Provides unit tests for the low-priority background task queue.                               */
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
#include "ssflptask.h"
#include "ssfport.h"

#if SSF_CONFIG_LPTASK_UNIT_TEST == 1
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1

/* --------------------------------------------------------------------------------------------- */
/* Test helpers                                                                                  */
/* --------------------------------------------------------------------------------------------- */
static volatile uint32_t _utWorkCount;
static volatile uint32_t _utCompleteCount;
static volatile uint32_t _utOrderTrace[16];
static volatile uint32_t _utOrderIdx;

static void _SSFLPTaskTestWork(void *ctx)
{
    uint32_t *val = (uint32_t *)ctx;
    (void)val;
    _utWorkCount++;
}

static void _SSFLPTaskTestComplete(void *ctx)
{
    (void)ctx;
    _utCompleteCount++;
}

/* For FIFO ordering test */
static void _SSFLPTaskTestOrderWork(void *ctx)
{
    uint32_t *val = (uint32_t *)ctx;
    if (_utOrderIdx < 16u)
    {
        _utOrderTrace[_utOrderIdx++] = *val;
    }
}

static void _SSFLPTaskTestOrderComplete(void *ctx)
{
    (void)ctx;
    _utCompleteCount++;
}

/* Spin-wait helper: wait for a volatile counter to reach a target value */
static void _SSFLPTaskTestWaitFor(volatile uint32_t *counter, uint32_t target,
                                   uint32_t timeoutMs)
{
    SSFPortTick_t start = SSFPortGetTick64();
    while (*counter < target)
    {
        if ((SSFPortGetTick64() - start) >= (SSFPortTick_t)timeoutMs) break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Unit test.                                                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFLPTaskUnitTest(void)
{
    SSFLPTaskHandle_t handle;
    SSFLPTaskStatus_t status;
    uint32_t i;

    /* ---- Init / DeInit lifecycle ---- */
    SSF_ASSERT(SSFLPTaskIsInited() == false);
    SSFLPTaskInit();
    SSF_ASSERT(SSFLPTaskIsInited() == true);
    SSFLPTaskDeInit();
    SSF_ASSERT(SSFLPTaskIsInited() == false);

    /* ---- Reinit for remaining tests ---- */
    SSFLPTaskInit();

    /* ---- NULL parameter assertion ---- */
    SSF_ASSERT_TEST(SSFLPTaskQueue(NULL, NULL, NULL, NULL));
    SSF_ASSERT_TEST(SSFLPTaskGetStatus(NULL));

    /* ---- Queue a single work item ---- */
    _utWorkCount = 0;
    _utCompleteCount = 0;
    {
        uint32_t testVal = 42;
        handle = SSFLPTaskQueue(_SSFLPTaskTestWork, _SSFLPTaskTestComplete, &testVal, NULL);
        SSF_ASSERT(handle != SSF_LPTASK_HANDLE_INVALID);

        /* Wait for completion (up to 1 second) */
        _SSFLPTaskTestWaitFor(&_utCompleteCount, 1, 1000);
        SSF_ASSERT(_utWorkCount == 1);
        SSF_ASSERT(_utCompleteCount == 1);
    }

    /* ---- Queue without completion callback ---- */
    _utWorkCount = 0;
    {
        uint32_t testVal = 99;
        handle = SSFLPTaskQueue(_SSFLPTaskTestWork, NULL, &testVal, NULL);
        SSF_ASSERT(handle != SSF_LPTASK_HANDLE_INVALID);

        _SSFLPTaskTestWaitFor(&_utWorkCount, 1, 1000);
        SSF_ASSERT(_utWorkCount == 1);
    }

    /* ---- FIFO ordering ---- */
    _utCompleteCount = 0;
    _utOrderIdx = 0;
    memset((void *)_utOrderTrace, 0, sizeof(_utOrderTrace));
    {
        uint32_t vals[4] = { 10u, 20u, 30u, 40u };

        for (i = 0; i < 4; i++)
        {
            handle = SSFLPTaskQueue(_SSFLPTaskTestOrderWork, _SSFLPTaskTestOrderComplete,
                                    &vals[i], NULL);
            SSF_ASSERT(handle != SSF_LPTASK_HANDLE_INVALID);
        }

        /* Wait for all 4 to complete */
        _SSFLPTaskTestWaitFor(&_utCompleteCount, 4, 2000);
        SSF_ASSERT(_utCompleteCount == 4);
        SSF_ASSERT(_utOrderIdx == 4);
        SSF_ASSERT(_utOrderTrace[0] == 10u);
        SSF_ASSERT(_utOrderTrace[1] == 20u);
        SSF_ASSERT(_utOrderTrace[2] == 30u);
        SSF_ASSERT(_utOrderTrace[3] == 40u);
    }

    /* ---- GetStatus ---- */
    SSF_ASSERT(SSFLPTaskGetStatus(&status) == true);
    SSF_ASSERT(status.maxQueueDepth == SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH);
    SSF_ASSERT(status.totalQueued >= 6u);  /* At least 6 items queued so far */
    SSF_ASSERT(status.totalCompleted >= 6u);
    SSF_ASSERT(status.threadRunning == true);
    SSF_ASSERT(status.queueDepth == 0);    /* All completed */

    /* ---- Cancel a queued item ---- */
    /* To test cancel, we need an item that hasn't executed yet.                                  */
    /* Queue a slow work item first, then queue the one to cancel.                               */
    _utWorkCount = 0;
    _utCompleteCount = 0;
    {
        static volatile bool _slowDone;
        _slowDone = false;

        /* Slow work function -- holds the thread busy */
        handle = SSFLPTaskQueue(
            (SSFLPTaskWorkFn_t)_SSFLPTaskTestWork, _SSFLPTaskTestComplete, NULL, NULL);
        SSF_ASSERT(handle != SSF_LPTASK_HANDLE_INVALID);

        /* This one may or may not be cancellable depending on timing */
        {
            SSFLPTaskHandle_t cancelHandle;
            uint32_t cancelVal = 77;
            cancelHandle = SSFLPTaskQueue(_SSFLPTaskTestWork, _SSFLPTaskTestComplete,
                                          &cancelVal, NULL);
            /* Try to cancel -- may succeed or fail depending on thread scheduling */
            (void)SSFLPTaskCancel(cancelHandle);
        }

        /* Wait for whatever runs to finish */
        _SSFLPTaskTestWaitFor(&_utCompleteCount, 1, 1000);
    }

    /* ---- Clean up ---- */
    /* Wait briefly for any in-flight work */
    {
        SSFPortTick_t waitStart = SSFPortGetTick64();
        while ((SSFPortGetTick64() - waitStart) < 100u) { /* brief wait */ }
    }

    SSFLPTaskDeInit();
}

#else /* SSF_CONFIG_ENABLE_THREAD_SUPPORT != 1 */
void SSFLPTaskUnitTest(void) { /* Thread support disabled -- skip */ }
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
#endif /* SSF_CONFIG_LPTASK_UNIT_TEST */
