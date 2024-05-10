/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsm.c                                                                                       */
/* Provides a state machine framework.                                                           */
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
#include <stdlib.h>
#include <string.h>
#include "ssfll.h"
#include "ssfsm.h"
#include "ssfmpool.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef struct SSFSMState
{
    SSFSMHandler_t current;
    SSFSMHandler_t next;
} SSFSMState_t;

typedef struct SSFSMEvent
{
    SSFLLItem_t item;
    SSFSMId_t smid;
    SSFSMEventId_t eid;
    SSFSMDataLen_t dataLen;
    SSFSMData_t *data;
} SSFSMEvent_t;

typedef struct SSFSMTimer
{
    SSFLLItem_t item;
    SSFSMEvent_t *event;
    SSFSMTimeout_t to;
} SSFSMTimer_t;

/* --------------------------------------------------------------------------------------------- */
/* Module variables                                                                              */
/* --------------------------------------------------------------------------------------------- */
static SSFSMState_t _SSFSMStates[SSF_SM_MAX];
static SSFSMId_t _ssfsmActive = SSF_SM_MAX;
static SSFSMId_t _ssfsmIsEntryExit;
static SSFMPool_t _ssfsmEventPool;
static SSFMPool_t _ssfsmTimerPool;
static SSFLL_t _ssfsmEvents;
static SSFLL_t _ssfsmTimers;
static bool _ssfsmIsInited;
static uint64_t _ssfsmMallocs;
static uint64_t _ssfsmFrees;

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
SSF_SM_THREAD_SYNC_DECLARATION;
SSF_SM_THREAD_WAKE_DECLARATION;
#endif

/* --------------------------------------------------------------------------------------------- */
/* Frees event data.                                                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMFreeEventData(SSFSMData_t *data)
{
    SSF_REQUIRE(data != NULL);
    SSF_FREE(data);
    _ssfsmFrees++;
    SSF_ENSURE(_ssfsmFrees <= _ssfsmMallocs);
    SSF_ENSURE((_ssfsmMallocs - _ssfsmFrees) <= SSFMPoolSize(&_ssfsmEventPool));
}

/* --------------------------------------------------------------------------------------------- */
/* Stops all timers for active state machine.                                                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMStopAllTimers(void)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    SSFSMTimer_t t;

    SSF_ASSERT((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX));

    item = SSF_LL_HEAD(&_ssfsmTimers);
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        memcpy(&t, item, sizeof(t));
        if (t.event->smid == _ssfsmActive)
        {
            if ((t.event->data) && (t.event->dataLen > sizeof(SSFSMData_t *)))
            { _SSFSMFreeEventData(t.event->data); }
            SSFLLGetItem(&_ssfsmTimers, &item, SSF_LL_LOC_ITEM, item);
            SSFMPoolFree(&_ssfsmEventPool, t.event);
            SSFMPoolFree(&_ssfsmTimerPool, item);
        }
        item = next;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns timer if timer with event ID found in active state machine, else NULL.                */
/* --------------------------------------------------------------------------------------------- */
static SSFLLItem_t *_SSFSMFindTimer(SSFSMEventId_t eid)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    SSFSMTimer_t t;

    SSF_ASSERT((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX));

    item = SSF_LL_HEAD(&_ssfsmTimers);
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        memcpy(&t, item, sizeof(t));
        if ((t.event->smid == _ssfsmActive) && (t.event->eid == eid)) break;
        item = next;
    }
    return item;
}

/* --------------------------------------------------------------------------------------------- */
/* Processes event in state machine context, performs state transitions as requested.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMProcessEvent(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data,
                               SSFSMDataLen_t dataLen)
{
    _ssfsmActive = smid;
    _SSFSMStates[_ssfsmActive].current(eid, data, dataLen);

    if (_SSFSMStates[_ssfsmActive].next != NULL)
    {
        _ssfsmIsEntryExit = true;
        _SSFSMStates[_ssfsmActive].current(SSF_SM_EVENT_EXIT, NULL, 0);
        _SSFSMStopAllTimers();
        _SSFSMStates[_ssfsmActive].current = _SSFSMStates[_ssfsmActive].next;
        _SSFSMStates[_ssfsmActive].next = NULL;
        _SSFSMStates[_ssfsmActive].current(SSF_SM_EVENT_ENTRY, NULL, 0);
        _ssfsmIsEntryExit = false;
    }
    _ssfsmActive = SSF_SM_MAX;
}

/* --------------------------------------------------------------------------------------------- */
/* Allocates event data.                                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMAllocEventData(SSFSMEvent_t *event, const SSFSMData_t *data,
                                 SSFSMDataLen_t dataLen)
{
    SSF_REQUIRE(event != NULL);

    event->dataLen = dataLen;
    if (event->dataLen == 0) event->data = NULL;
    else if (event->dataLen <= sizeof(SSFSMData_t *))
    { memcpy(&(event->data), data, event->dataLen); }
    else
    {
        SSF_ASSERT((event->data = (SSFSMData_t *)SSF_MALLOC(event->dataLen)) != NULL);
        _ssfsmMallocs++;
        memcpy(event->data, data, event->dataLen);
        SSF_ENSURE(_ssfsmFrees <= _ssfsmMallocs);
        SSF_ENSURE((_ssfsmMallocs - _ssfsmFrees) <= SSFMPoolSize(&_ssfsmEventPool));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes state machine framework.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSMInit(uint32_t maxEvents, uint32_t maxTimers)
{
    SSF_ASSERT(_ssfsmIsInited == false);

    SSFMPoolInit(&_ssfsmEventPool, maxEvents, sizeof(SSFSMEvent_t));
    SSFMPoolInit(&_ssfsmTimerPool, maxTimers, sizeof(SSFSMTimer_t));
    SSFLLInit(&_ssfsmEvents, maxEvents);
    SSFLLInit(&_ssfsmTimers, maxTimers);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_WAKE_INIT();
    SSF_SM_THREAD_SYNC_INIT();
#endif

    _ssfsmIsInited = true;
}
/* --------------------------------------------------------------------------------------------- */
/* Deinitializes state machine framework.                                                        */
/* --------------------------------------------------------------------------------------------- */
void SSFSMDeInit(void)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    SSFSMTimer_t t;
    SSFSMEvent_t e;

    SSF_ASSERT(_ssfsmIsInited);
    _ssfsmIsInited = false;

    /* Process all pending timers and free event data. */
    item = SSF_LL_HEAD(&_ssfsmTimers);
    while (item != NULL)
    {
        next =  SSF_LL_NEXT_ITEM(item);
        memcpy(&t, item, sizeof(t));
        SSFLLGetItem(&_ssfsmTimers, &item, SSF_LL_LOC_ITEM, item);
        if ((t.event->data != NULL) && (t.event->dataLen > sizeof(SSFSMData_t *)))
        { _SSFSMFreeEventData(t.event->data); }
        SSFMPoolFree(&_ssfsmTimerPool, item);
        item = next;
    }

    /* Process all pending events and free event data. */
    item = SSF_LL_HEAD(&_ssfsmEvents);
    while (item != NULL)
    {
        next =  SSF_LL_NEXT_ITEM(item);
        memcpy(&e, item, sizeof(e));
        SSFLLGetItem(&_ssfsmEvents, &item, SSF_LL_LOC_ITEM, item);
        if ((e.data != NULL) && (e.dataLen > sizeof(SSFSMData_t *)))
        { _SSFSMFreeEventData(e.data); }
        SSFMPoolFree(&_ssfsmEventPool, item);
        item = next;
    }

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_WAKE_DEINIT();
    SSF_SM_THREAD_SYNC_DEINIT();
#endif

    SSFLLDeInit(&_ssfsmTimers);
    SSFLLDeInit(&_ssfsmEvents);
    SSFMPoolDeInit(&_ssfsmTimerPool);
    SSFMPoolDeInit(&_ssfsmEventPool);

    memset(_SSFSMStates, 0, sizeof(_SSFSMStates));
    _ssfsmActive = SSF_SM_MAX;
    _ssfsmIsEntryExit = false;
    SSF_ASSERT(_ssfsmMallocs == _ssfsmFrees);
    _ssfsmMallocs = 0;
    _ssfsmFrees = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes a state machine handler.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSMInitHandler(SSFSMId_t smid, SSFSMHandler_t initial)
{
    SSF_REQUIRE((smid > SSF_SM_MIN) && (smid < SSF_SM_MAX));
    SSF_REQUIRE(initial != NULL);
    SSF_ASSERT(_ssfsmIsInited);

    _SSFSMStates[smid].current = initial;
    _ssfsmActive = smid;
    _ssfsmIsEntryExit = true;
    _SSFSMStates[smid].current(SSF_SM_EVENT_ENTRY, NULL, 0);
    _ssfsmActive = SSF_SM_MAX;
    _ssfsmIsEntryExit = false;
}

/* --------------------------------------------------------------------------------------------- */
/* Posts a new event to a state machine, processes it immediately if possible.                   */
/* --------------------------------------------------------------------------------------------- */
void SSFSMPutEventData(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data,
                       SSFSMDataLen_t dataLen)
{
    SSFSMEvent_t *e;

    SSF_REQUIRE((smid > SSF_SM_MIN) && (smid < SSF_SM_MAX));
    SSF_REQUIRE((eid > SSF_SM_EVENT_EXIT) && (eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));
    SSF_ASSERT(_ssfsmIsInited);
    SSF_ASSERT(_SSFSMStates[smid].current != NULL);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 0
    /* In state handler or there are pending events? */
    if (((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX)) ||
        (SSFLLIsEmpty(&_ssfsmEvents) == false))
    {
#endif
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
        SSF_SM_THREAD_SYNC_ACQUIRE();
#endif
        /* Queue event */
        e = (SSFSMEvent_t *)SSFMPoolAlloc(&_ssfsmEventPool, sizeof(SSFSMEvent_t), 0x11);
        e->smid = smid;
        e->eid = eid;
        _SSFSMAllocEventData(e, data, dataLen);
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, e);
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
        SSF_SM_THREAD_WAKE_POST();
        SSF_SM_THREAD_SYNC_RELEASE();
#else
    } else _SSFSMProcessEvent(smid, eid, data, dataLen);
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Record request for state transition.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSMTran(SSFSMHandler_t next)
{
    SSF_REQUIRE(next != NULL);
    SSF_ASSERT((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX));
    SSF_REQUIRE(next != _SSFSMStates[_ssfsmActive].current);
    SSF_ASSERT(_SSFSMStates[_ssfsmActive].next == NULL);
    SSF_ASSERT(_ssfsmIsEntryExit == false);
    SSF_ASSERT(_ssfsmIsInited);

    _SSFSMStates[_ssfsmActive].next = next;
}

/* --------------------------------------------------------------------------------------------- */
/* Start a timer with optional event data.                                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFSMStartTimerData(SSFSMEventId_t eid, SSFSMTimeout_t interval, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen)
{
    SSFSMTimer_t *tp;

    SSF_REQUIRE((eid > SSF_SM_EVENT_EXIT) && (eid > SSF_SM_EVENT_MIN) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));
    SSF_ASSERT((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX));
    SSF_ASSERT(_ssfsmIsInited);

    /* Stop duplicate timer if it already exists */
    SSFSMStopTimer(eid);

    /* Create new timer. */
    tp = (SSFSMTimer_t *)SSFMPoolAlloc(&_ssfsmTimerPool, sizeof(SSFSMTimer_t), 0x22);
    tp->event = (SSFSMEvent_t *)SSFMPoolAlloc(&_ssfsmEventPool, sizeof(SSFSMEvent_t), 0x33);
    tp->to = interval + SSFPortGetTick64();
    tp->event->smid = _ssfsmActive;
    tp->event->eid = eid;
    _SSFSMAllocEventData(tp->event, data, dataLen);
    SSF_LL_FIFO_PUSH(&_ssfsmTimers, tp);
}

/* --------------------------------------------------------------------------------------------- */
/* Stop timer for active state machine.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSMStopTimer(SSFSMEventId_t eid)
{
    SSFLLItem_t *item;
    SSFSMTimer_t t;

    SSF_ASSERT((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX));
    SSF_ASSERT(_ssfsmIsInited);

    item = _SSFSMFindTimer(eid);
    if (item != NULL)
    {
        SSFLLGetItem(&_ssfsmTimers, &item, SSF_LL_LOC_ITEM, item);
        memcpy(&t, item, sizeof(t));
        if ((t.event->data) && (t.event->dataLen > sizeof(SSFSMData_t *)))
        {_SSFSMFreeEventData(t.event->data); }
        SSFMPoolFree(&_ssfsmEventPool, t.event);
        SSFMPoolFree(&_ssfsmTimerPool, item);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Call periodically from main loop. Returns true if timers are pending, else false.             */
/* Optionally reports delta to next timer expiration in SSF_TICKS_PER_SEC units.                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFSMTask(SSFSMTimeout_t *nextTimeout)
{
    SSFSMEvent_t e;
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    SSFSMTimer_t t;
    SSFSMTimeout_t current = SSFPortGetTick64();
    bool retVal;

    SSF_ASSERT(_ssfsmActive >= SSF_SM_MAX);
    SSF_ASSERT(_ssfsmIsInited);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_SYNC_ACQUIRE();
#endif

    /* Process timers. */
    item = SSF_LL_HEAD(&_ssfsmTimers);
    while (item != NULL)
    {
        next =  SSF_LL_NEXT_ITEM(item);
        memcpy(&t, item, sizeof(t));  /* Ensure alignment */
        if (t.to > current) { item = next; continue; }
        SSFLLGetItem(&_ssfsmTimers, &item, SSF_LL_LOC_ITEM, item);
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, (SSFLLItem_t *)t.event);
        SSFMPoolFree(&_ssfsmTimerPool, item);
        item = next;
    }

    /* Process all pending events. */
    while (SSF_LL_FIFO_POP(&_ssfsmEvents, &item) == true)
    {
        memcpy(&e, item, sizeof(e)); /* Ensure alignment */
        if (e.dataLen > sizeof(SSFSMData_t *))
        { _SSFSMProcessEvent(e.smid, e.eid, e.data, e.dataLen); }
        else _SSFSMProcessEvent(e.smid, e.eid, (SSFSMData_t *)&e.data, e.dataLen);
        if ((e.data != NULL) && (e.dataLen > sizeof(SSFSMData_t *)))
        { _SSFSMFreeEventData(e.data); }
        SSFMPoolFree(&_ssfsmEventPool, item);
    }

    /* If necessary determine next timer expiration */
    if (nextTimeout != NULL)
    {
        *nextTimeout = SSF_SM_MAX_TIMEOUT;
        item = SSF_LL_HEAD(&_ssfsmTimers);
        while (item != NULL)
        {
            next = SSF_LL_NEXT_ITEM(item);
            memcpy(&t, item, sizeof(t));
            if (t.to < (*nextTimeout)) *nextTimeout = t.to;
            item = next;
        }
        if (*nextTimeout != SSF_SM_MAX_TIMEOUT) *nextTimeout -= current;
    }
    retVal = !SSFLLIsEmpty(&_ssfsmTimers);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_SYNC_RELEASE();
#endif
    return retVal;
}

