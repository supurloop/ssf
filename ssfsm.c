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
static SSFSMState_t _SSFSMStates[SSF_SM_END];
static SSFSMId_t _ssfsmActive = SSF_SM_END;
static SSFSMId_t _ssfsmIsEntryExit;
static SSFMPool_t _ssfsmEventPool;
static SSFMPool_t _ssfsmTimerPool;
static SSFLL_t _ssfsmEvents;
static SSFLL_t _ssfsmTimers;
static bool _ssfsmIsInited;
static uint64_t _ssfsmMallocs;
static uint64_t _ssfsmFrees;

/* --------------------------------------------------------------------------------------------- */
/* Stops all timers for active state machine.                                                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMStopAllTimers(void)
{
    SSFSMTimer_t *t;
    SSFSMTimer_t *next;

    SSF_ASSERT(_ssfsmActive < SSF_SM_END);

    t = (SSFSMTimer_t *)SSF_LL_HEAD(&_ssfsmTimers);
    while (t != NULL)
    {
        next = (SSFSMTimer_t *)SSF_LL_NEXT_ITEM((SSFLLItem_t *)t);
        if (t->event->smid == _ssfsmActive)
        {
            SSFLLGetItem(&_ssfsmTimers, (SSFLLItem_t **)&t, SSF_LL_LOC_ITEM, (SSFLLItem_t *)t);
            SSFMPoolFree(&_ssfsmEventPool, t->event);
            SSFMPoolFree(&_ssfsmTimerPool, t);
        }
        t = next;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns timer if timer with event ID found in active state machine, else NULL.                */
/* --------------------------------------------------------------------------------------------- */
static SSFSMTimer_t* _SSFSMFindTimer(SSFSMEventId_t eid)
{
    SSFSMTimer_t *t;
    SSFSMTimer_t *next;

    SSF_ASSERT(_ssfsmActive < SSF_SM_END);

    t = (SSFSMTimer_t *)SSF_LL_HEAD(&_ssfsmTimers);
    while (t != NULL)
    {
        next = (SSFSMTimer_t *)SSF_LL_NEXT_ITEM((SSFLLItem_t *)t);
        if ((t->event->smid == _ssfsmActive) && (t->event->eid == eid)) break;
        t = next;
    }
    return t;
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
    _ssfsmActive = SSF_SM_END;
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
    else if (event->dataLen <= sizeof(SSFSMData_t *)) memcpy(&(event->data), data, event->dataLen);
    else
    {
        SSF_ASSERT((event->data = (SSFSMData_t *)malloc(event->dataLen)) != NULL);
        _ssfsmMallocs++;
        memcpy(event->data, data, event->dataLen);
        SSF_ENSURE(_ssfsmFrees <= _ssfsmMallocs);
        SSF_ENSURE((_ssfsmMallocs - _ssfsmFrees) <= SSFMPoolSize(&_ssfsmEventPool));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Frees event data.                                                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMFreeEventData(SSFSMData_t *data)
{
    SSF_REQUIRE(data != NULL);
    free(data);
    _ssfsmFrees++;
    SSF_ENSURE(_ssfsmFrees <= _ssfsmMallocs);
    SSF_ENSURE((_ssfsmMallocs - _ssfsmFrees) <= SSFMPoolSize(&_ssfsmEventPool));
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
    _ssfsmIsInited = true;
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes a state machine handler.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSMInitHandler(SSFSMId_t smid, SSFSMHandler_t initial)
{
    SSF_REQUIRE(smid < SSF_SM_END);
    SSF_REQUIRE(initial != NULL);
    SSF_ASSERT(_ssfsmIsInited);

    _SSFSMStates[smid].current = initial;
    _ssfsmActive = smid;
    _ssfsmIsEntryExit = true;
    _SSFSMStates[smid].current(SSF_SM_EVENT_ENTRY, NULL, 0);
    _ssfsmActive = SSF_SM_END;
    _ssfsmIsEntryExit = false;
}

/* --------------------------------------------------------------------------------------------- */
/* Posts a new event to a state machine, processes it immediately if possible.                   */
/* --------------------------------------------------------------------------------------------- */
void SSFSMPutEventData(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data,
                       SSFSMDataLen_t dataLen)
{
    SSFSMEvent_t *e;

    SSF_REQUIRE(smid < SSF_SM_END);
    SSF_REQUIRE((eid > SSF_SM_EVENT_EXIT) && (eid < SSF_SM_EVENT_END));
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));
    SSF_ASSERT(_ssfsmIsInited);
    SSF_ASSERT(_SSFSMStates[smid].current != NULL);

    /* In state handler or there are pending events? */
    if ((_ssfsmActive < SSF_SM_END) || (SSFLLIsEmpty(&_ssfsmEvents) == false))
    {
        /* Must queue event */
        e = (SSFSMEvent_t *)SSFMPoolAlloc(&_ssfsmEventPool, sizeof(SSFSMEvent_t), 0x11);
        e->smid = smid;
        e->eid = eid;
        _SSFSMAllocEventData(e, data, dataLen);
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, e);
    } else _SSFSMProcessEvent(smid, eid, data, dataLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Record request for state transition.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSMTran(SSFSMHandler_t next)
{
    SSF_REQUIRE(next != NULL);
    SSF_ASSERT(_ssfsmActive < SSF_SM_END);
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
    SSFSMTimer_t *t;

    SSF_REQUIRE((eid > SSF_SM_EVENT_EXIT) && (eid < SSF_SM_EVENT_END));
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));
    SSF_ASSERT(_ssfsmActive < SSF_SM_END);
    SSF_ASSERT(_ssfsmIsInited);

    /* Does timer already exist? */
    t = _SSFSMFindTimer(eid);
    if (t != NULL)
    {
        /* Yes, update it with new timer request. */
        t->to = interval + SSFPortGetTick64();
        if ((t->event->data) && (t->event->dataLen > sizeof(SSFSMData_t *)))
        {_SSFSMFreeEventData(t->event->data); }
        _SSFSMAllocEventData(t->event, data, dataLen);
    } else
    {
        /* No, create new timer. */
        t = (SSFSMTimer_t *)SSFMPoolAlloc(&_ssfsmTimerPool, sizeof(SSFSMTimer_t), 0x22);
        t->event = (SSFSMEvent_t *)SSFMPoolAlloc(&_ssfsmEventPool, sizeof(SSFSMEvent_t), 0x33);
        t->to = interval + SSFPortGetTick64();
        t->event->smid = _ssfsmActive;
        t->event->eid = eid;
        _SSFSMAllocEventData(t->event, data, dataLen);
        SSF_LL_FIFO_PUSH(&_ssfsmTimers, t);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Stop timer for active state machine.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSMStopTimer(SSFSMEventId_t eid)
{
    SSFSMTimer_t *t;

    SSF_ASSERT(_ssfsmActive < SSF_SM_END);
    SSF_ASSERT(_ssfsmIsInited);

    t = _SSFSMFindTimer(eid);
    if (t != NULL)
    {
        SSFLLGetItem(&_ssfsmTimers, (SSFLLItem_t **)&t, SSF_LL_LOC_ITEM, (SSFLLItem_t *)t);
        if ((t->event->data) && (t->event->dataLen > sizeof(SSFSMData_t *)))
        {_SSFSMFreeEventData(t->event->data); }
        SSFMPoolFree(&_ssfsmEventPool, t->event);
        SSFMPoolFree(&_ssfsmTimerPool, t);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Call periodically from main loop. Returns true if timers are pending, else false.             */
/* --------------------------------------------------------------------------------------------- */
bool SSFSMTask(SSFSMTimeout_t *nextTimeout)
{
    SSFSMEvent_t *e;
    SSFSMTimer_t *t;
    SSFSMTimer_t *next;
    SSFSMTimeout_t current = SSFPortGetTick64();

    SSF_ASSERT(_ssfsmActive >= SSF_SM_END);
    SSF_ASSERT(_ssfsmIsInited);

    if (nextTimeout != NULL) *nextTimeout = SSF_SM_MAX_TIMEOUT;

    /* Process timers. */
    t = (SSFSMTimer_t *)SSF_LL_HEAD(&_ssfsmTimers);
    while (t != NULL)
    {
        next = (SSFSMTimer_t *)SSF_LL_NEXT_ITEM((SSFLLItem_t *)t);
        if ((nextTimeout != NULL) && (t->to < (*nextTimeout))) *nextTimeout = t->to;
        if (t->to > current)
        {t = next; continue; }
        SSFLLGetItem(&_ssfsmTimers, (SSFLLItem_t **)&t, SSF_LL_LOC_ITEM, (SSFLLItem_t *)t);
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, (SSFLLItem_t *)t->event);
        SSFMPoolFree(&_ssfsmTimerPool, t);
        t = next;
    }

    /* Process all pending events. */
    while (SSF_LL_FIFO_POP(&_ssfsmEvents, (SSFLLItem_t **)&e) == true)
    {
        if (e->dataLen > sizeof(SSFSMData_t *))
        {_SSFSMProcessEvent(e->smid, e->eid, e->data, e->dataLen); }
        else _SSFSMProcessEvent(e->smid, e->eid, (SSFSMData_t *)&e->data, e->dataLen);
        if ((e->data != NULL) && (e->dataLen > sizeof(SSFSMData_t *)))
        {_SSFSMFreeEventData(e->data); }
        SSFMPoolFree(&_ssfsmEventPool, e);
    }
    return !SSFLLIsEmpty(&_ssfsmTimers);
}

