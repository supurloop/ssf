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
typedef struct
{
    SSFSMHandler_t current;
    SSFSMHandler_t next;
} SSFSMState_t;

typedef struct
{
    SSFLLItem_t item;
    SSFSMId_t smid;
    SSFSMEventId_t eid;
    SSFSMDataLen_t dataLen;
    SSFSMData_t *data;
} SSFSMEvent_t;

typedef struct
{
    SSFLLItem_t item;
    SSFSMEvent_t *event;
    SSFSMTimeout_t to;
    SSFSMHandler_t owner;
} SSFSMTimer_t;

/* --------------------------------------------------------------------------------------------- */
/* Module variables                                                                              */
/* --------------------------------------------------------------------------------------------- */
static SSFSMState_t _SSFSMStates[SSF_SM_MAX];
static SSFSMId_t _ssfsmActive = SSF_SM_MAX;
static SSFSMId_t _ssfsmIsEntryExit;
static SSFSMHandler_t _ssfsmHandler; /* Handler whose code is executing; owns timers it starts */
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

        /* Same state machine and owner? */
        if ((t.event->smid == _ssfsmActive) && (t.owner == _ssfsmHandler))
        {
            /* Yes, any allocated event data? */
            if ((t.event->data != NULL) && (t.event->dataLen > sizeof(SSFSMData_t *)))
            {
                /* Yes, free it. */
                _SSFSMFreeEventData(t.event->data);
            }
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

    SSF_REQUIRE((eid > SSF_SM_EVENT_SUPER) && (eid < SSF_SM_EVENT_MAX));
    SSF_ASSERT((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX));

    item = SSF_LL_HEAD(&_ssfsmTimers);
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        memcpy(&t, item, sizeof(t));

        /* Same state machine, event ID, and owner? */
        if ((t.event->smid == _ssfsmActive) && (t.event->eid == eid) &&
            (t.owner == _ssfsmHandler))
        {
            /* Yes, found it */
            break;
        }
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
    SSFSMHandler_t currentSuper;
    SSFSMHandler_t nextSuper;
    SSFSMHandler_t super;

    SSF_REQUIRE((smid > SSF_SM_MIN) && (smid < SSF_SM_MAX));
    SSF_REQUIRE((eid > SSF_SM_EVENT_SUPER) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE((dataLen == 0) || (data != NULL));
    SSF_ASSERT(_ssfsmIsInited);
    SSF_ASSERT(_ssfsmActive >= SSF_SM_MAX);

    /* Process event in context of current state */
    _ssfsmActive = smid;
    currentSuper = NULL;
    SSF_ASSERT(_SSFSMStates[_ssfsmActive].current != NULL);
    _ssfsmHandler = _SSFSMStates[_ssfsmActive].current;
    _SSFSMStates[_ssfsmActive].current(eid, data, dataLen, (SSFVoidFn_t *)&currentSuper);

    /* Should super state also process event? */
    if (currentSuper != NULL)
    {
        /* Yes, let super state process the event; timers it starts belong to the super */
        super = NULL;
        _ssfsmHandler = currentSuper;
        currentSuper(eid, data, dataLen, (SSFVoidFn_t *)&super);
        SSF_ASSERT(super == NULL);
    }

    /* State transition requested? */
    if (_SSFSMStates[_ssfsmActive].next != NULL)
    {
        /* Yes, perform state transition */
        _ssfsmIsEntryExit = true;

        /* Determine current super state */
        currentSuper = NULL;
        _SSFSMStates[_ssfsmActive].current(SSF_SM_EVENT_SUPER, NULL, 0, (SSFVoidFn_t *)&currentSuper);
        SSF_ASSERT(currentSuper != _SSFSMStates[_ssfsmActive].current);

        /* Determine next super state */
        nextSuper = NULL;
        _SSFSMStates[_ssfsmActive].next(SSF_SM_EVENT_SUPER, NULL, 0, (SSFVoidFn_t *)&nextSuper);
        SSF_ASSERT(nextSuper != _SSFSMStates[_ssfsmActive].next);

        /* Exit current state; its timers go with it */
        _ssfsmHandler = _SSFSMStates[_ssfsmActive].current;
        _SSFSMStates[_ssfsmActive].current(SSF_SM_EVENT_EXIT, NULL, 0, (SSFVoidFn_t *)&super);
        _SSFSMStopAllTimers();

        /* Different supers? */
        if (currentSuper != nextSuper)
        {
            /* Yes, does current have a super? */
            if (currentSuper != NULL)
            {
                /* Yes, exit current super state; its timers go with it */
                _SSFSMStates[_ssfsmActive].current = currentSuper;
                _ssfsmHandler = currentSuper;
                _SSFSMStates[_ssfsmActive].current(SSF_SM_EVENT_EXIT, NULL, 0, (SSFVoidFn_t *)&super);
                _SSFSMStopAllTimers();
            }

            /* Does next have a super? */
            if (nextSuper != NULL)
            {
                /* Yes, enter next super */
                _SSFSMStates[_ssfsmActive].current = nextSuper;
                _ssfsmHandler = nextSuper;
                _SSFSMStates[_ssfsmActive].current(SSF_SM_EVENT_ENTRY, NULL, 0, (SSFVoidFn_t *)&super);
            }
        }

        /* Enter next state */
        _SSFSMStates[_ssfsmActive].current = _SSFSMStates[_ssfsmActive].next;
        _SSFSMStates[_ssfsmActive].next = NULL;
        _ssfsmHandler = _SSFSMStates[_ssfsmActive].current;
        _SSFSMStates[_ssfsmActive].current(SSF_SM_EVENT_ENTRY, NULL, 0, (SSFVoidFn_t *)&super);

        /* End of state transition */
        _ssfsmIsEntryExit = false;
    }
    _ssfsmHandler = NULL;
    _ssfsmActive = SSF_SM_MAX;
}

/* --------------------------------------------------------------------------------------------- */
/* Allocates event data.                                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMAllocEventData(SSFSMEvent_t *event, const SSFSMData_t *data,
                                 SSFSMDataLen_t dataLen)
{
    SSF_REQUIRE(event != NULL);
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));

    event->dataLen = dataLen;

    /* No event data? */
    if (event->dataLen == 0)
    {
        /* Yes, no data to store */
        event->data = NULL;
    }
    /* No, does event data fit in the data pointer? */
    else if (event->dataLen <= sizeof(SSFSMData_t *))
    {
        /* Yes, store event data in the data pointer */
        memcpy(&(event->data), data, event->dataLen);
    }
    else
    {
        /* No, allocate storage for event data */
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

    SSFMPoolInit(&_ssfsmEventPool, maxEvents + maxTimers, sizeof(SSFSMEvent_t));
    SSFMPoolInit(&_ssfsmTimerPool, maxTimers, sizeof(SSFSMTimer_t));
    SSFLLInit(&_ssfsmEvents, maxEvents + maxTimers);
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
        next = SSF_LL_NEXT_ITEM(item);
        memcpy(&t, item, sizeof(t));
        SSFLLGetItem(&_ssfsmTimers, &item, SSF_LL_LOC_ITEM, item);

        /* Any allocated event data? */
        if ((t.event->data != NULL) && (t.event->dataLen > sizeof(SSFSMData_t *)))
        {
            /* Yes, free it */
            _SSFSMFreeEventData(t.event->data);
        }
        SSFMPoolFree(&_ssfsmEventPool, t.event);
        SSFMPoolFree(&_ssfsmTimerPool, item);
        item = next;
    }

    /* Process all pending events and free event data. */
    item = SSF_LL_HEAD(&_ssfsmEvents);
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        memcpy(&e, item, sizeof(e));
        SSFLLGetItem(&_ssfsmEvents, &item, SSF_LL_LOC_ITEM, item);

        /* Any allocated event data? */
        if ((e.data != NULL) && (e.dataLen > sizeof(SSFSMData_t *)))
        {
            /* Yes, free it */
            _SSFSMFreeEventData(e.data);
        }
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
    SSFSMHandler_t initialSuper;
    SSFSMHandler_t super;

    SSF_REQUIRE((smid > SSF_SM_MIN) && (smid < SSF_SM_MAX));
    SSF_REQUIRE(initial != NULL);
    SSF_ASSERT(_ssfsmIsInited);
    SSF_ASSERT(_ssfsmActive >= SSF_SM_MAX);
    SSF_ASSERT(_SSFSMStates[smid].current == NULL);

    /* Allow state transitions */
    _ssfsmActive = smid;
    _ssfsmIsEntryExit = true;

    /* Determine initial's super */
    initialSuper = NULL;
    initial(SSF_SM_EVENT_SUPER, NULL, 0, (SSFVoidFn_t *)&initialSuper);
    SSF_ASSERT(initial != initialSuper);

    /* Does initial have a super? */
    if (initialSuper != NULL)
    {
        /* Yes, ensure super does not have super */
        super = NULL;
        initialSuper(SSF_SM_EVENT_SUPER, NULL, 0, (SSFVoidFn_t *)&super);
        SSF_ASSERT(super == NULL);

        /* Enter initial super */
        _SSFSMStates[smid].current = initialSuper;
        _ssfsmHandler = initialSuper;
        _SSFSMStates[smid].current(SSF_SM_EVENT_ENTRY, NULL, 0, (SSFVoidFn_t *)&super);
    }

    /* Enter initial state */
    _SSFSMStates[smid].current = initial;
    _ssfsmHandler = initial;
    _SSFSMStates[smid].current(SSF_SM_EVENT_ENTRY, NULL, 0, (SSFVoidFn_t *)&super);

    /* Disallow state transitions */
    _ssfsmHandler = NULL;
    _ssfsmActive = SSF_SM_MAX;
    _ssfsmIsEntryExit = false;
}

/* --------------------------------------------------------------------------------------------- */
/* DeInitializes a state machine handler.                                                        */
/* --------------------------------------------------------------------------------------------- */
void SSFSMDeInitHandler(SSFSMId_t smid)
{
    SSFSMHandler_t currentSuper;
    SSFSMHandler_t super;

    SSF_REQUIRE((smid > SSF_SM_MIN) && (smid < SSF_SM_MAX));
    SSF_ASSERT(_ssfsmIsInited);
    SSF_ASSERT(_ssfsmActive >= SSF_SM_MAX);
    SSF_ASSERT(_SSFSMStates[smid].current != NULL);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_SYNC_ACQUIRE();
#endif

    _ssfsmActive = smid;
    _ssfsmIsEntryExit = true;

    /* Determine current's super */
    currentSuper = NULL;
    _SSFSMStates[smid].current(SSF_SM_EVENT_SUPER, NULL, 0, (SSFVoidFn_t *)&currentSuper);
    SSF_ASSERT(currentSuper != _SSFSMStates[smid].current);

    /* Exit current state */
    _ssfsmHandler = _SSFSMStates[smid].current;
    _SSFSMStates[smid].current(SSF_SM_EVENT_EXIT, NULL, 0, (SSFVoidFn_t *)&super);
    _SSFSMStopAllTimers();

    /* Does current have a super? */
    if (currentSuper != NULL)
    {
        /* Yes, ensure super does not have super */
        super = NULL;
        currentSuper(SSF_SM_EVENT_SUPER, NULL, 0, (SSFVoidFn_t *)&super);
        SSF_ASSERT(super == NULL);

        /* Exit current super */
        _SSFSMStates[smid].current = currentSuper;
        _ssfsmHandler = currentSuper;
        _SSFSMStates[smid].current(SSF_SM_EVENT_EXIT, NULL, 0, (SSFVoidFn_t *)&super);
        _SSFSMStopAllTimers();
    }

    _ssfsmHandler = NULL;
    _ssfsmActive = SSF_SM_MAX;
    _ssfsmIsEntryExit = false;

    /* Reset the state machine */
    memset(&_SSFSMStates[smid], 0, sizeof(SSFSMState_t));
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_SYNC_RELEASE();
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Posts a new event to a state machine, processes it immediately if possible.                   */
/* --------------------------------------------------------------------------------------------- */
void SSFSMPutEventData(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data,
                       SSFSMDataLen_t dataLen)
{
    SSFSMEvent_t *e;

    SSF_REQUIRE((smid > SSF_SM_MIN) && (smid < SSF_SM_MAX));
    SSF_REQUIRE((eid > SSF_SM_EVENT_SUPER) && (eid < SSF_SM_EVENT_MAX));
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));
    SSF_ASSERT(_ssfsmIsInited);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 0
    SSF_ASSERT(_SSFSMStates[smid].current != NULL);
    /* In state handler or there are pending events? */
    if (((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX)) ||
        (SSFLLIsEmpty(&_ssfsmEvents) == false))
    {
#endif
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
        SSF_SM_THREAD_SYNC_ACQUIRE();
        SSF_ASSERT(_SSFSMStates[smid].current != NULL);
#endif
        /* Yes, queue event */
        e = (SSFSMEvent_t *)SSFMPoolAlloc(&_ssfsmEventPool, sizeof(SSFSMEvent_t), 0x11);
        e->smid = smid;
        e->eid = eid;
        _SSFSMAllocEventData(e, data, dataLen);
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, e);
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
        SSF_SM_THREAD_WAKE_POST();
        SSF_SM_THREAD_SYNC_RELEASE();
#else
    /* No, process event right now */
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

    SSF_REQUIRE((eid > SSF_SM_EVENT_SUPER) && (eid < SSF_SM_EVENT_MAX));
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
    SSF_ASSERT(_ssfsmHandler != NULL);
    tp->owner = _ssfsmHandler;
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

    SSF_REQUIRE((eid > SSF_SM_EVENT_SUPER) && (eid < SSF_SM_EVENT_MAX));
    SSF_ASSERT((_ssfsmActive > SSF_SM_MIN) && (_ssfsmActive < SSF_SM_MAX));
    SSF_ASSERT(_ssfsmIsInited);

    item = _SSFSMFindTimer(eid);

    /* Timer running? */
    if (item != NULL)
    {
        /* Yes, stop it */
        SSFLLGetItem(&_ssfsmTimers, &item, SSF_LL_LOC_ITEM, item);
        memcpy(&t, item, sizeof(t));

        /* Any allocated event data? */
        if ((t.event->data != NULL) && (t.event->dataLen > sizeof(SSFSMData_t *)))
        {
            /* Yes, free it */
            _SSFSMFreeEventData(t.event->data);
        }
        SSFMPoolFree(&_ssfsmEventPool, t.event);
        SSFMPoolFree(&_ssfsmTimerPool, item);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Processes pending events and expired timers, returns true if timers are pending, else false.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFSMTask(SSFPortTick_t *nextTimeoutOpt)
{
    SSFSMEvent_t e;
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    SSFSMTimer_t t;
    SSFPortTick_t current = SSFPortGetTick64();
    bool retVal;

    SSF_ASSERT(_ssfsmActive >= SSF_SM_MAX);
    SSF_ASSERT(_ssfsmIsInited);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_SYNC_ACQUIRE();
#endif

    /* Process all pending events. */
processEvents:
    while (SSF_LL_FIFO_POP(&_ssfsmEvents, &item) == true)
    {
        memcpy(&e, item, sizeof(e)); /* Ensure alignment */

        /* Is event data allocated? */
        if (e.dataLen > sizeof(SSFSMData_t *))
        {
            /* Yes, pass allocated event data */
            _SSFSMProcessEvent(e.smid, e.eid, e.data, e.dataLen);
        }
        else
        {
            /* No, pass event data stored in the data pointer */
            _SSFSMProcessEvent(e.smid, e.eid, (SSFSMData_t *)&e.data, e.dataLen);
        }

        /* Any allocated event data? */
        if ((e.data != NULL) && (e.dataLen > sizeof(SSFSMData_t *)))
        {
            /* Yes, free it */
            _SSFSMFreeEventData(e.data);
        }
        SSFMPoolFree(&_ssfsmEventPool, item);
    }

    /* Process timers. */
    item = SSF_LL_HEAD(&_ssfsmTimers);
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        memcpy(&t, item, sizeof(t)); /* Ensure alignment */

        /* Timer not yet expired? */
        if (t.to > current)
        {
            /* Yes, check next timer */
            item = next;
            continue;
        }

        /* No, queue the timer event and process it */
        SSFLLGetItem(&_ssfsmTimers, &item, SSF_LL_LOC_ITEM, item);
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, (SSFLLItem_t*)t.event);
        SSFMPoolFree(&_ssfsmTimerPool, item);
        item = next;
        goto processEvents;
    }

    /* Next timer expiration requested? */
    if (nextTimeoutOpt != NULL)
    {
        /* Yes, find the earliest timer expiration */
        SSFPortTick_t minTo = SSF_MAX_NEXT_TIMEOUT;

        item = SSF_LL_HEAD(&_ssfsmTimers);
        while (item != NULL)
        {
            next = SSF_LL_NEXT_ITEM(item);
            memcpy(&t, item, sizeof(t));
            if (t.to < minTo) { minTo = t.to; }
            item = next;
        }

        /* Any timers running? */
        if (minTo != SSF_MAX_NEXT_TIMEOUT)
        {
            /* Yes, report time remaining if sooner than caller's timeout */
            SSFPortTick_t remaining = (minTo > current) ? (minTo - current) : 0;

            if (remaining < *nextTimeoutOpt) { *nextTimeoutOpt = remaining; }
        }
    }
    retVal = (SSFLLIsEmpty(&_ssfsmTimers) == false);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_SM_THREAD_SYNC_RELEASE();
#endif
    return retVal;
}

