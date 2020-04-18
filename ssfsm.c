#include <stdlib.h>
#include <string.h>

#include "ssfll.h"
#include "ssfsm.h"
#include "ssfmpool.h"
#include "ssfassert.h"

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

static SSFSMState_t _SSFSMStates[SSF_SM_END];
SSFSMId_t _ssfsmActive = SSF_SM_END; /* make this reentrant??  would need to create full SM object.... */
SSFSMId_t _ssfsmIsEntryExit; /* make this reentrant?? */

SSFMPool_t _ssfsmEventPool;
SSFMPool_t _ssfsmTimerPool;
SSFLL_t _ssfsmEvents;
SSFLL_t _ssfsmTimers;

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMStopAllTimers(void)
{
    SSFSMTimer_t* t;
    SSFSMTimer_t* next;

    SSF_ASSERT(_ssfsmActive < SSF_SM_END);

    t = (SSFSMTimer_t*)SSF_LL_HEAD(&_ssfsmTimers);
    while (t != NULL)
    {
        next = (SSFSMTimer_t*)SSF_LL_NEXT_ITEM((SSFLLItem_t*)t);
        if (t->event->smid == _ssfsmActive)
        {
            SSFLLGetItem(&_ssfsmTimers, (SSFLLItem_t**)&t, SSF_LL_LOC_ITEM, (SSFLLItem_t*)t);
            SSFMPoolFree(&_ssfsmEventPool, t->event);
            SSFMPoolFree(&_ssfsmTimerPool, t);
        }
        t = next;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static SSFSMTimer_t* _SSFSMFindTimer(SSFSMEventId_t eid)
{
    SSFSMTimer_t* t;
    SSFSMTimer_t* next;

    SSF_ASSERT(_ssfsmActive < SSF_SM_END);

    t = (SSFSMTimer_t*)SSF_LL_HEAD(&_ssfsmTimers);
    while (t != NULL)
    {
        next = (SSFSMTimer_t*)SSF_LL_NEXT_ITEM((SSFLLItem_t*)t);
        if ((t->event->smid == _ssfsmActive) && (t->event->eid == eid)) break;
        t = next;
    }
    return t;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSMProcessEvent(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t* data, SSFSMDataLen_t dataLen)
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
/* --------------------------------------------------------------------------------------------- */
void SSFSMInit(SSFSMId_t smid, SSFSMHandler_t initial, uint32_t maxEvents, uint32_t maxTimers)
{
    SSF_REQUIRE(smid < SSF_SM_END);
    SSF_REQUIRE(initial != NULL);

    SSFMPoolInit(&_ssfsmEventPool, maxEvents + maxTimers, sizeof(SSFSMEvent_t));
    SSFMPoolInit(&_ssfsmTimerPool, maxTimers, sizeof(SSFSMTimer_t));
    SSFLLInit(&_ssfsmEvents, maxEvents + maxTimers);
    SSFLLInit(&_ssfsmTimers, maxTimers);

    _SSFSMStates[smid].current = initial;
    _ssfsmActive = smid;
    _ssfsmIsEntryExit = true;
    _SSFSMStates[smid].current(SSF_SM_EVENT_ENTRY, NULL, 0);
    _ssfsmActive = SSF_SM_END;
    _ssfsmIsEntryExit = false;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFSMPutEventData(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
{
    SSFSMEvent_t* e;

    SSF_REQUIRE(smid < SSF_SM_END);
    SSF_REQUIRE(eid < SSF_SM_EVENT_END);
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));

    /* In state handler or there are pending events? */
    if ((_ssfsmActive < SSF_SM_END) || (SSFLLIsEmpty(&_ssfsmEvents) == false))
    {
        /* Must queue event */
        e = (SSFSMEvent_t*)SSFMPoolAlloc(&_ssfsmEventPool, sizeof(SSFSMEvent_t*), 0x11);
        e->smid = smid;
        e->eid = eid;
        e->dataLen = dataLen;
        if (e->dataLen > 0) SSF_ASSERT((e->data = (SSFSMData_t*)malloc(e->dataLen)) != NULL);
        else e->data = NULL;
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, e);
    }
    else _SSFSMProcessEvent(smid, eid, data, dataLen);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFSMTran(SSFSMHandler_t next)
{
    SSF_REQUIRE(next != NULL);
    SSF_ASSERT(_ssfsmActive < SSF_SM_END);
    SSF_ASSERT(_SSFSMStates[_ssfsmActive].next == NULL);
    SSF_ASSERT(_ssfsmIsEntryExit == false);

    _SSFSMStates[_ssfsmActive].next = next;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFSMStartTimerData(SSFSMEventId_t eid, SSFSMTimeout_t interval, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
{
    SSFSMTimer_t* t;

    SSF_REQUIRE(eid < SSF_SM_EVENT_END);
    SSF_REQUIRE(((data == NULL) && (dataLen == 0)) || ((data != NULL) && (dataLen > 0)));
    SSF_ASSERT(_ssfsmActive < SSF_SM_END);

    if (interval == 0)
    {
        SSFSMPutEventData(_ssfsmActive, eid, data, dataLen);
        return;
    }

    t = _SSFSMFindTimer(eid);
    if (t != NULL)
    {
        t->to = interval + SSFSMGetTick64();

        if (t->event->dataLen > 0 && dataLen > 0)
        {
            if (t->event->dataLen != dataLen)
            {
                free(t->event->data);
                SSF_ASSERT((t->event->data = (SSFSMData_t*)malloc(dataLen)) != NULL);
            }
            memcpy(t->event->data, data, dataLen);
        }
        else if (t->event->dataLen > 0 && dataLen == 0)
        {
            free(t->event->data);
            t->event->data = NULL;
        }
        else if (t->event->dataLen == 0 && dataLen > 0)
        {
            SSF_ASSERT((t->event->data = (SSFSMData_t*)malloc(dataLen)) != NULL);
            memcpy(t->event->data, data, dataLen);
        }
        else
        {
            t->event->data = NULL;
        }
        t->event->dataLen = dataLen;
    }
    else
    {
        t = (SSFSMTimer_t*)SSFMPoolAlloc(&_ssfsmTimerPool, sizeof(SSFSMTimer_t*), 0x22);
        t->event = (SSFSMEvent_t*)SSFMPoolAlloc(&_ssfsmEventPool, sizeof(SSFSMEvent_t*), 0x33);
        t->to = interval + SSFSMGetTick64();
        t->event->smid = _ssfsmActive;
        t->event->eid = eid;
        t->event->dataLen = dataLen;
        if (t->event->dataLen > 0) 
        {
            SSF_ASSERT((t->event->data = (SSFSMData_t*)malloc(t->event->dataLen)) != NULL);
            memcpy(t->event->data, data, t->event->dataLen);
        }
        else t->event->data = NULL;
        SSF_LL_FIFO_PUSH(&_ssfsmTimers, t);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFSMStopTimer(SSFSMEventId_t eid)
{
    SSFSMTimer_t* t;

    SSF_ASSERT(_ssfsmActive < SSF_SM_END);

    t = _SSFSMFindTimer(eid);
    if (t != NULL)
    {
        SSFLLGetItem(&_ssfsmTimers, (SSFLLItem_t**)&t, SSF_LL_LOC_ITEM, (SSFLLItem_t*)t);
        SSF_LL_FIFO_PUSH(&_ssfsmEvents, (SSFLLItem_t*)t->event);
        if (t->event->data != NULL) free(t->event->data);
        SSFMPoolFree(&_ssfsmEventPool, t->event);
        SSFMPoolFree(&_ssfsmTimerPool, t);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFSMTask(void)
{
    SSFSMEvent_t* e;
    SSFSMTimer_t* t;
    SSFSMTimer_t* next;
    SSFSMTimeout_t current = SSFSMGetTick64();

    SSF_ASSERT(_ssfsmActive >= SSF_SM_END);

    t = (SSFSMTimer_t *) SSF_LL_HEAD(&_ssfsmTimers);
    while (t != NULL)
    {
        next = (SSFSMTimer_t*)SSF_LL_NEXT_ITEM((SSFLLItem_t*)t);
        if (t->to <= current)
        {
            SSFLLGetItem(&_ssfsmTimers, (SSFLLItem_t**)&t, SSF_LL_LOC_ITEM, (SSFLLItem_t*)t);
            SSF_LL_FIFO_PUSH(&_ssfsmEvents, (SSFLLItem_t*)t->event);
            SSFMPoolFree(&_ssfsmTimerPool, t);
        }
        t = next;
    }

    while (SSF_LL_FIFO_POP(&_ssfsmEvents, (SSFLLItem_t**) &e) == true)
    {
        _SSFSMProcessEvent(e->smid, e->eid, e->data, e->dataLen);
        if (e->data != NULL) free(e->data);
        SSFMPoolFree(&_ssfsmEventPool, e);
    }

    return SSFLLIsEmpty(&_ssfsmTimers);
}