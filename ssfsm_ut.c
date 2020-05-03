/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsm_ut.c                                                                                    */
/* Provides unit tests for ssfsm's state machine framework.                                      */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfsm.h"
#include "ssfport.h"
#include "ssfassert.h"

#if SSF_CONFIG_SM_UNIT_TEST == 1

    #define SSFSM_UT_MAX_EVENTS (4u)
    #define SSFSM_UT_MAX_TIMERS (2u)
    #define SSFSM_UT_NUM_SMS (SSF_SM_UNIT_TEST_2 + 1u)
    #define SSFSM_UT_NUM_HANDLERS (2u)
    #define SSFSM_UT_NUM_EVENTS (SSF_SM_EVENT_UTX_2 + 1u)
    #define SSF_ASSERT_CLEAR(sm, sh, ev) SSF_ASSERT(_ssfsmFlags[sm][sh][ev]); \
                                     _ssfsmFlags[sm][sh][ev] = false;


static bool _ssfsmFlags[SSFSM_UT_NUM_SMS][SSFSM_UT_NUM_HANDLERS][SSFSM_UT_NUM_EVENTS];

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all flags are cleared, else false.                                            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFSMFlagsAreCleared(void)
{
    uint8_t i;
    uint8_t j;
    uint8_t k;

    for (i = 0; i < SSFSM_UT_NUM_SMS; i++)
    {
        for (j = 0; j < SSFSM_UT_NUM_HANDLERS; j++)
        {
            for (k = 0; k < SSFSM_UT_NUM_EVENTS; k++)
            {
                if (_ssfsmFlags[i][j][k] == true) return false;
            }
        }
    }
    return true;
}

/* State handler prototypes */
void UT1TestHandler1(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);
void UT1TestHandler2(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);
void UT2TestHandler1(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);
void UT2TestHandler2(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);

/* --------------------------------------------------------------------------------------------- */
/* State machine 1 test handler 1.                                                               */
/* --------------------------------------------------------------------------------------------- */
void UT1TestHandler1(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
{
    SSF_ASSERT(_ssfsmFlags[SSF_SM_UNIT_TEST_1][0][eid] == false);
    _ssfsmFlags[SSF_SM_UNIT_TEST_1][0][eid] = true;

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_UT1_1:
        break;
    case SSF_SM_EVENT_UT1_2:
        SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_1);
        SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_1);
        SSFSMPutEvent(SSF_SM_UNIT_TEST_2, SSF_SM_EVENT_UT1_1);
        SSFSMPutEvent(SSF_SM_UNIT_TEST_2, SSF_SM_EVENT_UT1_2);
        SSF_ASSERT_TEST(SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_1));
        break;
    case SSF_SM_EVENT_UTX_1:
        if ((data != NULL) && (dataLen == 1))
        {
            char ed;
            SSF_SM_EVENT_DATA_ALIGN(ed);
            if (ed == 't')
            {
                SSFSMStartTimer(SSF_SM_EVENT_UT1_1, SSF_TICKS_PER_SEC);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_2, SSF_TICKS_PER_SEC << 1, "a", 1);
                SSF_ASSERT_TEST(SSFSMStartTimer(SSF_SM_EVENT_UT1_2, SSF_TICKS_PER_SEC << 1));
            }
        }
        break;
    case SSF_SM_EVENT_UTX_2:
        if ((data != NULL) && (dataLen == 1))
        {
            char ed;
            SSF_SM_EVENT_DATA_ALIGN(ed);
            if (ed == 'a') SSFSMTran(UT1TestHandler2);
            SSF_ASSERT_TEST(SSFSMTran(UT1TestHandler1));
        }
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* State machine 1 test handler 2.                                                               */
/* --------------------------------------------------------------------------------------------- */
void UT1TestHandler2(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
{
    SSF_ASSERT(_ssfsmFlags[SSF_SM_UNIT_TEST_1][1][eid] == false);
    _ssfsmFlags[SSF_SM_UNIT_TEST_1][1][eid] = true;

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_UT1_1:
        break;
    case SSF_SM_EVENT_UT1_2:
        break;
    case SSF_SM_EVENT_UTX_1:
        break;
    case SSF_SM_EVENT_UTX_2:
        SSF_ASSERT_TEST(SSFSMTran(UT1TestHandler2));
        if ((data != NULL) && (dataLen == 10))
        {
            char ed[10];
            SSF_SM_EVENT_DATA_ALIGN(ed);
            if (memcmp(ed, "1234567890", 10) == 0) SSFSMTran(UT1TestHandler1);
            SSF_ASSERT_TEST(SSFSMTran(UT1TestHandler1));
        }
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* State machine 2 test handler 1.                                                               */
/* --------------------------------------------------------------------------------------------- */
void UT2TestHandler1(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
{
    SSF_ASSERT(_ssfsmFlags[SSF_SM_UNIT_TEST_2][0][eid] == false);
    _ssfsmFlags[SSF_SM_UNIT_TEST_2][0][eid] = true;

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_UT2_1:
        if ((data != NULL) && (dataLen == 1))
        {
            char ed;
            SSF_SM_EVENT_DATA_ALIGN(ed);
            if (ed == 'd')
            {
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_1, SSF_TICKS_PER_SEC * 4, "1234567890", 10);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_2, SSF_TICKS_PER_SEC * 4, "1234567890", 10);
                SSFSMTran(UT2TestHandler2);
            }
        }
        break;
    case SSF_SM_EVENT_UT2_2:
        break;
    case SSF_SM_EVENT_UTX_1:
        SSFSMStopTimer(SSF_SM_EVENT_UT1_1);
        break;
    case SSF_SM_EVENT_UTX_2:
        if ((data != NULL) && (dataLen == 1))
        {
            char ed;
            SSF_SM_EVENT_DATA_ALIGN(ed);
            if (ed == 't')
            {
                SSFSMStartTimer(SSF_SM_EVENT_UT1_1, SSF_TICKS_PER_SEC * 2);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_1, SSF_TICKS_PER_SEC, "a", 1);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_1, SSF_TICKS_PER_SEC * 2, "b", 1);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_1, SSF_TICKS_PER_SEC * 3, "c", 1);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_1, SSF_TICKS_PER_SEC * 4, "1234567890", 10);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_1, SSF_TICKS_PER_SEC * 5,
                                    "12345678901234567890", 20);
                SSFSMStartTimerData(SSF_SM_EVENT_UTX_1, SSF_TICKS_PER_SEC,
                                    "123456789012345678901234567890", 30);
                SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_1, "p", 1);
                SSF_ASSERT_TEST(SSFSMStartTimer(SSF_SM_EVENT_UT1_2, SSF_TICKS_PER_SEC << 1));
            }
        }
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* State machine 2 test handler 2.                                                               */
/* --------------------------------------------------------------------------------------------- */
void UT2TestHandler2(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
{
    SSF_ASSERT(_ssfsmFlags[SSF_SM_UNIT_TEST_2][1][eid] == false);
    _ssfsmFlags[SSF_SM_UNIT_TEST_2][1][eid] = true;

    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        SSFSMStartTimerData(SSF_SM_EVENT_UT2_2, SSF_TICKS_PER_SEC * 2, "12345678901234567890", 20);
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_UT2_1:
        break;
    case SSF_SM_EVENT_UT2_2:
        if ((data != NULL) && (dataLen == 20))
        {
            char ed[20];
            SSF_SM_EVENT_DATA_ALIGN(ed);
            SSF_ASSERT(memcmp(ed, "12345678901234567890", 10) == 0);
            SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT2_2);
        }
        break;
    case SSF_SM_EVENT_UTX_1:
        break;
    case SSF_SM_EVENT_UTX_2:
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfll's external interface.                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFSMUnitTest()
{
    SSFSMTimeout_t nextTimeout;
    SSFSMTimeout_t lastTimeout;
    SSFSMTimeout_t start;
    SSFSMTimeout_t delta;

    memset(_ssfsmFlags, 0, sizeof(_ssfsmFlags));
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSF_ASSERT_TEST(SSFSMInitHandler(SSF_SM_UNIT_TEST_1, UT1TestHandler1));
    SSF_ASSERT_TEST(SSFSMInitHandler(SSF_SM_UNIT_TEST_2, UT2TestHandler1));
    SSF_ASSERT_TEST(SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_1));
    SSF_ASSERT_TEST(SSFSMTask(NULL));
    SSF_ASSERT_TEST(SSFSMTask(&nextTimeout));

    SSFSMInit(SSFSM_UT_MAX_EVENTS, SSFSM_UT_MAX_TIMERS);
    SSF_ASSERT_TEST(SSFSMInit(SSFSM_UT_MAX_EVENTS, SSFSM_UT_MAX_TIMERS));
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMInitHandler(SSF_SM_UNIT_TEST_1, UT1TestHandler1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_ENTRY);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UT1_1);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMInitHandler(SSF_SM_UNIT_TEST_2, UT2TestHandler1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 0, SSF_SM_EVENT_ENTRY);
    SSF_ASSERT(_SSFSMFlagsAreCleared());

    SSF_ASSERT_TEST(SSFSMTran(UT1TestHandler2));
    SSF_ASSERT_TEST(SSFSMStartTimerData(SSF_SM_EVENT_UT1_1, 1, "a", 1));
    SSF_ASSERT_TEST(SSFSMStartTimer(SSF_SM_EVENT_UT1_1, 1));
    SSF_ASSERT_TEST(SSFSMStopTimer(SSF_SM_EVENT_UT1_1));
    SSF_ASSERT_TEST(SSFSMPutEvent(SSF_SM_END, SSF_SM_EVENT_UT1_1));
    SSF_ASSERT_TEST(SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_END));
    SSF_ASSERT_TEST(SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_ENTRY));
    SSF_ASSERT_TEST(SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_EXIT));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_END, SSF_SM_EVENT_UT1_1, NULL, 0));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_END, NULL, 0));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_ENTRY, NULL, 0));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_EXIT, NULL, 0));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_1, "a", 0));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_1, NULL, 1));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_END, SSF_SM_EVENT_UT1_1, "a", 1));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_END, "a", 1));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_ENTRY, "a", 1));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_EXIT, "a", 1));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_END, SSF_SM_EVENT_UT1_1, "1234567890", 10));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_END, "1234567890", 10));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_ENTRY, "1234567890", 10));
    SSF_ASSERT_TEST(SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_EXIT, "1234567890", 10));
    SSF_ASSERT(SSFSMTask(NULL) == false);
    nextTimeout = 0;
    SSF_ASSERT(SSFSMTask(&nextTimeout) == false);
    SSF_ASSERT(nextTimeout == SSF_SM_MAX_TIMEOUT);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UT1_2);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UT1_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    nextTimeout = 0;
    SSF_ASSERT(SSFSMTask(&nextTimeout) == false);
    SSF_ASSERT(nextTimeout == SSF_SM_MAX_TIMEOUT);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UT1_1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UTX_1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 0, SSF_SM_EVENT_UT1_1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 0, SSF_SM_EVENT_UT1_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEvent(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_2, NULL, 0);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_2, "a", 1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_EXIT);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_ENTRY);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_2, NULL, 0);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_2, "a", 1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_2, "1234567890", 10);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_EXIT);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_ENTRY);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    start = SSFSMGetTick64();
    SSFSMPutEventData(SSF_SM_UNIT_TEST_1, SSF_SM_EVENT_UTX_1, "t", 1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UTX_1);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    nextTimeout = 0;
    SSF_ASSERT(SSFSMTask(&nextTimeout) == true);
    delta = nextTimeout - start;
    SSF_ASSERT((delta > (0.9 * SSF_TICKS_PER_SEC)) && (delta <= SSF_TICKS_PER_SEC));
    lastTimeout = nextTimeout;
    while (lastTimeout == nextTimeout)
    {
        nextTimeout = 0;
        SSF_ASSERT(SSFSMTask(&nextTimeout) == true);
    }
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UT1_1);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    delta = nextTimeout - start;
    SSF_ASSERT((delta > (1.9 * SSF_TICKS_PER_SEC)) && (delta < (2.1 * SSF_TICKS_PER_SEC)));
    lastTimeout = nextTimeout;
    while (lastTimeout == nextTimeout)
    {
        nextTimeout = 0;
        SSFSMTask(&nextTimeout);
    }
    delta = SSFSMGetTick64() - start;
    SSF_ASSERT((delta > (1.9 * SSF_TICKS_PER_SEC)) && (delta < (2.1 * SSF_TICKS_PER_SEC)));
    SSF_ASSERT(SSFSMTask(&nextTimeout) == false);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 0, SSF_SM_EVENT_EXIT);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_ENTRY);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSF_ASSERT(SSFSMTask(&nextTimeout) == false);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    start = SSFSMGetTick64();
    SSFSMPutEventData(SSF_SM_UNIT_TEST_2, SSF_SM_EVENT_UTX_2, "t", 1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 0, SSF_SM_EVENT_UTX_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSF_ASSERT(SSFSMTask(&nextTimeout) == true);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_UT1_1);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    delta = nextTimeout - start;
    SSF_ASSERT((delta > (0.9 * SSF_TICKS_PER_SEC)) && (delta <= SSF_TICKS_PER_SEC));
    lastTimeout = nextTimeout;
    while (lastTimeout == nextTimeout)
    {
        nextTimeout = 0;
        SSFSMTask(&nextTimeout);
    }
    SSF_ASSERT(SSFSMTask(&nextTimeout) == false);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 0, SSF_SM_EVENT_UTX_1);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSF_ASSERT(SSFSMTask(&nextTimeout) == false);
    start = SSFSMGetTick64();
    SSFSMPutEventData(SSF_SM_UNIT_TEST_2, SSF_SM_EVENT_UT2_1, "d", 1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 0, SSF_SM_EVENT_UT2_1);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 0, SSF_SM_EVENT_EXIT);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 1, SSF_SM_EVENT_ENTRY);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSF_ASSERT(SSFSMTask(&nextTimeout) == true);
    delta = nextTimeout - start;
    SSF_ASSERT((delta > (1.9 * SSF_TICKS_PER_SEC)) && (delta <= (SSF_TICKS_PER_SEC * 2)));
    lastTimeout = nextTimeout;
    while (lastTimeout == nextTimeout)
    {
        nextTimeout = 0;
        SSFSMTask(&nextTimeout);
    }
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_2, 1, SSF_SM_EVENT_UT2_2);
    SSF_ASSERT_CLEAR(SSF_SM_UNIT_TEST_1, 1, SSF_SM_EVENT_UT2_2);
    SSF_ASSERT(_SSFSMFlagsAreCleared());
    SSF_ASSERT(SSFSMTask(&nextTimeout) == false);
}
#endif /* SSF_CONFIG_SM_UNIT_TEST */

