/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsm.h                                                                                       */
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
#ifndef SSF_SM_INCLUDE_H
#define SSF_SM_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef uint8_t SSFSMId_t;
typedef uint8_t SSFSMEventId_t;
typedef uint8_t SSFSMData_t;
typedef uint16_t SSFSMDataLen_t;
typedef SSFPortTick_t SSFSMTimeout_t;
typedef void (*SSFSMHandler_t)(SSFSMEventId_t eid, const SSFSMData_t *data,\
                                   SSFSMDataLen_t dataLen);

#define SSF_SM_MAX_TIMEOUT ((SSFSMTimeout_t) (-1))
#define SSF_SM_EVENT_DATA_ALIGN(v) { \
      SSF_ASSERT((sizeof(v) >= dataLen) && (data != NULL)); \
      memcpy(&(v), data, dataLen); }

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFSMInit(uint32_t maxEvents, uint32_t maxTimers);
void SSFSMInitHandler(SSFSMId_t smid, SSFSMHandler_t initial);
void SSFSMPutEventData(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data,
                       SSFSMDataLen_t dataLen);
#define SSFSMPutEvent(smid, eid) SSFSMPutEventData(smid, eid, NULL, 0)
bool SSFSMTask(SSFSMTimeout_t *nextTimeout);

/* --------------------------------------------------------------------------------------------- */
/* External interface only for state handlers                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFSMTran(SSFSMHandler_t next);
void SSFSMStartTimerData(SSFSMEventId_t eid, SSFSMTimeout_t interval, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen);
#define SSFSMStartTimer(eid, to) SSFSMStartTimerData(eid, to, NULL, 0)
void SSFSMStopTimer(SSFSMEventId_t eid);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_SM_UNIT_TEST == 1
void SSFSMUnitTest(void);
#endif /* SSF_CONFIG_SM_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_SM_INCLUDE_H */

