#ifndef SSF_SM_INCLUDE_H
#define SSF_SM_INCLUDE_H

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

typedef uint8_t SSFSMId_t;
typedef uint8_t SSFSMEventId_t;
typedef uint8_t SSFSMData_t;
typedef uint16_t SSFSMDataLen_t;
typedef uint64_t SSFSMTimeout_t;

typedef void (*SSFSMHandler_t)(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);

#define SSF_SM_EVENT_DATA_ALIGN (var) { SSF_ASSERT((sizeof(var) >= dataLen) && (data != NULL)); memcpy(&(var), data, dataLen); }

void SSFSMInit(SSFSMId_t smid, SSFSMHandler_t initial, uint32_t maxEvents, uint32_t maxTimers);
void SSFSMPutEventData(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);
#define SSFSMPutEvent(smid, eid) SSFSMPutEventData(smid, eid, NULL, 0)

void SSFSMTran(SSFSMHandler_t next);
void SSFSMStartTimerData(SSFSMEventId_t eid, SSFSMTimeout_t interval, const SSFSMData_t *data, SSFSMDataLen_t dataLen);
#define SSFSMStartTimer(eid, to) SSFSMStartTimerData(eid, to, NULL, 0)
void SSFSMStopTimer(SSFSMEventId_t eid);

bool SSFSMTask(void);

#endif /* SSF_SM_INCLUDE_H */
