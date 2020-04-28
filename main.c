#include <stdio.h>
#include "ssfassert.h"
#include "ssfbfifo.h"
#include "ssfll.h"
#include "ssfsm.h"
#include "ssfmpool.h"
#include "ssfport.h"
#include "ssfjson.h"
#include "ssfbase64.h"
#include "ssfhex.h"

void* ssfUnused;

#define LL_MAX_SIZE 30
SSFLLItem_t items[LL_MAX_SIZE];

void TestHandler2(SSFSMEventId_t eid, const SSFSMData_t* data, SSFSMDataLen_t dataLen);

void TestHandler1(SSFSMEventId_t eid, const SSFSMData_t* data, SSFSMDataLen_t dataLen)
{
    SSF_UNUSED(data);
    SSF_UNUSED(dataLen);
    switch (eid)
    {
        case SSF_SM_EVENT_ENTRY:
            printf("ENTRY1\r\n");
            SSFSMStartTimer(SSF_SM_EVENT_2, 2000);
            break;
        case SSF_SM_EVENT_EXIT:
            printf("EXIT1\r\n");
            break;
        case SSF_SM_EVENT_1:
            printf("EVENT 1\r\n");
            break;
        case SSF_SM_EVENT_2:
            printf("EVENT 2\r\n");
            SSFSMTran(TestHandler2);
            break;
        default:
            break;
    }
}

void TestHandler2(SSFSMEventId_t eid, const SSFSMData_t* data, SSFSMDataLen_t dataLen)
{
    SSF_UNUSED(data);
    SSF_UNUSED(dataLen);
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        printf("ENTRY2\r\n");
        SSFSMStartTimer(SSF_SM_EVENT_1, 1000);
        break;
    case SSF_SM_EVENT_EXIT:
        printf("EXIT2\r\n");
        break;
    case SSF_SM_EVENT_1:
        printf("EVENT 1\r\n");
        SSFSMTran(TestHandler1);
        break;
    case SSF_SM_EVENT_2:
        printf("EVENT 2\r\n");
        SSFSMTran(TestHandler1);
        break;
    default:
        break;
    }
}

void main(void)
{
#if SSF_CONFIG_BFIFO_UNIT_TEST == 1
    SSFBFifoUnitTest();
#endif

#if SSF_CONFIG_LL_UNIT_TEST == 1
    SSFLLUnitTest();
#endif

#if SSF_CONFIG_MPOOL_UNIT_TEST == 1
    SSFMPoolUnitTest();
#endif /* SSF_CONFIG_MPOOL_UNIT_TEST */

#if SSF_CONFIG_JSON_UNIT_TEST == 1
    SSFJsonUnitTest();
#endif /* SSF_CONFIG_JSON_UNIT_TEST */

#if SSF_CONFIG_BASE64_UNIT_TEST == 1
    SSFBase64UnitTest();
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */

#if SSF_CONFIG_HEX_UNIT_TEST == 1
    SSFHexUnitTest();
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */


#if 0
    SSFSMInit(SSF_SM_TEST1, TestHandler1, 10, 1);
    SSFSMPutEvent(SSF_SM_TEST1, SSF_SM_EVENT_1);
    while (1) 
    {
        SSFSMTask();
        Sleep(1);
    }
    SSFSMPutEvent(SSF_SM_TEST1, SSF_SM_EVENT_2);
    SSFSMTask();
    SSFSMPutEvent(SSF_SM_TEST1, SSF_SM_EVENT_1);
    SSFSMTask();
    SSFSMPutEvent(SSF_SM_TEST1, SSF_SM_EVENT_2);
    SSFSMTask();
#endif
}

