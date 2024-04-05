/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* main.c                                                                                        */
/* Entry point for unit testing SSF components.                                                  */
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
#include <stdio.h>
#include "ssfassert.h"
#include "ssfversion.h"
#include "ssfbfifo.h"
#include "ssfll.h"
#include "ssfsm.h"
#include "ssfmpool.h"
#include "ssfport.h"
#include "ssfjson.h"
#include "ssfbase64.h"
#include "ssfhex.h"
#include "ssffcsum.h"
#include "ssfrs.h"
#include "ssfcrc16.h"
#include "ssfcrc32.h"
#include "ssfsha2.h"
#include "ssftlv.h"
#include "ssfaes.h"
#include "ssfaesgcm.h"
#include "ssfcfg.h"
#include "ssfprng.h"
#include "ssfini.h"
#include "ssfubjson.h"
#include "ssfdtime.h"
#include "ssfrtc.h"
#include "ssfiso8601.h"
#include "ssfdec.h"
#include "ssfstr.h"
#include "ssfheap.h"
#include "ssfgobj.h"

typedef struct
{
    char *module;
    char *description;
    void (*utf)(void);
} SSFUnitTest_t;

SSFUnitTest_t unitTests[] =
{
#if SSF_CONFIG_UBJSON_UNIT_TEST == 1
    { "ssfubjson", "Universal Binary JSON Codec", SSFUBJsonUnitTest },
#endif /* SSF_CONFIG_UBJSON_UNIT_TEST */

#if SSF_CONFIG_HEX_UNIT_TEST == 1
    { "ssfhex", "Hex String Codec", SSFHexUnitTest },
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */

#if SSF_CONFIG_JSON_UNIT_TEST == 1
    { "ssfjson", "JSON Codec", SSFJsonUnitTest },
#endif /* SSF_CONFIG_JSON_UNIT_TEST */

#if SSF_CONFIG_HEAP_UNIT_TEST == 1
    { "ssfheap", "Integrity Checked Heap", SSFHeapUnitTest },
#endif /* SSF_CONFIG_STR_UNIT_TEST */

#if SSF_CONFIG_STR_UNIT_TEST == 1
    { "ssfstr", "Safe C Strings", SSFStrUnitTest },
#endif /* SSF_CONFIG_STR_UNIT_TEST */

#if SSF_CONFIG_DEC_UNIT_TEST == 1
    { "ssfdec", "Decimal String Codec", SSFDecUnitTest },
#endif /* SSF_CONFIG_BFIFO_UNIT_TEST */

#if SSF_CONFIG_BFIFO_UNIT_TEST == 1
    { "ssfbfifo", "Byte FIFO", SSFBFifoUnitTest },
#endif /* SSF_CONFIG_BFIFO_UNIT_TEST */

#if SSF_CONFIG_LL_UNIT_TEST == 1
    { "ssfll", "Linked List", SSFLLUnitTest },
#endif  /* SSF_CONFIG_LL_UNIT_TEST */

#if SSF_CONFIG_MPOOL_UNIT_TEST == 1
    { "ssfmpool", "Memory Pool", SSFMPoolUnitTest },
#endif /* SSF_CONFIG_MPOOL_UNIT_TEST */

#if SSF_CONFIG_BASE64_UNIT_TEST == 1
    { "ssfbase64", "Base64 Codec", SSFBase64UnitTest },
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */

#if SSF_CONFIG_FCSUM_UNIT_TEST == 1
    { "ssffcsum", "Fletcher's Checksum", SSFFCSumUnitTest },
#endif /* SSF_CONFIG_FCSUM_UNIT_TEST */

#if SSF_CONFIG_SM_UNIT_TEST == 1
    { "ssfsm", "Finite State Machine", SSFSMUnitTest },
#endif /* SSF_CONFIG_SM_UNIT_TEST */

#if SSF_CONFIG_RS_UNIT_TEST == 1
    { "ssfrs", "Reed Solomon ECC", SSFRSUnitTest },
#endif /* SSF_CONFIG_SM_UNIT_TEST */

#if SSF_CONFIG_CRC16_UNIT_TEST == 1
    { "ssfcrc16", "16-bit XMODEM/CCITT-16", SSFCRC16UnitTest },
#endif /* SSF_CONFIG_CRC16_UNIT_TEST */

#if SSF_CONFIG_CRC32_UNIT_TEST == 1
    { "ssfcrc32", "32-bit CCITT-32", SSFCRC32UnitTest },
#endif /* SSF_CONFIG_CRC32_UNIT_TEST */

#if SSF_CONFIG_SHA2_UNIT_TEST == 1
    { "ssfsha2", "SHA2 256-512-bits", SSFSHA2UnitTest },
#endif /* SSF_CONFIG_SHA2_UNIT_TEST */

#if SSF_CONFIG_TLV_UNIT_TEST == 1
    { "ssftlv", "Tag/Length/Value Codec", SSFTLVUnitTest },
#endif /* SSF_CONFIG_TLV_UNIT_TEST */

#if SSF_CONFIG_AES_UNIT_TEST == 1
    { "ssfaes", "AES128-256 Block", SSFAESUnitTest },
#endif /* SSF_CONFIG_AES_UNIT_TEST */

#if SSF_CONFIG_AESGCM_UNIT_TEST == 1
    { "ssfaesgcm", "AES-GCM Authenticated Cipher", SSFAESGCMUnitTest },
#endif /* SSF_CONFIG_AESGCM_UNIT_TEST */

#if SSF_CONFIG_CFG_UNIT_TEST == 1
    { "ssfcfg", "Read/Write NV Config", SSFCfgUnitTest },
#endif /* SSF_CONFIG_CFG_UNIT_TEST */

#if SSF_CONFIG_PRNG_UNIT_TEST == 1
    { "ssfprng", "Crypto Secure Capable PRNG", SSFPRNGUnitTest },
#endif /* SSF_CONFIG_PRNG_UNIT_TEST */

#if SSF_CONFIG_INI_UNIT_TEST == 1
    { "ssfini", "INI Codec", SSFINIUnitTest },
#endif /* SSF_CONFIG_INI_UNIT_TEST */

#if SSF_CONFIG_RTC_UNIT_TEST == 1
    { "ssfrtc", "RTC", SSFRTCUnitTest },
#endif /* SSF_CONFIG_RTC_UNIT_TEST */

#if SSF_CONFIG_DTIME_UNIT_TEST == 1
    { "ssfdtime", "Date Time", SSFDTimeUnitTest },
#endif /* SSF_CONFIG_DTIME_UNIT_TEST */

#if SSF_CONFIG_ISO8601_UNIT_TEST == 1
    { "ssfiso8601", "ISO8601 Time", SSFISO8601UnitTest }
#endif /* SSF_CONFIG_ISO8601_UNIT_TEST */
};

uint32_t j = 0x80818283;
int64_t k;

void iterateCallback(SSFGObj_t *gobj, SSFLL_t *path, uint8_t depth)
{
    char label[128];
    SSFObjType_t dataType;
    uint32_t i;

    k = j;
    k = (int32_t)j;

    SSF_REQUIRE(gobj != NULL);

    dataType = SSFGObjGetType(gobj);

    SSFGObjPathToString(path);
    printf(" : ");
    switch (gobj->dataType)
    {
    case SSF_OBJ_TYPE_NUMBER_UINT64:
    {
        uint64_t u64;
        SSFGObjGetUInt(gobj, &u64);
        printf("%llud 0x%08llX", u64, u64);
    }
    break;
    default:
        break;
    }
    printf("\r\n");
#if 0
    for (i = 0; i < depth; i++)
    {
        printf("    ");
    }
    if (SSFGObjGetLabel(gobj, label, sizeof(label)))
    {
        printf("%s:%d\r\n", label, dataType);
    }
    else
    {
        printf("NO LABEL:%d\r\n", dataType);
    }
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* SSF unit test entry point.                                                                    */
/* --------------------------------------------------------------------------------------------- */
int main(void)
{
    size_t i;
    SSFPortTick_t start;
    SSFGObj_t *gobj = NULL;
    SSFGObj_t* gobjPeer = NULL;
    SSFGObj_t* gobjPeer2 = NULL;
    SSFGObj_t* gobjChild = NULL;
    SSFGObj_t* gobjChild2 = NULL;
    uint64_t valueOut;
    int64_t i64;
    double d64;
    char str[2000];
    size_t length;
    bool comma = false;

    SSF_ASSERT(SSFGObjInit(&gobj, 10, 10));
    SSF_ASSERT(SSFGObjSetLabel(gobj, "label"));
    SSF_ASSERT(SSFGObjSetString(gobj, "value"));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));


    SSF_ASSERT(SSFGObjSetUInt(gobj, 0x11223344));
    SSF_ASSERT(SSFGObjGetUInt(gobj, &valueOut));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));


    SSF_ASSERT(SSFGObjInit(&gobjPeer, 10, 10));

    SSF_ASSERT(SSFGObjInsertPeer(gobj, gobjPeer));

    SSF_ASSERT(SSFGObjSetObject(gobjPeer));

    SSF_ASSERT(SSFGObjInit(&gobjChild, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjChild, "childlabel"));
    SSF_ASSERT(SSFGObjSetUInt(gobjChild, 12345));

    SSF_ASSERT(SSFGObjInit(&gobjChild2, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjChild2, "childlabel2"));
    SSF_ASSERT(SSFGObjSetUInt(gobjChild2, 67890));

    SSF_ASSERT(SSFGObjInsertChild(gobjPeer, gobjChild));
    SSF_ASSERT(SSFGObjInsertChild(gobjPeer, gobjChild2));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobjChild, &comma));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobjPeer, &comma));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));

    SSF_ASSERT(SSFGObjInit(&gobjPeer2, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjPeer2, "peerlabel2"));
    SSF_ASSERT(SSFGObjSetInt(gobjPeer2, -11223344));
    SSF_ASSERT(SSFGObjGetInt(gobjPeer2, &i64));
    SSF_ASSERT(SSFGObjInsertPeer(gobjPeer, gobjPeer2));
    gobjPeer2 = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjPeer2, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjPeer2, "peerlabeldouble2"));
    SSF_ASSERT(SSFGObjSetDouble(gobjPeer2, -1.0987));
    SSF_ASSERT(SSFGObjGetDouble(gobjPeer2, &d64));
    SSF_ASSERT(SSFGObjInsertPeer(gobjPeer, gobjPeer2));
    gobjPeer2 = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjPeer2, 1, 10));
    SSF_ASSERT(SSFGObjSetLabel(gobjPeer2, "peerarray2"));
    SSF_ASSERT(SSFGObjSetArray(gobjPeer2));
    SSF_ASSERT(SSFGObjInsertPeer(gobjPeer, gobjPeer2));
    gobjChild = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjChild, 1, 1));
    SSF_ASSERT(SSFGObjSetUInt(gobjChild, 1));
    SSF_ASSERT(SSFGObjInsertChild(gobjPeer2, gobjChild));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));

    SSFGObjIterate(gobj, iterateCallback, 0);


    SSFGObjDeInit(&gobj);



    /* Print out SSF version */
    printf("\r\n");
    i = printf("Testing SSF Version %s", SSF_VERSION_STR);
    SSF_ASSERT(i > 0);
    printf("\r\n");
    while (i--) { printf("-"); }
    printf("\r\n");

    /* Iterate over all the configured unit tests */
    for (i = 0; i < sizeof(unitTests) / sizeof(SSFUnitTest_t); i++)
    {
        printf("Running %20s (%30s) unit test...", unitTests[i].module, unitTests[i].description);
        fflush(stdout);
        start = SSFPortGetTick64();
        unitTests[i].utf();
        printf("PASSED in %llus\r\n", (SSFPortGetTick64() - start) / SSF_TICKS_PER_SEC);
    }

    printf("\r\n");
    return 0;
}
