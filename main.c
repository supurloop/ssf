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
#include "ssfstrb.h"
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
#if SSF_CONFIG_STRB_UNIT_TEST == 1
    { "ssfstrb", "Safe C String Buffers", SSFStrBufUnitTest },
#endif /* SSF_CONFIG_STRB_UNIT_TEST */

#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
    { "ssfgobj", "Generic Object Codec", SSFGObjUnitTest },
#endif /* SSF_CONFIG_UBJSON_UNIT_TEST */

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
#endif /* SSF_CONFIG_HEAP_UNIT_TEST */

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

/* --------------------------------------------------------------------------------------------- */
/* SSF unit test entry point.                                                                    */
/* --------------------------------------------------------------------------------------------- */
int main(void)
{
    size_t i;
    SSFPortTick_t start;

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
