 /* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcfg_ut.c                                                                                   */
/* Provides unit test for configuration data storage interface.                                  */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#include <stdint.h>
#include <stdio.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfcfg.h"
#include "ssfcrc16.h"

#if SSF_CFG_ENABLE_STORAGE_RAM == 1
extern uint8_t _ssfCfgStorageRAM[SSF_MAX_CFG_RAM_SECTORS][SSF_MAX_CFG_DATA_SIZE_LIMIT];
#else
#error ssfcfg_ut.c requires that SSF_CFG_ENABLE_STORAGE_RAM set to 1.
#endif

#if SSF_MAX_CFG_RAM_SECTORS < 2
#error ssfcfg_ut.c requires at least 2 RAM sectors.
#endif

/* --------------------------------------------------------------------------------------------- */
/* Units tests the for configuration data storage interface.                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFCfgUnitTest(void)
{
    uint8_t data1[SSF_MAX_CFG_DATA_SIZE_LIMIT];
    uint8_t data2[SSF_MAX_CFG_DATA_SIZE_LIMIT];
    uint16_t data1Len;
    uint16_t data2Len;

    /* Check SSFCfgWrite requirements */
    SSF_ASSERT_TEST(SSFCfgWrite(NULL, 1, 0, 0));
    SSF_ASSERT_TEST(SSFCfgWrite(data1, 65535, 0, 0));
    SSF_ASSERT_TEST(SSFCfgWrite(data1, 1, 0, SSF_CFG_DATA_VERSION_INVALID));

    /* Check SSFCfgRead requirements */
    SSF_ASSERT_TEST(SSFCfgRead(NULL, &data1Len, sizeof(data1), 0));
    SSF_ASSERT_TEST(SSFCfgRead(data1, NULL, sizeof(data1), 0));

    /* Check basic write then read cases */
    memset(data1, 0x01, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 0));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 0);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 0) == false);

    memset(data1, 0x01, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1) - 5, 0, 0));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 0);
    SSF_ASSERT(data2Len == sizeof(data1) - 5);
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1) - 5, 0, 0) == false);

    memset(data1, 0x01, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, 0, 0, 0));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 0);
    SSF_ASSERT(data2Len == 0);
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, 0, 0, 0) == false);

    memset(data1, 0x01, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 0));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 0);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 0) == false);

    memset(data1, 0x01, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 1));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 1);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 1) == false);

    _ssfCfgStorageRAM[0][0] = 0;
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == SSF_CFG_DATA_VERSION_INVALID);

    memset(data1, 0x01, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 1));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 1);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 1) == false);

    memset(data1, 0x11, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 1, 2));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 1) == 2);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 1, 2) == false);

    memset(data1, 0x01, sizeof(data1));
    memset(data2, 0x02, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 1);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 1) == false);
    memset(data1, 0x11, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 1, 2) == false);
}
