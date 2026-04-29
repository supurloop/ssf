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
extern uint8_t _ssfCfgStorageRAM[SSF_MAX_CFG_RAM_SECTORS][SSF_CFG_MAX_STORAGE_SIZE];
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
    uint8_t data1[32];
    uint8_t data2[32];
    uint16_t data1Len;
    uint16_t data2Len;

    /* Check SSFCfgWrite requirements */
    SSF_ASSERT_TEST(SSFCfgWrite(NULL, 1, 0, 0));
    SSF_ASSERT_TEST(SSFCfgWrite(data1, 65535, 0, 0));
    SSF_ASSERT_TEST(SSFCfgWrite(data1, 1, 0, SSF_CFG_DATA_VERSION_INVALID));
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_ASSERT_TEST(SSFCfgWrite(data1, 1, 0, 0));
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

    /* Check SSFCfgRead requirements */
    SSF_ASSERT_TEST(SSFCfgRead(NULL, &data1Len, sizeof(data1), 0));
    SSF_ASSERT_TEST(SSFCfgRead(data1, NULL, sizeof(data1), 0));
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_ASSERT_TEST(SSFCfgRead(data1, &data1Len, sizeof(data1), 0));
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_ASSERT_TEST(SSFCfgDeInit());
    SSFCfgInit();
    SSF_ASSERT_TEST(SSFCfgInit());
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

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

    /* Read with dataSize too small for stored data */
    memset(data1, 0xAA, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 3));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data1) - 1, 0) == SSF_CFG_DATA_VERSION_INVALID);
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, 1, 0) == SSF_CFG_DATA_VERSION_INVALID);
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data1), 0) == 3);
    SSF_ASSERT(data2Len == sizeof(data1));

    /* Read from pristine/erased sector (never written, all 0xFF) */
    memset(_ssfCfgStorageRAM[1], 0xFF, SSF_CFG_MAX_STORAGE_SIZE);
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 1) == SSF_CFG_DATA_VERSION_INVALID);
    /* All zeros is also invalid (magic won't match) */
    memset(_ssfCfgStorageRAM[1], 0x00, SSF_CFG_MAX_STORAGE_SIZE);
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 1) == SSF_CFG_DATA_VERSION_INVALID);

    /* Write different data to same sector overwrites previous */
    memset(data1, 0xBB, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 4));
    memset(data1, 0xCC, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 4));
    memset(data2, 0, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 4);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(data2[0] == 0xCC);

    /* Write same data but different version succeeds (returns true) */
    memset(data1, 0xDD, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 5));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 5) == false);
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 6));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 6);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);

    /* Write different data same id/version succeeds (data changed, CRC differs) */
    memset(data1, 0xEE, sizeof(data1));
    SSF_ASSERT(SSFCfgWrite(data1, sizeof(data1), 0, 6));
    memset(data2, 0, sizeof(data2));
    SSF_ASSERT(SSFCfgRead(data2, &data2Len, sizeof(data2), 0) == 6);
    SSF_ASSERT(data2Len == sizeof(data1));
    SSF_ASSERT(memcmp(data1, data2, data2Len) == 0);
    SSF_ASSERT(data2[0] == 0xEE);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_ASSERT_TEST(SSFCfgInit());
    SSFCfgDeInit();
    SSF_ASSERT_TEST(SSFCfgDeInit());
    SSFCfgInit();
    SSFCfgDeInit();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
}
