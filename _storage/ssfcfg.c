/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcfg.c                                                                                      */
/* Provides interface for reliably reading and writing configuration data to NV storage.         */
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
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfcfg.h"
#include "ssfcrc16.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
SSF_CFG_TYPEDEF_STRUCT SSFCfgHeader
{
    uint16_t dataLen;
    dataId_t dataId;
    dataVersion_t dataVersion;
    uint16_t dataCRC;
    uint32_t magic;
    /* ...data follows */
} SSFCfgHeader_t;

#define SSF_CFG_STORAGE_LIMIT (65536ul)
#if SSF_CFG_MAX_STORAGE_SIZE > SSF_CFG_STORAGE_LIMIT
#error SSF_CFG_MAX_STORAGE_SIZE must be <= SSF_CFG_STORAGE_LIMIT
#endif
#define SSF_MAX_CFG_DATA_SIZE (SSF_CFG_MAX_STORAGE_SIZE - sizeof(SSFCfgHeader_t))
#define SSF_CFG_MAGIC (0x52504F57ul)

/* --------------------------------------------------------------------------------------------- */
/* Virtual NV Storage in RAM                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CFG_ENABLE_STORAGE_RAM == 1
uint8_t _ssfCfgStorageRAM[SSF_MAX_CFG_RAM_SECTORS][SSF_MAX_CFG_RAM_SECTOR_SIZE];
#endif

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
bool _ssfcfgIsInited; 
SSF_CFG_THREAD_SYNC_DECLARATION;
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
/* --------------------------------------------------------------------------------------------- */
/* Initializes the ssfcfg interface.                                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFCfgInit(void)
{
    SSF_ASSERT(_ssfcfgIsInited == false);
    SSF_CFG_THREAD_SYNC_INIT();
    _ssfcfgIsInited = true;
}
/* --------------------------------------------------------------------------------------------- */
/* Deinitializes the ssfcfg interface.                                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFCfgDeInit(void)
{
    SSF_ASSERT(_ssfcfgIsInited);
    _ssfcfgIsInited = false;
    SSF_CFG_THREAD_SYNC_DEINIT();
}
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if data written to storage, else false if data matched existing storage.         */
/* --------------------------------------------------------------------------------------------- */
bool SSFCfgWrite(uint8_t *data, uint16_t dataLen, dataId_t dataId, dataVersion_t dataVersion)
{
    SSFCfgHeader_t header;
    uint8_t tmp[SSF_CFG_WRITE_CHECK_CHUNK_SIZE];

    uint16_t remainingLen;
    uint16_t chunkLen;
    size_t offset = 0;
    uint16_t crcStorage = SSF_CRC16_INITIAL;
    uint16_t crcData;
    bool retVal = true;

    SSF_REQUIRE(data != NULL);
    SSF_REQUIRE(dataLen <= SSF_MAX_CFG_DATA_SIZE);
    SSF_REQUIRE(dataVersion >= 0);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_ASSERT(_ssfcfgIsInited);
    SSF_CFG_THREAD_SYNC_ACQUIRE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

    /* Is data already stored as expected in normal location? */
    SSF_CFG_READ_STORAGE((uint8_t *)&header, sizeof(header), dataId, offset);

    /* Does the length, id, version, and magic match what is stored? */
    if ((header.dataLen == dataLen) &&
        (header.dataId == dataId) &&
        (header.dataVersion == dataVersion) &&
        (header.magic == SSF_CFG_MAGIC))
    {
        /* Yes, read data in chunks from storage to compute CRC */
        remainingLen = header.dataLen;
        offset += sizeof(header);
        while (remainingLen)
        {
            chunkLen = (uint16_t) sizeof(header);
            if (chunkLen > remainingLen) chunkLen = remainingLen;
            SSF_CFG_READ_STORAGE(tmp, chunkLen, dataId, offset);
            crcStorage = SSFCRC16(tmp, chunkLen, crcStorage);
            offset += chunkLen;
            remainingLen -= chunkLen;
        }

        /* Compute data CRC*/
        crcData = SSFCRC16(data, dataLen, SSF_CRC16_INITIAL);

        /* If computed CRC matches data then nothing to do */
        if (crcData == crcStorage)
        { 
            retVal = false;
            goto _ssfcfgReadExit;
        }
    }

    /* New data, write data to storage */
    header.dataLen = dataLen;
    header.dataId = dataId;
    header.dataVersion = dataVersion;
    header.dataCRC = SSFCRC16(data, dataLen, SSF_CRC16_INITIAL);
    header.magic = SSF_CFG_MAGIC;
    SSF_CFG_ERASE_STORAGE(dataId);
    SSF_CFG_WRITE_STORAGE((uint8_t *)&header, sizeof(header), dataId, 0);
    SSF_CFG_WRITE_STORAGE(data, dataLen, dataId, sizeof(header));

_ssfcfgReadExit:
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_CFG_THREAD_SYNC_RELEASE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
    return retVal;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SSF_CFG_DATA_VERSION_INVALID if cfg bad, else version with data and dataLen set.      */
/* --------------------------------------------------------------------------------------------- */
dataVersion_t SSFCfgRead(uint8_t *data, uint16_t *dataLen, size_t dataSize, dataId_t dataId)
{
    SSFCfgHeader_t header;
    dataVersion_t dataVersion = SSF_CFG_DATA_VERSION_INVALID;
    uint16_t crcData;

    SSF_REQUIRE(data != NULL);
    SSF_REQUIRE(dataLen != NULL);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_ASSERT(_ssfcfgIsInited);
    SSF_CFG_THREAD_SYNC_ACQUIRE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

    /* Read Header */
    SSF_CFG_READ_STORAGE((uint8_t *)&header, sizeof(header), dataId, 0);

    /* Is header OK? */
    if ((header.dataLen <= dataSize) &&
        (header.dataId == dataId) &&
        (header.dataVersion >= 0) &&
        (header.magic == SSF_CFG_MAGIC))
    {
        /* Yes, read data */
        SSF_CFG_READ_STORAGE(data, header.dataLen, dataId, sizeof(header));

        /* Compute CRC */
        crcData = SSFCRC16(data, header.dataLen, SSF_CRC16_INITIAL);

        /* Does CRC match header? */
        if (crcData == header.dataCRC)
        {
            /* Yes, report back that valid data has been read */
            *dataLen = header.dataLen;
            dataVersion = header.dataVersion;
        }
    }

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_CFG_THREAD_SYNC_RELEASE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
    return dataVersion;
}

