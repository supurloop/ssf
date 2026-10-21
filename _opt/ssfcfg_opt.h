/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfcfg configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_CFG_OPT_H_INCLUDE
#define SSF_CFG_OPT_H_INCLUDE

#include "ssfport.h"        /* SSF_CONFIG_ENABLE_THREAD_SUPPORT, SSF_MUTEX_* */

#ifdef __cplusplus
extern "C" {
#endif

#define SSF_CFG_TYPEDEF_STRUCT typedef struct /* Optionally add packed struct attribute here */
#define SSF_CFG_MAX_STORAGE_SIZE (4096u) /* Max size of erasable NV storage sector */
#define SSF_CFG_WRITE_CHECK_CHUNK_SIZE (32u) /* Max size of tmp stack buffer for write checking */

/* 1 to use RAM as storage, 0 to specify another storage interface */
#define SSF_CFG_ENABLE_STORAGE_RAM (1u)
#if SSF_CFG_ENABLE_STORAGE_RAM == 0
#define SSF_CFG_ERASE_STORAGE(dataId)
#define SSF_CFG_WRITE_STORAGE(data, dataSize, dataId, dataOffset)
#define SSF_CFG_READ_STORAGE(data, dataSize, dataId, dataOffset)
#else
#define SSF_MAX_CFG_RAM_SECTORS (3u)
#define SSF_CFG_ERASE_STORAGE(dataId) { \
    memset(&_ssfCfgStorageRAM[dataId], 0xff, SSF_CFG_MAX_STORAGE_SIZE); \
}
#define SSF_CFG_WRITE_STORAGE(data, dataLen, dataId, dataOffset) { \
    memcpy(&_ssfCfgStorageRAM[dataId][dataOffset], data, dataLen); \
}
#define SSF_CFG_READ_STORAGE(data, dataSize, dataId, dataOffset) { \
    memcpy(data, &_ssfCfgStorageRAM[dataId][dataOffset], dataSize); \
}
#endif

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#define SSF_CFG_THREAD_SYNC_DECLARATION SSF_MUTEX_DECLARATION(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_INIT() SSF_MUTEX_INIT(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_DEINIT() SSF_MUTEX_DEINIT(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_ACQUIRE() SSF_MUTEX_ACQUIRE(_ssfcfgSyncMutex)
#define SSF_CFG_THREAD_SYNC_RELEASE() SSF_MUTEX_RELEASE(_ssfcfgSyncMutex)
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

#ifdef __cplusplus
}
#endif

#endif /* SSF_CFG_OPT_H_INCLUDE */
