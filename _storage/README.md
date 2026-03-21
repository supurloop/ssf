# ssfcfg — Version-Controlled Configuration Storage

[SSF](../README.md)

Reliable read and write of versioned configuration data to NV storage (e.g. NOR flash).

Each configuration block is identified by a `dataId_t` and tagged with a `dataVersion_t`.
`SSFCfgWrite()` stores the block with CRC protection and suppresses redundant writes when the
data in NV storage is already identical. `SSFCfgRead()` returns the version found or
`SSF_CFG_DATA_VERSION_INVALID` when no valid block exists for that ID, enabling clean bootstrap
and version-migration logic at startup.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfcfg--version-controlled-configuration-storage) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)
- [`ssfcrc16.h`](../_edc/ssfcrc16.h)

<a id="notes"></a>

## [↑](#ssfcfg--version-controlled-configuration-storage) Notes

- Each `dataId_t` value must be unique across all configuration types in the system; it maps to
  a distinct NV storage sector.
- The maximum number of `dataId_t` values is determined by the number of sectors available in
  the target NV storage; configure `SSF_MAX_CFG_RAM_SECTORS` accordingly when
  `SSF_CFG_ENABLE_STORAGE_RAM` is `1`.
- `dataVersion_t` values must be non-negative integers; `SSF_CFG_DATA_VERSION_INVALID` (`-1`)
  is reserved for the "not found" return value of `SSFCfgRead()`.
- `SSFCfgWrite()` performs a read-before-write check and returns `false` when
  the data in NV storage is already identical, extending flash endurance.
- Data length per `dataId` is limited to `SSF_MAX_CFG_DATA_SIZE` bytes, which is derived at
  compile time as `SSF_CFG_MAX_STORAGE_SIZE - sizeof(SSFCfgHeader_t)`.
- `SSFCfgInit()` and `SSFCfgDeInit()` are only compiled in when
  `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`; omit them in single-threaded builds.
- The interface is thread-safe when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1` and the
  `SSF_CFG_THREAD_SYNC_*` macros are implemented in `ssfoptions.h`.

<a id="configuration"></a>

## [↑](#ssfcfg--version-controlled-configuration-storage) Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_CFG_MAX_STORAGE_SIZE` | `4096` | Maximum size in bytes of one erasable NV storage sector |
| `SSF_CFG_WRITE_CHECK_CHUNK_SIZE` | `32` | Size of the temporary stack buffer used during the read-before-write check; reduce if stack space is limited |
| `SSF_CFG_ENABLE_STORAGE_RAM` | `1` | `1` to use a RAM-based simulated NV storage suitable for unit tests; `0` to use real hardware via the port macros below |
| `SSF_CFG_TYPEDEF_STRUCT` | `typedef struct` | Optionally append a packed-struct attribute (e.g. `__attribute__((packed))`) to the internal record structure |

**Port macros** (required when `SSF_CFG_ENABLE_STORAGE_RAM == 0`; implement in `ssfoptions.h`):

| Macro | Description |
|-------|-------------|
| `SSF_CFG_ERASE_STORAGE(dataId)` | Erase the NV storage sector associated with `dataId` |
| `SSF_CFG_WRITE_STORAGE(data, dataLen, dataId, dataOffset)` | Write `dataLen` bytes from `data` to the sector for `dataId` at byte offset `dataOffset` |
| `SSF_CFG_READ_STORAGE(data, dataSize, dataId, dataOffset)` | Read `dataSize` bytes from the sector for `dataId` at byte offset `dataOffset` into `data` |

**Thread sync macros** (required when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`; implement in `ssfoptions.h`):

| Macro | Description |
|-------|-------------|
| `SSF_CFG_THREAD_SYNC_DECLARATION` | Declare the thread sync object |
| `SSF_CFG_THREAD_SYNC_INIT()` | Initialize the thread sync object |
| `SSF_CFG_THREAD_SYNC_DEINIT()` | De-initialize the thread sync object |
| `SSF_CFG_THREAD_SYNC_ACQUIRE()` | Acquire the lock before accessing NV storage |
| `SSF_CFG_THREAD_SYNC_RELEASE()` | Release the lock after accessing NV storage |

<a id="api-summary"></a>

## [↑](#ssfcfg--version-controlled-configuration-storage) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-cfg-data-version-invalid"></a>`SSF_CFG_DATA_VERSION_INVALID` | Constant | `-1` — value returned by [`SSFCfgRead()`](#ssfcfgread) when no valid configuration block is found for the given `dataId` |
| <a id="dataid-t"></a>`dataId_t` | Type (`uint32_t`) | Identifies a configuration block; must be unique per configuration type and map to a distinct NV storage sector |
| <a id="dataversion-t"></a>`dataVersion_t` | Type (`int16_t`) | Version number for a configuration block; application-defined non-negative values; `SSF_CFG_DATA_VERSION_INVALID` is reserved |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFCfgInit()`](#ssfcfginit) | Initialize the module mutex (thread-safe builds only; `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`) |
| [e.g.](#ex-deinit) | [`void SSFCfgDeInit()`](#ssfcfgdeinit) | De-initialize the module mutex (thread-safe builds only) |
| [e.g.](#ex-write) | [`bool SSFCfgWrite(data, dataLen, dataId, dataVersion)`](#ssfcfgwrite) | Write versioned configuration data to NV storage with CRC protection |
| [e.g.](#ex-read) | [`dataVersion_t SSFCfgRead(data, datalen, dataSize, dataId)`](#ssfcfgread) | Read configuration data from NV storage; returns the stored version or `SSF_CFG_DATA_VERSION_INVALID` |

<a id="function-reference"></a>

## [↑](#ssfcfg--version-controlled-configuration-storage) Function Reference

<a id="ssfcfginit"></a>

### [↑](#functions) [`void SSFCfgInit()`](#functions)

```c
void SSFCfgInit(void);  /* compiled only when SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1 */
```

Initializes the internal mutex used to make `SSFCfgRead()` and `SSFCfgWrite()` thread-safe.
Must be called once before any other ssfcfg function in multi-threaded builds. Not compiled
when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 0`.

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
/* Only available when SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1 */
SSFCfgInit();
/* SSFCfgRead() and SSFCfgWrite() are now safe to call from multiple threads */
```

---

<a id="ssfcfgdeinit"></a>

### [↑](#functions) [`void SSFCfgDeInit()`](#functions)

```c
void SSFCfgDeInit(void);  /* compiled only when SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1 */
```

De-initializes the internal mutex. After this call, `SSFCfgRead()` and `SSFCfgWrite()` must
not be called until `SSFCfgInit()` is called again. Not compiled when
`SSF_CONFIG_ENABLE_THREAD_SUPPORT == 0`.

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
SSFCfgInit();
/* ... use SSFCfgRead / SSFCfgWrite ... */
SSFCfgDeInit();
/* Module mutex released; do not call SSFCfgRead/SSFCfgWrite until SSFCfgInit() again */
```

---

<a id="ssfcfgwrite"></a>

### [↑](#functions) [`bool SSFCfgWrite()`](#functions)

```c
bool SSFCfgWrite(uint8_t *data, uint16_t dataLen, dataId_t dataId, dataVersion_t dataVersion);
```

Writes `dataLen` bytes from `data` to NV storage for the given `dataId`, tagged with
`dataVersion` and protected by a CRC. Before writing, performs a read-back comparison; if the
NV storage already holds identical content (same `dataLen`, `dataId`, `dataVersion`, and CRC)
the erase and write cycle is suppressed and the function returns `false`, extending flash
endurance. The sector is erased and rewritten only when the stored content differs.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `data` | in | `uint8_t *` | Pointer to the configuration data to write. Must not be `NULL`. |
| `dataLen` | in | `uint16_t` | Number of bytes to write. May be `0`. Must be no more than `SSF_MAX_CFG_DATA_SIZE`. |
| `dataId` | in | `dataId_t` | Unique identifier for this configuration block. Maps to a distinct NV storage sector. |
| `dataVersion` | in | `dataVersion_t` | Application-defined version number to store alongside the data. Must be `>= 0`. |

**Returns:** `true` if new data was written to NV storage; `false` if the data in NV storage was
already identical (no write performed).

<a id="ex-write"></a>

**Example:**

```c
#define MY_CFG_ID  (0u)
#define MY_CFG_VER (1u)

uint8_t cfg[32];

/* Fill cfg with configuration data */
cfg[0] = 0x01u;
cfg[1] = 0x02u;

if (SSFCfgWrite(cfg, 2u, MY_CFG_ID, MY_CFG_VER))
{
    /* Data written to NV storage */
}

/* Redundant write of identical data — erase/write cycle is suppressed */
if (SSFCfgWrite(cfg, 2u, MY_CFG_ID, MY_CFG_VER) == false)
{
    /* Returns false; NV storage unchanged (content already matched) */
}
```

---

<a id="ssfcfgread"></a>

### [↑](#functions) [`dataVersion_t SSFCfgRead()`](#functions)

```c
dataVersion_t SSFCfgRead(uint8_t *data, uint16_t *datalen, size_t dataSize, dataId_t dataId);
```

Reads the configuration block for `dataId` from NV storage into `data`, validates the CRC,
and sets `*datalen` to the number of bytes read. Returns the version stored with the block, or
[`SSF_CFG_DATA_VERSION_INVALID`](#ssf-cfg-data-version-invalid) if no valid block is found.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `data` | out | `uint8_t *` | Buffer to receive the configuration data. Must not be `NULL`. |
| `datalen` | out | `uint16_t *` | Receives the actual number of bytes read. Must not be `NULL`. |
| `dataSize` | in | `size_t` | Allocated size of `data`. Must be at least as large as the stored `dataLen`; if smaller, the read fails and returns `SSF_CFG_DATA_VERSION_INVALID`. |
| `dataId` | in | `dataId_t` | Identifier of the configuration block to read. |

**Returns:** The `dataVersion_t` stored with the block if found and the CRC is valid;
[`SSF_CFG_DATA_VERSION_INVALID`](#ssf-cfg-data-version-invalid) (`-1`) if no valid block exists
for `dataId`. Compare the return value against the expected version constant to determine which
version (if any) was found.

<a id="ex-read"></a>

**Example:**

```c
#define MY_CFG_ID    (0u)
#define MY_CFG_VER_1 (1u)
#define MY_CFG_VER_2 (2u)

uint8_t       cfg[32];
uint16_t      cfgLen;
dataVersion_t ver;

ver = SSFCfgRead(cfg, &cfgLen, sizeof(cfg), MY_CFG_ID);

if (ver == MY_CFG_VER_2)
{
    /* Latest version found; cfgLen is the number of bytes read */
}
else if (ver == MY_CFG_VER_1)
{
    /* Older version found — migrate to V2 and persist */
    /* ... update cfg fields for V2 ... */
    SSFCfgWrite(cfg, cfgLen, MY_CFG_ID, MY_CFG_VER_2);
}
else
{
    /* SSF_CFG_DATA_VERSION_INVALID: no valid data found — apply defaults and persist */
    memset(cfg, 0, sizeof(cfg));
    SSFCfgWrite(cfg, sizeof(cfg), MY_CFG_ID, MY_CFG_VER_2);
}
```
