# ssfmpool — Memory Pool Interface

[SSF](../README.md) | [Data Structures](README.md)

Fixed-size block memory pool for deterministic O(1) allocation without fragmentation.

All blocks are allocated from the system heap once during `SSFMPoolInit()`. Every subsequent
`SSFMPoolAlloc()` and `SSFMPoolFree()` call is O(1) and involves no further heap interaction.
Each block is guarded by a canary value that detects buffer overruns at free time.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfmpool--memory-pool-interface) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`_opt/ssfmpool_opt.h`](../_opt/ssfmpool_opt.h) (aggregated through `ssfoptions.h`)
- [ssfll](ssfll.md) — Linked list (used internally)

<a id="notes"></a>

## [↑](#ssfmpool--memory-pool-interface) Notes

- `SSFMPoolAlloc()` asserts (never returns `NULL`) if the pool is empty; check
  `SSFMPoolIsEmpty()` before calling.
- `SSFMPoolAlloc()` asserts if `size` exceeds `blockSize`; pass `sizeof` your struct or a
  compile-time constant ≤ `blockSize`.
- `SSFMPoolFree()` returns `NULL`; assign the return value to null the caller's pointer:
  `ptr = (MyType_t *)SSFMPoolFree(&pool, ptr)`.
- `SSFMPoolDeInit()` asserts if any blocks are still allocated; free all blocks first.
- Each block carries a 3-byte canary; `SSFMPoolFree()` verifies it to detect overruns.
- When [`SSF_MPOOL_DEBUG`](#opt-mpool-debug) is `1`, each block records its `owner` tag to aid
  leak analysis.
- All blocks are the same size; allocating a struct smaller than `blockSize` is allowed but
  wastes the remainder.

<a id="configuration"></a>

## [↑](#ssfmpool--memory-pool-interface) Configuration

Options live in [`_opt/ssfmpool_opt.h`](../_opt/ssfmpool_opt.h) (aggregated into the build via `ssfoptions.h`).

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-mpool-debug"></a>`SSF_MPOOL_DEBUG` | `0` | `1` to enable a debug structure that tracks all blocks and their `owner` tags |

<a id="api-summary"></a>

## [↑](#ssfmpool--memory-pool-interface) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfmpool-t"></a>`SSFMPool_t` | Struct | Pool instance; pass by pointer to all API functions. Do not access fields directly. |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-init) | [`void SSFMPoolInit(pool, blocks, blockSize)`](#ssfmpoolinit) | Initialize a memory pool |
| [e.g.](#ex-deinit) | [`void SSFMPoolDeInit(pool)`](#ssfmpooldeinit) | De-initialize a memory pool |
| [e.g.](#ex-alloc) | [`void *SSFMPoolAlloc(pool, size, owner)`](#ssfmpoolalloc) | Allocate a block from the pool |
| [e.g.](#ex-free) | [`void *SSFMPoolFree(pool, ptr)`](#ssfmpoolfree) | Free a block back to the pool |
| [e.g.](#ex-blocksize) | [`uint32_t SSFMPoolBlockSize(pool)`](#ssfmpoolblocksize) | Returns the fixed block size in bytes |
| [e.g.](#ex-size) | [`uint32_t SSFMPoolSize(pool)`](#ssfmpoolsize) | Returns the total number of blocks in the pool |
| [e.g.](#ex-len) | [`uint32_t SSFMPoolLen(pool)`](#ssfmpoollen) | Returns the number of free blocks remaining |
| [e.g.](#ex-isempty) | [`bool SSFMPoolIsEmpty(pool)`](#ssfmpoolisempty) | Returns true if no free blocks remain |
| [e.g.](#ex-isfull) | [`bool SSFMPoolIsFull(pool)`](#ssfmpoolisfull) | Returns true if all blocks are free |

<a id="function-reference"></a>

## [↑](#ssfmpool--memory-pool-interface) Function Reference

<a id="ssfmpoolinit"></a>

### [↑](#functions) [`void SSFMPoolInit()`](#functions)

```c
void SSFMPoolInit(SSFMPool_t *pool, uint32_t blocks, uint32_t blockSize);
```

Initializes a memory pool by allocating `blocks` blocks of `blockSize` bytes each from the
system heap. The pool thereafter provides O(1) allocation and deallocation with no further heap
calls. Each block is zero-initialized and guarded by a canary value. The pool must not already
be initialized; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | out | [`SSFMPool_t *`](#type-ssfmpool-t) | Pointer to the pool structure to initialize. Must not be `NULL`. Must not already be initialized. |
| `blocks` | in | `uint32_t` | Number of blocks to allocate. Must be greater than `0`. |
| `blockSize` | in | `uint32_t` | Size of each block in bytes. Must be greater than `0`. |

**Returns:** Nothing. Asserts if `malloc` fails.

<a id="ex-init"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
/* pool holds 4 blocks of sizeof(MyMsg_t) bytes each */
```

---

<a id="ssfmpooldeinit"></a>

### [↑](#functions) [`void SSFMPoolDeInit()`](#functions)

```c
void SSFMPoolDeInit(SSFMPool_t *pool);
```

De-initializes the memory pool, freeing all block memory back to the system heap. All allocated
blocks must have been freed before calling; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in-out | [`SSFMPool_t *`](#type-ssfmpool-t) | Pointer to an initialized pool with all blocks returned. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
SSFMPoolDeInit(&pool);
/* pool is no longer valid */
```

---

<a id="ssfmpoolalloc"></a>

### [↑](#functions) [`void *SSFMPoolAlloc()`](#functions)

```c
void *SSFMPoolAlloc(SSFMPool_t *pool, uint32_t size, uint8_t owner);
```

Allocates one block from the pool and returns a pointer to it. The `size` argument is validated
against the pool's `blockSize`; it must not exceed `blockSize`. The block is not zeroed on
allocation. The `owner` tag is stored in the block's canary area to aid leak analysis when
[`SSF_MPOOL_DEBUG`](#opt-mpool-debug) is `1`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in-out | [`SSFMPool_t *`](#type-ssfmpool-t) | Pointer to an initialized pool. Must not be `NULL`. Must not be empty. |
| `size` | in | `uint32_t` | Requested allocation size in bytes. Must not exceed the pool's `blockSize`. |
| `owner` | in | `uint8_t` | Tag identifying the allocating code path. Stored in the block header regardless of `SSF_MPOOL_DEBUG`. |

**Returns:** Pointer to the allocated block. Asserts if the pool is empty or `size > blockSize`.

<a id="ex-alloc"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;
MyMsg_t *msg;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));

if (SSFMPoolIsEmpty(&pool) == false)
{
    msg = (MyMsg_t *)SSFMPoolAlloc(&pool, sizeof(MyMsg_t), 0x01u);
    msg->id = 42u;
    /* pool has 3 free blocks */
}
```

---

<a id="ssfmpoolfree"></a>

### [↑](#functions) [`void *SSFMPoolFree()`](#functions)

```c
void *SSFMPoolFree(SSFMPool_t *pool, void *ptr);
```

Returns a previously allocated block back to the pool. The canary value is verified before
returning the block; asserting on corruption or overrun. After this call the pointer is invalid.
Returns `NULL` to enable the nulling pattern `ptr = SSFMPoolFree(&pool, ptr)`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in-out | [`SSFMPool_t *`](#type-ssfmpool-t) | Pointer to the pool the block was allocated from. Must not be `NULL`. |
| `ptr` | in | `void *` | Pointer to the block to free. Must not be `NULL`. Must have been returned by `SSFMPoolAlloc()` on this pool. |

**Returns:** Always `NULL`.

<a id="ex-free"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;
MyMsg_t *msg;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
msg = (MyMsg_t *)SSFMPoolAlloc(&pool, sizeof(MyMsg_t), 0x01u);

msg = (MyMsg_t *)SSFMPoolFree(&pool, msg);
/* msg == NULL; pool has 4 free blocks */
```

---

<a id="ssfmpoolblocksize"></a>

### [↑](#functions) [`uint32_t SSFMPoolBlockSize()`](#functions)

```c
uint32_t SSFMPoolBlockSize(const SSFMPool_t *pool);
```

Returns the fixed block size of the pool.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | [`const SSFMPool_t *`](#type-ssfmpool-t) | Pointer to an initialized pool. Must not be `NULL`. |

**Returns:** The `blockSize` value supplied to `SSFMPoolInit()`.

<a id="ex-blocksize"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
SSFMPoolBlockSize(&pool);   /* returns sizeof(MyMsg_t) */
```

---

<a id="ssfmpoolsize"></a>

### [↑](#functions) [`uint32_t SSFMPoolSize()`](#functions)

```c
uint32_t SSFMPoolSize(const SSFMPool_t *pool);
```

Returns the total number of blocks in the pool.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | [`const SSFMPool_t *`](#type-ssfmpool-t) | Pointer to an initialized pool. Must not be `NULL`. |

**Returns:** The `blocks` value supplied to `SSFMPoolInit()`.

<a id="ex-size"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
SSFMPoolSize(&pool);   /* returns 4 */
```

---

<a id="ssfmpoollen"></a>

### [↑](#functions) [`uint32_t SSFMPoolLen()`](#functions)

```c
uint32_t SSFMPoolLen(const SSFMPool_t *pool);
```

Returns the number of free (available) blocks remaining in the pool.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | [`const SSFMPool_t *`](#type-ssfmpool-t) | Pointer to an initialized pool. Must not be `NULL`. |

**Returns:** Number of free blocks currently available for allocation (`Size` minus the number
of allocated blocks).

<a id="ex-len"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;
MyMsg_t *msg;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
SSFMPoolLen(&pool);   /* returns 4 (all blocks free) */

msg = (MyMsg_t *)SSFMPoolAlloc(&pool, sizeof(MyMsg_t), 0x01u);
SSFMPoolLen(&pool);   /* returns 3 */
```

---

<a id="ssfmpoolisempty"></a>

### [↑](#functions) [`bool SSFMPoolIsEmpty()`](#functions)

```c
bool SSFMPoolIsEmpty(const SSFMPool_t *pool);
```

Returns `true` if no free blocks remain — i.e., all blocks are currently allocated. Calling
`SSFMPoolAlloc()` on an empty pool will assert; check this function first.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | [`const SSFMPool_t *`](#type-ssfmpool-t) | Pointer to an initialized pool. Must not be `NULL`. |

**Returns:** `true` if no free blocks remain; `false` otherwise.

<a id="ex-isempty"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;
MyMsg_t *msgs[4];
uint32_t i;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
SSFMPoolIsEmpty(&pool);   /* returns false */

for (i = 0; i < 4u; i++) { msgs[i] = (MyMsg_t *)SSFMPoolAlloc(&pool, sizeof(MyMsg_t), 0x01u); }
SSFMPoolIsEmpty(&pool);   /* returns true (all blocks allocated) */
```

---

<a id="ssfmpoolisfull"></a>

### [↑](#functions) [`bool SSFMPoolIsFull()`](#functions)

```c
bool SSFMPoolIsFull(const SSFMPool_t *pool);
```

Returns `true` if all blocks are free — i.e., no blocks are currently allocated. This is the
required state before calling `SSFMPoolDeInit()`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | [`const SSFMPool_t *`](#type-ssfmpool-t) | Pointer to an initialized pool. Must not be `NULL`. |

**Returns:** `true` if all blocks are free; `false` otherwise.

<a id="ex-isfull"></a>

**Example:**

```c
typedef struct { uint32_t id; uint8_t payload[16]; } MyMsg_t;

SSFMPool_t pool;
MyMsg_t *msg;

SSFMPoolInit(&pool, 4u, sizeof(MyMsg_t));
SSFMPoolIsFull(&pool);   /* returns true (all blocks free) */

msg = (MyMsg_t *)SSFMPoolAlloc(&pool, sizeof(MyMsg_t), 0x01u);
SSFMPoolIsFull(&pool);   /* returns false */
```
