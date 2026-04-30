# ssfheap — Integrity-Checked Heap Interface

[SSF](../README.md) | [Data Structures](README.md)

Pedantic heap with integrity checking, double-free detection, and mark-based ownership tracking.

The heap operates entirely over a caller-supplied byte array — no system `malloc` is ever called.
Every allocation and free operation verifies block header checksums and checks the adjacent block
for overruns. Block headers use `+`/`-` ASCII markers that remain visible in raw memory dumps.

> **Note:** This is NOT a drop-in replacement for `malloc`/`free`. The API is intentionally more
> explicit to prevent common dynamic memory mistakes.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfheap--integrity-checked-heap-interface) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`_opt/ssfheap_opt.h`](../_opt/ssfheap_opt.h) (aggregated through `ssfoptions.h`)
- [ssfll](ssfll.md) — Linked list (used internally)
- [ssffcsum](../_edc/ssffcsum.md) — Fletcher checksum (used for block header integrity)

<a id="notes"></a>

## [↑](#ssfheap--integrity-checked-heap-interface) Notes

- `SSFHeapInit()` requires `*handleOut == NULL` before the call.
- `SSFHeapAlloc()` / `SSFHeapMalloc()` require `*heapMemOut == NULL` before the call.
- `SSFHeapDealloc()` / `SSFHeapFree()` set `*heapMemOut` to `NULL` on return; asserting on
  double-free.
- `SSFHeapDeInit()` asserts if any allocations remain; free all memory before de-initializing.
- `SSFHeapAllocResize()` treats a `NULL` `*heapMemOut` as a fresh allocation. On failure the
  original allocation is left unchanged.
- All integrity checks run on every operation; corruption is reported immediately via assertion.
- Designed to work on 8, 16, 32, and 64-bit machine word sizes.
- All allocations are aligned to the machine word size (`sizeof(uint64_t)`).
- Pass `NULL` for `markOutOpt` in `SSFHeapDealloc()` / `SSFHeapFree()` to skip mark retrieval.

<a id="configuration"></a>

## [↑](#ssfheap--integrity-checked-heap-interface) Configuration

Options live in [`_opt/ssfheap_opt.h`](../_opt/ssfheap_opt.h) (aggregated into the build via `ssfoptions.h`).

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-heap-set-block-check"></a>`SSF_HEAP_SET_BLOCK_CHECK` | `0` | `1` to verify block headers after every modification; useful when porting to a new architecture |

<a id="api-summary"></a>

## [↑](#ssfheap--integrity-checked-heap-interface) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfheaphandle-t"></a>`SSFHeapHandle_t` | Typedef | Opaque heap handle (`void *`); must be initialized to `NULL`, set by `SSFHeapInit()`, cleared by `SSFHeapDeInit()`. Do not dereference directly. |
| <a id="type-ssfheapstatus-t"></a>`SSFHeapStatus_t` | Struct | Heap usage snapshot populated by [`SSFHeapStatus()`](#ssfheapstatus). Fields: `allocatableSize` (total allocatable bytes), `allocatableLen` (current free bytes), `minAllocatableLen` (low-water mark), `numBlocks` (current block count), `numAllocatableBlocks` (free block count), `maxAllocatableBlockLen` (largest free block), `numTotalAllocRequests`, `numAllocRequests`, `numFreeRequests`. |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-initminmemsize) | [`uint32_t SSFHeapInitMinMemSize()`](#ssfheapinitminmemsize) | Returns the minimum buffer size required to create a heap |
| [e.g.](#ex-init) | [`void SSFHeapInit(handleOut, heapMem, heapMemSize, heapMark, isZeroed)`](#ssfheapinit) | Initialize a heap over a user-supplied buffer |
| [e.g.](#ex-deinit) | [`void SSFHeapDeInit(handleOut, isZeroed)`](#ssfheapdeinit) | De-initialize a heap |
| [e.g.](#ex-check) | [`void SSFHeapCheck(handle)`](#ssfheapcheck) | Verify heap integrity; asserts on corruption |
| [e.g.](#ex-status) | [`void SSFHeapStatus(handle, statusOut)`](#ssfheapstatus) | Retrieve heap usage statistics |
| [e.g.](#ex-alloc) | [`bool SSFHeapAlloc(handle, heapMemOut, size, mark, isZeroed)`](#ssfheapalloc) | Allocate memory from the heap |
| [e.g.](#ex-allocresize) | [`bool SSFHeapAllocResize(handle, heapMemOut, newSize, newMark, newIsZeroed)`](#ssfheapallocresize) | Resize an existing allocation |
| [e.g.](#ex-dealloc) | [`void SSFHeapDealloc(handle, heapMemOut, markOutOpt, isZeroed)`](#ssfheapdealloc) | Free memory back to the heap |
| [e.g.](#ex-macro-malloc) | [`bool SSFHeapMalloc(handle, heapMemOut, size, mark)`](#ssf-heap-malloc) | Macro: allocate without zeroing |
| [e.g.](#ex-macro-malloc-and-zero) | [`bool SSFHeapMallocAndZero(handle, heapMemOut, size, mark)`](#ssf-heap-malloc-and-zero) | Macro: allocate and zero memory |
| [e.g.](#ex-macro-realloc) | [`bool SSFHeapRealloc(handle, heapMemOut, newSize, newMark)`](#ssf-heap-realloc) | Macro: resize without zeroing new area |
| [e.g.](#ex-macro-realloc-and-zero-new) | [`bool SSFHeapReallocAndZeroNew(handle, heapMemOut, newSize, newMark)`](#ssf-heap-realloc-and-zero-new) | Macro: resize and zero newly added area |
| [e.g.](#ex-macro-free) | [`void SSFHeapFree(handle, heapMemOut, markOutOpt)`](#ssf-heap-free) | Macro: free without zeroing |
| [e.g.](#ex-macro-free-and-zero) | [`void SSFHeapFreeAndZero(handle, heapMemOut, markOutOpt)`](#ssf-heap-free-and-zero) | Macro: free and zero the freed memory |

<a id="function-reference"></a>

## [↑](#ssfheap--integrity-checked-heap-interface) Function Reference

<a id="ssfheapinitminmemsize"></a>

### [↑](#functions) [`uint32_t SSFHeapInitMinMemSize()`](#functions)

```c
uint32_t SSFHeapInitMinMemSize(void);
```

Returns the minimum number of bytes that the heap memory buffer must be to successfully
initialize a heap. A buffer of exactly this size yields zero allocatable bytes; use a larger
buffer to allow actual allocations.

**Returns:** Minimum number of bytes required for heap metadata and block headers.

<a id="ex-initminmemsize"></a>

**Example:**

```c
uint32_t minSize;

minSize = SSFHeapInitMinMemSize();
/* minSize is the minimum buffer size needed to initialize a heap */
/* A buffer larger than minSize provides allocatable memory */
```

---

<a id="ssfheapinit"></a>

### [↑](#functions) [`void SSFHeapInit()`](#functions)

```c
void SSFHeapInit(SSFHeapHandle_t *handleOut, uint8_t *heapMem, uint32_t heapMemSize,
                 uint8_t heapMark, bool isZeroed);
```

Initializes a heap over the caller-supplied byte array `heapMem`. The heap handle written to
`*handleOut` is an opaque pointer into `heapMem` and must be passed to all subsequent heap
operations. `heapMem` must remain valid for the lifetime of the heap.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handleOut` | out | [`SSFHeapHandle_t *`](#type-ssfheaphandle-t) | Receives the opaque heap handle. Must not be `NULL`. Must point to `NULL` before the call. |
| `heapMem` | in | `uint8_t *` | Caller-supplied backing buffer. Must not be `NULL`. Must be at least `SSFHeapInitMinMemSize()` bytes. |
| `heapMemSize` | in | `uint32_t` | Total size of `heapMem` in bytes. |
| `heapMark` | in | `uint8_t` | Owner tag written into every block header during init. Use a unique value per heap to distinguish heaps in memory dumps. |
| `isZeroed` | in | `bool` | `true` to zero all of `heapMem` before initializing; `false` to zero only the heap handle area. |

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
/* h is a valid heap handle */
SSFHeapDeInit(&h, false);
```

---

<a id="ssfheapdeinit"></a>

### [↑](#functions) [`void SSFHeapDeInit()`](#functions)

```c
void SSFHeapDeInit(SSFHeapHandle_t *handleOut, bool isZeroed);
```

De-initializes the heap. All allocations must have been freed before calling; asserting
otherwise. Sets `*handleOut` to `NULL` on return.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handleOut` | in-out | [`SSFHeapHandle_t *`](#type-ssfheaphandle-t) | Pointer to the heap handle. Set to `NULL` on return. Must not be `NULL`. Must not point to `NULL`. |
| `isZeroed` | in | `bool` | `true` to zero all of `heapMem` after de-init; `false` to zero only the heap handle area. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapDeInit(&h, false);
/* h == NULL; heap is no longer valid */
```

---

<a id="ssfheapcheck"></a>

### [↑](#functions) [`void SSFHeapCheck()`](#functions)

```c
void SSFHeapCheck(SSFHeapHandle_t handle);
```

Walks all heap block headers and verifies their integrity checksums. Asserts immediately if
any corruption is detected. Use during development or debugging to catch memory overwrites early.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle returned by `SSFHeapInit()`. Must be valid (non-`NULL`). |

**Returns:** Nothing.

<a id="ex-check"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapCheck(h);
/* returns normally if heap is intact; asserts on corruption */
SSFHeapDeInit(&h, false);
```

---

<a id="ssfheapstatus"></a>

### [↑](#functions) [`void SSFHeapStatus()`](#functions)

```c
void SSFHeapStatus(SSFHeapHandle_t handle, SSFHeapStatus_t *statusOut);
```

Fills `*statusOut` with a snapshot of current heap statistics. Condenses adjacent free blocks
before computing free-space figures.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `statusOut` | out | [`SSFHeapStatus_t *`](#type-ssfheapstatus-t) | Receives the status snapshot. Must not be `NULL`. `allocatableSize`: total allocatable bytes (fixed at init). `allocatableLen`: current free bytes. `minAllocatableLen`: low-water mark. `numBlocks`: current total block count. `numAllocatableBlocks`: current free block count. `maxAllocatableBlockLen`: largest single free block. `numTotalAllocRequests`: cumulative allocation attempts. `numAllocRequests`: successful allocations. `numFreeRequests`: cumulative free calls. |

**Returns:** Nothing.

<a id="ex-status"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
SSFHeapStatus_t status;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapMalloc(h, &ptr, 64u, APP_MARK);

SSFHeapStatus(h, &status);
/* status.allocatableLen == (status.allocatableSize - aligned 64 bytes - block overhead) */
/* status.numAllocRequests == 1 */

SSFHeapFree(h, &ptr, NULL);
SSFHeapDeInit(&h, false);
```

---

<a id="ssfheapalloc"></a>

### [↑](#functions) [`bool SSFHeapAlloc()`](#functions)

```c
bool SSFHeapAlloc(SSFHeapHandle_t handle, void **heapMemOut, uint32_t size, uint8_t mark,
                  bool isZeroed);
```

Allocates `size` bytes from the heap using a first-fit strategy. On success `*heapMemOut` is
set to the allocated block. On failure `*heapMemOut` is set to `NULL`. Prefer the
`SSFHeapMalloc()` or `SSFHeapMallocAndZero()` macros instead of calling this directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | out | `void **` | Receives a pointer to the allocated block on success, `NULL` on failure. Must not be `NULL`. Must point to `NULL` before the call. |
| `size` | in | `uint32_t` | Number of bytes to allocate. Passing `0` requests a minimum-sized allocation. |
| `mark` | in | `uint8_t` | Owner tag written into the block header to identify the allocator. |
| `isZeroed` | in | `bool` | `true` to zero the allocated memory before returning it. |

**Returns:** `true` if allocation succeeded; `false` if the heap has insufficient contiguous free space.

<a id="ex-alloc"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);

if (SSFHeapAlloc(h, (void **)&ptr, 64u, APP_MARK, false))
{
    /* ptr points to a 64-byte block */
    SSFHeapDealloc(h, (void **)&ptr, NULL, false);
    /* ptr == NULL */
}

SSFHeapDeInit(&h, false);
```

---

<a id="ssfheapallocresize"></a>

### [↑](#functions) [`bool SSFHeapAllocResize()`](#functions)

```c
bool SSFHeapAllocResize(SSFHeapHandle_t handle, void **heapMemOut, uint32_t newSize,
                        uint8_t newMark, bool newIsZeroed);
```

Resizes an existing allocation. If `*heapMemOut` is `NULL` on entry, behaves as a fresh
allocation. On success `*heapMemOut` is updated to the new location (which may differ from the
original) and the old block is freed; existing data is preserved up to `min(newSize, oldSize)`.
On failure `*heapMemOut` is left unchanged and the original allocation remains valid. Prefer the
`SSFHeapRealloc()` or `SSFHeapReallocAndZeroNew()` macros instead of calling this directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | On entry, points to the existing allocation or `NULL` for a fresh alloc. On success, updated to the new allocation. On failure, left unchanged. Must not be `NULL`. |
| `newSize` | in | `uint32_t` | New requested size in bytes. Passing `0` requests a minimum-sized allocation. |
| `newMark` | in | `uint8_t` | Owner tag for the resized block. |
| `newIsZeroed` | in | `bool` | `true` to zero any newly added bytes when growing. |

**Returns:** `true` if resize succeeded; `false` if the heap has insufficient space for the new size.

<a id="ex-allocresize"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapAlloc(h, (void **)&ptr, 64u, APP_MARK, false);

if (SSFHeapAllocResize(h, (void **)&ptr, 128u, APP_MARK, false))
{
    /* ptr points to a 128-byte block; original 64 bytes preserved */
}
/* if resize fails, ptr still points to the original 64-byte block */

if (ptr != NULL) { SSFHeapDealloc(h, (void **)&ptr, NULL, false); }
SSFHeapDeInit(&h, false);
```

---

<a id="ssfheapdealloc"></a>

### [↑](#functions) [`void SSFHeapDealloc()`](#functions)

```c
void SSFHeapDealloc(SSFHeapHandle_t handle, void **heapMemOut, uint8_t *markOutOpt,
                    bool isZeroed);
```

Frees a previously allocated block back to the heap. Sets `*heapMemOut` to `NULL` on return.
Verifies block header integrity and checks the adjacent block for overruns. Asserts on
double-free or corruption. Prefer the `SSFHeapFree()` or `SSFHeapFreeAndZero()` macros instead
of calling this directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | Pointer to the allocation to free. Set to `NULL` on return. Must not be `NULL`. Must not point to `NULL` (asserts on double-free). |
| `markOutOpt` | out (opt) | `uint8_t *` | If not `NULL`, receives the mark value stored in the freed block header. Pass `NULL` to skip mark retrieval. |
| `isZeroed` | in | `bool` | `true` to zero the freed block memory before returning it to the free pool. |

**Returns:** Nothing.

<a id="ex-dealloc"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;
uint8_t mark;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapAlloc(h, (void **)&ptr, 64u, APP_MARK, false);

SSFHeapDealloc(h, (void **)&ptr, &mark, false);
/* ptr == NULL; mark == APP_MARK */

SSFHeapDeInit(&h, false);
```

---

<a id="convenience-macros"></a>

### [↑](#functions) [Convenience Macros](#functions)

Macros that wrap `SSFHeapAlloc()`, `SSFHeapAllocResize()`, and `SSFHeapDealloc()` with the
`isZeroed` argument fixed, eliminating the need to pass it explicitly on every call. Use these
in preference to calling the underlying functions directly.

---

<a id="ssf-heap-malloc"></a>

#### [↑](#functions) [`bool SSFHeapMalloc()`](#functions)

```c
#define SSFHeapMalloc(handle, heapMemOut, size, mark) \
    SSFHeapAlloc(handle, (void **)heapMemOut, size, mark, false)
```

Allocates `size` bytes from the heap without zeroing the allocated memory.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | out | `void **` | Receives the allocated block on success, `NULL` on failure. Must not be `NULL`. Must point to `NULL` before the call. |
| `size` | in | `uint32_t` | Number of bytes to allocate. |
| `mark` | in | `uint8_t` | Owner tag written into the block header. |

**Returns:** `true` if allocation succeeded; `false` if insufficient contiguous free space.

<a id="ex-macro-malloc"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);

if (SSFHeapMalloc(h, &ptr, 64u, APP_MARK))
{
    /* ptr points to an unzeroed 64-byte block */
    SSFHeapFree(h, &ptr, NULL);
    /* ptr == NULL */
}

SSFHeapDeInit(&h, false);
```

---

<a id="ssf-heap-malloc-and-zero"></a>

#### [↑](#functions) [`bool SSFHeapMallocAndZero()`](#functions)

```c
#define SSFHeapMallocAndZero(handle, heapMemOut, size, mark) \
    SSFHeapAlloc(handle, (void **)heapMemOut, size, mark, true)
```

Allocates `size` bytes from the heap and zeroes the allocated memory before returning it.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | out | `void **` | Receives the zero-initialized allocated block on success, `NULL` on failure. Must not be `NULL`. Must point to `NULL` before the call. |
| `size` | in | `uint32_t` | Number of bytes to allocate. |
| `mark` | in | `uint8_t` | Owner tag written into the block header. |

**Returns:** `true` if allocation succeeded; `false` if insufficient contiguous free space.

<a id="ex-macro-malloc-and-zero"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);

if (SSFHeapMallocAndZero(h, &ptr, 64u, APP_MARK))
{
    /* ptr points to a zero-initialized 64-byte block */
    SSFHeapFree(h, &ptr, NULL);
}

SSFHeapDeInit(&h, false);
```

---

<a id="ssf-heap-realloc"></a>

#### [↑](#functions) [`bool SSFHeapRealloc()`](#functions)

```c
#define SSFHeapRealloc(handle, heapMemOut, newSize, newMark) \
    SSFHeapAllocResize(handle, (void **)heapMemOut, newSize, newMark, false)
```

Resizes an existing allocation without zeroing any newly added bytes.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | On entry, points to the existing allocation or `NULL`. Updated on success. Left unchanged on failure. Must not be `NULL`. |
| `newSize` | in | `uint32_t` | New requested size in bytes. |
| `newMark` | in | `uint8_t` | Owner tag for the resized block. |

**Returns:** `true` if resize succeeded; `false` if insufficient heap space.

<a id="ex-macro-realloc"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapMalloc(h, &ptr, 64u, APP_MARK);

if (SSFHeapRealloc(h, &ptr, 128u, APP_MARK))
{
    /* ptr points to 128-byte block; original 64 bytes preserved; bytes 64-127 unzeroed */
}
if (ptr != NULL) { SSFHeapFree(h, &ptr, NULL); }

SSFHeapDeInit(&h, false);
```

---

<a id="ssf-heap-realloc-and-zero-new"></a>

#### [↑](#functions) [`bool SSFHeapReallocAndZeroNew()`](#functions)

```c
#define SSFHeapReallocAndZeroNew(handle, heapMemOut, newSize, newMark) \
    SSFHeapAllocResize(handle, (void **)heapMemOut, newSize, newMark, true)
```

Resizes an existing allocation and zeroes any bytes added when the allocation grows.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | On entry, points to the existing allocation or `NULL`. Updated on success. Left unchanged on failure. Must not be `NULL`. |
| `newSize` | in | `uint32_t` | New requested size in bytes. |
| `newMark` | in | `uint8_t` | Owner tag for the resized block. |

**Returns:** `true` if resize succeeded; `false` if insufficient heap space.

<a id="ex-macro-realloc-and-zero-new"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapMalloc(h, &ptr, 64u, APP_MARK);

if (SSFHeapReallocAndZeroNew(h, &ptr, 128u, APP_MARK))
{
    /* ptr points to 128-byte block; original 64 bytes preserved; bytes 64-127 zeroed */
}
if (ptr != NULL) { SSFHeapFree(h, &ptr, NULL); }

SSFHeapDeInit(&h, false);
```

---

<a id="ssf-heap-free"></a>

#### [↑](#functions) [`void SSFHeapFree()`](#functions)

```c
#define SSFHeapFree(handle, heapMemOut, markOutOpt) \
    SSFHeapDealloc(handle, (void **)heapMemOut, markOutOpt, false)
```

Frees a previously allocated block without zeroing its memory.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | Pointer to the allocation to free. Set to `NULL` on return. Must not point to `NULL`. |
| `markOutOpt` | out (opt) | `uint8_t *` | If not `NULL`, receives the mark value from the freed block header. |

**Returns:** Nothing.

<a id="ex-macro-free"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapMalloc(h, &ptr, 64u, APP_MARK);

SSFHeapFree(h, &ptr, NULL);
/* ptr == NULL; block memory not zeroed */

SSFHeapDeInit(&h, false);
```

---

<a id="ssf-heap-free-and-zero"></a>

#### [↑](#functions) [`void SSFHeapFreeAndZero()`](#functions)

```c
#define SSFHeapFreeAndZero(handle, heapMemOut, markOutOpt) \
    SSFHeapDealloc(handle, (void **)heapMemOut, markOutOpt, true)
```

Frees a previously allocated block and zeroes its memory before returning it to the free pool.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFHeapHandle_t`](#type-ssfheaphandle-t) | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | Pointer to the allocation to free. Set to `NULL` on return. Must not point to `NULL`. |
| `markOutOpt` | out (opt) | `uint8_t *` | If not `NULL`, receives the mark value from the freed block header. |

**Returns:** Nothing.

<a id="ex-macro-free-and-zero"></a>

**Example:**

```c
#define HEAP_SIZE  (1024u)
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')

uint8_t heapMem[HEAP_SIZE];
SSFHeapHandle_t h = NULL;
uint8_t *ptr = NULL;

SSFHeapInit(&h, heapMem, sizeof(heapMem), HEAP_MARK, false);
SSFHeapMalloc(h, &ptr, 64u, APP_MARK);

SSFHeapFreeAndZero(h, &ptr, NULL);
/* ptr == NULL; freed block memory zeroed */

SSFHeapDeInit(&h, false);
```
