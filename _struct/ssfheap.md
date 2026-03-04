# ssfheap — Integrity-Checked Heap

[Back to Data Structures README](README.md) | [Back to ssf README](../README.md)

Pedantic heap with integrity checking, double-free detection, and mark-based ownership tracking.

> **Note:** This is NOT a drop-in replacement for `malloc`/`free`. The API is intentionally more
> explicit to prevent common dynamic memory mistakes.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_HEAP_SET_BLOCK_CHECK` | `0` | `1` to verify block headers after every modification (useful when porting to a new architecture) |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFHeapInitMinMemSize()` | Returns the minimum memory size required for an empty heap |
| `SSFHeapInit(handle, buf, bufSize, heapMark, isZeroed)` | Initialize a heap over a user-supplied buffer |
| `SSFHeapDeInit(handle, isZeroed)` | De-initialize a heap |
| `SSFHeapCheck(handle)` | Verify heap integrity; asserts on corruption |
| `SSFHeapStatus(handle, statusOut)` | Retrieve heap usage statistics |
| `SSFHeapAlloc(handle, pptr, size, mark, isZeroed)` | Allocate memory from the heap |
| `SSFHeapMalloc(handle, pptr, size, mark)` | Macro: allocate without zeroing |
| `SSFHeapMallocAndZero(handle, pptr, size, mark)` | Macro: allocate and zero memory |
| `SSFHeapAllocResize(handle, pptr, newSize, newMark, newIsZeroed)` | Resize an allocation |
| `SSFHeapRealloc(handle, pptr, newSize, newMark)` | Macro: resize without zeroing new area |
| `SSFHeapReallocAndZeroNew(handle, pptr, newSize, newMark)` | Macro: resize and zero newly added area |
| `SSFHeapDealloc(handle, pptr, markOutOpt, isZeroed)` | Free memory back to the heap |
| `SSFHeapFree(handle, pptr, markOutOpt)` | Macro: free without zeroing |
| `SSFHeapFreeAndZero(handle, pptr, markOutOpt)` | Macro: free and zero the freed memory |

## Function Reference

### `SSFHeapInitMinMemSize`

```c
uint32_t SSFHeapInitMinMemSize(void);
```

Returns the minimum number of bytes that the heap memory buffer must be to hold at least one
allocation. Use this to validate that a proposed heap buffer is large enough.

**Returns:** Minimum number of bytes required for the heap metadata and at least one block header.

---

### `SSFHeapInit`

```c
void SSFHeapInit(SSFHeapHandle_t *heapHandleOut, uint8_t *heapMem, uint32_t heapMemSize,
                 uint8_t heapMark, bool isZeroed);
```

Initializes a heap over the caller-supplied byte array `heapMem`. The heap handle written to
`*heapHandleOut` is an opaque pointer into `heapMem` and must be passed to all subsequent heap
operations. `heapMem` must remain valid for the lifetime of the heap.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `heapHandleOut` | out | `SSFHeapHandle_t *` | Receives the opaque heap handle. Must not be `NULL`. |
| `heapMem` | in | `uint8_t *` | Caller-supplied backing buffer. Must not be `NULL`. Must be at least `SSFHeapInitMinMemSize()` bytes. |
| `heapMemSize` | in | `uint32_t` | Total size of `heapMem` in bytes. |
| `heapMark` | in | `uint8_t` | Owner tag written into every block header during init. Use a unique value per heap to distinguish heaps in memory dumps. |
| `isZeroed` | in | `bool` | `true` to zero `heapMem` before initializing (useful if the memory may contain stale data); `false` to skip zeroing. |

**Returns:** Nothing.

---

### `SSFHeapDeInit`

```c
void SSFHeapDeInit(SSFHeapHandle_t *heapHandleOut, bool isZeroed);
```

De-initializes the heap. All allocations must have been freed before calling this function;
asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `heapHandleOut` | in-out | `SSFHeapHandle_t *` | Pointer to the heap handle. Set to `NULL` on return. Must not be `NULL`. |
| `isZeroed` | in | `bool` | `true` to zero the heap memory after de-init. |

**Returns:** Nothing.

---

### `SSFHeapCheck`

```c
void SSFHeapCheck(SSFHeapHandle_t handle);
```

Walks all heap block headers and verifies their integrity markers. Asserts immediately if any
corruption is detected. Use during development or debugging to catch memory overwrites early.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | `SSFHeapHandle_t` | Opaque heap handle returned by `SSFHeapInit`. Must be valid. |

**Returns:** Nothing.

---

### `SSFHeapStatus`

```c
void SSFHeapStatus(SSFHeapHandle_t handle, SSFHeapStatus_t *heapStatusOut);
```

Fills `*heapStatusOut` with current heap statistics including free space, block counts, and
low-water marks.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | `SSFHeapHandle_t` | Opaque heap handle. Must be valid. |
| `heapStatusOut` | out | `SSFHeapStatus_t *` | Receives the status. Must not be `NULL`. Fields include `allocatableSize`, `allocatableLen`, `minAllocatableLen`, `numBlocks`, `numAllocatableBlocks`, `maxAllocatableBlockLen`, `numTotalAllocRequests`, `numAllocRequests`, `numFreeRequests`. |

**Returns:** Nothing.

---

### `SSFHeapAlloc`

```c
bool SSFHeapAlloc(SSFHeapHandle_t handle, void **heapMemOut, uint32_t size, uint8_t mark,
                  bool isZeroed);
```

Allocates `size` bytes from the heap. On success, `*heapMemOut` is set to the allocated block.
On failure, `*heapMemOut` is set to `NULL`. Use `SSFHeapMalloc` or `SSFHeapMallocAndZero`
macros instead of calling this directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | `SSFHeapHandle_t` | Opaque heap handle. Must be valid. |
| `heapMemOut` | out | `void **` | Receives a pointer to the allocated block, or `NULL` on failure. Must not be `NULL`. Must point to a `NULL` pointer before the call. |
| `size` | in | `uint32_t` | Number of bytes to allocate. Must be greater than `0`. |
| `mark` | in | `uint8_t` | Owner tag written into the block header to identify the allocator. |
| `isZeroed` | in | `bool` | `true` to zero the allocated memory before returning it. |

**Returns:** `true` if allocation succeeded; `false` if the heap has insufficient contiguous free space.

---

### `SSFHeapMalloc` / `SSFHeapMallocAndZero`

```c
#define SSFHeapMalloc(handle, heapMemOut, size, mark) \
    SSFHeapAlloc(handle, (void **)heapMemOut, size, mark, false)
#define SSFHeapMallocAndZero(handle, heapMemOut, size, mark) \
    SSFHeapAlloc(handle, (void **)heapMemOut, size, mark, true)
```

Convenience macros for `SSFHeapAlloc`. `SSFHeapMalloc` does not zero the allocation;
`SSFHeapMallocAndZero` zeroes it. Parameters and return value are identical to `SSFHeapAlloc`
without the `isZeroed` argument.

---

### `SSFHeapAllocResize`

```c
bool SSFHeapAllocResize(SSFHeapHandle_t handle, void **heapMemOut, uint32_t newSize,
                        uint8_t newMark, bool newIsZeroed);
```

Resizes an existing allocation. The pointer in `*heapMemOut` is updated to the new location,
which may differ from the original. The old block is freed. Use `SSFHeapRealloc` or
`SSFHeapReallocAndZeroNew` macros instead of calling this directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | `SSFHeapHandle_t` | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | On entry, points to the existing allocation. On success, updated to the new allocation. On failure, left unchanged. Must not be `NULL`. |
| `newSize` | in | `uint32_t` | New requested size in bytes. |
| `newMark` | in | `uint8_t` | Owner tag for the resized block. |
| `newIsZeroed` | in | `bool` | `true` to zero any newly added bytes (when growing). |

**Returns:** `true` if resize succeeded; `false` if the heap has insufficient space for the new size.

---

### `SSFHeapRealloc` / `SSFHeapReallocAndZeroNew`

```c
#define SSFHeapRealloc(handle, heapMemOut, newSize, newMark) \
    SSFHeapAllocResize(handle, (void **)heapMemOut, newSize, newMark, false)
#define SSFHeapReallocAndZeroNew(handle, heapMemOut, newSize, newMark) \
    SSFHeapAllocResize(handle, (void **)heapMemOut, newSize, newMark, true)
```

Convenience macros for `SSFHeapAllocResize`. `SSFHeapReallocAndZeroNew` zeroes bytes added
when the allocation grows; `SSFHeapRealloc` does not.

---

### `SSFHeapDealloc`

```c
void SSFHeapDealloc(SSFHeapHandle_t handle, void **heapMemOut, uint8_t *markOutOpt,
                    bool isZeroed);
```

Frees a previously allocated block back to the heap. After this call, `*heapMemOut` is set to
`NULL`. Asserts on double-free or corruption. Use `SSFHeapFree` or `SSFHeapFreeAndZero` macros
instead of calling this directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | `SSFHeapHandle_t` | Opaque heap handle. Must be valid. |
| `heapMemOut` | in-out | `void **` | Pointer to the allocation to free. Set to `NULL` on return. Must not be `NULL`. |
| `markOutOpt` | out (opt) | `uint8_t *` | If not `NULL`, receives the mark value stored in the freed block header. Pass `NULL` to skip mark verification. |
| `isZeroed` | in | `bool` | `true` to zero the freed block before returning it to the free pool. |

**Returns:** Nothing.

---

### `SSFHeapFree` / `SSFHeapFreeAndZero`

```c
#define SSFHeapFree(handle, heapMemOut, markOutOpt) \
    SSFHeapDealloc(handle, (void **)heapMemOut, markOutOpt, false)
#define SSFHeapFreeAndZero(handle, heapMemOut, markOutOpt) \
    SSFHeapDealloc(handle, (void **)heapMemOut, markOutOpt, true)
```

Convenience macros for `SSFHeapDealloc`. `SSFHeapFreeAndZero` zeroes the freed block;
`SSFHeapFree` does not.

## Usage

The heap operates over a user-supplied byte array, making it suitable for embedded systems where
a single system heap is undesirable.

```c
#define HEAP_MARK  ('H')
#define APP_MARK   ('A')
#define HEAP_SIZE  (64000u)
#define STR_SIZE   (100u)

uint8_t heap[HEAP_SIZE];
SSFHeapHandle_t heapHandle;
uint8_t *ptr = NULL;

SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);

if (SSFHeapMalloc(heapHandle, &ptr, STR_SIZE, APP_MARK))
{
    strncpy((char *)ptr, "Hello", STR_SIZE);

    SSFHeapFree(heapHandle, &ptr, NULL);
    /* ptr == NULL */
}
SSF_ASSERT(ptr == NULL);

SSFHeapDeInit(&heapHandle, false);
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`
- [ssfll](ssfll.md) — Linked list (used internally)

## Notes

- Designed to work on 8, 16, 32, and 64-bit machine word sizes.
- All integrity checks run on every operation; corruption is reported immediately via assertion.
- `SSFHeapFree()` / `SSFHeapDealloc()` accepts `NULL` for `markOutOpt` to skip mark
  verification, useful when the allocating context is unknown.
- `SSFHeapStatus()` provides real-time tracking of current usage and minimum free space.
