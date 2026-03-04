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
| `SSFHeapInit(handle, buf, bufSize, heapMark, zeroMem)` | Initialize a heap over a user-supplied buffer |
| `SSFHeapDeInit(handle, zeroMem)` | De-initialize a heap |
| `SSFHeapMalloc(handle, pptr, size, allocMark)` | Allocate memory; sets `*pptr` |
| `SSFHeapCalloc(handle, pptr, count, size, allocMark)` | Allocate and zero memory |
| `SSFHeapRealloc(handle, pptr, size, allocMark)` | Resize an allocation |
| `SSFHeapFree(handle, pptr, allocMark, zeroMem)` | Free memory; sets `*pptr` to `NULL` |
| `SSFHeapCheck(handle)` | Verify heap integrity; asserts on corruption |
| `SSFHeapGetCurrentUsage(handle)` | Return current bytes allocated |
| `SSFHeapGetMinFree(handle)` | Return minimum free bytes recorded since init |

## Usage

The heap operates over a user-supplied byte array, making it suitable for embedded systems where
a single system heap is undesirable. Block headers use `+`/`-` markers to visually delimit live
and free blocks in a memory dump; freed blocks are zeroed so they never contaminate a dump.

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

    SSFHeapFree(heapHandle, &ptr, NULL, false);
    /* ptr == NULL */
}
SSF_ASSERT(ptr == NULL);

SSFHeapDeInit(&heapHandle, false);
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Designed to work on 8, 16, 32, and 64-bit machine word sizes.
- Allows allocations up to 32-bit size.
- All integrity checks run on every operation; corruption is reported immediately via assertion.
- `SSFHeapFree()` accepts `NULL` for `allocMark` to skip mark verification, useful when the
  allocating context is unknown.
- Real-time tracking of current usage and minimum free are available via
  `SSFHeapGetCurrentUsage()` and `SSFHeapGetMinFree()`.
