# ssfmpool — Fixed-Size Memory Pool

[Back to Data Structures README](README.md) | [Back to ssf README](../README.md)

Fixed-size block memory pool for deterministic allocation without calling `malloc`.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_MPOOL_DEBUG` | `0` | `1` to enable a debug struct that tracks all blocks and their allocators |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFMPoolInit(pool, blocks, blockSize)` | Initialize a memory pool |
| `SSFMPoolDeInit(pool)` | De-initialize a memory pool |
| `SSFMPoolAlloc(pool, size, owner)` | Allocate a block from the pool |
| `SSFMPoolFree(pool, ptr)` | Free a block back to the pool |
| `SSFMPoolBlockSize(pool)` | Returns the fixed block size in bytes |
| `SSFMPoolSize(pool)` | Returns the total number of blocks in the pool |
| `SSFMPoolLen(pool)` | Returns the number of currently allocated blocks |
| `SSFMPoolIsEmpty(pool)` | Returns true if no blocks are available |
| `SSFMPoolIsFull(pool)` | Returns true if all blocks are free |

## Function Reference

### `SSFMPoolInit`

```c
void SSFMPoolInit(SSFMPool_t *pool, uint32_t blocks, uint32_t blockSize);
```

Initializes a memory pool by allocating `blocks` blocks of `blockSize` bytes each from the
system heap via `malloc`. The pool thereafter provides deterministic O(1) allocation and
deallocation without any further `malloc` calls.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | out | `SSFMPool_t *` | Pointer to the pool structure to initialize. Must not be `NULL`. |
| `blocks` | in | `uint32_t` | Number of blocks to allocate. Must be greater than `0`. |
| `blockSize` | in | `uint32_t` | Size of each block in bytes. Must be greater than `0`. |

**Returns:** Nothing. Asserts if `malloc` fails.

---

### `SSFMPoolDeInit`

```c
void SSFMPoolDeInit(SSFMPool_t *pool);
```

De-initializes the memory pool, freeing all block memory back to the system heap. All allocated
blocks must have been freed before calling this function; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in-out | `SSFMPool_t *` | Pointer to an initialized pool with all blocks returned. Must not be `NULL`. |

**Returns:** Nothing.

---

### `SSFMPoolAlloc`

```c
void *SSFMPoolAlloc(SSFMPool_t *pool, uint32_t size, uint8_t owner);
```

Allocates one block from the pool. The `size` argument is validated against the pool's
`blockSize`; it must not exceed `blockSize`. The `owner` tag is stored in the block header
when `SSF_MPOOL_DEBUG == 1` to aid leak analysis.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in-out | `SSFMPool_t *` | Pointer to an initialized pool. Must not be `NULL`. Must not be empty. |
| `size` | in | `uint32_t` | Requested allocation size in bytes. Must not exceed the pool's `blockSize`. |
| `owner` | in | `uint8_t` | Tag identifying the allocating code path. Used only when `SSF_MPOOL_DEBUG == 1`. |

**Returns:** Pointer to the allocated block; asserts if the pool is empty or `size > blockSize`.

---

### `SSFMPoolFree`

```c
void *SSFMPoolFree(SSFMPool_t *pool, void *mpool);
```

Returns a previously allocated block back to the pool. After this call the pointer is invalid.
Note that this function returns `NULL` to allow the pattern `ptr = SSFMPoolFree(pool, ptr)` to
automatically null the caller's pointer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in-out | `SSFMPool_t *` | Pointer to the pool the block was allocated from. Must not be `NULL`. |
| `mpool` | in | `void *` | Pointer to the block to free. Must have been returned by `SSFMPoolAlloc` on this pool. |

**Returns:** Always `NULL`.

---

### `SSFMPoolBlockSize`

```c
uint32_t SSFMPoolBlockSize(const SSFMPool_t *pool);
```

Returns the fixed block size of the pool.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | `const SSFMPool_t *` | Pointer to an initialized pool. Must not be `NULL`. |

**Returns:** The `blockSize` value supplied to `SSFMPoolInit`.

---

### `SSFMPoolSize` / `SSFMPoolLen`

```c
uint32_t SSFMPoolSize(const SSFMPool_t *pool);
uint32_t SSFMPoolLen(const SSFMPool_t *pool);
```

Capacity and occupancy queries.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | `const SSFMPool_t *` | Pointer to an initialized pool. Must not be `NULL`. |

**`SSFMPoolSize` returns:** Total number of blocks in the pool (the `blocks` value from `SSFMPoolInit`).

**`SSFMPoolLen` returns:** Number of currently allocated (in-use) blocks.

---

### `SSFMPoolIsEmpty` / `SSFMPoolIsFull`

```c
bool SSFMPoolIsEmpty(const SSFMPool_t *pool);
bool SSFMPoolIsFull(const SSFMPool_t *pool);
```

State query functions.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pool` | in | `const SSFMPool_t *` | Pointer to an initialized pool. Must not be `NULL`. |

**`SSFMPoolIsEmpty` returns:** `true` if no free blocks remain (all are allocated).

**`SSFMPoolIsFull` returns:** `true` if all blocks are free (none are allocated).

## Usage

The memory pool creates a pool of fixed-size blocks that can be efficiently allocated and freed
without dynamic memory calls. All blocks are allocated from a contiguous heap region during
`SSFMPoolInit()`.

```c
#define BLOCK_SIZE  (42UL)
#define BLOCKS      (10UL)
#define MSG_FRAME_OWNER (0x11u)

SSFMPool_t pool;
MsgFrame_t *buf;

SSFMPoolInit(&pool, BLOCKS, BLOCK_SIZE);

/* Allocate and use a block */
if (SSFMPoolIsEmpty(&pool) == false)
{
    buf = (MsgFrame_t *)SSFMPoolAlloc(&pool, sizeof(MsgFrame_t), MSG_FRAME_OWNER);
    buf->header = 1;
    /* ... use buf ... */

    /* Free the block */
    buf = (MsgFrame_t *)SSFMPoolFree(&pool, buf);
    /* buf == NULL */
}
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- `SSFMPoolAlloc()` asserts if `size` exceeds `blockSize` — use `blockSize` as a compile-time
  constant for sizing.
- `SSFMPoolFree()` returns `NULL`; assign the return value to null the caller's pointer.
- When `SSF_MPOOL_DEBUG == 1`, each block records its `owner` tag to aid debugging leaks.
- Unlike `malloc`, all blocks are the same size; allocating a block smaller than `blockSize` is
  allowed but wastes the remainder.
