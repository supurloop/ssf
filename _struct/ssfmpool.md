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
| `SSFMPoolAlloc(pool, allocSize, owner)` | Allocate a block from the pool |
| `SSFMPoolFree(pool, ptr)` | Free a block back to the pool |
| `SSFMPoolIsEmpty(pool)` | Returns true if no blocks are available |
| `SSFMPoolIsFull(pool)` | Returns true if all blocks are free |

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
    SSFMPoolFree(&pool, (void **)&buf);
    /* buf == NULL */
}
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- `SSFMPoolAlloc()` asserts if `allocSize` exceeds `blockSize` — use `blockSize` as a compile-
  time constant for sizing.
- `SSFMPoolFree()` sets the caller's pointer to `NULL` after freeing.
- When `SSF_MPOOL_DEBUG == 1`, each block records its `owner` tag to aid debugging leaks.
- Unlike `malloc`, all blocks are the same size; allocating a block smaller than `blockSize` is
  allowed but wastes the remainder.
