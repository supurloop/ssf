# ssfll — Linked List

[Back to Data Structures README](README.md) | [Back to ssf README](../README.md)

Doubly-linked list supporting FIFO, stack, and arbitrary-position insert/remove operations.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFLLInit(ll, maxSize)` | Initialize a linked list with a maximum item count |
| `SSFLLDeInit(ll)` | De-initialize an empty linked list |
| `SSFLLIsInited(ll)` | Returns true if the list is initialized |
| `SSFLLPutItem(ll, inItem, loc, locItem)` | Insert an item at a specified location |
| `SSFLLGetItem(ll, outItem, loc, locItem)` | Remove and return an item from a specified location |
| `SSFLLIsEmpty(ll)` | Returns true if the list contains no items |
| `SSFLLIsFull(ll)` | Returns true if the list has reached its maximum item count |
| `SSFLLSize(ll)` | Returns the maximum item count |
| `SSFLLLen(ll)` | Returns the current item count |
| `SSFLLUnused(ll)` | Returns the number of additional items that can be added |
| `SSF_LL_STACK_PUSH(ll, item)` | Macro: push item onto head (LIFO) |
| `SSF_LL_STACK_POP(ll, item)` | Macro: pop item from head (LIFO) |
| `SSF_LL_FIFO_PUSH(ll, item)` | Macro: enqueue item at head |
| `SSF_LL_FIFO_POP(ll, item)` | Macro: dequeue item from tail |
| `SSF_LL_PUT(ll, inItem, locItem)` | Macro: insert item at position of `locItem` |
| `SSF_LL_GET(ll, outItem, locItem)` | Macro: remove item at position of `locItem` |
| `SSF_LL_HEAD(ll)` | Macro: pointer to the head item (or `NULL` if empty) |
| `SSF_LL_TAIL(ll)` | Macro: pointer to the tail item (or `NULL` if empty) |
| `SSF_LL_NEXT_ITEM(item)` | Macro: pointer to the next item in the list |
| `SSF_LL_PREV_ITEM(item)` | Macro: pointer to the previous item in the list |

## Function Reference

### `SSFLLInit`

```c
void SSFLLInit(SSFLL_t *ll, uint32_t maxSize);
```

Initializes a linked list. The `maxSize` parameter sets an upper bound on the number of items
the list may hold; `SSFLLIsFull()` returns `true` when `maxSize` items are present.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | out | `SSFLL_t *` | Pointer to the linked list structure to initialize. Must not be `NULL`. |
| `maxSize` | in | `uint32_t` | Maximum number of items the list may hold. Pass `UINT32_MAX` for an effectively unlimited list. |

**Returns:** Nothing.

---

### `SSFLLDeInit`

```c
void SSFLLDeInit(SSFLL_t *ll);
```

De-initializes an empty linked list, clearing its internal magic marker. The list must be empty
before calling this function; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | `SSFLL_t *` | Pointer to an initialized, empty linked list. Must not be `NULL`. |

**Returns:** Nothing.

---

### `SSFLLIsInited`

```c
bool SSFLLIsInited(SSFLL_t *ll);
```

Checks whether a linked list has been initialized.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | `SSFLL_t *` | Pointer to the linked list to check. Must not be `NULL`. |

**Returns:** `true` if the list is initialized; `false` otherwise.

---

### `SSFLLPutItem`

```c
void SSFLLPutItem(SSFLL_t *ll, SSFLLItem_t *inItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem);
```

Inserts `inItem` into the list at the position specified by `loc`. The item must not already be
in any list; asserting otherwise. Prefer the convenience macros for common use cases.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | `SSFLL_t *` | Pointer to an initialized linked list. Must not be `NULL`. Must not be full. |
| `inItem` | in | `SSFLLItem_t *` | Pointer to the item to insert. Must not be `NULL`. Must not currently be in any list. Must be the first field of the caller's struct. |
| `loc` | in | `SSF_LL_LOC_t` | Insertion location: `SSF_LL_LOC_HEAD` (before all items), `SSF_LL_LOC_TAIL` (after all items), or `SSF_LL_LOC_ITEM` (before `locItem`). |
| `locItem` | in | `SSFLLItem_t *` | Reference item used when `loc == SSF_LL_LOC_ITEM`. The new item is inserted before this item. Pass `NULL` for head/tail insertions. |

**Returns:** Nothing.

---

### `SSFLLGetItem`

```c
bool SSFLLGetItem(SSFLL_t *ll, SSFLLItem_t **outItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem);
```

Removes an item from the list at the position specified by `loc` and returns a pointer to it.
The caller is responsible for the removed item's lifetime.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | `SSFLL_t *` | Pointer to an initialized linked list. Must not be `NULL`. |
| `outItem` | out | `SSFLLItem_t **` | Receives a pointer to the removed item. Must not be `NULL`. |
| `loc` | in | `SSF_LL_LOC_t` | Removal location: `SSF_LL_LOC_HEAD`, `SSF_LL_LOC_TAIL`, or `SSF_LL_LOC_ITEM`. |
| `locItem` | in | `SSFLLItem_t *` | The specific item to remove when `loc == SSF_LL_LOC_ITEM`. Pass `NULL` for head/tail operations. |

**Returns:** `true` if an item was removed and written to `*outItem`; `false` if the list is empty.

---

### `SSFLLIsEmpty` / `SSFLLIsFull`

```c
bool SSFLLIsEmpty(const SSFLL_t *ll);
bool SSFLLIsFull(const SSFLL_t *ll);
```

State query functions.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | `const SSFLL_t *` | Pointer to an initialized linked list. Must not be `NULL`. |

**`SSFLLIsEmpty` returns:** `true` if the list contains no items.

**`SSFLLIsFull` returns:** `true` if the list contains `maxSize` items.

---

### `SSFLLSize` / `SSFLLLen` / `SSFLLUnused`

```c
uint32_t SSFLLSize(const SSFLL_t *ll);
uint32_t SSFLLLen(const SSFLL_t *ll);
uint32_t SSFLLUnused(const SSFLL_t *ll);
```

Capacity and occupancy queries.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | `const SSFLL_t *` | Pointer to an initialized linked list. Must not be `NULL`. |

**`SSFLLSize` returns:** The `maxSize` value passed to `SSFLLInit`.

**`SSFLLLen` returns:** The current number of items in the list.

**`SSFLLUnused` returns:** `Size - Len`, the number of additional items that can be inserted.

---

### Convenience Macros

```c
#define SSF_LL_STACK_PUSH(ll, inItem) SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_HEAD, NULL)
#define SSF_LL_STACK_POP(ll, outItem) SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_HEAD, NULL)
#define SSF_LL_FIFO_PUSH(ll, inItem)  SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_HEAD, NULL)
#define SSF_LL_FIFO_POP(ll, outItem)  SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_TAIL, NULL)
#define SSF_LL_PUT(ll, inItem, locItem) \
    SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_ITEM, (SSFLLItem_t *)locItem)
#define SSF_LL_GET(ll, outItem, locItem) \
    SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_ITEM, (SSFLLItem_t *)locItem)
#define SSF_LL_HEAD(ll)            ((ll)->head)
#define SSF_LL_TAIL(ll)            ((ll)->tail)
#define SSF_LL_NEXT_ITEM(item)     ((item)->next)
#define SSF_LL_PREV_ITEM(item)     ((item)->prev)
```

`SSF_LL_STACK_PUSH/POP` operate on the head (LIFO). `SSF_LL_FIFO_PUSH` inserts at the head;
`SSF_LL_FIFO_POP` removes from the tail (FIFO order). `SSF_LL_PUT/GET` operate on a specific
item by position. The traversal macros (`HEAD`, `TAIL`, `NEXT_ITEM`, `PREV_ITEM`) provide
direct field access for iteration.

## Usage

The key to using the linked list is to place an `SSFLLItem_t` named `item` at the top of any
struct you want to track. The linked list interface casts between `SSFLLItem_t *` and your struct
pointer.

```c
#define MYLL_MAX_ITEMS (3u)

typedef struct
{
    SSFLLItem_t item;   /* Must be first field */
    uint32_t mydata;
} SSFLLMyData_t;

SSFLL_t myll;
SSFLLMyData_t *item;

SSFLLInit(&myll, MYLL_MAX_ITEMS);

/* Push items onto a stack */
for (uint32_t i = 0; i < MYLL_MAX_ITEMS; i++)
{
    item = (SSFLLMyData_t *)malloc(sizeof(SSFLLMyData_t));
    SSF_ASSERT(item != NULL);
    item->mydata = i + 100;
    SSF_LL_STACK_PUSH(&myll, item);
}

/* Pop items from the stack (LIFO order) */
if (SSF_LL_STACK_POP(&myll, &item)) { /* item->mydata == 102 */ free(item); }
if (SSF_LL_STACK_POP(&myll, &item)) { /* item->mydata == 101 */ free(item); }
if (SSF_LL_STACK_POP(&myll, &item)) { /* item->mydata == 100 */ free(item); }
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- `SSFLLItem_t` must be the **first** field of any struct added to a list.
- An item already in one list cannot be added to another list; attempting to do so triggers an
  assertion. This prevents list corruption and resource leaks.
- `SSFLLIsFull()` returns true when the list contains `maxSize` items.
