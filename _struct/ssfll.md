# ssfll — Linked List

[Back to Data Structures README](README.md) | [Back to ssf README](../README.md)

Doubly-linked list supporting FIFO and STACK operations.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFLLInit(ll, maxItems)` | Initialize a linked list with a maximum item count |
| `SSFLLDeInit(ll)` | De-initialize an empty linked list |
| `SSF_LL_FIFO_PUSH(ll, item)` | Macro: push item onto FIFO tail |
| `SSF_LL_FIFO_POP(ll, item)` | Macro: pop item from FIFO head |
| `SSF_LL_STACK_PUSH(ll, item)` | Macro: push item onto STACK head |
| `SSF_LL_STACK_POP(ll, item)` | Macro: pop item from STACK head |
| `SSFLLInsertBefore(ll, ref, item)` | Insert item before a reference item |
| `SSFLLInsertAfter(ll, ref, item)` | Insert item after a reference item |
| `SSFLLIsEmpty(ll)` | Returns true if the list contains no items |
| `SSFLLIsFull(ll)` | Returns true if the list has reached its maximum item count |

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
- `SSFLLIsFull()` returns true when the list contains `maxItems` items.
