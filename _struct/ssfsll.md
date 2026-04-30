# ssfsll — Sorted Linked List Interface

[SSF](../README.md) | [Data Structures](README.md)

Doubly-linked list that keeps its items in sorted order at all times. Insertion finds the
correct position via a caller-supplied comparison function; head and tail always hold the
extremes (smallest first for ascending order, largest first for descending).

The key to using the sorted list — same as [`ssfll`](ssfll.md) — is to embed an
`SSFSLLItem_t` as the **first** field of any struct you want to track. The API casts between
`SSFSLLItem_t *` and your struct pointer, so any struct can participate without separate
allocation.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfsll--sorted-linked-list-interface) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfsll--sorted-linked-list-interface) Notes

- `SSFSLLItem_t` must be the **first** field of any struct added to a list.
- Each item carries a back-pointer (`item.sll`) to the list it currently belongs to.
  `SSFSLLInsertItem()` rejects an item whose `sll` is already non-`NULL` (i.e., already in
  any list) via `SSF_REQUIRE`. `SSFSLLRemoveItem()` uses the same back-pointer to confirm the
  item belongs to the list it is being removed from — passing an item from a different list
  returns `false`.
- Sort order is fixed at [`SSFSLLInit()`](#ssfsllinit) time via the
  [`SSF_SLL_ORDER_t`](#type-ssf-sll-order-t) parameter. `ASCENDING` puts the smallest item
  at the head; `DESCENDING` puts the largest at the head.
- The comparison function ([`SSFSLLCompareFn_t`](#type-comparefn)) returns the standard
  three-way `int32_t` value: negative if `a < b`, `0` if `a == b`, positive if `a > b`. The
  insertion algorithm is a stable "insert before the first element that is not strictly
  ordered before us", so equal-key items maintain insertion order within their equivalence
  class (tied items end up at the *back* of the run of equals on the chosen ordering).
- `SSFSLLDeInit()` asserts if the list is not empty; remove all items before
  de-initializing.
- `SSFSLLInit()` asserts if the list is already initialized (the magic marker is checked).
- Bounded capacity: `maxSize` (passed to [`SSFSLLInit()`](#ssfsllinit)) caps the number of
  items the list will hold. `SSFSLLInsertItem()` asserts when the list is full — callers
  that may overflow should check [`SSFSLLIsFull()`](#ssfsllisfull) first.
- The traversal macros [`SSF_SLL_HEAD`](#ssf-sll-head) / [`SSF_SLL_TAIL`](#ssf-sll-tail) /
  [`SSF_SLL_NEXT_ITEM`](#ssf-sll-next-item) / [`SSF_SLL_PREV_ITEM`](#ssf-sll-prev-item)
  expand to direct field access; do not call them on a `NULL` list / item pointer.
- Single-threaded: the list holds no internal lock. Concurrent access from multiple threads
  must be serialised externally (mutex, critical section, etc.).

<a id="configuration"></a>

## [↑](#ssfsll--sorted-linked-list-interface) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfsll--sorted-linked-list-interface) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfsllitem-t"></a>`SSFSLLItem_t` | Struct | List item handle (`{ next, prev, sll }`); must be the **first** field of any struct tracked by the list. Do not access fields directly. |
| <a id="type-ssfsll-t"></a>`SSFSLL_t` | Struct | List instance; pass by pointer to all API functions. Do not access fields directly. |
| <a id="type-comparefn"></a>`SSFSLLCompareFn_t` | Typedef | `int32_t (*)(const SSFSLLItem_t *a, const SSFSLLItem_t *b)` — caller-supplied comparison; returns negative/zero/positive in standard three-way form. |
| <a id="type-ssf-sll-order-t"></a>`SSF_SLL_ORDER_t` | Enum | Sort-order selector. |
| `SSF_SLL_ORDER_ASCENDING` | Enum value | Smallest item at head, largest at tail. |
| `SSF_SLL_ORDER_DESCENDING` | Enum value | Largest item at head, smallest at tail. |

`SSF_SLL_ORDER_MIN` and `SSF_SLL_ORDER_MAX` are bounds-only sentinels; do not pass them as
the `order` argument to [`SSFSLLInit()`](#ssfsllinit).

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-init) | [`void SSFSLLInit(sll, maxSize, compareFn, order)`](#ssfsllinit) | Initialize a sorted linked list |
| [e.g.](#ex-deinit) | [`void SSFSLLDeInit(sll)`](#ssfslldeinit) | De-initialize an empty sorted linked list |
| [e.g.](#ex-isinited) | [`bool SSFSLLIsInited(sll)`](#ssfsllisinited) | Returns true if the list is initialized |
| [e.g.](#ex-insert) | [`void SSFSLLInsertItem(sll, inItem)`](#ssfsllinsertitem) | Insert an item in sorted position |
| [e.g.](#ex-remove) | [`bool SSFSLLRemoveItem(sll, outItem)`](#ssfsllremoveitem) | Remove a specific item from the list |
| [e.g.](#ex-peek) | [`bool SSFSLLPeekHead(sll, outItem)`](#ssfsllpeekhead) | Peek the head item without removing it |
| [e.g.](#ex-peek) | [`bool SSFSLLPeekTail(sll, outItem)`](#ssfsllpeektail) | Peek the tail item without removing it |
| [e.g.](#ex-pop) | [`bool SSFSLLPopHead(sll, outItem)`](#ssfsllpophead) | Remove and return the head item |
| [e.g.](#ex-pop) | [`bool SSFSLLPopTail(sll, outItem)`](#ssfsllpoptail) | Remove and return the tail item |
| [e.g.](#ex-isempty) | [`bool SSFSLLIsEmpty(sll)`](#ssfsllisempty) | Returns true if the list contains no items |
| [e.g.](#ex-isfull) | [`bool SSFSLLIsFull(sll)`](#ssfsllisfull) | Returns true if the list has reached `maxSize` |
| [e.g.](#ex-size) | [`uint32_t SSFSLLSize(sll)`](#ssfsllsize) | Returns the maximum item count |
| [e.g.](#ex-len) | [`uint32_t SSFSLLLen(sll)`](#ssfslllen) | Returns the current item count |
| [e.g.](#ex-unused) | [`uint32_t SSFSLLUnused(sll)`](#ssfsllunused) | Returns `Size - Len` |
| [e.g.](#ex-traverse) | [`SSFSLLItem_t *SSF_SLL_HEAD(sll)`](#ssf-sll-head) | Macro: pointer to the head item (`NULL` if empty) |
| [e.g.](#ex-traverse) | [`SSFSLLItem_t *SSF_SLL_TAIL(sll)`](#ssf-sll-tail) | Macro: pointer to the tail item (`NULL` if empty) |
| [e.g.](#ex-traverse) | [`SSFSLLItem_t *SSF_SLL_NEXT_ITEM(item)`](#ssf-sll-next-item) | Macro: pointer to the next item (`NULL` if at tail) |
| [e.g.](#ex-traverse) | [`SSFSLLItem_t *SSF_SLL_PREV_ITEM(item)`](#ssf-sll-prev-item) | Macro: pointer to the previous item (`NULL` if at head) |

<a id="function-reference"></a>

## [↑](#ssfsll--sorted-linked-list-interface) Function Reference

<a id="ssfsllinit"></a>

### [↑](#functions) [`void SSFSLLInit()`](#functions)

```c
void SSFSLLInit(SSFSLL_t *sll, uint32_t maxSize, SSFSLLCompareFn_t compareFn,
                SSF_SLL_ORDER_t order);
```

Initializes a sorted linked list with a caller-supplied comparison function and sort order.
The list must not already be initialized; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | out | [`SSFSLL_t *`](#type-ssfsll-t) | Pointer to the list structure to initialize. Must not be `NULL`. Must not already be initialized. |
| `maxSize` | in | `uint32_t` | Maximum number of items the list may hold. Must be `> 0`. |
| `compareFn` | in | [`SSFSLLCompareFn_t`](#type-comparefn) | Three-way comparison callback. Must not be `NULL`. Called on every insert. |
| `order` | in | [`SSF_SLL_ORDER_t`](#type-ssf-sll-order-t) | `SSF_SLL_ORDER_ASCENDING` or `SSF_SLL_ORDER_DESCENDING`. |

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
typedef struct
{
    SSFSLLItem_t item;
    uint32_t key;
} MyItem_t;

/* Compare by .key — smaller key first under ASCENDING */
static int32_t myCompare(const SSFSLLItem_t *a, const SSFSLLItem_t *b)
{
    const MyItem_t *am = (const MyItem_t *)a;
    const MyItem_t *bm = (const MyItem_t *)b;

    if (am->key < bm->key) return -1;
    if (am->key > bm->key) return  1;
    return 0;
}

SSFSLL_t sll;

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
/* sll holds up to 10 items, head = smallest .key, tail = largest .key */
```

---

<a id="ssfslldeinit"></a>

### [↑](#functions) [`void SSFSLLDeInit()`](#functions)

```c
void SSFSLLDeInit(SSFSLL_t *sll);
```

De-initializes an empty sorted linked list, zeroing the entire structure. The list must be
empty before calling; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in-out | [`SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized, empty sorted linked list. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
SSFSLL_t sll;

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
/* ... drain the list ... */
SSFSLLDeInit(&sll);
/* sll is no longer valid */
```

---

<a id="ssfsllisinited"></a>

### [↑](#functions) [`bool SSFSLLIsInited()`](#functions)

```c
bool SSFSLLIsInited(SSFSLL_t *sll);
```

Returns whether the list has been initialized. Safe to call on a zero-initialized struct
before the first [`SSFSLLInit()`](#ssfsllinit).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`SSFSLL_t *`](#type-ssfsll-t) | Pointer to the list to check. Must not be `NULL`. |

**Returns:** `true` if the list is initialized; `false` otherwise.

<a id="ex-isinited"></a>

**Example:**

```c
static SSFSLL_t sll;   /* zero-initialized */

SSFSLLIsInited(&sll);                                      /* false */
SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLIsInited(&sll);                                      /* true */
SSFSLLDeInit(&sll);
SSFSLLIsInited(&sll);                                      /* false */
```

---

<a id="ssfsllinsertitem"></a>

### [↑](#functions) [`void SSFSLLInsertItem()`](#functions)

```c
void SSFSLLInsertItem(SSFSLL_t *sll, SSFSLLItem_t *inItem);
```

Inserts `inItem` into the list at its sorted position. The list walks from head to tail
calling the `compareFn` until it finds the first existing item that is **not strictly
ordered before** `inItem`, then splices `inItem` in front of it. The item must not already
be in any list (its `item.sll` field must be `NULL`); asserting otherwise. The list must
not be full; asserting otherwise.

Insertion is `O(N)` in the current item count (linear scan). For large lists where insert
performance matters, prefer a different data structure.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in-out | [`SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. Must not be full. |
| `inItem` | in | [`SSFSLLItem_t *`](#type-ssfsllitem-t) | Pointer to the item to insert. Must not be `NULL`. Must not currently be in any list. Must be the first field of the caller's struct. |

**Returns:** Nothing.

<a id="ex-insert"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 30u}, b = {{0}, 10u}, c = {{0}, 20u};

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);

SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);  /* list (head→tail): 30 */
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&b);  /* list: 10 → 30 */
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&c);  /* list: 10 → 20 → 30 */
```

---

<a id="ssfsllremoveitem"></a>

### [↑](#functions) [`bool SSFSLLRemoveItem()`](#functions)

```c
bool SSFSLLRemoveItem(SSFSLL_t *sll, SSFSLLItem_t *outItem);
```

Removes the specific `outItem` from the list. Uses the item's `sll` back-pointer to verify
that the item belongs to this list — if it does not, returns `false` without modifying
either side. After a successful removal the item's `next`, `prev`, and `sll` fields are all
cleared to `NULL`, so the same item can be re-inserted (into the same or a different list)
immediately.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in-out | [`SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | in-out | [`SSFSLLItem_t *`](#type-ssfsllitem-t) | The specific item to remove. Must not be `NULL`. |

**Returns:** `true` if `outItem` was in the list and has been removed; `false` if it was
not (e.g., never inserted, already removed, or in a different list).

<a id="ex-remove"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 10u}, b = {{0}, 20u}, c = {{0}, 30u};

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&b);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&c);   /* 10 → 20 → 30 */

SSFSLLRemoveItem(&sll, (SSFSLLItem_t *)&b);   /* returns true; list: 10 → 30 */
SSFSLLRemoveItem(&sll, (SSFSLLItem_t *)&b);   /* returns false (already removed) */
```

---

<a id="ssfsllpeekhead"></a>

### [↑](#functions) [`bool SSFSLLPeekHead()`](#functions)

```c
bool SSFSLLPeekHead(const SSFSLL_t *sll, SSFSLLItem_t **outItem);
```

Returns a pointer to the head item without removing it. `*outItem` is left unchanged when
the list is empty and `false` is returned.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`const SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | out | [`SSFSLLItem_t **`](#type-ssfsllitem-t) | Receives a pointer to the head item on success. Must not be `NULL`. |

**Returns:** `true` if the list was non-empty; `false` if it was empty.

---

<a id="ssfsllpeektail"></a>

### [↑](#functions) [`bool SSFSLLPeekTail()`](#functions)

```c
bool SSFSLLPeekTail(const SSFSLL_t *sll, SSFSLLItem_t **outItem);
```

Returns a pointer to the tail item without removing it. `*outItem` is left unchanged when
the list is empty and `false` is returned.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`const SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | out | [`SSFSLLItem_t **`](#type-ssfsllitem-t) | Receives a pointer to the tail item on success. Must not be `NULL`. |

**Returns:** `true` if the list was non-empty; `false` if it was empty.

<a id="ex-peek"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 10u}, b = {{0}, 20u};
MyItem_t *p;

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&b);   /* head: 10, tail: 20 */

if (SSFSLLPeekHead(&sll, (SSFSLLItem_t **)&p)) { /* p == &a, p->key == 10 */ }
if (SSFSLLPeekTail(&sll, (SSFSLLItem_t **)&p)) { /* p == &b, p->key == 20 */ }
```

---

<a id="ssfsllpophead"></a>

### [↑](#functions) [`bool SSFSLLPopHead()`](#functions)

```c
bool SSFSLLPopHead(SSFSLL_t *sll, SSFSLLItem_t **outItem);
```

Removes the head item and writes a pointer to it in `*outItem`. The removed item's `next`,
`prev`, and `sll` fields are cleared so it can be re-inserted immediately.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in-out | [`SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | out | [`SSFSLLItem_t **`](#type-ssfsllitem-t) | Receives a pointer to the removed item on success. Must not be `NULL`. |

**Returns:** `true` if an item was removed; `false` if the list was empty.

---

<a id="ssfsllpoptail"></a>

### [↑](#functions) [`bool SSFSLLPopTail()`](#functions)

```c
bool SSFSLLPopTail(SSFSLL_t *sll, SSFSLLItem_t **outItem);
```

Removes the tail item and writes a pointer to it in `*outItem`. The removed item's `next`,
`prev`, and `sll` fields are cleared so it can be re-inserted immediately.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in-out | [`SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | out | [`SSFSLLItem_t **`](#type-ssfsllitem-t) | Receives a pointer to the removed item on success. Must not be `NULL`. |

**Returns:** `true` if an item was removed; `false` if the list was empty.

<a id="ex-pop"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 10u}, b = {{0}, 20u}, c = {{0}, 30u};
MyItem_t *p;

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&b);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&c);   /* 10 → 20 → 30 */

while (SSFSLLPopHead(&sll, (SSFSLLItem_t **)&p))
{
    /* p->key in ascending order: 10, 20, 30 */
}
```

---

<a id="ssfsllisempty"></a>

### [↑](#functions) [`bool SSFSLLIsEmpty()`](#functions)

```c
bool SSFSLLIsEmpty(const SSFSLL_t *sll);
```

Returns `true` if the list contains no items.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`const SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |

**Returns:** `true` if the list is empty; `false` otherwise.

<a id="ex-isempty"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 1u};

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLIsEmpty(&sll);                              /* true */

SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLIsEmpty(&sll);                              /* false */
```

---

<a id="ssfsllisfull"></a>

### [↑](#functions) [`bool SSFSLLIsFull()`](#functions)

```c
bool SSFSLLIsFull(const SSFSLL_t *sll);
```

Returns `true` if the list contains `maxSize` items and a further
[`SSFSLLInsertItem()`](#ssfsllinsertitem) would assert.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`const SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |

**Returns:** `true` if the list is full; `false` otherwise.

<a id="ex-isfull"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFSLLInit(&sll, 2u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLIsFull(&sll);                                /* false */

SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&b);
SSFSLLIsFull(&sll);                                /* true */
```

---

<a id="ssfsllsize"></a>

### [↑](#functions) [`uint32_t SSFSLLSize()`](#functions)

```c
uint32_t SSFSLLSize(const SSFSLL_t *sll);
```

Returns the maximum number of items the list can hold (the `maxSize` value passed to
[`SSFSLLInit()`](#ssfsllinit)).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`const SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |

**Returns:** Maximum item count.

<a id="ex-size"></a>

**Example:**

```c
SSFSLL_t sll;

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLSize(&sll);   /* returns 10 */
```

---

<a id="ssfslllen"></a>

### [↑](#functions) [`uint32_t SSFSLLLen()`](#functions)

```c
uint32_t SSFSLLLen(const SSFSLL_t *sll);
```

Returns the current number of items in the list.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`const SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |

**Returns:** Current item count.

<a id="ex-len"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&b);
SSFSLLLen(&sll);   /* returns 2 */
```

---

<a id="ssfsllunused"></a>

### [↑](#functions) [`uint32_t SSFSLLUnused()`](#functions)

```c
uint32_t SSFSLLUnused(const SSFSLL_t *sll);
```

Returns `Size - Len` — the number of further items that can be inserted before the list
becomes full.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sll` | in | [`const SSFSLL_t *`](#type-ssfsll-t) | Pointer to an initialized list. Must not be `NULL`. |

**Returns:** Number of free slots remaining (`Size - Len`).

<a id="ex-unused"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 1u};

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLUnused(&sll);   /* returns 9 */
```

---

<a id="traversal-macros"></a>

### [↑](#functions) Traversal Macros

Direct field-access macros for walking the list head-to-tail or tail-to-head. They expand
to a single struct-field access (no function call), so they have zero overhead beyond what
a hand-rolled traversal would have.

<a id="ssf-sll-head"></a>

#### [↑](#functions) [`SSFSLLItem_t *SSF_SLL_HEAD()`](#functions)

```c
#define SSF_SLL_HEAD(sll) ((sll)->head)
```

Returns a pointer to the head item, or `NULL` if the list is empty.

<a id="ssf-sll-tail"></a>

#### [↑](#functions) [`SSFSLLItem_t *SSF_SLL_TAIL()`](#functions)

```c
#define SSF_SLL_TAIL(sll) ((sll)->tail)
```

Returns a pointer to the tail item, or `NULL` if the list is empty.

<a id="ssf-sll-next-item"></a>

#### [↑](#functions) [`SSFSLLItem_t *SSF_SLL_NEXT_ITEM()`](#functions)

```c
#define SSF_SLL_NEXT_ITEM(item) ((item)->next)
```

Returns the item immediately after `item`, or `NULL` if `item` is the tail.

<a id="ssf-sll-prev-item"></a>

#### [↑](#functions) [`SSFSLLItem_t *SSF_SLL_PREV_ITEM()`](#functions)

```c
#define SSF_SLL_PREV_ITEM(item) ((item)->prev)
```

Returns the item immediately before `item`, or `NULL` if `item` is the head.

<a id="ex-traverse"></a>

**Example:**

```c
SSFSLL_t sll;
MyItem_t a = {{0}, 10u}, b = {{0}, 20u}, c = {{0}, 30u};
MyItem_t *cur;

SSFSLLInit(&sll, 10u, myCompare, SSF_SLL_ORDER_ASCENDING);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&c);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&a);
SSFSLLInsertItem(&sll, (SSFSLLItem_t *)&b);   /* head→tail: 10 → 20 → 30 */

/* Forward walk */
for (cur = (MyItem_t *)SSF_SLL_HEAD(&sll); cur != NULL;
     cur = (MyItem_t *)SSF_SLL_NEXT_ITEM(&cur->item))
{
    /* cur->key: 10, then 20, then 30 */
}

/* Backward walk */
for (cur = (MyItem_t *)SSF_SLL_TAIL(&sll); cur != NULL;
     cur = (MyItem_t *)SSF_SLL_PREV_ITEM(&cur->item))
{
    /* cur->key: 30, then 20, then 10 */
}
```
