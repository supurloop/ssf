# ssfll — Linked List Interface

[SSF](../README.md) | [Data Structures](README.md)

Doubly-linked list supporting FIFO, stack, and arbitrary-position insert/remove operations.

The key to using the linked list is to embed an `SSFLLItem_t` as the **first** field of any
struct you want to track. The API casts between `SSFLLItem_t *` and your struct pointer,
allowing any struct to participate in the list without separate allocation.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfll--linked-list-interface) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfll--linked-list-interface) Notes

- `SSFLLItem_t` must be the **first** field of any struct added to a list.
- An item already in one list cannot be inserted into another list or the same list again;
  attempting to do so triggers an assertion.
- `SSFLLDeInit()` asserts if the list is not empty; remove all items before de-initializing.
- `SSFLLInit()` asserts if the list is already initialized.
- `SSF_LL_PUT()` inserts `inItem` **after** `locItem`. Pass `NULL` as `locItem` to insert at head.
- `SSF_LL_GET()` removes `locItem` itself from the list.

<a id="configuration"></a>

## [↑](#ssfll--linked-list-interface) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfll--linked-list-interface) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfllitem-t"></a>`SSFLLItem_t` | Struct | List item handle; must be the **first** field of any struct tracked by the list. Do not access fields directly. |
| <a id="type-ssfll-t"></a>`SSFLL_t` | Struct | List instance; pass by pointer to all API functions. Do not access fields directly. |
| <a id="type-ssf-ll-loc-t"></a>`SSF_LL_LOC_t` | Enum | Insertion/removal location selector |
| `SSF_LL_LOC_HEAD` | Constant | Operate on the head of the list |
| `SSF_LL_LOC_TAIL` | Constant | Operate on the tail of the list |
| `SSF_LL_LOC_ITEM` | Constant | Operate relative to a specific item (`locItem`) |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-init) | [`void SSFLLInit(ll, maxSize)`](#ssfllinit) | Initialize a linked list |
| [e.g.](#ex-deinit) | [`void SSFLLDeInit(ll)`](#ssflldeinit) | De-initialize an empty linked list |
| [e.g.](#ex-isinited) | [`bool SSFLLIsInited(ll)`](#ssfllisinited) | Returns true if the list is initialized |
| [e.g.](#ex-putitem) | [`void SSFLLPutItem(ll, inItem, loc, locItem)`](#ssfllputitem) | Insert an item at a specified location |
| [e.g.](#ex-getitem) | [`bool SSFLLGetItem(ll, outItem, loc, locItem)`](#ssfllgetitem) | Remove and return an item from a specified location |
| [e.g.](#ex-isempty) | [`bool SSFLLIsEmpty(ll)`](#ssfllisempty) | Returns true if the list contains no items |
| [e.g.](#ex-isfull) | [`bool SSFLLIsFull(ll)`](#ssfllisfull) | Returns true if the list has reached its maximum item count |
| [e.g.](#ex-size) | [`uint32_t SSFLLSize(ll)`](#ssfllsize) | Returns the maximum item count |
| [e.g.](#ex-len) | [`uint32_t SSFLLLen(ll)`](#ssflllen) | Returns the current item count |
| [e.g.](#ex-unused) | [`uint32_t SSFLLUnused(ll)`](#ssfllunused) | Returns the number of additional items that can be added |
| [e.g.](#ex-macro-stack-push) | [`void SSF_LL_STACK_PUSH(ll, inItem)`](#ssf-ll-stack-push) | Macro: push item onto head (LIFO) |
| [e.g.](#ex-macro-stack-pop) | [`bool SSF_LL_STACK_POP(ll, outItem)`](#ssf-ll-stack-pop) | Macro: pop item from head (LIFO) |
| [e.g.](#ex-macro-fifo-push) | [`void SSF_LL_FIFO_PUSH(ll, inItem)`](#ssf-ll-fifo-push) | Macro: enqueue item at head |
| [e.g.](#ex-macro-fifo-pop) | [`bool SSF_LL_FIFO_POP(ll, outItem)`](#ssf-ll-fifo-pop) | Macro: dequeue item from tail |
| [e.g.](#ex-macro-put) | [`void SSF_LL_PUT(ll, inItem, locItem)`](#ssf-ll-put) | Macro: insert `inItem` after `locItem` |
| [e.g.](#ex-macro-get) | [`bool SSF_LL_GET(ll, outItem, locItem)`](#ssf-ll-get) | Macro: remove `locItem` from the list |
| [e.g.](#ex-macro-head) | [`SSFLLItem_t *SSF_LL_HEAD(ll)`](#ssf-ll-head) | Macro: pointer to the head item (`NULL` if empty) |
| [e.g.](#ex-macro-tail) | [`SSFLLItem_t *SSF_LL_TAIL(ll)`](#ssf-ll-tail) | Macro: pointer to the tail item (`NULL` if empty) |
| [e.g.](#ex-macro-next-item) | [`SSFLLItem_t *SSF_LL_NEXT_ITEM(item)`](#ssf-ll-next-item) | Macro: pointer to the next item (`NULL` if at tail) |
| [e.g.](#ex-macro-prev-item) | [`SSFLLItem_t *SSF_LL_PREV_ITEM(item)`](#ssf-ll-prev-item) | Macro: pointer to the previous item (`NULL` if at head) |

<a id="function-reference"></a>

## [↑](#ssfll--linked-list-interface) Function Reference

<a id="ssfllinit"></a>

### [↑](#functions) [`void SSFLLInit()`](#functions)

```c
void SSFLLInit(SSFLL_t *ll, uint32_t maxSize);
```

Initializes a linked list. `maxSize` sets an upper bound on the number of items the list may
hold; `SSFLLIsFull()` returns `true` when `maxSize` items are present. The list must not already
be initialized; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to the list structure to initialize. Must not be `NULL`. Must not already be initialized. |
| `maxSize` | in | `uint32_t` | Maximum number of items the list may hold. Must be greater than `0`. Pass `UINT32_MAX` for an effectively unlimited list. |

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
SSFLL_t ll;

SSFLLInit(&ll, 10u);
/* ll is ready, capacity 10 items */
```

---

<a id="ssflldeinit"></a>

### [↑](#functions) [`void SSFLLDeInit()`](#functions)

```c
void SSFLLDeInit(SSFLL_t *ll);
```

De-initializes an empty linked list, clearing its internal magic marker. The list must be empty
before calling; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized, empty linked list. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
SSFLL_t ll;

SSFLLInit(&ll, 10u);
SSFLLDeInit(&ll);
/* ll is no longer valid */
```

---

<a id="ssfllisinited"></a>

### [↑](#functions) [`bool SSFLLIsInited()`](#functions)

```c
bool SSFLLIsInited(SSFLL_t *ll);
```

Checks whether a linked list has been initialized. Safe to call before `SSFLLInit()` on a
zero-initialized struct to test readiness.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`SSFLL_t *`](#type-ssfll-t) | Pointer to the linked list to check. Must not be `NULL`. |

**Returns:** `true` if the list is initialized; `false` otherwise.

<a id="ex-isinited"></a>

**Example:**

```c
static SSFLL_t ll;   /* zero-initialized */

SSFLLIsInited(&ll);   /* returns false */
SSFLLInit(&ll, 10u);
SSFLLIsInited(&ll);   /* returns true */
SSFLLDeInit(&ll);
SSFLLIsInited(&ll);   /* returns false */
```

---

<a id="ssfllputitem"></a>

### [↑](#functions) [`void SSFLLPutItem()`](#functions)

```c
void SSFLLPutItem(SSFLL_t *ll, SSFLLItem_t *inItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem);
```

Inserts `inItem` into the list at the position specified by `loc`. The item must not already be
in any list; asserting otherwise. The list must not be full; asserting otherwise. Prefer the
convenience macros for common use cases.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized linked list. Must not be `NULL`. Must not be full. |
| `inItem` | in | [`SSFLLItem_t *`](#type-ssfllitem-t) | Pointer to the item to insert. Must not be `NULL`. Must not currently be in any list. Must be the first field of the caller's struct. |
| `loc` | in | [`SSF_LL_LOC_t`](#type-ssf-ll-loc-t) | Insertion location: `SSF_LL_LOC_HEAD` inserts before all items; `SSF_LL_LOC_TAIL` inserts after all items; `SSF_LL_LOC_ITEM` inserts after `locItem` (`NULL` locItem inserts at head). |
| `locItem` | in | [`SSFLLItem_t *`](#type-ssfllitem-t) | Reference item when `loc == SSF_LL_LOC_ITEM`; `inItem` is inserted after this item. Must be `NULL` for `SSF_LL_LOC_HEAD` and `SSF_LL_LOC_TAIL`. |

**Returns:** Nothing.

<a id="ex-putitem"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 0xA0u}, b = {{0}, 0xB0u}, c = {{0}, 0xC0u};

SSFLLInit(&ll, 10u);
SSFLLPutItem(&ll, (SSFLLItem_t *)&a, SSF_LL_LOC_HEAD, NULL); /* list: a */
SSFLLPutItem(&ll, (SSFLLItem_t *)&b, SSF_LL_LOC_TAIL, NULL); /* list: a → b */
SSFLLPutItem(&ll, (SSFLLItem_t *)&c, SSF_LL_LOC_ITEM,        /* list: a → c → b */
             (SSFLLItem_t *)&a);
```

---

<a id="ssfllgetitem"></a>

### [↑](#functions) [`bool SSFLLGetItem()`](#functions)

```c
bool SSFLLGetItem(SSFLL_t *ll, SSFLLItem_t **outItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem);
```

Removes an item from the list at the position specified by `loc` and writes a pointer to it in
`*outItem`. The caller is responsible for the removed item's lifetime.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized linked list. Must not be `NULL`. |
| `outItem` | out | [`SSFLLItem_t **`](#type-ssfllitem-t) | Receives a pointer to the removed item on success. Must not be `NULL`. |
| `loc` | in | [`SSF_LL_LOC_t`](#type-ssf-ll-loc-t) | Removal location: `SSF_LL_LOC_HEAD` removes the head item; `SSF_LL_LOC_TAIL` removes the tail item; `SSF_LL_LOC_ITEM` removes `locItem` specifically. |
| `locItem` | in | [`SSFLLItem_t *`](#type-ssfllitem-t) | The specific item to remove when `loc == SSF_LL_LOC_ITEM`. Must not be `NULL` when using `SSF_LL_LOC_ITEM`. Must be `NULL` for `SSF_LL_LOC_HEAD` and `SSF_LL_LOC_TAIL`. |

**Returns:** `true` if an item was removed and written to `*outItem`; `false` if the list is empty.

<a id="ex-getitem"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 0xA0u}, b = {{0}, 0xB0u};
MyItem_t *out;

SSFLLInit(&ll, 10u);
SSFLLPutItem(&ll, (SSFLLItem_t *)&a, SSF_LL_LOC_TAIL, NULL); /* list: a */
SSFLLPutItem(&ll, (SSFLLItem_t *)&b, SSF_LL_LOC_TAIL, NULL); /* list: a → b */

if (SSFLLGetItem(&ll, (SSFLLItem_t **)&out, SSF_LL_LOC_HEAD, NULL))
{
    /* out == &a, out->data == 0xA0 */
}
if (SSFLLGetItem(&ll, (SSFLLItem_t **)&out, SSF_LL_LOC_ITEM,
                 (SSFLLItem_t *)&b))
{
    /* out == &b, out->data == 0xB0 */
}
```

---

<a id="ssfllisempty"></a>

### [↑](#functions) [`bool SSFLLIsEmpty()`](#functions)

```c
bool SSFLLIsEmpty(const SSFLL_t *ll);
```

Returns `true` if the list contains no items.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`const SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized linked list. Must not be `NULL`. |

**Returns:** `true` if the list is empty; `false` otherwise.

<a id="ex-isempty"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u};

SSFLLInit(&ll, 10u);
SSFLLIsEmpty(&ll);   /* returns true */

SSFLLPutItem(&ll, (SSFLLItem_t *)&a, SSF_LL_LOC_HEAD, NULL);
SSFLLIsEmpty(&ll);   /* returns false */
```

---

<a id="ssfllisfull"></a>

### [↑](#functions) [`bool SSFLLIsFull()`](#functions)

```c
bool SSFLLIsFull(const SSFLL_t *ll);
```

Returns `true` if the list contains `maxSize` items and no more can be inserted.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`const SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized linked list. Must not be `NULL`. |

**Returns:** `true` if the list is full; `false` otherwise.

<a id="ex-isfull"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFLLInit(&ll, 2u);
SSFLLIsFull(&ll);   /* returns false */

SSFLLPutItem(&ll, (SSFLLItem_t *)&a, SSF_LL_LOC_HEAD, NULL);
SSFLLPutItem(&ll, (SSFLLItem_t *)&b, SSF_LL_LOC_HEAD, NULL);
SSFLLIsFull(&ll);   /* returns true */
```

---

<a id="ssfllsize"></a>

### [↑](#functions) [`uint32_t SSFLLSize()`](#functions)

```c
uint32_t SSFLLSize(const SSFLL_t *ll);
```

Returns the maximum number of items the list can hold.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`const SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized linked list. Must not be `NULL`. |

**Returns:** The `maxSize` value passed to `SSFLLInit()`.

<a id="ex-size"></a>

**Example:**

```c
SSFLL_t ll;

SSFLLInit(&ll, 10u);
SSFLLSize(&ll);   /* returns 10 */
```

---

<a id="ssflllen"></a>

### [↑](#functions) [`uint32_t SSFLLLen()`](#functions)

```c
uint32_t SSFLLLen(const SSFLL_t *ll);
```

Returns the current number of items in the list.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`const SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized linked list. Must not be `NULL`. |

**Returns:** Current item count.

<a id="ex-len"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFLLInit(&ll, 10u);
SSFLLPutItem(&ll, (SSFLLItem_t *)&a, SSF_LL_LOC_HEAD, NULL);
SSFLLPutItem(&ll, (SSFLLItem_t *)&b, SSF_LL_LOC_HEAD, NULL);
SSFLLLen(&ll);   /* returns 2 */
```

---

<a id="ssfllunused"></a>

### [↑](#functions) [`uint32_t SSFLLUnused()`](#functions)

```c
uint32_t SSFLLUnused(const SSFLL_t *ll);
```

Returns the number of additional items that can be inserted before the list is full (`Size - Len`).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`const SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized linked list. Must not be `NULL`. |

**Returns:** Number of free slots remaining (`Size - Len`).

<a id="ex-unused"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u};

SSFLLInit(&ll, 10u);
SSFLLPutItem(&ll, (SSFLLItem_t *)&a, SSF_LL_LOC_HEAD, NULL);
SSFLLUnused(&ll);   /* returns 9 */
```

---

<a id="convenience-macros"></a>

### [↑](#functions) [Convenience Macros](#functions)

Macros that wrap `SSFLLPutItem()` and `SSFLLGetItem()` with fixed location arguments, plus
direct field-access macros for list traversal. Use these in preference to calling
`SSFLLPutItem()` / `SSFLLGetItem()` directly for common patterns.

---

<a id="ssf-ll-stack-push"></a>

#### [↑](#functions) [`void SSF_LL_STACK_PUSH()`](#functions)

```c
#define SSF_LL_STACK_PUSH(ll, inItem) \
    SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_HEAD, NULL)
```

Inserts `inItem` at the head of the list. Pair with `SSF_LL_STACK_POP()` for LIFO (stack)
behavior.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized, non-full list. Must not be `NULL`. |
| `inItem` | in | `void *` | Pointer to a struct whose first field is [`SSFLLItem_t`](#type-ssfllitem-t). Must not be `NULL`. Must not be in any list. |

**Returns:** Nothing.

<a id="ex-macro-stack-push"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFLLInit(&ll, 10u);
SSF_LL_STACK_PUSH(&ll, &a);   /* head: a */
SSF_LL_STACK_PUSH(&ll, &b);   /* head: b → a */
```

---

<a id="ssf-ll-stack-pop"></a>

#### [↑](#functions) [`bool SSF_LL_STACK_POP()`](#functions)

```c
#define SSF_LL_STACK_POP(ll, outItem) \
    SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_HEAD, NULL)
```

Removes and returns the head item. Pair with `SSF_LL_STACK_PUSH()` for LIFO (stack) behavior.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | out | `void **` | Pointer to a struct pointer whose first field is [`SSFLLItem_t`](#type-ssfllitem-t). Receives the removed item on success. |

**Returns:** `true` if an item was removed; `false` if the list is empty.

<a id="ex-macro-stack-pop"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};
MyItem_t *out;

SSFLLInit(&ll, 10u);
SSF_LL_STACK_PUSH(&ll, &a);
SSF_LL_STACK_PUSH(&ll, &b);         /* head: b → a */

if (SSF_LL_STACK_POP(&ll, &out)) { /* out == &b (LIFO) */ }
if (SSF_LL_STACK_POP(&ll, &out)) { /* out == &a */ }
```

---

<a id="ssf-ll-fifo-push"></a>

#### [↑](#functions) [`void SSF_LL_FIFO_PUSH()`](#functions)

```c
#define SSF_LL_FIFO_PUSH(ll, inItem) \
    SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_HEAD, NULL)
```

Inserts `inItem` at the head of the list. Pair with `SSF_LL_FIFO_POP()` for FIFO (queue)
behavior; items pushed at the head are dequeued from the tail in insertion order.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized, non-full list. Must not be `NULL`. |
| `inItem` | in | `void *` | Pointer to a struct whose first field is [`SSFLLItem_t`](#type-ssfllitem-t). Must not be `NULL`. Must not be in any list. |

**Returns:** Nothing.

<a id="ex-macro-fifo-push"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFLLInit(&ll, 10u);
SSF_LL_FIFO_PUSH(&ll, &a);   /* head: a */
SSF_LL_FIFO_PUSH(&ll, &b);   /* head: b → a */
```

---

<a id="ssf-ll-fifo-pop"></a>

#### [↑](#functions) [`bool SSF_LL_FIFO_POP()`](#functions)

```c
#define SSF_LL_FIFO_POP(ll, outItem) \
    SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_TAIL, NULL)
```

Removes and returns the tail item. Pair with `SSF_LL_FIFO_PUSH()` for FIFO (queue) behavior.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | out | `void **` | Pointer to a struct pointer whose first field is [`SSFLLItem_t`](#type-ssfllitem-t). Receives the removed item on success. |

**Returns:** `true` if an item was removed; `false` if the list is empty.

<a id="ex-macro-fifo-pop"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};
MyItem_t *out;

SSFLLInit(&ll, 10u);
SSF_LL_FIFO_PUSH(&ll, &a);
SSF_LL_FIFO_PUSH(&ll, &b);         /* head: b → a (tail) */

if (SSF_LL_FIFO_POP(&ll, &out)) { /* out == &a (FIFO: first pushed, first popped) */ }
if (SSF_LL_FIFO_POP(&ll, &out)) { /* out == &b */ }
```

---

<a id="ssf-ll-put"></a>

#### [↑](#functions) [`void SSF_LL_PUT()`](#functions)

```c
#define SSF_LL_PUT(ll, inItem, locItem) \
    SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_ITEM, (SSFLLItem_t *)locItem)
```

Inserts `inItem` immediately after `locItem` in the list. Pass `NULL` as `locItem` to insert at
the head.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized, non-full list. Must not be `NULL`. |
| `inItem` | in | `void *` | Pointer to a struct whose first field is [`SSFLLItem_t`](#type-ssfllitem-t). Must not be `NULL`. Must not be in any list. |
| `locItem` | in | `void *` | Item after which `inItem` is inserted. Pass `NULL` to insert at head. If not `NULL`, must be in `ll`. |

**Returns:** Nothing.

<a id="ex-macro-put"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u}, c = {{0}, 3u};

SSFLLInit(&ll, 10u);
SSF_LL_STACK_PUSH(&ll, &a);   /* list: a */
SSF_LL_STACK_PUSH(&ll, &b);   /* list: b → a */
SSF_LL_PUT(&ll, &c, &b);      /* inserts c after b: b → c → a */
```

---

<a id="ssf-ll-get"></a>

#### [↑](#functions) [`bool SSF_LL_GET()`](#functions)

```c
#define SSF_LL_GET(ll, outItem, locItem) \
    SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_ITEM, (SSFLLItem_t *)locItem)
```

Removes `locItem` from the list and writes a pointer to it in `*outItem`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in-out | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized list. Must not be `NULL`. |
| `outItem` | out | `void **` | Pointer to a struct pointer whose first field is [`SSFLLItem_t`](#type-ssfllitem-t). Receives `locItem` on success. Must not be `NULL`. |
| `locItem` | in | `void *` | The specific item to remove. Must not be `NULL`. Must be in `ll`. |

**Returns:** `true` if an item was removed and written to `*outItem`; `false` if the list is empty.

<a id="ex-macro-get"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};
MyItem_t *out;

SSFLLInit(&ll, 10u);
SSF_LL_STACK_PUSH(&ll, &a);
SSF_LL_STACK_PUSH(&ll, &b);   /* list: b → a */

if (SSF_LL_GET(&ll, &out, &a)) { /* removes a, out == &a; list: b */ }
```

---

<a id="ssf-ll-head"></a>

#### [↑](#functions) [`SSFLLItem_t *SSF_LL_HEAD()`](#functions)

```c
#define SSF_LL_HEAD(ll) ((ll)->head)
```

Returns a pointer to the head item without removing it. Returns `NULL` if the list is empty.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized list. Must not be `NULL`. |

**Returns:** [`SSFLLItem_t *`](#type-ssfllitem-t) pointing to the head item, or `NULL` if empty.

<a id="ex-macro-head"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFLLInit(&ll, 10u);
SSF_LL_STACK_PUSH(&ll, &a);
SSF_LL_STACK_PUSH(&ll, &b);   /* list: b → a */

((MyItem_t *)SSF_LL_HEAD(&ll))->data;   /* == 2 (b is head) */
```

---

<a id="ssf-ll-tail"></a>

#### [↑](#functions) [`SSFLLItem_t *SSF_LL_TAIL()`](#functions)

```c
#define SSF_LL_TAIL(ll) ((ll)->tail)
```

Returns a pointer to the tail item without removing it. Returns `NULL` if the list is empty.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ll` | in | [`SSFLL_t *`](#type-ssfll-t) | Pointer to an initialized list. Must not be `NULL`. |

**Returns:** [`SSFLLItem_t *`](#type-ssfllitem-t) pointing to the tail item, or `NULL` if empty.

<a id="ex-macro-tail"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u};

SSFLLInit(&ll, 10u);
SSF_LL_STACK_PUSH(&ll, &a);
SSF_LL_STACK_PUSH(&ll, &b);   /* list: b → a */

((MyItem_t *)SSF_LL_TAIL(&ll))->data;   /* == 1 (a is tail) */
```

---

<a id="ssf-ll-next-item"></a>

#### [↑](#functions) [`SSFLLItem_t *SSF_LL_NEXT_ITEM()`](#functions)

```c
#define SSF_LL_NEXT_ITEM(item) ((item)->next)
```

Returns a pointer to the item that follows `item` in the list. Used for forward (head-to-tail)
traversal. Returns `NULL` if `item` is the tail.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `item` | in | [`SSFLLItem_t *`](#type-ssfllitem-t) | Pointer to an item currently in the list. Must not be `NULL`. |

**Returns:** [`SSFLLItem_t *`](#type-ssfllitem-t) pointing to the next item, or `NULL` if `item` is the tail.

<a id="ex-macro-next-item"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u}, c = {{0}, 3u};
MyItem_t *cur;

SSFLLInit(&ll, 10u);
SSF_LL_FIFO_PUSH(&ll, &a);
SSF_LL_FIFO_PUSH(&ll, &b);
SSF_LL_FIFO_PUSH(&ll, &c);   /* head → tail: c → b → a */

for (cur = (MyItem_t *)SSF_LL_HEAD(&ll); cur != NULL;
     cur = (MyItem_t *)SSF_LL_NEXT_ITEM(&cur->item))
{
    /* cur->data: 3, then 2, then 1 */
}
```

---

<a id="ssf-ll-prev-item"></a>

#### [↑](#functions) [`SSFLLItem_t *SSF_LL_PREV_ITEM()`](#functions)

```c
#define SSF_LL_PREV_ITEM(item) ((item)->prev)
```

Returns a pointer to the item that precedes `item` in the list. Used for backward (tail-to-head)
traversal. Returns `NULL` if `item` is the head.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `item` | in | [`SSFLLItem_t *`](#type-ssfllitem-t) | Pointer to an item currently in the list. Must not be `NULL`. |

**Returns:** [`SSFLLItem_t *`](#type-ssfllitem-t) pointing to the previous item, or `NULL` if `item` is the head.

<a id="ex-macro-prev-item"></a>

**Example:**

```c
typedef struct { SSFLLItem_t item; uint32_t data; } MyItem_t;

SSFLL_t ll;
MyItem_t a = {{0}, 1u}, b = {{0}, 2u}, c = {{0}, 3u};
MyItem_t *cur;

SSFLLInit(&ll, 10u);
SSF_LL_FIFO_PUSH(&ll, &a);
SSF_LL_FIFO_PUSH(&ll, &b);
SSF_LL_FIFO_PUSH(&ll, &c);   /* head → tail: c → b → a */

for (cur = (MyItem_t *)SSF_LL_TAIL(&ll); cur != NULL;
     cur = (MyItem_t *)SSF_LL_PREV_ITEM(&cur->item))
{
    /* cur->data: 1, then 2, then 3 */
}
```
