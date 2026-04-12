# ssfgobj — Generic Object (BETA)

[SSF](../README.md) | [Codecs](README.md)

> **BETA:** This interface is still under development. The API may change in future releases.

Hierarchical generic object tree for building, modifying, and querying structured data
independently of any wire format. Designed as a portable in-memory representation that can
translate between JSON, UBJSON, and other encoding types.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfgobj--generic-object-beta) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)
- [ssfll](../\_struct/ssfll.md) — Linked list (used internally for child lists and path tracking)

<a id="notes"></a>

## [↑](#ssfgobj--generic-object-beta) Notes

- `maxChildren` passed to [`SSFGObjInit()`](#ssfgobjinit) controls the child-list capacity for
  that node. Pass the maximum number of direct children expected for container nodes
  (`OBJECT`/`ARRAY`); pass `0` for leaf nodes. [`SSFGObjInsertChild()`](#ssfgobjinsertchild)
  returns `false` for a node initialized with `maxChildren = 0`.
- `*gobj` must be `NULL` before [`SSFGObjInit()`](#ssfgobjinit); must not be `NULL` before
  [`SSFGObjDeInit()`](#ssfgobjdeinit). Both assert otherwise.
- [`SSFGObjSetLabel()`](#ssfgobjsetlabel) accepts `NULL` for `labelCStr` — this clears any
  existing label.
- [`SSFGObjSetBin()`](#ssfgobjsetbin) accepts `valueLen = 0` — this stores an empty binary node.
- [`SSFGObjInsertChild()`](#ssfgobjinsertchild) asserts if the parent type is not
  `SSF_OBJ_TYPE_OBJECT` or `SSF_OBJ_TYPE_ARRAY`; returns `false` if the parent's child list is
  full.
- Both `*gobjParentOut` and `*gobjChildOut` must be `NULL` before
  [`SSFGObjFindPath()`](#ssfgobjfindpath), and `path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH]` must be
  `NULL`. All three assert otherwise.
- [`SSFGObjDeInit()`](#ssfgobjdeinit) on a parent recursively frees all its children. Use
  [`SSFGObjRemoveChild()`](#ssfgobjremovechild) first if a child must outlive its parent.
- Call [`SSFGObjGetType()`](#ssfgobjgettype) before any `SSFGObjGet*` call to avoid a
  type-mismatch `false` return.
- [`SSFGObjSetNone()`](#ssfgobjsetnone), [`SSFGObjSetNull()`](#ssfgobjsetnull),
  [`SSFGObjSetObject()`](#ssfgobjsetobject), and [`SSFGObjSetArray()`](#ssfgobjsetarray) always
  return `true`.

<a id="configuration"></a>

## [↑](#ssfgobj--generic-object-beta) Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-gobj-max-depth"></a>`SSF_GOBJ_CONFIG_MAX_IN_DEPTH` | `4` | Maximum nesting depth for object and array iteration and path traversal |

<a id="api-summary"></a>

## [↑](#ssfgobj--generic-object-beta) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfobjtype-t"></a>`SSFObjType_t` | Enum | Value type held by a node; see table below |
| <a id="type-ssfgobj-t"></a>`SSFGObj_t` | Struct | One node in the generic object tree; pass by pointer to all API functions |
| <a id="type-ssfgobjpathitem-t"></a>`SSFGObjPathItem_t` | Struct | Path element supplied to the [`SSFGObjIterateFn_t`](#type-ssfgobjiteratefn-t) callback; fields: `gobj` (`SSFGObj_t *`), `index` (`int32_t`, ≥ 0 for array elements) |
| <a id="type-ssfgobjiteratefn-t"></a>`SSFGObjIterateFn_t` | Typedef | `void (*fn)(SSFGObj_t *gobj, SSFLL_t *path)` — callback passed to [`SSFGObjIterate()`](#ssfgobjiterate); called once per node during depth-first traversal |

**`SSFObjType_t` values:**

| Constant | Description |
|----------|-------------|
| `SSF_OBJ_TYPE_NONE` | Untyped sentinel — initial state, no value assigned |
| `SSF_OBJ_TYPE_STR` | Null-terminated string |
| `SSF_OBJ_TYPE_BIN` | Binary byte array |
| `SSF_OBJ_TYPE_INT` | Signed 64-bit integer |
| `SSF_OBJ_TYPE_UINT` | Unsigned 64-bit integer |
| `SSF_OBJ_TYPE_FLOAT` | Double-precision floating-point |
| `SSF_OBJ_TYPE_BOOL` | Boolean |
| `SSF_OBJ_TYPE_NULL` | Explicit null (e.g. JSON `null`) |
| `SSF_OBJ_TYPE_OBJECT` | Structured object container with named children |
| `SSF_OBJ_TYPE_ARRAY` | Ordered array container |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|---------|-------------|
| [e.g.](#ex-init) | [`bool SSFGObjInit(gobj, maxChildren)`](#ssfgobjinit) | Allocate and initialize a new node |
| [e.g.](#ex-deinit) | [`void SSFGObjDeInit(gobj)`](#ssfgobjdeinit) | Free a node and all its children |
| [e.g.](#ex-setlabel) | [`bool SSFGObjSetLabel(gobj, labelCStr)`](#ssfgobjsetlabel) | Set or clear the node's label |
| [e.g.](#ex-getlabel) | [`bool SSFGObjGetLabel(gobj, labelCStrOut, labelCStrOutSize)`](#ssfgobjgetlabel) | Copy the node's label into a buffer |
| [e.g.](#ex-gettype) | [`SSFObjType_t SSFGObjGetType(gobj)`](#ssfgobjgettype) | Return the node's current value type |
| [e.g.](#ex-getsize) | [`size_t SSFGObjGetSize(gobj)`](#ssfgobjgetsize) | Return the size of the node's stored value |
| [e.g.](#ex-setnone) | [`bool SSFGObjSetNone(gobj)`](#ssfgobjsetnone) | Clear the node's value (set type to NONE) |
| [e.g.](#ex-setstring) | [`bool SSFGObjSetString(gobj, valueCStr)`](#ssfgobjsetstring) | Store a string value |
| [e.g.](#ex-getstring) | [`bool SSFGObjGetString(gobj, valueCStrOut, valueCStrOutSize)`](#ssfgobjgetstring) | Copy the node's string value |
| [e.g.](#ex-setint) | [`bool SSFGObjSetInt(gobj, value)`](#ssfgobjsetint) | Store a signed 64-bit integer |
| [e.g.](#ex-getint) | [`bool SSFGObjGetInt(gobj, valueOut)`](#ssfgobjgetint) | Read the node's signed 64-bit integer |
| [e.g.](#ex-setuint) | [`bool SSFGObjSetUInt(gobj, value)`](#ssfgobjsetuint) | Store an unsigned 64-bit integer |
| [e.g.](#ex-getuint) | [`bool SSFGObjGetUInt(gobj, valueOut)`](#ssfgobjgetuint) | Read the node's unsigned 64-bit integer |
| [e.g.](#ex-setfloat) | [`bool SSFGObjSetFloat(gobj, value)`](#ssfgobjsetfloat) | Store a double-precision float |
| [e.g.](#ex-getfloat) | [`bool SSFGObjGetFloat(gobj, valueOut)`](#ssfgobjgetfloat) | Read the node's double-precision float |
| [e.g.](#ex-setbool) | [`bool SSFGObjSetBool(gobj, value)`](#ssfgobjsetbool) | Store a boolean |
| [e.g.](#ex-getbool) | [`bool SSFGObjGetBool(gobj, valueOut)`](#ssfgobjgetbool) | Read the node's boolean |
| [e.g.](#ex-setbin) | [`bool SSFGObjSetBin(gobj, value, valueLen)`](#ssfgobjsetbin) | Store a binary byte array |
| [e.g.](#ex-getbin) | [`bool SSFGObjGetBin(gobj, valueOut, valueSize, valueLenOutOpt)`](#ssfgobjgetbin) | Copy the node's binary value |
| [e.g.](#ex-setnull) | [`bool SSFGObjSetNull(gobj)`](#ssfgobjsetnull) | Set the node's type to NULL |
| [e.g.](#ex-setobject) | [`bool SSFGObjSetObject(gobj)`](#ssfgobjsetobject) | Set the node's type to OBJECT container |
| [e.g.](#ex-setarray) | [`bool SSFGObjSetArray(gobj)`](#ssfgobjsetarray) | Set the node's type to ARRAY container |
| [e.g.](#ex-insertchild) | [`bool SSFGObjInsertChild(gobjParent, gobjChild)`](#ssfgobjinsertchild) | Append a child node to a container |
| [e.g.](#ex-removechild) | [`bool SSFGObjRemoveChild(gobjParent, gobjChild)`](#ssfgobjremovechild) | Remove a child node from a container |
| [e.g.](#ex-getobjectlen) | [`bool SSFGObjGetObjectLen(gobj, numChildrenOut)`](#ssfgobjgetobjectlen) | Return the number of children of an OBJECT node |
| [e.g.](#ex-getarraylen) | [`bool SSFGObjGetArrayLen(gobj, numChildrenOut)`](#ssfgobjgetarraylen) | Return the number of elements of an ARRAY node |
| [e.g.](#ex-findpath) | [`bool SSFGObjFindPath(gobjRoot, path, gobjParentOut, gobjChildOut)`](#ssfgobjfindpath) | Locate a descendant by label path |
| [e.g.](#ex-iterate) | [`bool SSFGObjIterate(gobj, iterateCallback)`](#ssfgobjiterate) | Depth-first traversal of a subtree |

<a id="function-reference"></a>

## [↑](#ssfgobj--generic-object-beta) Function Reference

<a id="ssfgobjinit"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjInit()`](#functions)

```c
bool SSFGObjInit(SSFGObj_t **gobj, uint16_t maxChildren);
```

Allocates and initializes a new generic object node via `malloc`. The node starts with type
`SSF_OBJ_TYPE_NONE`, no label, no value, and an empty child list.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | out | `SSFGObj_t **` | Receives the allocated node pointer. Must not be `NULL`. Must point to a `NULL` pointer before the call. |
| `maxChildren` | in | `uint16_t` | Maximum number of direct children this node may hold. Pass `0` for leaf nodes. Pass the expected child count for container nodes — [`SSFGObjInsertChild()`](#ssfgobjinsertchild) returns `false` for nodes initialized with `0`. |

**Returns:** `true` if the node was allocated and initialized; `false` if `malloc` failed.

<a id="ex-init"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);
/* g is a leaf node with type SSF_OBJ_TYPE_NONE */
SSFGObjDeInit(&g);
/* g == NULL */
```

---

<a id="ssfgobjdeinit"></a>

### [↑](#ssfgobj--generic-object-beta) [`void SSFGObjDeInit()`](#functions)

```c
void SSFGObjDeInit(SSFGObj_t **gobj);
```

Frees the node and, recursively, all its children including their labels and value data. Sets
`*gobj` to `NULL` on return.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in-out | `SSFGObj_t **` | Pointer to the node to free. Must not be `NULL`. `*gobj` must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);
SSFGObjSetInt(g, 42);
SSFGObjDeInit(&g);
/* g == NULL; value memory freed */
```

---

<a id="ssfgobjsetlabel"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetLabel()`](#functions)

```c
bool SSFGObjSetLabel(SSFGObj_t *gobj, SSFCStrIn_t labelCStr);
```

Assigns a label to the node, replacing any existing one. Passing `NULL` for `labelCStr` clears
the label without error.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `labelCStr` | in | `SSFCStrIn_t` | Null-terminated label to copy, or `NULL` to clear. |

**Returns:** `true` if the label was set or cleared; `false` if `malloc` failed when setting.

<a id="ex-setlabel"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);
SSFGObjSetLabel(g, "count");
/* node label is "count" */

SSFGObjSetLabel(g, NULL);
/* label cleared */

SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetlabel"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetLabel()`](#functions)

```c
bool SSFGObjGetLabel(SSFGObj_t *gobj, SSFCStrOut_t labelCStrOut, size_t labelCStrOutSize);
```

Copies the node's label into `labelCStrOut`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `labelCStrOut` | out | `SSFCStrOut_t` | Buffer to receive the null-terminated label. Must not be `NULL`. |
| `labelCStrOutSize` | in | `size_t` | Size of `labelCStrOut` in bytes. Must be at least `strlen(label) + 1`. |

**Returns:** `true` if the label was copied; `false` if no label is set or the buffer is too small.

<a id="ex-getlabel"></a>

```c
SSFGObj_t *g = NULL;
char buf[16];

SSFGObjInit(&g, 0u);
SSFGObjSetLabel(g, "count");

if (SSFGObjGetLabel(g, buf, sizeof(buf)))
{
    /* buf == "count" */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgettype"></a>

### [↑](#ssfgobj--generic-object-beta) [`SSFObjType_t SSFGObjGetType()`](#functions)

```c
SSFObjType_t SSFGObjGetType(SSFGObj_t *gobj);
```

Returns the value type currently held by the node as set by the most recent `SSFGObjSet*` call.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |

**Returns:** The current [`SSFObjType_t`](#type-ssfobjtype-t) of the node.

<a id="ex-gettype"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);
SSFGObjGetType(g);   /* returns SSF_OBJ_TYPE_NONE */

SSFGObjSetInt(g, 7);
SSFGObjGetType(g);   /* returns SSF_OBJ_TYPE_INT */

SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetsize"></a>

### [↑](#ssfgobj--generic-object-beta) [`size_t SSFGObjGetSize()`](#functions)

```c
size_t SSFGObjGetSize(SSFGObj_t *gobj);
```

Returns the size in bytes of the value stored in the node. For `STR` this includes the null
terminator. For container types (`OBJECT`, `ARRAY`) and valueless types (`NONE`, `NULL`) this
is `0`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |

**Returns:** Size in bytes of the stored value, or `0` for valueless types.

<a id="ex-getsize"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);
SSFGObjSetString(g, "hi");
SSFGObjGetSize(g);   /* returns 3 (strlen("hi") + 1) */

SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetnone"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetNone()`](#functions)

```c
bool SSFGObjSetNone(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_NONE` and frees any existing value data. This is the
initial state of every freshly allocated node.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

<a id="ex-setnone"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);
SSFGObjSetInt(g, 42);
SSFGObjSetNone(g);
SSFGObjGetType(g);   /* returns SSF_OBJ_TYPE_NONE */

SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetstring"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetString()`](#functions)

```c
bool SSFGObjSetString(SSFGObj_t *gobj, SSFCStrIn_t valueCStr);
```

Stores a copy of `valueCStr` in the node. The node's type becomes `SSF_OBJ_TYPE_STR`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `valueCStr` | in | `SSFCStrIn_t` | Null-terminated string to store. Must not be `NULL`. |

**Returns:** `true` if the value was stored; `false` if `malloc` failed.

<a id="ex-setstring"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);

if (SSFGObjSetString(g, "hello"))
{
    /* node type is SSF_OBJ_TYPE_STR, SSFGObjGetSize(g) == 6 */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetstring"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetString()`](#functions)

```c
bool SSFGObjGetString(SSFGObj_t *gobj, SSFCStrOut_t valueCStrOut, size_t valueCStrOutSize);
```

Copies the node's string value into `valueCStrOut`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `valueCStrOut` | out | `SSFCStrOut_t` | Buffer to receive the null-terminated string. Must not be `NULL`. |
| `valueCStrOutSize` | in | `size_t` | Size of `valueCStrOut` in bytes. Must be at least `strlen(value) + 1`. |

**Returns:** `true` if the string was copied; `false` if the node type is not `SSF_OBJ_TYPE_STR`
or the buffer is too small.

<a id="ex-getstring"></a>

```c
SSFGObj_t *g = NULL;
char buf[16];

SSFGObjInit(&g, 0u);
SSFGObjSetString(g, "hello");

if (SSFGObjGetString(g, buf, sizeof(buf)))
{
    /* buf == "hello" */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetint"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetInt()`](#functions)

```c
bool SSFGObjSetInt(SSFGObj_t *gobj, int64_t value);
```

Stores a signed 64-bit integer. The node's type becomes `SSF_OBJ_TYPE_INT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `value` | in | `int64_t` | Signed integer value to store. |

**Returns:** `true` if the value was stored; `false` if `malloc` failed.

<a id="ex-setint"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);

if (SSFGObjSetInt(g, -42))
{
    /* node type is SSF_OBJ_TYPE_INT */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetint"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetInt()`](#functions)

```c
bool SSFGObjGetInt(SSFGObj_t *gobj, int64_t *valueOut);
```

Reads the node's signed 64-bit integer value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `int64_t *` | Receives the integer value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_INT`.

<a id="ex-getint"></a>

```c
SSFGObj_t *g = NULL;
int64_t val;

SSFGObjInit(&g, 0u);
SSFGObjSetInt(g, -42);

if (SSFGObjGetInt(g, &val))
{
    /* val == -42 */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetuint"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetUInt()`](#functions)

```c
bool SSFGObjSetUInt(SSFGObj_t *gobj, uint64_t value);
```

Stores an unsigned 64-bit integer. The node's type becomes `SSF_OBJ_TYPE_UINT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `value` | in | `uint64_t` | Unsigned integer value to store. |

**Returns:** `true` if the value was stored; `false` if `malloc` failed.

<a id="ex-setuint"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);

if (SSFGObjSetUInt(g, 100u))
{
    /* node type is SSF_OBJ_TYPE_UINT */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetuint"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetUInt()`](#functions)

```c
bool SSFGObjGetUInt(SSFGObj_t *gobj, uint64_t *valueOut);
```

Reads the node's unsigned 64-bit integer value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `uint64_t *` | Receives the unsigned integer value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_UINT`.

<a id="ex-getuint"></a>

```c
SSFGObj_t *g = NULL;
uint64_t val;

SSFGObjInit(&g, 0u);
SSFGObjSetUInt(g, 100u);

if (SSFGObjGetUInt(g, &val))
{
    /* val == 100 */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetfloat"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetFloat()`](#functions)

```c
bool SSFGObjSetFloat(SSFGObj_t *gobj, double value);
```

Stores a double-precision floating-point value. The node's type becomes `SSF_OBJ_TYPE_FLOAT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `value` | in | `double` | Double-precision float to store. |

**Returns:** `true` if the value was stored; `false` if `malloc` failed.

<a id="ex-setfloat"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);

if (SSFGObjSetFloat(g, 3.14))
{
    /* node type is SSF_OBJ_TYPE_FLOAT */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetfloat"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetFloat()`](#functions)

```c
bool SSFGObjGetFloat(SSFGObj_t *gobj, double *valueOut);
```

Reads the node's double-precision float value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `double *` | Receives the float value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_FLOAT`.

<a id="ex-getfloat"></a>

```c
SSFGObj_t *g = NULL;
double val;

SSFGObjInit(&g, 0u);
SSFGObjSetFloat(g, 3.14);

if (SSFGObjGetFloat(g, &val))
{
    /* val == 3.14 */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetbool"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetBool()`](#functions)

```c
bool SSFGObjSetBool(SSFGObj_t *gobj, bool value);
```

Stores a boolean value. The node's type becomes `SSF_OBJ_TYPE_BOOL`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `value` | in | `bool` | Boolean value to store. |

**Returns:** `true` if the value was stored; `false` if `malloc` failed.

<a id="ex-setbool"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);

if (SSFGObjSetBool(g, true))
{
    /* node type is SSF_OBJ_TYPE_BOOL */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetbool"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetBool()`](#functions)

```c
bool SSFGObjGetBool(SSFGObj_t *gobj, bool *valueOut);
```

Reads the node's boolean value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `bool *` | Receives the boolean value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_BOOL`.

<a id="ex-getbool"></a>

```c
SSFGObj_t *g = NULL;
bool val;

SSFGObjInit(&g, 0u);
SSFGObjSetBool(g, true);

if (SSFGObjGetBool(g, &val))
{
    /* val == true */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetbin"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetBin()`](#functions)

```c
bool SSFGObjSetBin(SSFGObj_t *gobj, uint8_t *value, size_t valueLen);
```

Stores a copy of a binary byte array. The node's type becomes `SSF_OBJ_TYPE_BIN`. `valueLen`
may be `0` to store an empty binary node.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `value` | in | `uint8_t *` | Pointer to the bytes to copy. Must not be `NULL`. |
| `valueLen` | in | `size_t` | Number of bytes to copy. May be `0`. |

**Returns:** `true` if the value was stored; `false` if `malloc` failed.

<a id="ex-setbin"></a>

```c
SSFGObj_t *g = NULL;
uint8_t data[] = {0x01u, 0x02u, 0x03u};

SSFGObjInit(&g, 0u);

if (SSFGObjSetBin(g, data, sizeof(data)))
{
    /* node type is SSF_OBJ_TYPE_BIN, SSFGObjGetSize(g) == 3 */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjgetbin"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetBin()`](#functions)

```c
bool SSFGObjGetBin(SSFGObj_t *gobj, uint8_t *valueOut, size_t valueSize,
                   size_t *valueLenOutOpt);
```

Copies the node's binary value into `valueOut`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `uint8_t *` | Buffer to receive the binary data. Must not be `NULL`. |
| `valueSize` | in | `size_t` | Size of `valueOut` in bytes. Must be at least the stored data size. |
| `valueLenOutOpt` | out (opt) | `size_t *` | If not `NULL`, receives the number of bytes copied. |

**Returns:** `true` if the data was copied; `false` if the node type is not `SSF_OBJ_TYPE_BIN` or
`valueSize` is too small.

<a id="ex-getbin"></a>

```c
SSFGObj_t *g = NULL;
uint8_t data[] = {0x01u, 0x02u, 0x03u};
uint8_t buf[8];
size_t len;

SSFGObjInit(&g, 0u);
SSFGObjSetBin(g, data, sizeof(data));

if (SSFGObjGetBin(g, buf, sizeof(buf), &len))
{
    /* len == 3, buf[0..2] == {0x01, 0x02, 0x03} */
}
SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetnull"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetNull()`](#functions)

```c
bool SSFGObjSetNull(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_NULL`, representing an explicit null value (e.g. JSON
`null`). Unlike `SSF_OBJ_TYPE_NONE`, this is a meaningful typed value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

<a id="ex-setnull"></a>

```c
SSFGObj_t *g = NULL;

SSFGObjInit(&g, 0u);
SSFGObjSetNull(g);
SSFGObjGetType(g);   /* returns SSF_OBJ_TYPE_NULL */

SSFGObjDeInit(&g);
```

---

<a id="ssfgobjsetobject"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetObject()`](#functions)

```c
bool SSFGObjSetObject(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_OBJECT`, marking it as a structured named-child
container (analogous to a JSON object `{}`). Call before
[`SSFGObjInsertChild()`](#ssfgobjinsertchild).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

<a id="ex-setobject"></a>

```c
SSFGObj_t *parent = NULL;

SSFGObjInit(&parent, 4u);   /* up to 4 children */
SSFGObjSetObject(parent);
SSFGObjGetType(parent);     /* returns SSF_OBJ_TYPE_OBJECT */

SSFGObjDeInit(&parent);
```

---

<a id="ssfgobjsetarray"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjSetArray()`](#functions)

```c
bool SSFGObjSetArray(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_ARRAY`, marking it as an ordered child container
(analogous to a JSON array `[]`). Call before
[`SSFGObjInsertChild()`](#ssfgobjinsertchild).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

<a id="ex-setarray"></a>

```c
SSFGObj_t *parent = NULL;

SSFGObjInit(&parent, 4u);   /* up to 4 children */
SSFGObjSetArray(parent);
SSFGObjGetType(parent);     /* returns SSF_OBJ_TYPE_ARRAY */

SSFGObjDeInit(&parent);
```

---

<a id="ssfgobjinsertchild"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjInsertChild()`](#functions)

```c
bool SSFGObjInsertChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild);
```

Appends `gobjChild` to the end of `gobjParent`'s child list. The parent must have been
initialized with `maxChildren > 0` and its type must be `SSF_OBJ_TYPE_OBJECT` or
`SSF_OBJ_TYPE_ARRAY`. Once inserted, the child's lifetime is managed by the parent.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobjParent` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the parent node. Must not be `NULL`. Must have type `SSF_OBJ_TYPE_OBJECT` or `SSF_OBJ_TYPE_ARRAY`. |
| `gobjChild` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the child node to insert. Must not be `NULL`. |

**Returns:** `true` if the child was inserted; `false` if the parent's child list is full or was
never initialized (`maxChildren = 0`).

<a id="ex-insertchild"></a>

```c
SSFGObj_t *parent = NULL;
SSFGObj_t *child = NULL;

SSFGObjInit(&parent, 2u);   /* capacity for 2 children */
SSFGObjSetObject(parent);

SSFGObjInit(&child, 0u);
SSFGObjSetLabel(child, "count");
SSFGObjSetInt(child, 42);

if (SSFGObjInsertChild(parent, child))
{
    /* child is now owned by parent */
}
SSFGObjDeInit(&parent);     /* frees parent and child */
```

---

<a id="ssfgobjremovechild"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjRemoveChild()`](#functions)

```c
bool SSFGObjRemoveChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild);
```

Removes `gobjChild` from `gobjParent`'s child list. After removal the caller owns the child
and must either re-insert it or free it with [`SSFGObjDeInit()`](#ssfgobjdeinit).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobjParent` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the parent node. Must not be `NULL`. Must have type `SSF_OBJ_TYPE_OBJECT` or `SSF_OBJ_TYPE_ARRAY`. |
| `gobjChild` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the child to remove. Must not be `NULL`. |

**Returns:** `true` if the child was found and removed; `false` otherwise.

<a id="ex-removechild"></a>

```c
SSFGObj_t *parent = NULL;
SSFGObj_t *child = NULL;

SSFGObjInit(&parent, 2u);
SSFGObjSetObject(parent);
SSFGObjInit(&child, 0u);
SSFGObjSetInt(child, 1);
SSFGObjInsertChild(parent, child);

if (SSFGObjRemoveChild(parent, child))
{
    /* child removed; caller now owns it */
    SSFGObjDeInit(&child);
}
SSFGObjDeInit(&parent);
```

---

<a id="ssfgobjgetobjectlen"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetObjectLen()`](#functions)

```c
bool SSFGObjGetObjectLen(SSFGObj_t *gobj, uint32_t *numChildren);
```

Returns the number of children currently attached to an OBJECT node. The call fails if `gobj`
is not of type `SSF_OBJ_TYPE_OBJECT`; in particular, an ARRAY node is rejected. A zero-capacity
OBJECT (one initialized with `maxChildren = 0` and then set to OBJECT) is valid and reports
`0`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node whose child count is requested. Must not be `NULL`. |
| `numChildren` | out | `uint32_t *` | Receives the number of children on success. Left unchanged on failure. Must not be `NULL`. |

**Returns:** `true` if `gobj` is an OBJECT and `*numChildren` has been written with the child
count; `false` if `gobj` is any other type. On failure `*numChildren` is left unchanged.

<a id="ex-getobjectlen"></a>

```c
SSFGObj_t *obj = NULL;
SSFGObj_t *child = NULL;
uint32_t n = 0;

SSFGObjInit(&obj, 2u);
SSFGObjSetObject(obj);

SSFGObjInit(&child, 0u);
SSFGObjSetLabel(child, "count");
SSFGObjSetInt(child, 42);
SSFGObjInsertChild(obj, child);

if (SSFGObjGetObjectLen(obj, &n))
{
    /* n == 1 */
}
SSFGObjDeInit(&obj);
```

---

<a id="ssfgobjgetarraylen"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjGetArrayLen()`](#functions)

```c
bool SSFGObjGetArrayLen(SSFGObj_t *gobj, uint32_t *numChildren);
```

Returns the number of elements currently attached to an ARRAY node. The call fails if `gobj`
is not of type `SSF_OBJ_TYPE_ARRAY`; in particular, an OBJECT node is rejected. A zero-capacity
ARRAY (one initialized with `maxChildren = 0` and then set to ARRAY) is valid and reports `0`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Pointer to the node whose element count is requested. Must not be `NULL`. |
| `numChildren` | out | `uint32_t *` | Receives the number of elements on success. Left unchanged on failure. Must not be `NULL`. |

**Returns:** `true` if `gobj` is an ARRAY and `*numChildren` has been written with the element
count; `false` if `gobj` is any other type. On failure `*numChildren` is left unchanged.

<a id="ex-getarraylen"></a>

```c
SSFGObj_t *arr = NULL;
SSFGObj_t *elem = NULL;
uint32_t n = 0;

SSFGObjInit(&arr, 2u);
SSFGObjSetArray(arr);

SSFGObjInit(&elem, 0u);
SSFGObjSetInt(elem, 10);
SSFGObjInsertChild(arr, elem);

if (SSFGObjGetArrayLen(arr, &n))
{
    /* n == 1 */
}
SSFGObjDeInit(&arr);
```

---

<a id="ssfgobjfindpath"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjFindPath()`](#functions)

```c
bool SSFGObjFindPath(SSFGObj_t *gobjRoot, SSFCStrIn_t *path,
                     SSFGObj_t **gobjParentOut, SSFGObj_t **gobjChildOut);
```

Locates a descendant node by following a null-terminated array of label strings from
`gobjRoot`. `gobjRoot` must be an `OBJECT` or `ARRAY` node. `path` is a `const char *` array
where each entry names a child at the corresponding depth; the array must end with a `NULL`
sentinel at index `SSF_GOBJ_CONFIG_MAX_IN_DEPTH`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobjRoot` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Root to search from. Must not be `NULL`. Must have type `SSF_OBJ_TYPE_OBJECT` or `SSF_OBJ_TYPE_ARRAY`. |
| `path` | in | `SSFCStrIn_t *` | Array of label strings. Each entry names a child at the corresponding depth. Must be `NULL`-terminated; `path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH]` must be `NULL`. |
| `gobjParentOut` | out | `SSFGObj_t **` | Receives the direct parent of the found node. Must not be `NULL`. `*gobjParentOut` must be `NULL` before the call. |
| `gobjChildOut` | out | `SSFGObj_t **` | Receives the found node. Must not be `NULL`. `*gobjChildOut` must be `NULL` before the call. |

**Returns:** `true` if the path was resolved; `false` if any label was not found or `gobjRoot` is
not a container type.

<a id="ex-findpath"></a>

```c
SSFGObj_t *root = NULL;
SSFGObj_t *child = NULL;
SSFGObj_t *foundParent = NULL;
SSFGObj_t *found = NULL;
int64_t val;
SSFCStrIn_t path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

SSFGObjInit(&root, 2u);
SSFGObjSetObject(root);

SSFGObjInit(&child, 0u);
SSFGObjSetLabel(child, "count");
SSFGObjSetInt(child, 42);
SSFGObjInsertChild(root, child);

memset(path, 0, sizeof(path));
path[0] = "count";

if (SSFGObjFindPath(root, path, &foundParent, &found))
{
    SSFGObjGetInt(found, &val);   /* val == 42 */
}
SSFGObjDeInit(&root);   /* frees root and child */
```

---

<a id="ssfgobjiterate"></a>

### [↑](#ssfgobj--generic-object-beta) [`bool SSFGObjIterate()`](#functions)

```c
bool SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback);
```

Performs a depth-first traversal of the subtree rooted at `gobj`, invoking `iterateCallback`
once for every node including `gobj` itself. The callback receives the current node and a
linked list of [`SSFGObjPathItem_t`](#type-ssfgobjpathitem-t) nodes representing the path from
the traversal root to the current node.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | [`SSFGObj_t *`](#type-ssfgobj-t) | Root of the subtree to traverse. Must not be `NULL`. |
| `iterateCallback` | in | [`SSFGObjIterateFn_t`](#type-ssfgobjiteratefn-t) | Callback invoked for each node. Must not be `NULL`. |

**Returns:** `true` if traversal completed; `false` if the nesting depth exceeded
[`SSF_GOBJ_CONFIG_MAX_IN_DEPTH`](#opt-gobj-max-depth).

<a id="ex-iterate"></a>

```c
void myCallback(SSFGObj_t *gobj, SSFLL_t *path)
{
    /* Called once per node; inspect gobj->dataType, gobj->labelCStr, etc. */
}

SSFGObj_t *root = NULL;
SSFGObj_t *child = NULL;

SSFGObjInit(&root, 2u);
SSFGObjSetObject(root);
SSFGObjInit(&child, 0u);
SSFGObjSetLabel(child, "x");
SSFGObjSetInt(child, 1);
SSFGObjInsertChild(root, child);

SSFGObjIterate(root, myCallback);
/* myCallback called twice: once for root, once for child */

SSFGObjDeInit(&root);
```

