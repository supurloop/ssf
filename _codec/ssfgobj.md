# ssfgobj — Generic Object Parser/Generator (BETA)

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Hierarchical generic object parser and generator. Designed as a common in-memory representation
that can translate between JSON, UBJSON, and other encoding types.

> **Note:** This interface is in BETA and still under development. The API may change.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_GOBJ_CONFIG_MAX_IN_DEPTH` | `4` | Maximum nesting depth for objects and arrays |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFGObjInit(gobj, maxChildren)` | Allocate and initialize a generic object node |
| `SSFGObjDeInit(gobj)` | De-initialize and free a generic object node and all its children |
| `SSFGObjSetLabel(gobj, labelCStr)` | Set the label (key name) of an object node |
| `SSFGObjGetLabel(gobj, labelCStrOut, labelCStrOutSize)` | Copy the label of an object node into a buffer |
| `SSFGObjGetType(gobj)` | Return the current data type of an object node |
| `SSFGObjGetSize(gobj)` | Return the current data size of an object node |
| `SSFGObjSetNone(gobj)` | Set the node's value to the untyped `NONE` sentinel |
| `SSFGObjSetString(gobj, valueCStr)` | Set the node's value to a string |
| `SSFGObjGetString(gobj, valueCStrOut, labelCStrOutSize)` | Copy the node's string value into a buffer |
| `SSFGObjSetInt(gobj, value)` | Set the node's value to a signed 64-bit integer |
| `SSFGObjGetInt(gobj, valueOut)` | Read the node's signed 64-bit integer value |
| `SSFGObjSetUInt(gobj, value)` | Set the node's value to an unsigned 64-bit integer |
| `SSFGObjGetUInt(gobj, valueOut)` | Read the node's unsigned 64-bit integer value |
| `SSFGObjSetFloat(gobj, value)` | Set the node's value to a double-precision float |
| `SSFGObjGetFloat(gobj, valueOut)` | Read the node's double-precision float value |
| `SSFGObjSetBool(gobj, value)` | Set the node's value to a boolean |
| `SSFGObjGetBool(gobj, valueOut)` | Read the node's boolean value |
| `SSFGObjSetBin(gobj, value, valueLen)` | Set the node's value to a binary byte array |
| `SSFGObjGetBin(gobj, valueOut, valueSize, valueLenOutOpt)` | Copy the node's binary value into a buffer |
| `SSFGObjSetNull(gobj)` | Set the node's value to JSON null |
| `SSFGObjSetObject(gobj)` | Set the node's type to a structured object container |
| `SSFGObjSetArray(gobj)` | Set the node's type to an array container |
| `SSFGObjInsertChild(gobjParent, gobjChild)` | Insert a child node into a parent object or array |
| `SSFGObjRemoveChild(gobjParent, gobjChild)` | Remove a child node from a parent object or array |
| `SSFGObjFindPath(gobjRoot, path, gobjParentOut, gobjChildOut)` | Locate a node by label path from the root |
| `SSFGObjIterate(gobj, iterateCallback)` | Depth-first traversal of all nodes under a subtree |

## Data Types

### `SSFObjType_t`

Enumerates the value type currently held by an `SSFGObj_t` node.

| Constant | Description |
|----------|-------------|
| `SSF_OBJ_TYPE_NONE` | Untyped sentinel — no value assigned |
| `SSF_OBJ_TYPE_STR` | Null-terminated string |
| `SSF_OBJ_TYPE_BIN` | Binary byte array |
| `SSF_OBJ_TYPE_INT` | Signed 64-bit integer |
| `SSF_OBJ_TYPE_UINT` | Unsigned 64-bit integer |
| `SSF_OBJ_TYPE_FLOAT` | Double-precision floating-point |
| `SSF_OBJ_TYPE_BOOL` | Boolean (`true` or `false`) |
| `SSF_OBJ_TYPE_NULL` | Explicit null (e.g., JSON `null`) |
| `SSF_OBJ_TYPE_OBJECT` | Structured object container with named children |
| `SSF_OBJ_TYPE_ARRAY` | Array container with ordered children |

### `SSFGObj_t`

Represents one node in the generic object tree.

| Field | Type | Description |
|-------|------|-------------|
| `item` | `SSFLLItem_t` | Linked-list linkage; used internally by the parent's child list |
| `labelCStr` | `char *` | Heap-allocated label string, or `NULL` if not set |
| `data` | `void *` | Heap-allocated value storage, or `NULL` for container types |
| `children` | `SSFLL_t` | Linked list of child `SSFGObj_t` nodes |
| `dataType` | `SSFObjType_t` | Current value type |
| `dataSize` | `size_t` | Size in bytes of `data`, or `0` for types without heap storage |

### `SSFGObjIterateFn_t`

```c
typedef void (*SSFGObjIterateFn_t)(SSFGObj_t *gobj, SSFLL_t *path);
```

Callback signature passed to `SSFGObjIterate`. Called once for every node in the subtree during
depth-first traversal. `gobj` is the current node; `path` is a linked list of
`SSFGObjPathItem_t` nodes describing the path from the traversal root to the current node.

## Function Reference

### `SSFGObjInit`

```c
bool SSFGObjInit(SSFGObj_t **gobj, uint16_t maxChildren);
```

Allocates and initializes a new generic object node. The node is created with type
`SSF_OBJ_TYPE_NONE`, no label, no value, and an empty child list. The caller is responsible for
calling `SSFGObjDeInit` when the node is no longer needed.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | out | `SSFGObj_t **` | Receives the pointer to the newly allocated node. Must not be `NULL`. Must point to a `NULL` pointer before the call. |
| `maxChildren` | in | `uint16_t` | Reserved for future use. Pass `0`. |

**Returns:** `true` if the node was allocated and initialized successfully; `false` if memory allocation failed.

---

### `SSFGObjDeInit`

```c
void SSFGObjDeInit(SSFGObj_t **gobj);
```

De-initializes and frees the node pointed to by `*gobj`, including its label, value data, and
all child nodes recursively. Sets `*gobj` to `NULL` on return. The node must not be a child of
another node at the time of this call; remove it from its parent with `SSFGObjRemoveChild` first.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in-out | `SSFGObj_t **` | Pointer to the node to de-initialize. Set to `NULL` on return. Must not be `NULL`. |

**Returns:** Nothing.

---

### `SSFGObjSetLabel`

```c
bool SSFGObjSetLabel(SSFGObj_t *gobj, SSFCStrIn_t labelCStr);
```

Assigns a label (key name) to the node, replacing any previously set label. The string is
copied internally. Labels are used to identify named fields within an object container, and
are also the key used by `SSFGObjFindPath`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `labelCStr` | in | `const char *` | Null-terminated label string to set. Must not be `NULL`. |

**Returns:** `true` if the label was set; `false` if memory allocation for the copy failed.

---

### `SSFGObjGetLabel`

```c
bool SSFGObjGetLabel(SSFGObj_t *gobj, SSFCStrOut_t labelCStrOut, size_t labelCStrOutSize);
```

Copies the node's label into `labelCStrOut`. If the node has no label set, returns `false`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `labelCStrOut` | out | `char *` | Buffer to receive the null-terminated label. Must not be `NULL`. |
| `labelCStrOutSize` | in | `size_t` | Size of `labelCStrOut` in bytes. Must be large enough to hold the label including the null terminator. |

**Returns:** `true` if the label was copied successfully; `false` if no label is set or the buffer is too small.

---

### `SSFGObjGetType`

```c
SSFObjType_t SSFGObjGetType(SSFGObj_t *gobj);
```

Returns the current data type of the node as set by the most recent `SSFGObjSet*` call.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |

**Returns:** The current `SSFObjType_t` value of the node.

---

### `SSFGObjGetSize`

```c
size_t SSFGObjGetSize(SSFGObj_t *gobj);
```

Returns the size in bytes of the value currently stored in the node. For string types this
includes the null terminator. For container types (`OBJECT`, `ARRAY`) and valueless types
(`NONE`, `NULL`) this is `0`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |

**Returns:** Size in bytes of the stored value, or `0` for valueless types.

---

### `SSFGObjSetNone`

```c
bool SSFGObjSetNone(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_NONE` and frees any existing value data. This is the
initial state of every node after `SSFGObjInit`. Use it to clear a node's value without
destroying it.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

---

### `SSFGObjSetString`

```c
bool SSFGObjSetString(SSFGObj_t *gobj, SSFCStrIn_t valueCStr);
```

Sets the node's value to a copy of the supplied null-terminated string, replacing any existing
value. The node's type becomes `SSF_OBJ_TYPE_STR`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `valueCStr` | in | `const char *` | Null-terminated string to store. Must not be `NULL`. |

**Returns:** `true` if the value was set; `false` if memory allocation failed.

---

### `SSFGObjGetString`

```c
bool SSFGObjGetString(SSFGObj_t *gobj, SSFCStrOut_t valueCStrOut, size_t labelCStrOutSize);
```

Copies the node's string value into `valueCStrOut`. Fails if the node's type is not
`SSF_OBJ_TYPE_STR` or the buffer is too small.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `valueCStrOut` | out | `char *` | Buffer to receive the null-terminated string. Must not be `NULL`. |
| `labelCStrOutSize` | in | `size_t` | Size of `valueCStrOut` in bytes. Must be large enough to hold the string including the null terminator. |

**Returns:** `true` if the string was copied; `false` if the node type is not `SSF_OBJ_TYPE_STR` or the buffer is too small.

---

### `SSFGObjSetInt`

```c
bool SSFGObjSetInt(SSFGObj_t *gobj, int64_t value);
```

Sets the node's value to a signed 64-bit integer, replacing any existing value. The node's type
becomes `SSF_OBJ_TYPE_INT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `value` | in | `int64_t` | Signed integer value to store. |

**Returns:** `true` if the value was set; `false` if memory allocation failed.

---

### `SSFGObjGetInt`

```c
bool SSFGObjGetInt(SSFGObj_t *gobj, int64_t *valueOut);
```

Reads the node's signed 64-bit integer value. Fails if the node's type is not
`SSF_OBJ_TYPE_INT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `int64_t *` | Receives the integer value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_INT`.

---

### `SSFGObjSetUInt`

```c
bool SSFGObjSetUInt(SSFGObj_t *gobj, uint64_t value);
```

Sets the node's value to an unsigned 64-bit integer, replacing any existing value. The node's
type becomes `SSF_OBJ_TYPE_UINT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `value` | in | `uint64_t` | Unsigned integer value to store. |

**Returns:** `true` if the value was set; `false` if memory allocation failed.

---

### `SSFGObjGetUInt`

```c
bool SSFGObjGetUInt(SSFGObj_t *gobj, uint64_t *valueOut);
```

Reads the node's unsigned 64-bit integer value. Fails if the node's type is not
`SSF_OBJ_TYPE_UINT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `uint64_t *` | Receives the unsigned integer value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_UINT`.

---

### `SSFGObjSetFloat`

```c
bool SSFGObjSetFloat(SSFGObj_t *gobj, double value);
```

Sets the node's value to a double-precision floating-point number, replacing any existing value.
The node's type becomes `SSF_OBJ_TYPE_FLOAT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `value` | in | `double` | Double-precision float value to store. |

**Returns:** `true` if the value was set; `false` if memory allocation failed.

---

### `SSFGObjGetFloat`

```c
bool SSFGObjGetFloat(SSFGObj_t *gobj, double *valueOut);
```

Reads the node's double-precision floating-point value. Fails if the node's type is not
`SSF_OBJ_TYPE_FLOAT`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `double *` | Receives the float value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_FLOAT`.

---

### `SSFGObjSetBool`

```c
bool SSFGObjSetBool(SSFGObj_t *gobj, bool value);
```

Sets the node's value to a boolean, replacing any existing value. The node's type becomes
`SSF_OBJ_TYPE_BOOL`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `value` | in | `bool` | Boolean value to store (`true` or `false`). |

**Returns:** `true` if the value was set; `false` if memory allocation failed.

---

### `SSFGObjGetBool`

```c
bool SSFGObjGetBool(SSFGObj_t *gobj, bool *valueOut);
```

Reads the node's boolean value. Fails if the node's type is not `SSF_OBJ_TYPE_BOOL`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `bool *` | Receives the boolean value. Must not be `NULL`. |

**Returns:** `true` if the value was read; `false` if the node type is not `SSF_OBJ_TYPE_BOOL`.

---

### `SSFGObjSetBin`

```c
bool SSFGObjSetBin(SSFGObj_t *gobj, uint8_t *value, size_t valueLen);
```

Sets the node's value to a copy of the supplied binary byte array, replacing any existing value.
The node's type becomes `SSF_OBJ_TYPE_BIN`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `value` | in | `uint8_t *` | Pointer to the byte array to copy. Must not be `NULL`. |
| `valueLen` | in | `size_t` | Number of bytes to copy from `value`. Must be greater than `0`. |

**Returns:** `true` if the value was set; `false` if memory allocation failed.

---

### `SSFGObjGetBin`

```c
bool SSFGObjGetBin(SSFGObj_t *gobj, uint8_t *valueOut, size_t valueSize,
                   size_t *valueLenOutOpt);
```

Copies the node's binary value into `valueOut`. Fails if the node's type is not
`SSF_OBJ_TYPE_BIN` or the buffer is too small.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |
| `valueOut` | out | `uint8_t *` | Buffer to receive the binary data. Must not be `NULL`. |
| `valueSize` | in | `size_t` | Size of `valueOut` in bytes. Must be at least the stored data size. |
| `valueLenOutOpt` | out (opt) | `size_t *` | If not `NULL`, receives the number of bytes copied. |

**Returns:** `true` if the data was copied; `false` if the node type is not `SSF_OBJ_TYPE_BIN` or the buffer is too small.

---

### `SSFGObjSetNull`

```c
bool SSFGObjSetNull(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_NULL` (representing an explicit null value such as JSON
`null`), freeing any existing value data. Unlike `SSFGObjSetNone`, this represents a meaningful
typed value, not an uninitialized state.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

---

### `SSFGObjSetObject`

```c
bool SSFGObjSetObject(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_OBJECT`, marking it as a structured object container
(analogous to a JSON object `{}`). Children added with `SSFGObjInsertChild` are accessible by
label via `SSFGObjFindPath`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

---

### `SSFGObjSetArray`

```c
bool SSFGObjSetArray(SSFGObj_t *gobj);
```

Sets the node's type to `SSF_OBJ_TYPE_ARRAY`, marking it as an ordered array container
(analogous to a JSON array `[]`). Children are accessed in insertion order.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Pointer to the node. Must not be `NULL`. |

**Returns:** `true` always.

---

### `SSFGObjInsertChild`

```c
bool SSFGObjInsertChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild);
```

Appends `gobjChild` to the child list of `gobjParent`. The parent must have type
`SSF_OBJ_TYPE_OBJECT` or `SSF_OBJ_TYPE_ARRAY`. The child must not already belong to another
parent. Once inserted, the child's lifetime is managed by the parent — `SSFGObjDeInit` on
the parent will recursively free all children.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobjParent` | in | `SSFGObj_t *` | Pointer to the parent node. Must not be `NULL`. Must have type `SSF_OBJ_TYPE_OBJECT` or `SSF_OBJ_TYPE_ARRAY`. |
| `gobjChild` | in | `SSFGObj_t *` | Pointer to the child node to insert. Must not be `NULL`. Must not already be a child of another node. |

**Returns:** `true` if the child was inserted; `false` if the parent type is not a container or another precondition fails.

---

### `SSFGObjRemoveChild`

```c
bool SSFGObjRemoveChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild);
```

Removes `gobjChild` from the child list of `gobjParent`. After removal, the caller owns the
child and must either insert it elsewhere or free it with `SSFGObjDeInit`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobjParent` | in | `SSFGObj_t *` | Pointer to the parent node. Must not be `NULL`. |
| `gobjChild` | in | `SSFGObj_t *` | Pointer to the child node to remove. Must not be `NULL`. Must be a direct child of `gobjParent`. |

**Returns:** `true` if the child was removed; `false` if `gobjChild` is not found in the parent's child list.

---

### `SSFGObjFindPath`

```c
bool SSFGObjFindPath(SSFGObj_t *gobjRoot, SSFCStrIn_t *path,
                     SSFGObj_t **gobjParentOut, SSFGObj_t **gobjChildOut);
```

Locates a descendant node by following a null-terminated array of label strings from
`gobjRoot`. Each element in `path` names a child at the corresponding nesting level; the array
is terminated by a `NULL` pointer sentinel. On success, `*gobjParentOut` receives the
second-to-last node and `*gobjChildOut` receives the target node.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobjRoot` | in | `SSFGObj_t *` | Root node to begin the search from. Must not be `NULL`. |
| `path` | in | `const char **` | Null-terminated array of label strings forming the path. Each string must match the label of a child at the corresponding depth. The last element must be `NULL`. |
| `gobjParentOut` | out | `SSFGObj_t **` | Receives the parent of the found node, or `NULL` if the root itself is the target. Must not be `NULL`. |
| `gobjChildOut` | out | `SSFGObj_t **` | Receives the found node. Must not be `NULL`. Set to `NULL` if the path is not found. |

**Returns:** `true` if the path was resolved and `*gobjChildOut` was set; `false` if any label in the path was not found.

---

### `SSFGObjIterate`

```c
bool SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback);
```

Performs a depth-first traversal of the subtree rooted at `gobj`, invoking `iterateCallback`
once for every node visited including `gobj` itself. The callback receives the current node and
a linked list of `SSFGObjPathItem_t` nodes representing the path from the traversal root to
the current node.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Root of the subtree to traverse. Must not be `NULL`. |
| `iterateCallback` | in | `SSFGObjIterateFn_t` | Callback invoked for each node. Must not be `NULL`. Signature: `void fn(SSFGObj_t *gobj, SSFLL_t *path)`. |

**Returns:** `true` if traversal completed; `false` if an internal error occurred (e.g., nesting depth exceeded `SSF_GOBJ_CONFIG_MAX_IN_DEPTH`).

---

## Usage

The generic object tree provides a flexible in-memory representation suitable for building,
modifying, and querying structured data independently of any wire format.

```c
SSFGObj_t *root = NULL;
SSFGObj_t *child = NULL;
SSFGObj_t *found = NULL;
SSFGObj_t *foundParent = NULL;
int64_t intVal;

/* Build: root object with one integer child labeled "count" */
SSF_ASSERT(SSFGObjInit(&root, 0));
SSFGObjSetObject(root);

SSF_ASSERT(SSFGObjInit(&child, 0));
SSFGObjSetLabel(child, "count");
SSFGObjSetInt(child, 42);
SSFGObjInsertChild(root, child);

/* Find the "count" node by path */
SSFCStrIn_t path[] = { "count", NULL };
if (SSFGObjFindPath(root, path, &foundParent, &found))
{
    SSFGObjGetInt(found, &intVal);  /* intVal == 42 */
}

/* Free the entire tree */
SSFGObjDeInit(&root);  /* root == NULL; child freed recursively */
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`
- [ssfll](ssfll.md) — Linked list (used internally for child lists and path tracking)

## Notes

- This module is in BETA; expect API changes in future releases.
- Nesting depth is limited by `SSF_GOBJ_CONFIG_MAX_IN_DEPTH`.
- Child nodes inserted into a parent via `SSFGObjInsertChild` must be removed with
  `SSFGObjRemoveChild` before the child can be freed independently; otherwise `SSFGObjDeInit`
  on the parent will free them.
- `SSFGObjSetObject` and `SSFGObjSetArray` do not free existing children; set the type before
  inserting children.
- `SSFGObjGetType` should be checked before calling any `SSFGObjGet*` function to avoid
  type-mismatch failures.
