# ssfgpath — Typed Lookup Path

[SSF](../README.md) | [Codecs](README.md)

The lookup path shared by [`ssfjson`](ssfjson.md), [`ssfubjson`](ssfubjson.md) and
[`ssfgobj`](ssfgobj.md). A path is an array of entries; each entry is either an object member
name or a pointer to an array element index, so a parser never has to guess which one an entry
is. Header only: there is no `.c` file to build.

[Dependencies](#dependencies) | [Notes](#notes) | [API Summary](#api-summary)

<a id="dependencies"></a>

## [↑](#ssfgpath--typed-lookup-path) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfgpath--typed-lookup-path) Notes

- Size a path array for the module it is passed to: `SSF_JSON_CONFIG_MAX_IN_DEPTH + 1`,
  `SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1` or `SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1` entries. The last
  entry must always be an END entry.
- Zero the array with `memset` before use: `SSF_GPATH_END` is 0, so a zeroed array is an empty
  path. Then set entries in order with the `SSF_GPATH_SET_` macros; the first END entry ends the
  path.
- An index entry stores a pointer to the caller's `size_t`, not a copy, so a loop can change the
  variable between lookups without re-setting the entry.
- A path matches only data of the same shape: a key entry where the data has an array, an index
  entry where it has an object, or an entry left over at a scalar means the value is not found.
- Each `SSF_GPATH_SET_` macro evaluates each argument once, so
  `SSF_GPATH_SET_KEY(path[n++], "a")` is safe.

<a id="api-summary"></a>

## [↑](#ssfgpath--typed-lookup-path) API Summary

| Name | Kind | Description |
|------|------|-------------|
| <a id="ssfgpathkind-t"></a>`SSFGPathKind_t` | Enum | Kind of an entry: `SSF_GPATH_END` (0, ends the path), `SSF_GPATH_KEY` (object member name), `SSF_GPATH_INDEX` (array element index) |
| <a id="ssfgpath-t"></a>`SSFGPath_t` | Struct | One path entry: `kind` and `u.key` (`SSFCStrIn_t`, the member name) or `u.index` (`const size_t *`, the index variable) |
| <a id="ssf-gpath-set-key"></a>`SSF_GPATH_SET_KEY(e, k)` | Macro | Sets entry `e` to member name `k` |
| <a id="ssf-gpath-set-index"></a>`SSF_GPATH_SET_INDEX(e, i)` | Macro | Sets entry `e` to the index variable pointed to by `i` |
| <a id="ssf-gpath-set-end"></a>`SSF_GPATH_SET_END(e)` | Macro | Sets entry `e` to the end of the path |
| <a id="ssfgpathisvalid"></a>`bool SSFGPathIsValid(path, maxDepth)` | Function (inline) | `true` if every entry up to the first END has a known kind and a non-`NULL` key or index pointer; `path` must hold `maxDepth + 1` entries. The parsers assert it on every lookup, so a key entry with a `NULL` name, an index entry with a `NULL` pointer, or an unknown kind asserts |

```c
size_t idx = 2;
SSFGPath_t path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];

/* items[2].name */
memset(path, 0, sizeof(path));
SSF_GPATH_SET_KEY(path[0], "items");
SSF_GPATH_SET_INDEX(path[1], &idx);
SSF_GPATH_SET_KEY(path[2], "name");
```
