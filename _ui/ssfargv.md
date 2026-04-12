# ssfargv — Command Line Argv Parser

[SSF](../README.md) | [User Interface](README.md)

Parses a command line string into a generic object (`SSFGObj_t`) tree of command, options,
and positional arguments.

The parser accepts a single null-terminated command line string and produces a hierarchical
gobj tree with three top-level children: a `cmd` string, an `opts` object whose children are
named options (each with an optional value), and an `args` array of positional arguments.
The grammar uses DOS-like single-slash `/opt value` and double-slash `//opt` (no value)
forms, with backslash escape sequences for embedding spaces and literal backslashes inside
arguments.

[Dependencies](#dependencies) | [Grammar](#grammar) | [Result Tree](#result-tree) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfargv--command-line-argv-parser) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssf.h`](../ssf.h)
- [`ssfgobj.h`](../_codec/ssfgobj.h)
- [`ssfstr.h`](../_codec/ssfstr.h)

<a id="grammar"></a>

## [↑](#ssfargv--command-line-argv-parser) Grammar

```
<cmdline> ::= <cmd> ( <opt-noarg> | <opt-witharg> | <arg> )*
<cmd>         ::= [A-Za-z0-9]+
<opt-noarg>   ::= "//" [A-Za-z0-9]+
<opt-witharg> ::= "/"  [A-Za-z0-9]+ <sep> <arg>
<arg>         ::= <printable-char>+
<sep>         ::= " "+
```

Where `<printable-char>` is any ASCII printable character except space (`' '`) and backslash
(`'\\'`), unless escaped by a preceding backslash. Two escape sequences are recognized:

- `\ ` — literal space inside an argument
- `\\` — literal backslash inside an argument

A backslash followed by any other character (including end-of-input) is a parse error.
Leading whitespace before the command and any number of spaces between tokens are tolerated.

The **first** character of `<arg>` cannot be `/`, because the parser treats a leading `/`
as the start of an option specifier. `/` is a normal printable character anywhere else
inside an argument (e.g., `path/to/file` parses as a single argument). If you need an
argument whose first character would be `/`, restructure the command to avoid it (for
example by passing the path as the value of a single-slash option: `cmd /path tmp/out`).

<a id="result-tree"></a>

## [↑](#ssfargv--command-line-argv-parser) Result Tree

A successful `SSFArgvInit()` produces this gobj structure:

```
root (OBJECT)
├── "cmd"  (STR)    — the parsed command name
├── "opts" (OBJECT) — one child per option
│   ├── "<optname>" (STR) — option value, or "" for //opts
│   └── ...
└── "args" (ARRAY)  — positional arguments in order
    ├── (STR)
    └── ...
```

The label constants [`SSF_ARGV_CMD_STR`](#ssf-argv-cmd-str),
[`SSF_ARGV_OPTS_STR`](#ssf-argv-opts-str), and [`SSF_ARGV_ARGS_STR`](#ssf-argv-args-str) can be
used with `SSFGObjFindPath()` to navigate the tree.

<a id="notes"></a>

## [↑](#ssfargv--command-line-argv-parser) Notes

- A command name is required; an empty or whitespace-only command line is rejected.
- Single-slash options (`/opt value`) require a following positional argument as their value.
  An option missing its required argument (at end of input or followed by another option) is
  a parse error.
- Double-slash options (`//opt`) take no value; their stored value is the empty string `""`.
- Option and command names are case-sensitive and limited to ASCII alphanumeric characters.
- `-` is no longer a special character; it can appear anywhere in an argument including as
  the first character. Only `/` triggers option parsing.
- The parser allocates an internal mutable copy of the command line via `SSF_MALLOC` and
  frees it before returning. The caller's input buffer is not modified.
- The result tree is heap-allocated via `ssfgobj`. The caller must release it with
  [`SSFArgvDeInit()`](#ssfargvdeinit) when finished.
- `maxOpts` and `maxArgs` are hard caps. Exceeding either limit causes
  [`SSFArgvInit()`](#ssfargvinit) to return `false`. When set to `0`, the corresponding
  container is created but cannot accept any children.

<a id="configuration"></a>

## [↑](#ssfargv--command-line-argv-parser) Configuration

The following option is defined in [`ssfport.h`](../ssfport.h):

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_CONFIG_ARGV_UNIT_TEST` | `1` | Set to `1` to compile the [`SSFArgvUnitTest()`](#ssfargvunittest) entry point and enable assertion-test coverage. |

<a id="api-summary"></a>

## [↑](#ssfargv--command-line-argv-parser) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-argv-cmd-str"></a>`SSF_ARGV_CMD_STR` | Constant | `"cmd"` — label of the command child gobj |
| <a id="ssf-argv-opts-str"></a>`SSF_ARGV_OPTS_STR` | Constant | `"opts"` — label of the options object child gobj |
| <a id="ssf-argv-args-str"></a>`SSF_ARGV_ARGS_STR` | Constant | `"args"` — label of the positional argument array child gobj |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`bool SSFArgvInit(cmdLineStr, cmdLineSize, gobj, maxOpts, maxArgs)`](#ssfargvinit) | Parse a command line string into a newly allocated gobj tree |
| [e.g.](#ex-deinit) | [`void SSFArgvDeInit(gobj)`](#ssfargvdeinit) | Release a gobj tree allocated by [`SSFArgvInit()`](#ssfargvinit) |

<a id="function-reference"></a>

## [↑](#ssfargv--command-line-argv-parser) Function Reference

<a id="ssfargvinit"></a>

### [↑](#ssfargv--command-line-argv-parser) [`bool SSFArgvInit()`](#functions)

```c
bool SSFArgvInit(SSFCStrIn_t cmdLineStr, size_t cmdLineSize, SSFGObj_t **gobj, uint8_t maxOpts,
                 uint8_t maxArgs);
```

Parses `cmdLineStr` according to the [grammar](#grammar) and, on success, allocates a gobj
tree representing the parsed command, options, and positional arguments. The caller must
release the tree with [`SSFArgvDeInit()`](#ssfargvdeinit).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cmdLineStr` | in | `const char *` | Null-terminated command line string to parse. Must not be `NULL`. Not modified by the call. |
| `cmdLineSize` | in | `size_t` | Total size in bytes of `cmdLineStr` including the null terminator. Must be large enough to contain the terminating null. |
| `gobj` | out | `SSFGObj_t **` | Receives the root of the newly allocated gobj tree on success. Must not be `NULL`, and `*gobj` must be `NULL` on entry. On failure `*gobj` is left as `NULL`. |
| `maxOpts` | in | `uint8_t` | Maximum number of distinct options the parser may insert. Inputs with more options return `false`. May be `0` to forbid options entirely. |
| `maxArgs` | in | `uint8_t` | Maximum number of positional arguments the parser may insert. Inputs with more args return `false`. May be `0` to forbid positional args entirely. |

**Returns:** `true` if the command line was parsed successfully and `*gobj` holds the result;
`false` if the input violates the grammar, exceeds `maxOpts` or `maxArgs`, or an internal
allocation fails. On failure no allocations remain and `*gobj` is `NULL`.

<a id="ex-init"></a>

```c
SSFGObj_t *gobj = NULL;
SSFGObj_t *parent = NULL;
SSFGObj_t *child  = NULL;
SSFCStrIn_t path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1] = { NULL };
char val[64];
size_t i;

if (SSFArgvInit("copy //verbose /dest tmp/out src.txt other.txt",
                sizeof("copy //verbose /dest tmp/out src.txt other.txt"),
                &gobj, 4, 4))
{
    /* Read the command name */
    path[0] = SSF_ARGV_CMD_STR;
    parent = NULL; child = NULL;
    SSFGObjFindPath(gobj, path, &parent, &child);
    SSFGObjGetString(child, val, sizeof(val));
    /* val == "copy" */

    /* Read //verbose (value-less option, stored as "") */
    memset(path, 0, sizeof(path));
    path[0] = SSF_ARGV_OPTS_STR;
    path[1] = "verbose";
    parent = NULL; child = NULL;
    SSFGObjFindPath(gobj, path, &parent, &child);
    SSFGObjGetString(child, val, sizeof(val));
    /* val == "" */

    /* Read /dest tmp/out */
    memset(path, 0, sizeof(path));
    path[0] = SSF_ARGV_OPTS_STR;
    path[1] = "dest";
    parent = NULL; child = NULL;
    SSFGObjFindPath(gobj, path, &parent, &child);
    SSFGObjGetString(child, val, sizeof(val));
    /* val == "tmp/out" */

    /* Read positional args by index */
    for (i = 0; i < 2; i++)
    {
        memset(path, 0, sizeof(path));
        path[0] = SSF_ARGV_ARGS_STR;
        path[1] = (SSFCStrIn_t)&i;
        parent = NULL; child = NULL;
        SSFGObjFindPath(gobj, path, &parent, &child);
        SSFGObjGetString(child, val, sizeof(val));
        /* i == 0 -> val == "src.txt"
           i == 1 -> val == "other.txt" */
    }

    SSFArgvDeInit(&gobj);
}
```

Inputs that the parser accepts:

```c
SSFArgvInit("ls", ...);                          /* cmd only */
SSFArgvInit("ls /l file.txt", ...);              /* cmd, opt with value, arg */
SSFArgvInit("ls //all", ...);                    /* cmd, value-less opt */
SSFArgvInit("echo hello\\ world", ...);          /* arg "hello world" (escaped space) */
SSFArgvInit("echo C:\\\\tmp", ...);              /* arg "C:\tmp" (escaped backslash) */
SSFArgvInit("echo path/to/file", ...);           /* '/' is ordinary inside an arg */
SSFArgvInit("echo -dash-arg", ...);              /* '-' is no longer a special character */
SSFArgvInit("  cmd  arg1   arg2  ", ...);        /* extra whitespace tolerated */
```

Inputs that the parser rejects:

```c
SSFArgvInit("",          ...);   /* empty - command name required */
SSFArgvInit("  ",        ...);   /* whitespace only - no command */
SSFArgvInit("/opt val",  ...);   /* missing command */
SSFArgvInit("cmd /opt",  ...);   /* /opt requires a following value */
SSFArgvInit("cmd a\\b",  ...);   /* \X is not a valid escape */
SSFArgvInit("cmd \t",    ...);   /* non-printable character */
SSFArgvInit("cmd!",      ...);   /* '!' is not allowed in a command name */
SSFArgvInit("cmd /path/to/file", ...); /* arg cannot begin with '/' */
```

---

<a id="ssfargvdeinit"></a>

### [↑](#ssfargv--command-line-argv-parser) [`void SSFArgvDeInit()`](#functions)

```c
void SSFArgvDeInit(SSFGObj_t **gobj);
```

Releases a gobj tree previously returned by a successful
[`SSFArgvInit()`](#ssfargvinit) call. Recursively frees the cmd, opts, args, and all child
nodes, then sets `*gobj` to `NULL`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in-out | `SSFGObj_t **` | Pointer to the gobj root pointer to free. Must not be `NULL`, and `*gobj` must point to a tree previously returned by [`SSFArgvInit()`](#ssfargvinit). On return `*gobj` is `NULL`. |

<a id="ex-deinit"></a>

```c
SSFGObj_t *gobj = NULL;

if (SSFArgvInit("cmd arg1", sizeof("cmd arg1"), &gobj, 4, 4))
{
    /* ... use gobj ... */
    SSFArgvDeInit(&gobj);
    /* gobj == NULL */
}
```
