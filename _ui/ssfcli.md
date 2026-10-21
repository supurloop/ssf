# ssfcli — CLI Framework

[SSF](../README.md) | [User Interface](README.md)

Provides a command-line interface framework that ties together the
[VT100 terminal line editor](ssfvted.md) and the [command line argv parser](ssfargv.md)
to deliver a complete interactive shell for embedded systems.

The module manages a list of registered commands, command history with arrow-key recall, input
character dispatch, argv parsing, handler invocation, and built-in help/syntax display.
The caller creates a VT100 editor context, a CLI context, registers one or more commands with
handler callbacks, and then feeds received bytes (from a UART, socket, or stdin in raw mode)
into [`SSFCLIProcessChar()`](#ssfcliprocesschar). The framework handles everything else:
line editing, escape-sequence decoding, argv parsing, command lookup, handler dispatch,
syntax-error output, and prompt management.

Three helper functions —
[`SSFCLIGObjGetOptArgStrRef()`](#ssfcligobjgetoptargstrref),
[`SSFCLIGObjGetIsOpt()`](#ssfcligobjgetisopt), and
[`SSFCLIGObjGetArgStrRef()`](#ssfcligobjgetargstrref) — simplify extracting option values
and positional arguments inside command handlers.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Complete Example](#complete-example)

<a id="dependencies"></a>

## [↑](#ssfcli--cli-framework) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssf.h`](../ssf.h)
- [`ssfassert.h`](../ssfassert.h)
- [`ssfvted.h`](ssfvted.h) — [VT100 Terminal Line Editor](ssfvted.md)
- [`ssfargv.h`](ssfargv.h) — [Command Line Argv Parser](ssfargv.md)
- [`ssfll.h`](../_struct/ssfll.h) — [Linked List](../_struct/ssfll.md) (for the registered command list)
- [`ssfgobj.h`](../_codec/ssfgobj.h) — [Generic Object](../_codec/ssfgobj.md) (for parsed command trees)
- [`ssfoptions.h`](../ssfoptions.h) — compile-time configuration constants

<a id="notes"></a>

## [↑](#ssfcli--cli-framework) Notes

- **Two-phase initialization**: the caller must initialize a `SSFVTEdContext_t` via
  [`SSFVTEdInit()`](ssfvted.md#ssfvtedinit) first, then pass it to
  [`SSFCLIInit()`](#ssfcliinit). The CLI context does not own the VT100 context or its line
  buffer; it stores only a pointer.

- **Zero-init before first use**: both `SSFVTEdContext_t` and `SSFCLIContext_t` must be
  zeroed before the first `Init` call. Stack-allocated structs require an explicit `memset`;
  static-allocated structs are automatically zeroed.

- **`SSFCLICmd_t` must be zeroed**: the command struct contains an `SSFLLItem_t` whose `ll`
  pointer must be `NULL` before the first [`SSFCLIInitCmd()`](#ssfcliinitcmd) call. Static
  command arrays are auto-zeroed; stack or heap structs must be zeroed by the caller.

- **Handler contract**: a command handler returns `true` on success and `false` on failure.
  When the handler returns `false`, the CLI automatically prints the command's
  `cmdSyntaxStr` to the terminal as usage help.

- **Command history**: when `maxCmdHist > 0`, the CLI saves each non-empty command line into
  a caller-supplied ring buffer on Enter. The Up and Down arrow keys recall previous commands.
  Empty-line Enter does not save to history. The history buffer must be at least
  `lineSize * maxCmdHist` bytes.

- **Built-in help**: when the user enters a command that does not match any registered command,
  the CLI prints the list of registered commands with their syntax strings. When the user
  enters a line that fails argv parsing (e.g. invalid characters), the CLI prints the
  command-line grammar.

- **No heap allocation**: the CLI context itself uses no heap. The argv parser
  ([`SSFArgvInit`](ssfargv.md#ssfargvinit)) allocates temporary gobj trees on the heap;
  these are freed by [`SSFArgvDeInit`](ssfargv.md#ssfargvdeinit) before
  `SSFCLIProcessChar()` returns.

- **Single-threaded**: each `SSFCLIContext_t` is independent and holds no shared state.
  Multiple CLI instances can coexist, but each must be accessed from only one thread at a time.

<a id="configuration"></a>

## [↑](#ssfcli--cli-framework) Configuration

The following options are defined in [`_opt/ssfcli_opt.h`](../_opt/ssfcli_opt.h)
(aggregated into the build via `ssfoptions.h`):

| Option | Default | Description |
|--------|---------|-------------|
| <a id="cfg-max-opts"></a>`SSF_CLI_MAX_OPTS` | `5` | Maximum number of options (`/opt` or `//opt`) per command line |
| <a id="cfg-max-args"></a>`SSF_CLI_MAX_ARGS` | `5` | Maximum number of positional arguments per command line |
| <a id="cfg-max-line-size"></a>`SSF_CLI_MAX_CMD_LINE_SIZE` | `80` | Maximum size of the command line buffer including null terminator |
| <a id="cfg-max-cmds"></a>`SSF_CLI_MAX_CMDS` | `10` | Maximum number of commands that can be registered in one CLI context |
| <a id="cfg-max-hist"></a>`SSF_CLI_MAX_CMD_HIST` | `6` | Maximum number of command history entries |

The following option is defined in [`ssfport.h`](../ssfport.h):

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_CONFIG_CLI_UNIT_TEST` | `1` | Set to `1` to compile the [`SSFCLIUnitTest()`](#ssfcliunittest) entry point and enable assertion-test coverage |

<a id="api-summary"></a>

## [↑](#ssfcli--cli-framework) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-handler"></a>`SSFCLIHandler_t` | Typedef | `bool (*)(SSFGObj_t *gobjCmd, uint32_t numOpts, SSFGObj_t *gobjOpts, uint32_t numArgs, SSFGObj_t *gobjArgs, SSFVTEdWriteStdoutFn_t writeStdoutFn)` — command handler callback |
| <a id="type-cmd"></a>`SSFCLICmd_t` | Struct | Registered command descriptor. Fields: `item` (linked-list header), `cmdStr` (command name), `cmdSyntaxStr` (usage string), `cmdFn` ([`SSFCLIHandler_t`](#type-handler)) |
| <a id="type-context"></a>`SSFCLIContext_t` | Struct | Per-CLI state. Fields: `vtEdCtx` (pointer to the VT100 editor), `cmds` (linked list of registered commands), `numCmdHist`, `cmdHistBufIndex`, `cmdHistBufSize`, `cmdHistBuf`, `magic` |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFCLIInit(context, maxCmds, maxCmdHist, cmdHistBuf, cmdHistBufSize, vtEdCtx)`](#ssfcliinit) | Initialize a CLI context |
| [e.g.](#ex-deinit) | [`void SSFCLIDeInit(context)`](#ssfclideinit) | Tear down a CLI context |
| [e.g.](#ex-initcmd) | [`void SSFCLIInitCmd(context, cmd)`](#ssfcliinitcmd) | Register a command |
| [e.g.](#ex-deinitcmd) | [`void SSFCLIDeInitCmd(context, cmd)`](#ssfclideinitcmd) | Unregister a command |
| [e.g.](#ex-processchar) | [`void SSFCLIProcessChar(context, inChar)`](#ssfcliprocesschar) | Process one input byte |
| [e.g.](#ex-getoptarg) | [`bool SSFCLIGObjGetOptArgStrRef(optStr, gobjOpts, strOut, strLen)`](#ssfcligobjgetoptargstrref) | Get an option's argument string |
| [e.g.](#ex-getisopt) | [`bool SSFCLIGObjGetIsOpt(optStr, gobjOpts)`](#ssfcligobjgetisopt) | Check whether a value-less option is present |
| [e.g.](#ex-getargstr) | [`bool SSFCLIGObjGetArgStrRef(argIndex, gobjArgs, strOut, strLen)`](#ssfcligobjgetargstrref) | Get a positional argument string by index |

<a id="function-reference"></a>

## [↑](#ssfcli--cli-framework) Function Reference

<a id="ssfcliinit"></a>

### [↑](#ssfcli--cli-framework) [`void SSFCLIInit()`](#functions)

```c
void SSFCLIInit(SSFCLIContext_t *context, uint16_t maxCmds, uint8_t maxCmdHist,
                uint8_t *cmdHistBuf, size_t cmdHistBufSize, SSFVTEdContext_t *vtEdCtx);
```

Initializes a CLI context and binds it to an already-initialized VT100 editor context.
The context must be zeroed by the caller before the first call. When `maxCmdHist` is `0`,
command history is disabled and `cmdHistBuf` must be `NULL` with `cmdHistBufSize` equal to
`0`. When `maxCmdHist > 0`, the caller must provide a buffer of at least
`vtEdCtx->lineSize * maxCmdHist` bytes; the buffer is zeroed by `SSFCLIInit()`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | [`SSFCLIContext_t *`](#type-context) | Caller-supplied context storage. Must not be `NULL`. `context->magic` must be `0` on entry. |
| `maxCmds` | in | `uint16_t` | Maximum number of commands that can be registered. Must be `> 0` and `<= SSF_CLI_MAX_CMDS`. |
| `maxCmdHist` | in | `uint8_t` | Maximum number of command history entries. May be `0` to disable history. Must be `<= SSF_CLI_MAX_CMD_HIST`. |
| `cmdHistBuf` | in | `uint8_t *` | Caller-supplied history ring buffer. Must be `NULL` when `maxCmdHist == 0`. |
| `cmdHistBufSize` | in | `size_t` | Size of `cmdHistBuf` in bytes. Must be `0` when `maxCmdHist == 0`. Must be `>= vtEdCtx->lineSize * maxCmdHist` otherwise. |
| `vtEdCtx` | in | `SSFVTEdContext_t *` | Pointer to an initialized VT100 editor context. Must not be `NULL`. Must be initialized via [`SSFVTEdInit()`](ssfvted.md#ssfvtedinit). |

<a id="ex-init"></a>

```c
SSFVTEdContext_t vtctx;
SSFCLIContext_t clictx;
char lineBuf[SSF_CLI_MAX_CMD_LINE_SIZE];
uint8_t histBuf[SSF_CLI_MAX_CMD_HIST * SSF_CLI_MAX_CMD_LINE_SIZE];

memset(&vtctx, 0, sizeof(vtctx));
SSFVTEdInit(&vtctx, (SSFCStrOut_t)lineBuf, sizeof(lineBuf), myWriteFn);

memset(&clictx, 0, sizeof(clictx));
SSFCLIInit(&clictx, SSF_CLI_MAX_CMDS, SSF_CLI_MAX_CMD_HIST,
           histBuf, sizeof(histBuf), &vtctx);
```

---

<a id="ssfclideinit"></a>

### [↑](#ssfcli--cli-framework) [`void SSFCLIDeInit()`](#functions)

```c
void SSFCLIDeInit(SSFCLIContext_t *context);
```

Tears down a CLI context. All registered commands must have been removed via
[`SSFCLIDeInitCmd()`](#ssfclideinitcmd) before calling this function; if the command list
is not empty, a debug assertion fires. After this call `context->magic` is `0` and the
context may be re-initialized.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | [`SSFCLIContext_t *`](#type-context) | Initialized CLI context. Must not be `NULL`. `context->magic` must equal `SSF_CLI_MAGIC`. Command list must be empty. |

<a id="ex-deinit"></a>

```c
SSFCLIDeInitCmd(&clictx, &myCmd);    /* remove all commands first */
SSFCLIDeInit(&clictx);
/* clictx is now fully zeroed and may be re-used. */
```

---

<a id="ssfcliinitcmd"></a>

### [↑](#ssfcli--cli-framework) [`void SSFCLIInitCmd()`](#functions)

```c
void SSFCLIInitCmd(SSFCLIContext_t *context, SSFCLICmd_t *cmd);
```

Registers a command in the CLI context. The command struct must be zeroed before the first
registration (the embedded `SSFLLItem_t` requires `item.ll == NULL`). The `cmdStr`,
`cmdSyntaxStr`, and `cmdFn` fields must all be non-`NULL`. The command list must not already
be full.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | [`SSFCLIContext_t *`](#type-context) | Initialized CLI context. Must not be `NULL`. |
| `cmd` | in-out | [`SSFCLICmd_t *`](#type-cmd) | Command descriptor. Must not be `NULL`. `cmdStr`, `cmdSyntaxStr`, and `cmdFn` must be set. |

<a id="ex-initcmd"></a>

```c
SSFCLICmd_t helpCmd = { {0}, "help", "help", helpHandler };
SSFCLIInitCmd(&clictx, &helpCmd);
```

---

<a id="ssfclideinitcmd"></a>

### [↑](#ssfcli--cli-framework) [`void SSFCLIDeInitCmd()`](#functions)

```c
void SSFCLIDeInitCmd(SSFCLIContext_t *context, SSFCLICmd_t *cmd);
```

Removes a previously registered command from the CLI context. The command must currently be
in the context's command list; if it is not, a debug assertion fires.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | [`SSFCLIContext_t *`](#type-context) | Initialized CLI context. Must not be `NULL`. |
| `cmd` | in-out | [`SSFCLICmd_t *`](#type-cmd) | Command descriptor previously passed to [`SSFCLIInitCmd()`](#ssfcliinitcmd). Must not be `NULL`. |

<a id="ex-deinitcmd"></a>

```c
SSFCLIDeInitCmd(&clictx, &helpCmd);
/* helpCmd is no longer registered; the CLI will not dispatch to it. */
```

---

<a id="ssfcliprocesschar"></a>

### [↑](#ssfcli--cli-framework) [`void SSFCLIProcessChar()`](#functions)

```c
void SSFCLIProcessChar(SSFCLIContext_t *context, uint8_t inChar);
```

Feeds one input byte to the CLI framework. The byte is first forwarded to the VT100 editor
([`SSFVTEdProcessChar()`](ssfvted.md#ssfvtedprocesschar)). If the editor signals a
high-level event the CLI handles it:

- **Enter** — the command line is saved to history (if enabled and non-empty), then parsed
  via [`SSFArgvInit()`](ssfargv.md#ssfargvinit). On successful parse, the registered command
  list is searched for an exact match; if found, the handler is invoked. If no match, the list
  of registered commands is printed. On parse failure, the command-line grammar is printed (if
  the line was non-empty) or the command list is printed (if the line was empty). In all cases,
  [`SSFVTEdReset()`](ssfvted.md#ssfvtedreset) is called to clear the line and redraw the
  prompt.
- **Ctrl-C** — the line buffer is cleared and the prompt is redrawn via
  [`SSFVTEdReset()`](ssfvted.md#ssfvtedreset).
- **Arrow Up** — recalls the previous command from history (if enabled). Skips empty slots.
  Blanks the line if no history exists.
- **Arrow Down** — recalls the next command from history (if enabled). Skips empty slots.
  Blanks the line if no history exists.

All other input (printable characters, arrow-left/right, backspace, partial escape
sequences) is handled internally by the VT100 editor.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | [`SSFCLIContext_t *`](#type-context) | Initialized CLI context. Must not be `NULL`. |
| `inChar` | in | `uint8_t` | One input byte from the terminal. |

<a id="ex-processchar"></a>

```c
/* Main loop: read one byte at a time from the terminal and feed it to the CLI. */
while (true)
{
    uint8_t ch = myReadByte();
    SSFCLIProcessChar(&clictx, ch);
}
```

---

<a id="ssfcligobjgetoptargstrref"></a>

### [↑](#ssfcli--cli-framework) [`bool SSFCLIGObjGetOptArgStrRef()`](#functions)

```c
bool SSFCLIGObjGetOptArgStrRef(SSFCStrOut_t optStr, SSFGObj_t *gobjOpts,
                               SSFCStrOut_t *strOut, size_t *strLen);
```

Looks up a named option in the parsed opts gobj and returns a pointer to its argument string.
Returns `true` for both valued options (`/opt value`) and value-less options (`//opt`); for
value-less options `*strLen` is `0`. Returns `false` if the option is not present.

The returned `strOut` pointer is valid only while the gobj tree is alive (i.e., within the
command handler callback).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `optStr` | in | `char *` | Null-terminated option name to look up. Must not be `NULL`. |
| `gobjOpts` | in | `SSFGObj_t *` | The opts gobj passed to the command handler. Must not be `NULL`. |
| `strOut` | out | `char **` | Receives a pointer to the option's argument string on success. Must not be `NULL`. |
| `strLen` | out | `size_t *` | Receives the length of the argument string (excluding null terminator) on success. Must not be `NULL`. |

**Returns:** `true` if the option was found and `*strOut` / `*strLen` have been set; `false`
if the option is not present.

<a id="ex-getoptarg"></a>

```c
bool myHandler(SSFGObj_t *gobjCmd, uint32_t numOpts, SSFGObj_t *gobjOpts,
               uint32_t numArgs, SSFGObj_t *gobjArgs,
               SSFVTEdWriteStdoutFn_t writeStdoutFn)
{
    SSFCStrOut_t str;
    size_t strLen;

    /* Look up /dest <path> */
    if (SSFCLIGObjGetOptArgStrRef("dest", gobjOpts, &str, &strLen))
    {
        /* str points to "path", strLen == strlen("path") */
        writeStdoutFn((const uint8_t *)str, strLen);
    }
    return true;
}
```

---

<a id="ssfcligobjgetisopt"></a>

### [↑](#ssfcli--cli-framework) [`bool SSFCLIGObjGetIsOpt()`](#functions)

```c
bool SSFCLIGObjGetIsOpt(SSFCStrOut_t optStr, SSFGObj_t *gobjOpts);
```

Returns `true` if `optStr` is a value-less option (`//opt`) present in the parsed opts gobj.
Returns `false` if the option is missing or if it has an argument value (i.e., it was parsed
as `/opt value` rather than `//opt`).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `optStr` | in | `char *` | Null-terminated option name. Must not be `NULL`. |
| `gobjOpts` | in | `SSFGObj_t *` | The opts gobj passed to the command handler. Must not be `NULL`. |

**Returns:** `true` if the option is present and has no argument value; `false` otherwise.

<a id="ex-getisopt"></a>

```c
/* Check for //verbose flag */
if (SSFCLIGObjGetIsOpt("verbose", gobjOpts))
{
    /* verbose mode is on */
}
```

---

<a id="ssfcligobjgetargstrref"></a>

### [↑](#ssfcli--cli-framework) [`bool SSFCLIGObjGetArgStrRef()`](#functions)

```c
bool SSFCLIGObjGetArgStrRef(size_t argIndex, SSFGObj_t *gobjArgs,
                            SSFCStrOut_t *strOut, size_t *strLen);
```

Returns the positional argument at `argIndex` from the parsed args gobj. Arguments are
zero-indexed in the order they appeared on the command line.

The returned `strOut` pointer is valid only while the gobj tree is alive (i.e., within the
command handler callback).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `argIndex` | in | `size_t` | Zero-based index of the argument. Must be `< SSF_CLI_MAX_ARGS`. |
| `gobjArgs` | in | `SSFGObj_t *` | The args gobj passed to the command handler. Must not be `NULL`. |
| `strOut` | out | `char **` | Receives a pointer to the argument string on success. Must not be `NULL`. |
| `strLen` | out | `size_t *` | Receives the length of the argument string (excluding null terminator) on success. Must not be `NULL`. |

**Returns:** `true` if the argument at `argIndex` exists and `*strOut` / `*strLen` have been
set; `false` if no argument exists at that index.

<a id="ex-getargstr"></a>

```c
/* Read positional arguments: echo arg0 arg1 arg2 ... */
size_t i;
SSFCStrOut_t str;
size_t strLen;

for (i = 0; i < numArgs; i++)
{
    if (SSFCLIGObjGetArgStrRef(i, gobjArgs, &str, &strLen) == false) return false;
    writeStdoutFn((const uint8_t *)str, strLen);
}
```

---

<a id="complete-example"></a>

## [↑](#ssfcli--cli-framework) Complete Example

The following example shows a complete CLI application with three commands: `help`, `echo`,
and `math`. It demonstrates initialization, command registration, the main input loop, and
handler implementations that use the option/argument getter helpers.

```c
#include <string.h>
#include <stdio.h>
#include <conio.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfvted.h"
#include "ssfcli.h"
#include "ssfdec.h"

/* ---- Terminal write callback ------------------------------------------------ */
void writeFn(const uint8_t *data, size_t dataLen)
{
    size_t i;

    SSF_REQUIRE(data != NULL);
    for (i = 0; i < dataLen; i++) { putchar(data[i]); }
}

/* ---- Command handlers ------------------------------------------------------- */

/* help
 *   Prints a help message. Accepts no options or arguments.
 */
bool help(SSFGObj_t *gobjCmd, uint32_t numOpts, SSFGObj_t *gobjOpts,
          uint32_t numArgs, SSFGObj_t *gobjArgs,
          SSFVTEdWriteStdoutFn_t writeStdoutFn)
{
    SSF_UNUSED_PTR(gobjCmd);
    SSF_UNUSED_PTR(gobjOpts);
    SSF_UNUSED_PTR(gobjArgs);

    if ((numOpts > 0) || (numArgs > 0)) return false;

    writeStdoutFn((const uint8_t *)"This is help output.\r\n",
                  strlen("This is help output.\r\n"));
    return true;
}

/* echo <str> [<str>]...
 *   Echoes all positional arguments to the terminal.
 */
bool echo(SSFGObj_t *gobjCmd, uint32_t numOpts, SSFGObj_t *gobjOpts,
          uint32_t numArgs, SSFGObj_t *gobjArgs,
          SSFVTEdWriteStdoutFn_t writeStdoutFn)
{
    SSFCStrOut_t str;
    size_t strLen;
    size_t i;

    SSF_UNUSED_PTR(gobjCmd);
    SSF_UNUSED_PTR(gobjOpts);

    if ((numOpts != 0) || (numArgs == 0)) return false;

    for (i = 0; i < numArgs; i++)
    {
        if (SSFCLIGObjGetArgStrRef(i, gobjArgs, &str, &strLen) == false) return false;
        writeStdoutFn((const uint8_t *)str, strLen);
    }
    return true;
}

/* math (//add | //sub) [/mult <int>] <int> <int>
 *   Adds or subtracts two integers with an optional multiplier.
 */
bool math(SSFGObj_t *gobjCmd, uint32_t numOpts, SSFGObj_t *gobjOpts,
          uint32_t numArgs, SSFGObj_t *gobjArgs,
          SSFVTEdWriteStdoutFn_t writeStdoutFn)
{
    bool hasAddOpt;
    bool hasSubOpt;
    SSFCStrOut_t str;
    char strBuf[SSF_DEC_MAX_STR_SIZE];
    size_t strLen;
    int64_t mult = 1;
    int64_t arg1;
    int64_t arg2;

    SSF_UNUSED_PTR(gobjCmd);

    if ((numOpts < 1) || (numArgs != 2)) return false;

    /* Must have exactly one of //add or //sub */
    hasAddOpt = SSFCLIGObjGetIsOpt("add", gobjOpts);
    hasSubOpt = SSFCLIGObjGetIsOpt("sub", gobjOpts);
    if ((hasAddOpt && hasSubOpt) ||
        ((hasAddOpt == false) && (hasSubOpt == false))) return false;

    /* Optional /mult <int> multiplier */
    if (SSFCLIGObjGetOptArgStrRef("mult", gobjOpts, &str, &strLen))
    {
        if (SSFDecStrToInt(str, &mult) == false) return false;
    }

    /* Two required positional integer arguments */
    if (SSFCLIGObjGetArgStrRef(0, gobjArgs, &str, &strLen) == false) return false;
    if (SSFDecStrToInt(str, &arg1) == false) return false;
    if (SSFCLIGObjGetArgStrRef(1, gobjArgs, &str, &strLen) == false) return false;
    if (SSFDecStrToInt(str, &arg2) == false) return false;

    arg1 = hasAddOpt ? (arg1 + arg2) : (arg1 - arg2);
    arg1 *= mult;
    strLen = SSFDecIntToStr(arg1, strBuf, sizeof(strBuf));
    if (strLen == 0) return false;
    writeStdoutFn((const uint8_t *)strBuf, strLen);
    return true;
}

/* ---- Command table ---------------------------------------------------------- */
SSFCLICmd_t cmds[] =
{
    { {0}, "help", "help", help },
    { {0}, "echo", "echo <str> [<str>]...", echo },
    { {0}, "math", "math (//add | //sub) [/mult <int>] <int> <int>", math },
};

/* ---- Main ------------------------------------------------------------------- */
int main(void)
{
    SSFVTEdContext_t vtctx;
    SSFCLIContext_t clictx;
    char lineBuf[SSF_CLI_MAX_CMD_LINE_SIZE];
    uint8_t histBuf[SSF_CLI_MAX_CMD_HIST * SSF_CLI_MAX_CMD_LINE_SIZE];
    uint8_t inChar;
    size_t i;

    /* Initialize VT100 editor context */
    memset(&vtctx, 0, sizeof(vtctx));
    SSFVTEdInit(&vtctx, (SSFCStrOut_t)lineBuf, sizeof(lineBuf), writeFn);

    /* Initialize CLI context with command history */
    memset(&clictx, 0, sizeof(clictx));
    SSFCLIInit(&clictx, SSF_CLI_MAX_CMDS, SSF_CLI_MAX_CMD_HIST,
               histBuf, sizeof(histBuf), &vtctx);

    /* Register commands */
    for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
    {
        SSFCLIInitCmd(&clictx, &cmds[i]);
    }

    /* Main input loop: read one byte at a time from the terminal */
    while (true)
    {
        inChar = (uint8_t)_getch();
        SSFCLIProcessChar(&clictx, inChar);
    }

    return 0;
}
```

**Example session** (user input shown after the `#` prompt):

```
# help
This is help output.

# echo hello world
helloworld

# math //add 3 4
7

# math //sub /mult 10 100 30
700

# math
math (//add | //sub) [/mult <int>] <int> <int>

# math /add
# <cmd> [(//<opt> | /<opt> <arg> | <arg>)]...

  <cmd> - One or more A-Z, a-z, and 0-9 chars
  <opt> - One or more A-Z, a-z, and 0-9 chars
  <arg> - One or more printable chars, ' ', '\', leading '/' escaped by '\'

  <ENTER>       - Run command
  <BACKSPACE>   - Delete char behind cursor
  <CTRL-C>      - New prompt

  <LEFT  ARROW> - Move cursor left
  <RIGHT ARROW> - Move cursor right
  <UP    ARROW> - Show previous command
  <DOWN  ARROW> - Show next command

# unknown
help - help
echo - echo <str> [<str>]...
math - math (//add | //sub) [/mult <int>] <int> <int>

#
help - help
echo - echo <str> [<str>]...
math - math (//add | //sub) [/mult <int>] <int> <int>
```
