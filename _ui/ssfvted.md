# ssfvted — VT100 Terminal Line Editor

[SSF](../README.md) | [User Interface](README.md)

Single-line editor that consumes ANSI/VT100 input escape sequences and emits ANSI/VT100
output escape sequences to keep a connected terminal display in sync with a caller-supplied
line buffer.

The module is a byte-at-a-time state machine: the caller feeds each received byte (typically
from stdin put into raw mode, a UART driver, or a socket) to
[`SSFVTEdProcessChar()`](#ssfvtedprocesschar), which interprets VT100 arrow/delete/home
sequences, backspace, carriage return, and printable characters; updates the caller's line
buffer; and writes terminal-sync bytes through a caller-supplied write callback. The caller
is notified of high-level events (Arrow Up, Arrow Down, Enter) via a return value plus an
out-parameter that the caller's own code handles (history navigation, line submission, etc.).

The editor is suitable for a small-system shell, bootloader command prompt, or any embedded
interactive UI where the user is at a VT100-compatible terminal (xterm, PuTTY, screen,
Windows Terminal, etc.) and the firmware wants line-editing behavior without pulling in a
full `readline`-style library.

[Dependencies](#dependencies) | [Input Sequences](#input-sequences) | [Output Sequences](#output-sequences) | [State Machine](#state-machine) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssf.h`](../ssf.h)
- [`ssfassert.h`](../ssfassert.h)

No heap allocation. No other SSF module dependencies. The caller provides both the line
buffer and the `writeStdoutFn` callback, so the module has no OS or I/O coupling.

<a id="input-sequences"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) Input Sequences

The decoder recognizes the following byte sequences. Bytes are passed one at a time to
[`SSFVTEdProcessChar()`](#ssfvtedprocesschar); the state machine accumulates them across
calls until a full sequence is identified or abandoned.

| Key | Input bytes | Effect |
|-----|-------------|--------|
| Arrow Up | `ESC [ A` (3 bytes) | Returns `SSF_VTED_ESC_CODE_UP` to the caller |
| Arrow Down | `ESC [ B` (3 bytes) | Returns `SSF_VTED_ESC_CODE_DOWN` to the caller |
| Arrow Right | `ESC [ C` (3 bytes) | Moves the cursor right within the line; auto-adds a trailing space when past end-of-line |
| Arrow Left | `ESC [ D` (3 bytes) | Moves the cursor left within the line; cleans up an auto-added trailing space when at end-of-line |
| Delete | `ESC [ 3 ~` (4 bytes) | Deletes the character at the cursor |
| Arrow Up (xterm app mode) | `ESC O A` (3 bytes) | Same as `ESC [ A` |
| Arrow Down (xterm app mode) | `ESC O B` (3 bytes) | Same as `ESC [ B` |
| Arrow Right (xterm app mode) | `ESC O C` (3 bytes) | Same as `ESC [ C` |
| Arrow Left (xterm app mode) | `ESC O D` (3 bytes) | Same as `ESC [ D` |
| Backspace (traditional) | `\b` (`0x08`) | Deletes the char before the cursor |
| Backspace (modern terminals) | `\x7F` (DEL char) | Same as `\b` |
| Enter / Return | `\r` (`0x0D`) | Returns `SSF_VTED_ESC_CODE_ENTER` to the caller |
| Printable | `0x20` – `0x7E` (`isprint`) | Inserted at the cursor position |

Any other byte in the `IDLE` state is silently ignored. Any byte that breaks a partial
escape sequence causes the partial sequence to be abandoned (the decoder returns to `IDLE`
and the offending byte is consumed without further effect). A new `ESC` (`0x1B`) received
at any point restarts the sequence decoder.

<a id="output-sequences"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) Output Sequences

The handlers emit the following sequences via the caller's `writeStdoutFn` to keep the
terminal display in sync with the line buffer:

| Operation | Output bytes | Meaning |
|-----------|--------------|---------|
| Cursor back | `\x1b[D` | CUB — Cursor Backward |
| Cursor forward | `\x1b[C` | CUF — Cursor Forward |
| Delete character | `\x1b[P` | DCH — Delete Character (used by both Delete and Backspace) |
| Insert character | `\x1b[@` | ICH — Insert Character (followed by the typed byte) |
| Backspace | `\b` + `\x1b[P` | Move cursor back, then DCH |
| Prompt | [`SSF_VTED_PROMPT_STR`](#cfg-prompt) | Configured prompt (default `"\r\n# "`) — emitted by both `SSFVTEdInit()` and `SSFVTEdReset()` |

All output is ANSI/VT100 standard and works on xterm, PuTTY, Windows Terminal, Linux/macOS
console, and most other modern terminals.

<a id="state-machine"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) State Machine

The input decoder is a small state machine with five states tracked in
`context->escState`:

```
IDLE          ── printable ──────▶ Insert at cursor            (stay IDLE)
IDLE          ── \b / \x7F ──────▶ Delete char before cursor   (stay IDLE)
IDLE          ── \r ─────────────▶ Return ENTER                (stay IDLE)
IDLE          ── \x1b ───────────▶ ESC
IDLE          ── other ──────────▶ ignore                      (stay IDLE)

ESC           ── '[' ────────────▶ CSI
ESC           ── 'O' ────────────▶ SS3
ESC           ── \x1b ───────────▶ ESC                         (restart)
ESC           ── other ──────────▶ abandon                     (→ IDLE)

CSI           ── 'A' ────────────▶ Return UP                   (→ IDLE)
CSI           ── 'B' ────────────▶ Return DOWN                 (→ IDLE)
CSI           ── 'C' ────────────▶ Cursor right                (→ IDLE)
CSI           ── 'D' ────────────▶ Cursor left                 (→ IDLE)
CSI           ── '3' ────────────▶ CSI_3
CSI           ── \x1b ───────────▶ ESC                         (restart)
CSI           ── other ──────────▶ abandon                     (→ IDLE)

CSI_3         ── '~' ────────────▶ Delete char at cursor       (→ IDLE)
CSI_3         ── \x1b ───────────▶ ESC                         (restart)
CSI_3         ── other ──────────▶ abandon                     (→ IDLE)

SS3           ── 'A' ────────────▶ Return UP                   (→ IDLE)
SS3           ── 'B' ────────────▶ Return DOWN                 (→ IDLE)
SS3           ── 'C' ────────────▶ Cursor right                (→ IDLE)
SS3           ── 'D' ────────────▶ Cursor left                 (→ IDLE)
SS3           ── \x1b ───────────▶ ESC                         (restart)
SS3           ── other ──────────▶ abandon                     (→ IDLE)
```

Every state has a defined transition for every possible input byte, and every non-`IDLE`
state has a path back to `IDLE`. There is no way to get the decoder stuck.

<a id="notes"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) Notes

- **Raw stdin required**: on POSIX systems the caller must put stdin into raw mode
  (`termios`, clearing `ICANON` and `ECHO`) so that escape sequences are delivered byte by
  byte rather than being buffered and cooked by the terminal driver. On Windows, use
  `ReadConsoleInputW` or put stdin into VT100 mode via `ENABLE_VIRTUAL_TERMINAL_INPUT`.

- **Caller-owned line buffer**: the caller supplies a `char *lineBuf` of size `lineSize`
  bytes to [`SSFVTEdInit()`](#ssfvtedinit). The module never allocates heap memory; all
  editing is done in the caller's buffer. `lineSize` is the total allocated size; the
  effective maximum line length is `lineSize - 1` (one byte reserved for the null
  terminator).

- **Null-terminated at all times**: the line buffer is always null-terminated while
  `context->magic` is valid. `context->lineLen` tracks `strlen(context->line)` after every
  edit. `context->line[lineLen] == 0` and `context->line[lineSize - 1] == 0` are module
  invariants.

- **Cursor invariant**: `0 ≤ context->cursor ≤ context->lineLen ≤ context->lineSize - 1`
  always holds. Insertions, backspace, delete, and arrow movement all preserve this.

- **Arrow-right auto-space**: if the user presses Arrow Right at or past end-of-line (with
  `cursor == lineLen` and `lineLen < lineSize - 1`), the module writes a space at the
  cursor position and advances both `cursor` and `lineLen`. This keeps the buffer-position
  indexing aligned with the terminal-column indexing so that a subsequent insertion at the
  new position works without special case.

- **Arrow-left trailing-space cleanup**: conversely, pressing Arrow Left at end-of-line
  (`cursor == lineLen`) when the char just before the cursor is a space will clear that
  space, decrementing both `cursor` and `lineLen`. This lets a user "undo" a stray
  Arrow Right press.

- **Dual backspace**: both `\b` (`0x08`, traditional terminals) and `\x7F` (DEL character,
  modern Linux/macOS terminals) are treated as backspace. The terminal receives `\b\x1b[P`
  (move cursor back + DCH) regardless of which was typed.

- **Prompt protection**: [`SSFVTEdInit()`](#ssfvtedinit) and
  [`SSFVTEdReset()`](#ssfvtedreset) both emit the configured prompt
  ([`SSF_VTED_PROMPT_STR`](#cfg-prompt)) to the terminal. The prompt is *not* added to the
  line buffer; `cursor` and `lineLen` both start at `0`. Because `LEFT` and `Backspace`
  guard on `cursor > 0` and `Insert`/`DCH`/`ICH` only operate at or past the cursor, the
  user cannot backspace into, overwrite, or navigate into the prompt.

- **Enter returns to caller**: pressing Enter does *not* emit a newline to the terminal and
  does *not* clear the buffer. Instead it returns `SSF_VTED_ESC_CODE_ENTER` to the caller.
  The caller is expected to read the completed line out of `context->line`, process it, and
  then call [`SSFVTEdReset()`](#ssfvtedreset) to print the next prompt.

- **Single-threaded / single-context**: the module holds no internal state — everything is
  in the caller's `SSFVTEdContext_t`. Multiple independent contexts can exist concurrently
  as long as each is accessed from only one thread at a time.

<a id="configuration"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) Configuration

The following options are defined in [`ssfoptions.h`](../ssfoptions.h):

| Option | Default | Description |
|--------|---------|-------------|
| <a id="cfg-prompt"></a>`SSF_VTED_PROMPT_STR` | `"\r\n# "` | Null-terminated string literal used as the prompt. Emitted by [`SSFVTEdInit()`](#ssfvtedinit) and [`SSFVTEdReset()`](#ssfvtedreset). The leading `\r\n` ensures the prompt appears on a fresh line. Length is derived at compile time via `sizeof - 1`. |

And in [`ssfport.h`](../ssfport.h):

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_CONFIG_VTED_UNIT_TEST` | `1` | Set to `1` to compile the [`SSFVTEdUnitTest()`](#ssfvtedunittest) entry point and enable assertion-test coverage. |

<a id="api-summary"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-esccode"></a>`SSFVTEdEscCode_t` | Enum | High-level event code returned via the `escOut` parameter of [`SSFVTEdProcessChar()`](#ssfvtedprocesschar) |
| `SSF_VTED_ESC_CODE_UP` | Enum value | [`SSFVTEdEscCode_t`](#type-esccode) — Arrow Up was pressed |
| `SSF_VTED_ESC_CODE_DOWN` | Enum value | [`SSFVTEdEscCode_t`](#type-esccode) — Arrow Down was pressed |
| `SSF_VTED_ESC_CODE_ENTER` | Enum value | [`SSFVTEdEscCode_t`](#type-esccode) — Enter (`\r`) was pressed; the line in `context->line` is ready to be consumed |
| <a id="type-escstate"></a>`SSFVTEdEscState_t` | Enum | Internal state of the VT100 input decoder; stored in `context->escState` |
| `SSF_VTED_ESC_STATE_IDLE` | Enum value | [`SSFVTEdEscState_t`](#type-escstate) — no escape sequence in progress |
| `SSF_VTED_ESC_STATE_ESC` | Enum value | [`SSFVTEdEscState_t`](#type-escstate) — saw `ESC`, awaiting `[` or `O` |
| `SSF_VTED_ESC_STATE_CSI` | Enum value | [`SSFVTEdEscState_t`](#type-escstate) — saw `ESC [`, awaiting final byte or parameter digit |
| `SSF_VTED_ESC_STATE_CSI_3` | Enum value | [`SSFVTEdEscState_t`](#type-escstate) — saw `ESC [ 3`, awaiting `~` |
| `SSF_VTED_ESC_STATE_SS3` | Enum value | [`SSFVTEdEscState_t`](#type-escstate) — saw `ESC O`, awaiting final byte |
| <a id="type-writefn"></a>`SSFVTEdWriteStdoutFn_t` | Typedef | `void (*)(const uint8_t *data, uint16_t dataLen)` — caller-supplied write callback; invoked by the module to emit VT100 output bytes |
| <a id="type-context"></a>`SSFVTEdContext_t` | Struct | Per-editor state; contains the line buffer pointer, cursor/length, escape decoder state, and the write callback |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFVTEdInit(context, lineBuf, lineSize, writeStdoutFn)`](#ssfvtedinit) | Initialize a line editor context and emit the initial prompt |
| [e.g.](#ex-process) | [`bool SSFVTEdProcessChar(context, inChar, escOut)`](#ssfvtedprocesschar) | Process one input byte; may return a high-level event code |
| [e.g.](#ex-reset) | [`void SSFVTEdReset(context)`](#ssfvtedreset) | Clear the line buffer and emit the prompt again |
| [e.g.](#ex-deinit) | [`void SSFVTEdDeInit(context)`](#ssfvteddeinit) | Tear down a line editor context |

<a id="function-reference"></a>

## [↑](#ssfvted--vt100-terminal-line-editor) Function Reference

<a id="ssfvtedinit"></a>

### [↑](#ssfvted--vt100-terminal-line-editor) [`void SSFVTEdInit()`](#functions)

```c
void SSFVTEdInit(SSFVTEdContext_t *context, SSFCStrOut_t lineBuf, size_t lineSize,
                 SSFVTEdWriteStdoutFn_t writeStdoutFn);
```

Initializes `context` and binds it to the caller-supplied `lineBuf` and `writeStdoutFn`.
Clears the line buffer, resets the cursor and decoder state, and immediately emits the
configured prompt via `writeStdoutFn`. The context must be zeroed by the caller before the
first call (stack-allocated contexts require an explicit `memset`; static-allocated
contexts are auto-zeroed).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFVTEdContext_t *` | Caller-supplied context storage. Must not be `NULL`. `context->magic` must be `0` on entry. |
| `lineBuf` | in-out | `char *` | Caller-supplied line buffer. Must not be `NULL`. The module zeroes it immediately. |
| `lineSize` | in | `size_t` | Total allocated size of `lineBuf` in bytes. Must be `> 0`. The maximum user-visible line length is `lineSize - 1`. |
| `writeStdoutFn` | in | [`SSFVTEdWriteStdoutFn_t`](#type-writefn) | Callback the module uses to emit terminal-sync bytes. Must not be `NULL`. Must accept a read-only byte pointer and a 16-bit length. |

<a id="ex-init"></a>

```c
SSFVTEdContext_t ctx;
char lineBuf[128];

memset(&ctx, 0, sizeof(ctx));
SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), myWriteFn);
/* Terminal now shows "\r\n# " with cursor just after the space. */
```

---

<a id="ssfvtedprocesschar"></a>

### [↑](#ssfvted--vt100-terminal-line-editor) [`bool SSFVTEdProcessChar()`](#functions)

```c
bool SSFVTEdProcessChar(SSFVTEdContext_t *context, uint8_t inChar, SSFVTEdEscCode_t *escOut);
```

Feeds one input byte to the editor. The module updates `context->line` / `cursor` /
`lineLen` / `escState` as appropriate and may call `writeStdoutFn` to emit terminal-sync
bytes. If the byte completes a high-level event (Arrow Up, Arrow Down, or Enter) the
function returns `true` and writes the event code to `*escOut`; otherwise it returns
`false` and `*escOut` is left unchanged.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFVTEdContext_t *` | Initialized editor context. Must not be `NULL`. `context->magic` must equal `SSF_VTED_MAGIC`. |
| `inChar` | in | `uint8_t` | One input byte. May be a printable character, a backspace (`\b` or `\x7F`), a carriage return (`\r`), an ESC (`\x1B`), or any byte that is part of a VT100 escape sequence. |
| `escOut` | out | [`SSFVTEdEscCode_t *`](#type-esccode) | Receives the event code when the function returns `true`. Must not be `NULL`. Not touched when the function returns `false`. |

**Returns:** `true` if `inChar` completed a high-level event (Arrow Up, Arrow Down, or
Enter) and `*escOut` is valid; `false` otherwise. A `false` return includes printable
insertion, backspace, delete, arrow-left/right, a partial escape sequence that hasn't
completed yet, and silently-ignored bytes.

<a id="ex-process"></a>

```c
SSFVTEdContext_t ctx;
char lineBuf[128];
SSFVTEdEscCode_t escCode;
uint8_t in;

memset(&ctx, 0, sizeof(ctx));
SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), myWriteFn);

for (;;)
{
    /* Read one byte from the terminal (raw mode assumed) */
    in = myReadByte();

    if (SSFVTEdProcessChar(&ctx, in, &escCode))
    {
        switch (escCode)
        {
        case SSF_VTED_ESC_CODE_ENTER:
            /* ctx.line contains the completed line. Dispatch it, then rearm. */
            myExecuteCommand(ctx.line);
            SSFVTEdReset(&ctx);
            break;
        case SSF_VTED_ESC_CODE_UP:
            /* Caller-owned history navigation: write a new line into ctx.line
               via SSFVTEdReset + inject history chars via SSFVTEdProcessChar. */
            break;
        case SSF_VTED_ESC_CODE_DOWN:
            /* ditto */
            break;
        default:
            break;
        }
    }
}
```

---

<a id="ssfvtedreset"></a>

### [↑](#ssfvted--vt100-terminal-line-editor) [`void SSFVTEdReset()`](#functions)

```c
void SSFVTEdReset(SSFVTEdContext_t *context);
```

Clears `context->line`, resets `cursor` and `lineLen` to `0`, returns the escape decoder
to `SSF_VTED_ESC_STATE_IDLE`, and emits the configured prompt via `writeStdoutFn`.
The `magic`, `line`, `lineSize`, and `writeStdoutFn` fields of `context` are preserved, so
the context remains usable for further input processing after the call.

The typical call site is immediately after handling an `SSF_VTED_ESC_CODE_ENTER` event —
the caller reads the completed line, executes it, prints any output, then calls
`SSFVTEdReset()` to clear the buffer and draw the next prompt.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFVTEdContext_t *` | Initialized editor context. Must not be `NULL`. `context->magic` must equal `SSF_VTED_MAGIC`. |

<a id="ex-reset"></a>

```c
if (SSFVTEdProcessChar(&ctx, in, &escCode) && escCode == SSF_VTED_ESC_CODE_ENTER)
{
    /* Execute the line the user typed */
    myExecuteCommand(ctx.line);
    /* Clear buffer and redraw prompt for the next input */
    SSFVTEdReset(&ctx);
}
```

---

<a id="ssfvteddeinit"></a>

### [↑](#ssfvted--vt100-terminal-line-editor) [`void SSFVTEdDeInit()`](#functions)

```c
void SSFVTEdDeInit(SSFVTEdContext_t *context);
```

Zeros the entire `SSFVTEdContext_t` struct, including `magic`. The caller's `lineBuf` is
not touched (the module does not own it). After this call, the context may be re-used with
a new [`SSFVTEdInit()`](#ssfvtedinit) call — the zeroed `magic` satisfies Init's
`magic == 0` precondition.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFVTEdContext_t *` | Initialized editor context. Must not be `NULL`. `context->magic` must equal `SSF_VTED_MAGIC`. |

<a id="ex-deinit"></a>

```c
SSFVTEdDeInit(&ctx);
/* ctx is now fully zeroed and may be re-used with SSFVTEdInit(). */
```
