# ssftrace — High Performance Debug Trace

[SSF](../README.md) | [Debug](README.md)

FIFO-backed debug trace buffer with optional thread-safe access.

On embedded targets, trace buffers capture a stream of diagnostic bytes (event codes, timestamps,
counters) in a fixed-size ring buffer. When the buffer is full, the oldest byte is automatically
discarded to make room for the newest. The high-performance macros minimize the time spent with
interrupts disabled or mutexes held.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssftrace--high-performance-debug-trace) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)
- [`ssfbfifo`](../_struct/ssfbfifo.md)

<a id="notes"></a>

## [↑](#ssftrace--high-performance-debug-trace) Notes

- The buffer passed to [`SSFTraceInit()`](#ssftraceinit) must be exactly `traceSize + 1` bytes (same
  requirement as `SSFBFifoInit()`).
- [`SSF_TRACE_PUT_BYTE()`](#ssf-trace-put-byte) automatically discards the oldest byte when the
  trace is full; the caller does not need to check for space before writing.
- [`SSFTraceGetByte()`](#ssftracegetbyte) returns `false` when the trace is empty; the caller does
  not need to check before reading.
- When [`SSF_CONFIG_ENABLE_THREAD_SUPPORT`](#opt-thread-support) is enabled, all API calls acquire
  and release the trace mutex around each access.

<a id="configuration"></a>

## [↑](#ssftrace--high-performance-debug-trace) Configuration

All options are set in `ssfoptions.h` or `ssfport.h`.

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-thread-support"></a>`SSF_CONFIG_ENABLE_THREAD_SUPPORT` | `1` | `1` to enable mutex-protected trace access; `0` for bare-metal single-threaded use |

The underlying FIFO capacity and index sizing are controlled by the
[`ssfbfifo` configuration options](../_struct/ssfbfifo.md#configuration).

<a id="api-summary"></a>

## [↑](#ssftrace--high-performance-debug-trace) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssftrace-t"></a>`SSFTrace_t` | Struct | Trace instance containing an [`SSFBFifo_t`](../_struct/ssfbfifo.md) and an optional mutex. Pass by pointer to all API calls. Do not access fields directly |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-init) | [`void SSFTraceInit(trace, traceSize, buffer, bufferSize)`](#ssftraceinit) | Initialize a trace buffer |
| [e.g.](#ex-deinit) | [`void SSFTraceDeInit(trace)`](#ssftracedeinit) | De-initialize a trace buffer |
| [e.g.](#ex-getbyte) | [`bool SSFTraceGetByte(trace, data)`](#ssftracegetbyte) | Get one byte; returns `false` if empty |
| [e.g.](#ex-putbyte) | [`SSF_TRACE_PUT_BYTE(trace, u8)`](#ssf-trace-put-byte) | Macro: put one byte, discarding oldest if full |
| [e.g.](#ex-putbytes) | [`SSF_TRACE_PUT_BYTES(trace, u8Ptr, len)`](#ssf-trace-put-bytes) | Macro: put multiple bytes |

<a id="function-reference"></a>

## [↑](#ssftrace--high-performance-debug-trace) Function Reference

<a id="ssftraceinit"></a>

### [↑](#functions) [`void SSFTraceInit()`](#functions)

```c
void SSFTraceInit(SSFTrace_t *trace,
                  uint32_t traceSize,
                  uint8_t *buffer,
                  uint32_t bufferSize);
```

Initializes a trace buffer over a caller-supplied byte array. The buffer must be exactly
`traceSize + 1` bytes. When thread support is enabled, a mutex is created for the trace instance.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `trace` | out | [`SSFTrace_t *`](#type-ssftrace-t) | Pointer to the trace structure to initialize. Must not be `NULL`. |
| `traceSize` | in | `uint32_t` | Desired trace capacity in bytes. Must be > 0. Must not exceed `SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE`. |
| `buffer` | in | `uint8_t *` | Caller-supplied backing buffer. Must not be `NULL`. Must be at least `traceSize + 1` bytes. |
| `bufferSize` | in | `uint32_t` | Allocated size of `buffer`. Must be > 0. Must equal `traceSize + 1`. |

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
SSFTrace_t trace;
uint8_t traceBuf[SSF_BFIFO_255 + 1ul];

SSFTraceInit(&trace, SSF_BFIFO_255, traceBuf, sizeof(traceBuf));
/* trace is ready for use with 255 bytes of capacity */
```

---

<a id="ssftracedeinit"></a>

### [↑](#functions) [`void SSFTraceDeInit()`](#functions)

```c
void SSFTraceDeInit(SSFTrace_t *trace);
```

De-initializes a trace buffer. When thread support is enabled, the mutex is destroyed. The trace
structure is zeroed after de-initialization.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `trace` | in-out | [`SSFTrace_t *`](#type-ssftrace-t) | Pointer to the trace to de-initialize. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
SSFTrace_t trace;
uint8_t traceBuf[SSF_BFIFO_255 + 1ul];

SSFTraceInit(&trace, SSF_BFIFO_255, traceBuf, sizeof(traceBuf));
SSFTraceDeInit(&trace);
/* trace is no longer valid */
```

---

<a id="ssf-trace-put-byte"></a>

### [↑](#functions) [`SSF_TRACE_PUT_BYTE()`](#functions)

```c
#define SSF_TRACE_PUT_BYTE(trace, u8)
```

Writes one byte into the trace buffer. If the trace is full, the oldest byte is automatically
purged before the new byte is written. When thread support is enabled, the mutex is acquired and
released around the operation.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `trace` | in-out | [`SSFTrace_t *`](#type-ssftrace-t) | Pointer to an initialized trace. Must not be `NULL`. |
| `u8` | in | `uint8_t` | Byte to write into the trace. |

**Returns:** Nothing.

<a id="ex-putbyte"></a>

**Example:**

```c
SSFTrace_t trace;
uint8_t traceBuf[SSF_BFIFO_255 + 1ul];

SSFTraceInit(&trace, SSF_BFIFO_255, traceBuf, sizeof(traceBuf));

/* No need to check for space; oldest byte is discarded automatically */
SSF_TRACE_PUT_BYTE(&trace, 0xA5u);
SSF_TRACE_PUT_BYTE(&trace, 0x01u);
```

---

<a id="ssftracegetbyte"></a>

### [↑](#functions) [`bool SSFTraceGetByte()`](#functions)

```c
bool SSFTraceGetByte(SSFTrace_t *trace,
                     uint8_t *data);
```

Reads and removes one byte from the trace buffer. Returns `true` if a byte was available and
written to `data`; returns `false` if the trace is empty. When thread support is enabled, the
mutex is acquired and released around the operation.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `trace` | in-out | [`SSFTrace_t *`](#type-ssftrace-t) | Pointer to an initialized trace. Must not be `NULL`. |
| `data` | out | `uint8_t *` | Receives the byte read from the trace. Must not be `NULL`. Unchanged if trace is empty. |

**Returns:** `true` if a byte was available and written to `data`; `false` if the trace was empty.

<a id="ex-getbyte"></a>

**Example:**

```c
SSFTrace_t trace;
uint8_t traceBuf[SSF_BFIFO_255 + 1ul];
uint8_t b;

SSFTraceInit(&trace, SSF_BFIFO_255, traceBuf, sizeof(traceBuf));
SSF_TRACE_PUT_BYTE(&trace, 0xA5u);

if (SSFTraceGetByte(&trace, &b))
{
    /* b == 0xA5 */
}

if (SSFTraceGetByte(&trace, &b) == false)
{
    /* trace was empty; b is unchanged */
}
```

---

<a id="ssf-trace-put-bytes"></a>

### [↑](#functions) [`SSF_TRACE_PUT_BYTES()`](#functions)

```c
#define SSF_TRACE_PUT_BYTES(trace, u8Ptr, len)
```

Writes `len` bytes from `u8Ptr` into the trace buffer by calling
[`SSF_TRACE_PUT_BYTE()`](#ssf-trace-put-byte) for each byte. Oldest bytes are discarded as needed.
Note that `u8Ptr` and `len` are modified in place.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `trace` | in-out | [`SSFTrace_t *`](#type-ssftrace-t) | Pointer to an initialized trace. Must not be `NULL`. |
| `u8Ptr` | in | `uint8_t *` | Pointer to the source bytes. Advanced after each write. |
| `len` | in | `uint32_t` | Number of bytes to write. Decremented to zero after the call. |

**Returns:** Nothing.

<a id="ex-putbytes"></a>

**Example:**

```c
SSFTrace_t trace;
uint8_t traceBuf[SSF_BFIFO_255 + 1ul];
uint8_t *p;
uint32_t n;
const uint8_t msg[] = {0x01u, 0x02u, 0x03u};

SSFTraceInit(&trace, SSF_BFIFO_255, traceBuf, sizeof(traceBuf));

p = (uint8_t *)msg;
n = sizeof(msg);
SSF_TRACE_PUT_BYTES(&trace, p, n);
/* 3 bytes written to trace; p and n are modified */
```
