# ssfbfifo — Byte FIFO

[Back to Data Structures README](README.md) | [Back to ssf README](../README.md)

Lock-free byte FIFO for buffering serial data between interrupt and main-loop contexts.

## Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE` | `255` | Maximum FIFO capacity in bytes; determines the integer width of internal index fields |
| `SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE` | `SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255` | Allowed runtime sizes: `ANY`, `255`, or `POW2_MINUS1` |
| `SSF_BFIFO_MULTI_BYTE_ENABLE` | `1` | `1` to enable multi-byte put/peek/get functions |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFBFifoInit(fifo, fifoSize, buffer, bufferSize)` | Initialize a byte FIFO |
| `SSFBFifoDeInit(fifo)` | De-initialize a byte FIFO |
| `SSFBFifoPutByte(fifo, inByte)` | Put one byte (bounds-checked function) |
| `SSFBFifoPeekByte(fifo, outByte)` | Peek at the next byte without consuming it |
| `SSFBFifoGetByte(fifo, outByte)` | Get (consume) one byte |
| `SSFBFifoIsEmpty(fifo)` | Returns true if FIFO is empty |
| `SSFBFifoIsFull(fifo)` | Returns true if FIFO is full |
| `SSFBFifoSize(fifo)` | Returns the FIFO capacity in bytes |
| `SSFBFifoLen(fifo)` | Returns the number of bytes currently in the FIFO |
| `SSFBFifoUnused(fifo)` | Returns the number of free bytes remaining |
| `SSFBFifoPutBytes(fifo, inBytes, inBytesLen)` | Put multiple bytes (requires `SSF_BFIFO_MULTI_BYTE_ENABLE`) |
| `SSFBFifoPeekBytes(fifo, outBytes, outBytesSize, outBytesLen)` | Peek at multiple bytes (requires `SSF_BFIFO_MULTI_BYTE_ENABLE`) |
| `SSFBFifoGetBytes(fifo, outBytes, outBytesSize, outBytesLen)` | Get multiple bytes (requires `SSF_BFIFO_MULTI_BYTE_ENABLE`) |
| `SSF_BFIFO_IS_EMPTY(fifo)` | Macro: true if FIFO is empty (no bounds check) |
| `SSF_BFIFO_IS_FULL(fifo)` | Macro: true if FIFO is full (no bounds check) |
| `SSF_BFIFO_PUT_BYTE(fifo, b)` | Macro: put one byte (no overflow check, asserts post-put) |
| `SSF_BFIFO_GET_BYTE(fifo, b)` | Macro: get one byte (asserts non-empty, no check) |
| `SSF_BFIFO_255` | Constant: FIFO size value for 255-byte capacity |
| `SSF_BFIFO_65535` | Constant: FIFO size value for 65535-byte capacity |

## Function Reference

### `SSFBFifoInit`

```c
void SSFBFifoInit(SSFBFifo_t *fifo, uint32_t fifoSize, uint8_t *buffer, uint32_t bufferSize);
```

Initializes a byte FIFO over a caller-supplied buffer. The buffer must be exactly `fifoSize + 1`
bytes to allow the full `fifoSize` bytes of capacity (one byte is used internally to distinguish
full from empty).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | out | `SSFBFifo_t *` | Pointer to the FIFO structure to initialize. Must not be `NULL`. |
| `fifoSize` | in | `uint32_t` | Desired FIFO capacity in bytes. Must not exceed `SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE`. Use `SSF_BFIFO_255` (255) or `SSF_BFIFO_65535` (65535) as appropriate. |
| `buffer` | in | `uint8_t *` | Caller-supplied backing buffer. Must not be `NULL`. Must be at least `fifoSize + 1` bytes. |
| `bufferSize` | in | `uint32_t` | Allocated size of `buffer`. Must equal `fifoSize + 1`. |

**Returns:** Nothing.

---

### `SSFBFifoDeInit`

```c
void SSFBFifoDeInit(SSFBFifo_t *fifo);
```

De-initializes a byte FIFO, clearing its internal magic marker.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | in-out | `SSFBFifo_t *` | Pointer to the FIFO to de-initialize. Must not be `NULL`. |

**Returns:** Nothing.

---

### `SSFBFifoPutByte`

```c
void SSFBFifoPutByte(SSFBFifo_t *fifo, uint8_t inByte);
```

Puts one byte into the FIFO. Asserts if the FIFO is full. Call `SSFBFifoIsFull()` or check
`SSF_BFIFO_IS_FULL()` before calling.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | in-out | `SSFBFifo_t *` | Pointer to an initialized FIFO. Must not be `NULL`. Must not be full. |
| `inByte` | in | `uint8_t` | Byte to insert into the FIFO. |

**Returns:** Nothing.

---

### `SSFBFifoPeekByte`

```c
bool SSFBFifoPeekByte(const SSFBFifo_t *fifo, uint8_t *outByte);
```

Reads the next byte from the FIFO without consuming it. The byte remains in the FIFO and will
be returned again on the next peek or get.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | in | `const SSFBFifo_t *` | Pointer to an initialized FIFO. Must not be `NULL`. |
| `outByte` | out | `uint8_t *` | Receives the next byte. Must not be `NULL`. |

**Returns:** `true` if a byte was available and written to `outByte`; `false` if the FIFO is empty.

---

### `SSFBFifoGetByte`

```c
bool SSFBFifoGetByte(SSFBFifo_t *fifo, uint8_t *outByte);
```

Removes and returns the next byte from the FIFO.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | in-out | `SSFBFifo_t *` | Pointer to an initialized FIFO. Must not be `NULL`. |
| `outByte` | out | `uint8_t *` | Receives the consumed byte. Must not be `NULL`. |

**Returns:** `true` if a byte was available and written to `outByte`; `false` if the FIFO is empty.

---

### `SSFBFifoIsEmpty` / `SSFBFifoIsFull`

```c
bool SSFBFifoIsEmpty(const SSFBFifo_t *fifo);
bool SSFBFifoIsFull(const SSFBFifo_t *fifo);
```

Query functions for FIFO state. These perform full argument validation; use the macros
`SSF_BFIFO_IS_EMPTY` and `SSF_BFIFO_IS_FULL` in interrupt-sensitive code paths where overhead
must be minimized.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | in | `const SSFBFifo_t *` | Pointer to an initialized FIFO. Must not be `NULL`. |

**Returns:** `true` / `false` as appropriate.

---

### `SSFBFifoSize` / `SSFBFifoLen` / `SSFBFifoUnused`

```c
ssfbf_uint_t SSFBFifoSize(const SSFBFifo_t *fifo);
ssfbf_uint_t SSFBFifoLen(const SSFBFifo_t *fifo);
ssfbf_uint_t SSFBFifoUnused(const SSFBFifo_t *fifo);
```

Capacity and occupancy queries. `ssfbf_uint_t` is `uint8_t`, `uint16_t`, or `uint32_t` depending
on `SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | in | `const SSFBFifo_t *` | Pointer to an initialized FIFO. Must not be `NULL`. |

**`SSFBFifoSize` returns:** Total FIFO capacity in bytes (the `fifoSize` value passed to `SSFBFifoInit`).

**`SSFBFifoLen` returns:** Number of bytes currently stored in the FIFO.

**`SSFBFifoUnused` returns:** Number of free bytes remaining (`Size - Len`).

---

### `SSFBFifoPutBytes` / `SSFBFifoPeekBytes` / `SSFBFifoGetBytes`

```c
/* Requires SSF_BFIFO_MULTI_BYTE_ENABLE == 1 */
void SSFBFifoPutBytes(SSFBFifo_t *fifo, const uint8_t *inBytes, uint32_t inBytesLen);
bool SSFBFifoPeekBytes(const SSFBFifo_t *fifo, uint8_t *outBytes, uint32_t outBytesSize,
                       uint32_t *outBytesLen);
bool SSFBFifoGetBytes(SSFBFifo_t *fifo, uint8_t *outBytes, uint32_t outBytesSize,
                      uint32_t *outBytesLen);
```

Multi-byte transfer functions. `SSFBFifoPutBytes` asserts if the FIFO does not have enough space.
`SSFBFifoPeekBytes` and `SSFBFifoGetBytes` copy as many bytes as are available, up to
`outBytesSize`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fifo` | in-out | `SSFBFifo_t *` | Pointer to an initialized FIFO. Must not be `NULL`. |
| `inBytes` | in | `const uint8_t *` | Buffer of bytes to put into the FIFO. Must not be `NULL`. |
| `inBytesLen` | in | `uint32_t` | Number of bytes to put. FIFO must have at least this many free bytes. |
| `outBytes` | out | `uint8_t *` | Buffer receiving bytes. Must not be `NULL`. |
| `outBytesSize` | in | `uint32_t` | Allocated size of `outBytes`. |
| `outBytesLen` | out (opt) | `uint32_t *` | If not `NULL`, receives the number of bytes written to `outBytes`. |

**`SSFBFifoPutBytes` returns:** Nothing.

**`SSFBFifoPeekBytes` / `SSFBFifoGetBytes` return:** `true` if at least one byte was transferred; `false` if the FIFO was empty.

---

### High-Performance Macros

```c
#define SSF_BFIFO_IS_EMPTY(fp)        /* true if head == tail */
#define SSF_BFIFO_IS_FULL(fp)         /* true if head + 1 == tail (wrapping) */
#define SSF_BFIFO_PUT_BYTE(fifo, b)   /* write b, advance head, assert not equal to tail */
#define SSF_BFIFO_GET_BYTE(fifo, b)   /* assert non-empty, read b, advance tail */
```

Direct field-access macros for use in interrupt service routines where function call overhead is
unacceptable. Always check `SSF_BFIFO_IS_FULL` before `SSF_BFIFO_PUT_BYTE` and
`SSF_BFIFO_IS_EMPTY` before `SSF_BFIFO_GET_BYTE`; the macros do not perform overflow or underflow
checks.

## Usage

Most embedded systems need to buffer bytes between an interrupt service routine that fills the
FIFO and a main loop that empties it. The low-overhead macros minimize the time spent with
interrupts disabled.

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
uint8_t x = 101;
uint8_t y = 0;

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));

/* Fill the FIFO (e.g., in an ISR) */
if (SSF_BFIFO_IS_FULL(&bf) == false)
{
    SSF_BFIFO_PUT_BYTE(&bf, x);
}

/* Empty the FIFO (e.g., in the main loop) */
if (SSF_BFIFO_IS_EMPTY(&bf) == false)
{
    SSF_BFIFO_GET_BYTE(&bf, y);
    /* y == 101 */
}
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Always check `SSF_BFIFO_IS_FULL` before `SSF_BFIFO_PUT_BYTE` and `SSF_BFIFO_IS_EMPTY` before
  `SSF_BFIFO_GET_BYTE`; the macros do not perform overflow or underflow checks.
- The buffer passed to `SSFBFifoInit()` must be exactly `fifoSize + 1` bytes.
