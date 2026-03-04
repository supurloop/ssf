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
| `SSFBFifoInit(fifo, fifoSize, buffer, bufferSize)` [f()](#ssfbfifoinit) [e.g.](#ex-init) | Initialize a byte FIFO |
| `SSFBFifoDeInit(fifo)` [f()](#ssfbfifodeinit) [e.g.](#ex-deinit) | De-initialize a byte FIFO |
| `SSFBFifoPutByte(fifo, inByte)` [f()](#ssfbfifoputbyte) [e.g.](#ex-putbyte) | Put one byte (bounds-checked function) |
| `SSFBFifoPeekByte(fifo, outByte)` [f()](#ssfbfifoPeekbyte) [e.g.](#ex-peekbyte) | Peek at the next byte without consuming it |
| `SSFBFifoGetByte(fifo, outByte)` [f()](#ssfbfifogetbyte) [e.g.](#ex-getbyte) | Get (consume) one byte |
| `SSFBFifoIsEmpty(fifo)` [f()](#ssfbfifoisempty--ssfbfifoisfull) [e.g.](#ex-isempty) | Returns true if FIFO is empty |
| `SSFBFifoIsFull(fifo)` [f()](#ssfbfifoisempty--ssfbfifoisfull) [e.g.](#ex-isfull) | Returns true if FIFO is full |
| `SSFBFifoSize(fifo)` [f()](#ssfbfifosize--ssfbfifolen--ssfbfifounused) [e.g.](#ex-size) | Returns the FIFO capacity in bytes |
| `SSFBFifoLen(fifo)` [f()](#ssfbfifosize--ssfbfifolen--ssfbfifounused) [e.g.](#ex-len) | Returns the number of bytes currently in the FIFO |
| `SSFBFifoUnused(fifo)` [f()](#ssfbfifosize--ssfbfifolen--ssfbfifounused) [e.g.](#ex-unused) | Returns the number of free bytes remaining |
| `SSFBFifoPutBytes(fifo, inBytes, inBytesLen)` [f()](#ssfbfifoputbytes--ssfbfifopeekbytes--ssfbfifogetbytes) [e.g.](#ex-putbytes) | Put multiple bytes (requires `SSF_BFIFO_MULTI_BYTE_ENABLE`) |
| `SSFBFifoPeekBytes(fifo, outBytes, outBytesSize, outBytesLen)` [f()](#ssfbfifoputbytes--ssfbfifopeekbytes--ssfbfifogetbytes) [e.g.](#ex-peekbytes) | Peek at multiple bytes (requires `SSF_BFIFO_MULTI_BYTE_ENABLE`) |
| `SSFBFifoGetBytes(fifo, outBytes, outBytesSize, outBytesLen)` [f()](#ssfbfifoputbytes--ssfbfifopeekbytes--ssfbfifogetbytes) [e.g.](#ex-getbytes) | Get multiple bytes (requires `SSF_BFIFO_MULTI_BYTE_ENABLE`) |
| `SSF_BFIFO_IS_EMPTY(fifo)` [f()](#high-performance-macros) [e.g.](#ex-macro-isempty) | Macro: true if FIFO is empty (no bounds check) |
| `SSF_BFIFO_IS_FULL(fifo)` [f()](#high-performance-macros) [e.g.](#ex-macro-isfull) | Macro: true if FIFO is full (no bounds check) |
| `SSF_BFIFO_PUT_BYTE(fifo, b)` [f()](#high-performance-macros) [e.g.](#ex-macro-putbyte) | Macro: put one byte (no overflow check, asserts post-put) |
| `SSF_BFIFO_GET_BYTE(fifo, b)` [f()](#high-performance-macros) [e.g.](#ex-macro-getbyte) | Macro: get one byte (asserts non-empty, no check) |
| `SSF_BFIFO_255` [f()](#ssfbfifoinit) [e.g.](#ex-255) | Constant: FIFO size value for 255-byte capacity |
| `SSF_BFIFO_65535` [f()](#ssfbfifoinit) [e.g.](#ex-65535) | Constant: FIFO size value for 65535-byte capacity |

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

<a id="ex-init"></a>

#### SSFBFifoInit

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
/* bf is ready for use with 255 bytes of capacity */
```

<a id="ex-deinit"></a>

#### SSFBFifoDeInit

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoDeInit(&bf);
/* bf is no longer valid */
```

<a id="ex-putbyte"></a>

#### SSFBFifoPutByte

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));

if (SSFBFifoIsFull(&bf) == false)
{
    SSFBFifoPutByte(&bf, 0xA5u);
    /* FIFO now contains one byte */
}
```

<a id="ex-peekbyte"></a>

#### SSFBFifoPeekByte

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
uint8_t b;

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoPutByte(&bf, 0xA5u);

if (SSFBFifoPeekByte(&bf, &b))
{
    /* b == 0xA5, byte is still in FIFO */
}
```

<a id="ex-getbyte"></a>

#### SSFBFifoGetByte

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
uint8_t b;

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoPutByte(&bf, 0xA5u);

if (SSFBFifoGetByte(&bf, &b))
{
    /* b == 0xA5, byte has been removed from FIFO */
}
/* SSFBFifoIsEmpty(&bf) == true */
```

<a id="ex-isempty"></a>

#### SSFBFifoIsEmpty

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoIsEmpty(&bf);   /* returns true */

SSFBFifoPutByte(&bf, 0x01u);
SSFBFifoIsEmpty(&bf);   /* returns false */
```

<a id="ex-isfull"></a>

#### SSFBFifoIsFull

```c
SSFBFifo_t bf;
uint8_t bfBuffer[4 + 1UL];
uint8_t i;

SSFBFifoInit(&bf, 4, bfBuffer, sizeof(bfBuffer));
SSFBFifoIsFull(&bf);   /* returns false */

for (i = 0; i < 4; i++) { SSFBFifoPutByte(&bf, i); }
SSFBFifoIsFull(&bf);   /* returns true */
```

<a id="ex-size"></a>

#### SSFBFifoSize

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoSize(&bf);   /* returns 255 */
```

<a id="ex-len"></a>

#### SSFBFifoLen

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoPutByte(&bf, 0x01u);
SSFBFifoPutByte(&bf, 0x02u);
SSFBFifoLen(&bf);   /* returns 2 */
```

<a id="ex-unused"></a>

#### SSFBFifoUnused

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoPutByte(&bf, 0x01u);
SSFBFifoPutByte(&bf, 0x02u);
SSFBFifoUnused(&bf);   /* returns 253 */
```

<a id="ex-putbytes"></a>

#### SSFBFifoPutBytes

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
const uint8_t data[] = {0x01u, 0x02u, 0x03u};

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));

if (SSFBFifoUnused(&bf) >= sizeof(data))
{
    SSFBFifoPutBytes(&bf, data, sizeof(data));
    /* FIFO now contains 3 bytes */
}
```

<a id="ex-peekbytes"></a>

#### SSFBFifoPeekBytes

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
uint8_t out[8];
uint32_t outLen;
const uint8_t data[] = {0x01u, 0x02u, 0x03u};

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoPutBytes(&bf, data, sizeof(data));

if (SSFBFifoPeekBytes(&bf, out, sizeof(out), &outLen))
{
    /* outLen == 3, out[0..2] == {0x01, 0x02, 0x03}, bytes still in FIFO */
}
```

<a id="ex-getbytes"></a>

#### SSFBFifoGetBytes

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
uint8_t out[8];
uint32_t outLen;
const uint8_t data[] = {0x01u, 0x02u, 0x03u};

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSFBFifoPutBytes(&bf, data, sizeof(data));

if (SSFBFifoGetBytes(&bf, out, sizeof(out), &outLen))
{
    /* outLen == 3, out[0..2] == {0x01, 0x02, 0x03}, bytes removed from FIFO */
}
/* SSFBFifoIsEmpty(&bf) == true */
```

<a id="ex-macro-isempty"></a>

#### SSF_BFIFO_IS_EMPTY

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));

/* Safe to call from an ISR; no argument validation overhead */
if (SSF_BFIFO_IS_EMPTY(&bf) == false)
{
    /* FIFO has data to process */
}
```

<a id="ex-macro-isfull"></a>

#### SSF_BFIFO_IS_FULL

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));

/* Safe to call from an ISR; no argument validation overhead */
if (SSF_BFIFO_IS_FULL(&bf) == false)
{
    /* FIFO has space for at least one more byte */
}
```

<a id="ex-macro-putbyte"></a>

#### SSF_BFIFO_PUT_BYTE

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
uint8_t rxByte = 0x42u;

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));

/* Typical ISR usage: check before putting */
if (SSF_BFIFO_IS_FULL(&bf) == false)
{
    SSF_BFIFO_PUT_BYTE(&bf, rxByte);
}
```

<a id="ex-macro-getbyte"></a>

#### SSF_BFIFO_GET_BYTE

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];
uint8_t rxByte = 0x42u;
uint8_t b;

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
SSF_BFIFO_PUT_BYTE(&bf, rxByte);

/* Typical main-loop usage: check before getting */
if (SSF_BFIFO_IS_EMPTY(&bf) == false)
{
    SSF_BFIFO_GET_BYTE(&bf, b);
    /* b == 0x42 */
}
```

<a id="ex-255"></a>

#### SSF_BFIFO_255

```c
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + 1UL];   /* 256-byte backing buffer */

SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));
/* FIFO capacity is 255 bytes */
```

<a id="ex-65535"></a>

#### SSF_BFIFO_65535

```c
/* Requires SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE >= 65535 */
SSFBFifo_t bf;
uint8_t bfBuffer[SSF_BFIFO_65535 + 1UL];   /* 65536-byte backing buffer */

SSFBFifoInit(&bf, SSF_BFIFO_65535, bfBuffer, sizeof(bfBuffer));
/* FIFO capacity is 65535 bytes */
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Always check `SSF_BFIFO_IS_FULL` before `SSF_BFIFO_PUT_BYTE` and `SSF_BFIFO_IS_EMPTY` before
  `SSF_BFIFO_GET_BYTE`; the macros do not perform overflow or underflow checks.
- The buffer passed to `SSFBFifoInit()` must be exactly `fifoSize + 1` bytes.
