# ssfbfifo — Byte FIFO

[Back to Data Structures README](README.md) | [Back to ssf README](../README.md)

Lock-free byte FIFO for buffering serial data between interrupt and main-loop contexts.

## Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE` | `255` | Maximum FIFO capacity in bytes |
| `SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE` | `SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255` | Allowed runtime sizes: `ANY`, `255`, or `POW2_MINUS1` |
| `SSF_BFIFO_MULTI_BYTE_ENABLE` | `1` | `1` to enable multi-byte put/get functions |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFBFifoInit(bf, size, buf, bufSize)` | Initialize a byte FIFO |
| `SSFBFifoDeInit(bf)` | De-initialize a byte FIFO |
| `SSF_BFIFO_IS_FULL(bf)` | Macro: true if FIFO is full |
| `SSF_BFIFO_IS_EMPTY(bf)` | Macro: true if FIFO is empty |
| `SSF_BFIFO_PUT_BYTE(bf, b)` | Macro: put one byte (no overflow check) |
| `SSF_BFIFO_GET_BYTE(bf, b)` | Macro: get one byte (no underflow check) |
| `SSFBFifoPutMulti(bf, in, inLen)` | Put multiple bytes (function) |
| `SSFBFifoGetMulti(bf, out, outSize, outLen)` | Get multiple bytes (function) |

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

To safely share the FIFO between an ISR and the main loop, protect access with a critical section
around the check-and-get operation in the main loop:

```c
__interrupt__ void RXInterrupt(void)
{
    if (SSF_BFIFO_IS_FULL(&bf) == false)
        SSF_BFIFO_PUT_BYTE(&bf, RXBUF_REG);
}

while (true)
{
    uint8_t in;

    CRITICAL_SECTION_ENTER();
    if (SSF_BFIFO_IS_EMPTY(&bf) == false)
    {
        SSF_BFIFO_GET_BYTE(&bf, in);
        CRITICAL_SECTION_EXIT();
        ProcessRX(in);
    }
    else
    {
        CRITICAL_SECTION_EXIT();
    }
}
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Always check `SSF_BFIFO_IS_FULL` before `SSF_BFIFO_PUT_BYTE` and `SSF_BFIFO_IS_EMPTY` before
  `SSF_BFIFO_GET_BYTE`; the macros do not perform overflow or underflow checks.
- The buffer passed to `SSFBFifoInit()` must be exactly `size + 1` bytes.
