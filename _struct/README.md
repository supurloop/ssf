# Data Structures

[Back to ssf README](../README.md)

Data structure primitives for embedded systems.

## Byte FIFO Interface

Most embedded systems need to send and receive data. The idea behind the byte FIFO is to provide a buffer for incoming and outgoing bytes on these communication interfaces. For example, you may have an interrupt that fires when a byte of data is received. You don't want to process the byte in the handler so it simply gets put onto the RX byte fifo. When the interrupt completes the main execution thread will check for bytes in the RX byte fifo and process them accordingly.

But wait, the interrupt is a different execution context so we have a race condition that can cause the byte FIFO interface to misbehave. The exact solution will vary between platforms, but the general idea is to disable interrupts in the main execution thread while checking _and_ pulling the byte out of the RX FIFO.

There are MACROs defined in ssfbfifo.h that avoid the overhead of a function call to minimize the amount of time with interrupts off.

```
SSFBFifo_t bf;
uint8_t bf;
uint8_t bfBuffer[SSF_BFIFO_255 + (1UL)];
uint8_t x = 101;
uint8_t y = 0;

/* Initialize the fifo */
SSFBFifoInit(&bf, SSF_BFIFO_255, bfBuffer, sizeof(bfBuffer));

...
/* Fill the fifo using the low overhead MACROs */
if (SSF_BFIFO_IS_FULL(&bf) == false)
{
    SSF_BFIFO_PUT_BYTE(&bf, x);
}

...
/* Empty the fifo using the low overhead MACROs */
if (SSF_BFIFO_IS_EMPTY(&bf) == false)
{
    /* y == 0 */
    SSF_BFIFO_GET_BYTE(&bf, y);
    /* y == 101 */
}
```

Here's how synchronize access to the RX FIFO if it is being filled in an interrupt and emptied in the main loop:

```
__interrupt__ void RXInterrupt(void)
{
    /* Fill the fifo using the low overhead MACROs */
    if (SSF_BFIFO_IS_FULL(&bf) == false)
    {
        SSF_BFIFO_PUT_BYTE(&bf, RXBUF_REG);
    }
}

/* Main loop */
while (true)
{
    uint8_t in;

    /* Empty the fifo using the low overhead MACROs */
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

Notice that the main loop disables interrupts while accessing the FIFO and immediately turns them back on once the FIFO access has been completed and before the main loop processes the RXed byte.

## Linked List Interface

The linked list interface allows the creation of FIFOs and STACKs for more managing more complex data structures.
The key to using the Linked List interface is that when you create the data structure that you want to track place a SSFLLItem_t called item at the top of the struct. For example:

```
#define MYLL_MAX_ITEMS (3u)
typedef struct SSFLLMyData
{
    SSFLLItem_t item;
    uint32_t mydata;
} SSFLLMyData_t;

SSFLL_t myll;
SSFLLMyData_t *item;
uint32_t i;

/* Initialize the linked list with maximum of three items */
SSFLLInit(&myll, MYLL_MAX_ITEMS);

/* Create items and push then onto stack */
for (i = 0; i < MYLL_MAX_ITEMS; i++)
{
    item = (SSFLLMyData_t *) malloc(sizeof(SSFLLMyData_t));
    SSF_ASSERT(item != NULL);
    item->mydata = i + 100;
    SSF_LL_STACK_PUSH(&myll, item);
}

/* Pop items from stack and free them */
if (SSF_LL_STACK_POP(&myll, &item))
{
    /* item->mydata == 102 */
    free(item);
}

if (SSF_LL_STACK_POP(&myll, &item))
{
    /* item->mydata == 101 */
    free(item);
}

if (SSF_LL_STACK_POP(&myll, &item))
{
    /* item->mydata == 100 */
    free(item);
}
```

Besides treating the linked list as a STACK or FIFO there are interfaces to insert an item at a specific point within an existing list.
Before an item is added to a list it cannot be part of another list otherwise an assertion will be triggered.
This prevents the linked list chain from being corrupted which can cause resource leaks and other logic errors to occur.

## Memory Pool Interface

The memory pool interface creates a pool of fixed sized memory blocks that can be efficiently allocated and freed without making dynamic memory calls.

```
#define BLOCK_SIZE (42UL)
#define BLOCKS (10UL)
SSFMPool_t pool;

#define MSG_FRAME_OWNER (0x11u)
MsgFrame_t *buf;

SSFMPoolInit(&pool, BLOCKS, BLOCK_SIZE);

/* If pool not empty then allocate block, use it, and free it. */
if (SSFMPoolIsEmpty(&pool) == false)
{
    buf = (MsgFrame_t *)SSFMPoolAlloc(&pool, sizeof(MsgFrame_t), MSG_FRAME_OWNER);
    /* buf now points to a memory pool block */
    buf->header = 1;
    ...

    /* Free the block */
    buf = free(&pool, buf);
    /* buf == NULL */
}
```

## Debuggable Integrity Checked Heap Interface

Note: This heap implementation is NOT a direct replacement for malloc, realloc, free, etc.

This interface has a more pedantic and consistent API designed to prevent common dynamic memory allocation mistakes that the standard C library happily permits, double frees, overruns, using pointers after being freed, etc...
All operations check the heap's integrity and asserts when corruption is found. When the time comes to read a heap dump, +/- chars help visually mark the block headers, while "dead" headers are zeroed so they never pollute the dump.

Designed to work on 8, 16, 32, and 64-bit machine word sizes, and allows up to 32-bit sized allocations.

```
    #define HEAP_MARK ('H')
    #define APP_MARK ('A')
    #define HEAP_SIZE (64000u)
    #define STR_SIZE (100u)

    uint8_t heap[HEAP_SIZE];
    SSFHeapHandle_t heapHandle;
    uint8_t *ptr = NULL;

    SSFHeapInit(&heapHandle, heap, sizeof(heap), HEAP_MARK, false);

    /* Can we alloc 100 bytes? */
    if (SSFHeapMalloc(heapHandle, &ptr, STR_SIZE, APP_MARK))
    {
        /* Yes, use the bytes for some operation */
        strncpy(ptr, "Hello", STR_SIZE);

        /* Free the memory */
        SSFHeapFree(heapHandle, &ptr, NULL, false);

        /* ptr == NULL */
    }
    SSF_ASSERT(ptr == NULL);

    SSFHeapDeInit(&heapHandle, false);
```
