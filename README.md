# ssf

Small System Framework

A collection of production ready software for small memory embedded systems.

## Overview

This code framework was designed:

1. To run on embedded systems that have constrained program and data memories.
2. To minimize the potential for common coding errors and detect and report runtime errors.

The framework implements a number of common embedded system functions:

1. An efficient byte FIFO interface.
2. A linked list interface, supporting FIFO and STACK behaviors.
3. A memory pool interface.
4. A Base64 encoder/decoder interface.
5. A Binary to Hex ASCII encoder/decoder interface.
6. A JSON parser/generator interface.
7. A 16-bit Fletcher checksum interface.
8. A finite state machine framework.
9. A Reed-Solomon FEC encoder/decoder interface.
10. A 16-bit XMODEM/CCITT-16 CRC interface.
11. A 32-bit CCITT-32 CRC interface.
12. A SHA-2 hash interface.
13. A TLV encoder/decoder interface.
14. An AES block encryption interface.
15. An AES-GCM authenticated encryption interface.
16. A version controlled interface for reliably storing configuration to NV storage.
17. A cryptograpically secure capable pseudo random number generator (PRNG).
18. A INI parser/generator interface.
19. A UBJSON (Universal Binary JSON) parser/generator interface.
20. A Unix Time RTC interface.
21. A Unix Date/Time interface.
22. An ISO8601 Date/Time interface.
23. An integer to decimal string interface.
24. An safe C string interface.
25. A debuggable, integrity checked heap interface.

To give you an idea of the framework size here are some program memory estimates for each component compiled on an MSP430 with Level 3 optimization:
Byte FIFO, linked list, memory pool, Base64, Hex ASCII are each about 1000 bytes.
JSON parser/generator is about 7300-8800 bytes depending on configuration.
Finite state machine is about 2000 bytes.
Fletcher checksum is about 88 bytes.

Little RAM is used internally by the framework, most RAM usage occurs outside the framwork when declaring or initializing different objects.

Microprocessors with >4KB RAM and >32KB program memory should easily be able to utilize this framework.
And, as noted above, portions of the framework will work on much smaller micros.

## Porting

This framework has been successfully ported and unit tested on the following platforms: Windows Visual Studio 32/64-bit, Linux 32/64-bit (GCC), MAC OS X, PIC32 (XC32), PIC24 (XC16), and MSP430 (TI 15.12.3.LTS). You should only need to change ssfport.c and ssfport.h to implement a successful port.

The code will compile cleanly and not report any analyzer(Lint) warnings under Windows in Visual Studio using the ssf.sln solution file.7
The code will compile cleanly under Linux. ./build-linux.sh will create the ssf executable in the source directory.
The code will compile cleanly under OS X. ./build-macos.sh will create the ssf executable in the source directory.

The Windows, Linux, and Mac OS builds are setup to output all compiler warnings.

For other platforms there are only a few essential tasks that must be completed:

-   Copy all the SSF C and H source files, except main.c, into your project sources and add them to your build environment.
-   In ssfport.h make sure SSF_TICKS_PER_SEC is set to the number of system ticks per second on your platform.
-   Map SSFPortGetTick64() to an existing function that returns the number of system ticks since boot, or
    implement SSFPortGetTick64() in ssfport.c if a simple mapping is not possible.
-   In ssfport.h make sure to follow the instructions for the byte order macros.
-   Run the unit tests.

Only a few modules in the framework use system ticks, so you can stub out SSFPortGetTick64() if it is not needed.
When the finite state machine framework runs in a multi-threaded environment some OS synchronization primitives must be implemented.

### Heap and Stack Memory

Only the memory pool and finite state machine use dynamic memory, aka heap. The memory pool only does so when a pool is created. The finite state machine only uses malloc when an event has data whose size is bigger than the sizeof a pointer.

The framework is fairly stack friendly, although the JSON/UBJSON parsers will recursively call functions for nested JSON objects and arrays. SSF\_[UB]JSON_CONFIG_MAX_IN_DEPTH in ssfport.h can be used to control the maximum depth the parser will recurse to prevent the stack from blowing up due to bad inputs. If the unit test for the JSON/UBJSON interface is failing weirdly then increase your system stack.

The most important step is to run the unit tests for the interfaces you intend to use on your platform. This will detect porting problems very quickly and avoid many future debugging headaches.

### SSFPortAssert()

For a production ready embedded system you should probably do something additional with SSFPortAssert() besides nothing.

First, I recommend that it should somehow safely record the file and line number where the assertion occurred so that it can be reported on the next boot.

Second, the system should be automatically reset rather than sitting forever in a loop.

Third, the system should have a safe boot mode that kicks in if the system reboots quickly many times in a row.

## Design Principles

### No Dependencies 

When you use the SSF, you just need the SSF and not a single other external dependency except for a few C standard library calls.

### No Error Codes

Too often API error codes are ignored in part or in whole, or improperly handled due to overloaded encodings (ex. <0=error, 0=ignored, >0=length)

Either a SSF API call will always succeed (void return), or it will return a boolean: true on success and false on failure.
That's it. Any function outputs are handled via the parameter list.
This makes application error handling simple to implement, and much less prone to errors.

### Militant Buffer and C String Overrun Protection

All SSF interfaces require the total allocated size of buffers and C strings to be passed as arguments.
The SSF API will never write beyond the end of a buffer or C string.
All C strings returned by a successful SSF API call are guaranteed to be NULL terminated.

Safe C string SSF API to replace crash inducing strlen(), strcat(), strcpy(), and strcmp(), and other "safe" C library calls that don't always ensure NULL termination like strncpy().

### Design by Contract

To help ensure correctness the framework uses Design by Contract techniques to immediately catch common errors that tend to creep into systems and cause problems at the worst possible times.

Design by Contract uses assertions, conditional code that ensures that the state of the system at runtime is operating within the allowable tolerances. The assertion interface uses several macros that hint at the assertions purpose. SSF_REQUIRE() is used to check function input parameters. SSF_ENSURE() is used to check the return result of a function. SSF_ASSERT() is used to check any other system state. SSF_ERROR() always forces an assertion.

The framework goes to great lengths to minimize and detect the potential for buffer overruns and prevent problems with unterminated C strings.

The framework will also detect common errors like using interfaces before they have been properly initialized.

### RTOS Support

You may have heard the terms bare-metal or superloop to describe single thread of execution systems that lack an OS.
This library is designed to primarily* run in a single thread of execution which avoids much of the overhead and pitfalls associated with RTOSes.
(*See Byte FIFO Interface for an explanation of how to deal with interrupts.)

Very few small memory systems need to have a threaded/tasked/real-time capable OS.
RTOSes introduce significant complexity, and in particular a dizzying amount of opportunity for introducing subtle race conditions (BUGS) that are easy to create and difficult to find and fix.

That said this framework can run perfectly fine with an RTOS, Windows, or Linux, so long as some precautions are taken.

Excepting the finite state machine framework, RTC interface, and heap, all interfaces are reentrant.
This means that calls into those interfaces from different execution contexts will not interfere with each other.

For example, you can have linked list object A in task 1 and linked list object B in task 2 and they will be managed independently and correctly, so long as they are only accessed from the context of their respective task.

To properly run the finite state machine framework in a multi-threaded system SSF_SM_CONFIG_ENABLE_THREAD_SUPPORT must be enabled and synchronization macros must be implemented. For more details see below.

### Deinitialization

This library has added support to deinitialize interfaces that have initialization functions. Primarily deinitialization was added to allow the library to better integrate with unit test frameworks.

## Interfaces

### Byte FIFO Interface

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

### Linked List Interface

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

### Memory Pool Interface

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

### Base64 Encoder/Decoder Interface

This interface allows you to encode a binary data stream into a Base64 string, or do the reverse.

```
char encodedStr[16];
char decodedBin[16];
uint8_t binOut[2];
size_t binLen;

/* Encode arbitrary binary data */
if (SSFBase64Encode("a", 1, encodedStr, sizeof(encodedStr), NULL))
{
    /* Encode successful */
    printf("%s", encodedStr);
    /* output is "YQ==" */
}

/* Decode Base64 string into binary data */
if (SSFBase64Decode(encodedStr, strlen(encodedStr), decodedBin, sizeof(decodedBin), &binLen))
{
    /* Decode successful */
    /* binLen == 1 */
    /* decodedBin[0] == 'a' */
}
```

### Binary to Hex ASCII Encoder/Decoder Interface

This interface allows you to encode a binary data stream into an ASCII hexadecimal string, or do the reverse.

```
uint8_t binOut[2];
char strOut[5];
size_t binLen;

if (SSFHexBytesToBin("A1F5", 4, binOut, sizeof(binOut), &binLen, false))
{
    /* Encode successful */
    /* binLen == 2 */
    /* binOut[0] = '\xA1' */
    /* binOut[1] = '\xF5' */
}

if (SSFHexBinToBytes(binOut, binLen, strOut, sizeof(strOut), NULL, false, SSF_HEX_CASE_LOWER))
{
  /* Decode in reverse successful */
  printf("%s", strOut);
  /* prints "a1f5" */
}
```

Another convienience feature is the API allows reversal of the byte ordering either for encoding or decoding.

### JSON Parser/Generator Interface

Having searched for and used many JSON parser/generators on small embedded platforms I never found exactly the right mix of attributes. The mjson project came the closest on the parser side, but relied on varargs for the generator, which provides a potential breeding ground for bugs.

Like mjson (a SAX-like parser) this parser operates on the JSON string in place and only consumes modest stack in proportion to the maximum nesting depth. Since the JSON string is parsed from the start each time a data element is accessed it is computationally inefficient; that's ok since most embedded systems are RAM constrained not performance constrained.

On the generator side it does away with varargs and opts for an interface that can be verified at compilation time to be called correctly.

Here are some simple parser examples:

```
char json1Str[] = "{\"name\":\"value\"}";
char json2Str[] = "{\"obj\":{\"name\":\"value\",\"array\":[1,2,3]}}";
char *path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
char strOut[32];
size_t idx;

/* Must zero out path variable before use */
memset(path, 0, sizeof(path));

/* Get the value of a top level element */
path[0] = "name";
if (SSFJsonGetString(json1Str, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s", strOut);
    /* Prints "value" excluding double quotes */
}

/* Get the value of a nested element */
path[0] = "obj";
path[1] = "name";
if (SSFJsonGetString(json2Str, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s", strOut);
    /* Prints "value" excluding double quotes */
}

path[0] = "obj";
path[1] = "array";
path[2] = (char *)&idx;
/* Iterate over a nested array */
for (idx = 0;;idx++)
{
    long si;

    if (SSFJsonGetLong(json2Str, (SSFCStrIn_t *)path, &si))
    {
        if (i != 0) print(", ");
        printf("%ld", si);
    }
    else break;
}
/* Prints "1, 2, 3" */
```

Here is a simple generation example:

```
bool printFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;

    if (!SSFJsonPrintLabel(js, size, start, &start, "label1", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "value1", false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "label2", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "value2", false)) return false;

    *end = start;
    return true;
}
...

char jsonStr[128];
size_t end;

/* JSON is contained within an object {}, so to create a JSON string call SSFJsonPrintObject() */
if (SSFJsonPrintObject(jsonStr, sizeof(jsonStr), 0, &end, printFn, NULL, false))
{
    /* jsonStr == "{\"name1\":\"value1\",\"name2\":\"value2\"}" */
}
```

Object and array nesting is achieved by calling SSFJsonPrintObject() or SSFJsonPrintArray() from within a printer function.

There is also an interface, SSFJsonUpdate(), for updating a JSON object with a new value or element.

### 16-bit Fletcher Checksum Interface

Every embedded system needs to use a checksum somewhere, somehow. The 16-bit Fletcher checksum has many of the error detecting properties of a 16-bit CRC, but at the computational cost of an arithmetic checksum. For 88 bytes of program memory how can you go wrong?

The API can compute the checksum of data incrementally.

For example, the first call to SSFFCSum16() results in the same checksum as the following three calls.

```
uint16_t fc;

fc = SSFFCSum16("abcde", 5, SSF_FCSUM_INITIAL);
/* fc == 0xc8f0 */

fc = SSFFCSum16("a", 1, SSF_FCSUM_INITIAL);
fc = SSFFCSum16("bcd", 3, fc);
fc = SSFFCSum16("e", 1, fc);
/* fc == 0xc8f0 */
```

### Finite State Machine Framework

The state machine framework allows you to create reliable and efficient state machines.

Unless SSF_SM_CONFIG_ENABLE_THREAD_SUPPORT is enabled, all event generation and execution of task handlers for ALL state machines must be done in a single thread of execution.
Calling into the state machine interface from two difference execution contexts is not supported and will eventually lead to problems.
There is a lot that can be said about state machines in general and this one specifically, and I will continue to add to this documentation in the future.

Here's a simple example:

```
/* ssfport.h */
...

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfsm's state machine interface                                                     */
/* --------------------------------------------------------------------------------------------- */
/* Maximum number of simultaneously queued events for all state machines. */
#define SSF_SM_MAX_ACTIVE_EVENTS (5u)

/* Maximum number of simultaneously running timers for all state machines. */
#define SSF_SM_MAX_ACTIVE_TIMERS (2u)

/* Defines the state machine identifers. */
typedef enum
{
    SSF_SM_MIN = -1,
    SSF_SM_STATUS_LED,
    SSF_SM_MAX
} SSFSMList_t;

typedef enum
{
    /* Defines the event identifiers for all state machines. */
    SSF_SM_EVENT_MIN = -1,
    /* Required SSF events */
    SSF_SM_EVENT_ENTRY,  /* Signalled on entry to state handler */
    SSF_SM_EVENT_EXIT,   /* Signalled on exit of state handler */
    SSF_SM_EVENT_SUPER,  /* Signalled to determine parent of current state handler */
                         /* Usually handled in default case with SSF_SM_SUPER() */
                         /* macro. If no parent then SSF_SM_SUPER() is not */
                         /* required or must be called with NULL */
                         /* Super states may not have a parent super state */
    /* User defined events */
    SSF_SM_EVENT_STATUS_RX_DATA,
    SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE,
    SSF_SM_EVENT_STATUS_LED_TIMER_IDLE,
    SSF_SM_EVENT_MAX
} SSFSMEventList_t;

/* main.c */
...

/* State handler prototypes */
static void StatusLEDIdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                 SSFVoidFn_t *superHandler);
static void StatusLEDBlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                  SSFVoidFn_t *superHandler);

static void StatusLEDIdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                 SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        STATUS_LED_OFF();
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_STATUS_RX_DATA:
        SSFSMTran(StatusLEDBlinkHandler);
        break;
    default:
        break;
    }
}

static void StatusLEDBlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                  SSFVoidFn_t *superHandler)

{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        SSFSMStartTimer(SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE, 0);
        SSFSMStartTimer(SSF_SM_EVENT_STATUS_LED_TIMER_IDLE, SSF_TICKS_PER_SEC * 10);
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE:
        STATUS_LED_TOGGLE();
        SSFSMStartTimer(SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE, SSF_TICKS_PER_SEC);
        break;
    case SSF_SM_EVENT_STATUS_LED_TIMER_IDLE:
        SSFSMTran(StatusLEDIdleHandler);
        break;
    default:
        break;
    }
}

void main(void)
{

    /* Initialize state machine framework */
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);

    /* Initialize status LED state machine */
    SSFSMInitHandler(SSF_SM_STATUS_LED, StatusLEDIdleHandler);

    while (true)
    {
        if (ReceivedMessage())
        {
            SSFSMPutEvent(SSF_SM_STATUS_LED, SSF_SM_EVENT_STATUS_RX_DATA);
        }
        SSFSMTask(NULL);
    }
...
```

The state machine framework is first initialized. Then the state machine for the Status LED is initialized, which causes the ENTRY action of the StatusLEDIdleHandler() to be executed, this turns off the LED.

Then main goes into its superloop that checks for a message begin received. When a message is received it will signal SSF_SM_EVENT_STATUS_RX_DATA. The idle handler will trigger a state transition to the StatusLEDBlinkHandler(). The state transition causes an EXIT event for the idle handler, AND an entry event for the blink handler.

On ENTRY the blink handler starts two timers. The SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE timer is set to go off immediately, and the SSF_SM_EVENT_STATUS_LED_TIMER_IDLE timer is set to go off in 10 seconds. When the SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE expires the status LED is toggled and the SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE timer is setup to fire again in 1 second. This cause the LED to blink.

If additional SSF_SM_EVENT_STATUS_RX_DATA events are signaled while in the toggle state they are ignored.

After 10 seconds the SSF_SM_EVENT_STATUS_LED_TIMER_IDLE timer expires and triggers a state transition to the idle state. First the EXIT event in the blink handler is executed automatically by the framework, followed by the ENTRY event in the idle handler that turns off the status LED.

The framework automatically stops all timers associated with a state machine when a state transition occurs. This is why it is not necessary to explicitly stop the SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE timer.

If you need to run the framework in a multi-threaded environment do the following:

-   Enable SSF_SM_CONFIG_ENABLE_THREAD_SUPPORT in ssfport.h
-   Implement the SSF*SM_THREAD_SYNC*\* macros using an OS mutext primitive.
-   Implement the SSF*SM_WAKE_SYNC*\* macros using an OS counting semaphore primitive. The unit test expects the maximum count to be capped at 1.
-   Implement an OS exection context (a task, thread, process, etc.) that initializes the framework and all the state machines. Then call SSFSMTask() throttled by SSF_SM_THREAD_WAKE_WAIT() with the timeout returned from SSFSMTask().
-   SSFSMTask() should normally execute as a high priority system task since it will execute quickly and block until a timer expires or an event is signalled.
-   Only SSFSMPutEventData() and SSFSMPutEvent() may be safely invoked from other execution contexts. Event signalling is allowed from interrupts when the OS synchronization primitives support such use.

Out of the box Windows supports the state machine framework in multi-threaded environments.
And, there is a pthread implementation for OS X and Linux that supports the state machine framework in multi-threaded environments.
OS X does not support CLOCK_MONOTONIC for pthread_cond_timedwait() so set SSF_SM_THREAD_PTHREAD_CLOCK_MONOTONIC to 0. Be aware that a system time change could cause unexpected behavior.
Another note on the pthread port: Contrary to standard pthreads docs, neither OS X or Linux return ETIMEDOUT from pthread_cond_timedwait() when a timeout occurred, this is something I intend to investigate.

Here's pseudocode for an OS thread initializing and running the framework, and demonstrating event generation from a different thread:

```
void OSThreadSSFSM(void *arg)
{
    SSFSMTimeout_t to;

    /* Initialize state machine framework */
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);

    /* Initialize status LED state machine */
    SSFSMInitHandler(SSF_SM_STATUS_LED, StatusLEDIdleHandler);

    while (true)
    {
        SSFSMTask(&to);
        SSF_SM_THREAD_WAKE_WAIT(to);
    }
}

...

void OSThreadEventGenerator(void *arg)
{
    ...

    while (true)
    {
        if (ReceivedMessage())
        {
            SSFSMPutEvent(SSF_SM_STATUS_LED, SSF_SM_EVENT_STATUS_RX_DATA);
        }
    }
}
```
The state machine framework also support 1-level of hierarchical state nesting. To designate a state to have a parent state simply use the SSF_SM_SUPER() macro in the default case of a state handler's event switch statement. The framework is able to automatically determine the state relationships by probing the default case statment. Parent and child state handlers are functionally identical except that a parent state handler cannot use the SSF_SM_SUPER() macro to name another state handler as its parent. When the child is the current state and does not handle an event, the event will be sent to the parent handler for processing. Both parent and child states can be the current state. When multiple children have the same parent they can can share the same core behaviors, and focus on just handling events which are different from the shared parent. This helps to reduce redundancy between state handlers.

```
static void ChildHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                         SSFVoidFn_t *superHandler);
static void ParentHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler);

static void ChildHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                         SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        STATUS_LED_OFF();
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_CHILD:
        /* Do something specific to the child state */
        break;
    default:
        SSF_SM_SUPER(ParentHandler);
        break;
    }
}

static void ParentHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_PARENT:
        /* Do something specific to the parent state */
        break;
    default:
        break;
    }
}

...

/* Initialize state machine framework */
SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);

/* Initialize status LED state machine */
SSFSMInitHandler(SSF_SM_CHILD_PARENT, ChildHandler);

```
If the initial state is ChildHandler() then the ParentHandler() SSF_SM_EVENT_ENTRY clause followed by the ChildHandler() SSF_SM_EVENT_ENTRY clause will be run during initialization. If SSF_SM_EVENT_CHILD occurs then the ChildHandler() will handle the event and the ParentHandler() will not run. However if SSF_SM_EVENT_PARENT occurs, ChildHandler() will be called and execute the default clause, which redirects the event to be processed by ParentHandler(). The framework handles all state transition permutations and will properly exit and enter child and parent states as necessary.

### Reed-Solomon FEC Encoder/Decoder Interface

The Reed-Solomon FEC encoder/decoder interface is a memory efficient (both program and RAM) implementation of the same error correction algorithm that the Voyager probes use to communicate reliably with Earth.

Reed-Solomon can be used to increase the effective receive sensitivity of radios purely in software!

The encoder takes a message and outputs a block of Reed-Solomom ECC bytes. To use, simply transmit the original message followed by the ECC bytes.
The decoder takes a received message, that includes both the message and ECC bytes, and then attempts to correct back to the original message.

The implementation allows larger messages to be processed in chunks which allows trade offs between RAM utilization and encoding/decoding speed.
Using Reed-Solomon still requires the use of CRCs to verify the integrity of the original message after error correction is applied because the error correction can "successfully" correct to the wrong message.

Here's a simple example:

```
/* ssfport.h */
...

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfrs's Reed-Solomon interface                                                      */
/* --------------------------------------------------------------------------------------------- */
...
/* The maximum total size in bytes of a message to be encoded or decoded */
#define SSF_RS_MAX_MESSAGE_SIZE (1024)
...
/* The maximum number of bytes that will be encoded with up to SSF_RS_MAX_SYMBOLS bytes */
#define SSF_RS_MAX_CHUNK_SIZE (127u)
...
/* The maximum number of chunks that a message will be broken up into for encoding and decoding */
#if SSF_RS_MAX_MESSAGE_SIZE % SSF_RS_MAX_CHUNK_SIZE == 0
#define SSF_RS_MAX_CHUNKS (SSF_RS_MAX_MESSAGE_SIZE / SSF_RS_MAX_CHUNK_SIZE)
#else
#define SSF_RS_MAX_CHUNKS ((SSF_RS_MAX_MESSAGE_SIZE / SSF_RS_MAX_CHUNK_SIZE) + 1)
#endif
...
/* The maximum number of symbols in bytes that will encode up to SSF_RS_MAX_CHUNK_SIZE bytes */
/* Reed-Solomon can correct SSF_RS_MAX_SYMBOLS/2 bytes with errors in a message */
#define SSF_RS_MAX_SYMBOLS (8ul)

/* main.c */
...

void main(void)
{
    uint8_t msg[SSF_RS_MAX_MESSAGE_SIZE];
    uint8_t ecc[SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS];
    uint8_t msgRx[SSF_RS_MAX_MESSAGE_SIZE + (SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS)];
    uint16_t eccLen;
    uint16_t msgLen;

    memset(msg, 0xaa, sizeof(msg));
    SSFRSEncode(msg, (uint16_t) sizeof(msg), ecc, (uint16_t)sizeof(ecc), &eccLen,
                SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE);

    /* Pretend to transmit the message and ecc bytes by combining them into a buffer */
    memcpy(msgRx, msg, SSF_RS_MAX_MESSAGE_SIZE);
    memcpy(&msgRx[SSF_RS_MAX_MESSAGE_SIZE], ecc, eccLen);

    /* Pretend to receive and decode the message which has incurred an error */
    msgRx[0] = 0x55;

    /* Perform error correction on the received message */
    if (SSFRSDecode(msgRx, (uint16_t) sizeof(msgRx), &msgLen, SSF_RS_MAX_SYMBOLS,
                    SSF_RS_MAX_CHUNK_SIZE))
    {
        /* msgRx[0] has been fixed and is now 0xaa again */
        /* msgLen is SSF_RS_MAX_MESSAGE_SIZE */

        /* Note: A CRC should verify the integrity of the message after error correction. */
        /* It has been omitted in this example for clarity. */
    }
    else
    {
        /* Error correction failed */
    }
...
```

The encode call will always succeed. It will populate the ecc buffer with up to SSF_RS_MAX_CHUNKS \* SSF_RS_MAX_SYMBOLS of ECC data depending on the actual length of the input message.
eccLen is the actual number of EEC bytes put into the ecc buffer.

Next the example copies the message and the ecc bytes to a contiguous buffer and modifies the first byte to simulate an error.

The decode will return true if it finds a solution and will correct the message in place.
After the decode completes the first byte is restored to 0xaa, and msgLen is SSF_RS_MAX_MESSAGE_SIZE.

For clarity, the example omits integrity checking the message after error correction occurs.
In a real system check the message integrity after error correction is applied because the Reed-Solomon algorithm can "successfully" find the wrong solution.

### 16-bit XMODEM/CCITT-16 CRC Interface

This 16-bit CRC uses the 0x1021 polynomial. It uses a table lookup to reduce execution time at the expense of 512 bytes of program memory.
Use if you need compatability with the XMODEM CRC and/or can spare the extra program memory for a little bit better error detection than the 16-bit Fletcher.

The API can compute the CRC of data incrementally.

For example, the first call to SSFCRC16() results in the same CRC as the following three calls.

```
uint16_t crc;

crc = SSFCRC16("abcde", 5, SSF_CRC16_INITIAL);
/* crc == 0x3EE1 */

crc = SSFCRC16("a", 1, SSF_CRC16_INITIAL);
crc = SSFCRC16("bcd", 3, crc);
crc = SSFCRC16("e", 1, crc);
/* crc == 0x3EE1 */
```

### 32-bit CCITT-32 CRC Interface

This 32-bit CRC uses the 0x04C11DB7 polynomial. It uses a table lookup to reduce execution time at the expense of 1024 bytes of program memory.
Use if you need more error detection than provided by CRC16 and/or in conjunction with Reed-Solomon to detect wrong solutions.

The API can compute the CRC of data incrementally.

For example, the first call to SSFCRC32() results in the same CRC as the following three calls.

```
uint32_t crc;

crc = SSFCRC32("abcde", 5, SSF_CRC32_INITIAL);
/* crc == 0x8587D865 */

crc = SSFCRC32("a", 1, SSF_CRC32_INITIAL);
crc = SSFCRC32("bcd", 3, crc);
crc = SSFCRC32("e", 1, crc);
/* crc == 0x8587D865 */
```

### SHA-2 Hash Interface

The SHA-2 hash interface supports SHA256, SHA224, SHA512, SHA384, SHA512/224, and SHA512/256. There are two base functions that provide the ability to compute the six supported hashes. There are macros provided to simplify the calling interface to the base functions.

For example, to compute the SHA256 hash of "abc".

```
uint8_t out[SSF_SHA2_256_BYTE_SIZE];

SSFSHA256("abc", 3, out, sizeof(out));
/* out == "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" */
```

### TLV Encoder/Decoder Interface

The TLV interface encodes and decodes data into tag, length, value data streams. TLV is a compact alternative to JSON when the size of the data matters, such as when using a metered data connection or sending data over a bandwidth constrained wireless connection.

For small data sets the interface can be compiled in fixed mode that limits the maximum number of tags to 256 and the length of each field to 255 bytes. For larger data sets the variable mode independently uses the 2 most significant bits to encode the byte size of the tag and length fields so they are 1 to 4 bytes in length. This allows many more tags and larger values to be encoded while still maintaining a compact encoding.

For initialization, a user supplied buffer is passed in. If the buffer already has TLV data then the total length of the TLV can be set as well.
When encoding the same tag can be used multiple times. On decode the interface allow simple iteration over all of the duplicate tags.
The decode interface allows a value to be copied to a user supplied buffer, or it can simply pass back the a pointer and length of the value within the TLV data.

```
#define TAG_NAME 1
#define TAG_HOBBY 2

SSFTLV_t tlv;
uint8_t buf[100];

SSFTLVInit(&tlv, buf, sizeof(buf), 0);
SSFTLVPut(&tlv, TAG_NAME, "Jimmy", 5);
SSFTLVPut(&tlv, TAG_HOBBY, "Coding", 6);
/* tlv.bufLen is the total length of the TLV data encoded */

... Transmit tlv.bufLen bytes of tlv.buf to another system ...

#define TAG_NAME 1
#define TAG_HOBBY 2

SSFTLV_t tlv;
uint8_t rxbuf[100];
uint8_t val[100];
SSFTLVVar_t valLen;
uint8_t *valPtr;

/* rxbuf contains rxlen bytes of received data */
SSFTLVInit(&tlv, rxbuf, sizeof(rxbuf), rxlen);

SSFTLVGet(&tlv, TAG_NAME, 0, val, sizeof(val), &valLen);
/* val == "Jimmy", valLen == 5 */

SSFTLVGet(&tlv, TAG_HOBBY, 0, val, sizeof(val), &valLen);
/* val == "Coding", valLen == 6 */

SSFTLVFind(&tlv, TAG_NAME, 0, &valPtr,  &valLen);
/* valPtr == "Jimmy", valLen == 5 */
```

## AES Block Interface

The AES block interface encrypts and decrypts 16 byte blocks of data with the AES cipher. The generic interface supports 128, 192 and 256 bit keys. Macros are supplied for these key sizes. This implementation _SHOULD NOT_ be used in production systems. It _IS_ vulnerable to timing attacks. Instead, processor specific AES instructions should be preferred.

```
    uint8_t pt[16];
    uint8_t dpt[16];
    uint8_t ct[16];
    uint8_t key[16];

    /* Initialize the plaintext and key here */
    memcpy(pt, "1234567890abcdef", sizeof(pt));
    memcpy(key, "secretkey1234567", sizeof(key));

    /* Encrypt the plaintext */
    SSFAES128BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));

    /* ct = "\xdc\xc9\x32\xee\xfa\x94\x00\x0d\xfb\x97\x3f\xd4\x3d\x52\x6c\x45" */

    /* Decrypt the ciphertext */
    SSFAES128BlockDecrypt(ct, sizeof(ct), dpt, sizeof(dpt), key, sizeof(key));

    /* dpt = "1234567890abcdef" */

    /* If the key size is variable use the generic interface */

    /* Encrypt the plaintext */
    SSFAESXXXBlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));

    /* ct = "\xdc\xc9\x32\xee\xfa\x94\x00\x0d\xfb\x97\x3f\xd4\x3d\x52\x6c\x45" */

    /* Decrypt the ciphertext */
    SSFAESXXXBlockDecrypt(ct, sizeof(ct), dpt, sizeof(dpt), key, sizeof(key));

    /* dpt = "1234567890abcdef" */
```

## AES-GCM Interface

The AES-GCM interface provides encryption and authentication for arbitary length data. The generic AES-GCM encrypt/decrypt functions support 128, 196 and 256 bit keys. There are four available modes: authentication, authenticated data, authenticated encryption and authenticated encryption with authenticated data. Examples of these are provided below. See the AES-GCM specification for details on how to generate valid IVs, example below. Note that the AES-GCM implementation relies on the _TIMING ATTACK VULNERABLE_ AES block cipher implementation.

```
    /* This shows a 128-bit IV generation, although a 96-bit IV is recommended and slightly more efficient */
    #define AES_GCM_MAKE_IV(iv, eui, fc) { \
        uint32_t befc = htonl(fc); \
        memcpy(iv, eui, 8); \
        memcpy(&iv[8], &befc, 4); \
        befc = ~befc; \
        memcpy(&iv[12], &befc, 4); \
    }
    size_t ptLen;
    uint8_t pt[100];
    uint8_t dpt[100];
    uint8_t iv[16];
    size_t authLen;
    uint8_t auth[100];
    uint8_t key[16];
    uint8_t tag[16];
    uint8_t ct[100];
    uint8_t eui64[8];
    uint32_t frameCounter;

    /* Initialize pt, iv, auth and key here */
    memcpy(eui64, "\x12\x34\x45\x67\x89\xab\xcd\xef", sizeof(eui64));
    frameCounter = 0;
    memcpy(pt, "1234567890abcdef", 16);
    ptLen = sizeof(pt);
    memcpy(key, "secretkey1234567", sizeof(key));
    memcpy(auth, "unencrypted auth data", 21);
    authLen = 21;

    /* Authentication */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag), NULL, 0);

    /* Pass values of iv, tag to receiver so they can verify with their copy of private key */
    if (!SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag,
                          sizeof(tag), NULL, 0))
    {
        printf("Authentication failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */


    /* Authenticated data */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag, sizeof(tag),
                     NULL, 0);

    /* Pass values of iv, auth, tag to receiver so they can verify with their copy of private key */
    if (!SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag,
                          sizeof(tag), NULL, 0))
    {
        printf("Authentication of unencrypted data failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */


    /* Authenticated encryption */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(pt, ptLen, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag),
                     ct, sizeof(ct));

    /* Pass values of iv, ct, tag to receiver so they can verify with their copy of private key */
    if (!SSFAESGCMDecrypt(ct, ptLen, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag,
                          sizeof(tag), dpt, sizeof(dpt)))
    {
        printf("Authentication of encrypted data failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */


    /* Authenticated encryption and authenticated data */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(pt, ptLen, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag,
                     sizeof(tag), ct, sizeof(ct));

    if (!SSFAESGCMDecrypt(ct, ptLen, iv, sizeof(iv), auth, authLen, key,
                          sizeof(key), tag, sizeof(tag), dpt, sizeof(dpt)))
    {
        printf("Authentication of encrypted and unencrypted data failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */
```

### Version Controlled Configuration Storage Interface

Most embedded systems need to read and write configuration data to non-volatile memory such as NOR flash. This cfg interface handles all the details of reliably storing versioned data to the flash and prevents redundant writes.

```
#define MY_CONFIG_ID (0u) /* 32-bit number uniquely each type of config in the system */
#define MY_CONFIG_VER_1 (1u) /* Version number 1 of my config data */
#define MY_CONFIG_VER_2 (2u) /* Version number 2 of my config data */

uint8_t myConfigData[SSF_MAX_CFG_DATA_SIZE_LIMIT]; /* Can be any arbitrary data or structure */
uint16_t myConfigDataLen;

/* Bootstrap config */
if (SSFCfgRead(myConfigData, &myConfigDataLen, sizeof(myConfigData), MY_CONFIG_ID) == MY_CONFIG_VER_1)
{
    /* Successfully read version 1 of my config data, myConfigDataLen is actual config data len */
    ...
}
if (SSFCfgRead(myConfigData, &myConfigDataLen, sizeof(myConfigData), MY_CONFIG_ID) == MY_CONFIG_VER_2)
{
    /* Successfully read version 2 of my config data, myConfigDataLen is actual config data len */
    ...
}
else
{
    /* Set my config to defaults */
    memset(myConfigData, 0, sizeof(myConfigData));
    SSFCfgWrite(myConfigData, 5, MY_CONFIG_ID, MY_CONFIG_VER_2);
}

```

### Cryptographically Secure Capable PRNG Interface

The strength of many cryptographically secure algorithms and protocols is derived from a source of cryptographically secure random numbers. This interface provides a pseudo random number generator (PRNG) that CAN generate a cryptographically secure sequence of random numbers when properly seeded with 128-bits of entropy. The interface is allowed to re-init with new entropy at any time...useful in case the system needs to generate trillions of random numbers and there is a concern that the 64-bit counter might wrap :) After initing, 1-16 bytes of random data can be read on each invocation.

```
uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
uint8_t random[SSF_PRNG_RANDOM_MAX_SIZE];

    ... To be cryptographically secure 128-bits of entropy from a true random source must be
        staged to the entropy buffer;
        Otherwise it is easier to predict the random number sequence which can compromise
        secure algorithms and protocols.

    entropy <----random source
    SSFPRNGInitContext(&context, entropy, sizeof(entropy));

    while (true)
    {
        ...
        SSFPRNGGetRandom(&context, random, sizeof(random));
        /* random now contains 16 bytes of pseudo random data */
        ...

        /* Should we reseed after trillons and trillions of loops? */
        if (reseed)
        {
            /* Yes, reseed */
            entropy <----random source
            SSFPRNGInitContext(&context, entropy, sizeof(entropy));
        }
    }
```

### INI Parser/Generator Interface

Sad that we still need this, but we still sometimes need to parse and generate INI files. Natively supports string, boolean, and long int types. The parser is forgiving and the main limitation is that it does not support quoted strings, so values cannot have whitespace.

```
    char iniParse[] = "; comment\r\nname=value1\r\n[section]\r\nname=yes\r\nname=0\r\nfoo=bar\r\nX=\r\n";
    char outStr[16];
    bool outBool;
    long int outLong;
    char iniGen[256];
    size_t iniGenLen;

    /* Parse */
    SSFINIIsSectionPresent(iniParse, "section"); /* Returns true */
    SSFINIIsSectionPresent(iniParse, "Section"); /* Returns false */

    SSFIsNameValuePresent(iniParse, NULL, "name", 0); /* Returns true */
    SSFIsNameValuePresent(iniParse, NULL, "name", 1); /* Returns false */
    SSFIsNameValuePresent(iniParse, "section", "name", 0); /* Returns true */
    SSFIsNameValuePresent(iniParse, "section", "name", 1); /* Returns true */
    SSFIsNameValuePresent(iniParse, "section", "name", 2); /* Returns false */
    SSFIsNameValuePresent(iniParse, "section", "foo", 0); /* Returns true */
    SSFIsNameValuePresent(iniParse, "section", "X", 0); /* Returns true */

    SSFINIGetStrValue(iniParse, "section", name, 1, outStr, sizeof(outStr), NULL); /* Returns true, outStr = "0" */
    SSFINIGetBoolValue(iniParse, "section", name, 1, &outBool); /* Returns true, outBool = false */
    SSFINIGetLongValue(iniParse, "section", name, 1, &outLong); /* Returns true, outLong = 0 */

    /* Generate */
    iniGenLen = 0;
    SSFINIPrintComment(iniGen, sizeof(iniGen), &iniGenLen, " comment", SSF_INI_COMMENT_HASH, SSF_INI_CRLF);
    SSFINIPrintSection(iniGen, sizeof(iniGen), &iniGenLen, "section", SSF_INI_CRLF);
    SSFINIPrintNameStrValue(iniGen, sizeof(iniGen), &iniGenLen, "strName", "value", SSF_INI_CRLF);
    SSFINIPrintNameBoolValue(iniGen, sizeof(iniGen), &iniGenLen, "boolName", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF);
    SSFINIPrintNameStrValue(iniGen, sizeof(iniGen), &iniGenLen, "longName", -1234567890l, SSF_INI_CRLF);

    /* iniGen = "# comment\r\n[section]\r\nstrName=value\r\nboolName=yes\r\nlongName=-1234567890\r\n" */
```

### Universal Binary JSON (UBJSON) Parser/Generator Interface

The UBJSON specification can be found at https://ubjson.org/.

It does appear that work on the specification has stalled, which is unfortunate since a lighter weight JSON encoding that is 1:1 compatible with JSON data types is a great idea.

This parser operates on the UBJSON message in place and only consumes modest stack in proportion to the maximum nesting depth. Since the UBJSON string is parsed from the start each time a data element is accessed it is computationally inefficient; that's ok since most embedded systems are RAM constrained not performance constrained.

Here are some simple parser examples:

```
    uint8_t ubjson1[] = "{i\x04nameSi\x05value}";
    size_t ubjson1Len = 16;
    uint8_t ubjson2[] = "{i\x03obj{i\x04nameSi\x05valuei\x05" "array[$i#i\x03" "123}}";
    size_t ubjson2Len = 39;
    char* path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
    char strOut[32];
    size_t idx;

    /* Must zero out path variable before use */
    memset(path, 0, sizeof(path));

    /* Get the value of a top level element */
    path[0] = "name";
    if (SSFUBJsonGetString(ubjson1, ubjson1Len, (SSFCStrIn_t*)path, strOut, sizeof(strOut), NULL))
    {
        printf("%s\r\n", strOut);
        /* Prints "value" excluding double quotes */
    }

    /* Get the value of a nested element */
    path[0] = "obj";
    path[1] = "name";
    if (SSFUBJsonGetString(ubjson2, ubjson2Len, (SSFCStrIn_t*)path, strOut, sizeof(strOut), NULL))
    {
        printf("%s\r\n", strOut);
        /* Prints "value" excluding double quotes */
    }

    path[0] = "obj";
    path[1] = "array";
    path[2] = (char*)&idx;
    /* Iterate over a nested array */
    for (idx = 0;; idx++)
    {
        int8_t si;

        if (SSFUBJsonGetInt8(ubjson2, ubjson2Len, (SSFCStrIn_t*)path, &si))
        {
            if (idx != 0) printf(", ");
            printf("%ld", si);
        }
        else break;
    }
    printf("\r\n");
    /* Prints "1, 2, 3" */
```

Here is a simple generation example:

```
bool printFn(uint8_t* js, size_t size, size_t start, size_t* end, void* in)
{
    SSF_ASSERT(in == NULL);

    if (!SSFUBJsonPrintLabel(js, size, start, &start, "label1")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, "value1")) return false;
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "label2")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, "value2")) return false;

    *end = start;
    return true;
}

...

    uint8_t ubjson[128];
    size_t end;

    /* JSON is contained within an object {}, so to create a JSON string call SSFJsonPrintObject() */
    if (SSFUBJsonPrintObject(ubjson, sizeof(ubjson), 0, &end, printFn, NULL))
    {
        /* ubjson == "{U\x06label1SU\x06value1U\x06label2SU\x06value2}", end == 36 */
        memset(path, 0, sizeof(path));
        path[0] = "label2";
        if (SSFUBJsonGetString(ubjson, end, (SSFCStrIn_t*)path, strOut, sizeof(strOut), NULL))
        {
            printf("%s\r\n", strOut);
            /* Prints "value2" excluding double quotes */
        }
    }
```

Object and array nesting is achieved by calling SSFUBJsonPrintObject() or SSFUBJsonPrintArray() from within a printer function.

Parsing and generation of optimized integer arrays is supported.

### Unix Time RTC Interface

This interface keeps Unix time, as initialized from an RTC, by using the system tick counter. When time is changed, the RTC is written to keep it in sync.

Since many embedded systems use I2C RTC devices, accessing the RTC everytime Unix time is required is time-intensive. This interface eliminates all unnecessary RTC reads.

```
    /* Reads the RTC and tracks Unix time based on the system tick */
    SSFRTCInit();

    while (true)
    {
        SSFPortTick_t unixSys;
        uint64_t newUnixSec;

        /* Returns Unix time in system ticks */
        unixSys = SSFRTCGetUnixNow();
        /* unixSys / SSF_TICKS_PER_SEC == Seconds since Unix Epoch */

        if (NTPUpdated(&newUnixSec))
        {
            /* NTP returned a new seconds since Unix Epoch */
            SSFRTCSet(newUnixSec);
            /* ...RTC has been written with new time */
        }
    }
```

### Date Time Interface

This interface converts Unix time in system ticks into a date time struct and vice versa.

```
    /* Supported date range: 1970-01-01T00:00:00.000000000Z - 2199-12-31T23:59:59.999999999Z         */
    /* Unix time is measured in system ticks (unixSys is seconds scaled by SSF_TICKS_PER_SEC)        */
    /* Unix time is always UTC (Z) time zone, other zones are handled by the ssfios8601 interface.   */
    /* Unix time does not account for leap seconds, it only accounts for leap years.                 */
    /* It is assumed that the RTC is periodically updated from an external time source, such as NTP. */
    /* Inputs are strictly checked to ensure they represent valid calendar dates.                    */
    /* System ticks (SSF_TICKS_PER_SEC) must be 1000, 1000000, or 1000000000.                        */

    SSFDTimeStruct_t ts;
    SSFPortTick_t unixSys;
    SSFDTimeStruct_t tsOut;

    /* Initialize a date time struct from basic date information */
    SSFDTimeStructInit(&ts, year, month, day, hour, min, sec, fsec);

    /* Convert the date time struct to Unix time in system ticks */
    SSFDTimeStructToUnix(&ts, &unixSys);
    /* unixSys == system ticks since epoch for year/month/day hour/min/sec/fsec */

    /* Convert unixSys back to a date time struct */
    SSFDTimeUnixToStruct(unixSys, &tsOut, sizeof(tsOut));
    /* tsOut struct fields == ts struct fields */
```

### ISO8601 Date Time Interface

This interface converts Unix time in system ticks into an ISO8601 extended date time string and vice versa. This is the only time interface in the framework that handles "local time".

```
    /* Supported date range: 1970-01-01T00:00:00.000000000Z - 2199-12-31T23:59:59.999999999Z         */
    /* Unix time is measured in system ticks (unixSys is seconds is scaled by SSF_TICKS_PER_SEC)     */
    /* Unix time is always UTC (Z) time zone.                                                        */
    /* Inputs are strictly checked to ensure they represent valid calendar dates.                    */
    /*                                                                                               */
    /* Only ISO8601 extended format is supported, and only with the following ordered fields:        */
    /*   Required Date & Time Field:      YYYY-MM-DDTHH:MM:SS                                        */
    /*   Optional Second Precision Field:                    .FFF                                    */
    /*                                                       .FFFFFF                                 */
    /*                                                       .FFFFFFFFF                              */
    /*   Optional Time Zone Field :                                    Z                             */
    /*                                                                 +HH                           */
    /*                                                                 -HH                           */
    /*                                                                 +HH:MM                        */
    /*                                                                 -HH:MM                        */
    /*                                                                 (no TZ field == local time)   */
    /*                                                                                               */
    /* The Date and Time field is always in local time, subtracting offset yields UTC time.          */
    /* The default fractional second precision is determined by SSF_TICKS_PER_SEC.                   */
    /* Fractional seconds may be optionally added when generating an ISO string.                     */
    /* 3 digits of pseudo-fractional seconds precision may be added when generating an ISO string.   */
    /* Daylight savings is handled by application code adjusting the zoneOffsetMin input as needed.  */

    SSFPortTick_t unixSys;
    SSFPortTick_t unixSysOut;
    int16_t zoneOffsetMin;
    char isoStr[SSFISO8601_MAX_SIZE];

    unixSys = SSFRTCGetUnixNow();
    SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr));
    /* isoStr looks something like "2022-11-23T13:00:12Z" */

    SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin);
    /* unixSys == unixSysOut, zoneOffsetMin == 0 */
```

### Integer to Decimal String Interface

This interface converts signed or unsigned integers to padded or unpadded decimal strings. It is meant to be faster and have stronger typing than snprintf().

```
    size_t len;
    char str[]

    len = SSFDecIntToStr(-123456789123ull, str, sizeof(str));
    /* len == 13, str = "-123456789123" */

    len = SSFDecIntToStrPadded(-123456789123ull, str, sizeof(str), 15, '0');
    /* len == 15, str = "-00123456789123" */
```

### Safe C String Interface

This interface provides true safe replacements for strcpy(), strcat(), strcpy(), strcmp(), and related "safe" strn() calls that don't always NULL terminate.

```
    size_t len;
    char str[10];

    /* Copy 10 byte string into str var? */
    if (SSFStrCpy(str, sizeof(str), &len, "1234567890", 11)) == false)
    {
        /* No, copy failed because str is not big enough to hold new string plus NULL terminator */
    }

    /* Copy 9 byte string into str var? */
    if (SSFStrCpy(str, sizeof(str), &len, "123456789", 10)) == true)
    {
        /* Yes copy worked, str="123456789", len = 9 */
    }
```


### Debuggable Integrity Checked Heap Interface

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

## Conclusion

I built this framework for primarily myself, although I hope you can find a good use for it.

Special thanks to my son, Calvin, for researching, implementing, and debugging the AES Block and AES-GCM interfaces!

Drop me a line if you have a question or comment.

Jim Higgins

President

Supurloop Software

jim@supurloop.com
