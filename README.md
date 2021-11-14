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

To give you an idea of the framework size here are some program memory estimates for each component compiled on an MSP430 with Level 3 optimization:
Byte FIFO, linked list, memory pool, Base64, Hex ASCII are each about 1000 bytes.
JSON parser/generator is about 7300-8800 bytes depending on configuration.
Finite state machine is about 2000 bytes.
Fletcher checksum is about 88 bytes.

Little RAM is used internally by the framework, most RAM usage occurs outside the framwork when declaring or initializing different objects.

Microprocessors with >4KB RAM and >32KB program memory should easily be able to utilize all of this framework.
And, as noted above, portions of the framework will work on much smaller micros.

## Porting

This framework has been successfully ported and unit tested on the following platforms: Windows Visual Studio 32/64-bit, Linux 32/64-bit (GCC), PIC32 (XC32), PIC24 (XC16), and MSP430 (TI 15.12.3.LTS). You should only need to change ssfport.c and ssfport.h to implement a successful port.

The code will compile cleanly under Windows in Visual Studio using the ssf.sln solution file.
The code will compile cleanly under Linux. ./build.sh will create the ssf executable in the source directory.

For other platforms there are only a few essential tasks that must be completed:
  - Copy all the SSF C and H source files, except main.c, into your project sources and add them to your build environment.
  - In ssfport.h make sure SSF_TICKS_PER_SEC is set to the number of system ticks per second on your platform.
  - Map SSFPortGetTick64() to an existing function that returns the number of system ticks since boot, or
    implement SSFPortGetTick64() in ssfport.c if a simple mapping is not possible.
  - In ssfport.h make sure to follow the instructions for the byte order macros.
  - Run the unit tests.

Only the finite state machine framework uses system ticks, so you can stub out SSFPortGetTick64() if it is not needed.

### Heap and Stack Memory
Only the memory pool and finite state machine use dynamic memory, aka heap. The memory pool only does so when a pool is created. The finite state machine only uses malloc when an event has data whose size is bigger than the sizeof a pointer.

The framework is fairly stack friendly, although the JSON parser will recursively call functions for nested JSON objects and arrays. SSF_JSON_CONFIG_MAX_IN_DEPTH in ssfport.h can be used to control the maximum depth the JSON parser will recurse to prevent the stack from blowing up due to bad inputs. If the unit test for the JSON interface is failing weirdly then increase your system stack.

The most important step is to run the unit tests for the interfaces you intend to use on your platform. This will detect porting problems very quickly and avoid many future debugging headaches.

### SSFPortAssert()

For a production ready embedded system you should probably do something additional with SSFPortAssert() besides nothing.

First, I recommend that it should somehow safely record the file and line number where the assertion occurred so that it can be reported on the next boot.

Second, the system should be automatically reset rather than sitting forever in a loop.

## Design Principles
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
RTOSes introduce significant complexity, and in particular a dizzying amount of opportunity for introducing subtle race conditions (BUGS) that are difficult to find and fix.

That said this framework can run perfectly fine with an RTOS, Windows, or Linux, so long as some precautions are taken.

Excepting the finite state machine framework, all interfaces are reentrant.
This means that calls into those interfaces from different execution contexts will not interfere with each other.

For example, you can have linked list object A in task 1 and linked list object B in task 2 and they will be managed independently and correctly, so long as they are only accessed from the context of their respective task.

In contrast the finite state machine framework requires that all event generation and state handler execution for all state machines occur in the same execution context.

## Interfaces
### Byte FIFO Interface

Most embedded systems need to send and receive data. The idea behind the byte FIFO is to provide a buffer for incoming and outgoing bytes on these communication interfaces. For example, you may have an interrupt that fires when a byte of data is received. You don't want to process the byte in the handler so it simply gets put onto the RX byte fifo. When the interrupt completes the main execution thread will check for bytes in the RX byte fifo and process them accordingly.

But wait, the interrupt is a different execution context so we have a race condition that can cause the byte FIFO interface to misbehave. The exact solution will vary between platforms, but the general idea is to disable interrupts in the main execution thread while checking *and* pulling the byte out of the RX FIFO.

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
Before an item is added to a list it cannot be part of a another list otherwise an assertion will be triggered.
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
    /* Prints "name" excluding double quotes */
}

/* Get the value of a nested element */
path[0] = "obj";
path[1] = "name";
if (SSFJsonGetString(json2Str, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s", strOut);
    /* Prints "name" excluding double quotes */
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

All event generation and execution of task handlers for ALL state machines must be done in a single thread of execution.
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
enum SSFSMList
{
    SSF_SM_STATUS_LED,
    SSF_SM_END
};

/* Defines the event identifiers for all state machines. */
enum SSFSMEventList
{
    SSF_SM_EVENT_ENTRY,
    SSF_SM_EVENT_EXIT,
    SSF_SM_EVENT_STATUS_RX_DATA,
    SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE,
    SSF_SM_EVENT_STATUS_LED_TIMER_IDLE,
    SSF_SM_EVENT_END
};

/* main.c */
...

/* State handler prototypes */
static void StatusLEDIdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);
static void StatusLEDBlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen);

static void StatusLEDIdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
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

static void StatusLEDBlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen)
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
...
    /* Initialize state machine framework */
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    
    /* Initialize status LED state machine */
    SSFSMInitHandler(SSF_SM_STATUS_LED, StatusLEDIdleHandler);

    while (true)
    {
        if (ReceivedMessage())
        {
            SSFSMPutEventData(SSF_SM_STATUS_LED, SSF_SM_EVENT_STATUS_RX_DATA);
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
The encode call will always succeed. It will populate the ecc buffer with up to SSF_RS_MAX_CHUNKS * SSF_RS_MAX_SYMBOLS of ECC data depending on the actual length of the input message.
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

The AES block interface encrypts and decrypts 16 byte blocks of data with the AES cipher. The generic interface supports 128, 192 and 256 bit keys. Macros are supplied for these key sizes. This implementation *SHOULD NOT* be used in production systems. It *IS* vulnerable to timing attacks. Instead, processor specific AES instructions should be preferred.

```
uint8_t pt[16];
uint8_t ct[16];
uint8_t key[16];

/* Initialize the plaintext and key here */

/* Encrypt the plaintext */
SSFAESBlockEncrypt128(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));

/* Decrypt the ciphertext */
SSFAESBlockDecrypt128(ct, sizeof(ct), pt, sizeof(pt), key, sizeof(key));

/* If the key size is unknown */

/* Encrypt the plaintext */
SSFAESBlockEncryptXXX(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));

/* Decrypt the ciphertext */
SSFAESBlockDecryptXXX(ct, sizeof(ct), pt, sizeof(pt), key, sizeof(key));
```

## AES-GCM Interface

The AES-GCM interface provides encryption and authentication for arbitary length data. The generic AES-GCM encrypt/decrypt functions support 128, 196 and 256 bit keys. There are four available modes: authentication, authenticated data, authenticated encryption and authenticated encryption with authenticated data. Examples of these are provided below. See the AES-GCM specification for details on how to generate valid IVs without. Note that the AES-GCM implementation relies on the *TIMING ATTACK VULNERABLE* AES block cipher implementation. 

```
uint8_t pt[100];
uint8_t iv[16];
uint8_t auth[200];
uint8_t key[16];
uint8_t tag[16];
uint8_t ct[100];

/* Initialize pt, iv, auth and key here */

/* Authentication */
SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag), NULL, 0);

bool isValid = SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, 
                                sizeof(tag), NULL, 0);


/* Authenticated data */
SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), auth, sizeof(auth), key, sizeof(key), tag, sizeof(tag), 
                 NULL, 0);
bool isValid = SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), auth, sizeof(auth), key, sizeof(key), tag, 
                                sizeof(tag), NULL, 0);


/* Authenticated encryption */
SSFAESGCMEncrypt(pt, sizeof(pt), iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag), 
                 ct, sizeof(ct));
bool isValid = SSFAESGCMDecrypt(ct, sizeof(ct), iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, 
                                sizeof(tag), pt, sizeof(pt));

/* Authenticated encryption and authenticated data */
SSFAESGCMEncrypt(pt, sizeof(pt), iv, sizeof(iv), auth, sizeof(auth), key, sizeof(key), tag, 
                 sizeof(tag), ct, sizeof(ct));
bool isValid = SSFAESGCMDecrypt(ct, sizeof(ct), iv, sizeof(iv), auth, sizeof(auth), key, 
                                sizeof(key), tag, sizeof(tag), pt, sizeof(pt));
```

## Conclusion

I built this framework for primarily myself, although I hope you can find a good use for it.
In the future I plan to add additional documentation, some encryption, and possibly de-init interfaces.

Special thanks to my son, Calvin, for researching, implementing, and debugging the AES Block and AES-GCM interfaces!

Drop me a line if you have a question or comment.

Jim Higgins

President

Supurloop Software

jim@supurloop.com
