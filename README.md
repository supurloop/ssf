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

To give you an idea of the framework size here are some program memory estimates for each component compiled on an MSP430 with Level 3 optimization:
Byte FIFO, linked list, memory pool, Base64, Hex ASCII are each about 1000 bytes.
JSON parser/generator is about 7300-8800 bytes depending on configuration.
Finite state machine is about 2000 bytes.
Fletcher checksum is about 88 bytes.

The Reed-Solomon encoder will run on an 8-bit PIC (4KB Code/256 bytes RAM) w/radio transmitter using only about half of its available memory.

The complete framework, assuming every function of every interface is used, is about 20000 bytes of program memory.
Many programs will only use a fraction of the functions in all the interfaces and should see the amount of program memory reduced further.

Little RAM is used internally by the framework, most RAM usage occurs outside the framwork when declaring or initializing different objects.

Microprocessors with >4KB RAM and >32KB program memory should easily be able to utilize this framework.
As noted above, portions of the framework will work on much smaller micros.

## Porting

This framework has been successfully ported and unit tested on the following platforms: Windows Visual Studio 32/64-bit, Linux 32/64-bit (GCC), PIC32 (XC32), PIC24 (XC16), and MSP430 (TI 15.12.3.LTS). You should only need to change ssfport.c and ssfport.h to implement a successful port.

The code will compile cleanly under Windows in Visual Studio using the ssf.sln solution file.
The code will compile cleanly under Linux. ./build.sh will create the ssf executable in the source directory.

For other platforms there are only a few essential tasks that must be completed:
  - Copy all the SSF C and H source files, except main.c, into your project sources and add them to your build environment.
  - In ssfport.h make sure SSF_TICKS_PER_SEC is set to the number of system ticks per second on your platform.
  - Map SSFPortGetTick64() to an existing function that returns the number of system ticks since boot, or
    implement SSFPortGetTick64() in ssfport.c if a simple mapping is not possible.
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
To help ensure correctness the framework uses Design by Contract techniques to immediately common errors that tend to creep into systems and cause problems at the worst possible times. 

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

### Linked List Interface

The linked list interface allows the creation of FIFOs and STACKs for more managing more complex data structures.
The key to using the Linked List interface is that when you create the data structure that you want to track place a SSFLLItem_t called item at the top of the struct. For example:

typedef struct SSFLLMyData
{
    SSFLLItem_t item;
    uint32_t mydata;
} SSFLLMyData_t;

### Memory Pool Interface

The memory pool interface creates a pool of fixed sized memory blocks that can be efficiently allocated and freed without making dynamic memory calls.

### Base64 Encoder/Decoder Interface

This interface allows you to encode a binary data stream into a Base64 string, or do the reverse.

### Binary to Hex ASCII Encoder/Decoder Interface

This interface allows you to encode a binary data stream into an ASCII hexadecimal string, or do the reverse.

### JSON Parser/Generator Interface

Having searched for used many JSON parser/generators on small embedded platforms I never found exactly the right mix of attributes. the mjson project came the closest on the parser side, but relied on varargs for the generator, which provides a potential breeding ground for bugs.

Like mjson (a SAX-like parser) this parser operates on the JSON string in place and only consumes modest stack in proportion to the maximum nesting depth. Since the JSON string is parsed from the start each time a data element is accessed it is computationally inefficient, but most embedded systems are RAM constrained not performance constrained.

On the generator side it does away with varargs and opts for an interface that can be verified at compilation time to be called correctly.

### 16-bit Fletcher Checksum Interface

Every embedded system needs to use a checksum somewhere, somehow. The 16-bit Fletcher checksum has many of the error detecting properties of a 16-bit CRC, but at the computational cost of an arithmetic checksum. For 88 bytes of program memory how can you go wrong?

### Finite State Machine Framework

The state machine framework allows you to create reliable and efficient state machines.
All event generation and execution of task handlers for ALL state machines must be done in a single thread of execution.
Calling into the state machine interface from two difference execution contexts is not supported and will eventually lead to problems.
There is a lot that can be said about state machines in general and this one specifically, and I will continue to add to this documentation in the future.

### Reed-Solomon FEC Encoder/Decoder Interface

The Reed-Solomon FEC encoder/decoder interface is a memory efficient (both program and RAM) implementation of the same error correction algorithm that the Voyager probes use to communicate reliably with Earth.

Reed-Solomon is very useful to increase the effective receive sensitivity of radios purely with software!

The encoder takes a message and outputs a block of Reed-Solomom ECC bytes. To use, simply transmit the original message followed by the ECC bytes.
The decoder takes a received message, that includes both the message and ECC bytes, and then attempts to correct back to the original message.

The implementation allows larger messages to be processed in chunks which allows trade offs between RAM utilization and encoding/decoding speed.
Using Reed-Solomon still requires the use of CRCs to verify the integrity of the original message after error correction is applied because the error correction can "successfully" correct to the wrong message.

## Conclusion

I built this framework for primarily myself, although I hope you can find a good use for it.
In the future I plan to add example documentation, CRCs, and possibly de-init interfaces.

Drop me a line if you have a question or comment.

Jim Higgins

President

Supurloop Software

jim@supurloop.com
