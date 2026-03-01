# Error Correction Codes (ECC)

[Back to ssf README](../README.md)

Forward error correction interfaces.

## Reed-Solomon FEC Encoder/Decoder Interface

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
