# ssfprng — Pseudo Random Number Generator

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

Cryptographically secure capable PRNG based on AES-CTR mode with a 128-bit seed.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFPRNGInitContext(ctx, entropy, entropySize)` | Initialize (or re-initialize) PRNG with entropy |
| `SSFPRNGGetRandom(ctx, out, outSize)` | Generate 1–16 bytes of pseudo-random data |
| `SSF_PRNG_ENTROPY_SIZE` | Required entropy buffer size (16 bytes) |
| `SSF_PRNG_RANDOM_MAX_SIZE` | Maximum bytes per `SSFPRNGGetRandom()` call (16 bytes) |

## Usage

This PRNG CAN generate cryptographically secure random numbers when seeded with 128 bits of
true entropy. Re-initialization with fresh entropy is allowed at any time.

```c
uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
uint8_t random[SSF_PRNG_RANDOM_MAX_SIZE];
SSFPRNGContext_t context;

/* Stage 128 bits of entropy from a true random source */
/* entropy <---- hardware RNG or other true entropy source */

SSFPRNGInitContext(&context, entropy, sizeof(entropy));

while (true)
{
    SSFPRNGGetRandom(&context, random, sizeof(random));
    /* random now contains 16 bytes of pseudo-random data */

    /* Optionally reseed after generating a very large number of values */
    if (reseed)
    {
        /* entropy <---- hardware RNG */
        SSFPRNGInitContext(&context, entropy, sizeof(entropy));
    }
}
```

## Dependencies

- `ssf/ssfport.h`
- [ssfaes](ssfaes.md) — AES block cipher (used internally)

## Notes

- Cryptographic security depends entirely on the quality of the entropy provided to
  `SSFPRNGInitContext()`. Weak or predictable entropy produces weak output.
- A maximum of 16 bytes may be generated per `SSFPRNGGetRandom()` call.
- Re-seeding is useful if the system must generate a very large number of random values and
  there is concern about the 64-bit internal counter eventually repeating.
- The PRNG is NOT thread-safe; use separate contexts per thread or protect access externally.
