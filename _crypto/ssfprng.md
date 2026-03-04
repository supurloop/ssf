# ssfprng — Pseudo Random Number Generator

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

Cryptographically secure capable PRNG based on AES-CTR mode with a 128-bit seed.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFPRNGInitContext(ctx, entropy, entropyLen)` | Initialize a PRNG context with entropy |
| `SSFPRNGReInitContext(ctx, entropy, entropyLen)` | Re-seed an existing context (alias of Init) |
| `SSFPRNGDeInitContext(ctx)` | De-initialize a PRNG context |
| `SSFPRNGGetRandom(ctx, out, outSize)` | Generate 1–16 bytes of pseudo-random data |
| `SSF_PRNG_ENTROPY_SIZE` | Required entropy buffer size (16 bytes) |
| `SSF_PRNG_RANDOM_MAX_SIZE` | Maximum bytes per `SSFPRNGGetRandom()` call (16 bytes) |

## Function Reference

### `SSFPRNGInitContext`

```c
void SSFPRNGInitContext(SSFPRNGContext_t *context, const uint8_t *entropy, size_t entropyLen);
```

Initializes a PRNG context using the provided entropy as the 128-bit seed. The context holds the
seed and an internal 64-bit counter that advances with each call to `SSFPRNGGetRandom()`. May also
be called on an already-initialized context to reseed it (identical behavior to
`SSFPRNGReInitContext`).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | out | `SSFPRNGContext_t *` | Pointer to the context to initialize. Must not be `NULL`. |
| `entropy` | in | `const uint8_t *` | Pointer to `SSF_PRNG_ENTROPY_SIZE` (16) bytes of entropy. Must not be `NULL`. The quality of the random output depends entirely on the quality of this entropy. |
| `entropyLen` | in | `size_t` | Must equal `SSF_PRNG_ENTROPY_SIZE` (16). |

**Returns:** Nothing.

---

### `SSFPRNGReInitContext`

```c
#define SSFPRNGReInitContext SSFPRNGInitContext
```

Alias for `SSFPRNGInitContext`. Re-seeds an existing context with fresh entropy. Functionally
identical; the separate name improves code readability at re-seed call sites.

---

### `SSFPRNGDeInitContext`

```c
void SSFPRNGDeInitContext(SSFPRNGContext_t *context);
```

De-initializes a PRNG context, clearing its internal state and magic marker. Call this when the
context is no longer needed to prevent the seed material from remaining in memory.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFPRNGContext_t *` | Pointer to the context to de-initialize. Must not be `NULL`. |

**Returns:** Nothing.

---

### `SSFPRNGGetRandom`

```c
void SSFPRNGGetRandom(SSFPRNGContext_t *context, uint8_t *random, size_t randomSize);
```

Generates pseudo-random bytes into `random`. Internally encrypts the current 64-bit counter
(zero-padded to 128 bits) using AES with the stored entropy as the key, then increments the
counter. Each call advances the counter regardless of `randomSize`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFPRNGContext_t *` | Pointer to an initialized context. Must not be `NULL`. |
| `random` | out | `uint8_t *` | Buffer receiving the pseudo-random bytes. Must not be `NULL`. |
| `randomSize` | in | `size_t` | Number of bytes to generate. Must be between 1 and `SSF_PRNG_RANDOM_MAX_SIZE` (16) inclusive. |

**Returns:** Nothing.

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
        SSFPRNGReInitContext(&context, entropy, sizeof(entropy));
    }
}

SSFPRNGDeInitContext(&context);
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
