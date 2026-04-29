# ssfprng — Pseudo Random Number Generator

[SSF](../README.md) | [Cryptography](README.md)

Cryptographically secure capable PRNG based on AES-CTR mode with a 128-bit seed.

Each call to `SSFPRNGGetRandom()` internally encrypts a monotonically increasing 64-bit counter
(zero-padded to 128 bits) with the stored entropy as the AES-128 key, producing up to 16 bytes of
pseudo-random output. Security depends entirely on the quality of the entropy supplied to
`SSFPRNGInitContext()`.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfprng--pseudo-random-number-generator) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfaes`](ssfaes.md) — AES block cipher used internally

<a id="notes"></a>

## [↑](#ssfprng--pseudo-random-number-generator) Notes

- **Timing attack warning — seed recovery, not just per-call leakage.** This implementation
  uses the timing-attack-vulnerable [`ssfaes`](ssfaes.md) block cipher with the entropy as
  the AES-128 key. In an ordinary AES use, recovering the key via timing observation
  compromises only the message protected with that key. Here, **the AES key IS the PRNG
  seed**: an attacker who recovers the key from timing observations can predict every future
  PRNG output (the counter is monotonic, so the keystream is deterministic) and reproduce
  every past output (the counter is recoverable). Any keys, nonces, IVs, or other secrets
  the higher-level code derived from this PRNG become predictable. Do not use in
  environments where an attacker can observe precise execution times unless the consuming
  application is explicitly designed to tolerate seed-recovery (e.g., one-shot use with
  immediate re-seed from a fresh entropy source).
- Cryptographic security depends entirely on the quality of the entropy provided to
  `SSFPRNGInitContext()`. Weak or predictable entropy produces weak output.
- Each `SSFPRNGGetRandom()` call advances the internal counter by one regardless of `randomSize`;
  unused bytes from the AES block are discarded.
- Re-seed with `SSFPRNGReInitContext()` when there is concern about the 64-bit counter eventually
  exhausting its period or when fresh entropy becomes available.
- The PRNG is not thread-safe; use separate contexts per thread or protect access with a mutex.
- Call `SSFPRNGDeInitContext()` when finished to clear the seed material from memory.

<a id="configuration"></a>

## [↑](#ssfprng--pseudo-random-number-generator) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfprng--pseudo-random-number-generator) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-prng-entropy-size"></a>`SSF_PRNG_ENTROPY_SIZE` | Constant | `16` — required size in bytes of the entropy buffer passed to `SSFPRNGInitContext()` and `SSFPRNGReInitContext()` |
| <a id="ssf-prng-random-max-size"></a>`SSF_PRNG_RANDOM_MAX_SIZE` | Constant | `16` — maximum number of bytes that can be requested in a single `SSFPRNGGetRandom()` call |
| <a id="ssfprngcontext-t"></a>`SSFPRNGContext_t` | Struct | PRNG context holding the entropy seed, internal counter, and state marker. Treat as opaque; pass by pointer to all API functions. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFPRNGInitContext(context, entropy, entropyLen)`](#ssfprnginitcontext) | Initialize a PRNG context with 16 bytes of entropy |
| [e.g.](#ex-reinit) | [`void SSFPRNGReInitContext(context, entropy, entropyLen)`](#ssfprngreinitcontext) | Re-seed an existing context with fresh entropy (alias for `SSFPRNGInitContext`) |
| [e.g.](#ex-deinit) | [`void SSFPRNGDeInitContext(context)`](#ssfprnginitcontext) | De-initialize a context and clear its internal state |
| [e.g.](#ex-getrandom) | [`void SSFPRNGGetRandom(context, random, randomSize)`](#ssfprnggetrandom) | Generate 1–16 bytes of pseudo-random data |

<a id="function-reference"></a>

## [↑](#ssfprng--pseudo-random-number-generator) Function Reference

<a id="ssfprnginitcontext"></a>

### [↑](#functions) [`void SSFPRNGInitContext()`](#functions)

```c
void SSFPRNGInitContext(SSFPRNGContext_t *context, const uint8_t *entropy, size_t entropyLen);
```

Initializes a PRNG context using `entropy` as the 128-bit AES key and resets the internal counter
to zero. May also be called on an already-initialized context to re-seed it; the behaviour is
identical to [`SSFPRNGReInitContext()`](#ssfprngreinitcontext). After this call the context is
ready for use with `SSFPRNGGetRandom()`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | out | `SSFPRNGContext_t *` | Pointer to the context to initialize. Must not be `NULL`. |
| `entropy` | in | `const uint8_t *` | Pointer to [`SSF_PRNG_ENTROPY_SIZE`](#ssf-prng-entropy-size) (16) bytes of entropy. Must not be `NULL`. The quality of the PRNG output depends entirely on the quality of this data. |
| `entropyLen` | in | `size_t` | Must equal [`SSF_PRNG_ENTROPY_SIZE`](#ssf-prng-entropy-size) (16). |

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
uint8_t         entropy[SSF_PRNG_ENTROPY_SIZE];
SSFPRNGContext_t ctx;

/* Obtain 16 bytes of true entropy from a hardware source */
/* entropy <--- hardware RNG or other true entropy source */

SSFPRNGInitContext(&ctx, entropy, sizeof(entropy));
/* ctx is ready; call SSFPRNGGetRandom() to produce random bytes */
```

---

<a id="ssfprngreinitcontext"></a>

### [↑](#functions) [`void SSFPRNGReInitContext()`](#functions)

```c
#define SSFPRNGReInitContext SSFPRNGInitContext
```

Alias for [`SSFPRNGInitContext()`](#ssfprnginitcontext). Re-seeds an existing context with fresh
entropy and resets the internal counter. Functionally identical to `SSFPRNGInitContext()`; the
separate name improves readability at re-seed call sites. Parameters and return value are the same
as [`SSFPRNGInitContext()`](#ssfprnginitcontext).

<a id="ex-reinit"></a>

**Example:**

```c
uint8_t         entropy[SSF_PRNG_ENTROPY_SIZE];
SSFPRNGContext_t ctx;

/* entropy <--- hardware RNG */
SSFPRNGInitContext(&ctx, entropy, sizeof(entropy));

/* ... generate many random values ... */

/* Re-seed with fresh entropy to reset the counter and update the key */
/* entropy <--- hardware RNG */
SSFPRNGReInitContext(&ctx, entropy, sizeof(entropy));
/* ctx counter reset to zero; subsequent calls use the new seed */
```

---

<a id="ssfprngdeinitcontext"></a>

### [↑](#functions) [`void SSFPRNGDeInitContext()`](#functions)

```c
void SSFPRNGDeInitContext(SSFPRNGContext_t *context);
```

De-initializes a PRNG context, zeroing the entropy seed, counter, and state marker. Call this
when the context is no longer needed so that seed material does not remain in memory. After this
call, `SSFPRNGGetRandom()` must not be used until `SSFPRNGInitContext()` is called again.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFPRNGContext_t *` | Pointer to an initialized context to de-initialize. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
uint8_t         entropy[SSF_PRNG_ENTROPY_SIZE];
SSFPRNGContext_t ctx;

/* entropy <--- hardware RNG */
SSFPRNGInitContext(&ctx, entropy, sizeof(entropy));
/* ... use ctx ... */
SSFPRNGDeInitContext(&ctx);
/* ctx internal state zeroed; entropy seed no longer in memory */
```

---

<a id="ssfprnggetrandom"></a>

### [↑](#functions) [`void SSFPRNGGetRandom()`](#functions)

```c
void SSFPRNGGetRandom(SSFPRNGContext_t *context, uint8_t *random, size_t randomSize);
```

Generates `randomSize` pseudo-random bytes into `random`. Internally, encrypts the current 64-bit
counter (zero-padded to 128 bits) with the stored entropy as the AES-128 key, writes the first
`randomSize` bytes of the result to `random`, then increments the counter. Unused bytes from the
AES block are discarded; the counter always advances by one per call.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFPRNGContext_t *` | Pointer to an initialized context. Must not be `NULL`. |
| `random` | out | `uint8_t *` | Buffer receiving the pseudo-random bytes. Must not be `NULL`. |
| `randomSize` | in | `size_t` | Number of bytes to generate. Must be between `1` and [`SSF_PRNG_RANDOM_MAX_SIZE`](#ssf-prng-random-max-size) (16) inclusive. |

**Returns:** Nothing.

<a id="ex-getrandom"></a>

**Example:**

```c
uint8_t         entropy[SSF_PRNG_ENTROPY_SIZE];
SSFPRNGContext_t ctx;
uint8_t random16[SSF_PRNG_RANDOM_MAX_SIZE];
uint8_t random8[8];
uint8_t random1[1];

/* entropy <--- hardware RNG */
SSFPRNGInitContext(&ctx, entropy, sizeof(entropy));

/* Generate a full 16-byte block */
SSFPRNGGetRandom(&ctx, random16, sizeof(random16));

/* Generate any size from 1 to SSF_PRNG_RANDOM_MAX_SIZE; counter advances by 1 each call */
SSFPRNGGetRandom(&ctx, random8, sizeof(random8));
SSFPRNGGetRandom(&ctx, random1, sizeof(random1));

SSFPRNGDeInitContext(&ctx);
```
