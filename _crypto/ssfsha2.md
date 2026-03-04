# ssfsha2 — SHA-2 Hash

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

SHA-2 hash interface supporting SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFSHA256(in, inLen, out, outSize)` | Compute SHA-256 hash (one-shot) |
| `SSFSHA224(in, inLen, out, outSize)` | Compute SHA-224 hash (one-shot) |
| `SSFSHA512(in, inLen, out, outSize)` | Compute SHA-512 hash (one-shot) |
| `SSFSHA384(in, inLen, out, outSize)` | Compute SHA-384 hash (one-shot) |
| `SSFSHA512_224(in, inLen, out, outSize)` | Compute SHA-512/224 hash (one-shot) |
| `SSFSHA512_256(in, inLen, out, outSize)` | Compute SHA-512/256 hash (one-shot) |
| `SSFSHA256Begin/Update/End` | Incremental SHA-256 interface |
| `SSFSHA224Begin/Update/End` | Incremental SHA-224 interface |
| `SSFSHA512Begin/Update/End` | Incremental SHA-512 interface |
| `SSFSHA384Begin/Update/End` | Incremental SHA-384 interface |
| `SSFSHA512_224Begin/Update/End` | Incremental SHA-512/224 interface |
| `SSFSHA512_256Begin/Update/End` | Incremental SHA-512/256 interface |
| `SSF_SHA2_256_BYTE_SIZE` | Output size constant for SHA-256 (32 bytes) |
| `SSF_SHA2_224_BYTE_SIZE` | Output size constant for SHA-224 (28 bytes) |
| `SSF_SHA2_512_BYTE_SIZE` | Output size constant for SHA-512 (64 bytes) |
| `SSF_SHA2_384_BYTE_SIZE` | Output size constant for SHA-384 (48 bytes) |
| `SSF_SHA2_512_224_BYTE_SIZE` | Output size constant for SHA-512/224 (28 bytes) |
| `SSF_SHA2_512_256_BYTE_SIZE` | Output size constant for SHA-512/256 (32 bytes) |

## Function Reference

### `SSFSHA2_32` (base function)

```c
void SSFSHA2_32(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize);
```

One-shot SHA-2 hash using the 32-bit (512-bit block) engine. Computes SHA-256 or SHA-224 over
`inLen` bytes of `in` in a single call. Use the `SSFSHA256` or `SSFSHA224` macros instead of
calling this function directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the data to hash. Must not be `NULL` unless `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes to hash from `in`. |
| `out` | out | `uint8_t *` | Buffer receiving the hash output. Must not be `NULL`. |
| `outSize` | in | `uint32_t` | Allocated size of `out`. Must be at least `SSF_SHA2_256_BYTE_SIZE` (32) for SHA-256 or `SSF_SHA2_224_BYTE_SIZE` (28) for SHA-224. |
| `hashBitSize` | in | `uint16_t` | Hash variant: `256` for SHA-256, `224` for SHA-224. |

**Returns:** Nothing.

---

### `SSFSHA256` / `SSFSHA224`

```c
#define SSFSHA256(in, inLen, out, outSize) SSFSHA2_32(in, inLen, out, outSize, 256)
#define SSFSHA224(in, inLen, out, outSize) SSFSHA2_32(in, inLen, out, outSize, 224)
```

Convenience macros for one-shot SHA-256 and SHA-224. Parameters and return value are identical to
`SSFSHA2_32` above (without the `hashBitSize` argument).

---

### `SSFSHA2_64` (base function)

```c
void SSFSHA2_64(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize, uint16_t truncationBitSize);
```

One-shot SHA-2 hash using the 64-bit (1024-bit block) engine. Computes SHA-512, SHA-384,
SHA-512/224, or SHA-512/256. Use the corresponding named macros instead of calling this directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the data to hash. Must not be `NULL` unless `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes to hash from `in`. |
| `out` | out | `uint8_t *` | Buffer receiving the hash output. Must not be `NULL`. |
| `outSize` | in | `uint32_t` | Allocated size of `out`. Must be at least the output size of the chosen variant. |
| `hashBitSize` | in | `uint16_t` | Hash variant: `512` for SHA-512 and its truncated variants; `384` for SHA-384. |
| `truncationBitSize` | in | `uint16_t` | Truncation: `0` for full output (SHA-512 or SHA-384), `256` for SHA-512/256, `224` for SHA-512/224. |

**Returns:** Nothing.

---

### `SSFSHA512` / `SSFSHA384` / `SSFSHA512_256` / `SSFSHA512_224`

```c
#define SSFSHA512(in, inLen, out, outSize)     SSFSHA2_64(in, inLen, out, outSize, 512, 0)
#define SSFSHA384(in, inLen, out, outSize)     SSFSHA2_64(in, inLen, out, outSize, 384, 0)
#define SSFSHA512_256(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 256)
#define SSFSHA512_224(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 224)
```

Convenience macros for one-shot SHA-512, SHA-384, SHA-512/256, and SHA-512/224. Parameters and
return value are identical to `SSFSHA2_64` (without `hashBitSize` and `truncationBitSize`).

---

### `SSFSHA2_32Begin` / `SSFSHA2_32Update` / `SSFSHA2_32End`

```c
void SSFSHA2_32Begin(SSFSHA2_32Context_t *context, uint16_t hashBitSize);
void SSFSHA2_32Update(SSFSHA2_32Context_t *context, const uint8_t *in, uint32_t inLen);
void SSFSHA2_32End(SSFSHA2_32Context_t *context, uint8_t *out, uint32_t outSize);
```

Incremental interface for SHA-256 and SHA-224. Call `Begin` to initialize the context, call
`Update` one or more times to feed data, then call `End` to obtain the final hash. Use the
`SSFSHA256Begin/Update/End` or `SSFSHA224Begin/Update/End` macros in preference to calling these
functions directly.

**`SSFSHA2_32Begin` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | out | `SSFSHA2_32Context_t *` | Pointer to the context to initialize. Must not be `NULL`. |
| `hashBitSize` | in | `uint16_t` | Hash variant: `256` for SHA-256, `224` for SHA-224. |

**`SSFSHA2_32Update` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFSHA2_32Context_t *` | Pointer to an initialized context. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Pointer to the next chunk of data to hash. Must not be `NULL` unless `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes in this chunk. |

**`SSFSHA2_32End` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFSHA2_32Context_t *` | Pointer to the context. Invalidated after this call. Must not be `NULL`. |
| `out` | out | `uint8_t *` | Buffer receiving the final hash. Must not be `NULL`. |
| `outSize` | in | `uint32_t` | Allocated size of `out`. Must be at least `SSF_SHA2_256_BYTE_SIZE` (32) or `SSF_SHA2_224_BYTE_SIZE` (28) for the chosen variant. |

All three functions **return:** Nothing.

---

### `SSFSHA256Begin/Update/End` and `SSFSHA224Begin/Update/End`

```c
#define SSFSHA256Begin(context)             SSFSHA2_32Begin(context, 256)
#define SSFSHA256Update(context, in, inLen) SSFSHA2_32Update(context, in, inLen)
#define SSFSHA256End(context, out, outSize) SSFSHA2_32End(context, out, outSize)

#define SSFSHA224Begin(context)             SSFSHA2_32Begin(context, 224)
#define SSFSHA224Update(context, in, inLen) SSFSHA2_32Update(context, in, inLen)
#define SSFSHA224End(context, out, outSize) SSFSHA2_32End(context, out, outSize)
```

Convenience macros for the incremental SHA-256 and SHA-224 interface.

---

### `SSFSHA2_64Begin` / `SSFSHA2_64Update` / `SSFSHA2_64End`

```c
void SSFSHA2_64Begin(SSFSHA2_64Context_t *context, uint16_t hashBitSize,
                     uint16_t truncationBitSize);
void SSFSHA2_64Update(SSFSHA2_64Context_t *context, const uint8_t *in, uint32_t inLen);
void SSFSHA2_64End(SSFSHA2_64Context_t *context, uint8_t *out, uint32_t outSize);
```

Incremental interface for SHA-512, SHA-384, SHA-512/256, and SHA-512/224. Use the
`SSFSHA512Begin/Update/End`, `SSFSHA384Begin/Update/End`, `SSFSHA512_256Begin/Update/End`, or
`SSFSHA512_224Begin/Update/End` macros in preference to calling these directly.

**`SSFSHA2_64Begin` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | out | `SSFSHA2_64Context_t *` | Pointer to the context to initialize. Must not be `NULL`. |
| `hashBitSize` | in | `uint16_t` | `512` for SHA-512 variants; `384` for SHA-384. |
| `truncationBitSize` | in | `uint16_t` | `0` for full output, `256` for SHA-512/256, `224` for SHA-512/224. |

**`SSFSHA2_64Update` parameters** are identical to `SSFSHA2_32Update` but use `SSFSHA2_64Context_t`.

**`SSFSHA2_64End` parameters** are identical to `SSFSHA2_32End` but use `SSFSHA2_64Context_t`; `outSize` must be at least the output size of the chosen variant.

All three functions **return:** Nothing.

---

### `SSFSHA512/384/512_256/512_224 Begin/Update/End`

```c
#define SSFSHA512Begin(context)             SSFSHA2_64Begin(context, 512, 0)
#define SSFSHA512Update(context, in, inLen) SSFSHA2_64Update(context, in, inLen)
#define SSFSHA512End(context, out, outSize) SSFSHA2_64End(context, out, outSize)
/* (similar macros defined for SHA384, SHA512_256, SHA512_224) */
```

Convenience macros for the incremental SHA-512 family interface.

## Usage

The macros simplify calling the two base functions that implement all six SHA-2 variants.

```c
uint8_t out[SSF_SHA2_256_BYTE_SIZE];

/* One-shot */
SSFSHA256("abc", 3, out, sizeof(out));
/* out == SHA-256("abc") */

/* Incremental */
SSFSHA2_32Context_t ctx;
SSFSHA256Begin(&ctx);
SSFSHA256Update(&ctx, "ab", 2);
SSFSHA256Update(&ctx, "c", 1);
SSFSHA256End(&ctx, out, sizeof(out));
/* out == same SHA-256("abc") as above */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- The output buffer must be at least as large as the hash output size for the chosen variant.
- The `SSF_SHA2_*_BYTE_SIZE` constants are provided for sizing output buffers.
- The incremental interface allows hashing data that arrives in multiple chunks without buffering
  the entire input.
