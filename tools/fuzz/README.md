# Differential Fuzzing — SSF vs OpenSSL

Two libFuzzer harnesses compare SSF cryptographic primitives against
OpenSSL's reference implementations on randomly-mutated inputs, and a third
checks the UTF-8 codec against itself (see `fuzz_utf8` below). Any divergence
(SSF accepts and OpenSSL rejects, or outputs differ on the same input) aborts
immediately and writes the triggering input to disk for triage.

All harnesses run under ASan + UBSan, so any memory bug or undefined
behavior either side hits on adversarial input also surfaces as an abort.

## Targets

- `fuzz_aes_ctr` — compares `SSFAESCTR(key, ...)` against
  `EVP_aes_{128,192,256}_ctr` for random key/IV/plaintext combinations.
  Round-trip property checked (decrypt(encrypt(pt)) == pt).
- `fuzz_ecdsa_verify` — compares `SSFECDSAVerify(P-256, pubkey, hash, sig)`
  against `ECDSA_verify` for random `(pubkey, hash, sig)` triples. Catches
  disagreements on the boundary of valid/invalid.
- `fuzz_utf8` — self-consistency of the [`ssfutf8`](../../_codec/ssfutf8.md)
  codec on arbitrary bytes (no OpenSSL side): `SSFUTF8IsValid` is true exactly
  when `SSFUTF8DecodeNext` walks the whole input, `SSFUTF8Count` agrees with the
  walk, `allowNul` false refuses exactly the inputs holding U+0000, and every
  decoded code point is a scalar value that `SSFUTF8EncodeCP` re-encodes to the
  very bytes it came from (so only shortest forms decode).

## Running

Driver: `tools/fuzz/run.sh [<target>] [<seconds>]`

```sh
./tools/fuzz/run.sh                       # all targets, 60s each (default)
./tools/fuzz/run.sh aes_ctr 300           # AES-CTR for 5 min
./tools/fuzz/run.sh ecdsa_verify 86400    # ECDSA-verify for 24 hr
./tools/fuzz/run.sh utf8 300              # UTF-8 codec for 5 min
```

Builds inside a `gcc:latest` Docker container (apt-installs clang +
libssl-dev). Output goes to `build/fuzz/<target>/`. Crash inputs land at
`build/fuzz/<target>/crash-*` per libFuzzer convention.

The macOS-arm64 host can't run libFuzzer natively (same dyld init race
that affects ASan). Docker is the supported path on Apple Silicon. Linux
hosts can also build directly with clang + libssl-dev installed.

## Smoke results

Initial 30-second runs on first build (clang 19, gcc:latest container,
arm64 Linux under Docker on Apple Silicon):

| Target           | Inputs    | exec/s  | Divergences | Sanitizer aborts |
|------------------|-----------|---------|-------------|------------------|
| `fuzz_aes_ctr`   | 542,956   | 17,514  | 0           | 0                |
| `fuzz_ecdsa_verify` | 1,092,320 | 35,236  | 0           | 0                |

ECDSA-verify is faster per input because most random byte strings fail
pubkey decode early, exiting the verify path before the curve arithmetic.

## Seed corpus

`tools/fuzz/seed_aes_ctr/`, `tools/fuzz/seed_ecdsa_verify/` and
`tools/fuzz/seed_utf8/` hold seed inputs the fuzzer mutates from. The driver
creates a single zero-filled seed (for `utf8`, one sequence of each length and
the edges of the ill-formed ranges) if a directory has none. To accelerate a campaign:

- Copy NIST CAVS / RFC 3686 vectors into `seed_aes_ctr/` (one file per
  test case, raw byte layout matching the harness's input parser).
- Copy Wycheproof ECDSA vectors into `seed_ecdsa_verify/` (raw
  pubkey || hash || sig bytes, no separators).

The fuzzer will mutate around these to find adjacent-but-different
inputs that exercise new code paths.

## Triaging a crash

When libFuzzer aborts, it writes the crashing input to
`build/fuzz/<target>/crash-<sha1>`. Reproduce with:

```sh
./build/fuzz/<target>/fuzz_<target> build/fuzz/<target>/crash-<sha1>
```

The harness prints a `DIVERGENCE: ssf=… ossl=…` line before the abort.
For ASan/UBSan aborts you'll get a stack trace pointing at the offending
line in either SSF or OpenSSL.
