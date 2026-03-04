# ssfgobj — Generic Object Parser/Generator (BETA)

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Hierarchical generic object parser and generator. Designed as a common in-memory representation
that can translate between JSON, UBJSON, and other encoding types.

> **Note:** This interface is in BETA and still under development. The API may change.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_GOBJ_CONFIG_MAX_IN_DEPTH` | `4` | Maximum nesting depth for objects and arrays |

## API Summary

API is still being finalized. Refer to `ssfgobj.h` for the current interface.

## Usage

This interface allows a generic hierarchical object structure to be generated and parsed. It is
meant to be a flexible in-memory representation that can easily translate between encoding types
like JSON and UBJSON, and provides more flexibility for modifying data elements than operating
directly on serialized strings.

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- This module is in BETA; expect API changes in future releases.
- Nesting depth is limited by `SSF_GOBJ_CONFIG_MAX_IN_DEPTH`.
