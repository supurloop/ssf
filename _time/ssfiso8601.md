# ssfiso8601 — ISO 8601 Date/Time String Interface

[Back to Time README](README.md) | [Back to ssf README](../README.md)

Converts between Unix time in system ticks and ISO 8601 extended date/time strings, including
local time zone offset support.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_ISO8601_ERR_STR` | `"0000-00-00T00:00:00"` | String written to the output buffer when a conversion fails |
| `SSF_ISO8601_ALLOW_FSEC_TRUNC` | `1` | `1` to truncate fractional seconds if the ISO string precision exceeds the system tick precision; `0` to fail |
| `SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX` | `1` | `1` to allow parsing ISO strings without a timezone field; `0` to fail |
| `SSF_ISO8601_EXHAUSTIVE_UNIT_TEST` | `0` | `1` to run an exhaustive unit test over every possible second (slow) |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFISO8601UnixToISO(unixSys, secPrecision, secPseudoPrecision, pseudoSecs, zone, zoneOffsetMin, outStr, outStrSize)` | Convert Unix time to an ISO 8601 string |
| `SSFISO8601ISOToUnix(inStr, unixSys, zoneOffsetMin)` | Parse an ISO 8601 string to Unix time |
| `SSFISO8601_MIN_SIZE` | Minimum output buffer size (20 bytes) |
| `SSFISO8601_MAX_SIZE` | Maximum output buffer size (36 bytes) |
| `SSF_ISO8601_ZONE_UTC` | Zone constant for UTC (`Z`) |
| `SSFISO8601_INVALID_ZONE_OFFSET` | Zone offset returned when no zone is present in the ISO string |

## Function Reference

### `SSFISO8601UnixToISO`

```c
bool SSFISO8601UnixToISO(SSFPortTick_t unixSys, bool secPrecision, bool secPseudoPrecision,
                         uint16_t pseudoSecs, SSFISO8601Zone_t zone, int16_t zoneOffsetMin,
                         SSFCStrOut_t outStr, size_t outStrSize);
```

Converts a Unix time value in system ticks to a null-terminated ISO 8601 extended datetime
string. The caller controls whether fractional seconds are included and how the timezone
is represented.

The output format is:

```
YYYY-MM-DDTHH:MM:SS[.FFF|.FFFFFF|.FFFFFFFFF][Z|+HH|+HH:MM|-HH|-HH:MM]
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSys` | in | `SSFPortTick_t` | Unix time in system ticks. |
| `secPrecision` | in | `bool` | `true` to include fractional seconds derived from the system tick sub-second value. `false` to omit fractional seconds (second-level precision only). |
| `secPseudoPrecision` | in | `bool` | `true` to insert a pseudo fractional-seconds field using `pseudoSecs` instead of the real sub-second value. Ignored when `secPrecision` is `true`. |
| `pseudoSecs` | in | `uint16_t` | Pseudo fractional-seconds value to use when `secPseudoPrecision` is `true`. Must be within the system tick sub-second range (0–`SSF_TS_FSEC_MAX`). |
| `zone` | in | `SSFISO8601Zone_t` | Timezone representation: `SSF_ISO8601_ZONE_UTC` appends `Z`; `SSF_ISO8601_ZONE_OFFSET_HH` appends `±HH`; `SSF_ISO8601_ZONE_OFFSET_HHMM` appends `±HH:MM`; `SSF_ISO8601_ZONE_LOCAL` omits the timezone field. |
| `zoneOffsetMin` | in | `int16_t` | Timezone offset in minutes from UTC. Positive for east-of-UTC zones (e.g., +330 for India). Ignored when `zone` is `SSF_ISO8601_ZONE_UTC` or `SSF_ISO8601_ZONE_LOCAL`. Valid range: −1439 to +1439. |
| `outStr` | out | `char *` | Buffer receiving the null-terminated ISO 8601 string. Must not be `NULL`. On failure, `SSF_ISO8601_ERR_STR` is written. |
| `outStrSize` | in | `size_t` | Allocated size of `outStr`. Must be at least `SSFISO8601_MAX_SIZE` (36) to guarantee all formats fit. |

**Returns:** `true` if the conversion succeeded; `false` if `unixSys` is out of range, `outStrSize` is too small, or another argument is invalid.

---

### `SSFISO8601ISOToUnix`

```c
bool SSFISO8601ISOToUnix(SSFCStrIn_t inStr, SSFPortTick_t *unixSys, int16_t *zoneOffsetMin);
```

Parses a null-terminated ISO 8601 extended datetime string and converts it to a Unix time value
in system ticks. Accepts the following optional components:

```
YYYY-MM-DDTHH:MM:SS[.FFF|.FFFFFF|.FFFFFFFFF][Z|+HH|+HH:MM|-HH|-HH:MM|(absent)]
```

When a timezone field is present, the returned `unixSys` is adjusted to UTC. When no timezone
is present and `SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1`, `unixSys` reflects the local
time without UTC adjustment and `*zoneOffsetMin` is set to `SSFISO8601_INVALID_ZONE_OFFSET`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `inStr` | in | `const char *` | Null-terminated ISO 8601 string to parse. Must not be `NULL`. |
| `unixSys` | out | `SSFPortTick_t *` | Receives the parsed Unix time in system ticks, adjusted to UTC when a timezone is present. Must not be `NULL`. |
| `zoneOffsetMin` | out | `int16_t *` | Receives the timezone offset in minutes. Set to `0` for UTC (`Z`), the parsed offset for `±HH`/`±HH:MM`, or `SSFISO8601_INVALID_ZONE_OFFSET` when no timezone field is present. Must not be `NULL`. |

**Returns:** `true` if parsing succeeded and `unixSys` was written; `false` if the string is malformed, the date/time is out of range, or the string has no timezone and `SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 0`.

## Usage

This is the only time interface in the framework that handles local time. The ISO 8601 extended
format is supported with the following optional fields (in order):

```
YYYY-MM-DDTHH:MM:SS[.FFF|.FFFFFF|.FFFFFFFFF][Z|+HH|+HH:MM|-HH|-HH:MM|(no zone)]
```

```c
SSFPortTick_t unixSys;
SSFPortTick_t unixSysOut;
int16_t zoneOffsetMin;
char isoStr[SSFISO8601_MAX_SIZE];

SSF_ASSERT(SSFRTCGetUnixNow(&unixSys));

/* Convert to UTC ISO string */
SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0,
                    isoStr, sizeof(isoStr));
/* isoStr looks like "2022-11-23T13:00:12Z" */

/* Parse back to Unix time */
SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin);
/* unixSys == unixSysOut, zoneOffsetMin == 0 */

/* Convert to local time string with +05:30 offset */
SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, 330,
                    isoStr, sizeof(isoStr));
/* isoStr looks like "2022-11-23T18:30:12+05:30" */
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`
- [ssfdtime](ssfdtime.md) — Date/time struct (used internally)

## Notes

- All inputs are strictly validated; invalid dates or out-of-range values return `false`.
- `SSF_TICKS_PER_SEC` must be 1000, 1,000,000, or 1,000,000,000.
- Daylight saving time is handled by the application adjusting `zoneOffsetMin` as needed.
- When `SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1` and no timezone is present, the returned
  `unixSys` may not be UTC-based; `zoneOffsetMin` is set to `SSFISO8601_INVALID_ZONE_OFFSET`.
- When a conversion fails, `SSF_ISO8601_ERR_STR` is written to the output buffer.
