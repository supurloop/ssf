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
| `SSFISO8601UnixToISO(unixSys, addFsec, addPseudoFsec, pseudoFsecMs, zone, zoneOffsetMin, out, outSize)` | Convert Unix time to an ISO 8601 string |
| `SSFISO8601ISOToUnix(isoStr, unixSys, zoneOffsetMin)` | Parse an ISO 8601 string to Unix time |
| `SSFISO8601_MAX_SIZE` | Maximum output string buffer size |
| `SSF_ISO8601_ZONE_UTC` | Zone constant for UTC (`Z`) |
| `SSFISO8601_INVALID_ZONE_OFFSET` | Zone offset returned when no zone is present in the ISO string |

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
