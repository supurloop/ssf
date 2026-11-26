# ssfhttphdr — HTTP/1.1 Message Head Codec

[SSF](../README.md) | [Network](README.md)

Builds HTTP/1.1 request heads and parses response heads (RFC 9112), with no I/O, no state and no
allocation. It is the head codec shared by SSF's HTTP users: the WebSocket handshake in
[`ssfnetws`](ssfnetws.md) today, and a full HTTP/1.1 client later. Message bodies
(`Content-Length`, chunked transfer coding) are deliberately not handled here; a body decoder
will be a separate set of pure functions in this module.

[Dependencies](#dependencies) | [Design](#design) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Known Trade-offs](#known-trade-offs)

<a id="dependencies"></a>

## [↑](#ssfhttphdr--http11-message-head-codec) Dependencies

- [`ssfport.h`](../ssfport.h), [`ssf.h`](../ssf.h), [`ssfassert.h`](../ssfassert.h)
- [`_codec/ssfstr.h`](../_codec/ssfstr.h) — bounded string length checks
- [`_opt/ssfhttp_opt.h`](../_opt/ssfhttp_opt.h) (aggregated through `ssfoptions.h`)

<a id="design"></a>

## [↑](#ssfhttphdr--http11-message-head-codec) Design

- **Building.** `SSFHTTPHdrReqBegin()` writes the request line and `Host`,
  `SSFHTTPHdrReqAddField()` appends one field line, and `SSFHTTPHdrReqEnd()` appends the empty
  line. Each returns `false` if the text would not fit or any string is not valid for its place;
  `Begin()` then sets the length to 0, and the others leave it unchanged. App strings therefore
  can never inject a CR, LF or NUL into the head (header injection, request splitting). Strings
  are NUL terminated, and the scan for each NUL stops one byte past the space the string could
  occupy. `Host` is written by `Begin()` only, and `AddField()` refuses any field named `Host`.
- **Strict parsing.** `SSFHTTPHdrParseResponse()` rejects a bare CR or LF, obs-fold (a field line
  starting with a space or tab), whitespace between a field name and its colon, a field name that
  is not a token, a control character in a value or reason phrase, a malformed status line and a
  head with more than `SSF_HTTP_CONFIG_MAX_FIELDS` fields. Lenient head parsing is what makes
  request smuggling and response splitting possible, so a future client gets this behaviour by
  default.
- **Incremental and stateless.** Call the parser again on the same buffer as more bytes arrive.
  It validates every byte it sees, so most malformed input is rejected before the head is
  complete. `INCOMPLETE` means "valid so far, more bytes needed"; a caller whose buffer is already
  full treats that as a head too large. `COMPLETE` gives `headLen`, and the bytes after it belong
  to the next layer (a body, or WebSocket frames) and are not examined.
- **Zero-copy fields.** Each parsed field is an offset and length into the caller's buffer, which
  must stay unchanged while the result is used. Values have surrounding whitespace removed. Names
  compare case-insensitively, and duplicate fields are kept in order, so
  `SSFHTTPHdrFindField()` can walk them and `SSFHTTPHdrFieldHasToken()` can search every
  comma-separated list.
- A head is at most `SSF_HTTP_HDR_MAX_HEAD_SIZE` (65535) bytes, so offsets fit in 16 bits.

<a id="configuration"></a>

## [↑](#ssfhttphdr--http11-message-head-codec) Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_HTTP_CONFIG_MAX_FIELDS` | `24` | Fields a parsed response head may hold, 1..255. A head with more is `MALFORMED`. Each costs 8 bytes in `SSFHTTPHdrResponse_t`. |

<a id="api-summary"></a>

## [↑](#ssfhttphdr--http11-message-head-codec) API Summary

<a id="functions"></a>

| | Function | Description |
|---|---|---|
| [e.g.](#ex-build) | [`bool SSFHTTPHdrReqBegin(buf, bufSize, lenOut, methodStr, targetStr, hostStr, portOpt)`](#ssfhttphdrreqbegin) | Write the request line and `Host` |
| [e.g.](#ex-build) | [`bool SSFHTTPHdrReqAddField(buf, bufSize, lenInOut, nameStr, valueStr)`](#ssfhttphdrreqaddfield) | Append one field line |
| [e.g.](#ex-build) | [`bool SSFHTTPHdrReqEnd(buf, bufSize, lenInOut)`](#ssfhttphdrreqend) | Append the empty line |
| [e.g.](#ex-parse) | [`SSFHTTPHdrParse_t SSFHTTPHdrParseResponse(buf, bufLen, respOut)`](#ssfhttphdrparseresponse) | Parse a response head |
| [e.g.](#ex-parse) | [`bool SSFHTTPHdrFindField(buf, resp, nameStr, indexInOut, valueOut, valueLenOut)`](#ssfhttphdrfindfield) | Find the next field with a name |
| | [`uint16_t SSFHTTPHdrFieldCount(buf, resp, nameStr)`](#ssfhttphdrfieldcount) | Count fields with a name |
| [e.g.](#ex-parse) | [`bool SSFHTTPHdrFieldIsOnly(buf, resp, nameStr, valueStr, isCaseInsensitive)`](#ssfhttphdrfieldisonly) | Exactly one field, with this value |
| [e.g.](#ex-parse) | [`bool SSFHTTPHdrFieldHasToken(buf, resp, nameStr, tokenStr)`](#ssfhttphdrfieldhastoken) | A list element equals a token |

<a id="function-reference"></a>

## [↑](#ssfhttphdr--http11-message-head-codec) Function Reference

<a id="ssfhttphdrreqbegin"></a>

### [↑](#functions) [`bool SSFHTTPHdrReqBegin()`](#functions)

```c
bool SSFHTTPHdrReqBegin(uint8_t *buf, size_t bufSize, size_t *lenOut, SSFCStrIn_t methodStr,
                        SSFCStrIn_t targetStr, SSFCStrIn_t hostStr, uint16_t portOpt);
```

Writes `method SP target SP HTTP/1.1 CRLF` and `Host: host[:port] CRLF` at `buf[0]`; `portOpt`
0 omits the port.

- `methodStr` is a token (RFC 9110 5.6.2).
- `targetStr` is made of URI characters (RFC 3986 unreserved, gen-delims except `#`, sub-delims),
  with well-formed `%XX` escapes. That covers origin form (`/a?b`), `*`, authority form
  (`host:443`) and absolute form.
- `hostStr` is a DNS name or IPv4 address: letters, digits, `-`, `.`, `_`, `~`. IPv6 is not
  supported (SSF is IPv4 only).

**Returns:** `true` with `*lenOut` set; `false`, with `*lenOut` 0, if any string is invalid or
the text does not fit in `bufSize` bytes. Asserts on a NULL pointer.

<a id="ssfhttphdrreqaddfield"></a>

### [↑](#functions) [`bool SSFHTTPHdrReqAddField()`](#functions)

```c
bool SSFHTTPHdrReqAddField(uint8_t *buf, size_t bufSize, size_t *lenInOut, SSFCStrIn_t nameStr,
                           SSFCStrIn_t valueStr);
```

Appends `name: value CRLF` at `buf[*lenInOut]`. `nameStr` is a token other than `Host`.
`valueStr` is made of visible characters, `obs-text` (0x80..0xFF), spaces and tabs, and may be
empty, but may not start or end with a space or tab.

**Returns:** `true` with `*lenInOut` advanced; `false` with it unchanged. Asserts on a NULL
pointer or `*lenInOut > bufSize`.

<a id="ssfhttphdrreqend"></a>

### [↑](#functions) [`bool SSFHTTPHdrReqEnd()`](#functions)

```c
bool SSFHTTPHdrReqEnd(uint8_t *buf, size_t bufSize, size_t *lenInOut);
```

Appends the empty line that ends the head.

**Returns:** `true` with `*lenInOut` advanced; `false` with it unchanged if 2 bytes do not fit.

<a id="ex-build"></a>

**Example:**

```c
uint8_t req[256];
size_t len;
bool ok;

ok = SSFHTTPHdrReqBegin(req, sizeof(req), &len, "GET", "/status", "device.example", 8080);
ok = ok && SSFHTTPHdrReqAddField(req, sizeof(req), &len, "Accept", "application/json");
ok = ok && SSFHTTPHdrReqEnd(req, sizeof(req), &len);
/* ok == true; req[0..len) == "GET /status HTTP/1.1\r\nHost: device.example:8080\r\n"
                              "Accept: application/json\r\n\r\n" */
```

---

<a id="ssfhttphdrparseresponse"></a>

### [↑](#functions) [`SSFHTTPHdrParse_t SSFHTTPHdrParseResponse()`](#functions)

```c
SSFHTTPHdrParse_t SSFHTTPHdrParseResponse(const uint8_t *buf, size_t bufLen,
                                          SSFHTTPHdrResponse_t *respOut);
```

Parses the response head at the start of `buf[0..len)`. The status line must be
`HTTP/x.y SP 3DIGIT`, optionally followed by `SP` and a reason phrase, with a status from 100 to
599. Only the first `SSF_HTTP_HDR_MAX_HEAD_SIZE` bytes are looked at. `buf` may be NULL only when
`bufLen` is 0.

**Returns:** `SSF_HTTP_HDR_COMPLETE` with `*respOut` filled (status, version, reason, fields,
`headLen`); `SSF_HTTP_HDR_INCOMPLETE` if no error so far and more bytes are needed;
`SSF_HTTP_HDR_MALFORMED` if the head is invalid or over a limit, in which case the stream is
unusable. `*respOut` is valid only on `COMPLETE`.

<a id="ssfhttphdrfindfield"></a>

### [↑](#functions) [`bool SSFHTTPHdrFindField()`](#functions)

```c
bool SSFHTTPHdrFindField(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp, SSFCStrIn_t nameStr,
                         uint16_t *indexInOut, const uint8_t **valueOut, size_t *valueLenOut);
```

Finds the first field named `nameStr` (case-insensitively) at or after index `*indexInOut`. `buf`
is the buffer that was parsed.

**Returns:** `true` with the value (not NUL terminated) and `*indexInOut` set to the index after
it, so repeated calls walk duplicates; `false` if there is no further match.

<a id="ssfhttphdrfieldcount"></a>

### [↑](#functions) [`uint16_t SSFHTTPHdrFieldCount()`](#functions)

```c
uint16_t SSFHTTPHdrFieldCount(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                              SSFCStrIn_t nameStr);
```

**Returns:** The number of fields named `nameStr`.

<a id="ssfhttphdrfieldisonly"></a>

### [↑](#functions) [`bool SSFHTTPHdrFieldIsOnly()`](#functions)

```c
bool SSFHTTPHdrFieldIsOnly(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                           SSFCStrIn_t nameStr, SSFCStrIn_t valueStr, bool isCaseInsensitive);
```

**Returns:** `true` if exactly one field is named `nameStr` and its whole value equals `valueStr`,
ASCII case-insensitively when `isCaseInsensitive`, else byte for byte. A duplicate field makes it
`false`, which is how a caller refuses an ambiguous response.

<a id="ssfhttphdrfieldhastoken"></a>

### [↑](#functions) [`bool SSFHTTPHdrFieldHasToken()`](#functions)

```c
bool SSFHTTPHdrFieldHasToken(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                             SSFCStrIn_t nameStr, SSFCStrIn_t tokenStr);
```

Searches the comma-separated lists (RFC 9110 5.6.1) in every field named `nameStr`. Elements are
trimmed of surrounding whitespace, and empty elements are skipped.

**Returns:** `true` if any element equals `tokenStr` case-insensitively; `false` for an empty token.

<a id="ex-parse"></a>

**Example:**

```c
static const char rx[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         "Connection: keep-alive, Upgrade\r\n\r\n";
SSFHTTPHdrResponse_t resp;
const uint8_t *b = (const uint8_t *)rx;

if ((SSFHTTPHdrParseResponse(b, sizeof(rx) - 1, &resp) == SSF_HTTP_HDR_COMPLETE) &&
    (resp.status == 101) &&
    SSFHTTPHdrFieldIsOnly(b, &resp, "upgrade", "websocket", true) &&
    SSFHTTPHdrFieldHasToken(b, &resp, "connection", "upgrade"))
{
    /* upgraded */
}
```

<a id="known-trade-offs"></a>

## [↑](#ssfhttphdr--http11-message-head-codec) Known Trade-offs

- **obs-fold is rejected, not unfolded.** RFC 9112 5.2 asks a user agent to replace an obs-fold
  in a response with spaces. Unfolding cannot be zero-copy, and servers have not sent folded
  lines in practice for years, so a folded response is `MALFORMED`.
- **No bare-LF tolerance.** RFC 9112 2.2 allows a recipient to accept a bare LF as a line end.
  This parser does not, because inconsistent line-end handling between parties is a smuggling
  vector.
- **Responses only.** There is no request parser and no request-line builder for a server.
- **Re-parsing is quadratic in the worst case.** The parser is stateless, so a caller re-parses
  the whole buffer each time bytes arrive. A server that sends one byte per segment costs
  O(n²) byte steps: about 0.5 M for ssfnetws' 1 KB handshake buffer, but about 2 G for a 64 KB
  head on a slow CPU. A future HTTP client with large head buffers should resume parsing from
  the last complete line, or cap the head size well below the maximum.
- **1xx responses come back `COMPLETE`.** A client must skip interim responses (RFC 9110 15.2)
  and parse the next head. ssfnetws needs exactly a 101, so this does not affect it.
- **The target's form is not matched to the method.** `GET *` or `GET host:443` builds; the
  caller picks the form.
- **The reason phrase is returned raw,** including a leading tab or trailing whitespace.
  Clients should ignore it anyway (RFC 9112 4).
