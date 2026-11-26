# ssfnetws — WebSocket Client Transport

[SSF](../README.md) | [Network](README.md)

An [`ssfnet`](ssfnet.h) transport that carries a byte stream inside WebSocket binary messages
(RFC 6455) over another transport: [`ssfnetsock`](ssfnetsock.h) for `ws://`, or
[`ssftlsc`](ssftlsc.h) over `ssfnetsock` for `wss://`. A client such as
[`ssfmqttc`](ssfmqttc.md) uses it like any other transport and sees only the stream. That
provides MQTT over WebSockets (MQTT 3.1.1 section 6) with no change to the MQTT client: it is
useful where only HTTP(S) ports are open, or where a broker serves MQTT only on a WebSocket
listener.

```
ssfmqttc ──► ssfnetws ──► ssftlsc ──► ssfnetsock      wss://host:443/mqtt
ssfmqttc ──► ssfnetws ──► ssfnetsock                  ws://host:8080/mqtt
```

[Dependencies](#dependencies) | [Design](#design) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Known Trade-offs](#known-trade-offs)

<a id="dependencies"></a>

## [↑](#ssfnetws--websocket-client-transport) Dependencies

- [`ssfport.h`](../ssfport.h) (`SSFPortGetEntropy()`), [`ssf.h`](../ssf.h), [`ssfassert.h`](../ssfassert.h)
- [`ssfnet.h`](ssfnet.h) — the transport interface it implements and consumes
- [`ssfhttphdr.h`](ssfhttphdr.md) — builds the Upgrade request and parses the response
- [`_crypto/ssfsha1.h`](../_crypto/ssfsha1.md), [`_codec/ssfbase64.h`](../_codec/ssfbase64.md) — `Sec-WebSocket-Key` / `Sec-WebSocket-Accept`
- [`_crypto/ssfprng.h`](../_crypto/ssfprng.h) — frame mask keys; [`_crypto/ssfcrypt.h`](../_crypto/ssfcrypt.h) — buffer wiping
- [`_codec/ssfstr.h`](../_codec/ssfstr.h)
- [`_opt/ssfnetws_opt.h`](../_opt/ssfnetws_opt.h), [`_opt/ssfhttp_opt.h`](../_opt/ssfhttp_opt.h) (aggregated through `ssfoptions.h`)

<a id="design"></a>

## [↑](#ssfnetws--websocket-client-transport) Design

- **Open.** `open()` validates the host and port, builds the HTTP/1.1 Upgrade request, and opens
  the inner transport. A bad path, bad extra field or oversized request makes `open()` return
  `false` before anything is sent. `pollOpen()` finishes the inner open, writes the request, then
  reads and checks the response. The request offers subprotocol `mqtt`, version 13 and no
  extensions:
  ```
  GET <path> HTTP/1.1
  Host: <host>[:<port>]
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Key: <base64 of 16 random bytes>
  Sec-WebSocket-Version: 13
  Sec-WebSocket-Protocol: mqtt
  <extra fields>
  ```
- **The response must accept exactly that.** Status 101 and HTTP/1.1; exactly one
  `Upgrade: websocket` (case-insensitive); `Connection` listing `upgrade`; exactly one correct
  `Sec-WebSocket-Accept`; no `Sec-WebSocket-Extensions`; and `Sec-WebSocket-Protocol` either
  absent or exactly one `mqtt`. Anything else, including a redirect or an auth challenge, fails
  the open with `ERROR`. The response head is parsed strictly by `ssfhttphdr`.
- **send()** frames up to `SSF_NETWS_CONFIG_TX_FRAME_SIZE` bytes per call as one masked binary
  frame. Each frame gets a fresh mask key from an ssfprng context seeded from
  `SSFPortGetEntropy()` at each `open()`. Accepted bytes may wait in the frame buffer until a
  later `send()`, `recv()` or `shutdown()` writes them out, the same contract TLS records follow
  in `ssftlsc`. RAM is fixed: the larger of the frame size and 125 (a Pong), plus 14 bytes.
- **recv()** strips framing and returns payload bytes as a stream. A message may span frames and a
  read may span messages, so nothing assumes the inner protocol lines up with frames (MQTT 3.1.1
  section 6). Frames of any length stream through the staging buffer to the caller, so none is
  ever held whole.
- **Control frames.** A Ping is answered with a masked Pong. Only the latest Ping is answered if
  several arrive before the frame buffer is free (RFC 6455 5.5.3). A Pong is ignored. A Close is
  echoed with its status code, and the stream then ends with `CLOSED`. Control frames are only
  sent between whole frames.
- **Protocol errors fail the connection with `ERROR`:**
  - a text frame (MQTT requires binary), a reserved opcode, or RSV bits set;
  - a masked server frame;
  - a fragmented control frame, or one with more than 125 bytes;
  - a continuation with no message open, or a new message inside one;
  - a 64-bit length with the top bit set;
  - a Close with a 1-byte payload, or a code an endpoint may not send (RFC 6455 7.4): anything
    but 1000..1003, 1007..1014 and 3000..4999, so 1005, 1006 and 1015 included.

  Payload already received in the same `recv()` is returned first, and the next call returns
  `ERROR`. A protocol error is answered with one best-effort Close 1002 (RFC 6455 7.1.7); a
  failure of the inner transport or the handshake sends nothing.
- **Ending.** `shutdown()` writes out any buffered frame, sends Close 1000, then shuts down the
  inner transport. After that, `send()` returns `ERROR`, but `recv()` still works until the
  server's Close. `close()` makes one best-effort attempt at the same Close, then closes the
  inner transport and wipes the session's buffers.
- **Secrets.** Extra fields may carry credentials (`Authorization`). The handshake buffer is
  wiped as soon as the request is sent, and the whole connection state is wiped on `close()`.
- **Handshake seam.** The handshake is two internal steps (send a request head; get a checked 101
  and the bytes after it). They can move onto a future HTTP/1.1 client, which would add
  redirects and auth challenges, without touching the framing.
- IPv4 only, like every ssfnet transport. `Host` carries the port unless it is 80 or 443.

<a id="configuration"></a>

## [↑](#ssfnetws--websocket-client-transport) Configuration

Options live in [`_opt/ssfnetws_opt.h`](../_opt/ssfnetws_opt.h); each can be overridden with `-D`.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_NETWS_CONFIG_MAX_HOST_SIZE` | `256` | Host names passed to `open()`, including the NUL, 2..256. A longer host makes `open()` return false. |
| `SSF_NETWS_CONFIG_HS_BUF_SIZE` | `1024` | Holds the Upgrade request (path and extra fields included), then the response head, then serves as the receive staging buffer. 256..65535. A request that does not fit makes `open()` return false; a response head that does not fit fails the handshake. A long query string, such as an AWS SigV4 presigned path, may need more. |
| `SSF_NETWS_CONFIG_TX_FRAME_SIZE` | `256` | Largest payload of one outbound frame, 1..65535. Each `send()` frames at most this many bytes; a larger write is split across calls. Overhead is 6 bytes per frame up to 125, else 8. |
| `SSF_HTTP_CONFIG_MAX_FIELDS` | `24` | From [`ssfhttphdr`](ssfhttphdr.md): fields the response head may hold. |

`SSFNetWSSession_t` is about `HS_BUF_SIZE + TX_FRAME_SIZE + MAX_HOST_SIZE + 400` bytes; with the
defaults, about 2 KB.

<a id="api-summary"></a>

## [↑](#ssfnetws--websocket-client-transport) API Summary

<a id="functions"></a>

| | Function | Description |
|---|---|---|
| [e.g.](#ex-init) | [`void SSFNetWSInit(ws, inner, pathStr, fieldsOpt, fieldsOptLen)`](#ssfnetwsinit) | Initialize a session over an inner transport |
| | [`void SSFNetWSDeInit(ws)`](#ssfnetwsdeinit) | Close and wipe the session |
| | [`SSFNetWSState_t SSFNetWSGetState(ws)`](#ssfnetwsgetstate) | Connection state |

The transport operations themselves are reached through `ws->transport` and follow
[`ssfnet.h`](ssfnet.h).

<a id="function-reference"></a>

## [↑](#ssfnetws--websocket-client-transport) Function Reference

<a id="ssfnetwsinit"></a>

### [↑](#functions) [`void SSFNetWSInit()`](#functions)

```c
void SSFNetWSInit(SSFNetWSSession_t *ws, SSFNetTransport_t *inner, SSFCStrIn_t pathStr,
                  const SSFHTTPHdrField_t *fieldsOpt, uint32_t fieldsOptLen);
```

Initializes a session over `inner`, which must outlive it. Pass `&ws->transport` to the client.

- `pathStr` is the request target, such as `"/mqtt"`, optionally followed by a query string.
- `fieldsOpt` holds `fieldsOptLen` extra request fields, such as `Authorization`. They may not name
  `Host`, `Upgrade`, `Connection`, `Content-Length`, `Transfer-Encoding` or any
  `Sec-WebSocket-*` field (case-insensitively).
- All strings are app owned and must stay valid. They are checked by every `open()`.

Asserts if the session is already initialized, if `inner` or any of its six operations is NULL,
if `pathStr` is NULL, or if `fieldsOptLen` is non-zero with `fieldsOpt` NULL.

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
static SSFNetSock_t sock;
static SSFTLSCSession_t tls;
static SSFNetWSSession_t ws;
static const SSFHTTPHdrField_t wsFields[] = { { "Authorization", "Bearer abc123" } };

/* wss://broker.example:443/mqtt */
SSFNetSockInit(&sock);
SSFTLSCInit(&tls, &sock.transport, &trustStore);
SSFNetWSInit(&ws, &tls.transport, "/mqtt", wsFields, 1);
SSFMQTTCInit(&ws.transport, 4, 512, 1024, OnRxPublish, NULL, OnEvent, NULL);
/* ... opts.host = "broker.example"; opts.port = 443; SSFMQTTCStart(&opts); */
```

---

<a id="ssfnetwsdeinit"></a>

### [↑](#functions) [`void SSFNetWSDeInit()`](#functions)

```c
void SSFNetWSDeInit(SSFNetWSSession_t *ws);
```

Closes any connection, as `close()` does, and wipes the session. Deinitialize the client that
uses the transport first.

**Returns:** Nothing.

<a id="ssfnetwsgetstate"></a>

### [↑](#functions) [`SSFNetWSState_t SSFNetWSGetState()`](#functions)

```c
SSFNetWSState_t SSFNetWSGetState(const SSFNetWSSession_t *ws);
```

**Returns:** `CLOSED`, `OPENING` (the inner transport opening), `HS_SEND`, `HS_RECV`, `OPEN`, or
`FAILED` (only `close()` is valid).

<a id="known-trade-offs"></a>

## [↑](#ssfnetws--websocket-client-transport) Known Trade-offs

- **No HTTP proxy.** An explicit forward proxy needs `CONNECT`, which belongs with the future
  HTTP/1.1 client as a tunnel transport. WSS on 443 already passes port-based and HTTPS-only
  firewalls.
- **No redirects or auth challenges.** A 3xx or 401 response fails the open (RFC 6455 allows
  this). Credentials must be sent up front in `fieldsOpt`.
- **The subprotocol is fixed at `mqtt`,** the name MQTT 3.1.1 requires. Using the transport for
  another protocol would need it made configurable.
- **A Close reason is not checked for UTF-8.** RFC 6455 7.1.7 asks for a failure on invalid
  UTF-8; the reason is ignored here, and only the code is echoed back.
- **Keep calling recv().** As with TLS records in `ssftlsc`, frame bytes can stay staged inside
  the transport after `recv()` returns, for example when the caller's buffer fills mid-frame. A
  caller must keep calling `recv()` rather than wait for socket readability. `recv()` also
  returns `WANT_READ` after a few inner reads that carry no payload (Pings, empty frames), so a
  flood of control frames cannot keep one call busy. That `WANT_READ` can follow work done (a
  Pong written) and bytes may still wait in the inner transport, so it means "call again", not
  "nothing happened". ssftlsc behaves the same way. ssfmqttc calls `recv()` once per
  `SSFMQTTCTask()`; an app that sleeps until a timer or the socket is readable may see such a
  flood add latency, never data loss.
- **A Pong or Close echo that cannot be written at once** goes out on the next `send()`,
  `recv()`, `shutdown()` or `close()`; `recv()` does not report `WANT_WRITE` for it.
- **`Host` omits the port for 80 and 443 whatever the scheme,** so `ws://h:443` or `wss://h:80`
  sends a `Host` without the port the URL named.
