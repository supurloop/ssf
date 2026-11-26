# ssfmqttc — MQTT 3.1.1 Client

[SSF](../README.md) | [Network](README.md)

A single-connection, non-blocking MQTT 3.1.1 client for QoS 0 and QoS 1. The client owns one
connection to one broker, keeps it alive, re-establishes it after any failure, delivers inbound
publishes to the application one at a time, and reports completion of outbound publishes.

The application supplies a transport ([`ssfnet.h`](ssfnet.h)), a set of fixed-size packet
buffers, two callbacks, and a table of options including the subscription set. Protocol logic
and timers run on the [ssfsm](../_fsm/README.md) state machine; transport I/O and delivery to
the application run in `SSFMQTTCTask()`. Both are driven from one application loop on one thread.

[Dependencies](#dependencies) | [Design](#design) | [Lifecycle](#lifecycle) | [Buffers](#buffers) | [Callbacks](#callbacks) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Known Trade-offs](#known-trade-offs)

<a id="dependencies"></a>

## [↑](#ssfmqttc--mqtt-311-client) Dependencies

- [`ssfport.h`](../ssfport.h), [`ssf.h`](../ssf.h), [`ssfassert.h`](../ssfassert.h)
- [`_fsm/ssfsm.h`](../_fsm/ssfsm.h) — state machine and timers. `SSFSMInit()` must be called
  before `SSFMQTTCInit()`. `SSF_SM_MQTTC` must be in `SSFSMList_t` and the `SSF_SM_EVENT_MQTTC_*`
  ids in `SSFSMEventList_t`, both in [`_opt/ssfsm_opt.h`](../_opt/ssfsm_opt.h)
- [`_struct/ssfmpool.h`](../_struct/ssfmpool.h), [`_struct/ssfll.h`](../_struct/ssfll.h) — packet pools and queues
- [`_codec/ssfstr.h`](../_codec/ssfstr.h) — bounded string length checks
- [`ssfmqttpkt.h`](ssfmqttpkt.h) — packet codec; also defines `SSFMQTTCQoS_t` and `SSFMQTTPktSub_t`
- [`ssfnet.h`](ssfnet.h) — transport interface; [`ssfnetsock.h`](ssfnetsock.h) is the hosted TCP implementation,
  [`ssftlsc.h`](ssftlsc.h) adds TLS, and [`ssfnetws.h`](ssfnetws.md) carries MQTT over WebSockets
  (MQTT 3.1.1 section 6) on either
- [`_opt/ssfmqttc_opt.h`](../_opt/ssfmqttc_opt.h) (aggregated through `ssfoptions.h`)

<a id="design"></a>

## [↑](#ssfmqttc--mqtt-311-client) Design

- **One connection.** The client is a singleton. All calls come from the thread that runs
  `SSFSMTask()` and `SSFMQTTCTask()`.
- **Clean session only.** Every CONNECT requests a clean session.
- **Printable ASCII strings.** Topic names, filters, the client id and the user name may hold
  only printable ASCII (0x20 to 0x7E). This is a limitation of this client, not an MQTT rule:
  MQTT allows any UTF-8, but the client has no UTF-8 validator, and a broker closes the
  connection on ill-formed UTF-8 (1.5.3). Restricting to ASCII means it can never send that, nor
  a control character. Non-ASCII text (for example `café`) is refused. Topic names may not hold
  the wildcards `+` or `#` (3.3.2.1), and filters must place them correctly (4.7.1). A bad topic
  makes `TxPublish()` return `false`; a bad Start string asserts. The password is binary and
  unrestricted. Inbound topics are only checked for NUL and wildcards; their UTF-8 is not
  validated (see the `topic` field of `SSFMQTTCRxPublish_t`).
- **Last Will.** An optional will (`willOpt`) rides on every CONNECT. The broker publishes it
  when the connection ends without DISCONNECT. A connection the client ends because of an error
  is closed without DISCONNECT, so the will fires whatever the cause; only `SSFMQTTCStop()`
  sends DISCONNECT, so an orderly stop never fires it. MQTT 3.1.1 DISCONNECT carries no reason,
  so the broker learns nothing more from one. See [the online/offline example](#ex-will).
- **Retained publish.** `TxPublish()` can set RETAIN; the broker then keeps the message as the
  topic's last known value and gives it to each new subscriber. An empty retained payload
  clears it. A broker without retained-message support does not store it.
- **QoS 0 and 1.** A QoS 2 PUBLISH from the broker is a protocol error (no subscription allows
  it) and ends the connection with `RX_PUBLISH_QOS2`, without acknowledgement or delivery.
- **Self-healing.** Once started the client works continuously to reach and hold READY. Every
  failed attempt or lost connection is followed by a doubling backoff and a new attempt, until
  `SSFMQTTCStop()` is called. No jitter is added to the backoff; devices in a fleet desynchronize
  through clock drift and differing failure times.
- **Subscriptions are configuration.** The subscription set is part of the Start options and is
  sent as one SUBSCRIBE after every CONNACK. READY follows the SUBACK whatever it granted, so a
  device whose broker refuses a filter still publishes and receives on the rest, and can report
  the refusal itself. READY's reason is `SUBSCRIBE_REFUSED` if any filter was refused, else
  `SUBSCRIBE_DOWNGRADED` if any was granted a lower QoS (which MQTT 3.1.1 allows), else NONE;
  [`SSFMQTTCGetSubResult()`](#ssfmqttcgetsubresult) gives each filter's result. Only a higher QoS
  than requested, a broker error, fails the attempt. No UNSUBSCRIBE is ever sent, since a clean
  session discards server-side state. To change the set: Stop, edit the table, Start.
- **Refused filters are retried.** A refusal is usually broker policy, fixed on the broker side.
  While any filter is refused the client subscribes just those again every
  [`SSF_MQTTC_CONFIG_SUB_RETRY_TICKS`](#opt-subretry) (5 minutes by default, at least 60 s), so a
  device recovers by itself once the broker is fixed. Each retry that grants a filter reports
  `SUBSCRIPTION_CHANGED`. A retry whose SUBACK does not arrive within `subscribeTimeout` ends the
  connection with `SUBSCRIBE_TIMEOUT`, as for the first SUBSCRIBE.
- **Keep-alive.** CONNECT advertises `keepAliveSec`, but PINGREQ is sent four times per interval
  so the broker's 1.5× deadline is never approached. A missed PINGRESP ends the connection
  within [`SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT`](#opt-pingresp) of its PINGREQ being queued; no
  further PINGREQ is sent while one is unanswered. The ping interval must be at least that
  timeout. With the default 30 s timeout the smallest `keepAliveSec` is 120. `SSFMQTTCStart()`
  asserts this.
- **Two tasks, one thread.** The state machine owns state transitions and timers. The task pump
  owns transport I/O, rxPublish delivery (offer, retry, timeout drop, PUBACK), QoS 0 publish
  completion, and drop reports. Application callbacks may therefore fire from either
  `SSFSMTask()` or `SSFMQTTCTask()`. `SSFMQTTCStop()` and `SSFMQTTCTxPublish()` may be called
  from inside any callback.
- **Back-pressure for QoS 1.** A QoS 1 PUBLISH that finds the rx queue full is held at the front
  of the framing buffer and the transport is not read until the application frees a slot, so TCP
  flow control holds the broker back and no QoS 1 message is lost to a brief burst. A hold lasts
  at most [`SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS`](#opt-hold); the packet is then dropped
  (`RX_PUBLISH_HOLD_TIMEOUT`) and reading resumes. A QoS 0 PUBLISH that finds the queue full is
  dropped at once (`RX_PUBLISH_QUEUE_FULL`), and reading goes on.
- **A PUBACK is never skipped.** Every dropped QoS 1 PUBLISH is acknowledged so the broker's
  in-flight window keeps moving. If no PUBACK block is free (the transport is not taking bytes),
  the packet id is owed and reads stop until its PUBACK is queued; at most one is ever owed. A
  delivery's PUBACK waits behind an owed one. A PUBLISH before CONNACK fails the attempt, and once
  `Stop()` has queued DISCONNECT nothing more is sent: inbound PUBLISH is dropped unacknowledged,
  and a hold or owed PUBACK is abandoned (the clean session forgets it).
- **Strings.** Every string the application supplies is NUL terminated and strictly shorter than
  its `SSF_MQTTC_CONFIG_MAX_*_SIZE` constant. Strings are validated with a bounded length scan
  against the constant, so no size argument accompanies them. An inbound PUBLISH whose topic is
  not shorter than the topic constant is dropped and reported with `RX_PUBLISH_TOPIC_TOO_LONG`.
- **Oversized inbound PUBLISH.** MQTT 3.1.1 gives the client no way to tell the broker its size
  limits. An inbound PUBLISH larger than `rxBlockSize` is consumed as it arrives, without being
  stored, and dropped with `RX_PUBLISH_TOO_LARGE`; the connection and subscriptions are
  unaffected. Its fixed header gives its length, so the stream stays in sync. It is still checked
  for malformed fields (`PROTOCOL`). Over a slow link a very large one delays every packet behind
  it, PINGRESP included.
- **Packet ids** start at 1 and continue across reconnects. Clean session makes a reset unnecessary.
- **Packet codec.** [`ssfmqttpkt.h`](ssfmqttpkt.h) is pure functions over caller-supplied
  buffers, with no state or allocation. Each encoder writes one complete packet, fixed header
  included, and sets `*lenOut` to its length; a packet that does not fit `size`, or an argument
  that is not encodable, asserts, so a caller that must refuse an oversized PUBLISH at run time
  checks `SSFMQTTPktPublishLen()` first. Each decoder takes exactly one complete packet as
  delimited by `SSFMQTTPktFrame()` and returns `false` if it is malformed for its type; it does
  not judge whether the packet is expected. `SSFMQTTPktFrame()` reports the total packet length
  as soon as the fixed header is complete, so an oversized packet can be rejected before all of
  it arrives. Strings are NUL terminated and validated with a bounded scan against their size
  argument, which includes the NUL, so a string must be strictly shorter than its size.

<a id="lifecycle"></a>

## [↑](#ssfmqttc--mqtt-311-client) Lifecycle

```
Init ──► STOPPED ──Start()──► CONNECTING ──CONNACK──► SUBSCRIBING ──SUBACK──► CONNECTED
            ▲                     │                        │                      │
            │                     └────────── failure ─────┴──────── loss ────────┘
            │                                            │
            │                                     RECONNECT_WAIT ──backoff──► CONNECTING
            │
            └──── STOPPED event ◄── STOPPING ◄──Stop()── (any state)
```

| State | Meaning |
|-------|---------|
| `SSF_MQTTC_STATE_STOPPED` | Initialized, not running. `Start()` and `DeInit()` are valid here only. |
| `SSF_MQTTC_STATE_CONNECTING` | Transport opening, CONNECT sent, awaiting CONNACK. |
| `SSF_MQTTC_STATE_SUBSCRIBING` | CONNACK accepted, SUBSCRIBE sent, awaiting SUBACK. Skipped when no subscriptions are configured. |
| `SSF_MQTTC_STATE_CONNECTED` | Session up and every subscription granted. The only state in which `TxPublish()` succeeds. |
| `SSF_MQTTC_STATE_RECONNECT_WAIT` | Attempt failed or connection lost; waiting out the backoff. |
| `SSF_MQTTC_STATE_STOPPING` | `Stop()` called with a session up; flushing the tx queue, then DISCONNECT, the transport's `shutdown()`, and close. |

**Events** are reported through `SSFMQTTCEventFn_t`. Per connection the sequence is CONNECTED,
READY (then any SUBSCRIPTION_CHANGED), then eventually DISCONNECTED or STOPPED. A failed attempt yields CONNECT_FAILED. The
`reason` argument is NONE except where the table says otherwise.

| Event | When | Reason |
|-------|------|--------|
| `CONNECTED` | CONNACK accepted; SUBSCRIBE sent if subscriptions are configured | NONE |
| `READY` | SUBACK received, or no subscriptions configured. Publishing and receiving active. | NONE, `SUBSCRIBE_DOWNGRADED` or `SUBSCRIBE_REFUSED` |
| `SUBSCRIPTION_CHANGED` | READY: a retry granted one or more refused filters. Read the results with `SSFMQTTCGetSubResult()`. | NONE once every filter is granted, else `SUBSCRIBE_REFUSED` |
| `CONNECT_FAILED` | An attempt ended before READY. Reported at the point of failure; the client then enters RECONNECT_WAIT. | valid |
| `DISCONNECTED` | A READY connection was lost. Reported at the point of failure; the client then enters RECONNECT_WAIT. | valid |
| `STOPPED` | `Stop()` complete. The client is in STOPPED. | NONE |
| `RX_PUBLISH_DROPPED` | An inbound PUBLISH was discarded; a QoS 1 one is still acknowledged. The connection is unaffected. | `RX_PUBLISH_TIMEOUT`, `RX_PUBLISH_HOLD_TIMEOUT`, `RX_PUBLISH_QUEUE_FULL`, `RX_PUBLISH_TOO_LARGE` or `RX_PUBLISH_TOPIC_TOO_LONG` |

Inside a `CONNECT_FAILED` or `DISCONNECTED` callback, `SSFMQTTCGetState()` returns the state the
connection failed in, not RECONNECT_WAIT.

**Reasons** (`SSFMQTTCReason_t`):

| Reason | Meaning |
|--------|---------|
| `TRANSPORT_ERROR` | The transport reported a local or network failure. |
| `PEER_CLOSED` | The broker closed or reset the connection. |
| `CONNECT_TIMEOUT` | Transport open plus CONNACK exceeded `connectTimeout`. |
| `CONNACK_PROTOCOL_VERSION`, `CONNACK_CLIENT_ID`, `CONNACK_SERVER_UNAVAILABLE`, `CONNACK_BAD_CREDENTIALS`, `CONNACK_NOT_AUTHORIZED` | Broker refused CONNECT; one reason per MQTT 3.1.1 return code 1 to 5. |
| `CONNACK_UNKNOWN` | CONNACK carried a reserved return code. |
| `SUBSCRIBE_TIMEOUT` | SUBACK not received within `subscribeTimeout`. |
| `SUBSCRIBE_REFUSED` | Reported with READY or SUBSCRIPTION_CHANGED, not a failure: one or more filters are refused and will be retried. |
| `SUBSCRIBE_QOS_EXCEEDED` | SUBACK granted a higher QoS than requested for one or more filters, initially or on a retry. Ends the attempt or connection. |
| `SUBSCRIBE_DOWNGRADED` | Reported with READY, not a failure: SUBACK granted a lower QoS than requested for one or more filters, and refused none. |
| `KEEPALIVE` | No PINGRESP within [`SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT`](#opt-pingresp). |
| `TX_PUBLISH_TIMEOUT` | A publish did not complete within `txPublishTimeout`. |
| `PROTOCOL` | Malformed packet, or a packet type not valid at that point: for example a PUBLISH before CONNACK (3.2.0), a PINGRESP other than exactly `D0 00`, or an inbound topic holding `+` or `#` (3.3.2.1). |
| `RX_PUBLISH_QOS2` | The broker sent a QoS 2 PUBLISH, which no subscription allows; decided by the fixed header alone. A broker bug: it recurs on every reconnect. |
| `RX_OVERFLOW` | Inbound packet other than PUBLISH larger than `rxBlockSize`. |
| `RX_PUBLISH_TIMEOUT` | The application deferred an inbound PUBLISH past [`SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS`](#opt-maxticks). |
| `RX_PUBLISH_QUEUE_FULL` | An inbound QoS 0 PUBLISH arrived with no free rx block. |
| `RX_PUBLISH_HOLD_TIMEOUT` | An inbound QoS 1 PUBLISH waited for a free rx block longer than [`SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS`](#opt-hold) while reads were held. |
| `RX_PUBLISH_TOO_LARGE` | An inbound PUBLISH was larger than `rxBlockSize`. |
| `RX_PUBLISH_TOPIC_TOO_LONG` | An inbound PUBLISH topic was not shorter than the topic constant. |

<a id="buffers"></a>

## [↑](#ssfmqttc--mqtt-311-client) Buffers

`SSFMQTTCInit()` builds three fixed-block pools from the heap. Nothing is allocated after init.
Every packet occupies one block of its pool, and the pools are independent: a backlog in one
direction cannot block the other, and application traffic cannot block the protocol's own packets.

| Pool | Holds | Count | Block size |
|------|-------|-------|------------|
| tx | CONNECT, SUBSCRIBE, application PUBLISH | `txBlocks` (app) | `txBlockSize` (app) |
| rx | Inbound framing buffer plus queued inbound PUBLISH | [`SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH`](#opt-depth) + 1 | `rxBlockSize` (app) |
| ctl | PINGREQ, DISCONNECT, PUBACK | internal | internal |

- `txBlockSize` must hold the largest of CONNECT (will included), SUBSCRIBE and any PUBLISH the
  application sends, including the fixed header. A CONNECT that does not fit asserts in
  `SSFMQTTCStart()`; a SUBSCRIBE that does not fit asserts at connect time; a PUBLISH that does
  not fit makes `TxPublish()` return `false`.
- tx blocks in use at any moment are those queued for the transport plus QoS 1 PUBLISH and
  SUBSCRIBE awaiting acknowledgement, so `txBlocks` bounds the application's outstanding publishes.
  `txBlocks` must be at least 1.
- `rxBlockSize` must hold the largest inbound packet the application wants, including the fixed
  header. A PUBLISH that does not fit is dropped (`RX_PUBLISH_TOO_LARGE`); any other packet that
  does not fit ends the connection (`RX_OVERFLOW`). One rx block is permanently the framing buffer;
  the rest hold inbound PUBLISH packets awaiting the application. A QoS 1 PUBLISH arriving with no
  free rx block waits in the framing buffer while reads are held; a QoS 0 one is dropped.
- At most 2 × queue depth + 2 inbound QoS 1 packets are ever unacknowledged as the broker sees
  them: the queue, one held, one owed, and up to queue depth PUBACKs queued but not yet written.
  The ctl pool reserves its other blocks for PINGREQ and DISCONNECT.
- Both block sizes must be at least 4.

<a id="callbacks"></a>

## [↑](#ssfmqttc--mqtt-311-client) Callbacks

All callbacks run on the application thread, from inside `SSFSMTask()` or `SSFMQTTCTask()`.
Each receives the context pointer given alongside it as its first argument. A context may only be
supplied together with its callback.

### `SSFMQTTCEventFn_t` — lifecycle events

```c
typedef void (*SSFMQTTCEventFn_t)(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason);
```

Optional. See [Lifecycle](#lifecycle) for the events and reasons.

### `SSFMQTTCTxPublishFn_t` — publish completion

```c
typedef void (*SSFMQTTCTxPublishFn_t)(void *ctx, bool isPublished);
```

Optional per publish. **Contract:** for every `SSFMQTTCTxPublish()` that returns `true` this fires
exactly once, no later than `txPublishTimeout` after the call plus task latency.

- `isPublished == true`: QoS 0 fully handed to the transport, or QoS 1 PUBACK received.
- `isPublished == false`: the connection ended, the client stopped, or `txPublishTimeout` expired
  before completion. Clean session means the message will not be re-sent.

### `SSFMQTTCRxPublishFn_t` — inbound publish

```c
typedef bool (*SSFMQTTCRxPublishFn_t)(void *ctx, const SSFMQTTCRxPublish_t *rxPublish);
```

Required. Offers the head of the inbound queue to the application. Packets are delivered as
received and in order. The client does not match topics against the subscription filters; routing
on topic is the application's job. It may fire while SUBSCRIBING, before the READY event, because
brokers may deliver matching and retained packets ahead of SUBACK.

| Field | Meaning |
|-------|---------|
| `topic`, `topicLen` | NUL terminated, shorter than the topic constant. Valid only during the callback. The bytes are as the broker sent them: never NUL, `+` or `#` (a topic holding one ends the connection with `PROTOCOL`), but not checked for UTF-8, so they may be non-ASCII, non-printable or ill-formed UTF-8. Validate them before treating them as text. |
| `payload`, `payloadLen` | Valid only during the callback. `payload` is NULL when the length is 0. |
| `qos` | 0 or 1. |
| `retain` | Set by the broker when delivering a retained message. |
| `dup` | The wire DUP flag as sent by the broker. |
| `offerCount` | 1 on the first offer, plus one for each time the application deferred it. |

- **Return `true`:** consumed. A QoS 1 packet is acknowledged after return. The next packet may be
  offered immediately.
- **Return `false`:** deferred, the same for QoS 0 and QoS 1. The packet stays at the head of the
  queue and is offered again after [`SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS`](#opt-retry) with
  `offerCount` incremented. Nothing behind it is offered meanwhile. Once
  [`SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS`](#opt-maxticks) has elapsed since the first offer it is
  dropped, a QoS 1 packet is acknowledged, and `RX_PUBLISH_DROPPED` is reported with
  `RX_PUBLISH_TIMEOUT`.

<a id="configuration"></a>

## [↑](#ssfmqttc--mqtt-311-client) Configuration

Options live in [`_opt/ssfmqttc_opt.h`](../_opt/ssfmqttc_opt.h) (aggregated into the build via
`ssfoptions.h`). Sizes include the NUL terminator, so application strings must be strictly shorter;
MQTT 3.1.1 caps every string field at 65535 bytes. Tick-based options use `SSF_TICKS_PER_SEC`
from `ssfport.h`, which must be included first (`ssfoptions.h` does this).

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE` | `128` | Topic names and filters, 2..65536. Also bounds inbound topics; a longer inbound PUBLISH topic is dropped with `SSF_MQTTC_REASON_RX_PUBLISH_TOPIC_TOO_LONG`. |
| `SSF_MQTTC_CONFIG_MAX_HOST_SIZE` | `64` | Broker host name or address, 2..256 (DNS name limit plus NUL). |
| `SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE` | `64` | Client identifier, 2..65536. Brokers must accept 1 to 23 characters and may accept longer. |
| `SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE` | `64` | User name, 2..65536. |
| `SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN` | `64` | Password bytes, 1..65535. Binary, not NUL terminated. |
| `SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS` | `8` | Maximum entries in the subscription set, 1..16. All filters are sent in one SUBSCRIBE, so the tx block size must hold them. |
| <a id="opt-subretry"></a>`SSF_MQTTC_CONFIG_SUB_RETRY_TICKS` | 5 minutes (500 ms in the ssfmqttc unit test build) | Interval at which refused filters are subscribed again, measured from READY and from each refused retry. At least 60 s outside the unit test build (`#error`). Override with `-D`. |
| <a id="opt-depth"></a>`SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH` | `4` | Inbound PUBLISH packets held for the application, at least 1. Sizes the rx pool (depth plus one framing block) and the PUBACK capacity of the control pool. |
| <a id="opt-retry"></a>`SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS` | 1 s | Re-offer interval for a deferred inbound PUBLISH, at least 1 tick. |
| <a id="opt-maxticks"></a>`SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS` | 30 s (5 s in the ssfmqttc unit test build) | A deferred inbound PUBLISH is dropped this long after its first offer. Must be at least `SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS`. Override with `-D`. |
| <a id="opt-hold"></a>`SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS` | 10 s (400 ms in the ssfmqttc unit test build, longer than its PINGRESP timeout) | Longest a QoS 1 PUBLISH is held, with reads suspended, waiting for queue space; it is then dropped and acknowledged (`SSF_MQTTC_REASON_RX_PUBLISH_HOLD_TIMEOUT`) and reading resumes. Everything behind it waits too, PINGRESP and PUBACKs for the application's own publishes included, so `txPublishTimeout` and `subscribeTimeout` should exceed it. Override with `-D`. |
| <a id="opt-openpoll"></a>`SSF_MQTTC_CONFIG_OPEN_POLL_TICKS` | 10 ms | Longest `SSFMQTTCTask()` lets the app loop sleep while the transport resolves the host and connects, at least 1 tick. |
| <a id="opt-pingresp"></a>`SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT` | 30 s (250 ms in the ssfmqttc unit test build) | Connection is dropped if PINGRESP does not follow PINGREQ within this time. PINGREQ is sent every `keepAliveSec / 4`, which must be at least this value, so the default allows a minimum `keepAliveSec` of 120. The unit test value keeps the same ratio with `keepAliveSec` 1. Override with `-D`. |

The ssfsm event and timer pools must be sized for the client: see `SSF_SM_MAX_ACTIVE_EVENTS` and
`SSF_SM_MAX_ACTIVE_TIMERS` in [`_opt/ssfsm_opt.h`](../_opt/ssfsm_opt.h). The client alone can
have outstanding at once: one each of TRANSPORT_OPEN, LINK_FAIL, TX_DRAINED, START and STOP, one
event per running timer (up to four during a session), plus one decoded-packet event per control
packet framed in a single `SSFMQTTCTask()` call. The defaults in that header allow for this with
margin for other state machines.

### Start options (`SSFMQTTCOpts_t`)

All pointed-to memory is application owned and must remain valid and unchanged from
`SSFMQTTCStart()` until the STOPPED event; it is re-read on every reconnect. The client does not
copy the password; the application may zeroize it after STOPPED.

| Field | Constraint |
|-------|------------|
| `host` | Required. Shorter than `MAX_HOST_SIZE`. |
| `port` | Non-zero. |
| `clientId` | Required. At least one character, shorter than `MAX_CLIENT_ID_SIZE`, printable ASCII. Chosen by the application; the client never generates one. Brokers must accept 1 to 23 characters of `0-9`, `a-z` and `A-Z` (3.1.3.1) and may refuse anything else (longer, or other characters) with `CONNACK_CLIENT_ID`, which is retried at the backoff rate. Stay within that set for a client id every broker accepts. |
| `usernameOpt` | NULL for none. Shorter than `MAX_USERNAME_SIZE`, printable ASCII. |
| `passwordOpt`, `passwordLen` | NULL and 0 for none. Requires `usernameOpt`. `passwordLen` at most `MAX_PASSWORD_LEN`. |
| `subsOpt`, `subCount` | Array of `SSFMQTTCSub_t` (filter and QoS 0 or 1). NULL and 0 for none. `subCount` at most `MAX_SUBSCRIPTIONS`; each filter shorter than `MAX_TOPIC_SIZE`, printable ASCII, with `#` only as the whole last level and `+` only as a whole level (4.7.1). |
| `keepAliveSec` | Advertised to the broker. Must be at least four times `PINGRESP_TIMEOUT` in seconds. |
| `connectTimeout` | Ticks, greater than 0. Transport open through CONNACK accepted. |
| `subscribeTimeout` | Ticks, greater than 0. SUBSCRIBE sent through SUBACK received. |
| `txPublishTimeout` | Ticks, greater than 0. Publish call through completion. On expiry the connection is dropped with `TX_PUBLISH_TIMEOUT` and every pending publish callback fires `false`. |
| `reconnectMinWait` | Ticks, greater than 0. First backoff; doubles per consecutive failure. |
| `reconnectMaxWait` | Ticks, at least `reconnectMinWait`. Backoff cap. |
| `willOpt` | `SSFMQTTCWill_t` (`topic`, `payloadOpt`, `payloadLen`, `qos`, `retain`), or NULL for none. `topic` is a topic name shorter than `MAX_TOPIC_SIZE`, printable ASCII, with no `+` or `#`; `qos` is 0 or 1; `payloadOpt` may be NULL only with `payloadLen` 0. The whole CONNECT must fit `txBlockSize`. A broker whose ACL does not allow the will topic may refuse every CONNECT (`CONNACK_NOT_AUTHORIZED`) or drop the will silently. The will is sent in every CONNECT, so it is as exposed on the wire as the credentials; use TLS if it matters. |

<a id="api-summary"></a>

## [↑](#ssfmqttc--mqtt-311-client) API Summary

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFMQTTCInit(...)`](#ssfmqttcinit) | Build the pools, install callbacks, register with ssfsm. Client is STOPPED after. |
| | [`void SSFMQTTCDeInit()`](#ssfmqttcdeinit) | Free the pools. Only valid in STOPPED. |
| [e.g.](#ex-start) | [`void SSFMQTTCStart(opts)`](#ssfmqttcstart) | Begin connecting and hold the connection until stopped. |
| [e.g.](#ex-stop) | [`void SSFMQTTCStop()`](#ssfmqttcstop) | Flush, disconnect, close; STOPPED is reported asynchronously. |
| [e.g.](#ex-task) | [`bool SSFMQTTCTask(nextTimeoutOpt)`](#ssfmqttctask) | Pump transport I/O and deliver inbound publishes. Call every loop iteration. |
| [e.g.](#ex-publish) | [`bool SSFMQTTCTxPublish(...)`](#ssfmqttctxpublish) | Queue a QoS 0 or 1 publish, optionally retained; completion reported by callback. |
| | [`SSFMQTTCState_t SSFMQTTCGetState()`](#ssfmqttcgetstate) | Current client state. |
| [e.g.](#ex-subresult) | [`bool SSFMQTTCGetSubResult(index, resultOut)`](#ssfmqttcgetsubresult) | While CONNECTED: one filter's granted QoS, or refused. |

### Macros

| Macro | Meaning |
|-------|---------|
| `SSFMQTTCIsStarted()` | Not STOPPED: the client is working to stay connected. |
| `SSFMQTTCIsConnected()` | SUBSCRIBING or CONNECTED: a session is up. |
| `SSFMQTTCIsReady()` | CONNECTED: all subscriptions granted; `TxPublish()` may be called. |

<a id="function-reference"></a>

## [↑](#ssfmqttc--mqtt-311-client) Function Reference

<a id="ssfmqttcinit"></a>

### [↑](#functions) [`void SSFMQTTCInit()`](#functions)

```c
void SSFMQTTCInit(SSFNetTransport_t *transport, uint32_t txBlocks, uint32_t txBlockSize,
                  uint32_t rxBlockSize, SSFMQTTCRxPublishFn_t rxPublishFn,
                  void *rxPublishFnCtxOpt, SSFMQTTCEventFn_t eventFnOpt, void *eventFnCtxOpt);
```

Builds the three packet pools (see [Buffers](#buffers)), installs the callbacks, and registers the
client with ssfsm, which must already be initialized. The transport must outlive the client. The
client is STOPPED on return and no event is reported for that initial state.

Asserts if already initialized, if the transport or any of its six operations is NULL, if
`txBlocks` is 0, if either block size is below 4, if `rxPublishFn` is NULL, or if an event
context is given without an event callback.

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
static SSFNetSock_t sock;
static uint8_t rxPublishCount;

static bool OnRxPublish(void *ctx, const SSFMQTTCRxPublish_t *rx)
{
    (*(uint8_t *)ctx)++;
    printf("%s: %.*s\n", rx->topic, (int)rx->payloadLen, (const char *)rx->payload);
    return true;                                  /* consumed */
}

static void OnEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason)
{
    (void)ctx; (void)reason;
    if (event == SSF_MQTTC_EVENT_READY) printf("ready\n");
}

SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
SSFNetSockInit(&sock);
SSFMQTTCInit(&sock.transport, 4, 512, 1024, OnRxPublish, &rxPublishCount, OnEvent, NULL);
```

---

<a id="ssfmqttcdeinit"></a>

### [↑](#functions) [`void SSFMQTTCDeInit()`](#functions)

```c
void SSFMQTTCDeInit(void);
```

Unregisters from ssfsm and frees the pools. Asserts unless initialized, STOPPED, and not between
`Start()` and the STOPPED event.

**Returns:** Nothing.

---

<a id="ssfmqttcstart"></a>

### [↑](#functions) [`void SSFMQTTCStart()`](#functions)

```c
void SSFMQTTCStart(const SSFMQTTCOpts_t *opts);
```

Starts the client. From here it works continuously to reach and hold READY. An attempt fails if
the transport open or CONNACK exceeds `connectTimeout`, CONNACK is refused, SUBACK exceeds
`subscribeTimeout`, or SUBACK grants a higher QoS than requested. A lower grant or a refused
filter is accepted and reported with READY; refused filters are then retried. On any failure or
lost connection
the client closes the transport without DISCONNECT (so the broker publishes the will, if one is
set), reports `CONNECT_FAILED` or `DISCONNECTED`, waits out the backoff in RECONNECT_WAIT, and
tries again.

Asserts unless STOPPED and not already started, if any option violates its
[constraint](#start-options-ssfmqttcopts_t), or if the CONNECT would not fit `txBlockSize`.

**Returns:** Nothing.

<a id="ex-start"></a>

**Example:**

```c
static const SSFMQTTCSub_t subs[] =
{
    { "sensors/+/temperature", SSF_MQTTC_QOS_1 },
    { "control/#",             SSF_MQTTC_QOS_0 },
};

static const SSFMQTTCOpts_t opts =
{
    .host = "broker.example.net",
    .port = 1883,
    .clientId = "device-0001",
    .usernameOpt = NULL,
    .passwordOpt = NULL,
    .passwordLen = 0,
    .subsOpt = subs,
    .subCount = 2,
    .keepAliveSec = 120,
    .connectTimeout = SSF_TICKS_PER_SEC * 10,
    .subscribeTimeout = SSF_TICKS_PER_SEC * 10,
    .txPublishTimeout = SSF_TICKS_PER_SEC * 10,
    .reconnectMinWait = SSF_TICKS_PER_SEC * 2,
    .reconnectMaxWait = SSF_TICKS_PER_SEC * 60,
};

SSFMQTTCStart(&opts);
```

<a id="ex-will"></a>

**Example (online/offline and the last disconnect reason):** a retained will says `offline` if
the device drops; a retained `online` on every READY replaces it; an orderly stop publishes
`offline` itself, since DISCONNECT cancels the will. The reason for the last lost connection is
published after the next READY, because a 3.1.1 will cannot carry it.

```c
static const SSFMQTTCWill_t will =
{ "devices/0001/status", (const uint8_t *)"offline", 7, SSF_MQTTC_QOS_1, true };
static SSFMQTTCReason_t lastReason = SSF_MQTTC_REASON_NONE;

static void OnEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason)
{
    char msg[16];

    if ((event == SSF_MQTTC_EVENT_DISCONNECTED) || (event == SSF_MQTTC_EVENT_CONNECT_FAILED))
    { lastReason = reason; }
    else if (event == SSF_MQTTC_EVENT_READY)
    {
        (void)SSFMQTTCTxPublish("devices/0001/status", (const uint8_t *)"online", 6,
                                SSF_MQTTC_QOS_1, true, NULL, NULL);
        if (lastReason != SSF_MQTTC_REASON_NONE)
        {
            int n = snprintf(msg, sizeof(msg), "%d", (int)lastReason);
            (void)SSFMQTTCTxPublish("devices/0001/last_disconnect", (const uint8_t *)msg,
                                    (size_t)n, SSF_MQTTC_QOS_1, true, NULL, NULL);
            lastReason = SSF_MQTTC_REASON_NONE;
        }
    }
}

/* opts.willOpt = &will; ... SSFMQTTCStart(&opts); */

/* Orderly shutdown: say offline first, since Stop()'s DISCONNECT cancels the will */
(void)SSFMQTTCTxPublish("devices/0001/status", (const uint8_t *)"offline", 7, SSF_MQTTC_QOS_1,
                        true, NULL, NULL);
SSFMQTTCStop();     /* Stop() flushes the queue before DISCONNECT */
```

---

<a id="ssfmqttcstop"></a>

### [↑](#functions) [`void SSFMQTTCStop()`](#functions)

```c
void SSFMQTTCStop(void);
```

Stops the client. Valid exactly once per `Start()`, in any state before STOPPED is reported. No
further connection attempts are made. If a session is up the client flushes the tx queue, sends
DISCONNECT, calls the transport's `shutdown()` until the DISCONNECT is delivered (over TLS, until
the last record and `close_notify` are written), then closes the transport. `txPublishTimeout`
bounds the whole stop; past it the transport is closed anyway. Otherwise it aborts the attempt or
backoff immediately.

Completion is asynchronous: STOPPED is reported from `SSFSMTask()`, never from inside `Stop()`.
Pending publish callbacks fire `false`. Queued inbound publishes are discarded without further
offers or events.

Asserts if not started, including a second call for the same run.

**Returns:** Nothing.

<a id="ex-stop"></a>

**Example:**

```c
static void OnEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason)
{
    if ((event == SSF_MQTTC_EVENT_CONNECT_FAILED) &&
        (reason == SSF_MQTTC_REASON_CONNACK_BAD_CREDENTIALS))
    {
        SSFMQTTCStop();     /* The client would otherwise retry at the backoff rate */
    }
    if (event == SSF_MQTTC_EVENT_STOPPED) { /* safe to DeInit or Start again */ }
}
```

---

<a id="ssfmqttctask"></a>

### [↑](#functions) [`bool SSFMQTTCTask()`](#functions)

```c
bool SSFMQTTCTask(SSFPortTick_t *nextTimeoutOpt);
```

Pumps transport I/O: drains the tx queue, reads and frames inbound bytes, posts decoded control
packets to the state machine, completes QoS 0 publishes, and offers queued inbound publishes to
the application. Call it on every iteration of the application loop, after `SSFSMTask()`.

`nextTimeoutOpt` follows the `SSFSMTask()` convention: the caller initializes it, typically to
`SSF_MAX_NEXT_TIMEOUT`, and the call only ever lowers it. It is lowered to the time of the next
inbound publish retry when one is pending, to [`SSF_MQTTC_CONFIG_OPEN_POLL_TICKS`](#opt-openpoll)
while the transport is still opening (there is no socket to wait on during name resolution), and
to 0 when more transport work is immediately available (unsent bytes accepted by the transport, or
inbound bytes still to frame).

**Returns:** `true` when more transport work is immediately available, `false` otherwise.

<a id="ex-task"></a>

**Example:**

```c
for (;;)
{
    SSFPortTick_t to = SSF_MAX_NEXT_TIMEOUT;

    SSFSMTask(&to);
    SSFMQTTCTask(&to);
    WaitForTransportOrTimeout(to);                /* platform specific */
}
```

---

<a id="ssfmqttctxpublish"></a>

### [↑](#functions) [`bool SSFMQTTCTxPublish()`](#functions)

```c
bool SSFMQTTCTxPublish(SSFCStrIn_t topicStr, const uint8_t *payload, size_t payloadLen,
                       SSFMQTTCQoS_t qos, bool retain, SSFMQTTCTxPublishFn_t txPublishFnOpt,
                       void *txPublishFnCtxOpt);
```

Queues a PUBLISH. Valid only when `SSFMQTTCIsReady()` is true. On `true` the completion callback,
if given, is guaranteed to fire exactly once within `txPublishTimeout` with the context as its
first argument; the tx block is held until then.

Asserts if not initialized, `topicStr` is NULL, `payload` is NULL with a non-zero length, `qos` is
not 0 or 1, or a context is given without a callback.

**Returns:** `false` if not READY; if `topicStr` is empty, not shorter than the topic constant,
holds `+` or `#`, or holds a character outside printable ASCII (sending it would make the
broker disconnect); if the encoded packet would not fit a tx block; or if no tx block is free.
Retry later, except for a bad topic, which never succeeds. `true` if queued.

**Retain:** with `retain` true the broker stores the message and gives it to every later
subscriber of the topic, replacing any message it stored before. An empty payload with `retain`
true clears the stored message instead. It works the same at QoS 0 and 1, and completion means
the same as without it. Use QoS 1 when the stored value matters, a clear included: a lost QoS 0
PUBLISH leaves the old message stored. A retained message stays on the broker, readable by any
client allowed to subscribe to the topic, until it is replaced or cleared.

<a id="ex-publish"></a>

**Example:**

```c
static void OnPublished(void *ctx, bool isPublished)
{
    printf("publish %u %s\n", (unsigned)(uintptr_t)ctx, isPublished ? "ok" : "lost");
}

if (SSFMQTTCIsReady())
{
    const char *msg = "21.5";
    if (SSFMQTTCTxPublish("sensors/0001/temperature", (const uint8_t *)msg, strlen(msg),
                          SSF_MQTTC_QOS_1, false, OnPublished, (void *)(uintptr_t)42) == false)
    { /* no tx block free or packet too large; try again later */ }

    /* Retained: a dashboard that subscribes later still sees the device's state */
    (void)SSFMQTTCTxPublish("devices/0001/state", (const uint8_t *)"on", 2, SSF_MQTTC_QOS_1,
                            true, NULL, NULL);
}
```

---

<a id="ssfmqttcgetstate"></a>

### [↑](#functions) [`SSFMQTTCState_t SSFMQTTCGetState()`](#functions)

```c
SSFMQTTCState_t SSFMQTTCGetState(void);
```

**Returns:** The current client state. See [Lifecycle](#lifecycle). The three `SSFMQTTCIs*()`
macros are shorthand over this.

---

<a id="ssfmqttcgetsubresult"></a>

### [↑](#functions) [`bool SSFMQTTCGetSubResult()`](#functions)

```c
#define SSF_MQTTC_SUB_REFUSED (0x80u)
bool SSFMQTTCGetSubResult(uint32_t index, uint8_t *resultOut);
```

While CONNECTED, sets `*resultOut` to the result for `subsOpt[index]`: the QoS the broker
granted (0 or 1), or `SSF_MQTTC_SUB_REFUSED`. The results change only when a retry grants a
filter, which `SUBSCRIPTION_CHANGED` reports.

Asserts if `resultOut` is NULL, or, while CONNECTED, if `index` is not less than `subCount`.

**Returns:** `true` with the result while CONNECTED; `false` in any other state.

<a id="ex-subresult"></a>

**Example:** report refused filters to the operator, on a topic the broker's policy is sure to
allow (a report on a refused topic is dropped silently):

```c
static void ReportSubs(void)
{
    char msg[160];
    size_t len = 0;
    uint32_t i;
    uint8_t r;

    for (i = 0; i < (sizeof(subs) / sizeof(subs[0])); i++)    /* The table passed to Start() */
    {
        if (SSFMQTTCGetSubResult(i, &r) && (r == SSF_MQTTC_SUB_REFUSED))
        {
            int n = snprintf(&msg[len], sizeof(msg) - len, "%s%s", (len > 0) ? "," : "",
                             subs[i].filter);
            if ((n < 0) || ((size_t)n >= (sizeof(msg) - len))) break;
            len += (size_t)n;
        }
    }
    (void)SSFMQTTCTxPublish("devices/0001/diag/refused", (const uint8_t *)msg, len,
                            SSF_MQTTC_QOS_1, true, NULL, NULL);   /* Empty clears it */
}

static void OnEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason)
{
    if ((event == SSF_MQTTC_EVENT_READY) || (event == SSF_MQTTC_EVENT_SUBSCRIPTION_CHANGED))
    { ReportSubs(); }
}
```

<a id="known-trade-offs"></a>

## [↑](#ssfmqttc--mqtt-311-client) Known Trade-offs

- **Non-transient failures are retried.** CONNACK refusals other than `SERVER_UNAVAILABLE`, and
  `SUBSCRIBE_QOS_EXCEEDED`, are retried at the backoff rate like any other failure. Bad
  credentials keep hitting the broker until the application calls `SSFMQTTCStop()`. A refused
  filter does not fail the connection; it is retried every `SSF_MQTTC_CONFIG_SUB_RETRY_TICKS`
  for as long as the connection lasts.
- **A refused filter is picked up only by a retry.** After the broker is fixed, a refused filter
  is granted at the next retry (up to `SSF_MQTTC_CONFIG_SUB_RETRY_TICKS` later) or the next
  connection. A broker that closes the connection on a filter it does not support, instead of
  refusing it in SUBACK, still fails every attempt (`PEER_CLOSED`), and no results are reported.
- **A hold blocks everything behind it.** The stream is ordered, so while a QoS 1 PUBLISH is held
  the PINGRESP, PUBACKs for the application's own publishes and SUBACK behind it wait too, each
  hold for up to `SSF_MQTTC_CONFIG_RX_HOLD_MAX_TICKS`. Keep-alive allows for this: a PINGRESP
  timeout that falls while reads are held for the application waits again, since a whole packet
  arrived. It does not while reads are stopped for an owed PUBACK, which means writes are blocked,
  so a dead uplink is still detected. Under a sustained flood an application slower than one
  message per hold can chain holds; outbound QoS 1 completion and SUBACK can then be delayed past
  their timeouts. While reads are held, a broker that closes the connection is noticed only once
  reading resumes or a write fails. A broker whose socket to the client stays full applies its
  own slow-consumer policy (queue limits, dropping, or disconnecting).
- **The will is slow and fires on every failure.** The broker publishes it only after 1.5 ×
  `keepAliveSec` of silence (at least 180 s with the smallest keep-alive allowed today) unless the
  TCP connection is seen to close. It fires on any failure the client detects too, so a failure
  followed by a quick reconnect shows `offline` then `online`. A reconnect with the same client
  id before the broker noticed the old connection was lost also makes the broker publish it.
- **PUBACK order is not arrival order in every case.** PUBACKs for dropped packets
  (`RX_PUBLISH_HOLD_TIMEOUT`, `RX_PUBLISH_TOO_LARGE`, `RX_PUBLISH_TOPIC_TOO_LONG`) can go out
  ahead of those for earlier packets still waiting in the queue, which MQTT 3.1.1 4.6 does not
  allow; an owed PUBACK always precedes those of later deliveries. Every QoS 1
  packet still gets exactly one PUBACK. Mosquitto, EMQX and HiveMQ match a PUBACK to its message
  by packet id anywhere in the in-flight window (checked in their source), so this is harmless
  with them; AWS IoT Core and Azure IoT Hub do not document either way.
- **ASCII only.** Topic names, filters, client ids and user names with non-ASCII UTF-8 (accented
  letters, other scripts, emoji) cannot be sent, although MQTT allows them. Inbound topics are
  not limited, so a wildcard subscription still receives them.
- **Inbound UTF-8 is not validated.** MQTT 1.5.3 says a receiver must close the connection on
  ill-formed UTF-8. The client does not check: it passes inbound topic bytes to the application
  as received, so a broker that sends bad UTF-8 is not detected. The application must not assume
  a received topic is valid UTF-8. An oversized PUBLISH, dropped as it arrives, has its topic
  checked for nothing, since only its fixed header and length fields are read.
- **IPv4 only.** SSF is not designed for an IPv6 stack ([`ssfnet.h`](ssfnet.h)): `host` is a
  DNS name or a dotted IPv4 address, names resolve to IPv4 addresses only, and an IPv6 literal
  fails every attempt with `TRANSPORT_ERROR`. A broker with no IPv4 address cannot be reached.
- **Name resolution is polled.** [`ssfnetsock`](ssfnetsock.h) resolves host names with the OS
  asynchronous resolver (Windows 8 or later, macOS, glibc Linux) and never blocks. On other
  platforms it accepts only literal IPv4 addresses. A lookup the OS cannot cancel keeps
  running after `close()`; `SSF_NETSOCK_CONFIG_MAX_LOOKUPS` bounds how many may pile up, and once
  all are in use the attempt fails with `TRANSPORT_ERROR` and is retried after the backoff.
