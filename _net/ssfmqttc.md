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
- [`ssfnet.h`](ssfnet.h) — transport interface; [`ssfnetsock.h`](ssfnetsock.h) is the hosted TCP implementation
- [`_opt/ssfmqttc_opt.h`](../_opt/ssfmqttc_opt.h) (aggregated through `ssfoptions.h`)

<a id="design"></a>

## [↑](#ssfmqttc--mqtt-311-client) Design

- **One connection.** The client is a singleton. All calls come from the thread that runs
  `SSFSMTask()` and `SSFMQTTCTask()`.
- **Clean session only.** Every CONNECT requests a clean session. There is no Last Will, and
  published messages are never retained.
- **QoS 0 and 1.** A QoS 2 packet from the broker is a protocol error and ends the connection.
- **Self-healing.** Once started the client works continuously to reach and hold READY. Every
  failed attempt or lost connection is followed by a doubling backoff and a new attempt, until
  `SSFMQTTCStop()` is called. No jitter is added to the backoff; devices in a fleet desynchronize
  through clock drift and differing failure times.
- **Subscriptions are configuration.** The subscription set is part of the Start options and is
  sent as one SUBSCRIBE after every CONNACK. READY means every filter was granted. A filter
  granted a lower QoS than requested, which MQTT 3.1.1 allows, still reaches READY, reported with
  `SUBSCRIBE_DOWNGRADED`; any refused filter fails the attempt, and so does a higher QoS than
  requested, which is a broker error. No UNSUBSCRIBE is ever sent, since a clean
  session discards server-side state. To change the set: Stop, edit the table, Start.
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
- **No back-pressure.** The transport is always read. An inbound PUBLISH that cannot be queued is
  dropped and reported; a dropped QoS 1 packet is still acknowledged so the broker's in-flight
  window keeps moving.
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
READY, then eventually DISCONNECTED or STOPPED. A failed attempt yields CONNECT_FAILED. The
`reason` argument is NONE except where the table says otherwise.

| Event | When | Reason |
|-------|------|--------|
| `CONNECTED` | CONNACK accepted; SUBSCRIBE sent if subscriptions are configured | NONE |
| `READY` | Every subscription granted, or none configured. Publishing and receiving active. | NONE, or `SUBSCRIBE_DOWNGRADED` |
| `CONNECT_FAILED` | An attempt ended before READY. Reported at the point of failure; the client then enters RECONNECT_WAIT. | valid |
| `DISCONNECTED` | A READY connection was lost. Reported at the point of failure; the client then enters RECONNECT_WAIT. | valid |
| `STOPPED` | `Stop()` complete. The client is in STOPPED. | NONE |
| `RX_PUBLISH_DROPPED` | An inbound PUBLISH was discarded; a QoS 1 one is still acknowledged. The connection is unaffected. | `RX_PUBLISH_TIMEOUT`, `RX_PUBLISH_QUEUE_FULL`, `RX_PUBLISH_TOO_LARGE` or `RX_PUBLISH_TOPIC_TOO_LONG` |

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
| `SUBSCRIBE_REFUSED` | SUBACK refused one or more filters. |
| `SUBSCRIBE_QOS_EXCEEDED` | SUBACK granted a higher QoS than requested for one or more filters. Takes precedence over `SUBSCRIBE_REFUSED`. |
| `SUBSCRIBE_DOWNGRADED` | Reported with READY, not a failure: SUBACK granted a lower QoS than requested for one or more filters, and refused none. |
| `KEEPALIVE` | No PINGRESP within [`SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT`](#opt-pingresp). |
| `TX_PUBLISH_TIMEOUT` | A publish did not complete within `txPublishTimeout`. |
| `PROTOCOL` | Malformed packet, QoS 2, or a packet type not valid at that point. |
| `RX_OVERFLOW` | Inbound packet other than PUBLISH larger than `rxBlockSize`. |
| `RX_PUBLISH_TIMEOUT` | The application deferred an inbound PUBLISH past [`SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS`](#opt-maxticks). |
| `RX_PUBLISH_QUEUE_FULL` | An inbound PUBLISH arrived with no free rx block. |
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

- `txBlockSize` must hold the largest of CONNECT, SUBSCRIBE and any PUBLISH the application sends,
  including the fixed header. CONNECT and SUBSCRIBE that do not fit assert at connect time; a
  PUBLISH that does not fit makes `TxPublish()` return `false`.
- tx blocks in use at any moment are those queued for the transport plus QoS 1 PUBLISH and
  SUBSCRIBE awaiting acknowledgement, so `txBlocks` bounds the application's outstanding publishes.
  `txBlocks` must be at least 1.
- `rxBlockSize` must hold the largest inbound packet the application wants, including the fixed
  header. A PUBLISH that does not fit is dropped (`RX_PUBLISH_TOO_LARGE`); any other packet that
  does not fit ends the connection (`RX_OVERFLOW`). One rx block is permanently the framing buffer
  so the transport can always be read; the rest hold inbound PUBLISH packets awaiting the
  application. A PUBLISH arriving with no free rx block is dropped.
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
| `topic`, `topicLen` | NUL terminated, shorter than the topic constant. Valid only during the callback. |
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
`ssfoptions.h`). Sizes include the NUL terminator.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE` | `128` | Topic names and filters, 2..65536. Also bounds inbound topics. |
| `SSF_MQTTC_CONFIG_MAX_HOST_SIZE` | `64` | Broker host name or address, 2..256. |
| `SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE` | `64` | Client identifier, 2..65536. Brokers must accept 1 to 23 characters. |
| `SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE` | `64` | User name, 2..65536. |
| `SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN` | `64` | Password bytes, 1..65535. Binary, not NUL terminated. |
| `SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS` | `8` | Maximum entries in the subscription set. |
| <a id="opt-depth"></a>`SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH` | `4` | Inbound PUBLISH packets held for the application. Sizes the rx pool and the PUBACK capacity. |
| <a id="opt-retry"></a>`SSF_MQTTC_CONFIG_RX_PUBLISH_RETRY_TICKS` | 1 s | Re-offer interval for a deferred inbound PUBLISH. |
| <a id="opt-maxticks"></a>`SSF_MQTTC_CONFIG_RX_PUBLISH_MAX_TICKS` | 30 s | A deferred inbound PUBLISH is dropped this long after its first offer. |
| <a id="opt-openpoll"></a>`SSF_MQTTC_CONFIG_OPEN_POLL_TICKS` | 10 ms | Longest `SSFMQTTCTask()` lets the app loop sleep while the transport resolves the host and connects. |
| <a id="opt-pingresp"></a>`SSF_MQTTC_CONFIG_PINGRESP_TIMEOUT` | 30 s (250 ms in the ssfmqttc unit test build) | Connection is dropped if PINGRESP does not follow PINGREQ within this time. Bounds the minimum `keepAliveSec` at four times this value. Override with `-D`. |

The ssfsm event and timer pools must be sized for the client: see `SSF_SM_MAX_ACTIVE_EVENTS` and
`SSF_SM_MAX_ACTIVE_TIMERS` in [`_opt/ssfsm_opt.h`](../_opt/ssfsm_opt.h). The client alone can
have outstanding at once: one each of TRANSPORT_OPEN, LINK_FAIL, TX_DRAINED, START and STOP, one
event per running timer (up to three during a session), plus one decoded-packet event per control
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
| `clientId` | Required. At least one character, shorter than `MAX_CLIENT_ID_SIZE`. Chosen by the application; the client never generates one. |
| `usernameOpt` | NULL for none. Shorter than `MAX_USERNAME_SIZE`. |
| `passwordOpt`, `passwordLen` | NULL and 0 for none. Requires `usernameOpt`. `passwordLen` at most `MAX_PASSWORD_LEN`. |
| `subsOpt`, `subCount` | Array of `SSFMQTTCSub_t` (filter and QoS 0 or 1). NULL and 0 for none. `subCount` at most `MAX_SUBSCRIPTIONS`; each filter shorter than `MAX_TOPIC_SIZE`. Wildcard placement is not checked; the broker refuses a bad filter. |
| `keepAliveSec` | Advertised to the broker. Must be at least four times `PINGRESP_TIMEOUT` in seconds. |
| `connectTimeout` | Ticks, greater than 0. Transport open through CONNACK accepted. |
| `subscribeTimeout` | Ticks, greater than 0. SUBSCRIBE sent through SUBACK received. |
| `txPublishTimeout` | Ticks, greater than 0. Publish call through completion. On expiry the connection is dropped with `TX_PUBLISH_TIMEOUT` and every pending publish callback fires `false`. |
| `reconnectMinWait` | Ticks, greater than 0. First backoff; doubles per consecutive failure. |
| `reconnectMaxWait` | Ticks, at least `reconnectMinWait`. Backoff cap. |

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
| [e.g.](#ex-publish) | [`bool SSFMQTTCTxPublish(...)`](#ssfmqttctxpublish) | Queue a QoS 0 or 1 publish; completion reported by callback. |
| | [`SSFMQTTCState_t SSFMQTTCGetState()`](#ssfmqttcgetstate) | Current client state. |

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
`subscribeTimeout`, or SUBACK refuses any filter or grants a higher QoS than requested. A lower
grant is accepted and reported with READY. On any failure or lost connection
the client sends DISCONNECT if a session exists, closes the transport, reports `CONNECT_FAILED` or
`DISCONNECTED`, waits out the backoff in RECONNECT_WAIT, and tries again.

Asserts unless STOPPED and not already started, and if any option violates its
[constraint](#start-options-ssfmqttcopts_t).

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
bool SSFMQTTCTxPublish(SSFCStrIn_t topic, const uint8_t *payload, size_t payloadLen,
                       SSFMQTTCQoS_t qos, SSFMQTTCTxPublishFn_t txPublishFnOpt,
                       void *txPublishFnCtxOpt);
```

Queues a PUBLISH. Valid only when `SSFMQTTCIsReady()` is true. On `true` the completion callback,
if given, is guaranteed to fire exactly once within `txPublishTimeout` with the context as its
first argument; the tx block is held until then.

Asserts if not initialized, `topic` is NULL, `payload` is NULL with a non-zero length, `qos` is
not 0 or 1, or a context is given without a callback.

**Returns:** `false` if not READY, if `topic` is not a valid topic shorter than the topic
constant, if the encoded packet would not fit a tx block, or if no tx block is free. Retry later.
`true` if queued.

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
                          SSF_MQTTC_QOS_1, OnPublished, (void *)(uintptr_t)42) == false)
    { /* no tx block free or packet too large; try again later */ }
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

<a id="known-trade-offs"></a>

## [↑](#ssfmqttc--mqtt-311-client) Known Trade-offs

- **Non-transient failures are retried.** CONNACK refusals other than `SERVER_UNAVAILABLE`, and
  `SUBSCRIBE_REFUSED` and `SUBSCRIBE_QOS_EXCEEDED`, are retried at the backoff rate like any other
  failure. Bad credentials or a refused filter keep hitting the broker until the application calls
  `SSFMQTTCStop()`. The event carries no per-filter detail, and one refused filter fails the whole
  set even if the others were granted. A later revision could stop the client
  itself and report the reason through the STOPPED event, or expose per-filter SUBACK results.
- **IPv4 only.** SSF is not designed for an IPv6 stack ([`ssfnet.h`](ssfnet.h)): `host` is a
  DNS name or a dotted IPv4 address, names resolve to IPv4 addresses only, and an IPv6 literal
  fails every attempt with `TRANSPORT_ERROR`. A broker with no IPv4 address cannot be reached.
- **Name resolution is polled.** [`ssfnetsock`](ssfnetsock.h) resolves host names with the OS
  asynchronous resolver (Windows 8 or later, macOS, glibc Linux) and never blocks. On other
  platforms it accepts only literal IPv4 addresses. A lookup the OS cannot cancel keeps
  running after `close()`; `SSF_NETSOCK_CONFIG_MAX_LOOKUPS` bounds how many may pile up, and once
  all are in use the attempt fails with `TRANSPORT_ERROR` and is retried after the backoff.
