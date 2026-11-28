# ssfawsprov — AWS IoT Fleet Provisioning

[SSF](../README.md) | [Network](README.md)

Device-side AWS IoT Core [fleet provisioning by claim](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html)
over MQTT. A device that ships with only a shared claim certificate connects once with it, asks
AWS to sign a certificate for a key the device generated itself (CreateCertificateFromCsr), and
registers itself as a thing (RegisterThing). It ends up with its own certificate, thing name and
private key, kept as one blob, and from then on connects with that identity.

> **Status: not yet validated against a live AWS account.** The module is unit tested against a
> scripted mock broker and OpenSSL-made fixtures. The live checks (plan tasks V01 to V03: TLS
> policy, real response sizes, the ownership token length, the claim policy, an empty CSR subject)
> are open. Known limitation: ssfmqttc, and so this module, does not yet work with
> `SSF_CONFIG_ENABLE_THREAD_SUPPORT` 0 (plan task G14); see [Known Limitations](#known-limitations).

The private key never leaves the device: AWS sees only a PKCS#10 CSR. The module runs on
[ssfmqttc](ssfmqttc.md) and [ssftlsc](README.md#ssftlsc-tls-13-client), uses the
[ssfsm](../_fsm/README.md) state machine for its timers, and allocates no memory: the caller owns
the work set and the credentials.

[Dependencies](#dependencies) | [Design](#design) | [AWS Setup](#aws-setup) | [Application Flow](#application-flow) | [Buffers and Memory](#buffers-and-memory) | [Security](#security) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Known Limitations](#known-limitations)

<!-- doccheck: include ssfawsprov.h ssfnetsock.h ssfsm.h ssfecdsa.h ssfrtc.h ssfpkey.h -->

<a id="dependencies"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Dependencies

- [`ssfport.h`](../ssfport.h), [`ssf.h`](../ssf.h), [`ssfassert.h`](../ssfassert.h)
- [`ssfmqttc.h`](ssfmqttc.h) — the MQTT client; one provisioning run owns it from `SSFMQTTCInit()`
  to `SSFMQTTCDeInit()`
- [`ssftlsc.h`](ssftlsc.h) — TLS 1.3 with the claim certificate, later with the device's own
- [`_fsm/ssfsm.h`](../_fsm/ssfsm.h) — `SSFSMInit()` before `SSFAWSProvInit()`. `SSF_SM_AWSPROV` in
  `SSFSMList_t` and the `SSF_SM_EVENT_AWSPROV_*` ids in `SSFSMEventList_t`, both in
  [`_opt/ssfsm_opt.h`](../_opt/ssfsm_opt.h) (already there)
- [`_codec/ssfjson.h`](../_codec/ssfjson.h) — request and response JSON
- [`_codec/ssfx509.h`](../_codec/ssfx509.h), [`_codec/ssfpem.h`](../_codec/ssfpem.h) — CSR
  encoding, certificate parsing
- [`_crypto/ssfecdsa.h`](../_crypto/ssfecdsa.h), [`_codec/ssfpkey.h`](../_codec/ssfpkey.h) — the
  device key (P-256 or P-384), CSR signature
- [`_edc/ssfcrc32.h`](../_edc/ssfcrc32.h) — the credentials blob check
- [`_opt/ssfawsprov_opt.h`](../_opt/ssfawsprov_opt.h) (aggregated through `ssfoptions.h`)

The state machine and the credentials need `SSF_ECDSA_CONFIG_ENABLE_SIGN` 1 and at least one of
P-256 and P-384. Without signing only the request builders and parsers below are compiled.

<a id="design"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Design

### The flow

```
 device                                                      AWS IoT Core
   |  TLS 1.3, claim certificate, clientId = app's choice          |
   |-- CONNECT ---------------------------------------------------->|
   |-- SUBSCRIBE (QoS 1) $aws/certificates/create-from-csr/json/    |
   |      accepted, .../rejected,                                   |
   |      $aws/provisioning-templates/<t>/provision/json/accepted,  |
   |      .../rejected ------------------------------------------->|
   |                                                                |
   |-- PUBLISH .../create-from-csr/json                             |
   |      {"certificateSigningRequest":"<CSR PEM>"} --------------->|
   |<- .../accepted {"certificateId","certificatePem",              |
   |                 "certificateOwnershipToken"} ------------------|
   |                                                                |
   |-- PUBLISH $aws/provisioning-templates/<t>/provision/json       |
   |      {"certificateOwnershipToken":"...","parameters":{...}} -->|
   |<- .../accepted {"thingName","deviceConfiguration"} ------------|
   |                                                                |
   |  done callback: keep the credentials, store the blob           |
   |  disconnect; reconnect with the new certificate,               |
   |  clientId = thingName                                          |
```

A `.../rejected` answer carries `{"statusCode","errorCode","errorMessage"}`.

### The state machine

`SSFAWSProvStart()` derives the public key, builds the topics and the CSR request (once: a retry
resends the same bytes and never signs again), and starts ssfmqttc. Then:

| State | Waits for | Then |
|---|---|---|
| WAIT_READY | ssfmqttc READY with all four filters granted | sends the step's stored request (SENT) |
| SENT | an answer, or `responseTimeout` | accepted: next step or done; rejected 429/5xx, unparseable or timeout: BACKOFF; rejected other: fails |
| | (a request `SSFMQTTCTxPublish()` refuses never reaches SENT) | BACKOFF, as a failed try |
| BACKOFF | the backoff timer | sends again (or WAIT_READY if the link is down) |

The two steps are CreateCertificateFromCsr then RegisterThing. Any answer for the current step
counts, also one arriving late in BACKOFF or WAIT_READY. Answers for the other step, duplicates and
publishes on other topics are ignored.

- **Backoff** doubles from `retryMinWait` to `retryMaxWait`; each wait is jittered within
  [w/2, w], seeded from the device public key, so a fleet coming up together spreads out (fleet
  provisioning is throttled account wide).
- **Link loss.** ssfmqttc always uses a clean session, so an answer published while the link is
  down is lost: after the next READY the step's request is sent again. A link loss during BACKOFF
  doesn't cut the backoff short.
- **Token age.** The ownership token expires after one hour, and AWS deletes a certificate that is
  never registered. If the RegisterThing request is about to be sent with a token older than
  `tokenLifetime`, the run goes back to CreateCertificateFromCsr with the same CSR.
- **Retries cost certificates.** Each CreateCertificateFromCsr request AWS accepts issues a new
  certificate, so a retry after a lost or late answer can leave extra ones in PENDING_ACTIVATION
  (AWS deletes them after the token's hour). The same holds for a run that ends with BUILD on the
  RegisterThing request (a parameter that can't be sent, a request over
  `SSF_AWSPROV_CONFIG_REG_REQ_SIZE`): that is only found once the certificate exists. Check the
  parameters before Start.
- **Every run ends.** `maxAttempts` counts tries per step for the whole run: each send and each
  failed connect is a try, and going back to the first step on an old token doesn't reset the
  counts. `deadline` counts from Start. Start requires at least one of them to be non-zero.
- **The result** goes to the done callback exactly once (`SSFAWSProvResult_t`): on success the
  certificate, thing name and device configuration; on failure a reason and the last rejected
  `statusCode`, `errorCode` and `errorMessage`. Then the work set is wiped and ssfmqttc is told to
  stop.

| Reason | Meaning |
|---|---|
| `SSF_AWSPROV_REASON_NONE` | Done: certificate issued, thing registered |
| `SSF_AWSPROV_REASON_BUILD` | A request could not be built: template name, private key, CSR too large for `SSF_AWSPROV_CONFIG_CSR_REQ_SIZE`, RegisterThing request too large or a parameter that can't be sent |
| `SSF_AWSPROV_REASON_REJECTED` | AWS rejected with a `statusCode` other than 429 or 5xx |
| `SSF_AWSPROV_REASON_ATTEMPTS` | `maxAttempts` used up on timeouts, retryable rejects, failed connects, or resends after link losses |
| `SSF_AWSPROV_REASON_BAD_RESPONSE` | `maxAttempts` used up, the last answer unparseable |
| `SSF_AWSPROV_REASON_TX_REFUSED` | `maxAttempts` used up, the last request refused by `SSFMQTTCTxPublish()` (a txBlockSize too small, or a full pool) |
| `SSF_AWSPROV_REASON_DEADLINE` | `deadline` passed |
| `SSF_AWSPROV_REASON_SUBSCRIBE_REFUSED` | AWS refused a response filter: the claim policy is wrong |
| `SSF_AWSPROV_REASON_CONNECT_REFUSED` | CONNACK 1, 2, 4 or 5; CONNACK 3 and transport failures are retried |

### What the parsers check

Every response is treated as untrusted input, though only AWS can publish on `$aws` topics over
the authenticated TLS session. The payload is copied with a NUL into the work set's rx buffer,
which is zeroed after every parse.

- **CreateCertificateFromCsr accepted:** `certificateId` 64 lowercase hex; the ownership token kept
  as the raw escaped JSON text; `certificatePem` exactly one CERTIFICATE block that parses, with an
  id-ecPublicKey key on the device's curve equal to the device's public key.
- **RegisterThing accepted:** `thingName` 1..128 of `[a-zA-Z0-9:_-]` (it becomes the operational
  MQTT client id; checked on the raw text, so an escape is refused); `deviceConfiguration` an
  object (or absent, given as `{}`) copied whole. The whole response may nest at most
  `SSF_JSON_CONFIG_MAX_IN_DEPTH` levels (4 by default, the response object included), so a
  template's device configuration can hold objects or arrays two levels deep; deeper makes the
  response unparseable (the run ends with BAD_RESPONSE).
- **Rejected:** `statusCode` exactly three digits 100..599; `errorCode` required and under 64
  characters, `errorMessage` optional and cut to fit; both reduced to printable ASCII. A reject that
  fails these checks counts as unparseable, not as REJECTED: it is retried, and a run whose last
  answer was one ends with BAD_RESPONSE even if AWS meant a fatal error.

<a id="aws-setup"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) AWS Setup

**Provisioning template.** Create a fleet provisioning template whose name is 1 to 36 characters of
`[0-9A-Za-z_-]`. Its parameters are what the device sends as `SSFAWSProvOpts_t.paramsOpt`: names
and values must be ASCII (bytes below 0x80; control bytes are escaped). Non-ASCII UTF-8 is refused,
because ssfjson would escape each byte separately and AWS would read different characters.

**Claim certificate policy.** The AWS documentation's example policy names
`$aws/certificates/create/*`, which does **not** match the CreateCertificateFromCsr topics this
module uses. Attach a policy like this to the claim certificate (replace region, account and
template):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "iot:Connect", "Resource": "*" },
    { "Effect": "Allow", "Action": ["iot:Publish", "iot:Receive"],
      "Resource": [
        "arn:aws:iot:REGION:ACCOUNT:topic/$aws/certificates/create-from-csr/*",
        "arn:aws:iot:REGION:ACCOUNT:topic/$aws/provisioning-templates/TEMPLATE/provision/*" ] },
    { "Effect": "Allow", "Action": "iot:Subscribe",
      "Resource": [
        "arn:aws:iot:REGION:ACCOUNT:topicfilter/$aws/certificates/create-from-csr/*",
        "arn:aws:iot:REGION:ACCOUNT:topicfilter/$aws/provisioning-templates/TEMPLATE/provision/*" ] }
  ]
}
```

A refused subscription ends the run with `SSF_AWSPROV_REASON_SUBSCRIBE_REFUSED`. A connection AWS
closes or refuses for another policy reason is retried as a failed connect, until `maxAttempts` or
`deadline` (how AWS signals each policy error is not yet observed; V01).

**Endpoint TLS policy.** ssftlsc speaks TLS 1.3 only. The default policy of a new domain
configuration allows it (`IoTSecurityPolicy_TLS13_1_2_2022_10`; in GovCloud
`IoTSecurityPolicy_TLS13_1_2_2022_01`). Which policy an older account's existing `iot:Data-ATS`
endpoint uses is not documented (to be checked on a real account, V01); a TLS 1.2-only one must be
changed. Check, and update if needed:

```sh
aws iot describe-domain-configuration --domain-configuration-name "iot:Data-ATS"
aws iot update-domain-configuration --domain-configuration-name "iot:Data-ATS" \
    --tls-config securityPolicy=IoTSecurityPolicy_TLS13_1_2_2022_10
```

**Server trust.** Trust Amazon Root CA 1 (RSA 2048) and Amazon Root CA 3 (ECC P-256); CA 2 and 4
may be added. Get them from AWS (they are not reproduced here) and build the store with
`SSFTLSCTrustFromPEM()`. `SSFRTCInit()` must have run, and the clock must be set, before a
handshake with trust anchors.

**Port.** 8883, or 443 with ALPN `x-amzn-mqtt-ca` (`SSFTLSCSetALPN()`).

**Trusted-user provisioning.** The temporary claim certificate from CreateProvisioningClaim
expires after five minutes, and the device must finish within five minutes of connecting with it.
Use the same flow with `deadline` at most `SSF_AWSPROV_TRUSTED_USER_DEADLINE`; `deadline` counts
from Start, so shorten it by however long the certificate took to reach the device.

**JITP (just-in-time provisioning)** needs no module: the device connects with a certificate
signed by a CA registered with a JITP template, and AWS registers it. With ssftlsc that is
`SSFTLSCSetClientCert()` with a one- or two-certificate chain.

<a id="application-flow"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Application Flow

The example covers the first boot (provision, keep the credentials) and every later boot (load
them and connect). `App*` functions are the application's own. The loop runs `SSFSMTask()` and
`SSFMQTTCTask()` on one thread; a real application sleeps on their `nextTimeout` between calls.

```c
#include <string.h>

/* The application's own (storage, claim credentials, logging) */
extern bool AppLoadBlob(uint8_t *blob, size_t size, size_t *len);
extern bool AppStoreBlob(const uint8_t *blob, size_t len);
extern const SSFTLSCTrustStore_t *AppAmazonRoots(void);  /* From SSFTLSCTrustFromPEM() */
extern const uint8_t *const appClaimChain[1];             /* Claim certificate DER */
extern const uint32_t appClaimChainLen[1];
extern const SSFPKey_t *AppClaimKey(void);                /* From SSFPKeyDecodeDER() */
extern void AppLogFailure(SSFAWSProvReason_t reason, uint16_t statusCode, SSFCStrIn_t code);
extern uint64_t AppGetUnixTime(void);                     /* NTP, GPS, a battery-backed RTC */

#define APP_ENDPOINT "xxxxxxxxxxxxxx-ats.iot.us-east-1.amazonaws.com"

static SSFNetSock_t _sock;
static SSFTLSCSession_t _tls;
static SSFAWSProvWork_t _work;           /* About 13.7 KB, only during provisioning */
static SSFAWSProvCred_t _cred;           /* Must outlive the operational session */
static uint8_t _blob[SSF_AWSPROV_CRED_BLOB_MAX_SIZE];
static uint8_t _devKey[32];              /* P-256 scalar; secret */
static bool _isProvisioned;
static const SSFAWSProvParam_t _params[] = { { "SerialNumber", "SN-0001" } };
static const SSFX509GenName_t _subject = { "SN-0001", NULL, NULL, NULL, NULL, NULL };

/* Keeps the credentials when provisioning succeeded; runs once per run */
static void AppProvDone(void *ctx, bool isDone, const SSFAWSProvResult_t *result)
{
    size_t len;

    (void)ctx;
    if (isDone == false)
    {
        AppLogFailure(result->reason, result->statusCode, result->errorCode);
        return;
    }
    /* The result is valid only here: copy it into the credentials, then store the blob */
    if (SSFAWSProvCredFromResult(result, SSF_EC_CURVE_P256, _devKey, sizeof(_devKey), &_cred) &&
        SSFAWSProvCredEncode(&_cred, _blob, sizeof(_blob), &len))
    {
        _isProvisioned = AppStoreBlob(_blob, len);
    }
    memset(_blob, 0, sizeof(_blob));     /* The blob holds the private key */
    if (_isProvisioned == false) SSFAWSProvCredWipe(&_cred);
}

/* Ends the claim connection: DeInit wipes ssfmqttc's buffers (they held the token) and the */
/* claim TLS session; the device key stays only where the credentials were kept */
static void AppClaimTeardown(bool isMqttInit)
{
    if (isMqttInit)
    {
        SSFAWSProvDeInit();
        SSFMQTTCDeInit();
    }
    SSFTLSCDeInit(&_tls);
    SSFNetSockDeInit(&_sock);
    memset(_devKey, 0, sizeof(_devKey));
}

/* Runs both tasks until the provisioning run is over and ssfmqttc has stopped */
static void AppRunProvisioning(void)
{
    while (SSFAWSProvIsStarted() || (SSFMQTTCGetState() != SSF_MQTTC_STATE_STOPPED))
    {
        (void)SSFSMTask(NULL);
        (void)SSFMQTTCTask(NULL);
    }
}

/* First boot: provision with the claim certificate. True if the credentials are stored. */
static bool AppProvision(void)
{
    SSFAWSProvOpts_t opts;
    uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
    size_t pubLen;

    /* The device key: a new one per run, so a CSR is never signed twice; never leaves the device */
    if (SSFECDSAKeyGen(SSF_EC_CURVE_P256, _devKey, sizeof(_devKey), pub, sizeof(pub),
                       &pubLen) == false) return false;

    /* Claim connection: TLS with the claim certificate, ssfmqttc bound to ssfawsprov */
    SSFNetSockInit(&_sock);
    SSFTLSCInit(&_tls, &_sock.transport, AppAmazonRoots());
    if (SSFTLSCSetClientCert(&_tls, appClaimChain, appClaimChainLen, 1u, AppClaimKey()) == false)
    {
        AppClaimTeardown(false);
        return false;
    }
    SSFMQTTCInit(&_tls.transport, 2u, SSF_AWSPROV_MIN_TX_BLOCK_SIZE,
                 SSF_AWSPROV_MIN_RX_BLOCK_SIZE, SSFAWSProvRxPublish, NULL, SSFAWSProvEvent,
                 NULL);
    SSFAWSProvInit();

    memset(&opts, 0, sizeof(opts));
    opts.mqtt.host = APP_ENDPOINT;
    opts.mqtt.port = 8883u;
    opts.mqtt.clientId = "SN-0001";      /* Any id the claim policy allows */
    opts.mqtt.keepAliveSec = 300u;
    opts.mqtt.connectTimeout = SSF_TICKS_PER_SEC * 30u;
    opts.mqtt.subscribeTimeout = SSF_TICKS_PER_SEC * 10u;
    opts.mqtt.txPublishTimeout = SSF_TICKS_PER_SEC * 10u;
    opts.mqtt.reconnectMinWait = SSF_TICKS_PER_SEC;
    opts.mqtt.reconnectMaxWait = SSF_TICKS_PER_SEC * 60u;
    opts.templateName = "MyFleetTemplate";
    opts.curve = SSF_EC_CURVE_P256;
    opts.privKey = _devKey;
    opts.privKeyLen = sizeof(_devKey);
    opts.subjectOpt = &_subject;
    opts.paramsOpt = _params;
    opts.paramCount = sizeof(_params) / sizeof(_params[0]);
    opts.responseTimeout = SSF_AWSPROV_DEFAULT_RESPONSE_TIMEOUT;
    opts.retryMinWait = SSF_AWSPROV_DEFAULT_RETRY_MIN_WAIT;
    opts.retryMaxWait = SSF_AWSPROV_DEFAULT_RETRY_MAX_WAIT;
    opts.deadline = SSF_TICKS_PER_SEC * 15u * 60u;
    opts.tokenLifetime = SSF_AWSPROV_DEFAULT_TOKEN_LIFETIME;
    opts.maxAttempts = SSF_AWSPROV_DEFAULT_MAX_ATTEMPTS;

    _isProvisioned = false;
    SSFAWSProvStart(&_work, &opts, AppProvDone, NULL, NULL, NULL);
    AppRunProvisioning();

    AppClaimTeardown(true);              /* The key is now only in _cred and the stored blob */
    return _isProvisioned;
}

/* Every boot after: load the credentials and point a TLS session at them */
static bool AppLoadIdentity(void)
{
    size_t len;
    bool ok;

    if (AppLoadBlob(_blob, sizeof(_blob), &len) == false) return false;
    ok = SSFAWSProvCredDecode(_blob, len, &_cred);
    memset(_blob, 0, sizeof(_blob));
    return ok;
}

/* Operational connection with the device's own identity; the app's own MQTT callbacks */
static bool AppConnect(SSFMQTTCRxPublishFn_t rxFn, SSFMQTTCEventFn_t eventFn,
                       const SSFMQTTCSub_t *subs, uint32_t subCount)
{
    SSFMQTTCOpts_t opts;

    SSFNetSockInit(&_sock);
    SSFTLSCInit(&_tls, &_sock.transport, AppAmazonRoots());
    if (SSFAWSProvApplyTLS(&_tls, &_cred) == false) return false;
    SSFMQTTCInit(&_tls.transport, 4u, 512u, 1024u, rxFn, NULL, eventFn, NULL);

    memset(&opts, 0, sizeof(opts));
    opts.host = APP_ENDPOINT;
    opts.port = 8883u;
    opts.clientId = _cred.thingName;     /* Thing policies usually require it as client id */
    opts.subsOpt = subs;
    opts.subCount = subCount;
    opts.keepAliveSec = 300u;
    opts.connectTimeout = SSF_TICKS_PER_SEC * 30u;
    opts.subscribeTimeout = SSF_TICKS_PER_SEC * 10u;
    opts.txPublishTimeout = SSF_TICKS_PER_SEC * 10u;
    opts.reconnectMinWait = SSF_TICKS_PER_SEC;
    opts.reconnectMaxWait = SSF_TICKS_PER_SEC * 60u;
    SSFMQTTCStart(&opts);
    return true;
}

/* Start-up: SSFRTCInit() and SSFSMInit() once, then provision if there is no identity yet */
bool AppStart(SSFMQTTCRxPublishFn_t rxFn, SSFMQTTCEventFn_t eventFn, const SSFMQTTCSub_t *subs,
              uint32_t subCount)
{
    /* Certificate checks need the real time: a clock at 1970 fails every handshake */
    if ((SSFRTCInit() == false) || (SSFRTCSet(AppGetUnixTime()) == false)) return false;
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
    if ((AppLoadIdentity() == false) && (AppProvision() == false)) return false;
    return AppConnect(rxFn, eventFn, subs, subCount);
}
```

Notes on the example:

- `AppProvDone()` runs once per run, possibly before `SSFAWSProvStart()` returns (reason
  `SSF_AWSPROV_REASON_BUILD`). It must not call `SSFAWSProvStart()` or `SSFAWSProvStop()`; start a
  new run after ssfmqttc reports STOPPED.
- `_cred` must outlive the TLS session that points into it. Before `SSFAWSProvCredWipe(&_cred)`,
  a new `SSFAWSProvCredDecode()` into it, or freeing it, clear the session's client certificate
  (`SSFTLSCSetClientCert(&_tls, NULL, NULL, 0, NULL)`) or `SSFTLSCDeInit()` it.
- The work set is needed only while a run is in progress; it may share memory with buffers the
  application uses only after provisioning.
- `SSFAWSProvStop()` ends a run at any point with no done callback; the work set is wiped before it
  returns and ssfmqttc stops afterwards.
- With the blob stored, a failed `SSFAWSProvCredDecode()` at a later boot means the blob is corrupt
  or from another build; the device can provision again.

<a id="buffers-and-memory"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Buffers and Memory

| What | Size at defaults | Notes |
|---|---|---|
| `SSFAWSProvWork_t` | 13,696 B (Cortex-M4) | Caller owned, during a run only. Mostly the rx copy (`SSF_AWSPROV_CONFIG_RX_SIZE`), the CSR accepted result (token, certificate DER, parsed certificate) and the two stored requests |
| `SSFAWSProvCred_t` | 2,808 B (Cortex-M4) | Caller owned, as long as the operational TLS session |
| Credentials blob | at most `SSF_AWSPROV_CRED_BLOB_MAX_SIZE` (1,790 B) | Fits one ssfcfg record |
| ssfmqttc `rxBlockSize` | at least `SSF_AWSPROV_MIN_RX_BLOCK_SIZE` (4,190 B) | A response payload of `SSF_AWSPROV_CONFIG_RX_SIZE` - 1 bytes on the longest topic at QoS 1: no response the parsers could take is dropped |
| ssfmqttc `txBlockSize` | at least `SSF_AWSPROV_MIN_TX_BLOCK_SIZE` (2,645 B) | The largest request the builders make |
| ssfawsprov static RAM | 32 B | |
| ssfawsprov code | 8,464 B (Cortex-M4), 9,384 B (Cortex-M0+), -Os | Not counting its dependencies |

- ssfmqttc allocates `SSF_MQTTC_CONFIG_RX_PUBLISH_QUEUE_DEPTH + 1` rx blocks (5 at the default
  depth 4), so the provisioning connection's rx pool is about 21 KB at the default rx block size.
  Both block minimums follow the options: a smaller `SSF_AWSPROV_CONFIG_RX_SIZE` (once real
  response sizes are known) or queue depth shrinks it. A tx block too small makes every send fail
  with `SSF_AWSPROV_REASON_TX_REFUSED`; an rx block too small drops the response
  (`SSF_MQTTC_EVENT_RX_PUBLISH_DROPPED`) and the step times out.
- The largest expected response is CreateCertificateFromCsr accepted: about 2.1 to 2.5 KB (a 1.2 KB
  certificate PEM, the token, the id). Its parser needs more than the payload in the rx copy: the
  payload, a NUL, the decoded certificate PEM and a NUL must all fit `SSF_AWSPROV_CONFIG_RX_SIZE`.
  When shrinking `SSF_AWSPROV_CONFIG_RX_SIZE` to real sizes (V02 will measure them), size it for
  that sum, not for the payload alone.
- ssfsm: the run uses 2 timers (deadline, and response or backoff) on top of ssfmqttc's at most 4;
  the default `SSF_SM_MAX_ACTIVE_TIMERS` (8) is enough. Its events add at most a few to the queue at
  once (START or STOP, one response, READY or a link event, one timer), and only while a run is
  started; see [ssfmqttc's sizing note](ssfmqttc.md#configuration) for `SSF_SM_MAX_ACTIVE_EVENTS`.
- Compile-time checks (`#error`) tie the options to ssfmqttc and ssfjson:
  `SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE` >= `SSF_AWSPROV_MAX_TOPIC_SIZE` (89),
  `SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE` >= `SSF_AWSPROV_CONFIG_THING_NAME_SIZE` (129 by default, so
  the thing name fits as the client id), `SSF_MQTTC_CONFIG_MAX_SUBSCRIPTIONS` >= 4,
  `SSF_JSON_CONFIG_MAX_IN_LEN` >= `SSF_AWSPROV_CONFIG_RX_SIZE` - 1 and >=
  `SSF_AWSPROV_CONFIG_REG_REQ_SIZE` - 1, `SSF_JSON_CONFIG_MAX_IN_DEPTH` >= 2.

<a id="security"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Security

- **The private key** is used only inside `SSFAWSProvStart()` (public key, CSR signature) and is not
  kept in the work set. After a successful run it lives in the application's key buffer, in
  `SSFAWSProvCred_t` and in the blob. **The blob is a secret**: store it where the device keeps
  secrets, and wipe RAM copies after use (`SSFAWSProvCredWipe()`, `memset`).
- **The ownership token** is a credential for RegisterThing on the new certificate for an hour. The
  module wipes its own copies (the rx buffer after every parse, the work set at the end). ssfmqttc
  does not wipe pool blocks when it frees them: the RegisterThing request and the
  CreateCertificateFromCsr response stay in ssfmqttc's tx and rx blocks until `SSFMQTTCDeInit()`,
  which wipes every block. DeInit ssfmqttc after provisioning, and `SSFTLSCDeInit()` the claim
  session (it wipes the session, record buffers included).
- **Deterministic signatures.** ssfecdsa signs with RFC 6979, so signing the same CSR again gives
  the same signature; a fault injected into a repeated signature is a known way to recover the key.
  The module builds the CSR request once per run and resends those bytes, but a new run with the
  same key signs the same CSR again: generate a new key for each run (the example does). For field
  devices, also set `SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN` 1.
- **Jitter** is seeded from the public key. It is not secret and is not meant to be.
- **What is not checked.** The certificate's CA signature is not verified (the device doesn't hold
  the AWS CA that issued it); the response arrives over the TLS session that authenticated AWS,
  and the certificate must carry the device's own public key. `certificateId` is checked for its
  format only, not against the certificate. A CRC protects the blob against corruption, not
  against deliberate change.
- **Threads.** Every call and callback runs on the one thread that runs `SSFSMTask()` and
  `SSFMQTTCTask()`.

<a id="configuration"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Configuration

Options live in [`_opt/ssfawsprov_opt.h`](../_opt/ssfawsprov_opt.h). Sizes include the NUL.

| Option | Default | Range | Description |
|---|---|---|---|
| `SSF_AWSPROV_CONFIG_RX_SIZE` | 4096 | 2..65536 | The NUL-terminated copy of one response payload; also the CSR build scratch |
| `SSF_AWSPROV_CONFIG_THING_NAME_SIZE` | 129 | 2..129 | Largest thing name accepted (AWS allows 128); also the blob's |
| `SSF_AWSPROV_CONFIG_TOKEN_SIZE` | 2048 | 2..RX_SIZE | The ownership token as raw escaped JSON text (real length measured by V02) |
| `SSF_AWSPROV_CONFIG_CERT_DER_SIZE` | 1536 | 256..min(`SSF_X509_CONFIG_MAX_CERT_SIZE`, 65000) | The issued certificate's DER |
| `SSF_AWSPROV_CONFIG_CSR_REQ_SIZE` | 1024 | 256..65536 | The stored CreateCertificateFromCsr request |
| `SSF_AWSPROV_CONFIG_REG_REQ_SIZE` | 2560 | 64..65536 | The stored RegisterThing request (token and parameters) |
| `SSF_AWSPROV_CONFIG_DEVICE_CONFIG_SIZE` | 512 | 3..RX_SIZE | The `deviceConfiguration` object text |

### Start options (`SSFAWSProvOpts_t`)

Everything the options point to must stay valid until the done callback or `SSFAWSProvStop()`.
Every timeout is at most 2^62 ticks.

| Field | Rule | Recommended |
|---|---|---|
| `mqtt` | ssfmqttc options for the claim connection; `subsOpt`, `subCount` and `willOpt` must be NULL/0 (the module sets the four filters) | — |
| `templateName` | 1..36 of `[0-9A-Za-z_-]`; otherwise the run ends with BUILD | — |
| `curve`, `privKey`, `privKeyLen` | P-256 (32 bytes) or P-384 (48); used only inside Start | — |
| `subjectOpt` | CSR subject, NULL for an empty one (AWS acceptance of an empty subject is unverified, V02); CN at most 64 characters | a serial number in CN |
| `paramsOpt`, `paramCount` | RegisterThing parameters, ASCII (bytes below 0x80); NULL/0 for none | — |
| `responseTimeout` | > 0 | `SSF_AWSPROV_DEFAULT_RESPONSE_TIMEOUT` (10 s) |
| `retryMinWait`, `retryMaxWait` | > 0, max >= min | `SSF_AWSPROV_DEFAULT_RETRY_MIN_WAIT` (1 s), `_MAX_WAIT` (60 s) |
| `deadline` | from Start; 0 for none | at most `SSF_AWSPROV_TRUSTED_USER_DEADLINE` (5 min) for trusted-user claims |
| `tokenLifetime` | > 0 | `SSF_AWSPROV_DEFAULT_TOKEN_LIFETIME` (55 min) |
| `maxAttempts` | tries per step; 0 for none; `maxAttempts` or `deadline` > 0 | `SSF_AWSPROV_DEFAULT_MAX_ATTEMPTS` (8) |

<a id="api-summary"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) API Summary

### Functions

| Function | Purpose |
|---|---|
| [`SSFAWSProvInit()`](#ssfawsprovinit), [`SSFAWSProvDeInit()`](#ssfawsprovdeinit) | Register and remove the state machine |
| [`SSFAWSProvStart()`](#ssfawsprovstart), [`SSFAWSProvStop()`](#ssfawsprovstop), [`SSFAWSProvIsStarted()`](#ssfawsprovisstarted) | Run provisioning |
| [`SSFAWSProvRxPublish()`](#ssfawsprovrxpublish), [`SSFAWSProvEvent()`](#ssfawsprovevent) | The ssfmqttc callbacks to pass to `SSFMQTTCInit()` |
| [`SSFAWSProvCredFromResult()`](#ssfawsprovcredfromresult) | Credentials from a successful run |
| [`SSFAWSProvCredEncode()`](#ssfawsprovcredencode), [`SSFAWSProvCredDecode()`](#ssfawsprovcreddecode) | The persistence blob |
| [`SSFAWSProvApplyTLS()`](#ssfawsprovapplytls), [`SSFAWSProvCredWipe()`](#ssfawsprovcredwipe) | Use and wipe the credentials |
| [Request builders and parsers](#request-builders-and-parsers) | The pure functions the state machine uses, for an application with its own MQTT flow |

### Types and macros

| Name | Purpose |
|---|---|
| `SSFAWSProvOpts_t` | Start options (above) |
| `SSFAWSProvWork_t` | The work set; caller owned, fields not part of the API |
| `SSFAWSProvResult_t` | The outcome passed to the done callback, valid only during it |
| `SSFAWSProvDoneFn_t` | `void (*)(void *ctx, bool isDone, const SSFAWSProvResult_t *result)` |
| `SSFAWSProvReason_t` | Why a run ended (above) |
| `SSFAWSProvCred_t` | The operational credentials; not copyable (its parsed certificate and chain point into it) |
| `SSFAWSProvTopics_t`, `SSFAWSProvCsrAccepted_t`, `SSFAWSProvParam_t` | Used by the builders and parsers |
| `SSF_AWSPROV_MIN_RX_BLOCK_SIZE`, `SSF_AWSPROV_MIN_TX_BLOCK_SIZE` | ssfmqttc block sizes |
| `SSF_AWSPROV_CRED_BLOB_MAX_SIZE`, `SSF_AWSPROV_CRED_BLOB_VERSION` | The blob |
| `SSF_AWSPROV_DEFAULT_*`, `SSF_AWSPROV_TRUSTED_USER_DEADLINE` | Recommended option values |

<a id="function-reference"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Function Reference

<a id="ssfawsprovinit"></a>

### [↑](#functions) `SSFAWSProvInit()`

```c
void SSFAWSProvInit(void);
```

Registers the provisioning state machine (`SSF_SM_AWSPROV`) in its idle state. `SSFSMInit()` must
have been called; not again until `SSFAWSProvDeInit()`.

<a id="ssfawsprovdeinit"></a>

### [↑](#functions) `SSFAWSProvDeInit()`

```c
void SSFAWSProvDeInit(void);
```

Removes the state machine. Only after a run has ended and its stop has been handled: call it once
ssfmqttc reports STOPPED (asserts otherwise).

<a id="ssfawsprovstart"></a>

### [↑](#functions) `SSFAWSProvStart()`

```c
void SSFAWSProvStart(SSFAWSProvWork_t *work, const SSFAWSProvOpts_t *opts,
                     SSFAWSProvDoneFn_t doneFn, void *doneCtxOpt,
                     SSFMQTTCEventFn_t appEventFnOpt, void *appEventCtxOpt);
```

Starts a run. ssfmqttc must be initialized with `SSFAWSProvRxPublish` and `SSFAWSProvEvent` (contexts
NULL) and be STOPPED; no other run may be started. `work` is zeroed and owned by the run until the
done callback has returned or `SSFAWSProvStop()`; `opts` is copied. `doneFn` is called exactly once
(possibly before Start returns, with `SSF_AWSPROV_REASON_BUILD`, in which case ssfmqttc is never
started). `appEventFnOpt`, if given, receives every ssfmqttc lifecycle event after the module has
seen it. Asserts (SSF_REQUIRE) on a NULL argument, a second Start, ssfmqttc not STOPPED, or an
option that breaks the rules above; a template name, key or curve that can't be used ends the
run with `SSF_AWSPROV_REASON_BUILD` instead.

<a id="ssfawsprovstop"></a>

### [↑](#functions) `SSFAWSProvStop()`

```c
void SSFAWSProvStop(void);
```

Ends a started run with no done callback. The work set is wiped before it returns; ssfmqttc is told
to stop and reports STOPPED later. Not from inside the done callback.

<a id="ssfawsprovisstarted"></a>

### [↑](#functions) `SSFAWSProvIsStarted()`

```c
bool SSFAWSProvIsStarted(void);
```

True from `SSFAWSProvStart()` until the done callback runs or `SSFAWSProvStop()`.

<a id="ssfawsprovrxpublish"></a>

### [↑](#functions) `SSFAWSProvRxPublish()`

```c
bool SSFAWSProvRxPublish(void *ctx, const SSFMQTTCRxPublish_t *rxPublish);
```

The ssfmqttc inbound-publish callback. Parses an answer for the current step into the work set and
always consumes the publish (returns true).

<a id="ssfawsprovevent"></a>

### [↑](#functions) `SSFAWSProvEvent()`

```c
void SSFAWSProvEvent(void *ctx, SSFMQTTCEvent_t event, SSFMQTTCReason_t reason);
```

The ssfmqttc lifecycle callback. Maps READY, DISCONNECTED and CONNECT_FAILED onto the state machine,
then forwards the event to the application's callback given to Start.

<a id="ssfawsprovcredfromresult"></a>

### [↑](#functions) `SSFAWSProvCredFromResult()`

```c
bool SSFAWSProvCredFromResult(const SSFAWSProvResult_t *result, SSFECCurve_t curve,
                              const uint8_t *priv, size_t privLen, SSFAWSProvCred_t *credOut);
```

From the done callback of a successful run (`isDone` true), with the device key given to Start
(32 bytes for P-256, 48 for P-384). Copies the certificate, thing name and certificate id and builds
the key. Returns false, with `credOut` zeroed, if the certificate isn't for that key or a field
breaks the rules `SSFAWSProvCredDecode()` applies, so credentials kept here always decode later.

<a id="ssfawsprovcredencode"></a>

### [↑](#functions) `SSFAWSProvCredEncode()`

```c
bool SSFAWSProvCredEncode(const SSFAWSProvCred_t *cred, uint8_t *out, size_t outSize,
                          size_t *outLen);
```

Writes the blob, version 1, all lengths big-endian: `"AWSC"`, version, curve (1 P-256, 2 P-384),
scalar length and scalar, certificate length (2 bytes) and DER, thing name length and name,
certificate id (64), CRC-32 (4 bytes) of everything before it. `out` of
`SSF_AWSPROV_CRED_BLOB_MAX_SIZE` is always enough. Returns false, with `out` zeroed and `*outLen`
0, if it doesn't fit. **The blob contains the private key.**

<a id="ssfawsprovcreddecode"></a>

### [↑](#functions) `SSFAWSProvCredDecode()`

```c
bool SSFAWSProvCredDecode(const uint8_t *blob, size_t blobLen, SSFAWSProvCred_t *credOut);
```

Checks the CRC, the magic and version, the curve and scalar length, every length (exactly, nothing
after the last field), the thing name's characters, the certificate id's format, that the scalar
is a valid key and that the certificate parses and carries its public key. Returns false, with
`credOut` zeroed, on any failure.

<a id="ssfawsprovapplytls"></a>

### [↑](#functions) `SSFAWSProvApplyTLS()`

```c
bool SSFAWSProvApplyTLS(SSFTLSCSession_t *session, SSFAWSProvCred_t *cred);
```

Sets the credentials as the session's client certificate (a one-certificate chain) and key, with
`SSFTLSCSetClientCert()`. Call before the session's handshake. The session keeps pointers into
`cred`, which must outlive that use (see the notes on the example). Returns false if the session
refuses them (for example a wiped credential).

<a id="ssfawsprovcredwipe"></a>

### [↑](#functions) `SSFAWSProvCredWipe()`

```c
void SSFAWSProvCredWipe(SSFAWSProvCred_t *cred);
```

Zeroes the credentials, private key included.

<a id="request-builders-and-parsers"></a>

### [↑](#functions) Request builders and parsers

The state machine is built from these; an application that drives its own MQTT flow can use them
directly. The parsers zero `rxBuf` on every return and their outputs on failure;
`SSFAWSProvBuildRegisterRequest()` and `SSFAWSProvBuildCsrRequest()` leave an empty string and a
zero length on failure (the CSR builder's scratch is left as is: it holds only public data);
`SSFAWSProvTopicsInit()` writes nothing on failure.

```c
bool SSFAWSProvTemplateNameIsValid(SSFCStrIn_t nameStr, size_t nameSize);
bool SSFAWSProvTopicsInit(SSFAWSProvTopics_t *topicsOut, SSFCStrIn_t templateNameStr,
                          size_t templateNameSize);
bool SSFAWSProvCsrRequestSizes(SSFECCurve_t curve, const SSFX509GenName_t *subjectOpt,
                               size_t *scratchSizeOut, size_t *outSizeOut);
bool SSFAWSProvBuildCsrRequest(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                               const SSFX509GenName_t *subjectOpt, uint8_t *scratch,
                               size_t scratchSize, char *outStr, size_t outSize, size_t *outLen);
bool SSFAWSProvParseCsrAccepted(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                                size_t rxSize, SSFECCurve_t curve, const uint8_t *pubKey,
                                size_t pubKeyLen, SSFAWSProvCsrAccepted_t *out);
bool SSFAWSProvBuildRegisterRequest(const char *tokenStr, size_t tokenLen,
                                    const SSFAWSProvParam_t *paramsOpt, size_t paramCount,
                                    char *outStr, size_t outSize, size_t *outLen);
bool SSFAWSProvParseRegisterAccepted(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                                     size_t rxSize, char *thingNameOut, size_t thingNameSize,
                                     char *cfgOutOpt, size_t cfgSize, size_t *cfgLenOutOpt);
bool SSFAWSProvParseRejected(const uint8_t *payload, size_t payloadLen, char *rxBuf,
                             size_t rxSize, uint16_t *statusCodeOut, char *errorCodeOut,
                             size_t errorCodeSize, char *errorMessageOut,
                             size_t errorMessageSize);
bool SSFAWSProvIsRetryable(uint16_t statusCode);
```

- `SSFAWSProvTopicsInit()` fills the RegisterThing topics and the four subscription filters (QoS 1).
  The struct is not copyable: its `subs` point into it, and it must outlive the MQTT connection.
- `SSFAWSProvCsrRequestSizes()` gives exact upper bounds for the scratch and output of
  `SSFAWSProvBuildCsrRequest()`, which signs a PKCS#10 CSR (SHA-256 for P-256, SHA-384 for P-384)
  and wraps its PEM in the request JSON.
- `SSFAWSProvParseCsrAccepted()`: `rxSize` must hold the payload, a NUL, the unescaped PEM and a
  NUL. The token is kept raw; `SSFAWSProvBuildRegisterRequest()` puts it back as is and checks that
  it could not change the request's structure.
- `SSFAWSProvIsRetryable()`: true for 429 and 500..599.

<a id="known-limitations"></a>

## [↑](#ssfawsprov--aws-iot-fleet-provisioning) Known Limitations

- **Not yet validated against a live AWS account** (plan tasks V01 to V03): the endpoint TLS policy
  and key-exchange group, real response sizes and the ownership token length (the defaults are
  estimates), the claim policy above, and whether AWS accepts an empty CSR subject.
- **Bare metal.** With `SSF_CONFIG_ENABLE_THREAD_SUPPORT` 0, ssfsm handles an event at once when no
  handler is running; ssfmqttc's task pump then changes its receive buffer under itself and
  asserts (`ssfmqttc.c`, `_SSFMQTTCRxFrameConsume`). ssfmqttc's own unit test fails the same way.
  Until plan task G14 fixes ssfmqttc, use thread support 1.
- One run at a time (ssfmqttc is a single client).
- JSON payloads only; no CBOR.
- P-256 and P-384 device keys only; no RSA device keys.
- CreateKeysAndCertificate (AWS makes the key and sends it to the device) is deliberately not
  supported.
- No certificate rotation after provisioning, and no MQTT 5.
