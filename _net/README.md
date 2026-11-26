# Network

[SSF](../README.md)

Network protocol clients and the byte stream transport interface they run on.

| Module | Description | Source Files | Documentation |
|--------|-------------|--------------|---------------|
| ssfhttphdr | HTTP/1.1 request head builder and strict response head parser (RFC 9112); shared by HTTP users | ssfhttphdr.c, ssfhttphdr.h | [ssfhttphdr.md](ssfhttphdr.md) |
| ssfmqttc | MQTT 3.1.1 client, QoS 0 and 1, single connection | ssfmqttc.c, ssfmqttc.h | [ssfmqttc.md](ssfmqttc.md) |
| ssfmqttpkt | MQTT 3.1.1 control packet framing, encoding and decoding | ssfmqttpkt.c, ssfmqttpkt.h | — |
| ssfnet | Non-blocking byte stream transport interface | ssfnet.h | — |
| ssfnetsock | Plaintext TCP transport over BSD sockets or Winsock, with non-blocking name resolution | ssfnetsock.c, ssfnetsock.h | — |
| ssfnetws | WebSocket client transport (RFC 6455) over another transport: ws:// on ssfnetsock, wss:// on ssftlsc; carries MQTT over WebSockets | ssfnetws.c, ssfnetws.h | [ssfnetws.md](ssfnetws.md) |

## See Also

- [Finite State Machine](../_fsm/README.md) — ssfsm runs the MQTT client protocol logic and timers
- [Data Structures](../_struct/README.md) — ssfmpool and ssfll back the client's packet pools and queues
