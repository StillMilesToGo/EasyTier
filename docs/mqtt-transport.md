# MQTT transport

EasyTier can relay a peer connection through an MQTT broker. It is useful when
two nodes cannot reach each other directly but can both reach a broker (a
self-hosted Mosquitto/EMQX, or a cloud IoT broker), and it keeps an otherwise
idle link alive with MQTT keep-alives.

## Usage

The same URL is used as a listener on one node and as a peer on the other:

```sh
# node A: accept sessions published on the topic
easytier-core -l tcp://0.0.0.0:11010 -l mqtt://user:pass@broker.example:1883/easytier/node-a ...

# node B: reach node A through the broker
easytier-core -p mqtt://user:pass@broker.example:1883/easytier/node-a ...
```

URL form: `mqtt://[user:pass@]host[:port]/<topic>` (default port 1883) or
`mqtts://...` for TLS (default port 8883, certificates verified against the
Mozilla root store). Query parameters:

| parameter   | default | meaning                                                   |
|-------------|---------|-----------------------------------------------------------|
| `qos`       | `1`     | MQTT QoS for tunnel messages, `0` or `1`                  |
| `keepalive` | `30`    | MQTT keep-alive in seconds (5-3600)                       |
| `insecure`  | `false` | `mqtts` only: accept an unverified broker certificate     |

Give every listener its own topic. The topic must not contain `+` or `#`.

## Behaviour

- Each peer connection is one session on the topic; its bytes are ordinary
  EasyTier tunnel traffic, so peer authentication and encryption are the same
  as for TCP. The broker only sees encrypted payloads, but it does see the
  broker credentials, so prefer `mqtts` on untrusted networks.
- Messages carry sequence numbers. Duplicates are dropped and a lost message
  closes the session, which the connector then re-establishes like any other
  broken connection.
- The listener reconnects to the broker on its own (backoff up to 30 s), so a
  broker outage does not remove it. A connector's last will lets the listener
  drop a session as soon as the connector disappears.
- The broker adds latency and usually limits throughput, so keep a direct
  listener (`tcp`/`udp`/...) next to the MQTT one: EasyTier prefers the better
  path and falls back to relaying through other peers when the broker is down.

## Compatibility

Support is behind the `mqtt` cargo feature (enabled by default). Nodes built
without it, or older versions, keep working in the same network: they simply
connect over the other transports, and the mesh routes traffic between MQTT
and non-MQTT peers. MQTT listeners are advertised to peers like other
listeners (without the password), but are never used for direct connections.
