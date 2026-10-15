# On-demand peers

An on-demand peer is a manually configured peer that a node connects to only
while the connection is needed. The typical case is a public node that NAT'd
nodes use to join the network: once they have found each other, a node can drop
its direct connection to the public node and stop sending it any traffic,
heartbeats included, until it needs that connection again.

```sh
# connect to the public node only when needed
easytier-core --on-demand-peers tcp://public.example.com:11010 --latency-first ...
```

```toml
[[peer]]
uri = "tcp://public.example.com:11010"
on_demand = true
```

The flag is also available as `on_demand` on the peers of the management API
network config, and as `ET_ON_DEMAND_PEERS` in the environment. A URL is either
a regular peer or an on-demand peer: adding it as the other kind is rejected.

## When the connection is held

The node connects to the on-demand peer while any of the following holds:

- **Bootstrap.** The peer's ID is not known yet, which is the case right after
  start.
- **Fallback.** The peer cannot be reached through the rest of the network, for
  example after all the node's other connections were lost.
- **Latency.** A peer this node exchanges data with gets a clearly lower
  latency-first path cost through the connection. This covers a destination
  that hole punching could not connect directly and that the on-demand peer
  relays faster than the current path. A longer path that has a lower latency
  wins over a shorter path, and data to the on-demand peer itself never counts.

Otherwise the connection is closed after a hold-down of 60 to 120 seconds,
chosen randomly so several nodes sharing a public node do not all drop it at
once. While the connection is down, the public node is still reachable through
the other peers, so management traffic and data addressed to it are relayed.

## How the latency decision works

Every second, the node computes the latency-first path cost to each peer it
exchanged data with in the last 30 seconds, twice: once without the on-demand
connection and once with it. Its own links are priced with their measured
latency; the rest of the network uses the latencies collected by the peer
center, the same costs `--latency-first` routing uses.

- While connected, the measured latency of the connection is used. The
  connection is kept while some destination gains at least 5 ms and 5%.
- While disconnected, the latency measured the last time the connection was up
  is used for 30 minutes. The node reconnects when a destination that has been
  active for 10 seconds would gain at least 10 ms and 10%. The 10 seconds give
  hole punching a chance to connect the destination directly first.
- Without a fresh measurement, the node assumes a zero-latency connection. If
  even that would not help, it stays disconnected. Otherwise it opens the
  connection to measure it, at most once every 10 minutes, and closes it again
  after 15 seconds when the measurement shows no gain.

Enable `--latency-first` on the node so its forwarding follows the same latency
costs the decision uses.

## Only the on-demand connector links the node to the peer

The node holds no other connection to an on-demand peer, whatever the peer is
configured to do:

- It never opens automatic P2P connections to the peer.
- It answers the peer's direct-connect and hole-punching requests as if it did
  not offer those services. A peer running EasyTier then stops asking for an
  hour.
- It refuses any other connection with the peer, such as one the peer dials in,
  during the handshake, and closes those that came up before the peer's ID was
  known, for example while the peer restarted.

## Recommended setup

- Give the on-demand node at least one other way into the network. In a NAT'd
  setup, that is the P2P connections hole punching establishes with the other
  nodes; those nodes keep regular connections to the public node.
- Start the public node with `--disable-p2p` if you can. It is not needed for
  the behaviour above, but it keeps the public node from sending the requests
  the on-demand node refuses.

## Limitations

- When every other path is lost, the node is reachable again only after it
  reconnects, which follows the usual retry backoff of 1 to 60 seconds while the
  on-demand peer is unreachable.
- Control traffic between the node and the public node, such as peer-center
  reports when the public node is the elected center, still flows; it is
  relayed by other peers while the direct connection is down.
- Only data packets exchanged with the node itself count as activity, not data
  the node forwards for others.
