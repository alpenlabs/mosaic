# Network Layer

The `net-*` crates provide P2P communication between Mosaic instances.

## Crate Responsibilities

| Crate | Purpose |
|-------|---------|
| net-wire | Wire format: length-prefixed framing, stream type headers |
| net-svc | Connection management, QUIC/TLS, stream multiplexing |
| net-types | Application message types and serialization |
| net-client | Typed API for SM Scheduler and JobScheduler |

## Design Decisions

### Why QUIC?

QUIC provides multiplexed streams over a single connection. This lets us:
- Send high-priority ACKs without head-of-line blocking from bulk transfers
- Use stream priorities (ACKs > protocol msgs > bulk transfers)
- Get built-in encryption and connection migration

### Why a Dedicated Tokio Thread?

Mosaic uses monoio for compute-heavy work (garbling, verification). Networking is I/O-bound and benefits from tokio's mature QUIC ecosystem (quinn). Running net-svc on an isolated thread with its own tokio runtime:
- Prevents network I/O from blocking compute
- Keeps tokio contained (doesn't leak into the rest of the codebase)
- Communicates via async channels that work across runtimes

### Why Ed25519 Identity?

Operators are identified by 32-byte Ed25519 public keys rather than X.509 certificates:
- Simpler than managing CA chains
- Keys can be derived from existing operator identities
- Custom TLS verifier checks public key against allowed peer set
- Self-signed certs wrap the keys (TLS requires certs, but we ignore the CA parts)

### Two Stream Types

**Protocol streams** carry control messages (CommitMsg, ChallengeMsg, etc.). They're small, latency-sensitive, and require acknowledgment.

**Bulk transfer streams** carry garbling tables (~43GB each). They're bandwidth-heavy and identified by a 32-byte hash so receivers can route them to the right job.

The stream header (first byte) tells net-svc how to route incoming streams:
- Protocol → SM Scheduler
- Bulk → JobScheduler (matched against pre-registered expectations)

### Crate Separation

**net-wire** is pure, no I/O—just encoding/decoding. Useful for testing and keeping the protocol format separate from transport.

**net-svc** handles connections but knows nothing about Mosaic messages. It just moves bytes with priority.

**net-types** defines what those bytes mean (message enums, serialization).

**net-client** combines them into a typed API that Jobs and SMs actually use.

This layering means net-svc could theoretically be reused for other protocols.

## Connection Behavior

- Connections to all configured peers are attempted on startup
- Disconnections trigger automatic reconnection with backoff
- Keep-alives prevent idle timeouts
- On simultaneous connect (both sides dial), lower peer_id wins deterministically

## Version Handshake

After QUIC TLS authentication and the overlap-key check, both sides exchange a
short version-handshake payload on a dedicated bi-stream. **No protocol streams
are exposed until the handshake succeeds on both sides.**

Two fields are checked:

- **`protocol_version`** — a manually-maintained `u32` constant
  (`PROTOCOL_VERSION` in `crates/net/svc-api/src/handshake.rs`). Bumped any
  time the wire-visible surface changes — message types in `cac/types`,
  garbler/evaluator STF semantics peers depend on, net-svc framing. Mismatch
  → refuse communication.
- **`deployment_version`** — operator-supplied cohort identifier via TOML
  config (`network.deployment_version = "tn3"`). All-or-none: every operator
  in a coordinated deployment must set the same value. Mismatched or
  asymmetric → refuse. Single-operator dev / local testing leaves it unset
  on every node.

**On mismatch:** the connection is closed with `CLOSE_VERSION_HANDSHAKE_FAILED`
(code 6), the peer is added to an in-memory `incompatible_peers` cache, and
the reason is logged at ERROR once per peer. Outbound reconnect attempts to
peers in the cache are suppressed to avoid log spam.

**Recovery:** inbound connections always run the handshake regardless of
cache state — an upgraded peer is free to dial us. A successful handshake
(inbound or outbound) clears the entry, so once they reconnect with matching
versions our outbound reconnect logic resumes normally too. The cache is
also fully cleared on process restart.

**Operator surface:** the `mosaic_nodeInfo` RPC returns the current
`protocol_version` and `deployment_version` so two operators can compare
configurations without log-diving.