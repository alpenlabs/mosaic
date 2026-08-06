# Garbling Progress Logs

Long-running garbling phases emit periodic INFO heartbeats on the
`mosaic_progress` tracing target. Filter with `RUST_LOG=mosaic_progress=info`
or grep for the target string. Each phase emits `progress` lines (throttled to
one per 30 s) and a final `summary` line on every exit — clean finish,
eviction, timeout, and failure alike — so summaries are available for
post-mortems. Sole exception: `table.store` emits no summary when the upload
itself fails; its error log covers that case.

Every line attributes elapsed wall-clock to named stages as
`stage=<duration>(<percent of elapsed>)`. The `table.*` lines omit zero
stages; `circuit.pass` always prints all four of its pairs.

At startup the binary logs the cut-and-choose variant it was built with —
use it to bound deploy windows and confirm the CaC parameters from logs
alone (the build revision itself comes from the deployed image's tag):

```text
mosaic starting n_circuits=5 n_open_circuits=3
```

## Identity fields (all phases)

Every progress line carries explicit identity fields instead of a bare `id=`.
Short hashes (`0x` + 8 hex chars) are prefixes of the full lowercase hex
encoding, so grepping a short id also matches log fields carrying the full
value.

| Field | Meaning |
|---|---|
| `peer=` | The counterparty this work item serves: transfer/receive peer, or the peer a commitment/verification is being built for |
| `circuit_index=` | The circuit index (1..=N_CIRCUITS) identifying the table within a pair |
| `pass=` | Coordinator pass sequence number (pass-scoped lines only) |

`(peer, circuit_index)` identifies a table. Cross-node join: the sender's
`table.upload`/`table.wire` on node A (`peer=` naming B) matches the
receiver's `table.receive` on node B (`peer=` naming A) at the same
`circuit_index` — so a table can be followed sender → wire → receiver →
store → evaluation without timestamp guesswork.

## Common fields (`table.upload` / `table.wire` / `table.receive`)

| Field | Meaning |
|---|---|
| `done=` | Cumulative bytes, with `/total` when the total is known |
| `pct=` | `done` as a percentage of the total |
| `inst=` / `avg=` | Throughput since the last line / since phase start |
| `elapsed=` | Time since phase start |
| `eta=` | Remaining time at the current `inst` rate |

## `circuit.pass` — the coordinator's read/barrier loop

One line per pass. The circuit read of chunk N+1 is pipelined against the
barrier (all workers finishing chunk N), so the pass advances at
`max(read, barrier)` per chunk.

At pass start, one `assign` line per session records the pass composition:

```text
circuit.pass assign pass=12 class=io worker=2 peer=0x9b41d7aa action=garbler_transfer attempts=0 queue_wait=4s
```

| Field | Meaning |
|---|---|
| `worker=` | Worker thread the session landed on (round-robin deal) |
| `action=` | `garbler_commitment`, `garbler_transfer`, `evaluator_commitment`, or `evaluator_evaluation`, with `circuit_index=` where the action carries one. Garbling seeds are secrets and never logged; a transfer's `circuit_index` appears on its `table.upload` line instead |
| `attempts=` | Times this job bounced back to the backlog (0 = first try) |
| `queue_wait=` | Time the job spent queued since submission or its last bounce |

`progress`/`summary` lines:

| Field | Meaning |
|---|---|
| `pass=` | Pass sequence number, joins with `assign` lines and strike/evict warns |
| `class=` | Session class of this pass, `compute` or `io` (passes are class-homogeneous) |
| `sessions=` | Sessions served by the pass |
| `read=` / `avg=` | Converted circuit bytes broadcast so far, and their rate |
| `read_gated=` | Wall-clock where the barrier was done but the read was still running |
| `barrier_gated=` | Wall-clock where the read was done but workers were still processing |
| `read_busy=` | Raw busy time of the read+convert side |
| `barrier_busy=` | Raw busy time of the barrier side |
| `straggler_peer=` | Peer whose session accumulated the most busy time processing chunks — the session that held the barrier longest. Measured per session inside the workers, so it has no report-ordering skew |

```text
circuit.pass progress pass=12 class=io sessions=5 read=84.4GiB avg=50.3MB/s elapsed=1800s read_gated=12s(1%) barrier_gated=1493s(83%) read_busy=289s(16%) barrier_busy=1782s(99%) straggler_peer=0x9b41d7aa(1102s)
```

**Reading the two pairs.** The `*_gated` values are *attribution*: additive
shares of wall-clock, so whichever dominates names what paces the pass, and
its value is the first-order win from fixing that side. The `*_busy` values
are *utilization*: they overlap under pipelining (together they can approach
200% of elapsed) and say how loaded each side already is — i.e. the floor you
hit after fixing the current gate. Example: `barrier_gated=10%` with
`read_busy=90%` means the barrier paces the pass, but fixing it only buys 10%
before the read becomes the gate.

Strike and eviction warns (plain `warn` level, not `mosaic_progress`) carry
`worker=`, `pass=`, and `peer=` (full hex), so they join against the same
pass and peer.

## `garbling.commit` / `garbling.verify` — commitment garbling (G3/E3)

Block-unit heartbeats for commitment garbling (G3) and opened-table
re-garbling verification (E3). Identity: `peer=` + `circuit_index=`.

```text
garbling.verify progress peer=0x9b41d7aa circuit_index=3 pct=~62% elapsed=2m10s
```

## `table.upload` — garbler, producer side (G8)

The garbler garbles blocks and enqueues ciphertext into a bounded outbox; a
drain thread owns the wire. `done`/rates measure **enqueue** pace — wire
progress trails by at most one outbox (~a few MiB).

| Stage | Meaning |
|---|---|
| `compute=` | Garbling gates (local CPU) |
| `outbox_full=` | Parked in the outbox `send` — the peer has fallen a full outbox behind (sustained backpressure). Preserved even when the session is evicted mid-send |

The summary line additionally reports `outbox_hwm=<peak>/<depth>` — the
highest outbox occupancy observed, in buffers. It answers whether the
configured `transfer_outbox_depth` was actually used: `outbox_full` alone
cannot distinguish a near-full outbox from an empty one.

```text
table.upload progress peer=0x9b41d7aa circuit_index=4 done=12.4GiB/40.1GiB pct=30.9% inst=52MB/s avg=51MB/s elapsed=4m22s eta=10m13s compute=3m30s(80%) outbox_full=31s(12%)
table.upload summary peer=0x9b41d7aa circuit_index=4 done=40.1GiB/40.1GiB pct=100.0% inst=50MB/s avg=51MB/s elapsed=13m20s compute=10m41s(80%) outbox_full=1m10s(9%) outbox_hwm=137/256
```

## `table.wire` — garbler, drain side (G8)

The wire truth for the same transfer (same identity fields as its
`table.upload`): bytes actually written to the peer.

| Stage | Meaning |
|---|---|
| `net_blocked=` | Inside the stream write — the peer's receive pace. Includes writes that stalled to timeout/cancel |
| `feed_wait=` | Waiting on the garbler for the next buffer — compute, not the wire, is the constraint |

```text
table.wire progress peer=0x9b41d7aa circuit_index=4 done=12.4GiB/40.1GiB pct=30.9% inst=45MB/s avg=50MB/s elapsed=4m24s eta=11m49s net_blocked=4m01s(91%) feed_wait=15s(6%)
```

## `table.receive` — evaluator ingest (E4)

Consumes a peer's bulk stream and forwards ciphertext to the table store.
`peer=` is the **sending** peer, so this line joins the sender's
`table.upload`/`table.wire` at the same `circuit_index`. The total
(translation + expected ciphertext) is known up front, so `pct=`/`eta=`
are present.

| Stage | Meaning |
|---|---|
| `net_wait=` | Waiting for the peer to send (plus transfer time of the data). Includes reads that expired the read timeout |
| `store_blocked=` | Blocked in `write_ciphertext` — the object-store upload is not keeping up |

```text
table.receive summary peer=0x9b41d7aa circuit_index=4 done=40.1GiB/40.1GiB pct=100.0% inst=41MB/s avg=42MB/s elapsed=17m05s net_wait=12m40s(74%) store_blocked=3m22s(20%)
```

## `table.eval` — evaluation of a stored table (E8)

Block-unit heartbeat while a stored table is evaluated during a dispute.
Identity: `peer=` + `circuit_index=`.

## `table.store` — object-store upload

Emitted by the S3 background writer while shipping a received table. The
`path=` embeds the sending peer's full hex id and the circuit index
(`…/{peer_hex}/{circuit_index}/versions/…`), so concurrent receives on one
node stay attributable.

| Field | Meaning |
|---|---|
| `path=` | Ciphertext object path — the table's identity |
| `parts=` / `uploaded=` | Multipart parts and bytes uploaded |
| `put=` | Throughput while actually inside `put_part` — the store's own speed |
| `avg=` | Throughput against wall-clock, diluted by waiting for the producer |
| `in_put=` | Serialized time inside `put_part` |

```text
table.store progress path=tables/9b41…d7aa/4/versions/0000…0001/ciphertexts parts=806 uploaded=6.3GiB put=118.7MB/s avg=37.6MB/s elapsed=180s in_put=57s(32%)
```

`put` well above `avg` means the writer is starved upstream; the two
converging means the store is the constraint.

## Pool saturation warns

Pool workers warn (throttled to one per 30 s per worker) when all slots were
busy for 5 s+ while jobs were queued behind them:

```text
pool at capacity — queued jobs delayed waiting for a free slot pool="light" worker=0 concurrency=512 waited_ms=6200 queued=17
```

On the light pool this is the signature of table receives holding slots for
minutes while small protocol messages queue behind them (the reason the light
pool default is `concurrency_per_worker = 512`).

## Diagnosis recipe

A slow transfer names its bottleneck by which stage dominates, and the lines
corroborate each other across nodes: sender `outbox_full`/`net_blocked` high →
find that receiver's `table.receive` for the sending peer at the same
`circuit_index`; there, `store_blocked` high → look at its `table.store`
`put` rate for the matching `path=`. `circuit.pass barrier_gated` high in an `io` pass means some
session — and so some peer, or that peer's store — gates every table in the
pass; `straggler_peer` names the peer directly, and the pass's `assign`
lines list who else shared the batch (and so was coupled to it).
