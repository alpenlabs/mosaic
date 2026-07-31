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

## Common fields (`table.upload` / `table.wire` / `table.receive`)

| Field | Meaning |
|---|---|
| `id=` | Work-item short id: commitment hash for upload/wire, sender peer id for receive |
| `done=` | Cumulative bytes, with `/total` when the total is known |
| `pct=` | `done` as a percentage of the total |
| `inst=` / `avg=` | Throughput since the last line / since phase start |
| `elapsed=` | Time since phase start |
| `eta=` | Remaining time at the current `inst` rate |

## `circuit.pass` — the coordinator's read/barrier loop

One line per pass. The circuit read of chunk N+1 is pipelined against the
barrier (all workers finishing chunk N), so the pass advances at
`max(read, barrier)` per chunk.

| Field | Meaning |
|---|---|
| `class=` | Session class of this pass, `compute` or `io` (passes are class-homogeneous) |
| `sessions=` | Sessions served by the pass |
| `read=` / `avg=` | Converted circuit bytes broadcast so far, and their rate |
| `read_gated=` | Wall-clock where the barrier was done but the read was still running |
| `barrier_gated=` | Wall-clock where the read was done but workers were still processing |
| `read_busy=` | Raw busy time of the read+convert side |
| `barrier_busy=` | Raw busy time of the barrier side |
| `straggler=` | Worker that accumulated the most barrier wait (in-order skew: a slow worker early in the list can mask later ones) |

```text
circuit.pass progress class=io sessions=5 read=84.4GiB avg=50.3MB/s elapsed=1800s read_gated=12s(1%) barrier_gated=1493s(83%) read_busy=289s(16%) barrier_busy=1782s(99%) straggler=worker2(1102s)
```

**Reading the two pairs.** The `*_gated` values are *attribution*: additive
shares of wall-clock, so whichever dominates names what paces the pass, and
its value is the first-order win from fixing that side. The `*_busy` values
are *utilization*: they overlap under pipelining (together they can approach
200% of elapsed) and say how loaded each side already is — i.e. the floor you
hit after fixing the current gate. Example: `barrier_gated=10%` with
`read_busy=90%` means the barrier paces the pass, but fixing it only buys 10%
before the read becomes the gate.

## `table.upload` — garbler, producer side (G8)

The garbler garbles blocks and enqueues ciphertext into a bounded outbox; a
drain thread owns the wire. `done`/rates measure **enqueue** pace — wire
progress trails by at most one outbox (~a few MiB).

| Stage | Meaning |
|---|---|
| `compute=` | Garbling gates (local CPU) |
| `outbox_full=` | Parked in the outbox `send` — the peer has fallen a full outbox behind (sustained backpressure). Preserved even when the session is evicted mid-send |

```text
table.upload progress id=0x3fa2c81d done=12.4GiB/40.1GiB pct=30.9% inst=52MB/s avg=51MB/s elapsed=4m22s eta=10m13s compute=3m30s(80%) outbox_full=31s(12%)
```

## `table.wire` — garbler, drain side (G8)

The wire truth for the same transfer (same `id` as its `table.upload`):
bytes actually written to the peer.

| Stage | Meaning |
|---|---|
| `net_blocked=` | Inside the stream write — the peer's receive pace. Includes writes that stalled to timeout/cancel |
| `feed_wait=` | Waiting on the garbler for the next buffer — compute, not the wire, is the constraint |

```text
table.wire progress id=0x3fa2c81d done=12.4GiB/40.1GiB pct=30.9% inst=45MB/s avg=50MB/s elapsed=4m24s eta=11m49s net_blocked=4m01s(91%) feed_wait=15s(6%)
```

## `table.receive` — evaluator ingest (E4)

Consumes a peer's bulk stream and forwards ciphertext to the table store.

| Stage | Meaning |
|---|---|
| `net_wait=` | Waiting for the peer to send (plus transfer time of the data). Includes reads that expired the read timeout |
| `store_blocked=` | Blocked in `write_ciphertext` — the object-store upload is not keeping up |

```text
table.receive summary id=0x9b41d7aa done=40.1GiB inst=41MB/s avg=42MB/s elapsed=17m05s net_wait=12m40s(74%) store_blocked=3m22s(20%)
```

## `table.store` — object-store upload

Emitted by the S3 background writer while shipping a received table.

| Field | Meaning |
|---|---|
| `parts=` / `uploaded=` | Multipart parts and bytes uploaded |
| `put=` | Throughput while actually inside `put_part` — the store's own speed |
| `avg=` | Throughput against wall-clock, diluted by waiting for the producer |
| `in_put=` | Serialized time inside `put_part` |

```text
table.store progress parts=806 uploaded=6.3GiB put=118.7MB/s avg=37.6MB/s elapsed=180s in_put=57s(32%)
```

`put` well above `avg` means the writer is starved upstream; the two
converging means the store is the constraint.

## Diagnosis recipe

A slow transfer names its bottleneck by which stage dominates, and the lines
corroborate each other across nodes: sender `outbox_full`/`net_blocked` high →
look at that receiver's `table.receive`; there, `store_blocked` high → look at
its `table.store` `put` rate. `circuit.pass barrier_gated` high in an `io`
pass means some session — and so some peer, or that peer's store — gates
every table in the pass; `straggler` says which worker to inspect first.
