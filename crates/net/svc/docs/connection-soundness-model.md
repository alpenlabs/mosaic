# net-svc Per-Peer Connection Soundness Model

This document is the normative model for connection selection and convergence in `net-svc`.
Implementation is correct only if it refines this model.

## 1. Goals

1. Exactly one selected connection per peer in steady state.
2. Deterministic convergence for true simultaneous-connect races, under the incoming-evidence assumption in 8.4.
3. Never replace a healthy selected connection outside race resolution.
4. No timer-driven race decisions. Resolve only from observed second-candidate evidence.
5. No stuck states: every queued open request eventually becomes `Opened | Canceled | Failed`.

## 2. Deterministic Tie-Break

For local peer `me` and remote peer `p`:

```text
preferred_direction(me, p) =
  Outgoing, if me < p
  Incoming, otherwise
```

This function is total and deterministic.
`me < p` uses canonical bytewise lexicographic ordering of peer ID bytes.
`Outbound` event/attempt naming is synonymous with `Outgoing` direction naming.
`candidate_id` ordering, when needed, uses canonical bytewise lexicographic ordering.

## 3. Per-Peer State

Each peer `p` has:

```text
state[p] : PeerState
pending_incoming_by_id : map<candidate_id, IncomingCandidate>
pending_incoming_by_peer : map<peer, set<candidate_id>>
pending_requests[p] : queue<OpenRequest>
open_request_state[request_id] : Pending{p} | InFlight{p, generation}
canceled_open_requests : set<request_id>
```

Where:

```text
IncomingCandidate = {
  candidate_id,
  peer_guess,
  accepted_at,
  overlap_key,
}

OutboundAttempt = {
  attempt_id,
  started_at,
  overlap_key,
}

TrackedConn = {
  dir: Incoming | Outgoing,
  generation,
  overlap_key,
}

PeerState =
  Idle
  | ConnectingOutbound { attempt }
  | Stable { conn }
  | Race {
      provisional: TrackedConn,
      waiting_for: Incoming | Outgoing,
      expected_outbound_attempt?: OutboundAttempt
    }
```

Identifier scope:

1. `generation` is a monotonic selected-connection identity token; implementations may allocate globally, but uniqueness must hold for all concurrently-relevant selected generations and stale/currentness checks.
2. `candidate_id` is a unique incoming-candidate identity token while pending; live candidates must not share an ID.
3. `attempt_id` is a unique logical outbound-attempt identity token for currentness validation.

Consistency constraints:

1. `Race.waiting_for == Outgoing` iff `expected_outbound_attempt` is `Some`.
2. `Race.waiting_for == Incoming` iff `expected_outbound_attempt` is `None`.
3. Logical outbound expectation in-flight exists iff state is `ConnectingOutbound` or `Race(waiting_for=Outgoing)`.
4. `Stable.conn` or `Race.provisional` is the only selected connection for a peer.
5. Every `candidate_id` appears in exactly one peer bucket and in `pending_incoming_by_id`.
6. Every request ID is in exactly one lifecycle class: `Pending`, `InFlight`, or terminal (absent from all request-tracking state).
7. Candidate index updates to `pending_incoming_by_id` and `pending_incoming_by_peer` are atomic as one logical state transition.
8. For any request in `pending_requests[p]`, `open_request_state[request_id] == Pending{p}`.
9. For any `open_request_state[request_id] == Pending{p}`, that request appears exactly once in `pending_requests[p]`.

`in-flight` in constraint 3 is state-machine logical expectation, not physical socket lifetime. A physically-running dial whose result is guaranteed to be treated as stale is not logically in-flight.

Health definition:

1. A selected connection is `healthy` iff no current `ConnectionLost` has been processed for its generation and it is not locally closed.
2. Initiating a local close marks that connection not healthy immediately, independent of later `ConnectionLost` delivery.

Derived helper:

```text
overlapping_incoming(peer, overlap_key) = {
  c in pending_incoming_by_peer[peer]
  where pending_incoming_by_id[c].overlap_key == overlap_key
}
```

If `pending_incoming_by_peer` has no entry for `peer`, `overlapping_incoming(peer, overlap_key)` is the empty set.
This convenience rule assumes consistency constraints above; missing bucket entries are not a valid substitute for required atomic index maintenance.

## 4. Establishment Window / Overlap

Race evidence is based on explicit overlap identity, not implicit timing.

```text
overlap_key : opaque per-establishment-window key
```

Required properties:

1. Two directional candidates are in the same establishment window iff their `overlap_key` values are equal.
2. `overlap_key` values are never reused for distinct establishment windows of the same peer pair.
3. Peer pair is unordered (`{a, b}`): reuse is forbidden across both directions between the same two peers.
4. For each establishment window between a peer pair, protocol flow must assign an `overlap_key` that is available to both `IncomingAccepted` candidates and outbound attempts (for example via handshake epoch/nonce exchange).

## 5. Events and Currentness

Events:

1. `OpenRequest(request_id, peer, ...)`
2. `CancelOpen(request_id)`
3. `IncomingAccepted(peer_guess, accepted_at, candidate_id, overlap_key)`
4. `IncomingReady(peer_auth, peer_guess, candidate_id, overlap_key, conn)`
5. `IncomingRejected(peer_guess, peer_auth_opt, candidate_id, reason)`
6. `OutboundReady(peer, attempt, conn)`
7. `OutboundFailed(peer, attempt_id, error)`
8. `ConnectionLost(peer, generation, reason)`
9. `IncomingStream(peer, generation, ...)`
10. `StreamReady(peer, generation, ...)`
11. `StreamHeaderFailed(peer, generation, ...)`
12. `StreamOpenFinished(request_id, generation, result)`

Event ordering assumption:

1. For any incoming connection that reaches `IncomingReady`, a matching `IncomingAccepted` for the same `candidate_id` is emitted earlier or atomically with it.
2. When `IncomingAccepted` and `IncomingReady` are delivered atomically, candidate insertion into pending maps occurs before currentness validation for the paired `IncomingReady`.

Selected generation definition:

1. If state is `Stable`, selected generation is `Stable.conn.generation`.
2. If state is `Race`, selected generation is `Race.provisional.generation`.
3. If state is `Idle` or `ConnectingOutbound`, no selected generation exists.

Current-event validation:

1. `OutboundReady/OutboundFailed` are current only if `attempt_id` matches expected outbound attempt in current state.
2. `ConnectionLost/IncomingStream/StreamReady/StreamHeaderFailed` are current only if generation matches selected connection generation per the definition above.
3. `IncomingReady/IncomingRejected` are current iff `candidate_id` exists in `pending_incoming_by_id` (peer bucket lookup is not authoritative).
4. `StreamOpenFinished` is current iff request ID is `InFlight` and event generation equals the stored `InFlight.generation`.
5. `ConnectionLost` for non-selected generations (including when state has no selected generation) is informational and may be ignored; cleanup for those paths is driven by explicit close/deselect rules and stale-ready cleanup.
6. `IncomingRejected` carries no resource handles; stale `IncomingRejected` may be ignored.
7. For `OutboundReady/OutboundFailed`, event `peer` must match the peer-state entry being updated; mismatched events are stale (and stale `OutboundReady` must close its carried handle).

Stale-event cleanup:

1. Stale events must not mutate selected connection state.
2. If a stale event carries an established connection or stream handle (including stale `StreamOpenFinished` success), it must be closed/reset deterministically.
3. `IncomingReady`/`OutboundReady` events carry connection handles; successful `StreamOpenFinished` carries a stream handle.

Established candidate definition:

1. An established candidate is a direction candidate delivered via `IncomingReady` or `OutboundReady` (each carries a connection handle).

## 6. Transition Rules

### 6.1 Open / Cancel / Pump

1. On `OpenRequest`:
   - If `Stable` with healthy conn: dispatch opener on `conn.generation` and mark `InFlight{peer, conn.generation}`.
   - Else enqueue as `Pending{peer}` and ensure outbound attempt exists.
   - Ensure-outbound semantics: this step is applied only when current state is `Idle`; in all other states it is a no-op.
   - If current state is `Idle`, transition to `ConnectingOutbound{attempt}` with a fresh `attempt_id` and `overlap_key`.
   - Entering `ConnectingOutbound{attempt}` implies initiating the dial for that `attempt_id`.
2. On `CancelOpen(request_id)`:
   - If `Pending`: remove from queue, clear request state, and remove `request_id` from `canceled_open_requests` if present.
   - If `InFlight`: add request ID to `canceled_open_requests`.
   - If request is terminal (absent from `open_request_state`), `CancelOpen` is ignored.
3. `pump_requests(peer)` must run:
   - on transition into `Stable`;
   - after each current `StreamOpenFinished` for that peer.
   - if a race/reorder-compensation decision keeps the same selected generation (logical no-op), additional pump work is optional.
4. `pump_requests(peer)` behavior:
   - while selected state is healthy `Stable` and pending requests exist, dispatch openers;
   - canceled requests are completed as `Canceled`;
   - each request gets exactly one terminal outcome and then leaves `open_request_state`;
   - terminal completion must also remove request ID from `canceled_open_requests`.
   - multiple `InFlight` requests per peer are permitted.
   - `pump_requests` may dispatch one or more requests per invocation; any implementation concurrency limit is permitted provided fairness holds and requests make progress.
5. Definition: `fail pending requests(peer)` applies only to `Pending{peer}` requests: complete them as `Failed`, remove them from `pending_requests[peer]` and `open_request_state`, and remove each such `request_id` from `canceled_open_requests` if present. `InFlight` requests are handled by the deselect/close rule.
   - This model intentionally fails pending requests on outbound-failure and connection-loss paths; transparent automatic retry of the same request is out of scope and callers resubmit.
6. Definition: `schedule reconnect(peer)` means enqueue future reconnect work that will attempt outbound establishment for `peer` when no healthy selected connection exists.
   - Reconnect work is conditional at execution time: when it runs, it must re-check that no healthy selected connection exists before initiating a new attempt.
   - Reconnect work enters through ensure-outbound semantics (same as §6.1.1): outbound attempt creation is `Idle`-only, so reconnect is a no-op in all non-`Idle` states.
   - Reconnect work may run regardless of whether pending requests exist; conditioning is on connection health, not queue occupancy.
7. Ordering of side effects `fail pending requests(peer)` and `schedule reconnect(peer)` is not observable and does not affect correctness.
8. Any transition into `ConnectingOutbound{attempt}` implies the dial for `attempt.attempt_id` is in-flight or is initiated immediately.
9. Definition: `attempt_resolved(attempt_id)` iff a current (i.e., `attempt_id` matches expected outbound attempt in current state) `OutboundReady` or `OutboundFailed` for that `attempt_id` has been processed.

### 6.2 Incoming Candidate Lifecycle

1. On `IncomingAccepted`: insert candidate into `pending_incoming_by_id` and the `peer_guess` bucket.
2. On `IncomingReady`/`IncomingRejected` (current): atomically remove candidate from `pending_incoming_by_id` and whichever peer bucket currently owns it.
3. Selection/race transitions for `IncomingReady(peer_auth, ...)` are always applied to peer `peer_auth` (never to `peer_guess`).
4. For `IncomingReady` where `peer_guess != peer_auth`, apply composite update order:
   - remove candidate from pending indexes atomically per rule 6.2.2;
   - re-evaluate incoming-race termination for owner/guess side (if different);
   - apply selection/race transition on peer `peer_auth`;
   - re-evaluate incoming-race termination for authenticated side.
   - For `IncomingRejected` with `peer_auth_opt = Some(peer_auth) != peer_guess`, steps 1-2 apply; steps 3-4 are vacuous.
5. Candidate removal or migration must trigger race re-evaluation for any peer currently in `Race(waiting_for=Incoming)` with matching overlap key.
6. `overlapping_incoming(peer, ...)` in race logic uses the authenticated peer-state key (never `peer_guess`).

### 6.3 Connection Selection

Any transition in this section that deselects or locally closes a previously selected generation must apply rule 6.4.1 before losing visibility of that generation.
`close exactly once` in this section means one logical ownership close action per rejected/losing handle; redundant close attempts, if they occur, must be idempotent no-ops.

#### From `Idle`

1. `IncomingReady(current)` -> `Stable(Incoming)`.
2. `OutboundReady` in `Idle` is stale by invariant (no expected outbound). Close stale connection handle carried by the event; remain `Idle`.

#### From `ConnectingOutbound {attempt}`

`peer` below denotes the peer key owning this state entry.

1. `OutboundReady(current attempt)`:
   - Let `S = overlapping_incoming(peer, attempt.overlap_key)`.
   - If `preferred_direction == Incoming` and `S` is non-empty: enter
     `Race(waiting_for=Incoming, provisional=Outgoing)`.
   - Else `Stable(Outgoing)`.
2. `IncomingReady(current)`:
   - If `incoming.overlap_key == attempt.overlap_key`: enter
     `Race(waiting_for=Outgoing, provisional=Incoming, expected_outbound_attempt=attempt)`.
   - Else `Stable(Incoming)`.
3. `OutboundFailed(current attempt)` -> `Idle` + `fail pending requests(peer)` + `schedule reconnect(peer)`.

#### From `Stable {conn}`

1. If selected connection is healthy, duplicate incoming is rejected; if duplicate arrives via `IncomingReady` (already established), its connection is closed exactly once.
2. Outbound duplicates in `Stable` are handled by the `OutboundReady`-in-`Stable` stale rule below (`OutboundReady` in `Stable` is stale and must be closed).
3. Replacement is forbidden except race-resolution transitions below.
4. Reorder compensation (explicit):
   - On `IncomingReady(current)` with `incoming.overlap_key == conn.overlap_key` and opposite direction,
     resolve immediately using tie-break, close loser exactly once, transition to `Stable(winner)`.
   - If loser is the previously selected generation, apply deselect/close rule for loser generation.
   - This is race resolution for the same overlap key under event reordering, not a steady-state replacement exception.
   - Reorder compensation is IncomingReady-driven in this model.
5. `OutboundReady` received while in `Stable` is stale by currentness rules in this model and its connection handle must be closed, even if its overlap_key matches `conn.overlap_key`.

#### From `Race { provisional, waiting_for, ... }`

`peer` below denotes the peer key owning this state entry.

1. `waiting_for = Outgoing`:
   - `OutboundReady(current expected attempt)` -> resolve with tie-break, close loser exactly once, `Stable(winner)`.
   - If loser is the previously selected generation, apply deselect/close rule for loser generation.
   - `OutboundFailed(current expected attempt)` -> `Stable(provisional)` if healthy, else `Idle + fail pending requests(peer) + schedule reconnect(peer)`.
   - `IncomingReady(current)` while `waiting_for=Outgoing` is duplicate for this race: close its connection handle exactly once and keep `Race(waiting_for=Outgoing)` unchanged. Candidate-removal/migration side effects still follow section 6.2.
2. `waiting_for = Incoming`:
   - Eligible-incoming selector: among matching `IncomingReady(current)` candidates processed while this race remains unresolved, define `eligible_incoming_candidate_id` as the minimal `candidate_id` (bytewise lexicographic).
   - Under strictly sequential event processing this is equivalent to "first matching `IncomingReady(current)` processed before race resolution"; minimality is the deterministic selector for atomic/batched multi-ready delivery.
   - If no matching `IncomingReady(current)` has been processed yet, `eligible_incoming_candidate_id` is undefined and becomes defined when the first matching `IncomingReady(current)` is processed.
   - `IncomingReady(current)` where `incoming.overlap_key == provisional.overlap_key` and `incoming.candidate_id == eligible_incoming_candidate_id`:
     resolve with tie-break, close loser exactly once, `Stable(winner)`.
   - If loser is the previously selected generation, apply deselect/close rule for loser generation.
   - `IncomingReady(current)` where `incoming.overlap_key == provisional.overlap_key` and `incoming.candidate_id != eligible_incoming_candidate_id` is duplicate and must be closed exactly once.
   - `IncomingReady(current)` with non-matching overlap key is duplicate for this race and its connection handle must be closed exactly once.
   - wait-set is exactly `overlapping_incoming(peer, provisional.overlap_key)`; unaccepted/non-pending candidates are not waited on.
   - wait-set is live: new `IncomingAccepted` events for `(peer, provisional.overlap_key)` expand it while race is unresolved.
   - On any current `IncomingReady` or `IncomingRejected`, if
     `overlapping_incoming(peer, provisional.overlap_key)` becomes empty,
     then `Stable(provisional)` if healthy else `Idle + fail pending requests(peer) + schedule reconnect(peer)`.
   - `OutboundReady` while `waiting_for=Incoming` is stale and its connection handle must be closed.
3. Any current ready connection that is rejected as non-winning/duplicate during race resolution must be closed exactly once.

### 6.4 Connection Loss and Stream-Open Completion

1. Deselect/close rule: on any transition that deselects or locally closes generation `g` for peer `p` (including race winner replacement, reorder-compensation replacement, and connection-loss handling), complete all `InFlight{p, g}` requests immediately as `Failed` (or `Canceled` if request ID is in canceled set), then clear their bookkeeping.
   - Under the current model, `Race` is entered from `ConnectingOutbound` and `pump_requests` does not run during `Race`; therefore this rule is typically vacuous for race-resolution transitions but retained as a structural invariant.
2. `ConnectionLost` for selected stable generation:
   - event peer must match the peer-state entry being updated;
   - apply deselect/close rule for that generation;
   - `fail pending requests(peer)`;
   - transition to `Idle` + `schedule reconnect(peer)`.
   - Ordering is normative: apply deselect/close, then fail pending, then schedule reconnect/transition.
3. `ConnectionLost` for `Race.provisional` generation:
   - event peer must match the peer-state entry being updated;
   - apply deselect/close rule for provisional generation;
   - `fail pending requests(peer)`;
   - if waiting for outbound and expected attempt exists:
     if `attempt_resolved(expected attempt.attempt_id)`, create a fresh `attempt_id`+`overlap_key` and transition to `ConnectingOutbound(fresh attempt)`;
     otherwise transition to `ConnectingOutbound(expected attempt)`;
   - under strictly sequential event processing this `attempt_resolved(...)` branch is typically unreachable; it is retained as a defensive rule for composite/asynchronous event-delivery implementations.
   - else transition to `Idle` + `schedule reconnect(peer)`.
   - Ordering is normative: apply deselect/close, then fail pending, then reconnect/transition.
4. `StreamOpenFinished(current request_id, generation, result)`:
   - cancellation is dominant: if request was canceled, terminal outcome is `Canceled` regardless of opener success/failure detail;
   - if result contains an opened stream for a canceled, stale-generation, or already-completed request, close/reset that stream;
   - clear request bookkeeping (including cancel-set entry) and run `pump_requests(peer)`.

## 7. Safety Invariants

1. `AtMostOneSelected`: per peer, at most one selected connection exists (`Stable.conn` or `Race.provisional`).
2. `ReplaceOnlyWithOverlapEvidence`: healthy selected connection replacement occurs only when second-candidate evidence has matching `overlap_key` (race resolution or reorder compensation).
3. `DeterministicWinner`: whenever the model resolves between two established opposite-direction candidates for one overlap key, winner direction equals `preferred_direction(me, peer)`.
4. `NoDoubleDropInRace`: race resolution never closes both race participants; exactly one selected winner remains.
5. `SteadyStateStickiness`: outside race/reorder-compensation with matching overlap key, healthy selected connection rejects duplicates.
6. `StaleEventIsolation`: stale attempt/generation/candidate/request events never mutate selected state.
7. `StaleResourceCleanup`: stale established resources are closed/rejected.
8. `RequestSingleTerminal`: each request ID yields exactly one terminal outcome and is removed from request-tracking state.
9. `TransientExtraConnectionsBounded`: non-selected physical connections may exist transiently, but any rejected/stale/losing connection is closed exactly once.

## 8. Liveness Requirements

Assumptions:

1. Handshake attempts/candidates eventually resolve (`Ready | Failed | Rejected`) or connection loss is emitted.
2. Main loop fairly processes commands/events.
3. Reconnect scheduling eventually runs and does not defer forever (bounded backoff/jitter policy).
4. Incoming-side evidence (`IncomingAccepted`/`IncomingReady`) is available for simultaneous-connect windows, enabling IncomingReady-driven reorder compensation.
5. Pending-request failure policy is active on outbound-attempt failure and connection-loss paths via `fail pending requests(peer)`.
6. For any fixed `(peer, overlap_key)` window, only finitely many incoming candidates can be accepted.

Then:

1. `OpenRequestProgress`: each open request eventually returns `Opened | Canceled | Failed`.
2. `RaceProgress`: each `Race` state eventually exits to `Stable | Idle`.
3. `NoPermanentWedge`: no legal event sequence leaves a peer forever in `Race` without a transition path.

## 9. Forbidden Behaviors

1. Timer-only race completion.
2. Replacing a healthy stable connection without second-candidate race evidence for same overlap key.
3. Treating unmatched attempt/generation/candidate/request events as current.
4. Ignoring stale ready events without closing carried connection/stream resources.
5. Leaving pending requests blocked behind race or loss paths with no termination rule.
6. Deselecting/closing a connection generation without terminating all `InFlight` requests bound to that generation.

## 10. Implementation Checklist

1. Every transition is explicit `(state, event) -> new_state`.
2. Every async completion carries identity (attempt/generation/candidate/request) and is validated.
3. `Race(waiting_for=Outgoing)` always stores expected outbound attempt.
4. `Race(waiting_for=Incoming)` has explicit termination by overlap-key candidate exhaustion.
5. `InFlight` open requests are generation-bound and are terminated on deselection/loss of that generation.
6. Open-request cancellation is explicit and enforced pre-open and post-open-before-return.
7. Request pump is explicit on `Stable` entry and stream-open completion.
8. Overlap and reorder compensation are keyed by `overlap_key`, not heuristic timing.
9. Reorder compensation is IncomingReady-driven; OutboundReady in `Stable` is treated stale and closed.
10. Rejected duplicate current connections are closed exactly once.
11. Stale resources are always closed/reset.
12. Connection-loss and outbound-failure paths apply the documented pending-request failure policy.
