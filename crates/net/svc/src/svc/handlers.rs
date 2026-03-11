//! Command and event handlers for the network service.
//!
//! This module contains the handler functions called by the main loop.
//! These handlers update state and spawn tasks but never block on I/O.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use kanal::{AsyncReceiver, bounded_async};

use super::{
    state::{
        ConnectionDirection, IncomingCandidate, IncomingCandidateId, OpenRequestState,
        OutboundAttempt, PeerConnectionState, PendingStreamRequest, ServiceEvent, ServiceState,
        TrackedConnection,
    },
    tasks,
};
use crate::{
    api::{ExpectError, NetCommand, OpenStreamError, Stream},
    close_codes::CLOSE_NORMAL,
    tls::PeerId,
};

/// Handle a command from a NetServiceHandle.
///
/// This function NEVER blocks. It either updates state instantly or spawns tasks.
pub fn handle_command(cmd: NetCommand, state: &mut ServiceState) {
    match cmd {
        NetCommand::OpenProtocolStream {
            request_id,
            peer,
            priority,
            cancel_token,
            respond_to,
        } => {
            handle_open_stream_request(
                request_id,
                peer,
                cancel_token,
                mosaic_net_wire::StreamType::Protocol,
                priority,
                respond_to,
                state,
            );
        }

        NetCommand::OpenBulkStream {
            request_id,
            peer,
            identifier,
            priority,
            cancel_token,
            respond_to,
        } => {
            let stream_type = mosaic_net_wire::StreamType::BulkTransfer { identifier };
            handle_open_stream_request(
                request_id,
                peer,
                cancel_token,
                stream_type,
                priority,
                respond_to,
                state,
            );
        }

        NetCommand::ExpectBulkTransfer {
            peer,
            identifier,
            respond_to,
        } => {
            handle_expect_bulk_transfer(peer, identifier, respond_to, state);
        }

        NetCommand::CancelBulkTransfer { peer, identifier } => {
            let key = (peer, blake3::hash(&identifier).into());
            if state.bulk_expectations.remove(&key).is_some() {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    identifier = %hex::encode(identifier),
                    "cancelled bulk transfer expectation"
                );
            }
        }

        NetCommand::CancelOpen { request_id } => {
            cancel_open_request(request_id, state);
        }
    }
}

fn preferred_direction(state: &ServiceState, peer: PeerId) -> ConnectionDirection {
    if state.config.our_peer_id() < peer {
        ConnectionDirection::Outgoing
    } else {
        ConnectionDirection::Incoming
    }
}

fn schedule_reconnect(peer: PeerId, state: &mut ServiceState) {
    let next_attempt = tokio::time::Instant::now() + state.config.reconnect_backoff;
    if !state.pending_reconnects.iter().any(|(p, _)| *p == peer) {
        state.pending_reconnects.push((peer, next_attempt));
    }
}

fn clear_reconnect(peer: PeerId, state: &mut ServiceState) {
    state.pending_reconnects.retain(|(p, _)| *p != peer);
}

fn start_outbound_attempt(peer: PeerId, state: &mut ServiceState) {
    let addr = match state.config.get_peer_addr(&peer) {
        Some(addr) => addr,
        None => return,
    };

    let attempt = OutboundAttempt {
        attempt_id: state.allocate_outbound_attempt_id(),
        started_at: tokio::time::Instant::now(),
        overlap_key: state.allocate_overlap_key(),
    };

    state
        .peer_states
        .insert(peer, PeerConnectionState::ConnectingOutbound { attempt });

    tasks::spawn_outbound_connection(
        state.endpoint.clone(),
        state.client_config.clone(),
        peer,
        attempt,
        addr,
        state.event_tx.clone(),
    );
}

fn ensure_outbound_attempt(peer: PeerId, state: &mut ServiceState) {
    let current = state
        .peer_states
        .get(&peer)
        .cloned()
        .unwrap_or(PeerConnectionState::Idle);

    if let PeerConnectionState::Idle = current {
        start_outbound_attempt(peer, state);
    }
}

fn connection_for_stream_open(
    state: &ServiceState,
    peer: PeerId,
) -> Option<(quinn::Connection, u64)> {
    match state.peer_states.get(&peer) {
        Some(PeerConnectionState::ActiveStable { connection })
            if connection.connection.close_reason().is_none() =>
        {
            Some((connection.connection.clone(), connection.generation))
        }
        _ => None,
    }
}

fn current_connection_generation(state: &ServiceState, peer: PeerId) -> Option<u64> {
    match state.peer_states.get(&peer) {
        Some(PeerConnectionState::ActiveStable { connection }) => Some(connection.generation),
        Some(PeerConnectionState::Race { provisional, .. }) => Some(provisional.generation),
        _ => None,
    }
}

fn stream_event_matches_current_generation(
    state: &ServiceState,
    peer: PeerId,
    generation: u64,
) -> bool {
    current_connection_generation(state, peer) == Some(generation)
}

fn fail_inflight_for_generation(
    peer: PeerId,
    generation: u64,
    reason: &str,
    state: &mut ServiceState,
) {
    let request_ids: Vec<u64> = state
        .open_request_states
        .iter()
        .filter_map(|(request_id, open_state)| match *open_state {
            OpenRequestState::InFlight {
                peer: request_peer,
                generation: request_generation,
            } if request_peer == peer && request_generation == generation => Some(*request_id),
            _ => None,
        })
        .collect();

    for request_id in request_ids {
        let canceled = state.open_request_cancels.take_if_canceled(request_id);
        state.open_request_states.remove(&request_id);
        state.open_request_cancels.clear(request_id);

        let terminal = if canceled {
            Err(OpenStreamError::ConnectionFailed(
                "stream open request canceled".to_string(),
            ))
        } else {
            Err(OpenStreamError::ConnectionFailed(reason.to_string()))
        };

        if let Some(respond_to) = state.in_flight_open_responders.remove(&request_id) {
            tokio::spawn(async move {
                let _ = respond_to.send(terminal).await;
            });
        }
    }
}

fn remove_pending_request_for_peer(
    peer: PeerId,
    request_id: u64,
    state: &mut ServiceState,
) -> Option<PendingStreamRequest> {
    let mut remove_entry = false;
    let mut removed_request = None;
    if let Some(requests) = state.pending_stream_requests.get_mut(&peer) {
        if let Some(index) = requests.iter().position(|req| req.request_id == request_id) {
            removed_request = Some(requests.remove(index));
        }
        remove_entry = requests.is_empty();
    }
    if remove_entry {
        state.pending_stream_requests.remove(&peer);
    }
    removed_request
}

fn send_terminal_open_result(
    respond_to: kanal::AsyncSender<Result<Stream, OpenStreamError>>,
    result: Result<Stream, OpenStreamError>,
) {
    tokio::spawn(async move {
        let _ = respond_to.send(result).await;
    });
}

fn cancel_open_request(request_id: u64, state: &mut ServiceState) {
    match state.open_request_states.get(&request_id).copied() {
        Some(OpenRequestState::Pending { peer }) => {
            if let Some(req) = remove_pending_request_for_peer(peer, request_id, state) {
                send_terminal_open_result(
                    req.respond_to,
                    Err(OpenStreamError::ConnectionFailed(
                        "stream open request canceled".to_string(),
                    )),
                );
            }
            state.open_request_states.remove(&request_id);
            state.open_request_cancels.clear(request_id);
            tracing::debug!(
                request_id,
                peer = %hex::encode(peer),
                "canceled pending stream-open request"
            );
        }
        Some(OpenRequestState::InFlight { .. }) => {
            state.open_request_cancels.cancel(request_id);
            tracing::debug!(request_id, "canceled in-flight stream-open request");
        }
        None => {
            // Open command was never observed for this request (for example the
            // caller dropped before enqueueing), so there is nothing to cancel.
            tracing::debug!(
                request_id,
                "ignoring cancel for unknown stream-open request"
            );
        }
    }
}

fn fail_pending_stream_requests(peer: PeerId, error: String, state: &mut ServiceState) {
    if let Some(requests) = state.pending_stream_requests.remove(&peer) {
        for req in requests {
            state.open_request_states.remove(&req.request_id);
            state.in_flight_open_responders.remove(&req.request_id);
            state.open_request_cancels.clear(req.request_id);
            let err = OpenStreamError::ConnectionFailed(error.clone());
            let _ = req.respond_to.to_sync().try_send(Err(err));
        }
    }
}

fn flush_pending_stream_requests(
    peer: PeerId,
    generation: u64,
    connection: &quinn::Connection,
    state: &mut ServiceState,
) {
    if let Some(requests) = state.pending_stream_requests.remove(&peer) {
        for req in requests {
            if req.cancel_token.load(Ordering::Acquire) {
                state.open_request_states.remove(&req.request_id);
                state.in_flight_open_responders.remove(&req.request_id);
                state.open_request_cancels.clear(req.request_id);
                send_terminal_open_result(
                    req.respond_to,
                    Err(OpenStreamError::ConnectionFailed(
                        "stream open request canceled".to_string(),
                    )),
                );
                continue;
            }

            let Some(open_state) = state.open_request_states.get(&req.request_id).copied() else {
                continue;
            };
            if !matches!(open_state, OpenRequestState::Pending { peer: p } if p == peer) {
                continue;
            }

            if state.open_request_cancels.take_if_canceled(req.request_id) {
                state.open_request_states.remove(&req.request_id);
                state.in_flight_open_responders.remove(&req.request_id);
                send_terminal_open_result(
                    req.respond_to,
                    Err(OpenStreamError::ConnectionFailed(
                        "stream open request canceled".to_string(),
                    )),
                );
                continue;
            }

            state.open_request_states.insert(
                req.request_id,
                OpenRequestState::InFlight { peer, generation },
            );
            state
                .in_flight_open_responders
                .insert(req.request_id, req.respond_to.clone());
            tasks::spawn_stream_opener(tasks::StreamOpenCtx {
                request_id: req.request_id,
                peer,
                generation,
                connection: connection.clone(),
                cancel_token: req.cancel_token,
                stream_type: req.stream_type,
                priority: req.priority,
                respond_to: req.respond_to,
                cancel_registry: state.open_request_cancels.clone(),
                event_tx: state.event_tx.clone(),
            });
        }
    }
}

fn transition_to_stable(peer: PeerId, connection: TrackedConnection, state: &mut ServiceState) {
    let old_selected_generation = current_connection_generation(state, peer);
    let new_generation = connection.generation;
    let conn = connection.connection.clone();
    state
        .peer_states
        .insert(peer, PeerConnectionState::ActiveStable { connection });
    if let Some(old_generation) = old_selected_generation
        && old_generation != new_generation
    {
        fail_inflight_for_generation(peer, old_generation, "selected connection replaced", state);
    }
    clear_reconnect(peer, state);
    flush_pending_stream_requests(peer, new_generation, &conn, state);
}

fn transition_to_race_waiting_outgoing(
    peer: PeerId,
    provisional: TrackedConnection,
    pending_attempt: OutboundAttempt,
    state: &mut ServiceState,
) {
    state.peer_states.insert(
        peer,
        PeerConnectionState::Race {
            provisional,
            pending_direction: ConnectionDirection::Outgoing,
            eligible_incoming_candidate_id: None,
            pending_outbound_attempt: Some(pending_attempt),
        },
    );
    clear_reconnect(peer, state);
}

fn transition_to_race_waiting_incoming(
    peer: PeerId,
    provisional: TrackedConnection,
    state: &mut ServiceState,
) {
    state.peer_states.insert(
        peer,
        PeerConnectionState::Race {
            provisional,
            pending_direction: ConnectionDirection::Incoming,
            eligible_incoming_candidate_id: None,
            pending_outbound_attempt: None,
        },
    );
    clear_reconnect(peer, state);
}

fn maybe_close_connection(conn: &quinn::Connection, reason: &'static [u8]) {
    if conn.close_reason().is_none() {
        conn.close(CLOSE_NORMAL, reason);
    }
}

fn insert_incoming_candidate(candidate: IncomingCandidate, state: &mut ServiceState) {
    state
        .pending_incoming_by_id
        .insert(candidate.candidate_id, candidate);
    state
        .pending_incoming_by_peer
        .entry(candidate.peer_guess)
        .or_default()
        .insert(candidate.candidate_id);
}

fn remove_incoming_candidate_by_id(
    candidate_id: IncomingCandidateId,
    state: &mut ServiceState,
) -> Option<(PeerId, IncomingCandidate)> {
    let candidate = state.pending_incoming_by_id.remove(&candidate_id)?;
    let owner_peer = candidate.peer_guess;
    let mut remove_bucket = false;
    if let Some(bucket) = state.pending_incoming_by_peer.get_mut(&owner_peer) {
        bucket.remove(&candidate_id);
        remove_bucket = bucket.is_empty();
    }
    if remove_bucket {
        state.pending_incoming_by_peer.remove(&owner_peer);
    }
    Some((owner_peer, candidate))
}

fn has_overlapping_incoming_candidate(
    peer: PeerId,
    overlap_key: u64,
    state: &ServiceState,
) -> bool {
    state
        .pending_incoming_by_peer
        .get(&peer)
        .map(|bucket| {
            bucket.iter().any(|candidate_id| {
                state
                    .pending_incoming_by_id
                    .get(candidate_id)
                    .map(|candidate| candidate.overlap_key == overlap_key)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn mark_outbound_attempt_resolved(peer: PeerId, attempt_id: u64, state: &mut ServiceState) {
    state
        .resolved_outbound_attempt_by_peer
        .insert(peer, attempt_id);
}

fn attempt_resolved(peer: PeerId, attempt_id: u64, state: &ServiceState) -> bool {
    state.resolved_outbound_attempt_by_peer.get(&peer).copied() == Some(attempt_id)
}

fn mark_incoming_candidate_resolved(candidate_id: IncomingCandidateId, state: &mut ServiceState) {
    state.resolved_incoming_candidate_ids.insert(candidate_id);
    if state.resolved_incoming_candidate_ids.len() > 8192 {
        state.resolved_incoming_candidate_ids.clear();
        state.resolved_incoming_candidate_ids.insert(candidate_id);
    }
}

fn handle_open_stream_request(
    request_id: u64,
    peer: PeerId,
    cancel_token: Arc<AtomicBool>,
    stream_type: mosaic_net_wire::StreamType,
    priority: i32,
    respond_to: kanal::AsyncSender<Result<Stream, OpenStreamError>>,
    state: &mut ServiceState,
) {
    if cancel_token.load(Ordering::Acquire) {
        tracing::debug!(
            request_id,
            peer = %hex::encode(peer),
            "dropped stream-open request canceled before command handling"
        );
        return;
    }

    if state.open_request_cancels.take_if_canceled(request_id) {
        tracing::debug!(
            request_id,
            peer = %hex::encode(peer),
            "dropped stream-open request canceled before processing"
        );
        return;
    }

    if state.open_request_states.contains_key(&request_id) {
        tracing::warn!(request_id, "duplicate stream-open request id rejected");
        tokio::spawn(async move {
            let _ = respond_to
                .send(Err(OpenStreamError::ConnectionFailed(
                    "duplicate stream-open request id".to_string(),
                )))
                .await;
        });
        return;
    }

    if !state.config.has_peer(&peer) {
        tokio::spawn(async move {
            let _ = respond_to.send(Err(OpenStreamError::PeerNotFound)).await;
        });
        return;
    }

    if let Some((connection, generation)) = connection_for_stream_open(state, peer) {
        state
            .open_request_states
            .insert(request_id, OpenRequestState::InFlight { peer, generation });
        state
            .in_flight_open_responders
            .insert(request_id, respond_to.clone());
        tasks::spawn_stream_opener(tasks::StreamOpenCtx {
            request_id,
            peer,
            generation,
            connection,
            cancel_token,
            stream_type,
            priority,
            respond_to,
            cancel_registry: state.open_request_cancels.clone(),
            event_tx: state.event_tx.clone(),
        });
        return;
    }

    state
        .open_request_states
        .insert(request_id, OpenRequestState::Pending { peer });

    state
        .pending_stream_requests
        .entry(peer)
        .or_default()
        .push(PendingStreamRequest {
            request_id,
            cancel_token,
            stream_type,
            priority,
            respond_to,
        });

    ensure_outbound_attempt(peer, state);
}

/// Handle a request to expect a bulk transfer.
fn handle_expect_bulk_transfer(
    peer: PeerId,
    identifier: [u8; 32],
    respond_to: kanal::AsyncSender<Result<AsyncReceiver<Stream>, ExpectError>>,
    state: &mut ServiceState,
) {
    if !state.config.has_peer(&peer) {
        tokio::spawn(async move {
            let _ = respond_to.send(Err(ExpectError::PeerNotFound)).await;
        });
        return;
    }

    let key = (peer, blake3::hash(&identifier).into());

    if state.bulk_expectations.contains_key(&key) {
        tokio::spawn(async move {
            let _ = respond_to.send(Err(ExpectError::AlreadyRegistered)).await;
        });
        return;
    }

    let (tx, rx) = bounded_async(1);
    state.bulk_expectations.insert(key, tx);

    tracing::debug!(
        peer = %hex::encode(peer),
        identifier = %hex::encode(identifier),
        "registered bulk transfer expectation"
    );

    tokio::spawn(async move {
        let _ = respond_to.send(Ok(rx)).await;
    });
}

fn on_incoming_ready(
    peer_auth: PeerId,
    peer_guess: PeerId,
    candidate_id: IncomingCandidateId,
    _accepted_at: tokio::time::Instant,
    incoming_overlap_key: u64,
    connection: quinn::Connection,
    state: &mut ServiceState,
) {
    let Some((owner_peer, candidate)) = remove_incoming_candidate_by_id(candidate_id, state) else {
        tracing::debug!(
            peer = %hex::encode(peer_auth),
            peer_guess = %hex::encode(peer_guess),
            candidate_id,
            "incoming ready has no current pending candidate; closing as stale"
        );
        maybe_close_connection(&connection, b"stale incoming");
        return;
    };

    if incoming_overlap_key != candidate.overlap_key {
        tracing::warn!(
            peer = %hex::encode(peer_auth),
            peer_guess = %hex::encode(peer_guess),
            candidate_id,
            expected_overlap_key = candidate.overlap_key,
            incoming_overlap_key,
            "incoming ready overlap key mismatch; closing connection"
        );
        mark_incoming_candidate_resolved(candidate_id, state);
        maybe_close_connection(&connection, b"invalid overlap key");
        maybe_resolve_waiting_incoming_race(owner_peer, "incoming overlap key mismatch", state);
        if owner_peer != peer_auth {
            maybe_resolve_waiting_incoming_race(peer_auth, "incoming overlap key mismatch", state);
        }
        return;
    }

    mark_incoming_candidate_resolved(candidate_id, state);

    if owner_peer != peer_auth {
        maybe_resolve_waiting_incoming_race(
            owner_peer,
            "incoming candidate authenticated to a different peer",
            state,
        );
    }

    let tracked = TrackedConnection {
        connection: connection.clone(),
        direction: ConnectionDirection::Incoming,
        generation: state.allocate_connection_generation(),
        overlap_key: candidate.overlap_key,
    };

    let current = state
        .peer_states
        .get(&peer_auth)
        .cloned()
        .unwrap_or(PeerConnectionState::Idle);

    match current {
        PeerConnectionState::Idle => {
            transition_to_stable(peer_auth, tracked.clone(), state);
            tasks::spawn_connection_monitor(
                peer_auth,
                tracked.generation,
                connection,
                state.event_tx.clone(),
            );
        }

        PeerConnectionState::ConnectingOutbound { attempt } => {
            if candidate.overlap_key == attempt.overlap_key {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    attempt_id = attempt.attempt_id,
                    "race start: incoming arrived while outbound attempt is pending"
                );
                transition_to_race_waiting_outgoing(peer_auth, tracked.clone(), attempt, state);
            } else {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    attempt_id = attempt.attempt_id,
                    "incoming does not overlap outbound attempt; keeping incoming stable"
                );
                transition_to_stable(peer_auth, tracked.clone(), state);
            }

            tasks::spawn_connection_monitor(
                peer_auth,
                tracked.generation,
                connection,
                state.event_tx.clone(),
            );
        }

        PeerConnectionState::ActiveStable {
            connection: stable_conn,
        } => {
            if stable_conn.connection.close_reason().is_some() {
                transition_to_stable(peer_auth, tracked.clone(), state);
                tasks::spawn_connection_monitor(
                    peer_auth,
                    tracked.generation,
                    connection,
                    state.event_tx.clone(),
                );
                return;
            }

            let incoming_preferred =
                preferred_direction(state, peer_auth) == ConnectionDirection::Incoming;
            let overlap = candidate.overlap_key == stable_conn.overlap_key;
            let opposite_direction = stable_conn.direction != ConnectionDirection::Incoming;

            if overlap && incoming_preferred && opposite_direction {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    old_direction = ?stable_conn.direction,
                    "race replacement: preferred incoming replaces active outgoing"
                );
                maybe_close_connection(&stable_conn.connection, b"replaced (race)");
                transition_to_stable(peer_auth, tracked.clone(), state);
                tasks::spawn_connection_monitor(
                    peer_auth,
                    tracked.generation,
                    connection,
                    state.event_tx.clone(),
                );
            } else {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    overlap,
                    incoming_preferred,
                    "rejecting incoming duplicate; stable connection retained"
                );
                maybe_close_connection(&connection, b"redundant");
            }
        }

        PeerConnectionState::Race {
            provisional,
            pending_direction,
            eligible_incoming_candidate_id,
            ..
        } => {
            if pending_direction != ConnectionDirection::Incoming {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    "rejecting duplicate incoming while waiting for outbound race candidate"
                );
                maybe_close_connection(&connection, b"redundant");
                return;
            }

            let overlap = candidate.overlap_key == provisional.overlap_key;
            if !overlap {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    "rejecting incoming candidate that does not overlap race provisional"
                );
                maybe_close_connection(&connection, b"redundant");
                maybe_resolve_waiting_incoming_race(
                    peer_auth,
                    "non-overlapping incoming candidate resolved while waiting for overlap",
                    state,
                );
                return;
            }

            let selected_candidate_id = eligible_incoming_candidate_id
                .map(|existing| existing.min(candidate.candidate_id))
                .unwrap_or(candidate.candidate_id);

            if eligible_incoming_candidate_id != Some(selected_candidate_id) {
                state.peer_states.insert(
                    peer_auth,
                    PeerConnectionState::Race {
                        provisional: provisional.clone(),
                        pending_direction: ConnectionDirection::Incoming,
                        eligible_incoming_candidate_id: Some(selected_candidate_id),
                        pending_outbound_attempt: None,
                    },
                );
            }

            if candidate.candidate_id != selected_candidate_id {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    candidate_id = candidate.candidate_id,
                    eligible_candidate_id = selected_candidate_id,
                    "rejecting non-eligible incoming candidate while waiting for deterministic race candidate"
                );
                maybe_close_connection(&connection, b"redundant");
                maybe_resolve_waiting_incoming_race(
                    peer_auth,
                    "non-eligible incoming candidate resolved while waiting for overlap",
                    state,
                );
                return;
            }

            let incoming_preferred =
                preferred_direction(state, peer_auth) == ConnectionDirection::Incoming;
            tracing::debug!(
                peer = %hex::encode(peer_auth),
                incoming_preferred,
                "race end: incoming candidate arrived, applying tie-break"
            );

            if incoming_preferred {
                tracing::debug!(
                    peer = %hex::encode(peer_auth),
                    old_direction = ?provisional.direction,
                    "race replacement: preferred incoming replaces provisional"
                );
                maybe_close_connection(&provisional.connection, b"replaced (race)");
                transition_to_stable(peer_auth, tracked.clone(), state);
                tasks::spawn_connection_monitor(
                    peer_auth,
                    tracked.generation,
                    connection,
                    state.event_tx.clone(),
                );
            } else {
                maybe_close_connection(&connection, b"redundant (race)");
                transition_to_stable(peer_auth, provisional, state);
            }
        }
    }
}

fn on_outgoing_ready(
    peer: PeerId,
    attempt: OutboundAttempt,
    _ready_at: tokio::time::Instant,
    connection: quinn::Connection,
    state: &mut ServiceState,
) {
    let current = state
        .peer_states
        .get(&peer)
        .cloned()
        .unwrap_or(PeerConnectionState::Idle);

    let tracked = TrackedConnection {
        connection: connection.clone(),
        direction: ConnectionDirection::Outgoing,
        generation: state.allocate_connection_generation(),
        overlap_key: attempt.overlap_key,
    };

    match current {
        PeerConnectionState::ConnectingOutbound { attempt: expected } => {
            if expected.attempt_id != attempt.attempt_id {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    attempt_id = attempt.attempt_id,
                    expected_attempt = expected.attempt_id,
                    "ignoring stale outbound ready event"
                );
                maybe_close_connection(&connection, b"stale outbound");
                return;
            }
            mark_outbound_attempt_resolved(peer, attempt.attempt_id, state);

            let incoming_preferred =
                preferred_direction(state, peer) == ConnectionDirection::Incoming;
            let overlapping_candidate =
                has_overlapping_incoming_candidate(peer, attempt.overlap_key, state);

            if incoming_preferred && overlapping_candidate {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    attempt_id = attempt.attempt_id,
                    "race start: outbound ready while overlapping incoming candidate is pending"
                );
                transition_to_race_waiting_incoming(peer, tracked.clone(), state);
            } else {
                transition_to_stable(peer, tracked.clone(), state);
            }
            tasks::spawn_connection_monitor(
                peer,
                tracked.generation,
                connection,
                state.event_tx.clone(),
            );
        }

        PeerConnectionState::ActiveStable {
            connection: stable_conn,
        } => {
            tracing::debug!(
                peer = %hex::encode(peer),
                attempt_id = attempt.attempt_id,
                "rejecting outbound ready while stable connection is selected"
            );
            let _ = stable_conn;
            maybe_close_connection(&connection, b"redundant");
        }

        PeerConnectionState::Race {
            provisional,
            pending_direction,
            pending_outbound_attempt,
            ..
        } => {
            if pending_direction != ConnectionDirection::Outgoing {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    attempt_id = attempt.attempt_id,
                    "rejecting outbound while waiting for incoming race candidate"
                );
                maybe_close_connection(&connection, b"redundant");
                return;
            }

            if pending_outbound_attempt.map(|a| a.attempt_id) != Some(attempt.attempt_id) {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    attempt_id = attempt.attempt_id,
                    expected = ?pending_outbound_attempt,
                    "ignoring stale outbound ready during race"
                );
                maybe_close_connection(&connection, b"stale outbound");
                return;
            }
            mark_outbound_attempt_resolved(peer, attempt.attempt_id, state);

            let outgoing_preferred =
                preferred_direction(state, peer) == ConnectionDirection::Outgoing;
            tracing::debug!(
                peer = %hex::encode(peer),
                outgoing_preferred,
                "race end: outbound candidate arrived, applying tie-break"
            );

            if outgoing_preferred {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    old_direction = ?provisional.direction,
                    "race replacement: preferred outgoing replaces provisional"
                );
                maybe_close_connection(&provisional.connection, b"replaced (race)");
                transition_to_stable(peer, tracked.clone(), state);
                tasks::spawn_connection_monitor(
                    peer,
                    tracked.generation,
                    connection,
                    state.event_tx.clone(),
                );
            } else {
                maybe_close_connection(&connection, b"redundant (race)");
                transition_to_stable(peer, provisional, state);
            }
        }

        PeerConnectionState::Idle => {
            tracing::debug!(
                peer = %hex::encode(peer),
                attempt_id = attempt.attempt_id,
                "ignoring outbound ready with no pending attempt"
            );
            maybe_close_connection(&connection, b"stale outbound");
        }
    }
}

fn on_incoming_accepted(
    peer_guess: PeerId,
    accepted_at: tokio::time::Instant,
    candidate_id: IncomingCandidateId,
    overlap_key: u64,
    state: &mut ServiceState,
) {
    if state
        .resolved_incoming_candidate_ids
        .contains(&candidate_id)
    {
        tracing::debug!(
            peer = %hex::encode(peer_guess),
            candidate_id,
            "ignoring late incoming accepted for already-resolved candidate"
        );
        return;
    }

    insert_incoming_candidate(
        IncomingCandidate {
            candidate_id,
            peer_guess,
            accepted_at,
            overlap_key,
        },
        state,
    );
}

fn on_incoming_rejected(
    _peer_guess: Option<PeerId>,
    peer_auth_opt: Option<PeerId>,
    candidate_id: IncomingCandidateId,
    reason: String,
    state: &mut ServiceState,
) {
    let Some((owner_peer, _candidate)) = remove_incoming_candidate_by_id(candidate_id, state)
    else {
        tracing::debug!(
            candidate_id,
            "ignoring stale incoming rejected event without pending candidate"
        );
        return;
    };
    mark_incoming_candidate_resolved(candidate_id, state);
    maybe_resolve_waiting_incoming_race(owner_peer, &reason, state);

    if let Some(peer_auth) = peer_auth_opt
        && peer_auth != owner_peer
    {
        maybe_resolve_waiting_incoming_race(peer_auth, &reason, state);
    }
}

fn maybe_resolve_waiting_incoming_race(peer: PeerId, reason: &str, state: &mut ServiceState) {
    let current = state
        .peer_states
        .get(&peer)
        .cloned()
        .unwrap_or(PeerConnectionState::Idle);

    if let PeerConnectionState::Race {
        provisional,
        pending_direction: ConnectionDirection::Incoming,
        eligible_incoming_candidate_id,
        pending_outbound_attempt: None,
        ..
    } = current
    {
        if has_overlapping_incoming_candidate(peer, provisional.overlap_key, state) {
            state.peer_states.insert(
                peer,
                PeerConnectionState::Race {
                    provisional,
                    pending_direction: ConnectionDirection::Incoming,
                    eligible_incoming_candidate_id,
                    pending_outbound_attempt: None,
                },
            );
            return;
        }

        tracing::debug!(
            peer = %hex::encode(peer),
            reason = %reason,
            "race end: incoming candidate resolved, keeping provisional outgoing"
        );

        if provisional.connection.close_reason().is_none() {
            transition_to_stable(peer, provisional, state);
        } else {
            state.peer_states.insert(peer, PeerConnectionState::Idle);
            schedule_reconnect(peer, state);
            fail_pending_stream_requests(
                peer,
                format!(
                    "provisional connection closed while resolving incoming candidate: {}",
                    reason
                ),
                state,
            );
        }
    }
}

fn on_outbound_failed(peer: PeerId, attempt_id: u64, error: String, state: &mut ServiceState) {
    let current = state
        .peer_states
        .get(&peer)
        .cloned()
        .unwrap_or(PeerConnectionState::Idle);

    match current {
        PeerConnectionState::ConnectingOutbound { attempt } if attempt.attempt_id == attempt_id => {
            mark_outbound_attempt_resolved(peer, attempt_id, state);
            state.peer_states.insert(peer, PeerConnectionState::Idle);
            fail_pending_stream_requests(peer, error, state);
            schedule_reconnect(peer, state);
        }

        PeerConnectionState::Race {
            provisional,
            pending_direction,
            pending_outbound_attempt,
            ..
        } if pending_direction == ConnectionDirection::Outgoing
            && pending_outbound_attempt.map(|a| a.attempt_id) == Some(attempt_id) =>
        {
            mark_outbound_attempt_resolved(peer, attempt_id, state);
            tracing::debug!(
                peer = %hex::encode(peer),
                attempt_id,
                "race end: outbound candidate failed, keeping provisional connection"
            );

            if provisional.connection.close_reason().is_none() {
                transition_to_stable(peer, provisional, state);
            } else {
                state.peer_states.insert(peer, PeerConnectionState::Idle);
                fail_pending_stream_requests(peer, error, state);
                schedule_reconnect(peer, state);
            }
        }

        _ => {
            tracing::debug!(
                peer = %hex::encode(peer),
                attempt_id,
                "ignoring stale outbound failed event"
            );
        }
    }
}

fn on_connection_lost(peer: PeerId, generation: u64, reason: String, state: &mut ServiceState) {
    let current = state
        .peer_states
        .get(&peer)
        .cloned()
        .unwrap_or(PeerConnectionState::Idle);

    match current {
        PeerConnectionState::ActiveStable { connection } => {
            if connection.generation != generation {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    generation,
                    expected = connection.generation,
                    "ignoring stale connection lost event"
                );
                return;
            }

            tracing::warn!(peer = %hex::encode(peer), reason = %reason, "stable connection lost");
            fail_inflight_for_generation(peer, generation, &reason, state);
            state.peer_states.insert(peer, PeerConnectionState::Idle);
            fail_pending_stream_requests(peer, reason, state);
            schedule_reconnect(peer, state);
        }

        PeerConnectionState::Race {
            provisional,
            pending_direction,
            pending_outbound_attempt,
            ..
        } => {
            if provisional.generation != generation {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    generation,
                    expected = provisional.generation,
                    "ignoring stale connection lost event during race"
                );
                return;
            }

            tracing::warn!(
                peer = %hex::encode(peer),
                reason = %reason,
                pending_direction = ?pending_direction,
                "provisional connection lost during race"
            );
            fail_inflight_for_generation(peer, generation, &reason, state);
            fail_pending_stream_requests(peer, reason.clone(), state);

            if pending_direction == ConnectionDirection::Outgoing {
                if let Some(expected_attempt) = pending_outbound_attempt {
                    // Defensive path: in strictly sequential processing this is
                    // typically unreachable, but we regenerate when the
                    // expected attempt already resolved to preserve liveness
                    // under composite/asynchronous event delivery.
                    if attempt_resolved(peer, expected_attempt.attempt_id, state) {
                        state.peer_states.insert(peer, PeerConnectionState::Idle);
                        start_outbound_attempt(peer, state);
                    } else {
                        state.peer_states.insert(
                            peer,
                            PeerConnectionState::ConnectingOutbound {
                                attempt: expected_attempt,
                            },
                        );
                    }
                } else {
                    state.peer_states.insert(peer, PeerConnectionState::Idle);
                    schedule_reconnect(peer, state);
                }
            } else {
                state.peer_states.insert(peer, PeerConnectionState::Idle);
                schedule_reconnect(peer, state);
            }
        }

        _ => {
            tracing::debug!(
                peer = %hex::encode(peer),
                generation,
                "ignoring connection lost for non-active peer state"
            );
        }
    }
}

fn on_stream_open_finished(
    request_id: u64,
    generation: u64,
    result: Result<Stream, OpenStreamError>,
    respond_to: kanal::AsyncSender<Result<Stream, OpenStreamError>>,
    state: &mut ServiceState,
) {
    let close_stream = |stream: Stream| {
        tokio::spawn(async move {
            stream.reset(0).await;
        });
    };

    let Some(open_state) = state.open_request_states.get(&request_id).copied() else {
        if let Ok(stream) = result {
            close_stream(stream);
        }
        state.open_request_cancels.clear(request_id);
        state.in_flight_open_responders.remove(&request_id);
        return;
    };

    let OpenRequestState::InFlight {
        peer,
        generation: in_flight_generation,
    } = open_state
    else {
        if let Ok(stream) = result {
            close_stream(stream);
        }
        state.open_request_cancels.clear(request_id);
        state.in_flight_open_responders.remove(&request_id);
        return;
    };

    if in_flight_generation != generation {
        tracing::debug!(
            request_id,
            generation,
            expected_generation = in_flight_generation,
            "ignoring stale stream-open completion event"
        );
        if let Ok(stream) = result {
            close_stream(stream);
        }
        state.open_request_cancels.clear(request_id);
        state.in_flight_open_responders.remove(&request_id);
        return;
    }

    let canceled = state.open_request_cancels.take_if_canceled(request_id);
    let terminal_result = if canceled {
        if let Ok(stream) = result {
            close_stream(stream);
        }
        Err(OpenStreamError::ConnectionFailed(
            "stream open request canceled".to_string(),
        ))
    } else {
        result
    };

    state.open_request_states.remove(&request_id);
    state.open_request_cancels.clear(request_id);
    let delivery = state
        .in_flight_open_responders
        .remove(&request_id)
        .unwrap_or(respond_to);
    send_terminal_open_result(delivery, terminal_result);
    if let Some((connection, current_generation)) = connection_for_stream_open(state, peer)
        && current_generation == generation
    {
        flush_pending_stream_requests(peer, generation, &connection, state);
    }
}

/// Handle an event from a spawned task.
///
/// This function NEVER blocks. It only updates state and spawns tasks.
pub fn handle_event(event: ServiceEvent, state: &mut ServiceState) {
    match event {
        ServiceEvent::IncomingConnectionAccepted {
            peer_guess,
            accepted_at,
            candidate_id,
            overlap_key,
        } => {
            tracing::debug!(
                peer = %hex::encode(peer_guess),
                candidate_id,
                "incoming connection candidate accepted"
            );
            on_incoming_accepted(peer_guess, accepted_at, candidate_id, overlap_key, state);
        }

        ServiceEvent::IncomingConnectionReady {
            peer_auth,
            peer_guess,
            candidate_id,
            accepted_at,
            overlap_key,
            connection,
        } => {
            tracing::info!(peer = %hex::encode(peer_auth), "incoming connection ready");
            on_incoming_ready(
                peer_auth,
                peer_guess,
                candidate_id,
                accepted_at,
                overlap_key,
                connection,
                state,
            );
        }

        ServiceEvent::IncomingConnectionRejected {
            peer_guess,
            peer_auth_opt,
            candidate_id,
            reason,
        } => {
            tracing::debug!(reason = %reason, "incoming connection rejected");
            on_incoming_rejected(peer_guess, peer_auth_opt, candidate_id, reason, state);
        }

        ServiceEvent::OutboundConnectionReady {
            peer,
            attempt,
            ready_at,
            connection,
        } => {
            tracing::info!(
                peer = %hex::encode(peer),
                attempt_id = attempt.attempt_id,
                "outbound connection ready"
            );
            on_outgoing_ready(peer, attempt, ready_at, connection, state);
        }

        ServiceEvent::OutboundConnectionFailed {
            peer,
            attempt_id,
            error,
        } => {
            tracing::debug!(
                peer = %hex::encode(peer),
                attempt_id,
                error = %error,
                "outbound connection failed"
            );
            on_outbound_failed(peer, attempt_id, error, state);
        }

        ServiceEvent::ConnectionLost {
            peer,
            generation,
            reason,
        } => {
            on_connection_lost(peer, generation, reason, state);
        }

        ServiceEvent::IncomingStream {
            peer,
            generation,
            mut send,
            recv,
        } => {
            if !stream_event_matches_current_generation(state, peer, generation) {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    generation,
                    current_generation = ?current_connection_generation(state, peer),
                    "dropping stale incoming stream before header read"
                );
                let _ = send.reset(0u32.into());
                return;
            }

            tasks::spawn_stream_header_reader(peer, generation, send, recv, state.event_tx.clone());
        }

        ServiceEvent::StreamReady {
            peer,
            generation,
            stream_type,
            mut send,
            recv,
        } => {
            if !stream_event_matches_current_generation(state, peer, generation) {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    generation,
                    current_generation = ?current_connection_generation(state, peer),
                    "dropping stale stream after header read"
                );
                let _ = send.reset(0u32.into());
                return;
            }

            match stream_type {
                mosaic_net_wire::StreamType::Protocol => {
                    tasks::spawn_protocol_stream_router(
                        peer,
                        send,
                        recv,
                        state.protocol_stream_tx.clone(),
                    );
                }
                mosaic_net_wire::StreamType::BulkTransfer { identifier } => {
                    let hash: [u8; 32] = blake3::hash(&identifier).into();
                    let key = (peer, hash);

                    if let Some(expectation_tx) = state.bulk_expectations.remove(&key) {
                        tasks::spawn_bulk_stream_router(peer, send, recv, expectation_tx);
                    } else {
                        tracing::debug!(
                            peer = %hex::encode(peer),
                            identifier = %hex::encode(identifier),
                            "no expectation for bulk transfer, dropping stream"
                        );
                    }
                }
            }
        }

        ServiceEvent::StreamHeaderFailed {
            peer,
            generation,
            error,
        } => {
            if stream_event_matches_current_generation(state, peer, generation) {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    generation,
                    error = %error,
                    "stream header read failed"
                );
            } else {
                tracing::debug!(
                    peer = %hex::encode(peer),
                    generation,
                    current_generation = ?current_connection_generation(state, peer),
                    "ignoring stale stream header failure"
                );
            }
        }

        ServiceEvent::StreamOpenFinished {
            request_id,
            generation,
            result,
            respond_to,
        } => {
            on_stream_open_finished(request_id, generation, result, respond_to, state);
        }
    }
}

/// Process pending reconnection attempts.
///
/// This function NEVER blocks. It only spawns connection tasks.
pub fn process_pending_reconnects(state: &mut ServiceState) {
    let now = tokio::time::Instant::now();

    let mut to_reconnect = Vec::new();

    state.pending_reconnects.retain(|(peer, next_attempt)| {
        if *next_attempt <= now {
            to_reconnect.push(*peer);
            false
        } else {
            true
        }
    });

    for peer in to_reconnect {
        if connection_for_stream_open(state, peer).is_some() {
            continue;
        }

        let current = state
            .peer_states
            .get(&peer)
            .cloned()
            .unwrap_or(PeerConnectionState::Idle);

        let outbound_in_flight = matches!(current, PeerConnectionState::ConnectingOutbound { .. })
            || matches!(
                current,
                PeerConnectionState::Race {
                    pending_direction: ConnectionDirection::Outgoing,
                    pending_outbound_attempt: Some(_),
                    ..
                }
            );

        if outbound_in_flight {
            continue;
        }

        // Reconnect attempts follow ensure-outbound semantics: only Idle can
        // create a fresh outbound attempt.
        if !matches!(current, PeerConnectionState::Idle) {
            continue;
        }

        ensure_outbound_attempt(peer, state);
    }
}

/// Return the earliest wakeup needed for reconnect work.
pub fn next_wakeup_deadline(state: &ServiceState) -> Option<tokio::time::Instant> {
    state.pending_reconnects.iter().map(|(_, t)| *t).min()
}

/// Fallback sleep duration when no reconnect work is pending.
pub fn idle_housekeeping_sleep() -> Duration {
    Duration::from_secs(3600)
}
