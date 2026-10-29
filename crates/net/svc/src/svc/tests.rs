use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

use ed25519_dalek::SigningKey;
use tokio::{sync::Notify, task::JoinHandle};

use super::*;
use crate::{api::ExpectError, config::PeerConfig};

const TEST_DEADLINE: Duration = Duration::from_secs(5);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_DEADLINE, future)
        .await
        .expect("service test operation must complete before its deadline")
}

struct RegistrationService {
    handle: NetServiceHandle,
    peer: PeerId,
    shutdown: AsyncSender<()>,
    task: JoinHandle<Result<(), ServiceError>>,
}

impl RegistrationService {
    async fn start() -> Self {
        let key = SigningKey::from_bytes(&[71; 32]);
        let peer = tls::peer_id_from_signing_key(&SigningKey::from_bytes(&[72; 32]));
        let config = Arc::new(NetServiceConfig::new(
            key,
            "127.0.0.1:0".parse().unwrap(),
            vec![PeerConfig::new(peer, "127.0.0.1:9".parse().unwrap())],
        ));
        let (command_tx, command_rx) = unbounded_async();
        let (protocol_tx, protocol_rx) = bounded_async(1);
        let (hint_tx, hint_rx) = bounded_async(1);
        let (shutdown, shutdown_rx) = bounded_async(1);
        let (startup_tx, startup_rx) = bounded_async(1);
        let handle = NetServiceHandle::new(config.clone(), command_tx, protocol_rx, hint_rx);
        let task = tokio::spawn(run_service_async(
            config,
            Arc::new(HashSet::from([peer])),
            command_rx,
            protocol_tx,
            hint_tx,
            shutdown_rx,
            startup_tx,
        ));
        within(startup_rx.recv()).await.unwrap().unwrap();
        Self {
            handle,
            peer,
            shutdown,
            task,
        }
    }

    async fn stop(self) {
        within(async {
            self.shutdown.send(()).await.unwrap();
            self.task
                .await
                .expect("service task must not panic")
                .expect("service must retain its shutdown signal");
        })
        .await;
    }
}

struct ReplyWake(Notify);

impl Wake for ReplyWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

fn poll_pending(future: Pin<&mut impl Future>) -> Arc<ReplyWake> {
    let wake = Arc::new(ReplyWake(Notify::new()));
    let waker = Waker::from(wake.clone());
    assert!(future.poll(&mut Context::from_waker(&waker)).is_pending());
    wake
}

fn service_loop_state() -> (ServiceState, PeerId) {
    let key = SigningKey::from_bytes(&[73; 32]);
    let peer = tls::peer_id_from_signing_key(&SigningKey::from_bytes(&[74; 32]));
    let config = Arc::new(NetServiceConfig::new(
        key,
        "127.0.0.1:0".parse().unwrap(),
        vec![PeerConfig::new(peer, "127.0.0.1:9".parse().unwrap())],
    ));
    let endpoint = Endpoint::client(config.bind_addr).unwrap();
    let client_config = tls::make_client_config(&config.signing_key, vec![peer]).unwrap();
    let (protocol_stream_tx, _protocol_rx) = bounded_async(1);
    let (hint_stream_tx, _hint_rx) = bounded_async(1);
    let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = ServiceState {
        peer_rate_limiter: peer_rate_limit::PeerStreamRateLimiter::new(
            config.peer_stream_rate_limit,
        ),
        config,
        endpoint,
        client_config,
        peer_states: HashMap::new(),
        bulk_expectations: HashMap::new(),
        protocol_stream_tx,
        hint_stream_tx,
        pending_reconnects: Vec::new(),
        pending_stream_requests: HashMap::new(),
        open_request_states: HashMap::new(),
        in_flight_open_responders: HashMap::new(),
        open_request_cancels: Arc::new(OpenRequestCancelRegistry::new()),
        pending_incoming_by_id: HashMap::new(),
        pending_incoming_by_peer: HashMap::new(),
        resolved_incoming_candidate_ids: ahash::HashSet::default(),
        event_tx,
        next_outbound_attempt_id: 1,
        next_overlap_key: 1,
        next_connection_generation: 1,
        resolved_outbound_attempt_by_peer: HashMap::new(),
        incompatible_peers: ahash::HashSet::default(),
    };
    (state, peer)
}

fn competing_events(
    peer: PeerId,
    mut handoff: impl FnMut() -> bool + Unpin,
) -> impl futures::Stream<Item = ServiceEvent> + Unpin {
    futures::stream::poll_fn(move |_| {
        if !handoff() {
            return Poll::Pending;
        }
        Poll::Ready(Some(ServiceEvent::MarkPeerIncompatible {
            peer,
            direction: "inbound",
            reason: "incompatible protocol version".to_owned(),
        }))
    })
}

#[tokio::test]
async fn cancelling_pending_bulk_registration_releases_identifier() {
    let service = RegistrationService::start().await;
    let identifier = [1; 32];
    let mut registration = Box::pin(
        service
            .handle
            .expect_bulk_transfer(service.peer, identifier),
    );
    let _wake = poll_pending(registration.as_mut());
    drop(registration);

    let replacement = within(
        service
            .handle
            .expect_bulk_transfer(service.peer, identifier),
    )
    .await
    .expect("cancelled pending registration must release its identifier");
    drop(replacement);
    service.stop().await;
}

#[tokio::test]
async fn cancelling_replied_bulk_registration_releases_identifier() {
    let service = RegistrationService::start().await;
    let identifier = [2; 32];
    let mut registration = Box::pin(
        service
            .handle
            .expect_bulk_transfer(service.peer, identifier),
    );
    let wake = poll_pending(registration.as_mut());
    within(wake.0.notified()).await;
    drop(registration);

    let replacement = within(
        service
            .handle
            .expect_bulk_transfer(service.peer, identifier),
    )
    .await
    .expect("cancelled unread reply must release its registration");
    drop(replacement);
    service.stop().await;
}

#[tokio::test]
async fn rejected_bulk_registration_preserves_existing_waiter() {
    let service = RegistrationService::start().await;
    let identifier = [3; 32];
    let original = within(
        service
            .handle
            .expect_bulk_transfer(service.peer, identifier),
    )
    .await
    .unwrap();

    for _ in 0..2 {
        assert!(matches!(
            within(
                service
                    .handle
                    .expect_bulk_transfer(service.peer, identifier),
            )
            .await,
            Err(ExpectError::AlreadyRegistered)
        ));
    }

    drop(original);
    let replacement = within(
        service
            .handle
            .expect_bulk_transfer(service.peer, identifier),
    )
    .await
    .expect("original waiter must retain ownership until dropped");
    drop(replacement);
    service.stop().await;
}

#[tokio::test]
async fn competing_event_preserves_handed_off_bulk_registration() {
    let (mut state, peer) = service_loop_state();
    let (command_tx, command_rx) = bounded_async(0);
    let (shutdown_tx, shutdown_rx) = bounded_async(0);
    let (response_tx, response_rx) = bounded_async(1);
    let identifier = [4; 32];
    let registration_id = 42;
    let handoff = Cell::new(None);
    let events = competing_events(peer, || {
        let Some(command) = handoff.take() else {
            return false;
        };
        assert!(
            command_tx.try_send(command).unwrap(),
            "the command must be handed directly to a waiting receiver"
        );
        true
    });

    let receiver;
    {
        let service_loop = run_service_loop(&mut state, command_rx, shutdown_rx, events);
        tokio::pin!(service_loop);
        let _wake = poll_pending(service_loop.as_mut());

        // All receives are waiting. The event poll hands off the command and
        // returns Ready before the selector can poll that command again.
        handoff.set(Some(NetCommand::ExpectBulkTransfer {
            registration_id,
            peer,
            identifier,
            respond_to: response_tx,
        }));
        let _wake = poll_pending(service_loop.as_mut());
        receiver = within(response_rx.recv())
            .await
            .unwrap()
            .expect("the handed-off registration must be processed before shutdown");

        within(shutdown_tx.send(())).await.unwrap();
        within(service_loop.as_mut()).await;
    }

    assert!(
        state.incompatible_peers.contains(&peer),
        "the competing event must be dispatched"
    );
    assert_eq!(
        state
            .bulk_expectations
            .get(&(peer, blake3::hash(&identifier).into()))
            .expect("the successful registration must remain owned")
            .registration_id,
        registration_id,
    );
    drop(receiver);
}

#[tokio::test]
async fn competing_event_preserves_handed_off_shutdown() {
    let (mut state, peer) = service_loop_state();
    let (_command_tx, command_rx) = unbounded_async();
    let (shutdown_tx, shutdown_rx) = bounded_async(0);
    let handoff = Cell::new(false);
    let events = competing_events(peer, || {
        if !handoff.replace(false) {
            return false;
        }
        assert!(
            shutdown_tx.try_send(()).unwrap(),
            "shutdown must be handed directly to a waiting receiver"
        );
        true
    });

    {
        let service_loop = run_service_loop(&mut state, command_rx, shutdown_rx, events);
        tokio::pin!(service_loop);
        let _wake = poll_pending(service_loop.as_mut());

        // Shutdown is delivered only while the competing event is being polled.
        // That event wins this selection even when shutdown was polled first.
        handoff.set(true);
        within(service_loop.as_mut()).await;
    }

    assert!(
        state.incompatible_peers.contains(&peer),
        "shutdown must not bypass the competing event"
    );
}
