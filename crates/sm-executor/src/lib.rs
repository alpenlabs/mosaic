//! SM executor implementation.

use std::panic::AssertUnwindSafe;

use fasm::{Input as FasmInput, StateMachine};
use futures::FutureExt;
use mosaic_cac_protocol::{SMError, evaluator::EvaluatorSM, garbler::GarblerSM};
use mosaic_cac_types::{
    Msg,
    state_machine::{evaluator, garbler},
};
use mosaic_job_api::{ActionCompletion, JobActions, JobBatch, JobCompletion, JobSchedulerHandle};
use mosaic_net_client::{InboundRequest, NetClient, RecvError};
use mosaic_net_svc_api::PeerId;
use mosaic_sm_executor_api::{
    DepositInitData, DisputedWithdrawalData, InitData, SmCommand, SmCommandKind, SmExecutorConfig,
    SmExecutorHandle, SmRole,
};
use mosaic_storage_api::{Commit, StorageProviderMut};
use tracing::Instrument;

/// SM executor error.
#[derive(Debug, thiserror::Error)]
pub enum SmExecutorError {
    /// Input source has shut down.
    #[error("source closed: {0}")]
    SourceClosed(&'static str),

    /// Network receive failed.
    #[error("network receive failed: {0}")]
    NetRecv(#[from] RecvError),

    /// Ack failed.
    #[error("protocol ack failed for peer={peer_id:?}: {source}")]
    Ack {
        /// Peer that sent the inbound message.
        peer_id: PeerId,
        /// Underlying ack error.
        #[source]
        source: mosaic_net_client::AckError,
    },

    /// Job submission channel has closed.
    #[error("job submission failed for peer={peer_id:?}: {source}")]
    JobSubmission {
        /// Peer whose actions failed to submit.
        peer_id: PeerId,
        /// Underlying scheduler stopped error.
        #[source]
        source: mosaic_job_api::SchedulerStopped,
    },

    /// Command failed role/payload validation.
    #[error("command role mismatch: {0}")]
    RoleMismatch(&'static str),

    /// STF transition failed.
    #[error("stf failed for peer={peer_id:?}, role={role:?}: {source}")]
    Stf {
        /// Peer id for the routed input.
        peer_id: PeerId,
        /// Role routed to.
        role: SmRole,
        /// Underlying SM transition error.
        #[source]
        source: SMError,
    },

    /// STF transition panicked.
    #[error("stf panicked for peer={peer_id:?}, role={role:?}, stage={stage}")]
    StfPanic {
        /// Peer id for the routed input.
        peer_id: PeerId,
        /// Role routed to.
        role: SmRole,
        /// STF stage that panicked.
        stage: &'static str,
    },

    /// Commit failed.
    #[error("commit failed for peer={peer_id:?}, role={role:?}: {reason}")]
    Commit {
        /// Peer id whose state failed to commit.
        peer_id: PeerId,
        /// Role whose state failed to commit.
        role: SmRole,
        /// Commit failure detail.
        reason: String,
    },
}

/// SM executor.
#[derive(Debug)]
pub struct SmExecutor<S>
where
    S: StorageProviderMut + 'static,
    S::GarblerState: garbler::StateMut + Commit,
    S::EvaluatorState: evaluator::StateMut + Commit,
{
    config: SmExecutorConfig,
    storage: S,
    job_handle: JobSchedulerHandle,
    net_client: NetClient,
    command_rx: kanal::AsyncReceiver<SmCommand>,
}

impl<S> SmExecutor<S>
where
    S: StorageProviderMut + 'static,
    S::GarblerState: garbler::StateMut + Commit,
    S::EvaluatorState: evaluator::StateMut + Commit,
{
    /// Create a new executor and handle.
    pub fn new(
        config: SmExecutorConfig,
        storage: S,
        job_handle: JobSchedulerHandle,
        net_client: NetClient,
    ) -> (Self, SmExecutorHandle) {
        let (command_tx, command_rx) = kanal::bounded_async(config.command_queue_size);
        let handle = SmExecutorHandle::new(command_tx);

        (
            Self {
                config,
                storage,
                job_handle,
                net_client,
                command_rx,
            },
            handle,
        )
    }

    /// Run executor loop.
    pub async fn run(self) -> Result<(), SmExecutorError> {
        let span = tracing::info_span!(
            "sm_executor.run",
            known_peers = self.config.known_peers.len(),
            command_queue_size = self.config.command_queue_size
        );
        async move {
            tracing::info!("sm executor starting");
            self.restore_known_peers().await?;
            tracing::info!("sm executor restore completed; entering main loop");

            loop {
                monoio::select! {
                    completion = self.job_handle.recv() => {
                        match completion {
                            Ok(c) => {
                                let role = completion_role(&c.completion);
                                tracing::debug!(peer = ?c.peer_id, role = ?role, "received job completion");
                                if let Err(err) = self.handle_job_completion(c).await {
                                    if Self::is_fatal_processing_error(&err) {
                                        tracing::error!(error = ?err, "fatal completion handling error; stopping sm executor");
                                        return Err(err);
                                    }
                                    tracing::warn!(error = ?err, "job completion handling failed; dropping completion");
                                }
                            }
                            Err(_) => {
                                tracing::error!("job completion channel closed; stopping sm executor");
                                return Err(SmExecutorError::SourceClosed("job completion channel"));
                            }
                        }
                    }
                    inbound = self.net_client.recv() => {
                        match inbound {
                            Ok(req) => {
                                tracing::debug!(
                                    peer = ?req.peer(),
                                    msg_kind = msg_kind(&req.message),
                                    "received inbound protocol request"
                                );
                                if let Err(err) = self.handle_inbound_request(req).await {
                                    tracing::warn!(error = ?err, "inbound protocol handling failed; leaving stream unacked");
                                }
                            }
                            Err(err) => {
                                if let Some(fatal) = Self::fatal_net_recv_error(&err) {
                                    tracing::error!(error = ?err, "network receive failed; stopping sm executor");
                                    return Err(fatal);
                                }
                                tracing::warn!(error = ?err, "network receive failed for one inbound stream; continuing executor loop");
                            }
                        }
                    }
                    command = self.command_rx.recv() => {
                        match command {
                            Ok(cmd) => {
                                tracing::debug!(
                                    peer = ?cmd.peer_id(),
                                    role = ?cmd.role(),
                                    kind = command_kind(&cmd.kind),
                                    "received executor command"
                                );
                                if let Err(err) = self.handle_command(cmd).await {
                                    if Self::is_fatal_processing_error(&err) {
                                        tracing::error!(error = ?err, "fatal command handling error; stopping sm executor");
                                        return Err(err);
                                    }
                                    tracing::warn!(error = ?err, "executor command handling failed; command dropped");
                                }
                            }
                            Err(_) => {
                                tracing::error!("executor command channel closed; stopping sm executor");
                                return Err(SmExecutorError::SourceClosed("executor command channel"));
                            }
                        }
                    }
                }
            }
        }
        .instrument(span)
        .await
    }

    async fn restore_known_peers(&self) -> Result<(), SmExecutorError> {
        let span = tracing::info_span!(
            "sm_executor.restore_known_peers",
            peers = self.config.known_peers.len()
        );
        async {
            tracing::info!("starting restore for configured peers");
            let mut restored = 0usize;
            let mut failed = 0usize;
            let mut garbler_ok = 0usize;
            let mut garbler_failed = 0usize;
            let mut evaluator_ok = 0usize;
            let mut evaluator_failed = 0usize;
            for peer_id in self.config.known_peers.iter().copied() {
                tracing::info!(peer = ?peer_id, "restoring peer");
                let (peer_garbler_ok, peer_evaluator_ok) = self.restore_peer(peer_id).await?;
                if peer_garbler_ok {
                    garbler_ok += 1;
                } else {
                    garbler_failed += 1;
                }
                if peer_evaluator_ok {
                    evaluator_ok += 1;
                } else {
                    evaluator_failed += 1;
                }
                if peer_garbler_ok && peer_evaluator_ok {
                    restored += 1;
                    tracing::info!(peer = ?peer_id, "peer restore completed");
                } else {
                    failed += 1;
                    tracing::warn!(
                        peer = ?peer_id,
                        garbler_ok = peer_garbler_ok,
                        evaluator_ok = peer_evaluator_ok,
                        "peer restore completed with role failures"
                    );
                }
            }
            tracing::info!(
                restored,
                failed,
                garbler_ok,
                garbler_failed,
                evaluator_ok,
                evaluator_failed,
                "restore pass finished"
            );

            Ok(())
        }
        .instrument(span)
        .await
    }

    async fn restore_peer(&self, peer_id: PeerId) -> Result<(bool, bool), SmExecutorError> {
        let span = tracing::debug_span!("sm_executor.restore_peer", peer = ?peer_id);
        async {
            let garbler_ok = {
                tracing::debug!(role = ?SmRole::Garbler, "restoring garbler state machine");
                let state = self.storage.garbler_state_mut(&peer_id);
                let mut actions = garbler::ActionContainer::default();
                match Self::stf_guard(peer_id, SmRole::Garbler, "restore", async {
                    GarblerSM::<S::GarblerState>::restore(&state, &mut actions).await
                })
                .await
                {
                    Ok(()) => {
                        tracing::debug!(
                            role = ?SmRole::Garbler,
                            actions = actions.len(),
                            "garbler restore STF completed"
                        );
                        match Self::commit_state(state, peer_id, SmRole::Garbler).await {
                            Ok(()) => {
                                match self
                                    .submit_actions(peer_id, JobActions::Garbler(actions))
                                    .await
                                {
                                    Ok(()) => true,
                                    Err(err) => {
                                        if Self::is_fatal_processing_error(&err) {
                                            return Err(err);
                                        }
                                        tracing::error!(
                                            role = ?SmRole::Garbler,
                                            error = ?err,
                                            "garbler restore action submission failed"
                                        );
                                        false
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::error!(
                                    role = ?SmRole::Garbler,
                                    error = ?err,
                                    "garbler restore commit failed"
                                );
                                false
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            role = ?SmRole::Garbler,
                            error = ?err,
                            "garbler restore STF failed"
                        );
                        false
                    }
                }
            };

            let evaluator_ok = {
                tracing::debug!(role = ?SmRole::Evaluator, "restoring evaluator state machine");
                let state = self.storage.evaluator_state_mut(&peer_id);
                let mut actions = evaluator::ActionContainer::default();
                match Self::stf_guard(peer_id, SmRole::Evaluator, "restore", async {
                    EvaluatorSM::<S::EvaluatorState>::restore(&state, &mut actions).await
                })
                .await
                {
                    Ok(()) => {
                        tracing::debug!(
                            role = ?SmRole::Evaluator,
                            actions = actions.len(),
                            "evaluator restore STF completed"
                        );
                        match Self::commit_state(state, peer_id, SmRole::Evaluator).await {
                            Ok(()) => {
                                match self
                                    .submit_actions(peer_id, JobActions::Evaluator(actions))
                                    .await
                                {
                                    Ok(()) => true,
                                    Err(err) => {
                                        if Self::is_fatal_processing_error(&err) {
                                            return Err(err);
                                        }
                                        tracing::error!(
                                            role = ?SmRole::Evaluator,
                                            error = ?err,
                                            "evaluator restore action submission failed"
                                        );
                                        false
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::error!(
                                    role = ?SmRole::Evaluator,
                                    error = ?err,
                                    "evaluator restore commit failed"
                                );
                                false
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            role = ?SmRole::Evaluator,
                            error = ?err,
                            "evaluator restore STF failed"
                        );
                        false
                    }
                }
            };

            Ok((garbler_ok, evaluator_ok))
        }
        .instrument(span)
        .await
    }

    async fn handle_command(&self, cmd: SmCommand) -> Result<(), SmExecutorError> {
        let peer_id = *cmd.peer_id();
        let role = cmd.role();
        let kind = command_kind(&cmd.kind);
        let span = tracing::debug_span!(
            "sm_executor.handle_command",
            peer = ?peer_id,
            role = ?role,
            kind
        );
        async move {
            tracing::debug!("applying executor command");
            let result = match (role, cmd.kind) {
                (SmRole::Garbler, SmCommandKind::Init(InitData::Garbler(data))) => {
                    self.apply_garbler_event(peer_id, garbler::Input::Init(data))
                        .await
                }
                (SmRole::Evaluator, SmCommandKind::Init(InitData::Evaluator(data))) => {
                    self.apply_evaluator_event(peer_id, evaluator::Input::Init(data))
                        .await
                }
                (
                    SmRole::Garbler,
                    SmCommandKind::DepositInit {
                        deposit_id,
                        data: DepositInitData::Garbler(data),
                    },
                ) => {
                    self.apply_garbler_event(peer_id, garbler::Input::DepositInit(deposit_id, data))
                        .await
                }
                (
                    SmRole::Evaluator,
                    SmCommandKind::DepositInit {
                        deposit_id,
                        data: DepositInitData::Evaluator(data),
                    },
                ) => {
                    self.apply_evaluator_event(
                        peer_id,
                        evaluator::Input::DepositInit(deposit_id, data),
                    )
                    .await
                }
                (
                    SmRole::Garbler,
                    SmCommandKind::DisputedWithdrawal {
                        deposit_id,
                        data: DisputedWithdrawalData::Garbler(withdrawal_inputs),
                    },
                ) => {
                    self.apply_garbler_event(
                        peer_id,
                        garbler::Input::DisputedWithdrawal(deposit_id, withdrawal_inputs),
                    )
                    .await
                }
                (
                    SmRole::Evaluator,
                    SmCommandKind::DisputedWithdrawal {
                        deposit_id,
                        data: DisputedWithdrawalData::Evaluator(data),
                    },
                ) => {
                    self.apply_evaluator_event(
                        peer_id,
                        evaluator::Input::DisputedWithdrawal(deposit_id, data),
                    )
                    .await
                }
                (SmRole::Garbler, SmCommandKind::UndisputedWithdrawal { deposit_id }) => {
                    self.apply_garbler_event(
                        peer_id,
                        garbler::Input::DepositUndisputedWithdrawal(deposit_id),
                    )
                    .await
                }
                (SmRole::Evaluator, SmCommandKind::UndisputedWithdrawal { deposit_id }) => {
                    self.apply_evaluator_event(
                        peer_id,
                        evaluator::Input::DepositUndisputedWithdrawal(deposit_id),
                    )
                    .await
                }
                _ => Err(SmExecutorError::RoleMismatch(
                    "role does not match command payload variant",
                )),
            };
            if result.is_ok() {
                tracing::debug!("executor command applied");
            }
            result
        }
        .instrument(span)
        .await
    }

    async fn handle_job_completion(
        &self,
        completion: JobCompletion,
    ) -> Result<(), SmExecutorError> {
        let peer_id = completion.peer_id;
        let role = completion_role(&completion.completion);
        let span = tracing::debug_span!(
            "sm_executor.handle_job_completion",
            peer = ?peer_id,
            role = ?role
        );
        async move {
            tracing::debug!("applying job completion");
            match completion.completion {
                ActionCompletion::Garbler { id, result } => {
                    self.apply_garbler_completion(peer_id, id, result).await
                }
                ActionCompletion::Evaluator { id, result } => {
                    self.apply_evaluator_completion(peer_id, id, result).await
                }
            }
        }
        .instrument(span)
        .await
    }

    async fn handle_inbound_request(&self, request: InboundRequest) -> Result<(), SmExecutorError> {
        let peer_id = request.peer();
        let span = tracing::debug_span!(
            "sm_executor.handle_inbound_request",
            peer = ?peer_id,
            msg_kind = msg_kind(&request.message)
        );
        async move {
            tracing::debug!("applying inbound request");

            match &request.message {
                Msg::CommitHeader(msg) => {
                    self.apply_evaluator_event(
                        peer_id,
                        evaluator::Input::RecvCommitMsgHeader(msg.clone()),
                    )
                    .await?;
                }
                Msg::CommitChunk(msg) => {
                    self.apply_evaluator_event(
                        peer_id,
                        evaluator::Input::RecvCommitMsgChunk(msg.clone()),
                    )
                    .await?;
                }
                Msg::Challenge(msg) => {
                    self.apply_garbler_event(
                        peer_id,
                        garbler::Input::RecvChallengeMsg(msg.clone()),
                    )
                    .await?;
                }
                Msg::ChallengeResponseHeader(msg) => {
                    self.apply_evaluator_event(
                        peer_id,
                        evaluator::Input::RecvChallengeResponseMsgHeader(msg.clone()),
                    )
                    .await?;
                }
                Msg::ChallengeResponseChunk(msg) => {
                    self.apply_evaluator_event(
                        peer_id,
                        evaluator::Input::RecvChallengeResponseMsgChunk(msg.clone()),
                    )
                    .await?;
                }
                Msg::AdaptorChunk(msg) => {
                    self.apply_garbler_event(
                        peer_id,
                        garbler::Input::DepositRecvAdaptorMsgChunk(msg.deposit_id, msg.clone()),
                    )
                    .await?;
                }
            }
            tracing::debug!("inbound request applied; acking");

            match request.ack().await {
                Ok(()) => {
                    tracing::debug!("inbound request acked");
                    Ok(())
                }
                Err(source) => Err(SmExecutorError::Ack { peer_id, source }),
            }
        }
        .instrument(span)
        .await
    }

    async fn apply_garbler_event(
        &self,
        peer_id: PeerId,
        input: garbler::Input,
    ) -> Result<(), SmExecutorError> {
        let span = tracing::trace_span!(
            "sm_executor.apply_garbler_event",
            peer = ?peer_id,
            role = ?SmRole::Garbler,
            input_kind = garbler_input_kind(&input)
        );
        async move {
            tracing::trace!("running STF for event");
            let mut state = self.storage.garbler_state_mut(&peer_id);
            let mut actions = garbler::ActionContainer::default();

            Self::stf_guard(peer_id, SmRole::Garbler, "event", async {
                GarblerSM::<S::GarblerState>::stf(
                    &mut state,
                    FasmInput::Normal(input),
                    &mut actions,
                )
                .await
            })
            .await?;
            tracing::debug!(actions = actions.len(), "garbler event STF completed");

            Self::commit_state(state, peer_id, SmRole::Garbler).await?;
            self.submit_actions(peer_id, JobActions::Garbler(actions))
                .await
        }
        .instrument(span)
        .await
    }

    async fn apply_evaluator_event(
        &self,
        peer_id: PeerId,
        input: evaluator::Input,
    ) -> Result<(), SmExecutorError> {
        let span = tracing::trace_span!(
            "sm_executor.apply_evaluator_event",
            peer = ?peer_id,
            role = ?SmRole::Evaluator,
            input_kind = evaluator_input_kind(&input)
        );
        async move {
            tracing::trace!("running STF for event");
            let mut state = self.storage.evaluator_state_mut(&peer_id);
            let mut actions = evaluator::ActionContainer::default();

            Self::stf_guard(peer_id, SmRole::Evaluator, "event", async {
                EvaluatorSM::<S::EvaluatorState>::stf(
                    &mut state,
                    FasmInput::Normal(input),
                    &mut actions,
                )
                .await
            })
            .await?;
            tracing::debug!(actions = actions.len(), "evaluator event STF completed");

            Self::commit_state(state, peer_id, SmRole::Evaluator).await?;
            self.submit_actions(peer_id, JobActions::Evaluator(actions))
                .await
        }
        .instrument(span)
        .await
    }

    async fn apply_garbler_completion(
        &self,
        peer_id: PeerId,
        id: garbler::ActionId,
        result: garbler::ActionResult,
    ) -> Result<(), SmExecutorError> {
        let span = tracing::trace_span!(
            "sm_executor.apply_garbler_completion",
            peer = ?peer_id,
            role = ?SmRole::Garbler,
            action_id = ?id
        );
        async move {
            tracing::trace!("running STF for tracked completion");
            let mut state = self.storage.garbler_state_mut(&peer_id);
            let mut actions = garbler::ActionContainer::default();

            Self::stf_guard(peer_id, SmRole::Garbler, "completion", async {
                GarblerSM::<S::GarblerState>::stf(
                    &mut state,
                    FasmInput::TrackedActionCompleted { id, result },
                    &mut actions,
                )
                .await
            })
            .await?;
            tracing::debug!(actions = actions.len(), "garbler completion STF completed");

            Self::commit_state(state, peer_id, SmRole::Garbler).await?;
            self.submit_actions(peer_id, JobActions::Garbler(actions))
                .await
        }
        .instrument(span)
        .await
    }

    async fn apply_evaluator_completion(
        &self,
        peer_id: PeerId,
        id: evaluator::ActionId,
        result: evaluator::ActionResult,
    ) -> Result<(), SmExecutorError> {
        let span = tracing::trace_span!(
            "sm_executor.apply_evaluator_completion",
            peer = ?peer_id,
            role = ?SmRole::Evaluator,
            action_id = ?id
        );
        async move {
            tracing::trace!("running STF for tracked completion");
            let mut state = self.storage.evaluator_state_mut(&peer_id);
            let mut actions = evaluator::ActionContainer::default();

            Self::stf_guard(peer_id, SmRole::Evaluator, "completion", async {
                EvaluatorSM::<S::EvaluatorState>::stf(
                    &mut state,
                    FasmInput::TrackedActionCompleted { id, result },
                    &mut actions,
                )
                .await
            })
            .await?;
            tracing::debug!(
                actions = actions.len(),
                "evaluator completion STF completed"
            );

            Self::commit_state(state, peer_id, SmRole::Evaluator).await?;
            self.submit_actions(peer_id, JobActions::Evaluator(actions))
                .await
        }
        .instrument(span)
        .await
    }

    async fn submit_actions(
        &self,
        peer_id: PeerId,
        actions: JobActions,
    ) -> Result<(), SmExecutorError> {
        let role = if actions.is_garbler() {
            SmRole::Garbler
        } else {
            SmRole::Evaluator
        };
        let action_count = actions.len();
        tracing::debug!(
            peer = ?peer_id,
            role = ?role,
            actions = action_count,
            "submitting job batch"
        );
        self.job_handle
            .submit(JobBatch { peer_id, actions })
            .await
            .map_err(|source| SmExecutorError::JobSubmission { peer_id, source })?;
        tracing::debug!(
            peer = ?peer_id,
            role = ?role,
            actions = action_count,
            "job batch submitted"
        );
        Ok(())
    }

    async fn commit_state<T: Commit>(
        state: T,
        peer_id: PeerId,
        role: SmRole,
    ) -> Result<(), SmExecutorError> {
        tracing::trace!(peer = ?peer_id, role = ?role, "committing state");
        state
            .commit()
            .await
            .map_err(|err| SmExecutorError::Commit {
                peer_id,
                role,
                reason: format!("{err:?}"),
            })?;
        tracing::debug!(peer = ?peer_id, role = ?role, "state committed");
        Ok(())
    }

    async fn stf_guard(
        peer_id: PeerId,
        role: SmRole,
        stage: &'static str,
        fut: impl core::future::Future<Output = Result<(), SMError>>,
    ) -> Result<(), SmExecutorError> {
        match AssertUnwindSafe(fut).catch_unwind().await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(SmExecutorError::Stf {
                peer_id,
                role,
                source,
            }),
            Err(_) => Err(SmExecutorError::StfPanic {
                peer_id,
                role,
                stage,
            }),
        }
    }

    fn fatal_net_recv_error(err: &RecvError) -> Option<SmExecutorError> {
        if matches!(err, RecvError::Closed) {
            Some(SmExecutorError::NetRecv(RecvError::Closed))
        } else {
            None
        }
    }

    fn is_fatal_processing_error(err: &SmExecutorError) -> bool {
        matches!(err, SmExecutorError::JobSubmission { .. })
    }
}

fn msg_kind(msg: &Msg) -> &'static str {
    match msg {
        Msg::CommitHeader(_) => "CommitHeader",
        Msg::CommitChunk(_) => "CommitChunk",
        Msg::Challenge(_) => "Challenge",
        Msg::ChallengeResponseHeader(_) => "ChallengeResponseHeader",
        Msg::ChallengeResponseChunk(_) => "ChallengeResponseChunk",
        Msg::AdaptorChunk(_) => "AdaptorChunk",
    }
}

fn completion_role(completion: &ActionCompletion) -> SmRole {
    if completion.is_garbler() {
        SmRole::Garbler
    } else {
        SmRole::Evaluator
    }
}

fn garbler_input_kind(input: &garbler::Input) -> &'static str {
    match input {
        garbler::Input::Init(_) => "Init",
        garbler::Input::RecvChallengeMsg(_) => "RecvChallengeMsg",
        garbler::Input::DepositInit(_, _) => "DepositInit",
        garbler::Input::DepositRecvAdaptorMsgChunk(_, _) => "DepositRecvAdaptorMsgChunk",
        garbler::Input::DepositUndisputedWithdrawal(_) => "DepositUndisputedWithdrawal",
        garbler::Input::DisputedWithdrawal(_, _) => "DisputedWithdrawal",
        _ => "Unknown",
    }
}

fn evaluator_input_kind(input: &evaluator::Input) -> &'static str {
    match input {
        evaluator::Input::Init(_) => "Init",
        evaluator::Input::RecvCommitMsgHeader(_) => "RecvCommitMsgHeader",
        evaluator::Input::RecvCommitMsgChunk(_) => "RecvCommitMsgChunk",
        evaluator::Input::RecvChallengeResponseMsgHeader(_) => "RecvChallengeResponseMsgHeader",
        evaluator::Input::RecvChallengeResponseMsgChunk(_) => "RecvChallengeResponseMsgChunk",
        evaluator::Input::DepositInit(_, _) => "DepositInit",
        evaluator::Input::DepositUndisputedWithdrawal(_) => "DepositUndisputedWithdrawal",
        evaluator::Input::DisputedWithdrawal(_, _) => "DisputedWithdrawal",
        _ => "Unknown",
    }
}

fn command_kind(kind: &SmCommandKind) -> &'static str {
    match kind {
        SmCommandKind::Init(_) => "Init",
        SmCommandKind::DepositInit { .. } => "DepositInit",
        SmCommandKind::DisputedWithdrawal { .. } => "DisputedWithdrawal",
        SmCommandKind::UndisputedWithdrawal { .. } => "UndisputedWithdrawal",
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, sync::Arc};

    use ark_serialize::{CanonicalSerialize, Compress, SerializationError};
    use ed25519_dalek::SigningKey;
    use mosaic_cac_types::state_machine::evaluator::StateRead as EvaluatorStateRead;
    use mosaic_cac_types::state_machine::garbler::StateMut as GarblerStateMut;
    use mosaic_cac_types::{
        ChallengeIndices, ChallengeMsg, HeapArray, Index, Msg,
        state_machine::evaluator::{self, EvaluatorInitData},
    };
    use mosaic_job_api::{JobBatch, JobCompletion, JobSchedulerHandle};
    use mosaic_net_client::NetClient;
    use mosaic_net_svc_api::{
        NetServiceConfig, NetServiceHandle, PeerId, Stream, StreamClosed, api::NetCommand,
        api::StreamRequest,
    };
    use mosaic_sm_executor_api::{InitData, SmTarget};
    use mosaic_storage_api::{Commit, StorageProvider, StorageProviderMut};
    use mosaic_storage_inmemory::{
        InMemoryStorageProvider, evaluator::StoredEvaluatorState, garbler::StoredGarblerState,
    };

    use super::*;

    #[derive(Debug, Default, Clone, Copy)]
    struct TestStorage;

    impl StorageProviderMut for TestStorage {
        type GarblerState = StoredGarblerState;
        type EvaluatorState = StoredEvaluatorState;

        fn garbler_state_mut(&self, _peer_id: &PeerId) -> Self::GarblerState {
            StoredGarblerState::default()
        }

        fn evaluator_state_mut(&self, _peer_id: &PeerId) -> Self::EvaluatorState {
            StoredEvaluatorState::default()
        }
    }

    fn run_monoio<F>(future: F)
    where
        F: Future<Output = ()> + 'static,
    {
        monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
            .build()
            .expect("build monoio runtime")
            .block_on(future);
    }

    fn make_job_handle() -> (
        JobSchedulerHandle,
        kanal::AsyncReceiver<JobBatch>,
        kanal::AsyncSender<JobCompletion>,
    ) {
        let (submit_tx, submit_rx) = kanal::bounded_async::<JobBatch>(8);
        let (completion_tx, completion_rx) = kanal::bounded_async::<JobCompletion>(8);
        (
            JobSchedulerHandle::new(submit_tx, completion_rx),
            submit_rx,
            completion_tx,
        )
    }

    fn make_net_client() -> (NetClient, kanal::AsyncSender<Stream>) {
        let config = Arc::new(NetServiceConfig::new(
            SigningKey::from_bytes(&[1; 32]),
            "127.0.0.1:0".parse().expect("parse socket addr"),
            Vec::new(),
        ));
        let (command_tx, _command_rx) = kanal::bounded_async::<NetCommand>(8);
        let (protocol_tx, protocol_rx) = kanal::bounded_async::<Stream>(8);
        let handle = NetServiceHandle::new(config, command_tx, protocol_rx);
        (NetClient::new(handle), protocol_tx)
    }

    fn sample_evaluator_init() -> EvaluatorInitData {
        EvaluatorInitData {
            seed: [2; 32].into(),
            setup_inputs: [0; 32],
        }
    }

    fn stream_with_message(
        peer_id: PeerId,
        msg: Msg,
    ) -> (Stream, kanal::AsyncReceiver<StreamRequest>) {
        let mut bytes = Vec::new();
        msg.serialize_with_mode(&mut bytes, Compress::No)
            .expect("serialize protocol msg");

        let (payload_tx, payload_rx) = kanal::bounded_async::<Vec<u8>>(1);
        payload_tx
            .to_sync()
            .send(bytes)
            .expect("queue protocol payload");

        let (request_tx, request_rx) = kanal::bounded_async::<StreamRequest>(8);
        let (_buf_return_tx, buf_return_rx) = kanal::bounded_async::<Vec<u8>>(1);
        let (_close_tx, close_rx) = kanal::bounded_async::<StreamClosed>(1);

        (
            Stream::new(peer_id, payload_rx, request_tx, buf_return_rx, close_rx),
            request_rx,
        )
    }

    #[test]
    fn command_role_payload_mismatch_fails_closed() {
        run_monoio(async {
            let (job_handle, _submit_rx, _completion_tx) = make_job_handle();
            let (net_client, _protocol_tx) = make_net_client();
            let (executor, _handle) = SmExecutor::new(
                SmExecutorConfig::default(),
                TestStorage,
                job_handle,
                net_client,
            );

            let peer_id = PeerId::from([9; 32]);
            let cmd = SmCommand {
                target: SmTarget {
                    peer_id,
                    role: SmRole::Garbler,
                },
                kind: SmCommandKind::Init(InitData::Evaluator(sample_evaluator_init())),
            };

            let err = executor
                .handle_command(cmd)
                .await
                .expect_err("role mismatch must be rejected");
            assert!(matches!(err, SmExecutorError::RoleMismatch(_)));
        });
    }

    #[test]
    fn net_recv_error_policy_is_fail_closed() {
        let peer_id = PeerId::from([3; 32]);

        let fatal = SmExecutor::<TestStorage>::fatal_net_recv_error(&RecvError::Closed);
        assert!(matches!(
            fatal,
            Some(SmExecutorError::NetRecv(RecvError::Closed))
        ));

        let non_fatal_read = SmExecutor::<TestStorage>::fatal_net_recv_error(&RecvError::Read {
            peer_id,
            source: StreamClosed::PeerFinished,
        });
        assert!(non_fatal_read.is_none());

        let non_fatal_deser =
            SmExecutor::<TestStorage>::fatal_net_recv_error(&RecvError::Deserialize {
                peer_id,
                error: SerializationError::InvalidData,
            });
        assert!(non_fatal_deser.is_none());
    }

    #[test]
    fn processing_error_policy_is_fail_closed_for_job_submission() {
        let peer_id = PeerId::from([4; 32]);
        let fatal =
            SmExecutor::<TestStorage>::is_fatal_processing_error(&SmExecutorError::JobSubmission {
                peer_id,
                source: mosaic_job_api::SchedulerStopped,
            });
        assert!(fatal, "job submission failures must stop the executor");

        let non_fatal = SmExecutor::<TestStorage>::is_fatal_processing_error(
            &SmExecutorError::RoleMismatch("mismatch"),
        );
        assert!(!non_fatal);
    }

    #[test]
    fn inbound_stf_failure_does_not_send_ack() {
        run_monoio(async {
            let (job_handle, _submit_rx, _completion_tx) = make_job_handle();
            let (net_client, protocol_tx) = make_net_client();
            let (executor, _handle) = SmExecutor::new(
                SmExecutorConfig::default(),
                TestStorage,
                job_handle,
                net_client.clone(),
            );

            let peer_id = PeerId::from([5; 32]);
            let challenge_msg = ChallengeMsg {
                challenge_indices: ChallengeIndices::new(|i| {
                    Index::new(i + 1).expect("valid challenge index")
                }),
            };
            let (stream, request_rx) = stream_with_message(peer_id, Msg::Challenge(challenge_msg));
            protocol_tx
                .send(stream)
                .await
                .expect("send inbound stream to net client");

            let inbound = net_client.recv().await.expect("decode inbound request");
            let err = executor
                .handle_inbound_request(inbound)
                .await
                .expect_err("challenge should fail without initialization");
            assert!(matches!(err, SmExecutorError::Stf { .. }));

            let mut ack_writes = 0usize;
            while let Ok(Some(_)) = request_rx.try_recv() {
                ack_writes += 1;
            }
            assert_eq!(ack_writes, 0, "unexpected ACK writes after STF failure");
        });
    }

    #[test]
    fn command_success_submits_and_commits() {
        run_monoio(async {
            let provider = InMemoryStorageProvider::new();
            let peer_id = PeerId::from([8; 32]);

            let (job_handle, submit_rx, _completion_tx) = make_job_handle();
            let (net_client, _protocol_tx) = make_net_client();
            let (executor, _handle) = SmExecutor::new(
                SmExecutorConfig::default(),
                provider.clone(),
                job_handle,
                net_client,
            );

            let cmd = SmCommand::init_evaluator(
                peer_id,
                evaluator::EvaluatorInitData {
                    seed: [6; 32].into(),
                    setup_inputs: [0; 32],
                },
            );
            executor
                .handle_command(cmd)
                .await
                .expect("init command should be accepted");

            let submitted = submit_rx.recv().await.expect("job batch submitted");
            assert_eq!(submitted.peer_id, peer_id);
            assert!(submitted.actions.is_evaluator());

            let committed = provider
                .evaluator_state(&peer_id)
                .get_root_state()
                .await
                .expect("read committed evaluator state")
                .expect("evaluator state should exist");
            assert!(
                !matches!(committed.step, evaluator::Step::Uninit),
                "state should advance past Uninit after Init command"
            );
        });
    }

    #[test]
    fn restore_known_peers_submits_both_roles() {
        run_monoio(async {
            let provider = InMemoryStorageProvider::new();
            let peer_id = PeerId::from([11; 32]);

            let (job_handle, submit_rx, _completion_tx) = make_job_handle();
            let (net_client, _protocol_tx) = make_net_client();
            let config = SmExecutorConfig {
                command_queue_size: 8,
                known_peers: vec![peer_id],
            };
            let (executor, _handle) = SmExecutor::new(config, provider, job_handle, net_client);

            executor
                .restore_known_peers()
                .await
                .expect("restore should succeed");

            let first = submit_rx.recv().await.expect("first restore batch");
            let second = submit_rx.recv().await.expect("second restore batch");
            assert_eq!(first.peer_id, peer_id);
            assert_eq!(second.peer_id, peer_id);

            let saw_garbler = first.actions.is_garbler() || second.actions.is_garbler();
            let saw_evaluator = first.actions.is_evaluator() || second.actions.is_evaluator();
            assert!(saw_garbler, "restore must submit garbler batch");
            assert!(saw_evaluator, "restore must submit evaluator batch");
        });
    }

    #[test]
    fn restore_peer_continues_with_evaluator_when_garbler_restore_fails() {
        run_monoio(async {
            let provider = InMemoryStorageProvider::new();
            let peer_id = PeerId::from([12; 32]);

            {
                let mut garbler_state = provider.garbler_state_mut(&peer_id);
                garbler_state
                    .put_root_state(&garbler::GarblerState {
                        config: None,
                        // Missing commit artifacts on purpose to force garbler restore failure.
                        step: garbler::Step::SendingCommit {
                            header_acked: false,
                            acked: HeapArray::from_elem(false),
                            all_aes128_keys: HeapArray::from_elem([0; 16]),
                            all_public_s: HeapArray::from_elem([0; 16]),
                            all_constant_zero_labels: HeapArray::from_elem([0; 16]),
                            all_constant_one_labels: HeapArray::from_elem([0; 16]),
                        },
                    })
                    .await
                    .expect("write garbler root state");
                garbler_state.commit().await.expect("commit garbler state");
            }

            let (job_handle, submit_rx, _completion_tx) = make_job_handle();
            let (net_client, _protocol_tx) = make_net_client();
            let config = SmExecutorConfig {
                command_queue_size: 8,
                known_peers: vec![peer_id],
            };
            let (executor, _handle) = SmExecutor::new(config, provider, job_handle, net_client);

            executor
                .restore_known_peers()
                .await
                .expect("restore pass should continue despite one role failing");

            let submitted = submit_rx
                .recv()
                .await
                .expect("evaluator restore batch should still be submitted");
            assert_eq!(submitted.peer_id, peer_id);
            assert!(
                submitted.actions.is_evaluator(),
                "evaluator restore should still run for the peer"
            );
            assert!(
                !matches!(submit_rx.try_recv(), Ok(Some(_))),
                "garbler restore should not submit a batch when STF restore fails"
            );
        });
    }
}
