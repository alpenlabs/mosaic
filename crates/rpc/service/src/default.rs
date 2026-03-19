//! Default [`MosaicApi`] implementation backed by storage and a state machine
//! executor channel.

use async_trait::async_trait;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use futures::TryStreamExt as _;
use kanal::AsyncSender;
use mosaic_cac_protocol::derive_stage_seed;
use mosaic_cac_types::{
    CompletedSignatures, DepositId, PubKey, SecretKey, Seed, WithdrawalInputs,
    state_machine::{
        Role, StateMachineExecutorInput, StateMachineId, StateMachineInput,
        evaluator::{
            self, EvaluatorDepositInitData, EvaluatorDisputedWithdrawalData, EvaluatorInitData,
            StateRead as _,
        },
        garbler::{self, GarblerDepositInitData, GarblerInitData, StateRead as _},
    },
};
use mosaic_common::Byte32;
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;
use mosaic_vs3::Index;
use parking_lot::Mutex;
use rand::{CryptoRng, Rng, SeedableRng};
use tracing::error;

use crate::{
    DepositStatus, DepositWithStatus, EvaluatorDepositInit, EvaluatorWithdrawalData,
    GarblerDepositInit, MosaicApi, ServiceError, ServiceResult, SetupConfig, TablesetStatus,
    schnorr_signer::SchnorrSigner,
};

/// Default [`MosaicApi`] implementation.
///
/// Backed by a [`StorageProvider`] for persistence and a channel to the state
/// machine executor for dispatching inputs.
#[derive(Debug)]
pub struct DefaultMosaicApi<S: StorageProvider, R: CryptoRng + Rng + Send> {
    own_peer_id: PeerId,
    other_peer_ids: Vec<PeerId>,
    executor_tx: AsyncSender<StateMachineExecutorInput>,
    storage: S,
    rng: Mutex<R>,
}

impl<S: StorageProvider, R: CryptoRng + Rng + Send> DefaultMosaicApi<S, R> {
    /// Creates a new instance.
    pub fn new(
        own_peer_id: PeerId,
        other_peer_ids: Vec<PeerId>,
        executor_tx: AsyncSender<StateMachineExecutorInput>,
        storage: S,
        rng: R,
    ) -> Self {
        Self {
            own_peer_id,
            other_peer_ids,
            executor_tx,
            storage,
            rng: Mutex::new(rng),
        }
    }

    fn generate_seed(&self) -> Seed {
        Seed::rand(&mut *self.rng.lock())
    }

    async fn dispatch(&self, sm_id: StateMachineId, input: StateMachineInput) -> ServiceResult<()> {
        self.executor_tx
            .send(StateMachineExecutorInput::new(sm_id, input))
            .await
            .map_err(ServiceError::executor)
    }

    async fn garbler_state(&self, peer_id: &PeerId) -> ServiceResult<S::GarblerState> {
        self.storage
            .garbler_state(peer_id)
            .await
            .map_err(ServiceError::storage)
    }

    async fn evaluator_state(&self, peer_id: &PeerId) -> ServiceResult<S::EvaluatorState> {
        self.storage
            .evaluator_state(peer_id)
            .await
            .map_err(ServiceError::storage)
    }
}

#[async_trait]
impl<S: StorageProvider, R: CryptoRng + Rng + Send + 'static> MosaicApi for DefaultMosaicApi<S, R> {
    fn get_peer_id(&self) -> PeerId {
        self.own_peer_id
    }

    fn get_tableset_id(&self, role: Role, peer_id: &PeerId, _instance: &Byte32) -> StateMachineId {
        match role {
            Role::Garbler => StateMachineId::garbler(*peer_id),
            Role::Evaluator => StateMachineId::evaluator(*peer_id),
        }
    }

    async fn list_tableset_ids(&self) -> ServiceResult<Vec<StateMachineId>> {
        let mut ids = Vec::new();

        // TODO: concurrent db reads
        for peer_id in self.other_peer_ids.iter() {
            let garbler_id = StateMachineId::garbler(*peer_id);
            if self
                .garbler_state(peer_id)
                .await?
                .get_root_state()
                .await
                .map_err(ServiceError::storage)?
                .is_some()
            {
                ids.push(garbler_id);
            }

            let evaluator_id = StateMachineId::evaluator(*peer_id);
            if self
                .evaluator_state(peer_id)
                .await?
                .get_root_state()
                .await
                .map_err(ServiceError::storage)?
                .is_some()
            {
                ids.push(evaluator_id);
            }
        }

        Ok(ids)
    }

    async fn setup_tableset(&self, config: SetupConfig) -> ServiceResult<StateMachineId> {
        let (statemachine_id, input) = match config.role {
            Role::Garbler => {
                let statemachine_id = StateMachineId::garbler(config.peer_id);
                if self
                    .garbler_state(statemachine_id.peer_id())
                    .await?
                    .get_root_state()
                    .await
                    .map_err(ServiceError::storage)?
                    .is_some()
                {
                    return Ok(statemachine_id);
                }
                let input = StateMachineInput::Garbler(garbler::Input::Init(GarblerInitData {
                    seed: self.generate_seed(),
                    setup_inputs: config.setup_inputs,
                }));
                (statemachine_id, input)
            }
            Role::Evaluator => {
                let statemachine_id = StateMachineId::evaluator(config.peer_id);
                if self
                    .evaluator_state(statemachine_id.peer_id())
                    .await?
                    .get_root_state()
                    .await
                    .map_err(ServiceError::storage)?
                    .is_some()
                {
                    return Ok(statemachine_id);
                }
                let input =
                    StateMachineInput::Evaluator(evaluator::Input::Init(EvaluatorInitData {
                        seed: self.generate_seed(),
                        setup_inputs: config.setup_inputs,
                    }));
                (statemachine_id, input)
            }
        };

        self.dispatch(statemachine_id, input).await?;
        Ok(statemachine_id)
    }

    async fn get_tableset_status(&self, sm_id: &StateMachineId) -> ServiceResult<TablesetStatus> {
        match sm_id.role() {
            Role::Garbler => {
                let state = self
                    .storage
                    .garbler_state(sm_id.peer_id())
                    .await
                    .map_err(ServiceError::storage)?
                    .get_root_state()
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

                if state.step == garbler::Step::Uninit {
                    return Err(ServiceError::UnexpectedState("Uninit".into()));
                }
                Ok(TablesetStatus::from(&state.step))
            }
            Role::Evaluator => {
                let state = self
                    .storage
                    .evaluator_state(sm_id.peer_id())
                    .await
                    .map_err(ServiceError::storage)?
                    .get_root_state()
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

                if state.step == evaluator::Step::Uninit {
                    return Err(ServiceError::UnexpectedState("Uninit".into()));
                }
                Ok(TablesetStatus::from(&state.step))
            }
        }
    }

    async fn get_fault_secret_pubkey(
        &self,
        sm_id: &StateMachineId,
    ) -> ServiceResult<Option<PubKey>> {
        let output_commitment = match sm_id.role() {
            Role::Garbler => self
                .storage
                .garbler_state(sm_id.peer_id())
                .await
                .map_err(ServiceError::storage)?
                .get_output_polynomial_commitment()
                .await
                .map_err(ServiceError::storage)?,
            Role::Evaluator => self
                .storage
                .evaluator_state(sm_id.peer_id())
                .await
                .map_err(ServiceError::storage)?
                .get_output_polynomial_commitment()
                .await
                .map_err(ServiceError::storage)?,
        };

        let Some(output_commitment) = output_commitment else {
            return Ok(None);
        };

        let reserve_output_share_commit = output_commitment[0].eval(Index::reserved());
        Ok(Some(PubKey(reserve_output_share_commit.point())))
    }

    async fn get_adaptor_pubkey(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
    ) -> ServiceResult<Option<PubKey>> {
        self.generate_adaptor_keypair_deterministic(sm_id, deposit_id)
            .await
            .map(|r| r.map(|(_, pk)| pk))
    }

    async fn init_garbler_deposit(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        init: GarblerDepositInit,
    ) -> ServiceResult<()> {
        let statemachine = self
            .garbler_state(sm_id.peer_id())
            .await?
            .get_root_state()
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

        if statemachine.step != garbler::Step::SetupComplete {
            return Err(ServiceError::InvalidInputForState(
                statemachine.step.step_name().into(),
            ));
        }

        if self
            .garbler_state(sm_id.peer_id())
            .await?
            .get_deposit(deposit_id)
            .await
            .map_err(ServiceError::storage)?
            .is_some()
        {
            return Err(ServiceError::DuplicateDeposit(*deposit_id));
        }

        let deposit_init_data = GarblerDepositInitData {
            pk: init.adaptor_pk,
            sighashes: init.sighashes,
            deposit_inputs: init.deposit_inputs,
        };

        let input =
            StateMachineInput::Garbler(garbler::Input::DepositInit(*deposit_id, deposit_init_data));
        self.dispatch(*sm_id, input).await
    }

    async fn init_evaluator_deposit(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        init: EvaluatorDepositInit,
    ) -> ServiceResult<()> {
        let statemachine = self
            .evaluator_state(sm_id.peer_id())
            .await?
            .get_root_state()
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

        if statemachine.step != evaluator::Step::SetupComplete {
            return Err(ServiceError::InvalidInputForState(
                statemachine.step.step_name().into(),
            ));
        }

        if self
            .evaluator_state(sm_id.peer_id())
            .await?
            .get_deposit(deposit_id)
            .await
            .map_err(ServiceError::storage)?
            .is_some()
        {
            return Err(ServiceError::DuplicateDeposit(*deposit_id));
        }

        let (sk, _) = self
            .generate_adaptor_keypair_deterministic(sm_id, deposit_id)
            .await?
            .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

        let deposit_init_data = EvaluatorDepositInitData {
            sk,
            sighashes: init.sighashes,
            deposit_inputs: init.deposit_inputs,
        };

        let input = StateMachineInput::Evaluator(evaluator::Input::DepositInit(
            *deposit_id,
            deposit_init_data,
        ));
        self.dispatch(*sm_id, input).await
    }

    async fn list_deposits(&self, sm_id: &StateMachineId) -> ServiceResult<Vec<DepositWithStatus>> {
        match sm_id.role() {
            Role::Garbler => {
                let deposits: Vec<_> = self
                    .garbler_state(sm_id.peer_id())
                    .await?
                    .stream_all_deposits()
                    .try_collect()
                    .await
                    .map_err(ServiceError::storage)?;

                Ok(deposits
                    .into_iter()
                    .map(|(deposit_id, state)| DepositWithStatus {
                        deposit_id,
                        status: DepositStatus::from(state),
                    })
                    .collect())
            }
            Role::Evaluator => {
                let deposits: Vec<_> = self
                    .evaluator_state(sm_id.peer_id())
                    .await?
                    .stream_all_deposits()
                    .try_collect()
                    .await
                    .map_err(ServiceError::storage)?;

                Ok(deposits
                    .into_iter()
                    .map(|(deposit_id, state)| DepositWithStatus {
                        deposit_id,
                        status: DepositStatus::from(state),
                    })
                    .collect())
            }
        }
    }

    async fn get_deposit_status(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
    ) -> ServiceResult<DepositStatus> {
        match sm_id.role() {
            Role::Garbler => {
                let deposit = self
                    .garbler_state(sm_id.peer_id())
                    .await?
                    .get_deposit(deposit_id)
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::DepositNotFound)?;

                Ok(DepositStatus::from(deposit))
            }
            Role::Evaluator => {
                let deposit = self
                    .evaluator_state(sm_id.peer_id())
                    .await?
                    .get_deposit(deposit_id)
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::DepositNotFound)?;

                Ok(DepositStatus::from(deposit))
            }
        }
    }

    async fn mark_deposit_withdrawn(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
    ) -> ServiceResult<()> {
        let input = match sm_id.role() {
            Role::Garbler => {
                let statemachine = self
                    .garbler_state(sm_id.peer_id())
                    .await?
                    .get_root_state()
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

                if statemachine.step != garbler::Step::SetupComplete {
                    return Err(ServiceError::InvalidInputForState(
                        statemachine.step.step_name().into(),
                    ));
                }

                let deposit = self
                    .garbler_state(sm_id.peer_id())
                    .await?
                    .get_deposit(deposit_id)
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::DepositNotFound)?;

                if deposit.step != garbler::DepositStep::DepositReady {
                    return Err(ServiceError::InvalidInputForState(
                        deposit.step.step_name().into(),
                    ));
                }

                StateMachineInput::Garbler(garbler::Input::DepositUndisputedWithdrawal(*deposit_id))
            }
            Role::Evaluator => {
                let statemachine = self
                    .evaluator_state(sm_id.peer_id())
                    .await?
                    .get_root_state()
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

                if statemachine.step != evaluator::Step::SetupComplete {
                    return Err(ServiceError::InvalidInputForState(
                        statemachine.step.step_name().into(),
                    ));
                }

                let deposit = self
                    .evaluator_state(sm_id.peer_id())
                    .await?
                    .get_deposit(deposit_id)
                    .await
                    .map_err(ServiceError::storage)?
                    .ok_or(ServiceError::DepositNotFound)?;

                if deposit.step != evaluator::DepositStep::DepositReady {
                    return Err(ServiceError::InvalidInputForState(
                        deposit.step.step_name().into(),
                    ));
                }

                StateMachineInput::Evaluator(evaluator::Input::DepositUndisputedWithdrawal(
                    *deposit_id,
                ))
            }
        };

        self.dispatch(*sm_id, input).await
    }

    async fn complete_adaptor_sigs(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        withdrawal_inputs: WithdrawalInputs,
    ) -> ServiceResult<()> {
        if sm_id.role() != Role::Garbler {
            return Err(ServiceError::RoleMismatch(
                "complete_adaptor_sigs only valid for garbler".into(),
            ));
        }

        let statemachine = self
            .garbler_state(sm_id.peer_id())
            .await?
            .get_root_state()
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

        if statemachine.step != garbler::Step::SetupComplete {
            return Err(ServiceError::InvalidInputForState(
                statemachine.step.step_name().into(),
            ));
        }

        let deposit = self
            .garbler_state(sm_id.peer_id())
            .await?
            .get_deposit(deposit_id)
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::DepositNotFound)?;

        if deposit.step != garbler::DepositStep::DepositReady {
            return Err(ServiceError::InvalidInputForState(
                deposit.step.step_name().into(),
            ));
        }

        let input = StateMachineInput::Garbler(garbler::Input::DisputedWithdrawal(
            *deposit_id,
            withdrawal_inputs,
        ));

        self.dispatch(*sm_id, input).await
    }

    async fn get_completed_adaptor_sigs(
        &self,
        sm_id: &StateMachineId,
    ) -> ServiceResult<CompletedSignatures> {
        if sm_id.role() != Role::Garbler {
            return Err(ServiceError::RoleMismatch(
                "get_completed_adaptor_sigs only valid for garbler".into(),
            ));
        }

        let statemachine = self
            .garbler_state(sm_id.peer_id())
            .await?
            .get_root_state()
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

        let garbler::Step::SetupConsumed { deposit_id } = statemachine.step else {
            return Err(ServiceError::InvalidInputForState(
                statemachine.step.step_name().into(),
            ));
        };

        self
            .garbler_state(sm_id.peer_id())
            .await?
            .get_completed_signatures(&deposit_id)
            .await
            .map_err(ServiceError::storage)?
            .ok_or_else(|| {
                error!(%sm_id, %deposit_id, "CRITICAL: expected completed adaptor sigs; found none");
                ServiceError::CompletedSigsNotFound
            })
    }

    async fn evaluate_tableset(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
        data: EvaluatorWithdrawalData,
    ) -> ServiceResult<()> {
        if sm_id.role() != Role::Evaluator {
            return Err(ServiceError::RoleMismatch(
                "evaluate_tableset only valid for evaluator".into(),
            ));
        }

        let statemachine = self
            .evaluator_state(sm_id.peer_id())
            .await?
            .get_root_state()
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

        if statemachine.step != evaluator::Step::SetupComplete {
            return Err(ServiceError::InvalidInputForState(
                statemachine.step.step_name().into(),
            ));
        }

        let deposit = self
            .evaluator_state(sm_id.peer_id())
            .await?
            .get_deposit(deposit_id)
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::DepositNotFound)?;

        if deposit.step != evaluator::DepositStep::DepositReady {
            return Err(ServiceError::InvalidInputForState(
                deposit.step.step_name().into(),
            ));
        }

        let withdrawal_data = EvaluatorDisputedWithdrawalData {
            withdrawal_inputs: data.withdrawal_inputs,
            signatures: data.signatures,
        };

        let input = StateMachineInput::Evaluator(evaluator::Input::DisputedWithdrawal(
            *deposit_id,
            withdrawal_data,
        ));

        self.dispatch(*sm_id, input).await
    }

    async fn sign_with_fault_secret(
        &self,
        sm_id: &StateMachineId,
        digest: [u8; 32],
        tweak: Option<[u8; 32]>,
    ) -> ServiceResult<Option<SchnorrSignature>> {
        let statemachine = self
            .evaluator_state(sm_id.peer_id())
            .await?
            .get_root_state()
            .await
            .map_err(ServiceError::storage)?
            .ok_or(ServiceError::StateMachineNotFound(*sm_id))?;

        let evaluator::Step::SetupConsumed { success, .. } = &statemachine.step else {
            return Err(ServiceError::InvalidInputForState(
                statemachine.step.step_name().into(),
            ));
        };

        if !success {
            return Ok(None);
        }

        let fault_secret_share = self
            .evaluator_state(sm_id.peer_id())
            .await?
            .get_fault_secret_share()
            .await
            .map_err(ServiceError::storage)?;

        let Some(fault_secret_share) = fault_secret_share else {
            return Ok(None);
        };

        let signer = SchnorrSigner::from_ark_scalar(&fault_secret_share.value());
        let sig = signer.sign(digest, tweak);
        Ok(Some(sig))
    }
}

// --- Private helpers ---

impl<S: StorageProvider, R: CryptoRng + Rng + Send + 'static> DefaultMosaicApi<S, R> {
    async fn generate_adaptor_keypair_deterministic(
        &self,
        sm_id: &StateMachineId,
        deposit_id: &DepositId,
    ) -> ServiceResult<Option<(SecretKey, PubKey)>> {
        let Some(seed) = self
            .evaluator_state(sm_id.peer_id())
            .await?
            .get_root_state()
            .await
            .map_err(ServiceError::storage)?
            .and_then(|x| x.config.map(|y| y.seed))
        else {
            return Ok(None);
        };

        Ok(Some(derive_deposit_keypair(seed, deposit_id)))
    }
}

fn derive_deposit_keypair(base_seed: Seed, deposit_id: &DepositId) -> (SecretKey, PubKey) {
    let stage = format!("deposit:{}", deposit_id.0.to_hex());
    let seed = derive_stage_seed(base_seed, &stage);

    let mut rng = rand_chacha::ChaChaRng::from_seed(seed.to_bytes());
    let sk = SecretKey::rand(&mut rng);
    let pk = sk.to_pubkey();

    (sk, pk)
}
