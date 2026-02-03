use std::sync::Arc;

use fasm::{Input as FasmInput, StateMachine};
use mosaic_cac_protocol::{
    SMResult,
    evaluator::{EvaluatorSM, artifact::EvaluatorArtifactStore, state::State as EvaluatorState},
};
use mosaic_cac_types::{
    AllGarblingTableCommitments, AllPolynomialCommitments, ChallengeIndices,
    ChallengeResponseMsgChunk, CommitMsgChunk, CompletedSignatures, DepositAdaptors, DepositId,
    DepositInputs, InputPolynomialCommitments, OpenedGarblingSeeds, OpenedInputShares,
    OpenedOutputShares, OutputPolynomialCommitment, ReservedSetupInputShares, Sighashes,
    WithdrawalAdaptors, WithdrawalInputs,
    state_machine::evaluator::{ActionContainer, EvaluatorInitData, Input},
};

use crate::{Db, ExecutorError, ExecutorResult, StateMachineId};

pub(crate) async fn handle_evaluator_input<D: Db>(
    sm_id: StateMachineId,
    input: Input,
    db: Arc<D>,
) -> ExecutorResult<ActionContainer> {
    let mut state = load_evaluator_state(sm_id, db.clone()).await?;

    let mut actions = vec![];

    EvaluatorSM::<EvaluatorArtifactStoreImpl<D>>::stf(
        &mut state,
        FasmInput::Normal(input),
        &mut actions,
    )
    .await
    .map_err(|err| ExecutorError::StateMachine(Box::new(err)))?;

    save_evaluator_state(db.as_ref(), &state).await?;

    Ok(actions)
}

#[expect(unused_variables)]
pub(crate) async fn handle_evaluator_init<D: Db>(
    sm_id: StateMachineId,
    init_data: EvaluatorInitData,
    db: Arc<D>,
) -> ExecutorResult<ActionContainer> {
    unimplemented!()
}

#[expect(unused_variables)]
pub(crate) async fn handle_evaluator_restore<D: Db>(
    sm_id: StateMachineId,
    db: Arc<D>,
) -> ExecutorResult<ActionContainer> {
    unimplemented!()
}

#[derive(Debug, Default)]
struct SaveCache {}

#[derive(Debug)]
#[expect(dead_code)]
pub(crate) struct EvaluatorArtifactStoreImpl<D: Db> {
    sm_id: StateMachineId,
    saved: SaveCache,
    db: Arc<D>,
}

#[expect(unused_variables)]
impl<D: Db> EvaluatorArtifactStore for EvaluatorArtifactStoreImpl<D> {
    async fn save_polynomial_commitments(
        &mut self,
        commitments: &AllPolynomialCommitments,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_polynomial_commitments(&self) -> SMResult<AllPolynomialCommitments> {
        todo!()
    }

    async fn load_input_polynomial_commitments(&self) -> SMResult<Box<InputPolynomialCommitments>> {
        todo!()
    }

    async fn load_output_polynomial_commitment(&self) -> SMResult<Box<OutputPolynomialCommitment>> {
        todo!()
    }

    async fn save_garbling_table_commitments(
        &mut self,
        commitments: &AllGarblingTableCommitments,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_garbling_table_commitments(&self) -> SMResult<Box<AllGarblingTableCommitments>> {
        todo!()
    }

    async fn save_commit_msg_chunk(&mut self, chunk: CommitMsgChunk) -> SMResult<()> {
        todo!()
    }

    async fn save_challenge_response_msg_chunk(
        &mut self,
        chunk: ChallengeResponseMsgChunk,
    ) -> SMResult<()> {
        todo!()
    }

    async fn save_challenge_indices(&mut self, challenge_idxs: &ChallengeIndices) -> SMResult<()> {
        todo!()
    }

    async fn load_challenge_indices(&self) -> SMResult<Box<ChallengeIndices>> {
        todo!()
    }

    async fn save_openend_input_shares(
        &mut self,
        opened_input_shares: &OpenedInputShares,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_openend_input_shares(&self) -> SMResult<Box<OpenedInputShares>> {
        todo!()
    }

    async fn save_reserved_setup_input_shares(
        &mut self,
        reserved_setup_input_shares: &ReservedSetupInputShares,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_reserved_setup_input_shares(&self) -> SMResult<Box<ReservedSetupInputShares>> {
        todo!()
    }

    async fn save_opened_output_shares(
        &mut self,
        opened_output_shares: &OpenedOutputShares,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_opened_output_shares(&self) -> SMResult<Box<OpenedOutputShares>> {
        todo!()
    }

    async fn save_opened_garbling_seeds(
        &mut self,
        opened_garbling_seeds: &OpenedGarblingSeeds,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_opened_garbling_seeds(&self) -> SMResult<Box<OpenedGarblingSeeds>> {
        todo!()
    }

    async fn save_sighashes_for_deposit(
        &mut self,
        deposit_id: DepositId,
        sighashes: &Sighashes,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_sighashes_for_deposit(&self, deposit_id: DepositId) -> SMResult<Box<Sighashes>> {
        todo!()
    }

    async fn save_inputs_for_deposit(
        &mut self,
        deposit_id: DepositId,
        inputs: &DepositInputs,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_inputs_for_deposit(&self, deposit_id: DepositId) -> SMResult<Box<DepositInputs>> {
        todo!()
    }

    async fn save_adaptors_for_deposit(
        &mut self,
        deposit_id: DepositId,
        deposit_adaptors: &DepositAdaptors,
        withdrawal_adaptors: &WithdrawalAdaptors,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_adaptors_for_deposit(
        &self,
        deposit_id: DepositId,
    ) -> SMResult<(Box<DepositAdaptors>, Box<WithdrawalAdaptors>)> {
        todo!()
    }

    async fn save_withdrawal_inputs(
        &mut self,
        deposit_id: DepositId,
        withdrawal_input: &WithdrawalInputs,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_withdrawal_inputs(
        &self,
        deposit_id: DepositId,
    ) -> SMResult<Box<WithdrawalInputs>> {
        todo!()
    }

    async fn save_completed_signatures(
        &mut self,
        deposit_id: DepositId,
        signatures: &CompletedSignatures,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_completed_signatures(
        &self,
        deposit_id: DepositId,
    ) -> SMResult<Box<CompletedSignatures>> {
        todo!()
    }
}

#[expect(unused_variables)]
async fn load_evaluator_state<D: Db>(
    sm_id: StateMachineId,
    db: Arc<D>,
) -> ExecutorResult<EvaluatorState<EvaluatorArtifactStoreImpl<D>>> {
    let artifact_store = EvaluatorArtifactStoreImpl {
        sm_id,
        saved: SaveCache::default(),
        db: db.clone(),
    };

    unimplemented!()
}

#[expect(unused_variables)]
async fn save_evaluator_state<D: Db, S: EvaluatorArtifactStore>(
    db: &D,
    state: &EvaluatorState<S>,
) -> ExecutorResult<()> {
    unimplemented!()
}
