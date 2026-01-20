use std::sync::Arc;

use fasm::{Input as FasmInput, StateMachine};
use mosaic_cac_protocol::{
    SMResult,
    garbler::{GarblerSM, artifact::GarblerArtifactStore, state::State},
};
use mosaic_cac_types::{
    AllPolynomialCommitments, AllPolynomials, InputShares, OutputShares,
    state_machine::{
        StateMachineId,
        garbler::{ActionContainer, GarblerInitData, Input},
    },
};

use crate::{Db, ExecutorError, ExecutorResult};

pub(crate) async fn handle_garbler_input<D: Db>(
    sm_id: StateMachineId,
    input: Input,
    db: Arc<D>,
) -> ExecutorResult<ActionContainer> {
    let mut state = load_garbler_state(sm_id, db.clone()).await?;

    let mut actions = vec![];

    GarblerSM::<GarblerArtifactStoreImpl<D>>::stf(
        &mut state,
        FasmInput::Normal(input),
        &mut actions,
    )
    .await
    .map_err(|err| ExecutorError::StateMachine(Box::new(err)))?;

    save_garbler_state(sm_id, &state, db).await?;

    Ok(actions)
}

pub(crate) async fn handle_garbler_restore<D: Db>(
    sm_id: StateMachineId,
    db: Arc<D>,
) -> ExecutorResult<ActionContainer> {
    let state = load_garbler_state(sm_id, db.clone()).await?;

    let mut actions = vec![];

    GarblerSM::<GarblerArtifactStoreImpl<D>>::restore(&state, &mut actions)
        .await
        .map_err(|err| ExecutorError::StateMachine(Box::new(err)))?;

    Ok(actions)
}

pub(crate) async fn handle_garbler_init<D: Db>(
    sm_id: StateMachineId,
    init_data: GarblerInitData,
    db: Arc<D>,
) -> ExecutorResult<ActionContainer> {
    let mut state = init_garbler_state(sm_id, db.clone());

    let mut actions = vec![];
    let input = FasmInput::Normal(Input::Init(init_data));

    GarblerSM::<GarblerArtifactStoreImpl<D>>::stf(&mut state, input, &mut actions)
        .await
        .map_err(|err| ExecutorError::StateMachine(Box::new(err)))?;

    Ok(actions)
}

fn init_garbler_state<D: Db>(
    sm_id: StateMachineId,
    db: Arc<D>,
) -> State<GarblerArtifactStoreImpl<D>> {
    let artifact_store = GarblerArtifactStoreImpl {
        sm_id,
        saved: Default::default(),
        db,
    };
    State::new_empty(artifact_store)
}

#[expect(unused_variables)]
async fn load_garbler_state<D: Db>(
    sm_id: StateMachineId,
    db: Arc<D>,
) -> ExecutorResult<State<GarblerArtifactStoreImpl<D>>> {
    todo!()
}

#[expect(unused_variables)]
async fn save_garbler_state<D: Db>(
    sm_id: StateMachineId,
    state: &State<GarblerArtifactStoreImpl<D>>,
    db: Arc<D>,
) -> ExecutorResult<()> {
    todo!()
}

#[derive(Debug, Default)]
#[expect(dead_code)]
struct SaveCache {
    polynomials: Option<Box<AllPolynomials>>,
    polynomial_commitments: Option<Box<AllPolynomialCommitments>>,
    input_shares: Option<Box<InputShares>>,
    output_shares: Option<Box<OutputShares>>,
    // TODO:
}

#[derive(Debug)]
#[expect(dead_code)]
pub(crate) struct GarblerArtifactStoreImpl<D: Db> {
    sm_id: StateMachineId,
    saved: SaveCache,
    db: Arc<D>,
}

#[expect(unused_variables)]
impl<D: Db> GarblerArtifactStore for GarblerArtifactStoreImpl<D> {
    async fn save_polynomials(&mut self, polynomials: &AllPolynomials) -> SMResult<()> {
        todo!()
    }

    async fn load_polynomials(&self) -> SMResult<Box<AllPolynomials>> {
        todo!()
    }

    async fn save_polynomial_commitments(
        &mut self,
        commitments: &AllPolynomialCommitments,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_polynomial_commitments(&self) -> SMResult<Box<AllPolynomialCommitments>> {
        todo!()
    }

    async fn save_shares(
        &mut self,
        input_shares: &InputShares,
        output_shares: &OutputShares,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_shares(&self) -> SMResult<(Box<InputShares>, Box<OutputShares>)> {
        todo!()
    }

    async fn load_reserved_input_shares(
        &self,
    ) -> SMResult<Box<mosaic_cac_types::ReservedInputShares>> {
        todo!()
    }

    async fn save_garbling_table_commitments(
        &mut self,
        commitments: &mosaic_cac_types::AllGarblingTableCommitments,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_garbling_table_commitments(
        &self,
    ) -> SMResult<Box<mosaic_cac_types::AllGarblingTableCommitments>> {
        todo!()
    }

    async fn save_challenge_indices(
        &mut self,
        challenge_idxs: &mosaic_cac_types::ChallengeIndices,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_challenge_indices(&self) -> SMResult<Box<mosaic_cac_types::ChallengeIndices>> {
        todo!()
    }

    async fn save_sighashes_for_deposit(
        &mut self,
        deposit_id: mosaic_cac_types::DepositId,
        sighashes: &mosaic_cac_types::Sighashes,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_sighashes_for_deposit(
        &self,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> SMResult<Box<mosaic_cac_types::Sighashes>> {
        todo!()
    }

    async fn save_inputs_for_deposit(
        &mut self,
        deposit_id: mosaic_cac_types::DepositId,
        inputs: &mosaic_cac_types::DepositInputs,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_inputs_for_deposit(
        &self,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> SMResult<Box<mosaic_cac_types::DepositInputs>> {
        todo!()
    }

    async fn save_adaptors_for_deposit(
        &mut self,
        deposit_id: mosaic_cac_types::DepositId,
        deposit_adaptors: &mosaic_cac_types::DepositAdaptors,
        withdrawal_adaptors: &mosaic_cac_types::WithdrawalAdaptors,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_adaptors_for_deposit(
        &self,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> SMResult<(
        Box<mosaic_cac_types::DepositAdaptors>,
        Box<mosaic_cac_types::WithdrawalAdaptors>,
    )> {
        todo!()
    }

    async fn save_withdrawal_input(
        &mut self,
        deposit_id: mosaic_cac_types::DepositId,
        withdrawal_input: &mosaic_cac_types::WithdrawalInputs,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_withdrawal_input(
        &self,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> SMResult<Box<mosaic_cac_types::WithdrawalInputs>> {
        todo!()
    }

    async fn save_completed_signatures(
        &mut self,
        deposit_id: mosaic_cac_types::DepositId,
        signatures: &mosaic_cac_types::CompletedSignatures,
    ) -> SMResult<()> {
        todo!()
    }

    async fn load_completed_signatures(
        &self,
        deposit_id: mosaic_cac_types::DepositId,
    ) -> SMResult<Box<mosaic_cac_types::CompletedSignatures>> {
        todo!()
    }
}
