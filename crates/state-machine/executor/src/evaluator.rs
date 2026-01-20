use std::sync::Arc;

use fasm::{Input as FasmInput, StateMachine};
use mosaic_cac_protocol::evaluator::{
    EvaluatorSM, artifact::EvaluatorArtifactStore, state::State as EvaluatorState,
};
use mosaic_cac_types::state_machine::{
    StateMachineId,
    evaluator::{ActionContainer, Input},
};

use crate::{Db, ExecutorError, ExecutorResult};

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

#[derive(Debug, Default)]
struct SaveCache {}

#[derive(Debug)]
#[expect(dead_code)]
pub(crate) struct EvaluatorArtifactStoreImpl<D: Db> {
    sm_id: StateMachineId,
    saved: SaveCache,
    db: Arc<D>,
}

impl<D: Db> EvaluatorArtifactStore for EvaluatorArtifactStoreImpl<D> {}

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
