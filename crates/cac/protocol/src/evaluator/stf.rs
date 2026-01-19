use super::{
    SMResult,
    action::Action,
    input::Input,
    state::{EvaluatorArtifactStore, State},
};

#[expect(unused_variables)]
pub(crate) async fn stf<S: EvaluatorArtifactStore>(
    state: &mut State<S>,
    input: Input,
) -> SMResult<Vec<Action>> {
    unimplemented!()
}

#[expect(unused_variables)]
pub(crate) async fn restore<S: EvaluatorArtifactStore>(state: &State<S>) -> SMResult<Vec<Action>> {
    unimplemented!()
}
