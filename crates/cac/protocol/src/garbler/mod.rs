#![allow(missing_docs)]
use std::{error::Error, marker::PhantomData};

use fasm::{
    StateMachine,
    actions::{Action, TrackedAction, TrackedActionTypes},
};
use mosaic_cac_types::{
    AllGarblingSeeds, AllPolynomialCommitments, AllPolynomials, AllShares, ChallengeIndices,
    ChallengeMsg, ChallengeResponseMsg, CommitMsg, GarblingTableCommitments, HasMsgId, MsgId, Seed,
};

mod state;
pub use state::*;

#[derive(Debug)]
pub struct GarblerSM<S: GarblerState> {
    _s: PhantomData<S>,
}

impl<S: GarblerState> StateMachine for GarblerSM<S> {
    type State = S;

    type Input = Input;

    type TrackedAction = GarblerTrackedActionTypes;

    type UntrackedAction = GarblerUntrackedAction;

    type Actions = Vec<Action<GarblerUntrackedAction, GarblerTrackedActionTypes>>;

    type TransitionError = GarblerError;

    type RestoreError = GarblerError;

    async fn stf(
        state_access: &mut Self::State,
        input: fasm::Input<Self::TrackedAction, Self::Input>,
        actions: &mut Self::Actions,
    ) -> Result<(), Self::TransitionError> {
        use GarblerTrackedActionResult::*;
        use fasm::Input::*;
        let mut state = state_access.load_state().await?;
        match input {
            Normal(input) => match input {
                Input::Init(config) => {
                    match state.step {
                        Step::Uninit => {
                            // state update
                            state.config = config;
                            state.step = Step::GeneratingPolynomials;

                            // generate actions
                            actions.push(
                                GarblerTrackedAction::GeneratePolynomials(state.config.seed).into(),
                            );

                            // save state
                            state_access.save_state(&state).await?;
                        }
                        _ => return Err(GarblerError::UnexpectedInput),
                    }
                }
                Input::RecvChallengeMsg(challenge_msg) => match state.step {
                    Step::SendingCommit | Step::WaitingForChallenge => {
                        if is_valid_challenge(&challenge_msg) {
                            let msg_id = challenge_msg.id();
                            let shares = state_access.load_shares().await?;
                            let challenge_response_msg = create_challenge_response_msg(
                                challenge_msg.challenge_indices.as_ref(),
                                shares,
                            );
                            state_access
                                .save_challenge_indices(challenge_msg.challenge_indices.as_ref())
                                .await?;
                            state.context.ackd_challenge_msg_id = Some(msg_id);

                            state.step = Step::SendingChallengeResponse;
                            state_access.save_state(&state).await?;

                            actions.push(GarblerTrackedAction::AckChallengeMsg(msg_id).into());
                            actions.push(
                                GarblerTrackedAction::SendChallengeResponseMsg(
                                    challenge_response_msg,
                                )
                                .into(),
                            );
                        } else {
                            // TODO: should this abort, or just ignore and stay at same state ?
                            state.step = Step::Aborted {
                                reason: "invalid challenge msg".into(),
                            };
                        }

                        state_access.save_state(&state).await?;
                    }
                    Step::SendingChallengeResponse
                    | Step::TransferGarblingTables
                    | Step::SetupComplete => {}
                    _ => return Err(GarblerError::UnexpectedInput),
                },
                Input::InitDeposit(_) => todo!(),
            },
            TrackedActionCompleted { result, .. } => match result {
                PolynomialsGenerated(polynomials, commitments) => {
                    match state.step {
                        Step::GeneratingPolynomials => {
                            // state update
                            state_access.save_polynomials(polynomials.as_ref()).await?;
                            state_access
                                .save_polynomial_commitments(commitments.as_ref())
                                .await?;
                            state.step = Step::GeneratingShares;

                            // generate actions
                            actions.push(GarblerTrackedAction::GenerateShares(polynomials).into());

                            state_access.save_state(&state).await?;
                        }
                        _ => return Err(GarblerError::UnexpectedInput),
                    }
                }
                SharesGenerated(shares) => {
                    match state.step {
                        Step::GeneratingShares => {
                            // state update
                            state_access.save_shares(shares.as_ref()).await?;

                            state.step = Step::GeneratingTableCommitments;

                            // generate actions
                            let seeds = generate_garbling_table_seeds(state.config.seed);
                            actions.push(
                                GarblerTrackedAction::GenerateTableCommitments(
                                    Box::new(seeds),
                                    shares,
                                )
                                .into(),
                            );

                            state_access.save_state(&state).await?;
                        }
                        _ => return Err(GarblerError::UnexpectedInput),
                    }
                }
                TableCommitmentsGenerated(garbling_table_commitments) => {
                    match state.step {
                        Step::GeneratingTableCommitments => {
                            // state update
                            state_access
                                .save_garbling_table_commitments(
                                    garbling_table_commitments.as_ref(),
                                )
                                .await?;
                            state.step = Step::SendingCommit;
                            state_access.save_state(&state).await?;

                            // generate actions
                            let polynomial_commitments =
                                state_access.load_polynomial_commitments().await?;
                            let commit_msg = CommitMsg {
                                polynomial_commitments,
                                garbling_table_commitments,
                            };
                            actions.push(GarblerTrackedAction::SendCommitMsg(commit_msg).into());
                        }
                        _ => return Err(GarblerError::UnexpectedInput),
                    }
                }
                CommitMsgAcked(msg_id) => match state.step {
                    Step::SendingCommit => {
                        let Some(sent_msg_id) = state.context.sent_commit_msg_id else {
                            return Err(GarblerError::StateConsistency(
                                "missing sent_commit_msg_id",
                            ));
                        };

                        if sent_msg_id != msg_id {
                            return Err(GarblerError::UnexpectedMsgId);
                        }

                        state.step = Step::WaitingForChallenge;
                        state_access.save_state(&state).await?;
                    }
                    _ => return Err(GarblerError::UnexpectedInput),
                },

                _ => unimplemented!(),
            },
        };

        Ok(())
    }

    #[expect(unused)]
    async fn restore(
        state_access: &Self::State,
        actions: &mut Self::Actions,
    ) -> Result<(), Self::RestoreError> {
        let state = state_access.load_state().await?;

        match &state.step {
            Step::Uninit => todo!(),
            Step::GeneratingPolynomials => todo!(),
            Step::GeneratingShares => todo!(),
            Step::GeneratingTableCommitments => todo!(),
            Step::SendingCommit => todo!(),
            Step::WaitingForChallenge => todo!(),
            Step::SendingChallengeResponse => todo!(),
            Step::TransferGarblingTables => todo!(),
            Step::SetupComplete => todo!(),
            Step::SetupConsumed { by_deposit } => todo!(),
            Step::Aborted { reason } => todo!(),
        }

        Ok(())
    }
}

fn generate_garbling_table_seeds(_base_seed: Seed) -> AllGarblingSeeds {
    todo!()
}

fn is_valid_challenge(_challenge: &ChallengeMsg) -> bool {
    // challenge indices must be in range, must not include 0, etc
    todo!()
}

fn create_challenge_response_msg(
    _challenge_idxs: &ChallengeIndices,
    _shares: Box<AllShares>,
) -> ChallengeResponseMsg {
    todo!()
}

#[derive(Debug)]
pub enum GarblerError {
    /// Received Input that is not expected at current state.
    UnexpectedInput,
    /// Received Ack for unexpected msg id.
    UnexpectedMsgId,
    /// CRITICAL: State is inconsitent with expectations.
    StateConsistency(&'static str),
    /// Error while accessing storage.
    Storage(Box<dyn Error>),
}

pub type GarblerResult<T> = Result<T, GarblerError>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Input {
    Init(Config),
    RecvChallengeMsg(ChallengeMsg),
    InitDeposit(DepositId),
    // PolynomialsGenerated(Box<AllPolynomials>, Box<AllPolynomialCommitments>),
    // SharesGenerated(Box<AllShares>),
    // TableCommitmentsGenerated(Box<GarblingTableCommitments>),
    // CommitMsgAcked(MsgId),
    // ChallengeResponseAcked(MsgId),
}

#[derive(Debug)]
pub enum GarblerUntrackedAction {}

impl From<GarblerUntrackedAction> for Action<GarblerUntrackedAction, GarblerTrackedActionTypes> {
    fn from(val: GarblerUntrackedAction) -> Self {
        Action::Untracked(val)
    }
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GarblerTrackedAction {
    GeneratePolynomials(Seed),
    GenerateShares(Box<AllPolynomials>),
    GenerateTableCommitments(Box<AllGarblingSeeds>, Box<AllShares>),
    SendCommitMsg(CommitMsg),
    AckChallengeMsg(MsgId),
    SendChallengeResponseMsg(ChallengeResponseMsg),
}

impl From<GarblerTrackedAction> for Action<GarblerUntrackedAction, GarblerTrackedActionTypes> {
    fn from(val: GarblerTrackedAction) -> Self {
        Action::Tracked(TrackedAction::new((), val))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum GarblerTrackedActionResult {
    PolynomialsGenerated(Box<AllPolynomials>, Box<AllPolynomialCommitments>),
    SharesGenerated(Box<AllShares>),
    TableCommitmentsGenerated(Box<GarblingTableCommitments>),
    CommitMsgAcked(MsgId),
    ChallengeResponseAcked(MsgId),
}

#[derive(Debug)]
pub struct GarblerTrackedActionTypes;

impl TrackedActionTypes for GarblerTrackedActionTypes {
    type Id = ();

    type Action = GarblerTrackedAction;

    type Result = GarblerTrackedActionResult;
}
