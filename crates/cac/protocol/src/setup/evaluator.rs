//! Setup Evaluator state machine.

use mosaic_cac_types::{
    ChallengeIndices, ChallengeMsg, ChallengeResponseMsg, CommitMsg, GarblingTableCommitments,
    HasMsgId, MsgId, OpenedGarblingSeeds, OpenedInputShares, OpenedOutputShares,
    PolynomialCommitments, ReservedSetupInputShares, Seed, SetupInputs,
};
use mosaic_state_machine_api::{StateMachinePairId, StateMachineSpec};

/// State machine for Evaluator during Setup.
#[derive(Debug)]
pub enum SetupEvalatorStateMachine {}

impl StateMachineSpec for SetupEvalatorStateMachine {
    type State = State;

    type Config = Config;

    type Input = Input;

    type Action = Action;

    fn stf(config: &Self::Config, state: Self::State, input: Self::Input) -> Self::State {
        stf(config, state, input)
    }

    fn emit_actions(config: &Self::Config, state: &Self::State) -> Vec<Self::Action> {
        emit_actions(config, state)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code, missing_docs, reason = "wip")]
pub struct Config {
    pub seed: Seed,
    pub setup_inputs: SetupInputs,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(missing_docs, reason = "wip")]
pub enum State {
    #[default]
    // waiting for commitments
    Initialized,
    // received commitments
    // challenge sent, waiting for challenge response
    ReceivedCommitments {
        commit_msg_id: MsgId,
        polynomial_commitments: Box<PolynomialCommitments>,
        garbling_table_commitments: Box<GarblingTableCommitments>,
    },
    // got challenge ack, now waiting for challenge response
    WaitChallengeResponse {
        polynomial_commitments: Box<PolynomialCommitments>,
        garbling_table_commitments: Box<GarblingTableCommitments>,
    },
    // received challenge response
    // verified shares are correct
    // triggered garb table verification for opened tables
    // waiting for verification to complete
    ReceivedChallegeResponse {
        challenge_response_msg_id: MsgId,
        polynomial_commitments: Box<PolynomialCommitments>,
        garbling_table_commitments: Box<GarblingTableCommitments>,
        opened_input_shares: Box<OpenedInputShares>,
        opened_output_shares: Box<OpenedOutputShares>,
        reserved_setup_input_shares: Box<ReservedSetupInputShares>,
        opened_garbling_seeds: Box<OpenedGarblingSeeds>,
    },
    // verified commitments are valid for opened tables
    // triggered receive and verify remaining tables
    // waiting for tables to be received
    VerifiedGarblingTableCommitments {
        polynomial_commitments: Box<PolynomialCommitments>,
        garbling_table_commitments: Box<GarblingTableCommitments>,
        challenge_indices: Box<ChallengeIndices>,
        opened_input_shares: Box<OpenedInputShares>,
        opened_output_shares: Box<OpenedOutputShares>,
        reserved_setup_input_shares: Box<ReservedSetupInputShares>,
        opened_garbling_seeds: Box<OpenedGarblingSeeds>,
    },
    SetupComplete {
        // TODO: remove states that are not needed
        polynomial_commitments: Box<PolynomialCommitments>,
        garbling_table_commitments: Box<GarblingTableCommitments>,
        challenge_indices: Box<ChallengeIndices>,
        opened_input_shares: Box<OpenedInputShares>,
        opened_output_shares: Box<OpenedOutputShares>,
        reserved_setup_input_shares: Box<ReservedSetupInputShares>,
        opened_garbling_seeds: Box<OpenedGarblingSeeds>,
    },
    SetupConsumed {
        by_deposit: StateMachinePairId,
        // TODO: what states need to be preserved ?
    },
    Aborted {
        reason: String,
    },
}

#[allow(missing_docs, reason = "wip")]
#[derive(Debug)]
pub enum Input {
    RecvCommitMsg(CommitMsg),
    RecvChallengeAck,
    RecvChallengeReponseMsg(ChallengeResponseMsg),
    GarblingTableCommitmentsVerified(bool),
    GarblingTablesReceived,
    ConsumeSetup(StateMachinePairId),
}

#[allow(missing_docs, reason = "wip")]
#[derive(Debug)]
pub enum Action {
    SendCommitAck(MsgId),
    SendChallengeMsg(ChallengeMsg),
    SendChallengeResponseAck(MsgId),
    VerifyOpenedGarbTableCommitments(Box<OpenedGarblingSeeds>, Box<GarblingTableCommitments>),
    ReceiveGarblingTables(()), // TODO: types
}

fn stf(config: &Config, state: State, input: Input) -> State {
    match input {
        Input::RecvCommitMsg(commit_msg) => match state {
            State::Initialized => {
                let commit_msg_id = commit_msg.id();
                let CommitMsg {
                    polynomial_commitments,
                    garbling_table_commitments,
                } = commit_msg;
                State::ReceivedCommitments {
                    commit_msg_id,
                    polynomial_commitments,
                    garbling_table_commitments,
                }
            }
            _ => state,
        },
        Input::RecvChallengeAck => match state {
            State::ReceivedCommitments {
                polynomial_commitments,
                garbling_table_commitments,
                ..
            } => State::WaitChallengeResponse {
                polynomial_commitments,
                garbling_table_commitments,
            },
            _ => state,
        },
        Input::RecvChallengeReponseMsg(challenge_response) => match state {
            State::ReceivedCommitments {
                polynomial_commitments,
                garbling_table_commitments,
                ..
            } => {
                let challenge_response_msg_id = challenge_response.id();
                let ChallengeResponseMsg {
                    opened_input_shares,
                    reserved_setup_input_shares,
                    opened_output_shares,
                    opened_garbling_seeds,
                } = challenge_response;
                // verify shares. to State::Aborted if invalid
                State::ReceivedChallegeResponse {
                    challenge_response_msg_id,
                    polynomial_commitments,
                    garbling_table_commitments,
                    opened_input_shares,
                    opened_output_shares,
                    reserved_setup_input_shares,
                    opened_garbling_seeds,
                }
            }
            _ => state,
        },
        Input::GarblingTableCommitmentsVerified(_) => match state {
            State::ReceivedChallegeResponse {
                polynomial_commitments,
                garbling_table_commitments,
                opened_input_shares,
                opened_output_shares,
                reserved_setup_input_shares,
                opened_garbling_seeds,
                ..
            } => {
                let challenge_indices = Box::new(generate_challenge_indices(&config.seed));
                State::VerifiedGarblingTableCommitments {
                    polynomial_commitments,
                    garbling_table_commitments,
                    challenge_indices,
                    opened_input_shares,
                    opened_output_shares,
                    reserved_setup_input_shares,
                    opened_garbling_seeds,
                }
            }
            _ => state,
        },
        Input::GarblingTablesReceived => match state {
            State::VerifiedGarblingTableCommitments {
                polynomial_commitments,
                garbling_table_commitments,
                challenge_indices,
                opened_input_shares,
                opened_output_shares,
                reserved_setup_input_shares,
                opened_garbling_seeds,
            } => State::SetupComplete {
                polynomial_commitments,
                garbling_table_commitments,
                challenge_indices,
                opened_input_shares,
                opened_output_shares,
                reserved_setup_input_shares,
                opened_garbling_seeds,
            },
            _ => state,
        },
        Input::ConsumeSetup(by_deposit) => match state {
            State::SetupComplete { .. } => State::SetupConsumed { by_deposit },
            _ => state,
        },
    }
}

fn emit_actions(config: &Config, state: &State) -> Vec<Action> {
    match state {
        State::Initialized => vec![],
        State::ReceivedCommitments { commit_msg_id, .. } => {
            let challenge_indices = Box::new(generate_challenge_indices(&config.seed));
            vec![
                Action::SendCommitAck(*commit_msg_id),
                Action::SendChallengeMsg(ChallengeMsg { challenge_indices }),
            ]
        }
        State::WaitChallengeResponse { .. } => vec![],
        State::ReceivedChallegeResponse {
            challenge_response_msg_id,
            garbling_table_commitments,
            opened_garbling_seeds,
            ..
        } => {
            vec![
                Action::SendChallengeResponseAck(*challenge_response_msg_id),
                Action::VerifyOpenedGarbTableCommitments(
                    opened_garbling_seeds.clone(),
                    garbling_table_commitments.clone(),
                ),
            ]
        }
        State::VerifiedGarblingTableCommitments { .. } => {
            vec![Action::ReceiveGarblingTables(())]
        }
        State::SetupComplete { .. } => vec![],
        State::SetupConsumed { .. } => vec![],
        State::Aborted { .. } => vec![],
    }
}

fn generate_challenge_indices(_seed: &Seed) -> ChallengeIndices {
    todo!()
}
