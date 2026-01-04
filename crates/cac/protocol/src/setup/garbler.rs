//! garbler setup state machine

use mosaic_cac_types::{
    ChallengeIndices, ChallengeMsg, ChallengeResponseMsg, CommitMsg, EvaluationIndices,
    GarblingTableCommitments, HasMsgId, MsgId, PolynomialCommitments, Seed, SetupInputs,
};
use mosaic_state_machine_api::{StateMachinePairId, StateMachineSpec};

/// State machine for Garbler during Setup
#[derive(Debug)]
pub enum SetupGrablerStateMachine {}

impl StateMachineSpec for SetupGrablerStateMachine {
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

/// Valid states.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[expect(missing_docs, reason = "wip")]
pub enum State {
    #[default]
    /// Initialized, start gt commitment generation and wait
    Initialized,
    /// Got gt commitments, generate polynomical commitments and send commit msg.
    /// Wait for commit msg ack.
    ///
    /// Q: should polynomial commitments be stored or re-generated when needed ?
    SendCommit {
        garbling_table_commitments: GarblingTableCommitments,
    },
    /// Wait for challenge msg
    WaitForChallenge,
    /// Got challenge message, send ack and challenge response
    ReceivedChallege {
        challenge_msg_id: MsgId,
        challenge_idxs: ChallengeIndices,
    },
    /// Challenge response msg ack received, send garbling tables
    TransferGarblingTables { challenge_idxs: ChallengeIndices },
    /// Setup is completed, ready to be used for deposits.
    SetupComplete { challenge_idxs: ChallengeIndices },
    /// Setup is consumed by a withdrawal dispute. Cannot be reused.
    SetupConsumed { by_deposit: StateMachinePairId },
    /// Setup was aborted due to a protocol violation.
    Aborted { reason: String },
}

/// Config
#[derive(Debug, Clone)]
#[expect(missing_docs, reason = "wip")]
pub struct Config {
    pub seed: Seed,
    pub setup_inputs: SetupInputs,
}

/// Inputs
#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum Input {
    GTCommitmentsGenerated(GarblingTableCommitments),
    RecvCommitMessageAck,
    RecvChallengeMsg(ChallengeMsg),
    RecvChallengeReponseAck,
    GarblingTablesTransferred,
    ConsumeSetup(StateMachinePairId),
}

#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum Action {
    GenerateGTCommitments(Seed),
    SendCommitMsg(CommitMsg),
    SendChallengeMsgAck(MsgId),
    SendChallengeResponseMsg(ChallengeResponseMsg),
    TransferGarblingTables(Seed, EvaluationIndices),
    /// Setup was consumed in provided deposit state machine
    ConsumeSetup(StateMachinePairId),
}

fn stf(_config: &Config, state: State, input: Input) -> State {
    match input {
        Input::GTCommitmentsGenerated(garbling_table_commitments) => match state {
            State::Initialized => State::SendCommit {
                garbling_table_commitments,
            },
            _ => state,
        },
        Input::RecvCommitMessageAck => match state {
            State::SendCommit { .. } => State::WaitForChallenge,
            _ => state,
        },
        Input::RecvChallengeMsg(challenge_msg) => match state {
            State::WaitForChallenge => {
                let challenge_msg_id = challenge_msg.id();
                State::ReceivedChallege {
                    challenge_msg_id,
                    challenge_idxs: challenge_msg.challenge_indices,
                }
            }
            _ => state,
        },
        Input::RecvChallengeReponseAck => match state {
            State::ReceivedChallege { challenge_idxs, .. } => {
                State::TransferGarblingTables { challenge_idxs }
            }
            _ => state,
        },
        Input::GarblingTablesTransferred => match state {
            State::TransferGarblingTables { challenge_idxs } => {
                State::SetupComplete { challenge_idxs }
            }
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
        State::Initialized => {
            vec![Action::GenerateGTCommitments(config.seed)]
        }
        State::SendCommit {
            garbling_table_commitments,
        } => {
            let polynomial_commitments = generate_polynomial_commmitments(config.seed);
            let commit_msg = CommitMsg {
                polynomial_commitments,
                garbling_table_commitments: garbling_table_commitments.clone(),
            };
            vec![Action::SendCommitMsg(commit_msg)]
        }
        State::WaitForChallenge => vec![],
        State::ReceivedChallege {
            challenge_msg_id,
            challenge_idxs,
        } => {
            let challenge_response = prepare_challenge_response_msg(config.seed, challenge_idxs);
            vec![
                Action::SendChallengeMsgAck(challenge_msg_id.clone()),
                Action::SendChallengeResponseMsg(challenge_response),
            ]
        }
        State::TransferGarblingTables { challenge_idxs } => {
            let eval_indices = get_eval_indices(challenge_idxs);
            vec![Action::TransferGarblingTables(config.seed, eval_indices)]
        }
        State::SetupComplete { .. } => vec![],
        State::SetupConsumed { .. } => vec![],
        State::Aborted { .. } => vec![],
    }
}

fn generate_polynomial_commmitments(_seed: Seed) -> PolynomialCommitments {
    todo!()
}

fn prepare_challenge_response_msg(
    _seed: Seed,
    _challenge_idxs: &ChallengeIndices,
) -> ChallengeResponseMsg {
    todo!()
}

fn get_eval_indices(_challenge_idxs: &ChallengeIndices) -> EvaluationIndices {
    todo!()
}
