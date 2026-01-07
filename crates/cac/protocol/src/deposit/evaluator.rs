//! Evaluator Deposit + Withdrawal state machine.

use std::vec;

use mosaic_cac_types::AdaptorMsg;
use mosaic_state_machine_api::{StateMachinePairId, StateMachineSpec};
use tracing::error;

/// Garbler Deposit + Withdrawal state machine.
#[derive(Debug)]
pub enum DepositGarblerStateMachine {}

impl StateMachineSpec for DepositGarblerStateMachine {
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
#[expect(missing_docs, dead_code, reason = "wip")]
pub struct Config {
    setup: StateMachinePairId,
    deposit_idx: u64,
    // TODO: types
    sighashes: (),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(missing_docs, reason = "wip")]
pub enum State {
    SendingAdaptorMsg,
    DepositReady,
    EvaluatingTables,
    SecretExtracted(()), // TODO: secret type
    EvaluationFailed,
    Consumed { by_deposit: StateMachinePairId },
}

#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum Input {
    RecvAdaptorAck,
    ExtractShares(()),                // TODO: signatures type
    GarbTableEvalResults(Option<()>), // TODO: output shares type
    SetupConsumed(StateMachinePairId),
}

#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum Action {
    SendAdaptorMsg(AdaptorMsg),
    ConsumeSetup,
    EvaluateGarbingTables {
        setup: StateMachinePairId,
        // TODO: evaluation inputs
    },
}

fn stf(_config: &Config, state: State, input: Input) -> State {
    match input {
        Input::RecvAdaptorAck => match state {
            State::SendingAdaptorMsg => State::DepositReady,
            _ => state,
        },
        Input::ExtractShares(_signatures) => match state {
            State::DepositReady => State::EvaluatingTables,
            _ => state,
        },
        Input::GarbTableEvalResults(maybe_output_shares) => match state {
            State::EvaluatingTables => {
                if let Some(_output_shares) = maybe_output_shares {
                    State::SecretExtracted(())
                } else {
                    State::EvaluationFailed
                }
            }
            _ => state,
        },
        Input::SetupConsumed(by_deposit) => match state {
            State::Consumed {
                by_deposit: prev_by_deposit,
            } => {
                if prev_by_deposit != by_deposit {
                    error!("!!!!! setup possibly consumed twice !!!!!");
                };
                State::Consumed {
                    by_deposit: prev_by_deposit,
                }
            }
            State::SendingAdaptorMsg | State::DepositReady => State::Consumed { by_deposit },
            _ => state,
        },
    }
}

fn emit_actions(config: &Config, state: &State) -> Vec<Action> {
    match state {
        State::SendingAdaptorMsg => {
            let adaptor_msg = generate_adaptor_message();
            vec![Action::SendAdaptorMsg(adaptor_msg)]
        }
        State::DepositReady => vec![],
        State::EvaluatingTables => {
            vec![
                Action::ConsumeSetup,
                Action::EvaluateGarbingTables {
                    setup: config.setup,
                },
            ]
        }
        State::SecretExtracted(_) => vec![],
        State::EvaluationFailed => vec![],
        State::Consumed { .. } => vec![],
    }
}

fn generate_adaptor_message() -> AdaptorMsg {
    todo!()
}
