//! Garbler Deposit + Withdrawal state machine.

use std::vec;

use mosaic_cac_types::{AdaptorMsg, DepositAdaptors, HasMsgId, MsgId, WithdrawalAdaptors};
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
    evaluator_adaptor_key: (),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(missing_docs, reason = "wip")]
pub enum State {
    WaitForAdaptors,
    DepositReady {
        adaptor_msg_id: MsgId,
        deposit_adaptors: DepositAdaptors,
        withdrawal_adaptors: WithdrawalAdaptors,
    },
    Completed {
        counterproof_sig: (), // TODO: counterproof sig type
    },
    Consumed {
        by_deposit: StateMachinePairId,
    },
    Aborted {
        reason: String,
    },
}

#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum Input {
    RecvAdaptorMsg(AdaptorMsg),
    GenerateCounterproofSignature(()), // TODO: counterproof type
    SetupConsumed(StateMachinePairId),
}

#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum Action {
    SendAdaptorAck(MsgId),
    ConsumeSetup,
}

fn stf(_config: &Config, state: State, input: Input) -> State {
    match input {
        Input::RecvAdaptorMsg(adaptor_msg) => match state {
            State::WaitForAdaptors => {
                let adaptor_msg_id = adaptor_msg.id();
                // TODO: validate adaptor msg
                if let Some(failure_reason) = validate_adaptors() {
                    State::Aborted {
                        reason: failure_reason,
                    }
                } else {
                    let AdaptorMsg {
                        deposit_adaptors,
                        withdrawal_adaptors,
                    } = adaptor_msg;
                    State::DepositReady {
                        adaptor_msg_id,
                        deposit_adaptors,
                        withdrawal_adaptors,
                    }
                }
            }
            _ => state,
        },
        Input::GenerateCounterproofSignature(counterproof) => match state {
            State::DepositReady { .. } => {
                let counterproof_sig = generate_counterproof_signature(counterproof);
                State::Completed { counterproof_sig }
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
            State::WaitForAdaptors | State::DepositReady { .. } => State::Consumed { by_deposit },
            _ => state,
        },
    }
}

fn emit_actions(_config: &Config, state: &State) -> Vec<Action> {
    match state {
        State::WaitForAdaptors => vec![],
        State::DepositReady { adaptor_msg_id, .. } => {
            vec![Action::SendAdaptorAck(*adaptor_msg_id)]
        }
        State::Completed { .. } => {
            vec![Action::ConsumeSetup]
        }
        State::Consumed { .. } => vec![],
        State::Aborted { .. } => vec![],
    }
}

type AdaptorValidationFailure = Option<String>;

fn validate_adaptors() -> AdaptorValidationFailure {
    todo!()
}

fn generate_counterproof_signature(_counterproof: ()) -> () {
    todo!()
}
