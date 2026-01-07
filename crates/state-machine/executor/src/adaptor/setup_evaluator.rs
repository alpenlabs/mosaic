//! additional glue logic for setup evaluator state machine.

use mosaic_cac_proto_types::CacRole;
use mosaic_cac_protocol::setup::evaluator::{
    Action, Config, Input, SetupEvalatorStateMachine, State,
};
use mosaic_cac_types::{HasMsgId, Msg, MsgId};
use mosaic_state_machine_api::{
    ExecutorInputMsgType, ExecutorOutputMsgType, JobExecution, StateMachineAdaptorSpec,
    StateMachineInitData, StateMachinePhase, StateMachineSpec,
};
use tracing::warn;

/// Additional state maintained by this adaptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorState {
    commit_ack: Option<MsgId>,
    challenge_msg: Option<MsgId>,
    challenge_response_ack: Option<MsgId>,
}

#[expect(clippy::derivable_impls, reason = "keeping this explicit")]
impl Default for AdaptorState {
    fn default() -> Self {
        Self {
            commit_ack: None,
            challenge_msg: None,
            challenge_response_ack: None,
        }
    }
}

/// Executor adaptor for [`SetupEvalatorStateMachine`].
#[derive(Debug)]
pub enum SetupEvalatorAdaptor {}

impl StateMachineSpec for SetupEvalatorAdaptor {
    type State = <SetupEvalatorStateMachine as StateMachineSpec>::State;

    type Config = <SetupEvalatorStateMachine as StateMachineSpec>::Config;

    type Input = <SetupEvalatorStateMachine as StateMachineSpec>::Input;

    type Action = <SetupEvalatorStateMachine as StateMachineSpec>::Action;

    fn stf(config: &Self::Config, state: Self::State, input: Self::Input) -> Self::State {
        SetupEvalatorStateMachine::stf(config, state, input)
    }

    fn emit_actions(config: &Self::Config, state: &Self::State) -> Vec<Self::Action> {
        SetupEvalatorStateMachine::emit_actions(config, state)
    }
}

impl StateMachineAdaptorSpec for SetupEvalatorAdaptor {
    type AdaptorState = AdaptorState;

    const ROLE: CacRole = CacRole::Evaluator;

    const PHASE: StateMachinePhase = StateMachinePhase::Setup;

    fn process_init(
        init: StateMachineInitData,
    ) -> Option<(Self::Config, Self::State, Self::AdaptorState)> {
        use StateMachineInitData::*;
        match init {
            EvaluatorSetup { seed, setup_inputs } => {
                let config = Config { seed, setup_inputs };
                let state = State::Initialized;
                let ws = AdaptorState::default();

                Some((config, state, ws))
            }
            _ => None,
        }
    }

    fn process_input(
        ws: &Self::AdaptorState,
        input: ExecutorInputMsgType,
    ) -> (Vec<Self::Input>, Vec<ExecutorOutputMsgType>) {
        let mut inputs = vec![];
        let mut output_msgs = vec![];
        match input {
            ExecutorInputMsgType::PeerMessage(msg) => {
                match msg {
                    Msg::CommitMsg(commit_msg) => {
                        match ws.commit_ack {
                            Some(msg_id) => {
                                // already acked a commit message
                                if commit_msg.id() == msg_id {
                                    // send ack but dont run stat machine again
                                    output_msgs = vec![map_action_to_output_message(
                                        Action::SendCommitAck(msg_id),
                                    )];
                                } else {
                                    // ignore the message
                                    warn!(acked = %msg_id, new = %commit_msg.id(), "received different commit than previously ACK'd message");
                                }
                            }
                            None => {
                                inputs = vec![Input::RecvCommitMsg(commit_msg)];
                            }
                        }
                    }
                    Msg::ChallengeResponseMsg(challenge_response_msg) => {
                        match ws.challenge_response_ack {
                            Some(msg_id) => {
                                // already acked a commit message
                                if challenge_response_msg.id() == msg_id {
                                    // send ack but dont run stat machine again
                                    output_msgs = vec![map_action_to_output_message(
                                        Action::SendChallengeResponseAck(msg_id),
                                    )];
                                } else {
                                    // ignore the message
                                    warn!(acked = %msg_id, new = %challenge_response_msg.id(), "received different challenge response than previously ACK'd message");
                                }
                            }
                            None => {
                                inputs =
                                    vec![Input::RecvChallengeReponseMsg(challenge_response_msg)];
                            }
                        }
                    }
                    Msg::ChallengeMsgAck(msg_id) => {
                        match ws.challenge_msg {
                            Some(sent_msg_id) if msg_id == sent_msg_id => {
                                inputs = vec![Input::RecvChallengeAck];
                            }
                            _ => {
                                // ignore unexpected message
                                warn!(%msg_id, "received unexpected challenge msg ack");
                            }
                        }
                    }
                    msg => {
                        // ignore everything else
                        warn!(?msg, "received unexpected message type");
                    }
                }
            }
            ExecutorInputMsgType::JobCompletion(_job_completion) => todo!(),
        };

        (inputs, output_msgs)
    }

    fn process_action(
        mut ws: Self::AdaptorState,
        action: Self::Action,
    ) -> (Self::AdaptorState, Vec<ExecutorOutputMsgType>) {
        use ExecutorOutputMsgType::*;
        let output_msgs = match action {
            Action::SendCommitAck(msg_id) => {
                ws.commit_ack = Some(msg_id);
                vec![PeerMessage(Msg::CommitMsgAck(msg_id))]
            }
            Action::SendChallengeMsg(challenge_msg) => {
                ws.challenge_msg = Some(challenge_msg.id());
                vec![PeerMessage(Msg::ChallengeMsg(challenge_msg))]
            }
            Action::SendChallengeResponseAck(msg_id) => {
                ws.challenge_response_ack = Some(msg_id);
                vec![PeerMessage(Msg::ChallengeResponseMsgAck(msg_id))]
            }
            Action::VerifyOpenedGarbTableCommitments(seeds, commitments) => {
                vec![JobExecutionRequest(JobExecution::VerifyGTCommitments(
                    seeds,
                    commitments,
                ))]
            }
            _ => todo!(),
        };

        (ws, output_msgs)
    }
}

fn map_action_to_output_message(action: Action) -> ExecutorOutputMsgType {
    use ExecutorOutputMsgType::*;
    match action {
        Action::SendCommitAck(msg_id) => PeerMessage(Msg::CommitMsgAck(msg_id)),
        Action::SendChallengeMsg(challenge_msg) => PeerMessage(Msg::ChallengeMsg(challenge_msg)),
        Action::SendChallengeResponseAck(msg_id) => {
            PeerMessage(Msg::ChallengeResponseMsgAck(msg_id))
        }
        Action::VerifyOpenedGarbTableCommitments(_, _) => todo!(),
        _ => todo!(),
    }
}
