use mosaic_cac_types::{
    EvaluationIndices, AllGarblingTableCommitments, Msg, OpenedGarblingSeeds, Seed, SetupInputs,
};

use crate::{StateMachineMetadata, StateMachinePairId};

/// An input received by an executor.
#[derive(Debug)]
pub struct ExecutorInput {
    /// The state machine this message is for.
    pub state_machine_id: StateMachinePairId,
    /// message.
    pub msg: ExecutorInputMsg,
}

/// Type of executor input
#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum ExecutorInputMsg {
    Control(ExecutorControlMsgType),
    Input(ExecutorInputMsgType),
}

/// Special casing on executor.
#[derive(Debug)]
pub enum ExecutorControlMsgType {
    /// Init new state machine.
    Init(StateMachineInitData, StateMachineMetadata),
    /// Load the state machine and re-emit actions.
    Load,
}

/// All possible input messages types bound to the state machines.
#[derive(Debug)]
pub enum ExecutorInputMsgType {
    /// Message from a peer from the network.
    PeerMessage(Msg),
    /// Job completion report.
    JobCompletion(JobCompletionReport),
}

/// All possible job completion reports.
#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum JobCompletionReport {
    GTCommitmentsGenerated(Box<AllGarblingTableCommitments>),
    GarblingTablesTransferred,
    GarblingTablesReceived(bool),
    GTCommitmentsVerified(bool),
    GarbTablesEvaluated(Option<()>),
}

/// All possible init options.
#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum StateMachineInitData {
    GarblerSetup {
        seed: Seed,
        setup_inputs: SetupInputs,
    },
    EvaluatorSetup {
        seed: Seed,
        setup_inputs: SetupInputs,
    },
    GarblerDeposit {
        sighashes: (),
        eval_adaptor_pubkey: (),
        deposit_idx: (),
        setup_id: StateMachinePairId,
    },
    EvaluatorDeposit {
        sighashes: (),
        deposit_idx: (),
        setup_id: StateMachinePairId,
    },
}

/// An output message sent out by an executor.
#[derive(Debug)]
pub struct ExecutorOutput {
    /// The state machine this message is from.
    pub state_machine_id: StateMachinePairId,
    /// message.
    pub msg: ExecutorOutputMsgType,
}

/// All possible output message types from an executor.
#[derive(Debug)]
pub enum ExecutorOutputMsgType {
    /// Message to a peer on the network.
    PeerMessage(Msg),
    /// Request a job to be executed.
    JobExecutionRequest(JobExecution),
    /// Notify that the setup has been consumed.
    ConsumeSetup,
}

#[derive(Debug)]
#[expect(missing_docs, reason = "wip")]
pub enum JobExecution {
    GenerateGTCommitments(Seed),
    TransferGarblingTables(Seed, Box<EvaluationIndices>),
    ReceiveAndVerifyGarblingTables(Box<EvaluationIndices>, Box<AllGarblingTableCommitments>),
    VerifyGTCommitments(Box<OpenedGarblingSeeds>, Box<AllGarblingTableCommitments>),
    EvaluateGarbTables(()),
}
