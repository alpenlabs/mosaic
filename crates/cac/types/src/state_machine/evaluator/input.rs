use crate::{DepositId, DepositInputs, SecretKey, Seed, SetupInputs, Sighashes};

/// Evaluator state machine inputs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Input {
    /// Initialize evaluator state machine.
    Init(EvaluatorInitData),
    // TODO: inputs
    /// Initialize deposit for specified deposit id.
    DepositInit(DepositId, EvaluatorDepositInitData),
}

/// Data required during evaluator state machine setup.
#[derive(Debug)]
pub struct EvaluatorInitData {
    /// Seed for deterministic rng.
    pub seed: Seed,
    /// Setup input wire values.
    pub setup_inputs: SetupInputs,
}

/// Data required to create a deposit.
#[derive(Debug)]
pub struct EvaluatorDepositInitData {
    /// Secret key used to generate adaptors.
    pub sk: SecretKey,
    /// Sighashes to be signed using the adaptors.
    pub sighashes: Box<Sighashes>,
    /// Deposit input wire values.
    pub deposit_inputs: Box<DepositInputs>,
}
