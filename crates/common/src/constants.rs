//! shared constants

// Garbling table count constants

/// Number of circuits in a tableset. (N)
pub const N_CIRCUITS: usize = 181;
/// Number of circuits opened during CaC for verification. (K)
pub const N_VERIFICAITON_CIRCUITS: usize = 174;
/// Number of circuits for evaluation. (N - K)
pub const N_EVAL_CIRCUITS: usize = N_CIRCUITS - N_VERIFICAITON_CIRCUITS;

// Garbling table wires constants

/// TODO: number of input wires
pub const N_INPUT_WIRES: usize = 160;
/// TODO: number of setup input wires
pub const N_SETUP_INPUT_WIRES: usize = 4;
/// TODO: number of deposit input wires
pub const N_DEPOSIT_INPUT_WIRES: usize = 4;
/// TODO: number of withdrawal input wires
pub const N_WITHDRAWAL_INPUT_WIRES: usize = 152;

const _: () = assert!(
    N_INPUT_WIRES == N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES
);
