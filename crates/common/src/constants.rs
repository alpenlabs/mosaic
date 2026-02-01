//! shared constants

// Garbling table count constants

/// Number of circuits in a tableset. (N)
pub const N_CIRCUITS: usize = 181;
/// Number of circuits opened during CaC for verification. (K)
pub const N_OPEN_CIRCUITS: usize = 174;
/// Number of circuits for evaluation. (N - K)
pub const N_EVAL_CIRCUITS: usize = N_CIRCUITS - N_OPEN_CIRCUITS;

// Garbling table wires constants

/// Number of bits in a single wide label
pub const WIDE_LABEL_WIDTH: usize = 8;
/// Total number of values represented by a single wide label
pub const WIDE_LABEL_VALUE_COUNT: usize = 1 << WIDE_LABEL_WIDTH;
/// Type for a wide label value
pub type WideLabelValue = u8;

const _: () = assert!(
    WIDE_LABEL_WIDTH <= WideLabelValue::BITS as usize,
    "WideLabelValue type is too small for WIDE_LABEL_WIDTH"
);

// NOTE: *_INPUT_WIRES are groups of `WIDE_LABEL_WIDTH` wires.

/// TODO: number of setup input wire groups.
pub const N_SETUP_INPUT_WIRES: usize = 4;
/// TODO: number of deposit input wire groups.
pub const N_DEPOSIT_INPUT_WIRES: usize = 4;
/// TODO: number of withdrawal input wire groups.
pub const N_WITHDRAWAL_INPUT_WIRES: usize = 128 + 36;
/// Total number of input wire groups.
pub const N_INPUT_WIRES: usize =
    N_SETUP_INPUT_WIRES + N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES;

/// Number of withdrawal wires per AdaptorMsgChunk.
/// This divides evenly: 164 / 4 = 41 wires per chunk.
pub const WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK: usize =
    N_WITHDRAWAL_INPUT_WIRES / N_DEPOSIT_INPUT_WIRES;

const _: () = assert!(
    N_WITHDRAWAL_INPUT_WIRES % N_DEPOSIT_INPUT_WIRES == 0,
    "N_WITHDRAWAL_INPUT_WIRES must be divisible by N_DEPOSIT_INPUT_WIRES for clean chunking"
);
