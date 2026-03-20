//! Row specifications used by evaluator state storage.

mod protocol;
mod state;

/// Evaluator row tags.
///
/// Reserve a contiguous range from `0x01..=0x3F` for evaluator rows.
/// Row tag for evaluator root state.
pub const ROW_TAG_ROOT_STATE: u8 = 0x01;
/// Row tag for per-deposit evaluator state.
pub const ROW_TAG_DEPOSIT_STATE: u8 = 0x02;
/// Row tag for sub-chunked input polynomial commitment by wire index and value index.
pub const ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK: u8 = 0x03;
/// Row tag for output polynomial commitment singleton.
pub const ROW_TAG_OUTPUT_POLY_COMMITMENT: u8 = 0x04;
/// Row tag for all garbling table commitments singleton.
pub const ROW_TAG_GARBLING_TABLE_COMMITMENTS: u8 = 0x05;
/// Row tag for challenge indices singleton.
pub const ROW_TAG_CHALLENGE_INDICES: u8 = 0x06;
/// Row tag for sub-chunked opened input shares by challenged circuit index and wire index.
pub const ROW_TAG_OPENED_INPUT_SHARE_CHUNK: u8 = 0x07;
/// Row tag for reserved setup input shares singleton.
pub const ROW_TAG_RESERVED_SETUP_INPUT_SHARES: u8 = 0x08;
/// Row tag for opened output shares singleton.
pub const ROW_TAG_OPENED_OUTPUT_SHARES: u8 = 0x09;
/// Row tag for opened garbling seeds singleton.
pub const ROW_TAG_OPENED_GARBLING_SEEDS: u8 = 0x0A;
/// Row tag for deposit sighashes by deposit id.
pub const ROW_TAG_DEPOSIT_SIGHASHES: u8 = 0x0B;
/// Row tag for deposit inputs by deposit id.
pub const ROW_TAG_DEPOSIT_INPUTS: u8 = 0x0C;
/// Row tag for withdrawal inputs by deposit id.
pub const ROW_TAG_WITHDRAWAL_INPUTS: u8 = 0x0D;
/// Row tag for deposit adaptors by deposit id.
pub const ROW_TAG_DEPOSIT_ADAPTORS: u8 = 0x0E;
/// Row tag for sub-chunked withdrawal adaptors by deposit id, chunk index, and wire index.
pub const ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK: u8 = 0x0F;
/// Row tag for completed signatures by deposit id.
pub const ROW_TAG_COMPLETED_SIGNATURES: u8 = 0x10;
/// Row tag for AES128 key by circuit index.
pub const ROW_TAG_AES128_KEY: u8 = 0x11;
/// Row tag for public S by circuit index.
pub const ROW_TAG_PUBLIC_S: u8 = 0x12;
/// Row tag for constant-zero label by circuit index.
pub const ROW_TAG_CONSTANT_ZERO_LABEL: u8 = 0x13;
/// Row tag for constant-one label by circuit index.
pub const ROW_TAG_CONSTANT_ONE_LABEL: u8 = 0x14;
/// Row tag for output label ciphertext by evaluation-circuit index.
pub const ROW_TAG_OUTPUT_LABEL_CT: u8 = 0x15;
/// Row tag for fault secret.
pub const ROW_TAG_FAULT_SECRET: u8 = 0x16;
/// Row tag for zeroth coefficient of input polynomial commitment by wire index.
pub const ROW_TAG_INPUT_POLY_ZEROTH_COEFF: u8 = 0x17;

pub use protocol::*;
pub use state::*;
