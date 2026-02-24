//! Row specifications used by garbler state storage.

mod deposit;
mod protocol;
mod state;

/// Garbler row tags.
///
/// Reserve a contiguous range from `0x01..=0x3F` for garbler rows.
/// Row tag for garbler root state.
pub const ROW_TAG_ROOT_STATE: u8 = 0x01;
/// Row tag for per-deposit garbler state.
pub const ROW_TAG_DEPOSIT_STATE: u8 = 0x02;
/// Row tag for input polynomial commitment chunk by wire index.
pub const ROW_TAG_INPUT_POLY_COMMITMENT_CHUNK: u8 = 0x03;
/// Row tag for output polynomial commitment singleton.
pub const ROW_TAG_OUTPUT_POLY_COMMITMENT: u8 = 0x04;
/// Row tag for input share by circuit index.
pub const ROW_TAG_INPUT_SHARE: u8 = 0x05;
/// Row tag for output share by circuit index.
pub const ROW_TAG_OUTPUT_SHARE: u8 = 0x06;
/// Row tag for garbling table commitment by zero-based circuit index.
pub const ROW_TAG_GARBLING_TABLE_COMMITMENT: u8 = 0x07;
/// Row tag for challenge indices singleton.
pub const ROW_TAG_CHALLENGE_INDICES: u8 = 0x08;
/// Row tag for deposit sighashes by deposit id.
pub const ROW_TAG_DEPOSIT_SIGHASHES: u8 = 0x09;
/// Row tag for deposit inputs by deposit id.
pub const ROW_TAG_DEPOSIT_INPUTS: u8 = 0x0A;
/// Row tag for withdrawal input by deposit id.
pub const ROW_TAG_WITHDRAWAL_INPUT: u8 = 0x0B;
/// Row tag for deposit adaptor chunk by deposit id and chunk index.
pub const ROW_TAG_DEPOSIT_ADAPTOR_CHUNK: u8 = 0x0C;
/// Row tag for withdrawal adaptor chunk by deposit id and chunk index.
pub const ROW_TAG_WITHDRAWAL_ADAPTOR_CHUNK: u8 = 0x0D;
/// Row tag for completed signatures by deposit id.
pub const ROW_TAG_COMPLETED_SIGNATURES: u8 = 0x0E;
/// Row tag for AES128 key by circuit index.
pub const ROW_TAG_AES128_KEY: u8 = 0x0F;
/// Row tag for public S by circuit index.
pub const ROW_TAG_PUBLIC_S: u8 = 0x10;
/// Row tag for constant-zero label by circuit index.
pub const ROW_TAG_CONSTANT_ZERO_LABEL: u8 = 0x11;
/// Row tag for constant-one label by circuit index.
pub const ROW_TAG_CONSTANT_ONE_LABEL: u8 = 0x12;
/// Row tag for output label ciphertext by evaluation-circuit index.
pub const ROW_TAG_OUTPUT_LABEL_CT: u8 = 0x13;

pub use deposit::*;
pub use protocol::*;
pub use state::*;
