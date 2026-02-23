mod deposit;
mod state;

/// Garbler row tags.
///
/// Reserve a contiguous range from `0x01..=0x3F` for garbler rows.
pub const ROW_TAG_ROOT_STATE: u8 = 0x01;
pub const ROW_TAG_DEPOSIT_STATE: u8 = 0x02;

pub use deposit::*;
pub use state::*;
