//! Generic encode to bytes/decode from bytes traits.

/// Trait for encoding to bytes.
pub trait Encode {
    /// Encode self into a byte vector.
    fn encode(&self) -> Result<Vec<u8>, String>;
}

/// Trait for decoding from bytes.
pub trait Decode: Sized {
    /// Decode from a byte slice.
    fn decode(bytes: &[u8]) -> Result<Self, String>;
}
