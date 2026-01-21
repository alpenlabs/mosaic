//! Wire format types and length-prefixed framing for net-svc.
//!
//! All messages on the wire are length-prefixed:
//! ```text
//! ┌─────────────────┬────────────────────────────┐
//! │ u32 length (LE) │ payload                    │
//! └─────────────────┴────────────────────────────┘
//! ```
//!
//! The first message on any stream is a [`StreamHeader`] indicating the stream type.

use std::mem::size_of;

// ============================================================================
// Frame Size Limits
// ============================================================================

/// Default maximum frame size (1 MB).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 1024;

/// Absolute maximum frame size (u32::MAX).
/// Individual connections may enforce smaller limits.
pub const ABSOLUTE_MAX_FRAME_SIZE: u32 = u32::MAX;

/// Frame size limit configuration.
#[derive(Debug, Clone, Copy)]
pub struct FrameLimits {
    /// Maximum frame size to accept when receiving.
    pub max_recv_size: u32,
    /// Maximum frame size to send (for validation).
    pub max_send_size: u32,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            max_recv_size: DEFAULT_MAX_FRAME_SIZE,
            max_send_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

impl FrameLimits {
    /// Create limits with specified max sizes.
    pub fn new(max_recv_size: u32, max_send_size: u32) -> Self {
        Self {
            max_recv_size,
            max_send_size,
        }
    }

    /// Create limits that allow any size (up to u32::MAX).
    pub fn unlimited() -> Self {
        Self {
            max_recv_size: ABSOLUTE_MAX_FRAME_SIZE,
            max_send_size: ABSOLUTE_MAX_FRAME_SIZE,
        }
    }

    /// Check if a payload size is valid for sending.
    pub fn can_send(&self, payload_len: usize) -> bool {
        payload_len <= self.max_send_size as usize
    }

    /// Check if a payload size is valid for receiving.
    pub fn can_recv(&self, payload_len: u32) -> bool {
        payload_len <= self.max_recv_size
    }
}

// ============================================================================
// Stream Header
// ============================================================================

/// Header sent at the start of every stream to indicate its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    pub stream_type: StreamType,
}

impl StreamHeader {
    /// Create a new stream header.
    pub fn new(stream_type: StreamType) -> Self {
        Self { stream_type }
    }

    /// Create a protocol stream header.
    pub fn protocol() -> Self {
        Self::new(StreamType::Protocol)
    }

    /// Create a bulk transfer stream header.
    pub fn bulk_transfer(identifier: [u8; 32]) -> Self {
        Self::new(StreamType::BulkTransfer { identifier })
    }

    /// Encode the header into bytes.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match &self.stream_type {
            StreamType::Protocol => {
                buf.push(0x00);
            }
            StreamType::BulkTransfer { identifier } => {
                buf.push(0x01);
                buf.extend_from_slice(identifier);
            }
        }
    }

    /// Get the encoded size of this header.
    pub fn encoded_size(&self) -> usize {
        match &self.stream_type {
            StreamType::Protocol => 1,
            StreamType::BulkTransfer { .. } => 1 + 32,
        }
    }

    /// Decode a header from bytes.
    /// Returns the header and number of bytes consumed.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::Incomplete { needed: 1 });
        }

        match bytes[0] {
            0x00 => Ok((Self::new(StreamType::Protocol), 1)),
            0x01 => {
                if bytes.len() < 33 {
                    return Err(DecodeError::Incomplete {
                        needed: 33 - bytes.len(),
                    });
                }
                let identifier: [u8; 32] =
                    bytes[1..33].try_into().expect("slice is exactly 32 bytes");
                Ok((Self::new(StreamType::BulkTransfer { identifier }), 33))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

/// Type of stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Protocol message stream (normal priority).
    Protocol,
    /// Bulk transfer stream (low priority).
    /// The identifier is used by the receiver to route to the correct handler.
    BulkTransfer {
        /// 32-byte identifier (typically a commitment hash).
        identifier: [u8; 32],
    },
}

impl StreamType {
    /// Check if this is a protocol stream.
    pub fn is_protocol(&self) -> bool {
        matches!(self, StreamType::Protocol)
    }

    /// Check if this is a bulk transfer stream.
    pub fn is_bulk_transfer(&self) -> bool {
        matches!(self, StreamType::BulkTransfer { .. })
    }

    /// Get the identifier if this is a bulk transfer.
    pub fn bulk_identifier(&self) -> Option<&[u8; 32]> {
        match self {
            StreamType::BulkTransfer { identifier } => Some(identifier),
            _ => None,
        }
    }
}

// ============================================================================
// Length-Prefixed Framing
// ============================================================================

/// Size of the length prefix in bytes.
pub const LENGTH_PREFIX_SIZE: usize = size_of::<u32>();

/// Encode a frame with length prefix.
///
/// Format: `[u32 length (LE)][payload]`
///
/// Returns an error if the payload exceeds the configured limit.
pub fn encode_frame(
    payload: &[u8],
    buf: &mut Vec<u8>,
    limits: &FrameLimits,
) -> Result<(), EncodeError> {
    if !limits.can_send(payload.len()) {
        return Err(EncodeError::PayloadTooLarge {
            size: payload.len(),
            max: limits.max_send_size as usize,
        });
    }

    let len = payload.len() as u32;
    buf.reserve(LENGTH_PREFIX_SIZE + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    Ok(())
}

/// Encode a frame with length prefix using default limits.
pub fn encode_frame_default(payload: &[u8], buf: &mut Vec<u8>) -> Result<(), EncodeError> {
    encode_frame(payload, buf, &FrameLimits::default())
}

/// Encode a frame with no size limit (only u32::MAX).
pub fn encode_frame_unchecked(payload: &[u8], buf: &mut Vec<u8>) -> Result<(), EncodeError> {
    if payload.len() > ABSOLUTE_MAX_FRAME_SIZE as usize {
        return Err(EncodeError::PayloadTooLarge {
            size: payload.len(),
            max: ABSOLUTE_MAX_FRAME_SIZE as usize,
        });
    }

    let len = payload.len() as u32;
    buf.reserve(LENGTH_PREFIX_SIZE + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    Ok(())
}

/// Try to decode a frame from a buffer.
///
/// Returns `(payload, bytes_consumed)` on success.
/// Returns `Incomplete` if more data is needed.
/// Returns `FrameTooLarge` if the frame exceeds the configured limit.
pub fn decode_frame(buf: &[u8], limits: &FrameLimits) -> Result<(Vec<u8>, usize), DecodeError> {
    if buf.len() < LENGTH_PREFIX_SIZE {
        return Err(DecodeError::Incomplete {
            needed: LENGTH_PREFIX_SIZE - buf.len(),
        });
    }

    let len = u32::from_le_bytes(buf[0..4].try_into().expect("slice is 4 bytes"));

    if !limits.can_recv(len) {
        return Err(DecodeError::FrameTooLarge {
            size: len as usize,
            max: limits.max_recv_size as usize,
        });
    }

    let total = LENGTH_PREFIX_SIZE + len as usize;
    if buf.len() < total {
        return Err(DecodeError::Incomplete {
            needed: total - buf.len(),
        });
    }

    let payload = buf[LENGTH_PREFIX_SIZE..total].to_vec();
    Ok((payload, total))
}

/// Decode a frame using default limits.
pub fn decode_frame_default(buf: &[u8]) -> Result<(Vec<u8>, usize), DecodeError> {
    decode_frame(buf, &FrameLimits::default())
}

/// Peek at the frame length without consuming bytes.
/// Returns `None` if not enough bytes for the length prefix.
pub fn peek_frame_length(buf: &[u8]) -> Option<u32> {
    if buf.len() < LENGTH_PREFIX_SIZE {
        return None;
    }
    Some(u32::from_le_bytes(
        buf[0..4].try_into().expect("slice is 4 bytes"),
    ))
}

// ============================================================================
// Errors
// ============================================================================

/// Error encoding a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Payload exceeds maximum allowed size.
    PayloadTooLarge { size: usize, max: usize },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload too large: {} bytes (max {})", size, max)
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Error decoding a frame or header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Need more bytes to complete decoding.
    Incomplete { needed: usize },
    /// Frame exceeds maximum allowed size.
    FrameTooLarge { size: usize, max: usize },
    /// Invalid stream type tag.
    InvalidTag { tag: u8 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete { needed } => {
                write!(f, "incomplete: need {} more bytes", needed)
            }
            Self::FrameTooLarge { size, max } => {
                write!(f, "frame too large: {} bytes (max {})", size, max)
            }
            Self::InvalidTag { tag } => {
                write!(f, "invalid stream type tag: 0x{:02x}", tag)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

impl DecodeError {
    /// Check if this is an incomplete error (need more data).
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }

    /// Check if this is a fatal error (won't be resolved with more data).
    pub fn is_fatal(&self) -> bool {
        !self.is_incomplete()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_header_protocol_roundtrip() {
        let header = StreamHeader::protocol();
        let mut buf = Vec::new();
        header.encode(&mut buf);

        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0x00);

        let (decoded, consumed) = StreamHeader::decode(&buf).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn stream_header_bulk_transfer_roundtrip() {
        let identifier = [0xab; 32];
        let header = StreamHeader::bulk_transfer(identifier);
        let mut buf = Vec::new();
        header.encode(&mut buf);

        assert_eq!(buf.len(), 33);
        assert_eq!(buf[0], 0x01);
        assert_eq!(&buf[1..33], &identifier);

        let (decoded, consumed) = StreamHeader::decode(&buf).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, 33);
    }

    #[test]
    fn stream_header_decode_incomplete() {
        let err = StreamHeader::decode(&[]).unwrap_err();
        assert!(err.is_incomplete());

        let err = StreamHeader::decode(&[0x01]).unwrap_err();
        assert!(err.is_incomplete());

        let err = StreamHeader::decode(&[0x01; 20]).unwrap_err();
        assert!(err.is_incomplete());
    }

    #[test]
    fn stream_header_decode_invalid_tag() {
        let err = StreamHeader::decode(&[0xff]).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidTag { tag: 0xff }));
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        encode_frame_default(payload, &mut buf).unwrap();

        assert_eq!(buf.len(), 4 + payload.len());
        assert_eq!(&buf[0..4], &(payload.len() as u32).to_le_bytes());
        assert_eq!(&buf[4..], payload);

        let (decoded, consumed) = decode_frame_default(&buf).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_decode_incomplete() {
        // Not enough for length prefix
        let err = decode_frame_default(&[0x00, 0x00]).unwrap_err();
        assert!(err.is_incomplete());

        // Length says 10 bytes, only 5 present
        let buf = [0x0a, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let err = decode_frame_default(&buf).unwrap_err();
        assert!(err.is_incomplete());
    }

    #[test]
    fn frame_too_large_encode() {
        let limits = FrameLimits::new(1024, 1024);
        let payload = vec![0u8; 2000];
        let mut buf = Vec::new();

        let err = encode_frame(&payload, &mut buf, &limits).unwrap_err();
        assert!(matches!(err, EncodeError::PayloadTooLarge { .. }));
    }

    #[test]
    fn frame_too_large_decode() {
        let limits = FrameLimits::new(1024, 1024);

        // Encode a "valid" frame header claiming 2000 bytes
        let mut buf = Vec::new();
        buf.extend_from_slice(&2000u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 2000]);

        let err = decode_frame(&buf, &limits).unwrap_err();
        assert!(matches!(err, DecodeError::FrameTooLarge { .. }));
    }

    #[test]
    fn peek_frame_length_works() {
        let mut buf = Vec::new();
        encode_frame_default(b"test data", &mut buf).unwrap();

        assert_eq!(peek_frame_length(&buf), Some(9));
        assert_eq!(peek_frame_length(&buf[0..2]), None);
    }

    #[test]
    fn frame_limits_default() {
        let limits = FrameLimits::default();
        assert_eq!(limits.max_recv_size, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(limits.max_send_size, DEFAULT_MAX_FRAME_SIZE);
    }

    #[test]
    fn frame_limits_unlimited() {
        let limits = FrameLimits::unlimited();
        assert!(limits.can_send(u32::MAX as usize));
        assert!(limits.can_recv(u32::MAX));
    }

    #[test]
    fn stream_type_helpers() {
        let proto = StreamType::Protocol;
        assert!(proto.is_protocol());
        assert!(!proto.is_bulk_transfer());
        assert!(proto.bulk_identifier().is_none());

        let bulk = StreamType::BulkTransfer {
            identifier: [0x42; 32],
        };
        assert!(!bulk.is_protocol());
        assert!(bulk.is_bulk_transfer());
        assert_eq!(bulk.bulk_identifier(), Some(&[0x42; 32]));
    }
}
