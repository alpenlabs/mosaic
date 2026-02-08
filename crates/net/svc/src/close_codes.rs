//! QUIC connection close error codes.
//!
//! These codes are used when closing QUIC connections to indicate the reason
//! for closure. They are passed to `connection.close(code, reason)` and can
//! be observed by the remote peer.
//!
//! # Code Assignments
//!
//! | Code | Meaning                                      |
//! |------|----------------------------------------------|
//! | 0    | Normal/expected closure (shutdown, replaced) |
//! | 1    | Invalid peer ID in certificate (incoming)    |
//! | 2    | Unknown/unauthorized peer                    |
//! | 3    | Invalid peer ID in certificate (outbound)    |
//! | 4    | Peer ID mismatch (connected to wrong peer)   |

use quinn::VarInt;

/// Normal closure - used for shutdown, redundant connections, or replacements.
///
/// This is not an error condition; the connection was closed intentionally
/// as part of normal operation.
pub const CLOSE_NORMAL: VarInt = VarInt::from_u32(0);

/// Invalid peer ID extracted from certificate (incoming connection).
///
/// The peer's TLS certificate did not contain a valid Ed25519 public key
/// in the expected format.
pub const CLOSE_INVALID_PEER_ID_INCOMING: VarInt = VarInt::from_u32(1);

/// Unknown or unauthorized peer.
///
/// The connecting peer is not in our allowed peers list.
pub const CLOSE_UNKNOWN_PEER: VarInt = VarInt::from_u32(2);

/// Invalid peer ID extracted from certificate (outbound connection).
///
/// The remote peer's TLS certificate did not contain a valid Ed25519 public key
/// in the expected format.
pub const CLOSE_INVALID_PEER_ID_OUTBOUND: VarInt = VarInt::from_u32(3);

/// Peer ID mismatch on outbound connection.
///
/// We connected to a peer, but their certificate contains a different peer ID
/// than we expected. This could indicate a misconfiguration or MITM attempt.
pub const CLOSE_PEER_ID_MISMATCH: VarInt = VarInt::from_u32(4);
