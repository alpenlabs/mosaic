//! Connection utilities for the network service.
//!
//! This module provides utilities for extracting peer identity from QUIC connections.

use quinn::Connection;

use crate::tls::PeerId;

/// Extract the peer ID from a QUIC connection's certificate.
///
/// The peer ID is the 32-byte Ed25519 public key from the peer's certificate.
pub fn extract_peer_id(conn: &Connection) -> Option<PeerId> {
    // Get peer's certificate chain
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer>>()
        .ok()?;
    let cert = certs.first()?;

    // Parse the certificate to extract the public key
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let spki = parsed.public_key();
    let pubkey_bytes = spki.subject_public_key.as_ref();

    // Ed25519 public keys are exactly 32 bytes
    if pubkey_bytes.len() != 32 {
        return None;
    }

    let peer_id: [u8; 32] = pubkey_bytes.try_into().ok()?;
    Some(PeerId::from_bytes(peer_id))
}

#[cfg(test)]
mod tests {
    // Tests require actual QUIC connections which are tested in integration tests
}
