//! TLS configuration for QUIC with Ed25519 peer authentication.
//!
//! This module provides a simple public-key based authentication scheme:
//! - Each peer has an Ed25519 keypair
//! - PeerId is the 32-byte public key
//! - Self-signed certificates wrap the keypair (required by TLS)
//! - Custom verifier ignores CA chains, only checks if public key is in allowed set

use std::{collections::HashSet, fmt, sync::Arc};

use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};

// Re-export peer identity types from svc-api so existing `crate::tls::PeerId` paths
// and `use super::*` in tests continue to work.
pub use mosaic_net_svc_api::peer_id::{
    PeerId, peer_id_from_signing_key, peer_id_from_verifying_key,
};
use quinn::{ClientConfig, ServerConfig};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};

/// Generate a self-signed certificate from an Ed25519 signing key.
///
/// The certificate is minimal - just enough to satisfy TLS requirements.
/// The actual authentication happens via [`PeerVerifier`] checking the public key.
pub fn generate_self_signed_cert(
    signing_key: &SigningKey,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CertGenError> {
    use rcgen::{CertificateParams, KeyPair};

    // Convert ed25519-dalek key to PKCS#8 DER format for rcgen
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|_| CertGenError::KeyConversion)?;

    let key_pair =
        KeyPair::try_from(pkcs8_der.as_bytes()).map_err(|_| CertGenError::KeyConversion)?;

    // Minimal certificate parameters
    let params = CertificateParams::new(vec!["mosaic.local".to_string()])
        .map_err(|_| CertGenError::InvalidParams)?;

    // Self-sign with our key pair
    let cert = params
        .self_signed(&key_pair)
        .map_err(|_| CertGenError::Signing)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes().to_vec()));

    Ok((cert_der, key_der))
}

/// Error generating self-signed certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertGenError {
    KeyConversion,
    InvalidParams,
    Signing,
}

impl fmt::Display for CertGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyConversion => write!(f, "failed to convert signing key"),
            Self::InvalidParams => write!(f, "invalid certificate parameters"),
            Self::Signing => write!(f, "failed to self-sign certificate"),
        }
    }
}

impl std::error::Error for CertGenError {}

/// Custom certificate verifier that authenticates peers by their Ed25519 public key.
///
/// Ignores CA chains and certificate validity periods - only checks if the
/// certificate's public key is in the allowed peer set.
#[derive(Debug)]
pub struct PeerVerifier {
    allowed_peers: HashSet<PeerId>,
    crypto_provider: Arc<CryptoProvider>,
}

impl PeerVerifier {
    /// Create a new verifier with the given set of allowed peer public keys.
    pub fn new(allowed_peers: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            allowed_peers: allowed_peers.into_iter().collect(),
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// Add a peer to the allowed set.
    pub fn add_peer(&mut self, peer: PeerId) {
        self.allowed_peers.insert(peer);
    }

    /// Remove a peer from the allowed set.
    pub fn remove_peer(&mut self, peer: &PeerId) -> bool {
        self.allowed_peers.remove(peer)
    }

    /// Check if a peer is in the allowed set.
    pub fn is_allowed(&self, peer: &PeerId) -> bool {
        self.allowed_peers.contains(peer)
    }

    /// Extract and verify the peer ID from a certificate.
    fn verify_peer_cert(&self, cert: &CertificateDer<'_>) -> Result<PeerId, TlsError> {
        // Parse X.509 certificate
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

        // Extract the public key from the SubjectPublicKeyInfo
        let spki = parsed.public_key();

        // Ed25519 public keys are 32 bytes
        // The subject_public_key bit string contains the raw key
        let pubkey_data = spki.subject_public_key.as_ref();
        let pubkey_bytes: PeerId = pubkey_data
            .try_into()
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

        // Check if this peer is allowed
        if self.allowed_peers.contains(&pubkey_bytes) {
            Ok(pubkey_bytes)
        } else {
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.verify_peer_cert(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for PeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA roots - we verify by public key
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.verify_peer_cert(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        // Require client certificates - both sides must authenticate
        true
    }
}

/// Create a QUIC client configuration with Ed25519 peer authentication.
///
/// The client will present its own certificate and verify that the server's
/// public key is in the `allowed_peers` set.
pub fn make_client_config(
    signing_key: &SigningKey,
    allowed_peers: impl IntoIterator<Item = PeerId>,
) -> Result<ClientConfig, ConfigError> {
    let (cert, key) = generate_self_signed_cert(signing_key).map_err(ConfigError::CertGen)?;

    let verifier = Arc::new(PeerVerifier::new(allowed_peers));

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(|_| ConfigError::InvalidKey)?;

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|_| ConfigError::QuicConfig)?;

    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

/// Create a QUIC server configuration with Ed25519 peer authentication.
///
/// The server will present its own certificate and require clients to present
/// certificates with public keys in the `allowed_peers` set.
pub fn make_server_config(
    signing_key: &SigningKey,
    allowed_peers: impl IntoIterator<Item = PeerId>,
) -> Result<ServerConfig, ConfigError> {
    let (cert, key) = generate_self_signed_cert(signing_key).map_err(ConfigError::CertGen)?;

    let verifier = Arc::new(PeerVerifier::new(allowed_peers));

    let crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|_| ConfigError::InvalidKey)?;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|_| ConfigError::QuicConfig)?;

    Ok(ServerConfig::with_crypto(Arc::new(quic_crypto)))
}

/// Error creating QUIC configuration.
#[derive(Debug)]
pub enum ConfigError {
    CertGen(CertGenError),
    InvalidKey,
    QuicConfig,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertGen(e) => write!(f, "certificate generation failed: {}", e),
            Self::InvalidKey => write!(f, "invalid key for TLS"),
            Self::QuicConfig => write!(f, "failed to create QUIC config"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CertGen(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_key() -> SigningKey {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn peer_id_round_trip() {
        let signing_key = generate_test_key();
        let peer_id = peer_id_from_signing_key(&signing_key);
        let verifying_key = signing_key.verifying_key();

        assert_eq!(peer_id, peer_id_from_verifying_key(&verifying_key));
        assert_eq!(*peer_id.as_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn generate_cert_works() {
        let signing_key = generate_test_key();
        let (cert, _key) = generate_self_signed_cert(&signing_key).unwrap();

        // Should be parseable
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();

        // Public key should match
        let pubkey_data = parsed.public_key().subject_public_key.as_ref();
        let pubkey: PeerId = pubkey_data.try_into().unwrap();
        assert_eq!(pubkey, peer_id_from_signing_key(&signing_key));
    }

    #[test]
    fn verifier_allows_known_peer() {
        let signing_key = generate_test_key();
        let peer_id = peer_id_from_signing_key(&signing_key);
        let (cert, _) = generate_self_signed_cert(&signing_key).unwrap();

        let verifier = PeerVerifier::new([peer_id]);
        assert!(verifier.verify_peer_cert(&cert).is_ok());
    }

    #[test]
    fn verifier_rejects_unknown_peer() {
        let signing_key = generate_test_key();
        let (cert, _) = generate_self_signed_cert(&signing_key).unwrap();

        // Different peer in allowed set
        let other_key = generate_test_key();
        let verifier = PeerVerifier::new([peer_id_from_signing_key(&other_key)]);

        assert!(verifier.verify_peer_cert(&cert).is_err());
    }

    #[test]
    fn make_configs_works() {
        let server_key = generate_test_key();
        let client_key = generate_test_key();

        let server_id = peer_id_from_signing_key(&server_key);
        let client_id = peer_id_from_signing_key(&client_key);

        // Server allows client, client allows server
        let _server_config = make_server_config(&server_key, [client_id]).unwrap();
        let _client_config = make_client_config(&client_key, [server_id]).unwrap();
    }
}
