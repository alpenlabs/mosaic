//! Version handshake exchanged as the first app-layer message after QUIC TLS
//! authentication completes.
//!
//! Two fields are exchanged:
//!
//! - [`HandshakePayload::protocol_version`] — code-level compatibility marker. A
//!   manually-maintained `u32` ([`PROTOCOL_VERSION`]) bumped whenever the wire-visible protocol
//!   surface changes (message types in `cac/types` / `cac/protocol`, net-svc wire framing,
//!   garbler/evaluator STF semantics peers depend on). Mismatch → refuse communication.
//! - [`HandshakePayload::deployment_version`] — operator-supplied cohort identifier
//!   (`Option<String>`). All-or-none: every operator in a coordinated deployment sets the same
//!   string (e.g. `"tn3"`); single-operator dev / local testing leaves it unset. Asymmetric or
//!   mismatched → refuse.
//!
//! The handshake runs on a dedicated bi-stream opened immediately after QUIC
//! TLS completes and the peer-identity has been verified. No protocol streams
//! are opened until the handshake succeeds on both sides.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Current protocol version.
///
/// **Bump this constant whenever a wire-visible protocol change ships.** The
/// surface that needs tracking:
///
/// - Message types and serialization in `crates/cac/types`
/// - Garbler/evaluator state machine semantics in `crates/cac/protocol` that change what peers send
///   or expect
/// - net-svc wire framing or stream priorities in `crates/net/svc`
///
/// We deliberately use a manual constant (not a git-hash or content-hash) so
/// that protocol-irrelevant commits don't sever connectivity. The PR template
/// includes a "touches wire-visible surface" checkbox to make this visible at
/// review time.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum number of bytes the receiver will read for a handshake payload.
/// Sized comfortably above the largest legitimate payload (protocol version
/// + optional ~64-byte deployment string + ark-serialize overhead).
pub const MAX_HANDSHAKE_PAYLOAD_BYTES: usize = 256;

/// Maximum length of the deployment-version string in bytes. Anything longer
/// is rejected at deserialize time, before any peer-controlled allocation.
pub const MAX_DEPLOYMENT_VERSION_LEN: usize = 64;

/// Magic prefix identifying a mosaic version handshake payload. Lets the
/// receiver fail fast on a stream that was opened against the wrong service or
/// carrying an unrelated payload.
pub const HANDSHAKE_MAGIC: [u8; 4] = *b"Zk2u";

/// Payload exchanged on the version-handshake stream.
///
/// Encoded with ark-serialize (consistent with the rest of the mosaic wire
/// surface). The receiver MUST refuse to read more than
/// [`MAX_HANDSHAKE_PAYLOAD_BYTES`] bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePayload {
    /// See [`HANDSHAKE_MAGIC`]. Always set to that value on send.
    pub magic: [u8; 4],
    /// See [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Optional operator-coordinated cohort identifier. `None` for
    /// uncoordinated deployments; `Some` for coordinated cohorts where every
    /// operator must set the same value.
    pub deployment_version: Option<String>,
    /// Whether this node is built / configured to run reduced-circuits mode.
    /// Hard-matched: peers with different values cannot interop because the
    /// circuit definitions (and therefore tableset shapes, wire counts, and
    /// commitment material) diverge.
    pub reduced_circuits: bool,
}

impl HandshakePayload {
    /// Construct the local payload for this node.
    pub fn new(deployment_version: Option<String>, reduced_circuits: bool) -> Self {
        Self {
            magic: HANDSHAKE_MAGIC,
            protocol_version: PROTOCOL_VERSION,
            deployment_version,
            reduced_circuits,
        }
    }
}

// Manual ark-serialize impl. We deliberately don't derive because we want the
// deployment-version length cap enforced at decode time, before allocation.
impl CanonicalSerialize for HandshakePayload {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.magic.serialize_with_mode(&mut writer, compress)?;
        self.protocol_version
            .serialize_with_mode(&mut writer, compress)?;
        match &self.deployment_version {
            None => 0u8.serialize_with_mode(&mut writer, compress)?,
            Some(s) => {
                if s.len() > MAX_DEPLOYMENT_VERSION_LEN {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                1u8.serialize_with_mode(&mut writer, compress)?;
                (s.len() as u8).serialize_with_mode(&mut writer, compress)?;
                writer.write_all(s.as_bytes())?;
            }
        }
        (self.reduced_circuits as u8).serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let base = self.magic.serialized_size(compress)
            + self.protocol_version.serialized_size(compress)
            + 0u8.serialized_size(compress); // reduced_circuits byte
        match &self.deployment_version {
            None => base + 0u8.serialized_size(compress),
            Some(s) => {
                base + 0u8.serialized_size(compress) + 0u8.serialized_size(compress) + s.len()
            }
        }
    }
}

impl ark_serialize::Valid for HandshakePayload {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        if self.magic != HANDSHAKE_MAGIC {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        if let Some(s) = &self.deployment_version
            && s.len() > MAX_DEPLOYMENT_VERSION_LEN
        {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        Ok(())
    }
}

impl CanonicalDeserialize for HandshakePayload {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let magic = <[u8; 4]>::deserialize_with_mode(&mut reader, compress, validate)?;
        if magic != HANDSHAKE_MAGIC {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let protocol_version = u32::deserialize_with_mode(&mut reader, compress, validate)?;
        let has_deployment = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        let deployment_version = match has_deployment {
            0 => None,
            1 => {
                let len = u8::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                if len > MAX_DEPLOYMENT_VERSION_LEN {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                let s = String::from_utf8(buf)
                    .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
                Some(s)
            }
            _ => return Err(ark_serialize::SerializationError::InvalidData),
        };
        let reduced_byte = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        let reduced_circuits = match reduced_byte {
            0 => false,
            1 => true,
            _ => return Err(ark_serialize::SerializationError::InvalidData),
        };
        Ok(Self {
            magic,
            protocol_version,
            deployment_version,
            reduced_circuits,
        })
    }
}

/// Reason a handshake was rejected. Distinct from a transport error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMismatch {
    /// Magic prefix did not match — either a stream from an unrelated service
    /// or a malformed handshake.
    MagicMismatch,
    /// Protocol versions differed. Operators are running incompatible builds.
    ProtocolVersionMismatch { local: u32, remote: u32 },
    /// Both peers set a `deployment_version` but they differ.
    DeploymentVersionMismatch { local: String, remote: String },
    /// Local has `deployment_version` set, remote does not.
    DeploymentVersionMissingRemote { local: String },
    /// Remote has `deployment_version` set, local does not.
    DeploymentVersionMissingLocal { remote: String },
    /// Reduced-circuits mode differed. One side is running full circuits and
    /// the other reduced (or vice versa) — wire-incompatible because the
    /// circuit shape diverges.
    ReducedCircuitsMismatch { local: bool, remote: bool },
}

impl HandshakeMismatch {
    /// Short, log-safe reason string.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::MagicMismatch => "magic mismatch",
            Self::ProtocolVersionMismatch { .. } => "protocol version mismatch",
            Self::DeploymentVersionMismatch { .. } => "deployment version mismatch",
            Self::DeploymentVersionMissingRemote { .. } => {
                "remote missing deployment version (local set)"
            }
            Self::DeploymentVersionMissingLocal { .. } => {
                "local missing deployment version (remote set)"
            }
            Self::ReducedCircuitsMismatch { .. } => "reduced-circuits mode mismatch",
        }
    }
}

impl std::fmt::Display for HandshakeMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MagicMismatch => write!(f, "{}", self.reason()),
            Self::ProtocolVersionMismatch { local, remote } => {
                write!(f, "{}: local={local} remote={remote}", self.reason())
            }
            Self::DeploymentVersionMismatch { local, remote } => {
                write!(f, "{}: local={local:?} remote={remote:?}", self.reason())
            }
            Self::DeploymentVersionMissingRemote { local } => {
                write!(f, "{}: local={local:?}", self.reason())
            }
            Self::DeploymentVersionMissingLocal { remote } => {
                write!(f, "{}: remote={remote:?}", self.reason())
            }
            Self::ReducedCircuitsMismatch { local, remote } => {
                write!(f, "{}: local={local} remote={remote}", self.reason())
            }
        }
    }
}

impl std::error::Error for HandshakeMismatch {}

/// Validate a received handshake payload against the local configuration.
/// `local_deployment_version` is the deployment-version this node is
/// configured with (or `None` for uncoordinated single-operator dev).
/// `local_reduced_circuits` is whether this node is running reduced circuits.
pub fn validate_handshake(
    local_protocol_version: u32,
    local_deployment_version: Option<&str>,
    local_reduced_circuits: bool,
    remote: &HandshakePayload,
) -> Result<(), HandshakeMismatch> {
    if remote.magic != HANDSHAKE_MAGIC {
        return Err(HandshakeMismatch::MagicMismatch);
    }
    if remote.protocol_version != local_protocol_version {
        return Err(HandshakeMismatch::ProtocolVersionMismatch {
            local: local_protocol_version,
            remote: remote.protocol_version,
        });
    }
    if remote.reduced_circuits != local_reduced_circuits {
        return Err(HandshakeMismatch::ReducedCircuitsMismatch {
            local: local_reduced_circuits,
            remote: remote.reduced_circuits,
        });
    }
    match (local_deployment_version, &remote.deployment_version) {
        (None, None) => Ok(()),
        (Some(l), Some(r)) if l == r => Ok(()),
        (Some(l), Some(r)) => Err(HandshakeMismatch::DeploymentVersionMismatch {
            local: l.to_string(),
            remote: r.clone(),
        }),
        (Some(l), None) => Err(HandshakeMismatch::DeploymentVersionMissingRemote {
            local: l.to_string(),
        }),
        (None, Some(r)) => {
            Err(HandshakeMismatch::DeploymentVersionMissingLocal { remote: r.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_serialize::{Compress, Validate};

    use super::*;

    fn roundtrip(payload: &HandshakePayload) -> HandshakePayload {
        let mut buf = Vec::new();
        payload
            .serialize_with_mode(&mut buf, Compress::No)
            .expect("serialize");
        assert!(
            buf.len() <= MAX_HANDSHAKE_PAYLOAD_BYTES,
            "encoded payload exceeds MAX_HANDSHAKE_PAYLOAD_BYTES"
        );
        HandshakePayload::deserialize_with_mode(buf.as_slice(), Compress::No, Validate::Yes)
            .expect("deserialize")
    }

    #[test]
    fn roundtrip_no_deployment_version() {
        for rc in [false, true] {
            let p = HandshakePayload::new(None, rc);
            assert_eq!(roundtrip(&p), p);
        }
    }

    #[test]
    fn roundtrip_with_deployment_version() {
        for rc in [false, true] {
            let p = HandshakePayload::new(Some("tn3".to_string()), rc);
            assert_eq!(roundtrip(&p), p);
        }
    }

    #[test]
    fn roundtrip_with_max_length_deployment_version() {
        let s = "x".repeat(MAX_DEPLOYMENT_VERSION_LEN);
        let p = HandshakePayload::new(Some(s), true);
        assert_eq!(roundtrip(&p), p);
    }

    #[test]
    fn over_length_deployment_version_fails_to_serialize() {
        let s = "x".repeat(MAX_DEPLOYMENT_VERSION_LEN + 1);
        let p = HandshakePayload::new(Some(s), false);
        let mut buf = Vec::new();
        assert!(p.serialize_with_mode(&mut buf, Compress::No).is_err());
    }

    #[test]
    fn over_length_deployment_version_fails_to_deserialize() {
        // Hand-construct a payload with a deployment-version length byte that
        // exceeds the cap. Receivers MUST reject before allocating the buffer.
        let mut buf = Vec::new();
        buf.extend_from_slice(&HANDSHAKE_MAGIC);
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(1u8); // has_deployment
        buf.push((MAX_DEPLOYMENT_VERSION_LEN as u8) + 1); // over-cap length
        buf.extend(std::iter::repeat_n(b'x', MAX_DEPLOYMENT_VERSION_LEN + 1));
        buf.push(0u8); // reduced_circuits
        let r =
            HandshakePayload::deserialize_with_mode(buf.as_slice(), Compress::No, Validate::Yes);
        assert!(r.is_err());
    }

    #[test]
    fn bad_magic_fails_to_deserialize() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"XXXX");
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(0u8);
        buf.push(0u8); // reduced_circuits
        let r =
            HandshakePayload::deserialize_with_mode(buf.as_slice(), Compress::No, Validate::Yes);
        assert!(r.is_err());
    }

    #[test]
    fn invalid_reduced_circuits_byte_fails_to_deserialize() {
        // Anything other than 0/1 in the reduced_circuits position is invalid.
        let mut buf = Vec::new();
        buf.extend_from_slice(&HANDSHAKE_MAGIC);
        buf.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        buf.push(0u8); // no deployment
        buf.push(2u8); // invalid reduced_circuits
        let r =
            HandshakePayload::deserialize_with_mode(buf.as_slice(), Compress::No, Validate::Yes);
        assert!(r.is_err());
    }

    #[test]
    fn validate_matching_passes() {
        let remote = HandshakePayload::new(Some("tn3".to_string()), true);
        assert!(validate_handshake(PROTOCOL_VERSION, Some("tn3"), true, &remote).is_ok());
    }

    #[test]
    fn validate_no_deployment_passes() {
        let remote = HandshakePayload::new(None, false);
        assert!(validate_handshake(PROTOCOL_VERSION, None, false, &remote).is_ok());
    }

    #[test]
    fn validate_protocol_mismatch_rejects() {
        let mut remote = HandshakePayload::new(None, false);
        remote.protocol_version = PROTOCOL_VERSION.wrapping_add(1);
        let err = validate_handshake(PROTOCOL_VERSION, None, false, &remote).unwrap_err();
        assert!(matches!(
            err,
            HandshakeMismatch::ProtocolVersionMismatch { .. }
        ));
    }

    #[test]
    fn validate_deployment_mismatch_rejects() {
        let remote = HandshakePayload::new(Some("tn4".to_string()), false);
        let err = validate_handshake(PROTOCOL_VERSION, Some("tn3"), false, &remote).unwrap_err();
        assert!(matches!(
            err,
            HandshakeMismatch::DeploymentVersionMismatch { .. }
        ));
    }

    #[test]
    fn validate_deployment_asymmetry_rejects_both_directions() {
        let local_set = HandshakePayload::new(None, false);
        let err = validate_handshake(PROTOCOL_VERSION, Some("tn3"), false, &local_set).unwrap_err();
        assert!(matches!(
            err,
            HandshakeMismatch::DeploymentVersionMissingRemote { .. }
        ));

        let remote_set = HandshakePayload::new(Some("tn3".to_string()), false);
        let err = validate_handshake(PROTOCOL_VERSION, None, false, &remote_set).unwrap_err();
        assert!(matches!(
            err,
            HandshakeMismatch::DeploymentVersionMissingLocal { .. }
        ));
    }

    #[test]
    fn validate_bad_magic_rejects() {
        let mut remote = HandshakePayload::new(None, false);
        remote.magic = [0u8; 4];
        let err = validate_handshake(PROTOCOL_VERSION, None, false, &remote).unwrap_err();
        assert!(matches!(err, HandshakeMismatch::MagicMismatch));
    }

    #[test]
    fn validate_reduced_circuits_mismatch_rejects_both_directions() {
        let remote_reduced = HandshakePayload::new(None, true);
        let err = validate_handshake(PROTOCOL_VERSION, None, false, &remote_reduced).unwrap_err();
        match err {
            HandshakeMismatch::ReducedCircuitsMismatch { local, remote } => {
                assert!(!local);
                assert!(remote);
            }
            other => panic!("expected ReducedCircuitsMismatch, got {other:?}"),
        }

        let remote_full = HandshakePayload::new(None, false);
        let err = validate_handshake(PROTOCOL_VERSION, None, true, &remote_full).unwrap_err();
        match err {
            HandshakeMismatch::ReducedCircuitsMismatch { local, remote } => {
                assert!(local);
                assert!(!remote);
            }
            other => panic!("expected ReducedCircuitsMismatch, got {other:?}"),
        }
    }
}
