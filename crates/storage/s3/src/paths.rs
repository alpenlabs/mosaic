//! Object store path construction for garbling table components.

use mosaic_storage_api::table_store::TableId;
use object_store::path::Path;

/// Resolved object store paths for the three components of a garbling table.
#[derive(Debug, Clone)]
pub(crate) struct TablePaths {
    /// Path to the ciphertext stream object (~43 GB).
    pub ciphertexts: Path,
    /// Path to the translation material object (~4 MB).
    pub translation: Path,
    /// Path to the small metadata object (64 B serialised).
    pub metadata: Path,
}

impl TablePaths {
    /// Build paths for a table identified by `(prefix, peer_id, circuit_index)`.
    ///
    /// Layout:
    /// ```text
    /// {prefix}/{peer_id_hex}/{index}/ciphertexts
    /// {prefix}/{peer_id_hex}/{index}/translation
    /// {prefix}/{peer_id_hex}/{index}/metadata
    /// ```
    pub(crate) fn new(prefix: &str, id: &TableId) -> Self {
        let peer_hex = hex_encode(id.peer_id.as_bytes());
        let index = id.index.get();
        let base = format!("{prefix}/{peer_hex}/{index}");

        Self {
            ciphertexts: Path::from(format!("{base}/ciphertexts")),
            translation: Path::from(format!("{base}/translation")),
            metadata: Path::from(format!("{base}/metadata")),
        }
    }
}

/// Lowercase hex encoding of a byte slice (no 0x prefix).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use mosaic_net_svc_api::PeerId;
    use mosaic_vs3::Index;

    use super::*;

    #[test]
    fn paths_have_expected_structure() {
        let id = TableId {
            peer_id: PeerId::from_bytes([0xab; 32]),
            index: Index::new(42).unwrap(),
        };
        let paths = TablePaths::new("tables", &id);

        let peer_hex = "ab".repeat(32);
        assert_eq!(
            paths.ciphertexts.to_string(),
            format!("tables/{peer_hex}/42/ciphertexts")
        );
        assert_eq!(
            paths.translation.to_string(),
            format!("tables/{peer_hex}/42/translation")
        );
        assert_eq!(
            paths.metadata.to_string(),
            format!("tables/{peer_hex}/42/metadata")
        );
    }
}
