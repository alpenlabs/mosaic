//! Object store path construction for garbling table components.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use mosaic_storage_api::table_store::TableId;
use object_store::path::Path;

static VERSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Live marker object name under a table root.
const COMMITTED_MARKER: &str = "committed";

/// Root namespace for versioned table payload objects.
const VERSIONS_DIR: &str = "versions";

/// Root object-store paths for a specific table.
#[derive(Debug, Clone)]
pub(crate) struct TableRootPaths {
    /// Prefix for all objects belonging to the table.
    pub prefix: Path,
    /// Marker containing the currently committed version id.
    pub committed: Path,
}

/// Resolved paths for one immutable committed/staged table version.
#[derive(Debug, Clone)]
pub(crate) struct TableVersionPaths {
    /// Unique immutable version identifier.
    pub version: String,
    /// Path to the ciphertext stream object (~43 GB).
    pub ciphertexts: Path,
    /// Path to the translation material object (~4 MB).
    pub translation: Path,
    /// Path to the small metadata object (64 B serialised).
    pub metadata: Path,
}

impl TableRootPaths {
    /// Build root paths for a table identified by `(prefix, peer_id, circuit_index)`.
    pub(crate) fn new(prefix: &str, id: &TableId) -> Self {
        let peer_hex = hex_encode(id.peer_id.as_bytes());
        let index = id.index.get();
        let base = format!("{prefix}/{peer_hex}/{index}");

        Self {
            prefix: Path::from(base.clone()),
            committed: Path::from(format!("{base}/{COMMITTED_MARKER}")),
        }
    }

    /// Resolve object paths for an existing committed version id.
    pub(crate) fn version_paths(&self, version: impl Into<String>) -> TableVersionPaths {
        let version = version.into();
        let prefix = Path::from(format!("{}/{VERSIONS_DIR}/{}", self.prefix, version));

        TableVersionPaths {
            version,
            ciphertexts: Path::from(format!("{prefix}/ciphertexts")),
            translation: Path::from(format!("{prefix}/translation")),
            metadata: Path::from(format!("{prefix}/metadata")),
        }
    }

    /// Allocate a fresh immutable version id and return its object paths.
    pub(crate) fn allocate_version_paths(&self) -> TableVersionPaths {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let seq = VERSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.version_paths(format!("{nanos:032x}-{seq:016x}"))
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
    fn root_and_version_paths_have_expected_structure() {
        let id = TableId {
            peer_id: PeerId::from_bytes([0xab; 32]),
            index: Index::new(4).unwrap(),
        };
        let root = TableRootPaths::new("tables", &id);
        let version = root.version_paths("v1");

        let peer_hex = "ab".repeat(32);
        assert_eq!(root.prefix.to_string(), format!("tables/{peer_hex}/4"));
        assert_eq!(
            root.committed.to_string(),
            format!("tables/{peer_hex}/4/committed")
        );
        assert_eq!(
            version.ciphertexts.to_string(),
            format!("tables/{peer_hex}/4/versions/v1/ciphertexts")
        );
        assert_eq!(
            version.translation.to_string(),
            format!("tables/{peer_hex}/4/versions/v1/translation")
        );
        assert_eq!(
            version.metadata.to_string(),
            format!("tables/{peer_hex}/4/versions/v1/metadata")
        );
    }
}
