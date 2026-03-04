//! Keyspace envelope helpers for typed row specs.

use std::ops::Bound;

use crate::row_spec::{KVRowSpec, PackableKey, error::KeyspaceDecodeError};

/// Key schema version encoded as the first byte of every namespacing prefix.
pub const KEY_SCHEMA_VERSION: u8 = 1;

/// Top-level key domain, used by concrete `StorageProvider` implementations
/// to build namespacing prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyDomain {
    /// Garbler storage rows.
    Garbler = 1,
    /// Evaluator storage rows.
    Evaluator = 2,
}

impl KeyDomain {
    pub(crate) const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Build the row prefix: `[row_tag]`.
pub fn row_prefix<R: KVRowSpec>() -> Vec<u8> {
    vec![R::ROW_TAG]
}

/// Build a full key by appending row-local key bytes to the row prefix.
pub fn full_key<R: KVRowSpec>(
    key: &R::Key,
) -> Result<Vec<u8>, <R::Key as PackableKey>::PackingError> {
    let mut out = row_prefix::<R>();
    let row_local = key.pack()?;
    out.extend_from_slice(row_local.as_ref());
    Ok(out)
}

/// Decode a row-local key from a full key, validating the row-tag prefix.
pub fn split_row_key<R: KVRowSpec>(
    full: &[u8],
) -> Result<R::Key, KeyspaceDecodeError<<R::Key as PackableKey>::UnpackingError>> {
    let expected_prefix = row_prefix::<R>();
    if let Some(row_key) = full.strip_prefix(expected_prefix.as_slice()) {
        return R::Key::unpack(row_key).map_err(KeyspaceDecodeError::KeyUnpack);
    }

    match full.first().copied() {
        None => Err(KeyspaceDecodeError::MissingPrefix),
        Some(found) => Err(KeyspaceDecodeError::BadRowTag {
            expected: R::ROW_TAG,
            found,
        }),
    }
}

/// Convert a raw prefix to a bounded range that matches all keys with that prefix.
pub fn prefix_range(prefix: &[u8]) -> (Bound<Vec<u8>>, Bound<Vec<u8>>) {
    let start = Bound::Included(prefix.to_vec());
    let end = match next_prefix(prefix) {
        Some(p) => Bound::Excluded(p),
        None => Bound::Unbounded,
    };
    (start, end)
}

pub(crate) fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut next = prefix.to_vec();
    for i in (0..next.len()).rev() {
        if next[i] != 0xFF {
            next[i] += 1;
            next.truncate(i + 1);
            return Some(next);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::ops::Bound;

    use mosaic_cac_types::DepositId;
    use mosaic_common::Byte32;

    use super::*;
    use crate::row_spec::{
        KVRowSpec,
        garbler::{DepositStateKey, DepositStateRowSpec, RootStateRowSpec},
    };

    fn dep_id(byte: u8) -> DepositId {
        let mut bytes = [0u8; 32];
        bytes.fill(byte);
        DepositId(Byte32::from(bytes))
    }

    #[test]
    fn row_prefix_layout_is_stable() {
        let prefix = row_prefix::<DepositStateRowSpec>();
        assert_eq!(prefix[0], DepositStateRowSpec::ROW_TAG);
        assert_eq!(prefix.len(), 1);
    }

    #[test]
    fn split_row_key_roundtrip() {
        let key = DepositStateKey::new(dep_id(0xAB));
        let full = full_key::<DepositStateRowSpec>(&key).expect("must encode");
        let parsed = split_row_key::<DepositStateRowSpec>(&full).expect("must decode");
        assert_eq!(parsed.deposit_id, key.deposit_id);
    }

    #[test]
    fn namespace_isolation_between_rows() {
        let dep_key = full_key::<DepositStateRowSpec>(&DepositStateKey::new(dep_id(0x05)))
            .expect("must encode");
        let root_key = full_key::<RootStateRowSpec>(&crate::row_spec::garbler::RootStateKey)
            .expect("must encode");
        assert_ne!(dep_key, root_key);
    }

    #[test]
    fn prefix_range_filters_correctly() {
        let prefix = vec![0x10, 0x20];
        let (start, end) = prefix_range(&prefix);
        assert_eq!(start, Bound::Included(vec![0x10, 0x20]));
        assert_eq!(end, Bound::Excluded(vec![0x10, 0x21]));
    }

    #[test]
    fn prefix_range_handles_all_ff_prefix() {
        let prefix = vec![0xFF, 0xFF];
        let (_, end) = prefix_range(&prefix);
        assert_eq!(end, Bound::Unbounded);
    }
}
