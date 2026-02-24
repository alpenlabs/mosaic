//! Keyspace envelope helpers for typed row specs.

use std::ops::Bound;

use ark_serialize::CanonicalSerialize as _;
use mosaic_cac_types::state_machine::StateMachineId;

use crate::row_spec::{KVRowSpec, PackableKey, error::KeyspaceDecodeError};

/// Key schema version encoded as the first byte of every key.
pub const KEY_SCHEMA_VERSION: u8 = 1;

/// Top-level key domain.
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

/// Build the row prefix:
/// `[schema_version][domain][state_machine_id][row_tag]`.
pub fn row_prefix<R: KVRowSpec>(sm_id: StateMachineId) -> Vec<u8> {
    let mut key = Vec::with_capacity(35);
    key.push(KEY_SCHEMA_VERSION);
    key.push(R::DOMAIN.to_u8());
    sm_id
        .serialize_compressed(&mut key)
        .expect("serializing StateMachineId into Vec<u8> must not fail");
    key.push(R::ROW_TAG);
    key
}

/// Build a full key by appending row-local key bytes to the row prefix.
pub fn full_key<R: KVRowSpec>(
    sm_id: StateMachineId,
    key: &R::Key,
) -> Result<Vec<u8>, <R::Key as PackableKey>::PackingError> {
    let mut out = row_prefix::<R>(sm_id);
    let row_local = key.pack()?;
    out.extend_from_slice(row_local.as_ref());
    Ok(out)
}

/// Decode a row-local key from a full key, validating version/domain/row-tag prefix.
pub fn split_row_key<R: KVRowSpec>(
    sm_id: StateMachineId,
    full: &[u8],
) -> Result<R::Key, KeyspaceDecodeError<<R::Key as PackableKey>::UnpackingError>> {
    let expected_prefix = row_prefix::<R>(sm_id);
    if let Some(row_key) = full.strip_prefix(expected_prefix.as_slice()) {
        return R::Key::unpack(row_key).map_err(KeyspaceDecodeError::KeyUnpack);
    }

    if let Some(found) = full.first().copied() {
        if found != KEY_SCHEMA_VERSION {
            return Err(KeyspaceDecodeError::BadVersion {
                expected: KEY_SCHEMA_VERSION,
                found,
            });
        }
    } else {
        return Err(KeyspaceDecodeError::MissingPrefix);
    }

    if let Some(found) = full.get(1).copied() {
        let expected = R::DOMAIN.to_u8();
        if found != expected {
            return Err(KeyspaceDecodeError::BadDomain { expected, found });
        }
    } else {
        return Err(KeyspaceDecodeError::MissingPrefix);
    }

    let row_tag_offset = expected_prefix.len().saturating_sub(1);
    if full.len() <= row_tag_offset {
        return Err(KeyspaceDecodeError::MissingPrefix);
    }

    let found = full[row_tag_offset];
    if found != R::ROW_TAG {
        return Err(KeyspaceDecodeError::BadRowTag {
            expected: R::ROW_TAG,
            found,
        });
    }

    Err(KeyspaceDecodeError::MissingPrefix)
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

fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
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

    use mosaic_cac_types::{DepositId, state_machine::StateMachineId};
    use mosaic_common::Byte32;

    use super::*;
    use crate::row_spec::{
        KVRowSpec,
        garbler::{DepositStateKey, DepositStateRowSpec, RootStateRowSpec},
    };

    fn sm_id(byte: u8) -> StateMachineId {
        StateMachineId::from([byte; 32])
    }

    fn dep_id(byte: u8) -> DepositId {
        let mut bytes = [0u8; 32];
        bytes.fill(byte);
        DepositId(Byte32::from(bytes))
    }

    #[test]
    fn row_prefix_layout_is_stable() {
        let prefix = row_prefix::<DepositStateRowSpec>(sm_id(0xAA));
        assert_eq!(prefix[0], KEY_SCHEMA_VERSION);
        assert_eq!(prefix[1], KeyDomain::Garbler.to_u8());
        assert_eq!(prefix.last().copied(), Some(DepositStateRowSpec::ROW_TAG));
        assert_eq!(prefix.len(), 35);
    }

    #[test]
    fn split_row_key_roundtrip() {
        let sm = sm_id(0x01);
        let key = DepositStateKey::new(dep_id(0xAB));
        let full = full_key::<DepositStateRowSpec>(sm, &key).expect("must encode");
        let parsed = split_row_key::<DepositStateRowSpec>(sm, &full).expect("must decode");
        assert_eq!(parsed.deposit_id, key.deposit_id);
    }

    #[test]
    fn namespace_isolation_between_rows() {
        let sm = sm_id(0x02);
        let dep_key = full_key::<DepositStateRowSpec>(sm, &DepositStateKey::new(dep_id(0x05)))
            .expect("must encode");
        let root_key = full_key::<RootStateRowSpec>(sm, &crate::row_spec::garbler::RootStateKey)
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
