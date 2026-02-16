//! Polynomial cache for garbler setup.
//!
//! During garbler setup, [`GeneratePolynomialCommitments`] generates ~240 MB
//! of polynomials from a 32-byte seed. The subsequent 181
//! [`GenerateShares`] calls each need those same polynomials to evaluate at
//! their circuit index.
//!
//! This cache stores the polynomials keyed by seed so they are generated once
//! and shared across all `GenerateShares` handlers via [`Arc`]. Entries are
//! automatically evicted after [`N_CIRCUITS`] reads (one per `GenerateShares`
//! call).
//!
//! [`GeneratePolynomialCommitments`]: mosaic_cac_types::state_machine::garbler::Action::GeneratePolynomialCommitments
//! [`GenerateShares`]: mosaic_cac_types::state_machine::garbler::Action::GenerateShares

use std::{collections::HashMap, sync::Arc};

use mosaic_cac_types::{AllPolynomials, Seed};
use mosaic_common::constants::N_CIRCUITS;
use parking_lot::Mutex;

/// Bounded cache for polynomials generated during garbler setup.
///
/// Thread-safe via [`parking_lot::Mutex`]. The lock is held only for brief
/// `HashMap` operations — never while generating or evaluating polynomials.
pub struct PolynomialCache {
    inner: Mutex<HashMap<Seed, CacheEntry>>,
    max_entries: usize,
}

struct CacheEntry {
    polynomials: Arc<AllPolynomials>,
    /// Number of [`get`](PolynomialCache::get) calls remaining before
    /// auto-eviction. Initialized to [`N_CIRCUITS`].
    remaining: usize,
}

/// Error returned when the cache is at capacity.
#[derive(Debug)]
pub struct CacheFull;

impl PolynomialCache {
    /// Create a new cache that holds at most `max_entries` polynomial sets
    /// concurrently.
    ///
    /// Each entry is ~240 MB, so `max_entries` of 4 caps memory at ~960 MB.
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::with_capacity(max_entries)),
            max_entries,
        }
    }

    /// Insert polynomials for `seed` and return a shared reference for
    /// immediate use by the caller.
    ///
    /// If an entry for this seed already exists it is replaced. Returns
    /// [`CacheFull`] if the cache is at capacity and the seed is not already
    /// present.
    pub fn insert(
        &self,
        seed: Seed,
        polynomials: AllPolynomials,
    ) -> Result<Arc<AllPolynomials>, CacheFull> {
        let arc = Arc::new(polynomials);
        let mut map = self.inner.lock();

        // Allow replacement of an existing entry for the same seed.
        if !map.contains_key(&seed) && map.len() >= self.max_entries {
            return Err(CacheFull);
        }

        map.insert(
            seed,
            CacheEntry {
                polynomials: Arc::clone(&arc),
                remaining: N_CIRCUITS,
            },
        );

        Ok(arc)
    }

    /// Retrieve polynomials for `seed`, decrementing the remaining counter.
    ///
    /// When the counter reaches zero the entry is removed from the map.
    /// In-flight holders of the [`Arc`] keep the memory alive until they drop.
    ///
    /// Returns `None` on cache miss (caller should regenerate from seed).
    pub fn get(&self, seed: &Seed) -> Option<Arc<AllPolynomials>> {
        let mut map = self.inner.lock();
        let entry = map.get_mut(seed)?;
        let arc = Arc::clone(&entry.polynomials);

        entry.remaining = entry.remaining.saturating_sub(1);
        if entry.remaining == 0 {
            map.remove(seed);
        }

        Some(arc)
    }

    /// Number of entries currently in the cache.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

impl std::fmt::Debug for PolynomialCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = self.inner.lock();
        f.debug_struct("PolynomialCache")
            .field("entries", &map.len())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use mosaic_cac_types::{InputPolynomials, OutputPolynomial};
    use mosaic_common::Byte32;
    use mosaic_heap_array::HeapArray;
    use mosaic_vs3::Polynomial;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    /// Generate a real `AllPolynomials` from a seed (same logic handlers use).
    fn generate_test_polynomials(seed: Seed) -> AllPolynomials {
        let mut rng = ChaCha20Rng::from_seed(seed.into());
        let input_polys: InputPolynomials =
            HeapArray::new(|_| HeapArray::new(|_| Polynomial::rand(&mut rng)));
        let output_poly: OutputPolynomial = Polynomial::rand(&mut rng);
        (input_polys, output_poly)
    }

    fn test_seed(v: u8) -> Seed {
        Byte32::from([v; 32])
    }

    #[test]
    fn insert_and_get() {
        let cache = PolynomialCache::new(4);
        let seed = test_seed(1);
        let polys = generate_test_polynomials(seed);

        let arc = cache.insert(seed, polys).expect("insert should succeed");
        assert_eq!(cache.len(), 1);

        // First get should succeed.
        let got = cache.get(&seed).expect("should hit cache");
        assert!(Arc::ptr_eq(&arc, &got));
    }

    #[test]
    fn auto_evict_after_n_circuits() {
        let cache = PolynomialCache::new(4);
        let seed = test_seed(2);
        let polys = generate_test_polynomials(seed);

        cache.insert(seed, polys).unwrap();

        // Consume all N_CIRCUITS reads.
        for i in 0..N_CIRCUITS {
            let result = cache.get(&seed);
            if i < N_CIRCUITS - 1 {
                assert!(result.is_some(), "should hit on read {i}");
            } else {
                // Last read succeeds but removes the entry.
                assert!(result.is_some(), "last read should still return data");
            }
        }

        // Entry should be gone now.
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&seed).is_none());
    }

    #[test]
    fn cache_full_rejects_new_seed() {
        let cache = PolynomialCache::new(1);
        let seed1 = test_seed(1);
        let seed2 = test_seed(2);

        cache
            .insert(seed1, generate_test_polynomials(seed1))
            .unwrap();
        let result = cache.insert(seed2, generate_test_polynomials(seed2));
        assert!(result.is_err());
    }

    #[test]
    fn replace_existing_seed() {
        let cache = PolynomialCache::new(1);
        let seed = test_seed(1);

        cache.insert(seed, generate_test_polynomials(seed)).unwrap();
        // Second insert for same seed should succeed even at capacity.
        let result = cache.insert(seed, generate_test_polynomials(seed));
        assert!(result.is_ok());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn miss_returns_none() {
        let cache = PolynomialCache::new(4);
        assert!(cache.get(&test_seed(99)).is_none());
    }

    #[test]
    fn arc_keeps_data_alive_after_eviction() {
        let cache = PolynomialCache::new(4);
        let seed = test_seed(3);
        let polys = generate_test_polynomials(seed);

        let held = cache.insert(seed, polys).unwrap();

        // Drain all reads to trigger eviction.
        for _ in 0..N_CIRCUITS {
            cache.get(&seed);
        }

        assert_eq!(cache.len(), 0);

        // The Arc we held from insert is still valid.
        let (input, _output) = held.as_ref();
        assert_eq!(input.len(), mosaic_common::constants::N_INPUT_WIRES);
    }
}
