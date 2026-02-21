//! Polynomial cache for garbler setup.
//!
//! During garbler setup, [`GeneratePolynomialCommitments`] generates ~240 MB
//! of polynomials from a 32-byte seed. The subsequent 182
//! [`GenerateShares`] calls each need those same polynomials to evaluate at
//! their circuit index. In total, 347 handler invocations read from the cache
//! per seed (165 commitment jobs + 182 share jobs).
//!
//! This cache stores the polynomials keyed by seed so they are generated once
//! and shared across all handlers via [`Arc`]. The design addresses three
//! concurrency concerns:
//!
//! - **No redundant generation**: A `pending` set ensures only one worker
//!   generates polynomials for a given seed. Other workers see
//!   [`CacheResult::Unavailable`] and retry.
//!
//! - **No premature eviction**: Entries track a `remaining` counter that is
//!   decremented by [`mark_completed`](PolynomialCache::mark_completed) (called
//!   by handlers only on success, never on retry). Eviction occurs only when
//!   `remaining` reaches 0.
//!
//! - **Slot reservation invariant**: `entries.len() + pending.len() <= max_entries`
//!   at all times. A [`GenerationGuard`] reserves a slot on creation; its
//!   [`complete`](GenerationGuard::complete) method is therefore guaranteed to
//!   find room for insertion.
//!
//! [`GeneratePolynomialCommitments`]: mosaic_cac_types::state_machine::garbler::Action::GeneratePolynomialCommitments
//! [`GenerateShares`]: mosaic_cac_types::state_machine::garbler::Action::GenerateShares

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use mosaic_cac_types::{AllPolynomials, Seed};
use mosaic_common::constants::{N_CIRCUITS, N_INPUT_WIRES};
use parking_lot::Mutex;

/// Total number of handler invocations that will call [`PolynomialCache::mark_completed`]
/// for a single seed.
///
/// - `N_INPUT_WIRES + 1` commitment jobs (164 input wires + 1 output wire)
/// - `N_CIRCUITS + 1` share jobs (181 circuit indices + 1 reserved index)
const EXPECTED_TOTAL_USES: usize = (N_INPUT_WIRES + 1) + (N_CIRCUITS + 1);

/// Bounded cache for polynomials generated during garbler setup.
///
/// Thread-safe via [`parking_lot::Mutex`]. The lock is held only for brief
/// `HashMap` / `HashSet` operations — never while generating or evaluating
/// polynomials.
pub struct PolynomialCache {
    state: Arc<Mutex<CacheState>>,
    max_entries: usize,
}

struct CacheState {
    /// Cached polynomial entries keyed by seed.
    entries: HashMap<Seed, CacheEntry>,
    /// Seeds for which a worker is currently generating polynomials.
    /// Reserves a slot in the cache to maintain the
    /// `entries.len() + pending.len() <= max_entries` invariant.
    pending: HashSet<Seed>,
}

struct CacheEntry {
    polynomials: Arc<AllPolynomials>,
    /// Number of successful handler completions remaining before this entry
    /// becomes evictable. Initialized to [`EXPECTED_TOTAL_USES`] at insertion
    /// and decremented by [`PolynomialCache::mark_completed`].
    remaining: usize,
}

/// Result of a cache lookup via [`PolynomialCache::get`].
#[derive(Debug)]
pub enum CacheResult {
    /// Cache hit — polynomials are available. Use the [`Arc`] directly.
    Hit(Arc<AllPolynomials>),

    /// Cache is unavailable for this seed. Either another worker is already
    /// generating (seed is in the `pending` set) or the cache is full with no
    /// evictable entries. The caller should return [`HandlerOutcome::Retry`].
    ///
    /// [`HandlerOutcome::Retry`]: crate::handlers::HandlerOutcome::Retry
    Unavailable,

    /// Cache miss and no one is generating this seed. The caller has been
    /// designated as the generator and **must** either call
    /// [`GenerationGuard::complete`] with the generated polynomials, or drop
    /// the guard (which releases the reserved slot so another worker can try).
    Generate(GenerationGuard),
}

/// RAII guard that reserves a cache slot for polynomial generation.
///
/// Created by [`PolynomialCache::get`] when it hands out a
/// [`CacheResult::Generate`]. The guard marks the seed as `pending` in the
/// cache, preventing other workers from redundantly generating the same data.
///
/// # Completion
///
/// Call [`complete`](Self::complete) to consume the guard and store the
/// generated polynomials. This always succeeds because the slot was reserved
/// at creation time (invariant: `entries.len() + pending.len() <= max_entries`).
///
/// # Drop (failure path)
///
/// If the guard is dropped without calling `complete` (handler failed, panicked,
/// or returned `Retry` for a non-cache reason), the `Drop` impl removes the
/// seed from the `pending` set, releasing the reserved slot so another worker
/// can attempt generation.
pub struct GenerationGuard {
    /// Shared cache state. Held as `Arc` so the guard can outlive the borrow
    /// of `PolynomialCache` (necessary for async handlers).
    state: Arc<Mutex<CacheState>>,
    /// Seed this guard is generating for.
    seed: Seed,
    /// Maximum number of entries the cache can hold. Stored here so
    /// `complete()` can run debug assertions without re-deriving it.
    max_entries: usize,
}

impl std::fmt::Debug for GenerationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationGuard")
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

impl GenerationGuard {
    /// Consume the guard and store the generated polynomials in the cache.
    ///
    /// This method always succeeds. The slot was reserved when the guard was
    /// created (the `pending` set entry counts toward `max_entries`), so there
    /// is guaranteed room for the new cache entry.
    ///
    /// Returns an [`Arc`] reference to the cached polynomials for immediate
    /// use by the handler.
    pub fn complete(self, polynomials: AllPolynomials) -> Arc<AllPolynomials> {
        let arc = Arc::new(polynomials);

        {
            let mut state = self.state.lock();
            let was_pending = state.pending.remove(&self.seed);
            debug_assert!(
                was_pending,
                "GenerationGuard::complete called but seed was not in pending set"
            );

            let occupied = state.entries.len() + state.pending.len();
            debug_assert!(
                occupied < self.max_entries,
                "invariant violation: no room for insertion after removing from pending \
                 (entries={}, pending={}, max={})",
                state.entries.len(),
                state.pending.len(),
                self.max_entries,
            );

            state.entries.insert(
                self.seed,
                CacheEntry {
                    polynomials: Arc::clone(&arc),
                    remaining: EXPECTED_TOTAL_USES,
                },
            );
        }

        // Prevent `Drop` from running — we already cleaned up `pending` above.
        std::mem::forget(self);

        arc
    }
}

impl Drop for GenerationGuard {
    fn drop(&mut self) {
        // Handler did not call `complete` — release the reserved slot.
        let mut state = self.state.lock();
        state.pending.remove(&self.seed);
    }
}

impl PolynomialCache {
    /// Create a new cache that holds at most `max_entries` polynomial sets
    /// concurrently.
    ///
    /// Each entry is ~240 MB, so `max_entries` of 4 caps memory at ~960 MB.
    pub fn new(max_entries: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(CacheState {
                entries: HashMap::with_capacity(max_entries),
                pending: HashSet::with_capacity(max_entries),
            })),
            max_entries,
        }
    }

    /// Look up polynomials for `seed`.
    ///
    /// Returns one of three outcomes:
    ///
    /// - [`CacheResult::Hit`] — polynomials are cached. Use them directly.
    /// - [`CacheResult::Unavailable`] — another worker is generating this seed,
    ///   or the cache is full with no evictable entries. Caller should retry.
    /// - [`CacheResult::Generate`] — caller is designated as the generator.
    ///   A slot has been reserved. Call [`GenerationGuard::complete`] after
    ///   generating, or drop the guard to release the slot.
    pub fn get(&self, seed: &Seed) -> CacheResult {
        let mut state = self.state.lock();

        // 1. Cache hit
        if let Some(entry) = state.entries.get(seed) {
            return CacheResult::Hit(Arc::clone(&entry.polynomials));
        }

        // 2. Another worker is generating this seed
        if state.pending.contains(seed) {
            return CacheResult::Unavailable;
        }

        // 3. Check if there's room (entries + pending must stay <= max_entries)
        if state.entries.len() + state.pending.len() >= self.max_entries {
            // Try to free a slot by evicting a fully-consumed entry
            let evictable = state
                .entries
                .iter()
                .find(|(_, e)| e.remaining == 0)
                .map(|(s, _)| *s);

            if let Some(victim) = evictable {
                state.entries.remove(&victim);
            } else {
                // All slots occupied by active entries + pending generations
                return CacheResult::Unavailable;
            }
        }

        // 4. Reserve a slot and hand out the generation guard
        state.pending.insert(*seed);
        CacheResult::Generate(GenerationGuard {
            state: Arc::clone(&self.state),
            seed: *seed,
            max_entries: self.max_entries,
        })
    }

    /// Record a successful handler completion for `seed`.
    ///
    /// Decrements the `remaining` counter on the cache entry. When `remaining`
    /// reaches 0 the entry becomes eligible for eviction (but is not removed
    /// immediately — eviction happens lazily in [`get`](Self::get) when a new
    /// seed needs room).
    ///
    /// This is a no-op if `seed` is not in the cache (e.g. the polynomials
    /// were never cached because the cache was full at setup time).
    ///
    /// # Call site
    ///
    /// Called by handlers right before returning [`HandlerOutcome::Done`].
    /// **Never** called on [`HandlerOutcome::Retry`] — this is what prevents
    /// double-decrement on retried jobs.
    ///
    /// [`HandlerOutcome::Done`]: crate::handlers::HandlerOutcome::Done
    /// [`HandlerOutcome::Retry`]: crate::handlers::HandlerOutcome::Retry
    pub fn mark_completed(&self, seed: &Seed) {
        let mut state = self.state.lock();
        if let Some(entry) = state.entries.get_mut(seed) {
            entry.remaining = entry.remaining.saturating_sub(1);
        }
    }

    /// Number of entries currently in the cache (not counting pending).
    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Number of seeds currently being generated (pending).
    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.state.lock().pending.len()
    }

    /// Remaining count for a seed (for testing).
    #[cfg(test)]
    fn remaining(&self, seed: &Seed) -> Option<usize> {
        self.state.lock().entries.get(seed).map(|e| e.remaining)
    }
}

impl std::fmt::Debug for PolynomialCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock();
        f.debug_struct("PolynomialCache")
            .field("entries", &state.entries.len())
            .field("pending", &state.pending.len())
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
    fn get_hit_after_generate_complete() {
        let cache = PolynomialCache::new(4);
        let seed = test_seed(1);

        // First get: should hand out a generation guard.
        let guard = match cache.get(&seed) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };
        assert_eq!(cache.pending_count(), 1);

        // Complete the generation.
        let polys = generate_test_polynomials(seed);
        let arc1 = guard.complete(polys);
        assert_eq!(cache.entry_count(), 1);
        assert_eq!(cache.pending_count(), 0);

        // Second get: should be a cache hit.
        let arc2 = match cache.get(&seed) {
            CacheResult::Hit(a) => a,
            other => panic!("expected Hit, got {:?}", result_name(&other)),
        };

        assert!(Arc::ptr_eq(&arc1, &arc2));
    }

    #[test]
    fn unavailable_when_seed_pending() {
        let cache = PolynomialCache::new(4);
        let seed = test_seed(1);

        // Take out a generation guard.
        let _guard = match cache.get(&seed) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };

        // Same seed again: should be Unavailable (pending).
        assert!(matches!(cache.get(&seed), CacheResult::Unavailable));
    }

    #[test]
    fn unavailable_when_all_slots_occupied() {
        let cache = PolynomialCache::new(2);
        let seed1 = test_seed(1);
        let seed2 = test_seed(2);
        let seed3 = test_seed(3);

        // Fill both slots.
        let g1 = match cache.get(&seed1) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate for seed1, got {:?}", result_name(&other)),
        };
        g1.complete(generate_test_polynomials(seed1));

        let g2 = match cache.get(&seed2) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate for seed2, got {:?}", result_name(&other)),
        };
        g2.complete(generate_test_polynomials(seed2));

        // Both entries have remaining > 0, so neither is evictable.
        assert!(matches!(cache.get(&seed3), CacheResult::Unavailable));
    }

    #[test]
    fn evict_when_remaining_zero() {
        let cache = PolynomialCache::new(1);
        let seed1 = test_seed(1);
        let seed2 = test_seed(2);

        // Insert seed1.
        let g1 = match cache.get(&seed1) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };
        g1.complete(generate_test_polynomials(seed1));

        // Drain remaining to 0.
        for _ in 0..EXPECTED_TOTAL_USES {
            cache.mark_completed(&seed1);
        }
        assert_eq!(cache.remaining(&seed1), Some(0));

        // Now seed2 should be able to get a slot (seed1 is evictable).
        let g2 = match cache.get(&seed2) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate for seed2, got {:?}", result_name(&other)),
        };
        g2.complete(generate_test_polynomials(seed2));

        // seed1 should be evicted, seed2 should be present.
        assert_eq!(cache.entry_count(), 1);
        // seed1 is gone, but cache is full with seed2 (remaining > 0), so
        // seed1 can't get a new slot — it gets Unavailable, not Generate.
        assert!(matches!(cache.get(&seed1), CacheResult::Unavailable));
        // seed2 is still cached.
        assert!(matches!(cache.get(&seed2), CacheResult::Hit(_)));
    }

    #[test]
    fn guard_drop_clears_pending() {
        let cache = PolynomialCache::new(4);
        let seed = test_seed(1);

        // Take out a guard.
        let guard = match cache.get(&seed) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };
        assert_eq!(cache.pending_count(), 1);

        // Drop the guard without completing — simulates handler failure.
        drop(guard);
        assert_eq!(cache.pending_count(), 0);

        // The seed should be available for generation again.
        assert!(matches!(cache.get(&seed), CacheResult::Generate(_)));
    }

    #[test]
    fn mark_completed_decrements_remaining() {
        let cache = PolynomialCache::new(4);
        let seed = test_seed(1);

        let guard = match cache.get(&seed) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };
        guard.complete(generate_test_polynomials(seed));

        assert_eq!(cache.remaining(&seed), Some(EXPECTED_TOTAL_USES));

        cache.mark_completed(&seed);
        assert_eq!(cache.remaining(&seed), Some(EXPECTED_TOTAL_USES - 1));

        // Drain the rest.
        for _ in 1..EXPECTED_TOTAL_USES {
            cache.mark_completed(&seed);
        }
        assert_eq!(cache.remaining(&seed), Some(0));

        // Saturating: extra calls don't underflow.
        cache.mark_completed(&seed);
        assert_eq!(cache.remaining(&seed), Some(0));
    }

    #[test]
    fn mark_completed_noop_for_uncached_seed() {
        let cache = PolynomialCache::new(4);
        // Should not panic on a seed that was never cached.
        cache.mark_completed(&test_seed(99));
    }

    #[test]
    fn complete_always_succeeds_with_reserved_slot() {
        // Verify the invariant: if get() returns Generate, complete() always works.
        let cache = PolynomialCache::new(2);
        let seed1 = test_seed(1);
        let seed2 = test_seed(2);

        // Get guards for both slots.
        let g1 = match cache.get(&seed1) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };
        let g2 = match cache.get(&seed2) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };

        // Both slots reserved by pending. Third seed should be unavailable.
        let seed3 = test_seed(3);
        assert!(matches!(cache.get(&seed3), CacheResult::Unavailable));

        // Complete both — should not panic (slots reserved).
        g1.complete(generate_test_polynomials(seed1));
        g2.complete(generate_test_polynomials(seed2));

        assert_eq!(cache.entry_count(), 2);
        assert_eq!(cache.pending_count(), 0);
    }

    #[test]
    fn pending_counts_toward_capacity() {
        let cache = PolynomialCache::new(2);
        let seed1 = test_seed(1);
        let seed2 = test_seed(2);
        let seed3 = test_seed(3);

        // One entry, one pending = 2 slots used.
        let g1 = match cache.get(&seed1) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };
        g1.complete(generate_test_polynomials(seed1));

        let _g2 = match cache.get(&seed2) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };

        // 1 entry + 1 pending = full.
        assert_eq!(cache.entry_count(), 1);
        assert_eq!(cache.pending_count(), 1);
        assert!(matches!(cache.get(&seed3), CacheResult::Unavailable));
    }

    #[test]
    fn arc_keeps_data_alive_after_eviction() {
        let cache = PolynomialCache::new(1);
        let seed1 = test_seed(1);
        let seed2 = test_seed(2);

        // Insert and hold a reference.
        let guard = match cache.get(&seed1) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate, got {:?}", result_name(&other)),
        };
        let held = guard.complete(generate_test_polynomials(seed1));

        // Drain remaining to make evictable.
        for _ in 0..EXPECTED_TOTAL_USES {
            cache.mark_completed(&seed1);
        }

        // Insert seed2, which evicts seed1.
        let g2 = match cache.get(&seed2) {
            CacheResult::Generate(g) => g,
            other => panic!("expected Generate for seed2, got {:?}", result_name(&other)),
        };
        g2.complete(generate_test_polynomials(seed2));

        // seed1 is evicted from the cache...
        assert_eq!(cache.entry_count(), 1);

        // ...but the Arc we held is still valid.
        let (input, _output) = held.as_ref();
        assert_eq!(input.len(), N_INPUT_WIRES);
    }

    /// Helper to name a CacheResult variant for panic messages.
    fn result_name(r: &CacheResult) -> &'static str {
        match r {
            CacheResult::Hit(_) => "Hit",
            CacheResult::Unavailable => "Unavailable",
            CacheResult::Generate(_) => "Generate",
        }
    }
}
