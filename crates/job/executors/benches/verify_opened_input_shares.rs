//! Benchmarks for `verify_opened_input_shares` (single-batch vs chunked).
//!
//! Generates synthetic but valid share/commitment data matching production
//! constants and compares the single-MSM path against the chunked path at
//! various chunk sizes. Storage I/O is excluded — only computation is measured.
//!
//! Also reports peak heap memory for each variant.
//!
//! Run with:
//!   cargo bench -p mosaic-job-executors --bench verify_opened_input_shares
//!
//! With reduced-circuits (faster data generation, smaller problem):
//!   cargo bench -p mosaic-job-executors --bench verify_opened_input_shares \
//!       --features mosaic-common/reduced-circuits

#![allow(missing_docs)]
#![allow(unused_crate_dependencies)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use mosaic_cac_types::{CircuitInputShares, WideLabelWirePolynomialCommitments};
use mosaic_common::constants::{N_INPUT_WIRES, N_OPEN_CIRCUITS, WIDE_LABEL_VALUE_COUNT};
use mosaic_heap_array::HeapArray;
use mosaic_job_executors::evaluator::{
    verify_opened_input_shares, verify_opened_input_shares_chunked,
};
use mosaic_vs3::{Index, Polynomial};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ============================================================================
// Tracking allocator — measures peak memory during a marked region
// ============================================================================

struct TrackingAllocator;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TRACKING: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && TRACKING.load(Ordering::Relaxed) {
            let prev = CURRENT.fetch_add(layout.size(), Ordering::Relaxed);
            let now = prev + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACKING.load(Ordering::Relaxed) {
            CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() && TRACKING.load(Ordering::Relaxed) {
            if new_size > layout.size() {
                let diff = new_size - layout.size();
                let prev = CURRENT.fetch_add(diff, Ordering::Relaxed);
                let now = prev + diff;
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                let diff = layout.size() - new_size;
                CURRENT.fetch_sub(diff, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator;

/// Reset counters and start tracking. Returns the start instant.
fn start_tracking() -> std::time::Instant {
    CURRENT.store(0, Ordering::SeqCst);
    PEAK.store(0, Ordering::SeqCst);
    TRACKING.store(true, Ordering::SeqCst);
    std::time::Instant::now()
}

/// Stop tracking and return (peak bytes, elapsed duration).
fn stop_tracking(start: std::time::Instant) -> (usize, std::time::Duration) {
    TRACKING.store(false, Ordering::SeqCst);
    (PEAK.load(Ordering::SeqCst), start.elapsed())
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ============================================================================
// Test data generation
// ============================================================================

/// Generate deterministic test data matching production dimensions.
fn generate_test_data() -> (Vec<CircuitInputShares>, Vec<WideLabelWirePolynomialCommitments>) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let mut commitments: Vec<WideLabelWirePolynomialCommitments> =
        Vec::with_capacity(N_INPUT_WIRES);
    let mut polynomials: Vec<Vec<Polynomial>> = Vec::with_capacity(N_INPUT_WIRES);

    for _ in 0..N_INPUT_WIRES {
        let mut wire_polys = Vec::with_capacity(WIDE_LABEL_VALUE_COUNT);
        let wire_commits: WideLabelWirePolynomialCommitments = HeapArray::new(|_| {
            let poly = Polynomial::rand(&mut rng);
            let commit = poly.commit();
            wire_polys.push(poly);
            commit
        });
        commitments.push(wire_commits);
        polynomials.push(wire_polys);
    }

    let mut opened_input_shares: Vec<CircuitInputShares> = Vec::with_capacity(N_OPEN_CIRCUITS);
    for circuit_idx in 0..N_OPEN_CIRCUITS {
        let index = Index::new(circuit_idx + 1).expect("valid index");
        let circuit_shares: CircuitInputShares = HeapArray::new(|wire| {
            HeapArray::new(|val| polynomials[wire][val].eval(index))
        });
        opened_input_shares.push(circuit_shares);
    }

    (opened_input_shares, commitments)
}

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_verify_opened(c: &mut Criterion) {
    // ── Print actual type sizes for analysis ─────────────────────────
    eprintln!("=== Type sizes ===\n");
    eprintln!("  Share:                {} bytes", std::mem::size_of::<mosaic_vs3::Share>());
    eprintln!("  PolynomialCommitment: {} bytes", std::mem::size_of::<mosaic_vs3::PolynomialCommitment>());
    eprintln!("  Point (Projective):   {} bytes", std::mem::size_of::<mosaic_vs3::Point>());
    eprintln!("  Scalar:               {} bytes", std::mem::size_of::<mosaic_vs3::Scalar>());
    eprintln!();

    eprintln!(
        "Generating test data: {} circuits x {} wires x {} values ...",
        N_OPEN_CIRCUITS, N_INPUT_WIRES, WIDE_LABEL_VALUE_COUNT
    );
    let (shares, commitments) = generate_test_data();
    eprintln!("Test data generated.\n");


    // ── Peak memory measurement (one run each, outside criterion) ────
    eprintln!("=== Peak memory (computation only, excludes input data) ===\n");

    let t = start_tracking();
    verify_opened_input_shares(&shares, &commitments).expect("should pass");
    let (peak, elapsed) = stop_tracking(t);
    eprintln!("  single_batch:    {:>10}  ({:.2?})", format_bytes(peak), elapsed);

    for chunk_size in [64, 128, 256, 512, 1024] {
        let t = start_tracking();
        verify_opened_input_shares_chunked(&shares, &commitments, chunk_size).expect("should pass");
        let (peak, elapsed) = stop_tracking(t);
        eprintln!("  chunked/{chunk_size:>4}:     {:>10}  ({:.2?})", format_bytes(peak), elapsed);
    }

    eprintln!();

    // ── Criterion timing benchmarks ──────────────────────────────────
    let mut group = c.benchmark_group("verify_opened_input_shares");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(30));

    group.bench_function("single_batch", |b| {
        b.iter(|| {
            verify_opened_input_shares(&shares, &commitments).expect("verification should pass");
        });
    });

    for chunk_size in [64, 128, 256, 512, 1024] {
        group.bench_with_input(
            BenchmarkId::new("chunked", chunk_size),
            &chunk_size,
            |b, &cs| {
                b.iter(|| {
                    verify_opened_input_shares_chunked(&shares, &commitments, cs)
                        .expect("verification should pass");
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_verify_opened);
criterion_main!(benches);
