//! Benchmarks for share verification
//!
//! Run with: cargo bench -p mosaic-vs3

#![allow(missing_docs)]
#![allow(unused_crate_dependencies)]

use criterion::{Criterion, criterion_group, criterion_main};
use mosaic_vs3::{Index, Polynomial, batch_verify_shares};
use rand::rngs::OsRng;

/// Single-share verification
fn bench_verify(c: &mut Criterion) {
    let mut rng = OsRng;

    c.bench_function("single_share", |b| {
        // Generate polynomial
        let poly = Polynomial::rand(&mut rng);
        let commit = poly.commit();

        // Generate share
        let index = Index::new(1).unwrap();
        let share = poly.eval(index);

        // Benchmark verification
        b.iter(|| {
            assert!(commit.verify_share(share).is_ok());
        });
    });
}

/// Trivial batch verification
fn bench_batch_verify(c: &mut Criterion) {
    let mut rng = OsRng;

    c.bench_function("batch_share", |b| {
        // Generate polynomial
        let poly = Polynomial::rand(&mut rng);
        let commit = poly.commit();

        // Generate share
        let index = Index::new(1).unwrap();
        let share = poly.eval(index);

        // Set up trivial batch
        let pairs = [(&commit, &[share][..])];

        // Benchmark verification
        b.iter(|| {
            assert!(batch_verify_shares(&pairs, &mut rng).is_ok());
        });
    });
}

criterion_group!(benches, bench_verify, bench_batch_verify);
criterion_main!(benches);
