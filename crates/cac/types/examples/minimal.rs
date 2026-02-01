//! Test using Vec instead of fixed array to avoid the hang.
//!
//! The hang occurs with [PolynomialCommitment; N] where N >= 250.
//! This tests if using Vec<PolynomialCommitment> avoids the issue.
//!
//! Run with: cargo run -r --example minimal -p mosaic-cac-types

#![allow(unused_crate_dependencies)]

use std::time::Instant;

use ark_serialize::{CanonicalSerialize, Compress};
use mosaic_vs3::{Polynomial, PolynomialCommitment};
use rand::SeedableRng;

fn main() {
    eprintln!("=== main() started ===");

    // Create a single PolynomialCommitment
    eprintln!("Creating polynomial...");
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let poly_commit: PolynomialCommitment = Polynomial::rand(&mut rng).commit();
    eprintln!("Polynomial commitment created");

    // Use Vec instead of fixed array - this should avoid the hang
    const ARRAY_SIZE: usize = 256;
    eprintln!("Creating Vec of {} polynomial commitments...", ARRAY_SIZE);
    let start = Instant::now();
    let commitments: Vec<PolynomialCommitment> =
        (0..ARRAY_SIZE).map(|_| poly_commit.clone()).collect();
    eprintln!("Vec created in {:?}", start.elapsed());

    // Serialize uncompressed
    eprintln!("Serializing Vec (uncompressed)...");
    let start = Instant::now();
    let mut bytes = Vec::new();
    commitments
        .serialize_with_mode(&mut bytes, Compress::No)
        .unwrap();
    eprintln!("Serialized {} bytes in {:?}", bytes.len(), start.elapsed());

    // Serialize compressed
    eprintln!("Serializing Vec (compressed)...");
    let start = Instant::now();
    let mut bytes_comp = Vec::new();
    commitments
        .serialize_with_mode(&mut bytes_comp, Compress::Yes)
        .unwrap();
    eprintln!(
        "Serialized {} bytes in {:?}",
        bytes_comp.len(),
        start.elapsed()
    );

    eprintln!("\n=== Summary ===");
    eprintln!(
        "Uncompressed: {} bytes ({:.2} MB)",
        bytes.len(),
        bytes.len() as f64 / 1024.0 / 1024.0
    );
    eprintln!(
        "Compressed:   {} bytes ({:.2} MB)",
        bytes_comp.len(),
        bytes_comp.len() as f64 / 1024.0 / 1024.0
    );

    eprintln!("\n=== main() finished ===");
}
