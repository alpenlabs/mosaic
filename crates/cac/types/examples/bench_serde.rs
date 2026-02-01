//! Benchmark serialization for all protocol message types.
//!
//! Tests actual serialization and deserialization times for full messages:
//! - CommitMsgChunk (172 chunks)
//! - ChallengeResponseMsgChunk (174 chunks)
//! - ChallengeMsg (single message)
//! - AdaptorMsg (single message)
//!
//! Compares Compressed vs Uncompressed modes.
//!
//! Run with: cargo run --example bench_serde -r -p mosaic-cac-types

#![allow(unused_crate_dependencies)]

use std::time::{Duration, Instant};

use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use mosaic_cac_types::{
    Adaptor, AdaptorMsgChunk, AdaptorMsgChunkWithdrawals, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, CircuitInputShares, CommitMsgChunk, WideLabelWireAdaptors,
    WideLabelWirePolynomialCommitments, WideLabelWireShares,
};
use mosaic_common::constants::{
    N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_OPEN_CIRCUITS, WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK,
};
use mosaic_vs3::{Index, Point, Polynomial, Scalar, Share};
use rand::SeedableRng;

struct BenchResult {
    name: &'static str,
    compressed_size: usize,
    uncompressed_size: usize,
    compressed_ser: Duration,
    uncompressed_ser: Duration,
    compressed_deser: Duration,
    uncompressed_deser: Duration,
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn format_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2}s", d.as_secs_f64())
    } else if d.as_millis() > 0 {
        format!("{:.1}ms", d.as_secs_f64() * 1000.0)
    } else {
        format!("{:.1}µs", d.as_secs_f64() * 1_000_000.0)
    }
}

fn main() {
    println!("=== Protocol Message Serialization Benchmark ===");
    println!("    Measuring ACTUAL full message times (Compressed vs Uncompressed)\n");

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let single_scalar = Scalar::from_le_bytes_mod_order(&[42u8; 32]);
    let mut results: Vec<BenchResult> = Vec::new();

    // =========================================================================
    // 1. CommitMsgChunk - Full message (172 chunks)
    // =========================================================================
    println!("--- CommitMsg (as {} CommitMsgChunks) ---", N_INPUT_WIRES);
    println!(
        "    Structure: {} chunks × 256 PolynomialCommitments × 174 curve points\n",
        N_INPUT_WIRES
    );

    let poly_commit = Polynomial::rand(&mut rng).commit();

    // Create all chunks
    let start = Instant::now();
    let commit_chunks: Vec<CommitMsgChunk> = (0..N_INPUT_WIRES)
        .map(|i| CommitMsgChunk {
            wire_index: i as u16,
            commitments: WideLabelWirePolynomialCommitments::new(|_| poly_commit.clone()),
        })
        .collect();
    println!("    Create:      {:>12?}", start.elapsed());

    // Compressed
    let start = Instant::now();
    let compressed_chunks: Vec<Vec<u8>> = commit_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .unwrap();
            bytes
        })
        .collect();
    let compressed_ser = start.elapsed();
    let compressed_size: usize = compressed_chunks.iter().map(|b| b.len()).sum();

    let start = Instant::now();
    let _: Vec<CommitMsgChunk> = compressed_chunks
        .iter()
        .map(|bytes| {
            CommitMsgChunk::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes).unwrap()
        })
        .collect();
    let compressed_deser = start.elapsed();

    // Uncompressed
    let start = Instant::now();
    let uncompressed_chunks: Vec<Vec<u8>> = commit_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
        .collect();
    let uncompressed_ser = start.elapsed();
    let uncompressed_size: usize = uncompressed_chunks.iter().map(|b| b.len()).sum();

    let start = Instant::now();
    let _: Vec<CommitMsgChunk> = uncompressed_chunks
        .iter()
        .map(|bytes| {
            CommitMsgChunk::deserialize_with_mode(&bytes[..], Compress::No, Validate::Yes).unwrap()
        })
        .collect();
    let uncompressed_deser = start.elapsed();

    println!(
        "    Compressed:   ser {:>10}, deser {:>10}, size {}",
        format_duration(compressed_ser),
        format_duration(compressed_deser),
        format_size(compressed_size)
    );
    println!(
        "    Uncompressed: ser {:>10}, deser {:>10}, size {}\n",
        format_duration(uncompressed_ser),
        format_duration(uncompressed_deser),
        format_size(uncompressed_size)
    );

    results.push(BenchResult {
        name: "CommitMsg (172 chunks)",
        compressed_size,
        uncompressed_size,
        compressed_ser,
        uncompressed_ser,
        compressed_deser,
        uncompressed_deser,
    });

    // =========================================================================
    // 2. ChallengeResponseMsgChunk - Full message (174 chunks)
    // =========================================================================
    println!(
        "--- ChallengeResponseMsg (as {} ChallengeResponseMsgChunks) ---",
        N_OPEN_CIRCUITS
    );
    println!(
        "    Structure: {} chunks × 172 wires × 256 shares\n",
        N_OPEN_CIRCUITS
    );

    let idx = Index::new(1).unwrap();
    let single_share = Share::new(idx, single_scalar);

    // Create all chunks
    let start = Instant::now();
    let response_chunks: Vec<ChallengeResponseMsgChunk> = (0..N_OPEN_CIRCUITS)
        .map(|i| ChallengeResponseMsgChunk {
            circuit_index: i as u16,
            shares: CircuitInputShares::new(|_| WideLabelWireShares::new(|_| single_share.clone())),
        })
        .collect();
    println!("    Create:      {:>12?}", start.elapsed());

    // Compressed
    let start = Instant::now();
    let compressed_chunks: Vec<Vec<u8>> = response_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .unwrap();
            bytes
        })
        .collect();
    let compressed_ser = start.elapsed();
    let compressed_size: usize = compressed_chunks.iter().map(|b| b.len()).sum();

    let start = Instant::now();
    let _: Vec<ChallengeResponseMsgChunk> = compressed_chunks
        .iter()
        .map(|bytes| {
            ChallengeResponseMsgChunk::deserialize_with_mode(
                &bytes[..],
                Compress::Yes,
                Validate::Yes,
            )
            .unwrap()
        })
        .collect();
    let compressed_deser = start.elapsed();

    // Uncompressed
    let start = Instant::now();
    let uncompressed_chunks: Vec<Vec<u8>> = response_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
        .collect();
    let uncompressed_ser = start.elapsed();
    let uncompressed_size: usize = uncompressed_chunks.iter().map(|b| b.len()).sum();

    let start = Instant::now();
    let _: Vec<ChallengeResponseMsgChunk> = uncompressed_chunks
        .iter()
        .map(|bytes| {
            ChallengeResponseMsgChunk::deserialize_with_mode(
                &bytes[..],
                Compress::No,
                Validate::Yes,
            )
            .unwrap()
        })
        .collect();
    let uncompressed_deser = start.elapsed();

    println!(
        "    Compressed:   ser {:>10}, deser {:>10}, size {}",
        format_duration(compressed_ser),
        format_duration(compressed_deser),
        format_size(compressed_size)
    );
    println!(
        "    Uncompressed: ser {:>10}, deser {:>10}, size {}\n",
        format_duration(uncompressed_ser),
        format_duration(uncompressed_deser),
        format_size(uncompressed_size)
    );

    results.push(BenchResult {
        name: "ChallengeResponseMsg (174)",
        compressed_size,
        uncompressed_size,
        compressed_ser,
        uncompressed_ser,
        compressed_deser,
        uncompressed_deser,
    });

    // =========================================================================
    // 3. ChallengeMsg (single message)
    // =========================================================================
    println!("--- ChallengeMsg ---");
    println!(
        "    Structure: {} challenge indices (single message)\n",
        N_OPEN_CIRCUITS
    );

    let start = Instant::now();
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());
    let challenge_msg = ChallengeMsg { challenge_indices };
    println!("    Create:      {:>12?}", start.elapsed());

    // Compressed
    let start = Instant::now();
    let mut compressed_bytes = Vec::new();
    challenge_msg
        .serialize_with_mode(&mut compressed_bytes, Compress::Yes)
        .unwrap();
    let compressed_ser = start.elapsed();
    let compressed_size = compressed_bytes.len();

    let start = Instant::now();
    let _ =
        ChallengeMsg::deserialize_with_mode(&compressed_bytes[..], Compress::Yes, Validate::Yes)
            .unwrap();
    let compressed_deser = start.elapsed();

    // Uncompressed
    let start = Instant::now();
    let mut uncompressed_bytes = Vec::new();
    challenge_msg
        .serialize_with_mode(&mut uncompressed_bytes, Compress::No)
        .unwrap();
    let uncompressed_ser = start.elapsed();
    let uncompressed_size = uncompressed_bytes.len();

    let start = Instant::now();
    let _ =
        ChallengeMsg::deserialize_with_mode(&uncompressed_bytes[..], Compress::No, Validate::Yes)
            .unwrap();
    let uncompressed_deser = start.elapsed();

    println!(
        "    Compressed:   ser {:>10}, deser {:>10}, size {}",
        format_duration(compressed_ser),
        format_duration(compressed_deser),
        format_size(compressed_size)
    );
    println!(
        "    Uncompressed: ser {:>10}, deser {:>10}, size {}\n",
        format_duration(uncompressed_ser),
        format_duration(uncompressed_deser),
        format_size(uncompressed_size)
    );

    results.push(BenchResult {
        name: "ChallengeMsg",
        compressed_size,
        uncompressed_size,
        compressed_ser,
        uncompressed_ser,
        compressed_deser,
        uncompressed_deser,
    });

    // =========================================================================
    // 4. AdaptorMsg (as 4 AdaptorMsgChunks)
    // =========================================================================
    println!(
        "--- AdaptorMsg (as {} AdaptorMsgChunks) ---",
        N_DEPOSIT_INPUT_WIRES
    );
    println!(
        "    Structure: {} chunks, each with 1 deposit + {} × 256 withdrawal adaptors\n",
        N_DEPOSIT_INPUT_WIRES, WITHDRAWAL_WIRES_PER_ADAPTOR_CHUNK
    );

    let point = Point::generator() * single_scalar;
    let single_adaptor = Adaptor {
        tweaked_s: single_scalar,
        tweaked_r: point,
        share_commitment: point,
    };

    // Create all chunks
    let start = Instant::now();
    let adaptor_chunks: Vec<AdaptorMsgChunk> = (0..N_DEPOSIT_INPUT_WIRES)
        .map(|i| AdaptorMsgChunk {
            chunk_index: i as u8,
            deposit_adaptor: single_adaptor,
            withdrawal_adaptors: AdaptorMsgChunkWithdrawals::new(|_| {
                WideLabelWireAdaptors::new(|_| single_adaptor)
            }),
        })
        .collect();
    println!("    Create:      {:>12?}", start.elapsed());

    // Compressed
    let start = Instant::now();
    let compressed_chunks: Vec<Vec<u8>> = adaptor_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .unwrap();
            bytes
        })
        .collect();
    let compressed_ser = start.elapsed();
    let compressed_size: usize = compressed_chunks.iter().map(|b| b.len()).sum();

    let start = Instant::now();
    let _: Vec<AdaptorMsgChunk> = compressed_chunks
        .iter()
        .map(|bytes| {
            AdaptorMsgChunk::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
                .unwrap()
        })
        .collect();
    let compressed_deser = start.elapsed();

    // Uncompressed
    let start = Instant::now();
    let uncompressed_chunks: Vec<Vec<u8>> = adaptor_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
        .collect();
    let uncompressed_ser = start.elapsed();
    let uncompressed_size: usize = uncompressed_chunks.iter().map(|b| b.len()).sum();

    let start = Instant::now();
    let _: Vec<AdaptorMsgChunk> = uncompressed_chunks
        .iter()
        .map(|bytes| {
            AdaptorMsgChunk::deserialize_with_mode(&bytes[..], Compress::No, Validate::Yes).unwrap()
        })
        .collect();
    let uncompressed_deser = start.elapsed();

    println!(
        "    Compressed:   ser {:>10}, deser {:>10}, size {}",
        format_duration(compressed_ser),
        format_duration(compressed_deser),
        format_size(compressed_size)
    );
    println!(
        "    Uncompressed: ser {:>10}, deser {:>10}, size {}",
        format_duration(uncompressed_ser),
        format_duration(uncompressed_deser),
        format_size(uncompressed_size)
    );
    println!(
        "    Per-chunk:    ser {:.2?}, deser {:.2?}\n",
        uncompressed_ser / N_DEPOSIT_INPUT_WIRES as u32,
        uncompressed_deser / N_DEPOSIT_INPUT_WIRES as u32
    );

    results.push(BenchResult {
        name: "AdaptorMsg (4 chunks)",
        compressed_size,
        uncompressed_size,
        compressed_ser,
        uncompressed_ser,
        compressed_deser,
        uncompressed_deser,
    });

    // =========================================================================
    // Summary Tables
    // =========================================================================
    println!("=== Summary: Compressed Mode ===\n");
    println!(
        "| {:<26} | {:>10} | {:>12} | {:>12} |",
        "Message", "Size", "Serialize", "Deserialize"
    );
    println!("|{:-<28}|{:-<12}|{:-<14}|{:-<14}|", "", "", "", "");
    for r in &results {
        println!(
            "| {:<26} | {:>10} | {:>12} | {:>12} |",
            r.name,
            format_size(r.compressed_size),
            format_duration(r.compressed_ser),
            format_duration(r.compressed_deser)
        );
    }

    println!("\n=== Summary: Uncompressed Mode ===\n");
    println!(
        "| {:<26} | {:>10} | {:>12} | {:>12} |",
        "Message", "Size", "Serialize", "Deserialize"
    );
    println!("|{:-<28}|{:-<12}|{:-<14}|{:-<14}|", "", "", "", "");
    for r in &results {
        println!(
            "| {:<26} | {:>10} | {:>12} | {:>12} |",
            r.name,
            format_size(r.uncompressed_size),
            format_duration(r.uncompressed_ser),
            format_duration(r.uncompressed_deser)
        );
    }

    println!("\n=== Size Comparison ===\n");
    println!(
        "| {:<26} | {:>12} | {:>12} | {:>10} |",
        "Message", "Uncompressed", "Compressed", "Ratio"
    );
    println!("|{:-<28}|{:-<14}|{:-<14}|{:-<12}|", "", "", "", "");
    for r in &results {
        let ratio = r.uncompressed_size as f64 / r.compressed_size as f64;
        println!(
            "| {:<26} | {:>12} | {:>12} | {:>9.2}x |",
            r.name,
            format_size(r.uncompressed_size),
            format_size(r.compressed_size),
            ratio
        );
    }

    println!("\n=== Key Observations ===\n");
    println!("  • Curve point compression (Compress::Yes) gives ~2x size reduction");
    println!("  • Compressed serialization is slightly FASTER (fewer bytes to write)");
    println!("  • Compressed deserialization is MUCH SLOWER for curve points");
    println!("    (requires point decompression: solving y² = x³ + 7)");
    println!("  • ChallengeResponseMsg has no curve points, so no size difference");
    println!();
    println!("=== Recommendations ===\n");
    println!("  • Storage/Network: Use Compress::Yes (2x smaller)");
    println!("  • Latency-sensitive reads: Use Compress::No (fast deser)");
    println!("  • ChallengeResponseMsg: Either mode works (no curve points)");
}
