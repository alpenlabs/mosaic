//! Criterion benchmarks for protocol message serialization/deserialization.
//!
//! Run with: cargo bench -p mosaic-cac-types

#![allow(missing_docs)]
#![allow(unused_crate_dependencies)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use mosaic_cac_types::{
    Adaptor, AdaptorMsgChunk, AdaptorMsgChunkWithdrawals, ChallengeIndices, ChallengeMsg,
    ChallengeResponseMsgChunk, CircuitInputShares, CommitMsgChunk, WideLabelWireAdaptors,
    WideLabelWirePolynomialCommitments, WideLabelWireShares,
};
use mosaic_common::constants::{N_DEPOSIT_INPUT_WIRES, N_INPUT_WIRES, N_OPEN_CIRCUITS};
use mosaic_vs3::{Index, Point, Polynomial, Scalar, Share};
use rand::SeedableRng;

/// Benchmark CommitMsgChunk serialization/deserialization.
fn bench_commit_msg_chunk(c: &mut Criterion) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let poly_commit = Polynomial::rand(&mut rng).commit();

    let chunk = CommitMsgChunk {
        wire_index: 0,
        commitments: WideLabelWirePolynomialCommitments::new(|_| poly_commit.clone()),
    };

    // Pre-serialize for deserialization benchmarks
    let mut compressed_bytes = Vec::new();
    chunk
        .serialize_with_mode(&mut compressed_bytes, Compress::Yes)
        .unwrap();

    let mut uncompressed_bytes = Vec::new();
    chunk
        .serialize_with_mode(&mut uncompressed_bytes, Compress::No)
        .unwrap();

    let mut group = c.benchmark_group("CommitMsgChunk");
    group.throughput(Throughput::Bytes(compressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "compressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(compressed_bytes.len());
            chunk
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "compressed"), |b| {
        b.iter(|| {
            CommitMsgChunk::deserialize_with_mode(
                &compressed_bytes[..],
                Compress::Yes,
                Validate::Yes,
            )
            .unwrap()
        })
    });

    group.throughput(Throughput::Bytes(uncompressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "uncompressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(uncompressed_bytes.len());
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "uncompressed"), |b| {
        b.iter(|| {
            CommitMsgChunk::deserialize_with_mode(
                &uncompressed_bytes[..],
                Compress::No,
                Validate::Yes,
            )
            .unwrap()
        })
    });

    group.finish();
}

/// Benchmark ChallengeResponseMsgChunk serialization/deserialization.
fn bench_challenge_response_msg_chunk(c: &mut Criterion) {
    let single_scalar = Scalar::from_le_bytes_mod_order(&[42u8; 32]);
    let idx = Index::new(1).unwrap();
    let single_share = Share::new(idx, single_scalar);

    let chunk = ChallengeResponseMsgChunk {
        circuit_index: 0,
        shares: CircuitInputShares::new(|_| WideLabelWireShares::new(|_| single_share.clone())),
    };

    // Pre-serialize for deserialization benchmarks
    let mut compressed_bytes = Vec::new();
    chunk
        .serialize_with_mode(&mut compressed_bytes, Compress::Yes)
        .unwrap();

    let mut uncompressed_bytes = Vec::new();
    chunk
        .serialize_with_mode(&mut uncompressed_bytes, Compress::No)
        .unwrap();

    let mut group = c.benchmark_group("ChallengeResponseMsgChunk");
    group.throughput(Throughput::Bytes(compressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "compressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(compressed_bytes.len());
            chunk
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "compressed"), |b| {
        b.iter(|| {
            ChallengeResponseMsgChunk::deserialize_with_mode(
                &compressed_bytes[..],
                Compress::Yes,
                Validate::Yes,
            )
            .unwrap()
        })
    });

    group.throughput(Throughput::Bytes(uncompressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "uncompressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(uncompressed_bytes.len());
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "uncompressed"), |b| {
        b.iter(|| {
            ChallengeResponseMsgChunk::deserialize_with_mode(
                &uncompressed_bytes[..],
                Compress::No,
                Validate::Yes,
            )
            .unwrap()
        })
    });

    group.finish();
}

/// Benchmark ChallengeMsg serialization/deserialization.
fn bench_challenge_msg(c: &mut Criterion) {
    let challenge_indices = ChallengeIndices::new(|i| Index::new(i + 1).unwrap());
    let msg = ChallengeMsg { challenge_indices };

    // Pre-serialize for deserialization benchmarks
    let mut compressed_bytes = Vec::new();
    msg.serialize_with_mode(&mut compressed_bytes, Compress::Yes)
        .unwrap();

    let mut uncompressed_bytes = Vec::new();
    msg.serialize_with_mode(&mut uncompressed_bytes, Compress::No)
        .unwrap();

    let mut group = c.benchmark_group("ChallengeMsg");
    group.throughput(Throughput::Bytes(compressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "compressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(compressed_bytes.len());
            msg.serialize_with_mode(&mut bytes, Compress::Yes).unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "compressed"), |b| {
        b.iter(|| {
            ChallengeMsg::deserialize_with_mode(&compressed_bytes[..], Compress::Yes, Validate::Yes)
                .unwrap()
        })
    });

    group.throughput(Throughput::Bytes(uncompressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "uncompressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(uncompressed_bytes.len());
            msg.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "uncompressed"), |b| {
        b.iter(|| {
            ChallengeMsg::deserialize_with_mode(
                &uncompressed_bytes[..],
                Compress::No,
                Validate::Yes,
            )
            .unwrap()
        })
    });

    group.finish();
}

/// Benchmark AdaptorMsgChunk serialization/deserialization.
fn bench_adaptor_msg_chunk(c: &mut Criterion) {
    let single_scalar = Scalar::from_le_bytes_mod_order(&[42u8; 32]);
    let point = Point::generator() * single_scalar;
    let single_adaptor = Adaptor {
        tweaked_s: single_scalar,
        tweaked_r: point,
        share_commitment: point,
    };

    let chunk = AdaptorMsgChunk {
        chunk_index: 0,
        deposit_adaptor: single_adaptor,
        withdrawal_adaptors: AdaptorMsgChunkWithdrawals::new(|_| {
            WideLabelWireAdaptors::new(|_| single_adaptor)
        }),
    };

    // Pre-serialize for deserialization benchmarks
    let mut compressed_bytes = Vec::new();
    chunk
        .serialize_with_mode(&mut compressed_bytes, Compress::Yes)
        .unwrap();

    let mut uncompressed_bytes = Vec::new();
    chunk
        .serialize_with_mode(&mut uncompressed_bytes, Compress::No)
        .unwrap();

    let mut group = c.benchmark_group("AdaptorMsgChunk");
    group.throughput(Throughput::Bytes(compressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "compressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(compressed_bytes.len());
            chunk
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "compressed"), |b| {
        b.iter(|| {
            AdaptorMsgChunk::deserialize_with_mode(
                &compressed_bytes[..],
                Compress::Yes,
                Validate::Yes,
            )
            .unwrap()
        })
    });

    group.throughput(Throughput::Bytes(uncompressed_bytes.len() as u64));

    group.bench_function(BenchmarkId::new("serialize", "uncompressed"), |b| {
        b.iter(|| {
            let mut bytes = Vec::with_capacity(uncompressed_bytes.len());
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
    });

    group.bench_function(BenchmarkId::new("deserialize", "uncompressed"), |b| {
        b.iter(|| {
            AdaptorMsgChunk::deserialize_with_mode(
                &uncompressed_bytes[..],
                Compress::No,
                Validate::Yes,
            )
            .unwrap()
        })
    });

    group.finish();
}

/// Benchmark full message sets (all chunks for a complete protocol message).
fn bench_full_messages(c: &mut Criterion) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let single_scalar = Scalar::from_le_bytes_mod_order(&[42u8; 32]);

    // CommitMsg: N_INPUT_WIRES chunks
    let poly_commit = Polynomial::rand(&mut rng).commit();
    let commit_chunks: Vec<CommitMsgChunk> = (0..N_INPUT_WIRES)
        .map(|i| CommitMsgChunk {
            wire_index: i as u16,
            commitments: WideLabelWirePolynomialCommitments::new(|_| poly_commit.clone()),
        })
        .collect();

    let commit_uncompressed: Vec<Vec<u8>> = commit_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
        .collect();
    let commit_total_size: usize = commit_uncompressed.iter().map(|b| b.len()).sum();

    // ChallengeResponseMsg: N_OPEN_CIRCUITS chunks
    let idx = Index::new(1).unwrap();
    let single_share = Share::new(idx, single_scalar);
    let response_chunks: Vec<ChallengeResponseMsgChunk> = (0..N_OPEN_CIRCUITS)
        .map(|i| ChallengeResponseMsgChunk {
            circuit_index: i as u16,
            shares: CircuitInputShares::new(|_| WideLabelWireShares::new(|_| single_share.clone())),
        })
        .collect();

    let response_uncompressed: Vec<Vec<u8>> = response_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
        .collect();
    let response_total_size: usize = response_uncompressed.iter().map(|b| b.len()).sum();

    // AdaptorMsg: N_DEPOSIT_INPUT_WIRES chunks
    let point = Point::generator() * single_scalar;
    let single_adaptor = Adaptor {
        tweaked_s: single_scalar,
        tweaked_r: point,
        share_commitment: point,
    };
    let adaptor_chunks: Vec<AdaptorMsgChunk> = (0..N_DEPOSIT_INPUT_WIRES)
        .map(|i| AdaptorMsgChunk {
            chunk_index: i as u8,
            deposit_adaptor: single_adaptor,
            withdrawal_adaptors: AdaptorMsgChunkWithdrawals::new(|_| {
                WideLabelWireAdaptors::new(|_| single_adaptor)
            }),
        })
        .collect();

    let adaptor_uncompressed: Vec<Vec<u8>> = adaptor_chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            chunk.serialize_with_mode(&mut bytes, Compress::No).unwrap();
            bytes
        })
        .collect();
    let adaptor_total_size: usize = adaptor_uncompressed.iter().map(|b| b.len()).sum();

    let mut group = c.benchmark_group("FullMessage");

    // CommitMsg (all chunks)
    group.throughput(Throughput::Bytes(commit_total_size as u64));
    group.bench_function(
        BenchmarkId::new("CommitMsg", format!("{}_chunks", N_INPUT_WIRES)),
        |b| {
            b.iter(|| {
                commit_uncompressed
                    .iter()
                    .map(|bytes| {
                        CommitMsgChunk::deserialize_with_mode(
                            &bytes[..],
                            Compress::No,
                            Validate::Yes,
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
        },
    );

    // ChallengeResponseMsg (all chunks)
    group.throughput(Throughput::Bytes(response_total_size as u64));
    group.bench_function(
        BenchmarkId::new(
            "ChallengeResponseMsg",
            format!("{}_chunks", N_OPEN_CIRCUITS),
        ),
        |b| {
            b.iter(|| {
                response_uncompressed
                    .iter()
                    .map(|bytes| {
                        ChallengeResponseMsgChunk::deserialize_with_mode(
                            &bytes[..],
                            Compress::No,
                            Validate::Yes,
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
        },
    );

    // AdaptorMsg (all chunks)
    group.throughput(Throughput::Bytes(adaptor_total_size as u64));
    group.bench_function(
        BenchmarkId::new("AdaptorMsg", format!("{}_chunks", N_DEPOSIT_INPUT_WIRES)),
        |b| {
            b.iter(|| {
                adaptor_uncompressed
                    .iter()
                    .map(|bytes| {
                        AdaptorMsgChunk::deserialize_with_mode(
                            &bytes[..],
                            Compress::No,
                            Validate::Yes,
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_commit_msg_chunk,
    bench_challenge_response_msg_chunk,
    bench_challenge_msg,
    bench_adaptor_msg_chunk,
    bench_full_messages,
);

criterion_main!(benches);
