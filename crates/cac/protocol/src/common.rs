use mosaic_cac_types::{
    AllGarblingTableCommitments, ChallengeIndices, EvalGarblingTableCommitments, EvaluationIndices,
    HeapArray, Index, Seed,
};
use mosaic_common::constants::{N_CIRCUITS, N_EVAL_CIRCUITS};

pub(crate) fn get_eval_indices(challenge_indices: &ChallengeIndices) -> EvaluationIndices {
    let challenged_indices: Vec<usize> = challenge_indices
        .iter()
        .map(|x| x.get())
        .collect::<Vec<usize>>();
    let unchallenged_indices: [Index; N_EVAL_CIRCUITS] = (1..=N_CIRCUITS)
        .filter(|id| !challenged_indices.contains(id))
        .map(|id| Index::new(id).expect("indices in valid range"))
        .collect::<Vec<Index>>()
        .try_into()
        .expect("unchallenge length");
    unchallenged_indices
}

pub(crate) fn get_eval_commitments(
    eval_indices: &EvaluationIndices,
    garbling_commitments: &AllGarblingTableCommitments,
) -> EvalGarblingTableCommitments {
    HeapArray::new(|i| {
        // eval_indices are 1-indexed (1..=181), garbling_commitments are 0-indexed (0..=180)
        let seed_idx = eval_indices[i].get() - 1;
        garbling_commitments[seed_idx]
    })
}

/// Derive a high-entropy stage seed.
///
/// This is done using BLAKE3 in KDF mode, with the `stage` used as static context and the
/// high-entropy 32-byte `base_seed` as key material. You can optionally supply `dynamic` context
/// data (which may be low entropy) that is included with the key material, per the BLAKE3
/// specification. This is useful for cases where a stage needs more differentiation than a single
/// static context can provide.
pub fn derive_stage_seed(base_seed: Seed, stage: &str, dynamic: Option<&[u8]>) -> Seed {
    let key_material = if let Some(bytes) = dynamic {
        [base_seed.as_bytes(), bytes].concat()
    } else {
        base_seed.as_bytes().to_vec()
    };
    let seed = blake3::derive_key(stage, &key_material);
    Seed::from(seed)
}
