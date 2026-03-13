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

// derive stage seed
pub(crate) fn derive_stage_seed(base_seed: Seed, stage: &str) -> Seed {
    let base_seed: [u8; 32] = base_seed.into();
    let hash = blake3::keyed_hash(&base_seed, stage.as_bytes());
    Seed::from(*hash.as_bytes())
}
