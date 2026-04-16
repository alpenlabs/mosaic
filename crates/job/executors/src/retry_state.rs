//! Evaluator state wrapper with transparent FDB transaction retry.

use mosaic_cac_types::{
    ChallengeIndices, CircuitInputShares, DepositId, WideLabelWirePolynomialCommitments,
};
use mosaic_job_api::CircuitError;
use mosaic_net_svc_api::PeerId;
use mosaic_storage_api::StorageProvider;
use mosaic_vs3::{Index, Share};
use tracing::warn;

/// Wrapper over an evaluator state handle that transparently re-creates the
/// underlying transaction on read errors (e.g. FDB error 1007 —
/// `transaction_timed_out`).
///
/// FoundationDB transactions have a ~5-second timeout. When a handler performs
/// long-running I/O (e.g. bulk network transfers) between storage reads, or
/// when iterating over many keys within a single transaction, the underlying
/// transaction may expire. This wrapper detects any read error, obtains a fresh
/// state handle from the [`StorageProvider`], and retries the failed read once.
///
/// Implements [`StateRead`] so it can be used as a drop-in replacement for a
/// bare evaluator state handle.
///
/// For non-FDB backends (e.g. in-memory), the retry is harmless — if the
/// first read fails the second will almost certainly fail too, and the error
/// propagates normally.
pub(crate) struct RetryEvalState<'a, SP: StorageProvider> {
    storage: &'a SP,
    peer_id: &'a PeerId,
    state: std::cell::UnsafeCell<SP::EvaluatorState>,
}

// SAFETY: monoio is a cooperative, thread-per-core runtime — tasks on a worker
// thread never run concurrently and values never migrate between threads.
// `refresh()` is only called after a failed `.await` (the borrowing future has
// been dropped), so no aliasing between `inner()` reads and `refresh()` writes
// can occur.
unsafe impl<SP: StorageProvider> Send for RetryEvalState<'_, SP> {}
unsafe impl<SP: StorageProvider> Sync for RetryEvalState<'_, SP> {}

impl<'a, SP: StorageProvider> RetryEvalState<'a, SP> {
    /// Create a new wrapper, obtaining the initial state handle.
    pub(crate) async fn new(storage: &'a SP, peer_id: &'a PeerId) -> Result<Self, CircuitError> {
        let state = storage
            .evaluator_state(peer_id)
            .await
            .map_err(|_| CircuitError::StorageUnavailable)?;
        Ok(Self {
            storage,
            peer_id,
            state: std::cell::UnsafeCell::new(state),
        })
    }

    /// Get a shared reference to the inner state.
    fn inner(&self) -> &SP::EvaluatorState {
        // SAFETY: monoio is cooperative — no other task can be in `refresh()`
        // concurrently, so no mutable alias exists.
        unsafe { &*self.state.get() }
    }

    /// Replace the inner state handle with a fresh one (new FDB transaction).
    ///
    /// # Safety requirement (upheld by callers and the monoio runtime)
    /// Must only be called when no future borrowing the previous state is alive
    /// (i.e. after the failed `.await` has completed). monoio's cooperative
    /// scheduling ensures no concurrent task can hold a reference via `inner()`.
    async fn refresh(&self) -> Result<(), CircuitError> {
        let new_state = self
            .storage
            .evaluator_state(self.peer_id)
            .await
            .map_err(|_| CircuitError::StorageUnavailable)?;
        // SAFETY: The failed `.await` has completed and its future (which
        // borrowed the old state) has been dropped, so no references to the
        // old state exist. monoio's cooperative scheduling guarantees no
        // other task is concurrently reading via `inner()`.
        unsafe { *self.state.get() = new_state };
        Ok(())
    }
}

/// Generate a `StateRead` method on `RetryEvalState` that delegates to the
/// inner state and retries once with a fresh transaction on error.
macro_rules! impl_retry_read {
    // Methods with no extra arguments.
    ( fn $method:ident(&self $(,)?) -> $ret:ty ) => {
        fn $method(&self) -> impl Future<Output = $ret> + Send {
            async {
                match self.inner().$method().await {
                    Ok(val) => Ok(val),
                    Err(err) => {
                        let peer_id = self.peer_id;
                        warn!(%peer_id, ?err, concat!(stringify!($method), " failed, retrying with fresh txn"));
                        self.refresh().await.map_err(|_| err)?;
                        self.inner().$method().await
                    }
                }
            }
        }
    };
    // Methods with Copy/reference arguments — can be passed twice without clone.
    // Do NOT use this variant for non-Copy value args (e.g. Range<usize>).
    ( fn $method:ident(&self, $($arg:ident : $arg_ty:ty),+ $(,)?) -> $ret:ty ) => {
        fn $method(&self, $($arg: $arg_ty),+) -> impl Future<Output = $ret> + Send {
            async move {
                match self.inner().$method($($arg),+).await {
                    Ok(val) => Ok(val),
                    Err(err) => {
                        let peer_id = self.peer_id;
                        warn!(%peer_id, ?err, concat!(stringify!($method), " failed, retrying with fresh txn"));
                        self.refresh().await.map_err(|_| err)?;
                        self.inner().$method($($arg),+).await
                    }
                }
            }
        }
    };
}

impl<'a, SP: StorageProvider> mosaic_cac_types::state_machine::evaluator::StateRead
    for RetryEvalState<'a, SP>
{
    type Error =
        <SP::EvaluatorState as mosaic_cac_types::state_machine::evaluator::StateRead>::Error;

    impl_retry_read!(fn get_root_state(&self) -> Result<Option<mosaic_cac_types::state_machine::evaluator::EvaluatorState>, Self::Error>);
    impl_retry_read!(fn get_deposit(&self, deposit_id: &DepositId) -> Result<Option<mosaic_cac_types::state_machine::evaluator::DepositState>, Self::Error>);
    impl_retry_read!(fn get_input_polynomial_commitments_for_wire(&self, wire_idx: u16) -> Result<Option<WideLabelWirePolynomialCommitments>, Self::Error>);
    impl_retry_read!(fn get_output_polynomial_commitment(&self) -> Result<Option<mosaic_cac_types::OutputPolynomialCommitment>, Self::Error>);
    // Manual impl: Range<usize> is not Copy, so we clone for the retry.
    async fn get_input_polynomial_zeroth_coefficients(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<mosaic_cac_types::WideLabelZerothPolynomialCoefficients>, Self::Error> {
        let retry_range = range.clone();
        match self
            .inner()
            .get_input_polynomial_zeroth_coefficients(range)
            .await
        {
            Ok(val) => Ok(val),
            Err(err) => {
                let peer_id = self.peer_id;
                warn!(%peer_id, ?err, "get_input_polynomial_zeroth_coefficients failed, retrying with fresh txn");
                self.refresh().await.map_err(|_| err)?;
                self.inner()
                    .get_input_polynomial_zeroth_coefficients(retry_range)
                    .await
            }
        }
    }
    impl_retry_read!(fn get_garbling_table_commitments(&self) -> Result<Option<mosaic_cac_types::AllGarblingTableCommitments>, Self::Error>);
    impl_retry_read!(fn get_challenge_indices(&self) -> Result<Option<ChallengeIndices>, Self::Error>);
    impl_retry_read!(fn get_opened_input_shares_for_circuit(&self, circuit_idx: u16) -> Result<Option<CircuitInputShares>, Self::Error>);
    impl_retry_read!(fn get_reserved_setup_input_shares(&self) -> Result<Option<mosaic_cac_types::ReservedSetupInputShares>, Self::Error>);
    impl_retry_read!(fn get_opened_output_shares(&self) -> Result<Option<mosaic_cac_types::OpenedOutputShares>, Self::Error>);
    impl_retry_read!(fn get_opened_garbling_seeds(&self) -> Result<Option<mosaic_cac_types::OpenedGarblingSeeds>, Self::Error>);
    impl_retry_read!(fn get_deposit_sighashes(&self, deposit_id: &DepositId) -> Result<Option<mosaic_cac_types::Sighashes>, Self::Error>);
    impl_retry_read!(fn get_deposit_inputs(&self, deposit_id: &DepositId) -> Result<Option<mosaic_cac_types::DepositInputs>, Self::Error>);
    impl_retry_read!(fn get_withdrawal_inputs(&self, deposit_id: &DepositId) -> Result<Option<mosaic_cac_types::WithdrawalInputs>, Self::Error>);
    impl_retry_read!(fn get_deposit_adaptors(&self, deposit_id: &DepositId) -> Result<Option<mosaic_cac_types::DepositAdaptors>, Self::Error>);
    impl_retry_read!(fn get_withdrawal_adaptors(&self, deposit_id: &DepositId) -> Result<Option<mosaic_cac_types::WithdrawalAdaptors>, Self::Error>);
    impl_retry_read!(fn get_completed_signatures(&self, deposit_id: &DepositId) -> Result<Option<mosaic_cac_types::CompletedSignatures>, Self::Error>);
    impl_retry_read!(fn get_aes128_key(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error>);
    impl_retry_read!(fn get_public_s(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error>);
    impl_retry_read!(fn get_constant_zero_label(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error>);
    impl_retry_read!(fn get_constant_one_label(&self, index: Index) -> Result<Option<[u8; 16]>, Self::Error>);
    impl_retry_read!(fn get_output_label_ct(&self, index: Index) -> Result<Option<mosaic_common::Byte32>, Self::Error>);
    impl_retry_read!(fn get_fault_secret_share(&self) -> Result<Option<Share>, Self::Error>);

    fn stream_all_deposits(
        &self,
    ) -> impl futures::Stream<
        Item = Result<
            (
                mosaic_cac_types::DepositId,
                mosaic_cac_types::state_machine::evaluator::DepositState,
            ),
            Self::Error,
        >,
    > + Send {
        self.inner().stream_all_deposits()
    }
}
