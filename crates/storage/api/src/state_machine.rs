use mosaic_state_machine_api::{StateMachineAdaptorSpec, StateMachineData, StateMachinePairId};

use crate::StorageResult;

/// Storage interface for state machine data.
pub trait StateMachineDb {
    /// Load data for a state machine of type [`StateMachineAdaptorSpec`] identified by `id`, if it
    /// exists.
    fn load_state<Spec: StateMachineAdaptorSpec>(
        &self,
        id: &StateMachinePairId,
    ) -> StorageResult<Option<StateMachineData<Spec>>>;

    /// Save data for a state machine of type [`StateMachineAdaptorSpec`] identified by `id`.
    /// Entries can be marked as `active`, which should also be tracked.
    /// `active` means these states emit actions, so these must be preloaded on startup to restart
    /// the flow.
    fn save_state<Spec: StateMachineAdaptorSpec>(
        &self,
        id: &StateMachinePairId,
        data: &StateMachineData<Spec>,
        active: bool,
    ) -> StorageResult<()>;

    /// Get all entries that are currently marked as `active`.
    fn get_active_states<Spec: StateMachineAdaptorSpec>(
        &self,
    ) -> impl Iterator<Item = StateMachinePairId>;
}
