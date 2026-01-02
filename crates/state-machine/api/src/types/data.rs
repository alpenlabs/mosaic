use mosaic_cac_proto_types::CacRole;
use mosaic_common::PeerId;

use crate::{StateMachineAdaptorSpec, StateMachinePairId, StateMachinePairInfo};

/// Additional metadata associated with a state machine used by executor.
#[derive(Debug, Clone)]
pub struct StateMachineMetadata {
    /// id of peer to this garbling setup
    pub peer_id: PeerId,
    /// distinguishes between multiple instances of this state machine running between same pair.
    pub instance: u64,
}

/// All the data related to a state machine needed to run it on the executor.
#[derive(Debug)]
pub struct StateMachineData<Spec: StateMachineAdaptorSpec> {
    /// State machine config
    pub config: Spec::Config,
    /// State machine state
    pub state: Spec::State,
    /// Additional state used by adaptor glue layer.
    pub work_state: Spec::AdaptorState,
    /// Additional state machine metadata use by executor.
    pub metadata: StateMachineMetadata,
}

impl<Spec: StateMachineAdaptorSpec> StateMachineData<Spec> {
    /// Create [`StateMachinePairInfo`] from this [`StateMachineData`].
    pub fn state_machine_pair(&self, own_id: PeerId) -> StateMachinePairInfo {
        let (garbler, evaluator) = if Spec::ROLE == CacRole::Garbler {
            (own_id, self.metadata.peer_id.clone())
        } else {
            (self.metadata.peer_id.clone(), own_id)
        };
        StateMachinePairInfo {
            garbler,
            evaluator,
            phase: Spec::PHASE,
            instance: self.metadata.instance,
        }
    }

    /// Get [`StateMachinePairId`] for this [`StateMachineData`].
    pub fn id(&self, own_id: PeerId) -> StateMachinePairId {
        self.state_machine_pair(own_id).id()
    }
}
