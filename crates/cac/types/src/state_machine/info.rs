use mosaic_net_svc_api::PeerId;
use sha2::{Digest, Sha256};

use super::StateMachineId;

/// State machine info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateMachineInfo {
    garbler: PeerId,
    evaluator: PeerId,
    instance: u64,
}

impl StateMachineInfo {
    /// Compute deterministic id of this state machine
    pub fn id(&self) -> StateMachineId {
        let mut s = [0u8; 32 + 32 + 8];
        s[0..32].copy_from_slice(Sha256::digest(self.garbler.as_bytes()).as_slice());
        s[32..64].copy_from_slice(Sha256::digest(self.evaluator.as_bytes()).as_slice());
        s[64..].copy_from_slice(&self.instance.to_be_bytes());
        let x: [u8; 32] = Sha256::digest(s).into();
        StateMachineId(x.into())
    }
}
