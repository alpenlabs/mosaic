use mosaic_cac_types::{
    DepositId, WithdrawalInputs,
    state_machine::{
        evaluator::{EvaluatorDepositInitData, EvaluatorDisputedWithdrawalData, EvaluatorInitData},
        garbler::{GarblerDepositInitData, GarblerInitData},
    },
};
use mosaic_net_svc_api::PeerId;

/// SM role targeted by a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmRole {
    /// Garbler state machine.
    Garbler,
    /// Evaluator state machine.
    Evaluator,
}

impl SmRole {
    /// Returns true if role is garbler.
    pub const fn is_garbler(self) -> bool {
        matches!(self, Self::Garbler)
    }

    /// Returns true if role is evaluator.
    pub const fn is_evaluator(self) -> bool {
        matches!(self, Self::Evaluator)
    }
}

/// Peer and role target for an SM command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmTarget {
    /// Peer whose state machine should process the command.
    pub peer_id: PeerId,
    /// Role to route the command to.
    pub role: SmRole,
}

/// Command sent to the SM executor.
#[derive(Debug)]
pub struct SmCommand {
    /// Target peer and role.
    pub target: SmTarget,
    /// Command payload.
    pub kind: SmCommandKind,
}

impl SmCommand {
    /// Build a garbler init command.
    pub fn init_garbler(peer_id: PeerId, data: GarblerInitData) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Garbler,
            },
            kind: SmCommandKind::Init(InitData::Garbler(data)),
        }
    }

    /// Build an evaluator init command.
    pub fn init_evaluator(peer_id: PeerId, data: EvaluatorInitData) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Evaluator,
            },
            kind: SmCommandKind::Init(InitData::Evaluator(data)),
        }
    }

    /// Build a garbler deposit init command.
    pub fn deposit_init_garbler(
        peer_id: PeerId,
        deposit_id: DepositId,
        data: GarblerDepositInitData,
    ) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Garbler,
            },
            kind: SmCommandKind::DepositInit {
                deposit_id,
                data: DepositInitData::Garbler(data),
            },
        }
    }

    /// Build an evaluator deposit init command.
    pub fn deposit_init_evaluator(
        peer_id: PeerId,
        deposit_id: DepositId,
        data: EvaluatorDepositInitData,
    ) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Evaluator,
            },
            kind: SmCommandKind::DepositInit {
                deposit_id,
                data: DepositInitData::Evaluator(data),
            },
        }
    }

    /// Build a garbler disputed withdrawal command.
    pub fn disputed_withdrawal_garbler(
        peer_id: PeerId,
        deposit_id: DepositId,
        withdrawal_inputs: WithdrawalInputs,
    ) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Garbler,
            },
            kind: SmCommandKind::DisputedWithdrawal {
                deposit_id,
                data: DisputedWithdrawalData::Garbler(withdrawal_inputs),
            },
        }
    }

    /// Build an evaluator disputed withdrawal command.
    pub fn disputed_withdrawal_evaluator(
        peer_id: PeerId,
        deposit_id: DepositId,
        data: EvaluatorDisputedWithdrawalData,
    ) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Evaluator,
            },
            kind: SmCommandKind::DisputedWithdrawal {
                deposit_id,
                data: DisputedWithdrawalData::Evaluator(data),
            },
        }
    }

    /// Build a garbler undisputed withdrawal command.
    pub fn undisputed_withdrawal_garbler(peer_id: PeerId, deposit_id: DepositId) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Garbler,
            },
            kind: SmCommandKind::UndisputedWithdrawal { deposit_id },
        }
    }

    /// Build an evaluator undisputed withdrawal command.
    pub fn undisputed_withdrawal_evaluator(peer_id: PeerId, deposit_id: DepositId) -> Self {
        Self {
            target: SmTarget {
                peer_id,
                role: SmRole::Evaluator,
            },
            kind: SmCommandKind::UndisputedWithdrawal { deposit_id },
        }
    }

    /// Target role.
    pub const fn role(&self) -> SmRole {
        self.target.role
    }

    /// Target peer id.
    pub fn peer_id(&self) -> &PeerId {
        &self.target.peer_id
    }
}

/// Init payload for a role-specific SM.
#[derive(Debug)]
pub enum InitData {
    /// Garbler init payload.
    Garbler(GarblerInitData),
    /// Evaluator init payload.
    Evaluator(EvaluatorInitData),
}

/// Deposit init payload for a role-specific SM.
#[derive(Debug)]
pub enum DepositInitData {
    /// Garbler deposit init payload.
    Garbler(GarblerDepositInitData),
    /// Evaluator deposit init payload.
    Evaluator(EvaluatorDepositInitData),
}

/// Disputed withdrawal payload for a role-specific SM.
#[derive(Debug)]
pub enum DisputedWithdrawalData {
    /// Garbler disputed withdrawal input payload.
    Garbler(WithdrawalInputs),
    /// Evaluator disputed withdrawal input payload.
    Evaluator(EvaluatorDisputedWithdrawalData),
}

/// Command payloads accepted by the SM executor.
#[derive(Debug)]
pub enum SmCommandKind {
    /// Initialize statemachine.
    Init(InitData),
    /// Initialize deposit state.
    DepositInit {
        /// Deposit identifier.
        deposit_id: DepositId,
        /// Role-specific payload.
        data: DepositInitData,
    },
    /// Start disputed withdrawal path.
    DisputedWithdrawal {
        /// Deposit identifier.
        deposit_id: DepositId,
        /// Role-specific payload.
        data: DisputedWithdrawalData,
    },
    /// Mark undisputed withdrawal.
    UndisputedWithdrawal {
        /// Deposit identifier.
        deposit_id: DepositId,
    },
}

#[cfg(test)]
mod tests {
    use mosaic_cac_types::{HeapArray, SecretKey, Sighash, Signature};

    use super::*;

    fn sample_garbler_init() -> GarblerInitData {
        GarblerInitData {
            seed: [1; 32].into(),
            setup_inputs: [0; 32],
        }
    }

    fn sample_evaluator_init() -> EvaluatorInitData {
        EvaluatorInitData {
            seed: [2; 32].into(),
            setup_inputs: [0; 32],
        }
    }

    fn sample_sighashes() -> mosaic_cac_types::Sighashes {
        HeapArray::new(|_| Sighash::from([7; 32]))
    }

    fn sample_garbler_deposit_init() -> GarblerDepositInitData {
        let sk = SecretKey::from_raw_bytes(&[11; 32]);
        GarblerDepositInitData {
            pk: sk.to_pubkey(),
            sighashes: sample_sighashes(),
            deposit_inputs: [3; 4],
        }
    }

    fn sample_evaluator_deposit_init() -> EvaluatorDepositInitData {
        EvaluatorDepositInitData {
            sk: SecretKey::from_raw_bytes(&[13; 32]),
            sighashes: sample_sighashes(),
            deposit_inputs: [5; 4],
        }
    }

    fn sample_evaluator_disputed_withdrawal() -> EvaluatorDisputedWithdrawalData {
        let sig = Signature::from_bytes([1; 64]).expect("test signature should deserialize");
        EvaluatorDisputedWithdrawalData {
            signatures: HeapArray::new(|_| sig),
        }
    }

    #[test]
    fn role_helpers_are_consistent() {
        assert!(SmRole::Garbler.is_garbler());
        assert!(!SmRole::Garbler.is_evaluator());
        assert!(SmRole::Evaluator.is_evaluator());
        assert!(!SmRole::Evaluator.is_garbler());
    }

    #[test]
    fn command_builders_enforce_role_payload_pairs() {
        let peer_id = mosaic_net_svc_api::PeerId::from([21; 32]);
        let deposit_id = DepositId::from([22; 32]);

        let cmd = SmCommand::init_garbler(peer_id, sample_garbler_init());
        assert_eq!(cmd.role(), SmRole::Garbler);
        assert_eq!(cmd.peer_id(), &peer_id);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::Init(InitData::Garbler(_))
        ));

        let cmd = SmCommand::init_evaluator(peer_id, sample_evaluator_init());
        assert_eq!(cmd.role(), SmRole::Evaluator);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::Init(InitData::Evaluator(_))
        ));

        let cmd =
            SmCommand::deposit_init_garbler(peer_id, deposit_id, sample_garbler_deposit_init());
        assert_eq!(cmd.role(), SmRole::Garbler);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::DepositInit {
                data: DepositInitData::Garbler(_),
                ..
            }
        ));

        let cmd =
            SmCommand::deposit_init_evaluator(peer_id, deposit_id, sample_evaluator_deposit_init());
        assert_eq!(cmd.role(), SmRole::Evaluator);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::DepositInit {
                data: DepositInitData::Evaluator(_),
                ..
            }
        ));

        let cmd = SmCommand::disputed_withdrawal_garbler(peer_id, deposit_id, [7; 128]);
        assert_eq!(cmd.role(), SmRole::Garbler);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::DisputedWithdrawal {
                data: DisputedWithdrawalData::Garbler(_),
                ..
            }
        ));

        let cmd = SmCommand::disputed_withdrawal_evaluator(
            peer_id,
            deposit_id,
            sample_evaluator_disputed_withdrawal(),
        );
        assert_eq!(cmd.role(), SmRole::Evaluator);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::DisputedWithdrawal {
                data: DisputedWithdrawalData::Evaluator(_),
                ..
            }
        ));

        let cmd = SmCommand::undisputed_withdrawal_garbler(peer_id, deposit_id);
        assert_eq!(cmd.role(), SmRole::Garbler);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::UndisputedWithdrawal { .. }
        ));

        let cmd = SmCommand::undisputed_withdrawal_evaluator(peer_id, deposit_id);
        assert_eq!(cmd.role(), SmRole::Evaluator);
        assert!(matches!(
            cmd.kind,
            SmCommandKind::UndisputedWithdrawal { .. }
        ));
    }
}
