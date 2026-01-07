//! Deposit Stage Garbler

use core::panic;

use mosaic_cac_types::{
    CompletedSignatures, DepositAdaptors, DepositInputs, ReservedDepositInputShares,
    ReservedWithdrawalInputShares, Sighash, WithdrawalAdaptors, WithdrawalInputs,
};
use mosaic_common::constants::{N_DEPOSIT_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES};
use mosaic_vs3::Point;

use crate::setup_garbler::ReservedNonSetupInputShares;

/// WaitAdaptorsGarbState
#[derive(Debug)]
pub struct WaitAdaptorsGarbState {
    /// reserved input shares for wires other than setup data
    pub input_shares: ReservedNonSetupInputShares,
}

/// DepositGarbData
#[derive(Debug)]
pub struct DepositGarbData {
    /// sighashes provided by bridge
    pub sighashes: [Sighash; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES],
    /// evaluator's public key used with adaptors
    pub evaluator_pk: Point,
    /// deposit input
    pub deposit_input: DepositInputs,
}

/// AdaptorMsg: Evaluator -> Garbler
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptorMsg {
    /// N_DEPOSIT_INPUT_WIRES
    pub deposit_adaptors: Box<DepositAdaptors>,
    /// N_WITHDRAWAL_INPUT_WIRES * 256
    pub withdrawal_adaptors: Box<WithdrawalAdaptors>,
}

impl WaitAdaptorsGarbState {
    /// exec_verify_adaptors
    pub fn exec_verify_adaptors(
        &self,
        deposit_data: DepositGarbData,
        adaptor_msg: AdaptorMsg,
    ) -> WaitProofGarbState {
        let deposit_adaptors: DepositAdaptors = *adaptor_msg.deposit_adaptors;
        let withdrawal_adaptors: WithdrawalAdaptors = *adaptor_msg.withdrawal_adaptors;
        let deposit_input = deposit_data.deposit_input;

        // select deposit input shares using deposit_input, one per wire
        let deposit_input_shares: ReservedDepositInputShares = std::array::from_fn(|wire| {
            self.input_shares[wire][deposit_input[wire] as usize].clone()
        });

        // withdrawal input not yet known, store one per value, per wire
        let withdrawal_input_shares: &ReservedWithdrawalInputShares = self.input_shares
            [N_DEPOSIT_INPUT_WIRES..]
            .try_into()
            .expect("match length");

        // Verify deposit adaptors with sighash, input shares
        let evaluator_master_pk = deposit_data.evaluator_pk;
        let sighashes = deposit_data.sighashes;
        for (i, adaptor) in deposit_adaptors.iter().enumerate() {
            if adaptor
                .verify(evaluator_master_pk, sighashes[i].0.as_ref())
                .is_err()
            {
                panic!("failed adaptor verification of {i}-th deposit adaptor");
            }
        }

        // Verify withdrawal adaptors with wire-specific sighash, input shares
        for (wire, wire_adaptors) in withdrawal_adaptors.iter().enumerate() {
            for (val, adaptor) in wire_adaptors.iter().enumerate() {
                if adaptor
                    .verify(
                        evaluator_master_pk,
                        sighashes[N_DEPOSIT_INPUT_WIRES + wire].0.as_ref(),
                    )
                    .is_err()
                {
                    panic!("failed adaptor verification of {wire}{val}-th withdrawal adaptor")
                }
            }
        }

        WaitProofGarbState {
            deposit_input_shares,
            withdrawal_input_shares: withdrawal_input_shares.clone(),
            deposit_adaptors,
            withdrawal_adaptors,
        }
    }
}

/// WaitProofGarbState
#[derive(Debug)]
pub struct WaitProofGarbState {
    /// deposit input shares given deposit input value
    pub deposit_input_shares: ReservedDepositInputShares,
    /// withdrawal input shares for all possible withdrawal input values
    pub withdrawal_input_shares: ReservedWithdrawalInputShares,
    /// deposit adaptors given deposit input value
    pub deposit_adaptors: DepositAdaptors,
    /// withdrawal adaptors for all possible withdrawal input values
    pub withdrawal_adaptors: WithdrawalAdaptors,
}

/// WithdrawalGarbData
#[derive(Debug)]
pub struct WithdrawalGarbData {
    /// withdrwawal input value
    pub withdrawal_input: WithdrawalInputs,
}

/// SigMsg
#[derive(Debug)]
pub struct SigMsg {
    /// withdrawal input values
    pub withdrawal_input: WithdrawalInputs,
    /// signatures corresponding to deposit and withdrawal message
    pub signatures: CompletedSignatures,
}

impl WaitProofGarbState {
    /// exec_sign
    pub fn exec_sign(&self, withdrawal_data: WithdrawalGarbData) -> (FinishGarbState, SigMsg) {
        let mut signatures = vec![];
        for (wire, adaptor) in self.deposit_adaptors.iter().enumerate() {
            signatures.push(adaptor.complete(self.deposit_input_shares[wire].value()));
        }

        for (wire, adaptor) in self.withdrawal_adaptors.iter().enumerate() {
            let val = withdrawal_data.withdrawal_input[wire] as usize;
            signatures.push(adaptor[val].complete(self.withdrawal_input_shares[wire][val].value()));
        }

        let next_state = FinishGarbState {};
        let msg = SigMsg {
            withdrawal_input: withdrawal_data.withdrawal_input,
            signatures: signatures.try_into().unwrap(),
        };
        (next_state, msg)
    }
}

/// FinishGarbState
#[derive(Debug)]
pub struct FinishGarbState {}
