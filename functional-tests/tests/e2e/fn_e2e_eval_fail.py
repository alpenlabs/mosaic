import secrets

import flexitest

from common.base_test import BaseTest
from common.mosaic_e2e import handle_deposit, handle_setup, handle_withdrawal
from envs.mosaic_env import MosaicEnv


@flexitest.register
class MosaicE2EEvaluatorFailTest(BaseTest):
    """
    Tests mosaic e2e across 2 nodes with 1 setup, where evaluator fails:
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(2))

    def main(self, ctx: flexitest.RunContext):
        garbler = ctx.get_service("mosaic_0").create_rpc()
        evaluator = ctx.get_service("mosaic_1").create_rpc()

        setup_inputs = secrets.token_hex(32)
        garbler_tsid, evaluator_tsid = handle_setup(self.logger, garbler, evaluator, setup_inputs)
        self.logger.info("*** SETUP COMPETED ***")

        # odd deposit idx -> garbler's proof is valid and evaluator loses
        deposit_idx = 1
        deposit_id = handle_deposit(
            self.logger, garbler, evaluator, garbler_tsid, evaluator_tsid, deposit_idx
        )
        self.logger.info("*** DEPOSIT COMPETED ***")

        witndrawal_inputs = secrets.token_hex(128)
        handle_withdrawal(
            self.logger,
            garbler,
            evaluator,
            garbler_tsid,
            evaluator_tsid,
            deposit_id,
            witndrawal_inputs,
        )
        self.logger.info("*** WITHDRAWAL COMPETED ***")

        fault_sighash = secrets.token_hex(32)
        signature = evaluator.mosaic_signWithFaultSecret(evaluator_tsid, fault_sighash, None)

        # evaluator loses, so should not get valid signature
        assert signature is None
