import secrets

import flexitest

from common.mosaic_base import MosaicE2EBase
from common.rpc import JsonRpcClient
from envs.mosaic_env import MosaicEnv


@flexitest.register
class MosaicE2EEvaluatorWinTest(MosaicE2EBase):
    """
    Tests mosaic e2e across 2 nodes with 1 setup, where evaluator wins:
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(2))

    def main(self, ctx: flexitest.RunContext):
        self.garbler = self.get_service("mosaic_0").create_rpc()
        self.evaluator = self.get_service("mosaic_1").create_rpc()

        setup_inputs = secrets.token_hex(32)
        self.handle_setup(setup_inputs)
        self.logger.info("*** SETUP COMPETED ***")

        # even deposit idx -> garbler's proof is invalid and evaluator wins
        deposit_idx = 2
        self.handle_deposit(deposit_idx)
        self.logger.info("*** DEPOSIT COMPETED ***")

        witndrawal_inputs = secrets.token_hex(128)
        self.handle_withdrawal(witndrawal_inputs)
        self.logger.info("*** WITHDRAWAL COMPETED ***")

        fault_sighash = secrets.token_hex(32)
        signature = self.evaluator.mosaic_signWithFaultSecret(
            self.evaluator_tsid, fault_sighash, None
        )

        # evaluator wins, so should get valid signature
        assert signature is not None
