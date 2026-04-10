import secrets

import flexitest

from common.base_test import BaseTest
from common.mosaic_e2e import (
    handle_concurrent_withdrawal,
    handle_setup_and_deposits,
)
from envs.mosaic_env import MosaicEnv

NETWORK_SIZE = 5


@flexitest.register
class MosaicConcurrentWithdrawalTest(BaseTest):
    """
    Tests mosaic setup across multiple nodes:
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(NETWORK_SIZE))

    def main(self, ctx: flexitest.RunContext):
        rpcs = {i: ctx.get_service(f"mosaic_{i}").create_rpc() for i in range(NETWORK_SIZE)}

        deposits_idxs = [0]

        tsid_map = handle_setup_and_deposits(self.logger, rpcs, NETWORK_SIZE, deposits_idxs)

        # Single withdrawal: deposit 0, evaluator node 0 vs all its garblers
        withdrawal_inputs = secrets.token_hex(128)
        withdrawal_evaluator = 0
        withdrawal_deposit = 0
        handle_concurrent_withdrawal(
            self.logger,
            rpcs,
            tsid_map,
            evaluator_node=withdrawal_evaluator,
            deposit_idx=withdrawal_deposit,
            withdrawal_inputs=withdrawal_inputs,
            network_size=NETWORK_SIZE,
        )
        self.logger.info("*** WITHDRAWAL COMPLETE ***")

        for garbler in range(NETWORK_SIZE):
            if garbler == withdrawal_evaluator:
                continue

            fault_sighash = secrets.token_hex(32)
            tsids = tsid_map[(garbler, withdrawal_evaluator)]
            signature = rpcs[withdrawal_evaluator].mosaic_signWithFaultSecret(
                tsids.evaluator_tsid, fault_sighash, None
            )

            # evaluator wins, so should get valid signature
            assert signature is not None

        return True
