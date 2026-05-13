import secrets

import flexitest

from common.base_test import BaseTest
from common.mosaic_e2e import (
    check_setup_consumed,
    handle_deposit,
    handle_setup,
)
from common.rpc import RpcError
from common.wait import wait_until
from envs.mosaic_env import MosaicEnv


@flexitest.register
class MosaicE2EDepositAfterWithdrawalTest(BaseTest):
    """
    Tests that after a withdrawal is initiated and after it completes:
    1. A new deposit can be created on the same tableset.
    2. A new withdrawal on the consumed setup fails with InvalidInputForState.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(2))

    def main(self, ctx: flexitest.RunContext):
        garbler = ctx.get_service("mosaic_0").create_rpc()
        evaluator = ctx.get_service("mosaic_1").create_rpc()

        setup_inputs = secrets.token_hex(32)
        garbler_tsid, evaluator_tsid = handle_setup(self.logger, garbler, evaluator, setup_inputs)
        self.logger.info("*** SETUP COMPLETED ***")

        # even deposit idx -> evaluator wins
        deposit_idx = 2
        deposit_id = handle_deposit(
            self.logger, garbler, evaluator, garbler_tsid, evaluator_tsid, deposit_idx
        )
        self.logger.info("*** DEPOSIT COMPLETED ***")

        # -- Initiate withdrawal (garbler side only) --
        withdrawal_inputs = secrets.token_hex(128)
        garbler.mosaic_completeAdaptorSigs(garbler_tsid, deposit_id, withdrawal_inputs)

        wait_until(
            lambda: check_setup_consumed(self.logger, "garbler withdrawal", garbler_tsid, garbler),
            error_msg="garbler withdrawal did not complete within timeout",
        )
        self.logger.info("*** WITHDRAWAL INITIATED (garbler consumed) ***")

        # -- Checks after withdrawal initiated (garbler consumed, evaluator still SetupComplete) --

        # Check 2: re-initiating withdrawal on the same deposit should fail
        # RPC error code 12 = InvalidInputForState (tableset is no longer SetupComplete)
        try:
            garbler.mosaic_completeAdaptorSigs(garbler_tsid, deposit_id, secrets.token_hex(128))
            raise AssertionError("expected withdrawal to fail on consumed garbler")
        except RpcError as e:
            self.logger.info(
                f"withdrawal on consumed garbler correctly rejected: code={e.code} msg={e.msg}"
            )
            assert e.code == 12, f"expected error code 12 (InvalidInputForState), got {e.code}"

        # Check 1: new deposit should be allowed on the same tableset
        new_deposit_idx_1 = 4
        handle_deposit(
            self.logger, garbler, evaluator, garbler_tsid, evaluator_tsid, new_deposit_idx_1
        )
        self.logger.info("new deposit after withdrawal initiated: OK")

        # -- Complete withdrawal (evaluator side) --
        completed_adaptor_sigs = garbler.mosaic_getCompletedAdaptorSigs(garbler_tsid)
        evaluator.mosaic_evaluateTableset(
            evaluator_tsid,
            deposit_id,
            {
                "withdrawal_inputs": withdrawal_inputs,
                "completed_signatures": completed_adaptor_sigs,
            },
        )

        wait_until(
            lambda: check_setup_consumed(
                self.logger, "evaluator withdrawal", evaluator_tsid, evaluator
            ),
            error_msg="evaluator withdrawal did not complete within timeout",
        )
        self.logger.info("*** WITHDRAWAL COMPLETED (both consumed) ***")

        # -- Checks after withdrawal completed (both sides consumed) --

        # Check 2: re-initiating withdrawal on the same deposit should fail
        # RPC error code 12 = InvalidInputForState (tableset is no longer SetupComplete)
        try:
            evaluator.mosaic_evaluateTableset(
                evaluator_tsid,
                deposit_id,
                {
                    "withdrawal_inputs": secrets.token_hex(128),
                    "completed_signatures": completed_adaptor_sigs,
                },
            )
            raise AssertionError("expected withdrawal to fail on consumed evaluator")
        except RpcError as e:
            self.logger.info(
                f"withdrawal on consumed evaluator correctly rejected: code={e.code} msg={e.msg}"
            )
            assert e.code == 12, f"expected error code 12 (InvalidInputForState), got {e.code}"

        # Check 1: new deposit should be allowed on the same tableset
        new_deposit_idx_2 = 6
        handle_deposit(
            self.logger, garbler, evaluator, garbler_tsid, evaluator_tsid, new_deposit_idx_2
        )
        self.logger.info("new deposit after withdrawal completed: OK")
