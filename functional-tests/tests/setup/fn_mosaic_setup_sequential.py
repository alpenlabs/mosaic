import secrets

import flexitest

from common.base_test import BaseTest
from common.mosaic_e2e import handle_setup
from envs.mosaic_env import MosaicEnv

NETWORK_SIZE = 3


@flexitest.register
class MosaicSetupSequentialTest(BaseTest):
    """
    Tests mosaic setup across multiple nodes where each (garbler, evaluator)
    direction completes fully before the next one starts.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(NETWORK_SIZE))

    def main(self, ctx: flexitest.RunContext):
        rpcs = {i: ctx.get_service(f"mosaic_{i}").create_rpc() for i in range(NETWORK_SIZE)}

        for garbler in range(NETWORK_SIZE):
            for evaluator in range(NETWORK_SIZE):
                if garbler == evaluator:
                    continue

                setup_inputs = secrets.token_hex(32)
                self.logger.info(
                    f"Starting setup: node{garbler} garbler -> node{evaluator} evaluator"
                )
                handle_setup(self.logger, rpcs[garbler], rpcs[evaluator], setup_inputs)
                self.logger.info(
                    f"Setup complete: node{garbler} garbler -> node{evaluator} evaluator"
                )

        self.logger.info("*** ALL SETUPS COMPLETE ***")
        return True
