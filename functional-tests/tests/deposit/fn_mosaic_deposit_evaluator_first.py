import time

import flexitest

from common.base_test import BaseTest
from common.mosaic_e2e import (
    PreparedDeposit,
    handle_all_setups,
    init_evaluator_deposit,
    init_garbler_deposit,
    prepare_deposit,
    wait_all_deposits_ready,
)
from envs.mosaic_env import MosaicEnv

NETWORK_SIZE = 3
DEPOSIT_COUNT = 2


@flexitest.register
class MosaicConcurrentEvaluatorFirstTest(BaseTest):
    """
    Tests multiple mosaic deposit across multiple nodes,
    with all evaluators initializing first, before garblers:
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(NETWORK_SIZE))

    def main(self, ctx: flexitest.RunContext):
        rpcs = {i: ctx.get_service(f"mosaic_{i}").create_rpc() for i in range(NETWORK_SIZE)}
        peer_ids = {i: rpcs[i].mosaic_getRpcPeerId() for i in range(NETWORK_SIZE)}

        tsid_map = handle_all_setups(self.logger, rpcs, peer_ids, NETWORK_SIZE)
        self.logger.info("*** ALL SETUPS COMPLETE ***")

        # Prepare and init deposits on every setup for every deposit index
        prepared: list[tuple[str, PreparedDeposit]] = []
        for deposit_idx in range(DEPOSIT_COUNT):
            for garbler in range(NETWORK_SIZE):
                for evaluator in range(NETWORK_SIZE):
                    if garbler == evaluator:
                        continue
                    tsids = tsid_map[(garbler, evaluator)]
                    name = f"deposit_{deposit_idx}_g{garbler}_e{evaluator}"
                    dep = prepare_deposit(
                        rpcs[garbler],
                        rpcs[evaluator],
                        tsids.garbler_tsid,
                        tsids.evaluator_tsid,
                        deposit_idx,
                    )
                    prepared.append((name, dep))

        for name, dep in prepared:
            init_evaluator_deposit(self.logger, dep, name)

        time.sleep(10)

        for name, dep in prepared:
            init_garbler_deposit(self.logger, dep, name)

        wait_all_deposits_ready(self.logger, prepared)
        self.logger.info("*** ALL DEPOSITS COMPLETE ***")

        return True
