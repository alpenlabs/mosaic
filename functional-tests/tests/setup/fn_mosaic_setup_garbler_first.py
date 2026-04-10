import secrets
import time

import flexitest

from common.base_test import BaseTest
from common.mosaic_e2e import TablesetPair, TsidMap, wait_all_setup_complete
from envs.mosaic_env import MosaicEnv

NETWORK_SIZE = 3


@flexitest.register
class MosaicSetupGerblerFirstTest(BaseTest):
    """
    Tests mosaic setup across multiple nodes where all garbler setups
    are issued first, then after a 10s delay, all evaluator setups are issued.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(NETWORK_SIZE))

    def main(self, ctx: flexitest.RunContext):
        rpcs = {i: ctx.get_service(f"mosaic_{i}").create_rpc() for i in range(NETWORK_SIZE)}
        peer_ids = {i: rpcs[i].mosaic_getRpcPeerId() for i in range(NETWORK_SIZE)}

        instance_id = "0" * 64
        setups = []
        tsid_map: TsidMap = {}

        # Phase 1: issue all garbler setups
        setup_inputs_map: dict[tuple[int, int], str] = {}
        for garbler in range(NETWORK_SIZE):
            for evaluator in range(NETWORK_SIZE):
                if garbler == evaluator:
                    continue

                setup_inputs = secrets.token_hex(32)
                setup_inputs_map[(garbler, evaluator)] = setup_inputs

                tsid_g = rpcs[garbler].mosaic_setupTableset(
                    {
                        "role": "garbler",
                        "peer_info": {"peer_id": peer_ids[evaluator]},
                        "setup_inputs": setup_inputs,
                        "instance_id": instance_id,
                    }
                )
                name_g = f"node{garbler}_garbler_to_node{evaluator}"
                self.logger.info(f"{name_g}: {tsid_g}")
                setups.append((name_g, rpcs[garbler], tsid_g))

                tsid_map[(garbler, evaluator)] = TablesetPair(tsid_g, "")

        self.logger.info("*** ALL GARBLER SETUPS ISSUED, waiting 10s ***")
        time.sleep(10)

        # Phase 2: issue all evaluator setups
        for garbler in range(NETWORK_SIZE):
            for evaluator in range(NETWORK_SIZE):
                if garbler == evaluator:
                    continue

                setup_inputs = setup_inputs_map[(garbler, evaluator)]

                tsid_e = rpcs[evaluator].mosaic_setupTableset(
                    {
                        "role": "evaluator",
                        "peer_info": {"peer_id": peer_ids[garbler]},
                        "setup_inputs": setup_inputs,
                        "instance_id": instance_id,
                    }
                )
                name_e = f"node{evaluator}_evaluator_to_node{garbler}"
                self.logger.info(f"{name_e}: {tsid_e}")
                setups.append((name_e, rpcs[evaluator], tsid_e))

                tp = tsid_map[(garbler, evaluator)]
                tsid_map[(garbler, evaluator)] = TablesetPair(tp.garbler_tsid, tsid_e)

        self.logger.info("*** ALL EVALUATOR SETUPS ISSUED ***")

        wait_all_setup_complete(self.logger, setups)
        self.logger.info("*** ALL SETUPS COMPLETE ***")

        return True
