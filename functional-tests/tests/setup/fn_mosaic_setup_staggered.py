import secrets
import time

import flexitest

from common.base_test import BaseTest
from common.wait import wait_until
from envs.mosaic_env import MosaicEnv


@flexitest.register
class MosaicSetupStaggeredTest(BaseTest):
    """
    Tests mosaic setup with 2 nodes where setup calls are staggered:
    both setup calls (garbler + evaluator) are issued on node 0 first,
    then after a 10s delay, both are issued on node 1.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv(2))

    def main(self, ctx: flexitest.RunContext):
        instance_id = "0" * 64
        setup_inputs = secrets.token_hex(32)

        rpc_0 = ctx.get_service("mosaic_0").create_rpc()
        rpc_1 = ctx.get_service("mosaic_1").create_rpc()

        self.logger.info("Waiting for both nodes to be ready")
        self.wait_until_ready(rpc_0, "mosaic_0")
        self.wait_until_ready(rpc_1, "mosaic_1")

        peer_id_0 = rpc_0.mosaic_getRpcPeerId()
        peer_id_1 = rpc_1.mosaic_getRpcPeerId()

        # Issue both setup calls on node 0
        self.logger.info("Issuing garbler + evaluator setup on node 0")
        tsid_n0_garbler = rpc_0.mosaic_setupTableset(
            {
                "role": "garbler",
                "peer_info": {"peer_id": peer_id_1},
                "setup_inputs": setup_inputs,
                "instance_id": instance_id,
            }
        )
        tsid_n0_evaluator = rpc_0.mosaic_setupTableset(
            {
                "role": "evaluator",
                "peer_info": {"peer_id": peer_id_1},
                "setup_inputs": setup_inputs,
                "instance_id": instance_id,
            }
        )
        self.logger.info(f"node0 garbler tsid: {tsid_n0_garbler}")
        self.logger.info(f"node0 evaluator tsid: {tsid_n0_evaluator}")

        # Wait 10 seconds
        self.logger.info("Waiting 10s before issuing setup calls on node 1")
        time.sleep(10)

        # Issue both setup calls on node 1
        self.logger.info("Issuing garbler + evaluator setup on node 1")
        tsid_n1_garbler = rpc_1.mosaic_setupTableset(
            {
                "role": "garbler",
                "peer_info": {"peer_id": peer_id_0},
                "setup_inputs": setup_inputs,
                "instance_id": instance_id,
            }
        )
        tsid_n1_evaluator = rpc_1.mosaic_setupTableset(
            {
                "role": "evaluator",
                "peer_info": {"peer_id": peer_id_0},
                "setup_inputs": setup_inputs,
                "instance_id": instance_id,
            }
        )
        self.logger.info(f"node1 garbler tsid: {tsid_n1_garbler}")
        self.logger.info(f"node1 evaluator tsid: {tsid_n1_evaluator}")

        # Poll all four setups in each iteration until all complete
        all_setups = [
            ("node0_garbler", rpc_0, tsid_n0_garbler),
            ("node0_evaluator", rpc_0, tsid_n0_evaluator),
            ("node1_garbler", rpc_1, tsid_n1_garbler),
            ("node1_evaluator", rpc_1, tsid_n1_evaluator),
        ]
        self.wait_all_setup_complete(all_setups)

        return True

    def wait_until_ready(self, rpc, name, timeout=60):
        def check():
            try:
                rpc.mosaic_getRpcPeerId()
                return True
            except Exception as e:
                self.logger.debug(f"{name} not ready yet: {e}")
                return False

        wait_until(
            check,
            timeout=timeout,
            step=2,
            error_msg=f"{name} did not become ready within {timeout}s",
        )
        self.logger.info(f"{name}: ready")

    def wait_all_setup_complete(self, setups, timeout=120):
        pending = {name for name, _, _ in setups}

        def check():
            for name, rpc, tsid in setups:
                if name not in pending:
                    continue
                status = rpc.mosaic_getTablesetStatus(tsid)
                self.logger.info(f"{name} status: {status}")
                if isinstance(status, dict) and "Aborted" in status:
                    reason = status["Aborted"].get("reason", "unknown")
                    raise RuntimeError(f"{name} setup aborted: {reason}")
                if status == "SetupComplete":
                    self.logger.info(f"{name} reached SetupComplete")
                    pending.discard(name)
            return len(pending) == 0

        wait_until(
            check,
            timeout=timeout,
            step=2,
            error_msg=f"Setups not complete within {timeout}s. Still pending: {pending}",
        )
