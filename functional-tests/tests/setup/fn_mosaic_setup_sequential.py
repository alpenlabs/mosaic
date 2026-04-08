import secrets

import flexitest

from common.base_test import BaseTest
from common.wait import wait_until
from envs.mosaic_env import MosaicEnv


@flexitest.register
class MosaicSetupSequentialTest(BaseTest):
    """
    Tests mosaic setup with 2 nodes where directions run sequentially:
    direction A (node 0 garbler, node 1 evaluator) completes fully,
    then direction B (node 1 garbler, node 0 evaluator) is started.
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

        # Direction A: node 0 as garbler, node 1 as evaluator
        self.logger.info("Starting direction A: node0 garbler -> node1 evaluator")
        tsid_n0_garbler = rpc_0.mosaic_setupTableset(
            {
                "role": "garbler",
                "peer_info": {"peer_id": peer_id_1},
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
        self.logger.info(f"node0 garbler tsid: {tsid_n0_garbler}")
        self.logger.info(f"node1 evaluator tsid: {tsid_n1_evaluator}")

        # Wait for direction A to complete
        direction_a = [
            ("node0_garbler", rpc_0, tsid_n0_garbler),
            ("node1_evaluator", rpc_1, tsid_n1_evaluator),
        ]
        self.wait_all_setup_complete(direction_a)
        self.logger.info("Direction A complete")

        # Direction B: node 1 as garbler, node 0 as evaluator
        self.logger.info("Starting direction B: node1 garbler -> node0 evaluator")
        tsid_n1_garbler = rpc_1.mosaic_setupTableset(
            {
                "role": "garbler",
                "peer_info": {"peer_id": peer_id_0},
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
        self.logger.info(f"node1 garbler tsid: {tsid_n1_garbler}")
        self.logger.info(f"node0 evaluator tsid: {tsid_n0_evaluator}")

        # Wait for direction B to complete
        direction_b = [
            ("node1_garbler", rpc_1, tsid_n1_garbler),
            ("node0_evaluator", rpc_0, tsid_n0_evaluator),
        ]
        self.wait_all_setup_complete(direction_b)
        self.logger.info("Direction B complete")

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
