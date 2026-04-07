"""
Shared helpers and base class for E2E mosaic tests.
"""

import secrets

from common.base_test import BaseTest
from common.rpc import JsonRpcClient
from common.wait import wait_until


class MosaicE2EBase(BaseTest):
    """
    Base class for E2E tests that run setup -> deposit -> withdrawal -> fault sign.

    Subclasses set ``deposit_idx`` and implement assertions on the fault-secret result.
    """

    garbler: JsonRpcClient | None
    evaluator: JsonRpcClient | None

    garbler_tsid: str | None
    evaluator_tsid: str | None

    deposit_id: str | None

    # -- orchestration helpers ------------------------------------------------

    def handle_setup(self, setup_inputs: str):
        instance_id = "00" * 32

        garbler_peer_id = self.garbler.mosaic_getRpcPeerId()
        evaluator_peer_id = self.evaluator.mosaic_getRpcPeerId()

        garbler_tsid = self.garbler.mosaic_setupTableset(
            {
                "role": "garbler",
                "peer_info": {"peer_id": evaluator_peer_id},
                "setup_inputs": setup_inputs,
                "instance_id": instance_id,
            }
        )
        self.logger.info(f"starting garbler setup; tsid = {garbler_tsid}")
        evaluator_tsid = self.evaluator.mosaic_setupTableset(
            {
                "role": "evaluator",
                "peer_info": {"peer_id": garbler_peer_id},
                "setup_inputs": setup_inputs,
                "instance_id": instance_id,
            }
        )
        self.logger.info(f"starting evaluator setup; tsid = {evaluator_tsid}")

        def check_both_setup_complete():
            garbler_ok = check_setup_complete(self.logger, "garbler", garbler_tsid, self.garbler)
            evaluator_ok = check_setup_complete(
                self.logger, "evaluator", evaluator_tsid, self.evaluator
            )
            return garbler_ok and evaluator_ok

        wait_until(
            check_both_setup_complete,
            error_msg="setup did not complete within timeout",
        )

        self.garbler_tsid = garbler_tsid
        self.evaluator_tsid = evaluator_tsid

    def handle_deposit(self, deposit_idx: int):
        deposit_inputs = create_deposit_input(deposit_idx)
        deposit_id = create_deposit_id(deposit_idx)

        adaptor_pk = self.evaluator.mosaic_getAdaptorPubkey(self.evaluator_tsid, deposit_id)

        sighashes = generate_sighashes(adaptor_pk)

        self.evaluator.mosaic_initEvaluatorDeposit(
            self.evaluator_tsid,
            deposit_id,
            {"deposit_inputs": deposit_inputs, "sighashes": sighashes},
        )

        self.garbler.mosaic_initGarblerDeposit(
            self.garbler_tsid,
            deposit_id,
            {
                "deposit_inputs": deposit_inputs,
                "sighashes": sighashes,
                "adaptor_pk": adaptor_pk,
            },
        )

        def check_both_deposit_ready():
            garbler_ok = check_deposit_ready(
                self.logger,
                "garbler deposit",
                self.garbler_tsid,
                deposit_id,
                self.garbler,
            )
            evaluator_ok = check_deposit_ready(
                self.logger,
                "evaluator deposit",
                self.evaluator_tsid,
                deposit_id,
                self.evaluator,
            )
            return garbler_ok and evaluator_ok

        wait_until(
            check_both_deposit_ready,
            error_msg="deposit did not complete within timeout",
        )

        self.deposit_id = deposit_id

    def handle_withdrawal(self, withdrawal_inputs: str):
        self.garbler.mosaic_completeAdaptorSigs(
            self.garbler_tsid, self.deposit_id, withdrawal_inputs
        )

        wait_until(
            lambda: check_setup_consumed(
                self.logger, "garbler withdrawal", self.garbler_tsid, self.garbler
            ),
            error_msg="garbler withdrawal did not complete within timeout",
        )
        completed_adaptor_sigs = self.garbler.mosaic_getCompletedAdaptorSigs(self.garbler_tsid)

        self.evaluator.mosaic_evaluate_tableset(
            self.evaluator_tsid,
            self.deposit_id,
            {
                "withdrawal_inputs": withdrawal_inputs,
                "completed_signatures": completed_adaptor_sigs,
            },
        )

        wait_until(
            lambda: check_setup_consumed(
                self.logger,
                "evaluator withdrawal",
                self.evaluator_tsid,
                self.evaluator,
            ),
            error_msg="evaluator withdrawal did not complete within timeout",
        )


# -- free helper functions ----------------------------------------------------


def create_deposit_input(deposit_idx: int) -> str:
    """Return the deposit index as a 4-byte little-endian hex string."""
    return deposit_idx.to_bytes(4, byteorder="little").hex()


def generate_sighashes(_adaptor_pk: str) -> list[list[int]]:
    """Generate a list of n random sighashes, each as a list of 32 bytes."""
    n = 4 + 128
    return [list(secrets.token_bytes(32)) for _ in range(n)]


def create_deposit_id(deposit_idx: int) -> str:
    """Return the deposit index as a 32 byte hex string."""
    return deposit_idx.to_bytes(32).hex()


def check_setup_complete(logger, name: str, tsid: str, rpc) -> bool:
    status = rpc.mosaic_getTablesetStatus(tsid)
    logger.info(f"{name} status: {status}")

    if isinstance(status, dict) and "Aborted" in status:
        reason = status["Aborted"].get("reason", "unknown")
        raise RuntimeError(f"{name} setup aborted: {reason}")

    if isinstance(status, dict) and "Consumed" in status:
        raise RuntimeError(f"{name} setup consumed")

    if status == "SetupComplete":
        logger.info(f"{name} reached SetupComplete")
        return True

    return False


def check_deposit_ready(logger, name: str, tsid: str, deposit_id: str, rpc) -> bool:
    status = rpc.mosaic_getDepositStatus(tsid, deposit_id)
    logger.info(f"{name} status: {status}")

    if isinstance(status, dict) and "Aborted" in status:
        reason = status["Aborted"].get("reason", "unknown")
        raise RuntimeError(f"{name} setup aborted: {reason}")

    if status == "UncontestedWithdrawal":
        raise RuntimeError(f"{name} deposit already withdrawn (uncontested)")

    if isinstance(status, dict) and "Consumed" in status:
        by = status["Consumed"].get("by", "unknown")
        raise RuntimeError(f"{name} deposit consumed by: {by}")

    if status == "Ready":
        logger.info(f"{name} reached SetupComplete")
        return True

    return False


def check_setup_consumed(logger, name: str, tsid: str, rpc) -> bool:
    status = rpc.mosaic_getTablesetStatus(tsid)
    logger.info(f"{name} status: {status}")

    if isinstance(status, dict) and "Aborted" in status:
        reason = status["Aborted"].get("reason", "unknown")
        raise RuntimeError(f"{name} setup aborted: {reason}")

    if status == "UncontestedWithdrawal":
        raise RuntimeError(f"{name} deposit already withdrawn (uncontested)")

    return isinstance(status, dict) and "Consumed" in status
