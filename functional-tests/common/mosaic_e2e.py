"""
Shared helpers for E2E mosaic tests.
"""

import secrets
from logging import Logger

from common.rpc import JsonRpcClient
from common.wait import wait_until


def handle_setup(
    logger: Logger,
    garbler: JsonRpcClient,
    evaluator: JsonRpcClient,
    setup_inputs: str,
) -> tuple[str, str]:
    """Run tableset setup on both nodes. Returns (garbler_tsid, evaluator_tsid)."""
    instance_id = "00" * 32

    garbler_peer_id = garbler.mosaic_getRpcPeerId()
    evaluator_peer_id = evaluator.mosaic_getRpcPeerId()

    garbler_tsid = garbler.mosaic_setupTableset(
        {
            "role": "garbler",
            "peer_info": {"peer_id": evaluator_peer_id},
            "setup_inputs": setup_inputs,
            "instance_id": instance_id,
        }
    )
    logger.info(f"starting garbler setup; tsid = {garbler_tsid}")
    evaluator_tsid = evaluator.mosaic_setupTableset(
        {
            "role": "evaluator",
            "peer_info": {"peer_id": garbler_peer_id},
            "setup_inputs": setup_inputs,
            "instance_id": instance_id,
        }
    )
    logger.info(f"starting evaluator setup; tsid = {evaluator_tsid}")

    def check_both_setup_complete():
        garbler_ok = check_setup_complete(logger, "garbler", garbler_tsid, garbler)
        evaluator_ok = check_setup_complete(logger, "evaluator", evaluator_tsid, evaluator)
        return garbler_ok and evaluator_ok

    wait_until(
        check_both_setup_complete,
        error_msg="setup did not complete within timeout",
    )

    return garbler_tsid, evaluator_tsid


def handle_deposit(
    logger: Logger,
    garbler: JsonRpcClient,
    evaluator: JsonRpcClient,
    garbler_tsid: str,
    evaluator_tsid: str,
    deposit_idx: int,
) -> str:
    """Run deposit on both nodes. Returns deposit_id."""
    deposit_inputs = create_deposit_input(deposit_idx)
    deposit_id = create_deposit_id(deposit_idx)

    adaptor_pk = evaluator.mosaic_getAdaptorPubkey(evaluator_tsid, deposit_id)

    sighashes = generate_sighashes(adaptor_pk)

    evaluator.mosaic_initEvaluatorDeposit(
        evaluator_tsid,
        deposit_id,
        {"deposit_inputs": deposit_inputs, "sighashes": sighashes},
    )

    garbler.mosaic_initGarblerDeposit(
        garbler_tsid,
        deposit_id,
        {
            "deposit_inputs": deposit_inputs,
            "sighashes": sighashes,
            "adaptor_pk": adaptor_pk,
        },
    )

    def check_both_deposit_ready():
        garbler_ok = check_deposit_ready(
            logger, "garbler deposit", garbler_tsid, deposit_id, garbler
        )
        evaluator_ok = check_deposit_ready(
            logger, "evaluator deposit", evaluator_tsid, deposit_id, evaluator
        )
        return garbler_ok and evaluator_ok

    wait_until(
        check_both_deposit_ready,
        error_msg="deposit did not complete within timeout",
    )

    return deposit_id


def handle_withdrawal(
    logger: Logger,
    garbler: JsonRpcClient,
    evaluator: JsonRpcClient,
    garbler_tsid: str,
    evaluator_tsid: str,
    deposit_id: str,
    withdrawal_inputs: str,
):
    """Run withdrawal on both nodes."""
    garbler.mosaic_completeAdaptorSigs(garbler_tsid, deposit_id, withdrawal_inputs)

    wait_until(
        lambda: check_setup_consumed(logger, "garbler withdrawal", garbler_tsid, garbler),
        error_msg="garbler withdrawal did not complete within timeout",
    )
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
        lambda: check_setup_consumed(logger, "evaluator withdrawal", evaluator_tsid, evaluator),
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
    return deposit_idx.to_bytes(32, byteorder="little").hex()


def check_setup_complete(logger, name: str, tsid: str, rpc: JsonRpcClient) -> bool:
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


def check_deposit_ready(logger, name: str, tsid: str, deposit_id: str, rpc: JsonRpcClient) -> bool:
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


def check_setup_consumed(logger, name: str, tsid: str, rpc: JsonRpcClient) -> bool:
    status = rpc.mosaic_getTablesetStatus(tsid)
    logger.info(f"{name} status: {status}")

    if isinstance(status, dict) and "Aborted" in status:
        reason = status["Aborted"].get("reason", "unknown")
        raise RuntimeError(f"{name} setup aborted: {reason}")

    if status == "UncontestedWithdrawal":
        raise RuntimeError(f"{name} deposit already withdrawn (uncontested)")

    return isinstance(status, dict) and "Consumed" in status
