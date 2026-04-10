"""
Shared helpers for E2E mosaic tests.
"""

import secrets
from dataclasses import dataclass
from logging import Logger

from common.rpc import JsonRpcClient
from common.wait import wait_until

# -- dataclasses & type aliases -----------------------------------------------


@dataclass
class TablesetPair:
    garbler_tsid: str
    evaluator_tsid: str


@dataclass
class WithdrawalPair:
    name: str
    garbler_idx: int
    tableset: TablesetPair


@dataclass
class PreparedDeposit:
    garbler: JsonRpcClient
    evaluator: JsonRpcClient
    garbler_tsid: str
    evaluator_tsid: str
    deposit_id: str
    deposit_inputs: str
    sighashes: list[list[int]]
    adaptor_pk: str


# node idx -> rpc client
NodeRpcs = dict[int, JsonRpcClient]
# node idx -> peer_id
NodePeerIds = dict[int, str]
# (garbler_idx, evaluator_idx) -> TablesetPair
TsidMap = dict[tuple[int, int], TablesetPair]


# -- low-level utilities ------------------------------------------------------


def create_deposit_input(deposit_idx: int) -> str:
    """Return the deposit index as a 4-byte little-endian hex string."""
    return deposit_idx.to_bytes(4, byteorder="little").hex()


def create_deposit_id(deposit_idx: int) -> str:
    """Return the deposit index as a 32 byte hex string."""
    return deposit_idx.to_bytes(32, byteorder="little").hex()


def generate_sighashes() -> list[list[int]]:
    """Generate a list of n random sighashes, each as a list of 32 bytes."""
    n = 4 + 128
    return [list(secrets.token_bytes(32)) for _ in range(n)]


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
        logger.info(f"{name} reached Ready")
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


# -- single-pair helpers ------------------------------------------------------


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

    sighashes = generate_sighashes()

    garbler.mosaic_initGarblerDeposit(
        garbler_tsid,
        deposit_id,
        {
            "deposit_inputs": deposit_inputs,
            "sighashes": sighashes,
            "adaptor_pk": adaptor_pk,
        },
    )

    evaluator.mosaic_initEvaluatorDeposit(
        evaluator_tsid,
        deposit_id,
        {"deposit_inputs": deposit_inputs, "sighashes": sighashes},
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


# -- multi-node setup ---------------------------------------------------------


def handle_all_setups(
    logger: Logger,
    rpcs: NodeRpcs,
    peer_ids: NodePeerIds,
    network_size: int,
) -> TsidMap:
    """Returns dict mapping (garbler, evaluator) -> TablesetPair."""
    instance_id = "00" * 32

    setups = []
    tsid_map: TsidMap = {}
    for garbler in range(network_size):
        for evaluator in range(network_size):
            if garbler == evaluator:
                continue

            setup_inputs = secrets.token_hex(32)

            tsid_g = rpcs[garbler].mosaic_setupTableset(
                {
                    "role": "garbler",
                    "peer_info": {"peer_id": peer_ids[evaluator]},
                    "setup_inputs": setup_inputs,
                    "instance_id": instance_id,
                }
            )
            name_g = f"node{garbler}_garbler_to_node{evaluator}"
            logger.info(f"{name_g}: {tsid_g}")
            setups.append((name_g, rpcs[garbler], tsid_g))

            tsid_e = rpcs[evaluator].mosaic_setupTableset(
                {
                    "role": "evaluator",
                    "peer_info": {"peer_id": peer_ids[garbler]},
                    "setup_inputs": setup_inputs,
                    "instance_id": instance_id,
                }
            )
            name_e = f"node{evaluator}_evaluator_to_node{garbler}"
            logger.info(f"{name_e}: {tsid_e}")
            setups.append((name_e, rpcs[evaluator], tsid_e))

            tsid_map[(garbler, evaluator)] = TablesetPair(tsid_g, tsid_e)

    wait_all_setup_complete(logger, setups)

    return tsid_map


def wait_all_setup_complete(
    logger: Logger, setups: list[tuple[str, JsonRpcClient, str]], timeout=120, step=2
):
    """Poll all tableset setups until every one reaches SetupComplete.
    Raises immediately if any setup returns Aborted."""
    pending = {name for name, _, _ in setups}

    def check_all_complete():
        for name, rpc, tsid in setups:
            if name not in pending:
                continue

            if check_setup_complete(logger, name, tsid, rpc):
                pending.discard(name)

        return len(pending) == 0

    wait_until(
        check_all_complete,
        timeout=timeout,
        step=step,
        error_msg=(
            f"Not all setups reached SetupComplete within {timeout}s. Still pending: {pending}"
        ),
    )


# -- multi-node deposit -------------------------------------------------------


def prepare_deposit(
    garbler: JsonRpcClient,
    evaluator: JsonRpcClient,
    garbler_tsid: str,
    evaluator_tsid: str,
    deposit_idx: int,
) -> PreparedDeposit:
    """Compute all deposit parameters without initiating anything."""
    deposit_inputs = create_deposit_input(deposit_idx)
    deposit_id = create_deposit_id(deposit_idx)
    adaptor_pk = evaluator.mosaic_getAdaptorPubkey(evaluator_tsid, deposit_id)
    sighashes = generate_sighashes()

    return PreparedDeposit(
        garbler=garbler,
        evaluator=evaluator,
        garbler_tsid=garbler_tsid,
        evaluator_tsid=evaluator_tsid,
        deposit_id=deposit_id,
        deposit_inputs=deposit_inputs,
        sighashes=sighashes,
        adaptor_pk=adaptor_pk,
    )


def init_garbler_deposit(logger: Logger, dep: PreparedDeposit, name: str):
    """Initiate the garbler side of a prepared deposit."""
    dep.garbler.mosaic_initGarblerDeposit(
        dep.garbler_tsid,
        dep.deposit_id,
        {
            "deposit_inputs": dep.deposit_inputs,
            "sighashes": dep.sighashes,
            "adaptor_pk": dep.adaptor_pk,
        },
    )
    logger.info(f"{name} garbler deposit initiated")


def init_evaluator_deposit(logger: Logger, dep: PreparedDeposit, name: str):
    """Initiate the evaluator side of a prepared deposit."""
    dep.evaluator.mosaic_initEvaluatorDeposit(
        dep.evaluator_tsid,
        dep.deposit_id,
        {
            "deposit_inputs": dep.deposit_inputs,
            "sighashes": dep.sighashes,
        },
    )
    logger.info(f"{name} evaluator deposit initiated")


def wait_all_deposits_ready(
    logger: Logger,
    prepared: list[tuple[str, PreparedDeposit]],
    timeout: int = 120,
    step: int = 2,
):
    """Poll all deposits until every one reaches Ready."""
    pending = {name for name, _ in prepared}

    def check_all_ready():
        for name, dep in prepared:
            if name not in pending:
                continue
            g_ok = check_deposit_ready(
                logger,
                f"{name}/garbler",
                dep.garbler_tsid,
                dep.deposit_id,
                dep.garbler,
            )
            e_ok = check_deposit_ready(
                logger,
                f"{name}/evaluator",
                dep.evaluator_tsid,
                dep.deposit_id,
                dep.evaluator,
            )
            if g_ok and e_ok:
                logger.info(f"{name} deposit ready")
                pending.discard(name)
        return len(pending) == 0

    wait_until(
        check_all_ready,
        timeout=timeout,
        step=step,
        error_msg=(f"Not all deposits reached Ready within {timeout}s. Still pending: {pending}"),
    )


# -- multi-node orchestrators -------------------------------------------------


def handle_setup_and_deposits(
    logger: Logger, rpcs: NodeRpcs, network_size: int, deposits: list[int]
) -> TsidMap:
    peer_ids = {i: rpcs[i].mosaic_getRpcPeerId() for i in range(network_size)}

    tsid_map = handle_all_setups(logger, rpcs, peer_ids, network_size)

    # Prepare and init deposits on every setup for every deposit index
    prepared: list[tuple[str, PreparedDeposit]] = []
    for deposit_idx in deposits:
        for garbler in range(network_size):
            for evaluator in range(network_size):
                if garbler == evaluator:
                    continue
                tp = tsid_map[(garbler, evaluator)]
                name = f"deposit_{deposit_idx}_g{garbler}_e{evaluator}"
                dep = prepare_deposit(
                    rpcs[garbler],
                    rpcs[evaluator],
                    tp.garbler_tsid,
                    tp.evaluator_tsid,
                    deposit_idx,
                )
                init_garbler_deposit(logger, dep, name)
                init_evaluator_deposit(logger, dep, name)
                prepared.append((name, dep))

    wait_all_deposits_ready(logger, prepared)

    return tsid_map


def handle_concurrent_withdrawal(
    logger: Logger,
    rpcs: NodeRpcs,
    tsid_map: TsidMap,
    evaluator_node: int,
    deposit_idx: int,
    withdrawal_inputs: str,
    network_size: int,
):
    """Run withdrawal for a single deposit on one evaluator against all its garblers.

    Args:
        rpcs: mapping node index -> rpc client.
        tsid_map: mapping (garbler, evaluator) -> TablesetPair.
        evaluator_node: index of the evaluator node.
        deposit_idx: deposit to withdraw.
        withdrawal_inputs: hex-encoded withdrawal inputs.
        network_size: total number of nodes in the network.
    """
    # Step 1: kick off garbler completion
    deposit_id = create_deposit_id(deposit_idx)
    pairs: list[WithdrawalPair] = []
    for garbler in range(network_size):
        if garbler == evaluator_node:
            continue
        tp = tsid_map[(garbler, evaluator_node)]
        rpcs[garbler].mosaic_completeAdaptorSigs(tp.garbler_tsid, deposit_id, withdrawal_inputs)
        name = f"withdrawal_g{garbler}_e{evaluator_node}"
        pairs.append(WithdrawalPair(name=name, garbler_idx=garbler, tableset=tp))
        logger.info(f"initiated garbler completion: {name}")

    # Step 2: wait for each garbler to be Consumed, then trigger evaluator
    for wp in pairs:
        wait_until(
            lambda w=wp: check_setup_consumed(
                logger, w.name, w.tableset.garbler_tsid, rpcs[w.garbler_idx]
            ),
            error_msg=f"{wp.name} garbler did not reach Consumed",
        )
        logger.info(f"{wp.name} garbler consumed")

        completed_adaptor_sigs = rpcs[wp.garbler_idx].mosaic_getCompletedAdaptorSigs(
            wp.tableset.garbler_tsid
        )
        rpcs[evaluator_node].mosaic_evaluateTableset(
            wp.tableset.evaluator_tsid,
            deposit_id,
            {
                "withdrawal_inputs": withdrawal_inputs,
                "completed_signatures": completed_adaptor_sigs,
            },
        )
        logger.info(f"{wp.name} evaluator evaluation initiated")

    # Step 3: wait for all evaluator tablesets to be Consumed
    for wp in pairs:
        wait_until(
            lambda w=wp: check_setup_consumed(
                logger, w.name, w.tableset.evaluator_tsid, rpcs[evaluator_node]
            ),
            error_msg=f"{wp.name} evaluator did not reach Consumed",
        )
        logger.info(f"{wp.name} evaluator consumed")
