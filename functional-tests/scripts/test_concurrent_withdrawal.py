#!/usr/bin/env python3
"""
Standalone concurrent withdrawal test for a running mosaic cluster.

This script replicates the logic of MosaicConcurrentWithdrawalTest but talks
to externally-running nodes.  It uses only the Python standard library.

Edit the configuration section below, then run:

    python test_concurrent_withdrawal.py
"""

import json
import secrets
import sys
import time
import urllib.request

# =============================================================================
# Configuration — edit these to match your deployment
# =============================================================================

RPC_URLS = [
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8001",
    # "http://127.0.0.1:18553",
    # "http://127.0.0.1:18554",
    # "http://127.0.0.1:18555",
]

NETWORK_SIZE = len(RPC_URLS)

DEPOSIT_IDXS = [0]  # deposit indices to set up
EVALUATOR_NODE = 0  # node that acts as evaluator during withdrawal
WITHDRAWAL_DEPOSIT = 0  # which deposit to withdraw

SETUP_TIMEOUT = 3600  # seconds
POLL_INTERVAL = 2  # seconds

# =============================================================================
# Minimal JSON-RPC client (stdlib only)
# =============================================================================


class RpcError(Exception):
    def __init__(self, code, message, data=None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"RpcError {code}: {message}")


class JsonRpcClient:
    def __init__(self, url):
        self.url = url
        self._seq = 0

    def call(self, method, params):
        body = json.dumps(
            {"jsonrpc": "2.0", "method": method, "id": self._seq, "params": params}
        ).encode()
        self._seq += 1

        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())

        if "error" in result:
            e = result["error"]
            raise RpcError(e["code"], e["message"], e.get("data"))
        return result["result"]

    def __getattr__(self, name):
        def _rpc(*args):
            return self.call(name, list(args))

        return _rpc


# =============================================================================
# Helpers
# =============================================================================


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def wait_until(condition, timeout=SETUP_TIMEOUT, step=POLL_INTERVAL, error_msg="timeout"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(step)
        try:
            if condition():
                return
        except Exception as e:
            log(f"  (transient: {e})")
    raise TimeoutError(f"{error_msg} (after {timeout}s)")


def create_deposit_input(idx):
    return idx.to_bytes(4, byteorder="little").hex()


def create_deposit_id(idx):
    return idx.to_bytes(32, byteorder="little").hex()


def generate_sighashes():
    return [list(secrets.token_bytes(32)) for _ in range(4 + 128)]


# =============================================================================
# Status checkers
# =============================================================================


def check_setup_complete(name, tsid, rpc):
    status = rpc.mosaic_getTablesetStatus(tsid)
    log(f"  {name} status: {status}")

    if isinstance(status, dict) and "Aborted" in status:
        raise RuntimeError(f"{name} setup aborted: {status['Aborted'].get('reason', '?')}")
    if isinstance(status, dict) and "Consumed" in status:
        raise RuntimeError(f"{name} already consumed during setup")

    return status == "SetupComplete"


def check_deposit_ready(name, tsid, deposit_id, rpc):
    status = rpc.mosaic_getDepositStatus(tsid, deposit_id)
    log(f"  {name} status: {status}")

    if isinstance(status, dict) and "Aborted" in status:
        raise RuntimeError(f"{name} deposit aborted: {status['Aborted'].get('reason', '?')}")
    if status == "UncontestedWithdrawal":
        raise RuntimeError(f"{name} deposit already withdrawn (uncontested)")
    if isinstance(status, dict) and "Consumed" in status:
        raise RuntimeError(f"{name} deposit consumed by: {status['Consumed'].get('by', '?')}")

    return status == "Ready"


def check_setup_consumed(name, tsid, rpc):
    status = rpc.mosaic_getTablesetStatus(tsid)
    log(f"  {name} status: {status}")

    if isinstance(status, dict) and "Aborted" in status:
        raise RuntimeError(f"{name} aborted: {status['Aborted'].get('reason', '?')}")
    if status == "UncontestedWithdrawal":
        raise RuntimeError(f"{name} uncontested withdrawal")

    return isinstance(status, dict) and "Consumed" in status


# =============================================================================
# Phases
# =============================================================================


def phase_setup(rpcs):
    """Set up tablesets for every (garbler, evaluator) pair. Returns tsid_map."""
    log("=== PHASE: SETUP ===")
    instance_id = "00" * 32

    # Get peer IDs
    peer_ids = {}
    for i, rpc in rpcs.items():
        peer_ids[i] = rpc.mosaic_getRpcPeerId()
        log(f"node {i} peer_id: {peer_ids[i]}")

    # Initiate all setups
    tsid_map = {}  # (garbler, evaluator) -> (garbler_tsid, evaluator_tsid)
    setups = []  # [(name, rpc, tsid), ...]

    for garbler in range(NETWORK_SIZE):
        for evaluator in range(NETWORK_SIZE):
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
            log(f"{name_g}: tsid={tsid_g}")
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
            log(f"{name_e}: tsid={tsid_e}")
            setups.append((name_e, rpcs[evaluator], tsid_e))

            tsid_map[(garbler, evaluator)] = (tsid_g, tsid_e)

    # Poll until all setups complete
    log("waiting for all setups to complete...")
    pending = {name for name, _, _ in setups}

    def all_setups_complete():
        for name, rpc, tsid in setups:
            if name not in pending:
                continue
            if check_setup_complete(name, tsid, rpc):
                pending.discard(name)
                log(f"  {name} -> SetupComplete")
        return len(pending) == 0

    wait_until(all_setups_complete, error_msg=f"setups not complete, still pending: {pending}")
    log("all setups complete")
    return tsid_map


def phase_deposits(rpcs, tsid_map):
    """Run deposits for each index in DEPOSIT_IDXS on all pairs."""
    log("=== PHASE: DEPOSITS ===")
    prepared = []  # [(name, garbler_rpc, evaluator_rpc, garbler_tsid, evaluator_tsid, deposit_id)]

    for deposit_idx in DEPOSIT_IDXS:
        deposit_id = create_deposit_id(deposit_idx)
        deposit_inputs = create_deposit_input(deposit_idx)

        for garbler in range(NETWORK_SIZE):
            for evaluator in range(NETWORK_SIZE):
                if garbler == evaluator:
                    continue

                tsid_g, tsid_e = tsid_map[(garbler, evaluator)]
                name = f"deposit_{deposit_idx}_g{garbler}_e{evaluator}"

                # Get adaptor pubkey from evaluator
                adaptor_pk = rpcs[evaluator].mosaic_getAdaptorPubkey(tsid_e, deposit_id)
                sighashes = generate_sighashes()

                # Init garbler deposit
                rpcs[garbler].mosaic_initGarblerDeposit(
                    tsid_g,
                    deposit_id,
                    {
                        "deposit_inputs": deposit_inputs,
                        "sighashes": sighashes,
                        "adaptor_pk": adaptor_pk,
                    },
                )
                log(f"{name} garbler deposit initiated")

                # Init evaluator deposit
                rpcs[evaluator].mosaic_initEvaluatorDeposit(
                    tsid_e,
                    deposit_id,
                    {"deposit_inputs": deposit_inputs, "sighashes": sighashes},
                )
                log(f"{name} evaluator deposit initiated")

                prepared.append((name, rpcs[garbler], rpcs[evaluator], tsid_g, tsid_e, deposit_id))

    # Poll until all deposits ready
    log("waiting for all deposits to be ready...")
    pending = {name for name, *_ in prepared}

    def all_deposits_ready():
        for name, g_rpc, e_rpc, tsid_g, tsid_e, dep_id in prepared:
            if name not in pending:
                continue
            g_ok = check_deposit_ready(f"{name}/garbler", tsid_g, dep_id, g_rpc)
            e_ok = check_deposit_ready(f"{name}/evaluator", tsid_e, dep_id, e_rpc)
            if g_ok and e_ok:
                pending.discard(name)
                log(f"  {name} -> Ready")
        return len(pending) == 0

    wait_until(all_deposits_ready, error_msg=f"deposits not ready, still pending: {pending}")
    log("all deposits ready")


def phase_concurrent_withdrawal(rpcs, tsid_map):
    """Run concurrent withdrawal: evaluator=EVALUATOR_NODE, deposit=WITHDRAWAL_DEPOSIT."""
    log("=== PHASE: CONCURRENT WITHDRAWAL ===")
    deposit_id = create_deposit_id(WITHDRAWAL_DEPOSIT)
    withdrawal_inputs = secrets.token_hex(128)

    # Step 1: kick off garbler completion for each garbler
    pairs = []  # [(name, garbler_idx, tsid_g, tsid_e)]
    for garbler in range(NETWORK_SIZE):
        if garbler == EVALUATOR_NODE:
            continue
        tsid_g, tsid_e = tsid_map[(garbler, EVALUATOR_NODE)]
        rpcs[garbler].mosaic_completeAdaptorSigs(tsid_g, deposit_id, withdrawal_inputs)
        name = f"withdrawal_g{garbler}_e{EVALUATOR_NODE}"
        pairs.append((name, garbler, tsid_g, tsid_e))
        log(f"initiated garbler completion: {name}")

    # Step 2: for each garbler, wait for Consumed, then trigger evaluator
    for name, garbler_idx, tsid_g, tsid_e in pairs:
        wait_until(
            lambda n=name, t=tsid_g, r=rpcs[garbler_idx]: check_setup_consumed(n, t, r),
            error_msg=f"{name} garbler did not reach Consumed",
        )
        log(f"{name} garbler consumed")

        completed_adaptor_sigs = rpcs[garbler_idx].mosaic_getCompletedAdaptorSigs(tsid_g)
        rpcs[EVALUATOR_NODE].mosaic_evaluateTableset(
            tsid_e,
            deposit_id,
            {
                "withdrawal_inputs": withdrawal_inputs,
                "completed_signatures": completed_adaptor_sigs,
            },
        )
        log(f"{name} evaluator evaluation initiated")

    # Step 3: wait for all evaluator tablesets to be Consumed
    for name, _garbler_idx, _tsid_g, tsid_e in pairs:
        wait_until(
            lambda n=name, t=tsid_e: check_setup_consumed(n, t, rpcs[EVALUATOR_NODE]),
            error_msg=f"{name} evaluator did not reach Consumed",
        )
        log(f"{name} evaluator consumed")

    log("*** WITHDRAWAL COMPLETE ***")
    return pairs


def phase_verify_fault_secrets(rpcs, tsid_map):
    """Verify fault secret signatures for each garbler."""
    log("=== PHASE: VERIFY FAULT SECRETS ===")
    for garbler in range(NETWORK_SIZE):
        if garbler == EVALUATOR_NODE:
            continue

        _tsid_g, tsid_e = tsid_map[(garbler, EVALUATOR_NODE)]
        fault_sighash = secrets.token_hex(32)
        signature = rpcs[EVALUATOR_NODE].mosaic_signWithFaultSecret(tsid_e, fault_sighash, None)
        assert signature is not None, (
            f"expected valid fault signature for garbler {garbler}, got None"
        )
        log(f"garbler {garbler}: fault secret signature OK")

    log("all fault secret verifications passed")


# =============================================================================
# Main
# =============================================================================


def main():
    assert EVALUATOR_NODE < NETWORK_SIZE, "EVALUATOR_NODE out of range"
    assert WITHDRAWAL_DEPOSIT in DEPOSIT_IDXS, "WITHDRAWAL_DEPOSIT must be in DEPOSIT_IDXS"

    rpcs = {i: JsonRpcClient(url) for i, url in enumerate(RPC_URLS)}
    log(
        f"targeting {NETWORK_SIZE} nodes, deposits={DEPOSIT_IDXS}, "
        f"evaluator={EVALUATOR_NODE}, withdrawal_deposit={WITHDRAWAL_DEPOSIT}"
    )

    tsid_map = phase_setup(rpcs)
    phase_deposits(rpcs, tsid_map)
    phase_concurrent_withdrawal(rpcs, tsid_map)
    phase_verify_fault_secrets(rpcs, tsid_map)

    log("=== ALL TESTS PASSED ===")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"FAILED: {e}")
        sys.exit(1)
