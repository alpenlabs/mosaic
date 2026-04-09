"""
Waiting utilities for test synchronization.
"""

import logging
import time
from collections.abc import Callable
from typing import TypeVar

from .rpc import RpcError

logger = logging.getLogger(__name__)

# Transient errors that should be retried rather than propagated.
# OSError covers ConnectionError, requests.RequestException (inherits IOError), etc.
_RETRYABLE = (RpcError, OSError)


def wait_until(
    condition: Callable[[], bool],
    timeout: int = 120,
    step: int = 1,
    error_msg: str = "Condition not met within timeout",
):
    """
    Generic wait function that polls a condition until it's met or timeout occurs.

    Args:
        condition: A callable that returns True when the condition is met.
        timeout: Timeout in seconds (default: 120).
        step: Poll interval in seconds (default: 1).
        error_msg: Custom error message for timeout.
    """
    end_time = time.time() + timeout

    while time.time() < end_time:
        time.sleep(step)  # sleep first

        try:
            if condition():
                return
        except Exception as e:
            ety = type(e)
            logging.debug(f"caught exception {ety}, will still wait for timeout: {e}")
            pass

    raise TimeoutError(f"{error_msg} (timeout: {timeout}s)")


T = TypeVar("T")


def wait_until_with_value(
    fn: Callable[..., T],
    predicate: Callable[[T], bool],
    error_with: str = "Timed out",
    timeout: int = 5,
    step: float = 0.5,
    debug=False,
) -> T:
    """
    Similar to `wait_until` but this returns the value of the function.
    This also takes another predicate which acts on the function value and returns a bool
    """
    deadline = time.monotonic() + timeout

    while True:
        try:
            r = fn()
            if debug:
                print("Waiting.. current value:", r)
            if predicate(r):
                return r
        except _RETRYABLE as e:
            logger.warning(f"caught {type(e).__name__}, will still wait for timeout: {e}")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        time.sleep(min(step, remaining))

    try:
        r = fn()
        if debug:
            print("Waiting.. current value:", r)
        if predicate(r):
            return r
    except _RETRYABLE as e:
        logger.warning(f"caught {type(e).__name__}, will still wait for timeout: {e}")

    raise AssertionError(error_with)
