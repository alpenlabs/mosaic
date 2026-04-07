"""
Base test class with common utilities.
"""

import flexitest

from .logging import setup_test_logger


class BaseTest(flexitest.Test):
    """
    Base class for all functional tests.

    Provides:
    - Logging utilities
    - Common assertions

    Tests should explicitly:
    - Get services from ctx.get_service()
    - Create RPC clients
    - Set up any required state
    """

    def premain(self, ctx: flexitest.RunContext):
        """
        Things that need to be done before we run the test.
        """
        self.runctx = ctx
        logger = setup_test_logger(ctx.datadir_root, ctx.name)
        self.logger = logger

    def get_service(self, typ: str) -> flexitest.service.ProcService:
        svc = self.runctx.get_service(typ)
        if svc is None:
            raise RuntimeError(
                f"Service '{typ}' not found. Available services: "
                f"{list(self.runctx.env.services.keys())}"
            )
        return svc
