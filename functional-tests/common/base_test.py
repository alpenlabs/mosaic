"""
Base test class with common utilities.
"""

import flexitest

from .logging import setup_test_logger


class BaseTest(flexitest.Test):
    """
    Class to be used instead of flexitest.Test for accessing logger
    """

    def premain(self, ctx: flexitest.RunContext):
        logger = setup_test_logger(ctx.datadir_root, ctx.name)
        self.logger = logger
