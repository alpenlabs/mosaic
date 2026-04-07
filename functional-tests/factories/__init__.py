from enum import Enum

from .fdb import FdbFactory
from .mosaic import MosaicFactory


class FactoryType(str, Enum):
    """
    Factory type identifiers for test environments.
    """

    FoundationDB = "fdb"
    Mosaic = "mosaic"

    def __str__(self) -> str:
        """Allow direct use in f-strings and format operations."""
        return self.value


__all__ = [FactoryType, FdbFactory, MosaicFactory]
