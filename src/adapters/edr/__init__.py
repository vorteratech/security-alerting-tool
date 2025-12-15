"""EDR platform adapters."""

from .base import BaseEDRAdapter, Alert
from .sentinelone import SentinelOneAdapter
from .crowdstrike import CrowdStrikeAdapter

__all__ = [
    "BaseEDRAdapter",
    "Alert",
    "SentinelOneAdapter",
    "CrowdStrikeAdapter",
]
