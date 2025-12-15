"""Chat platform adapters."""

from .base import BaseChatAdapter, MessageResult, AlertCard
from .teams import TeamsAdapter

__all__ = [
    "BaseChatAdapter",
    "MessageResult",
    "AlertCard",
    "TeamsAdapter",
]
