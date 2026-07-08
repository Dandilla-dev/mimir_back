"""
core/memory.py — память разговора и контекст.

Хранит историю сообщений по сессиям в памяти процесса.
Для продакшена слой можно заменить на Redis, не меняя интерфейс.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Literal

Role = Literal["user", "assistant", "system"]


@dataclass
class Message:
    role: Role
    content: str
    ts: float = field(default_factory=time.time)

    def to_api(self) -> dict:
        """Формат, который ожидает Claude API."""
        return {"role": self.role, "content": self.content}


class SessionMemory:
    """История сообщений одной сессии с ограничением по длине."""

    def __init__(self, max_messages: int = 40):
        self.max_messages = max_messages
        self._messages: Deque[Message] = deque(maxlen=max_messages)

    def add(self, role: Role, content: str) -> None:
        self._messages.append(Message(role=role, content=content))

    def history(self) -> list[Message]:
        return list(self._messages)

    def to_api_messages(self) -> list[dict]:
        return [m.to_api() for m in self._messages if m.role != "system"]

    def clear(self) -> None:
        self._messages.clear()


class MemoryStore:
    """Реестр памяти по всем активным сессиям (session_id -> SessionMemory)."""

    def __init__(self, max_messages_per_session: int = 40):
        self._max = max_messages_per_session
        self._sessions: dict[str, SessionMemory] = defaultdict(
            lambda: SessionMemory(max_messages=self._max)
        )

    def get(self, session_id: str) -> SessionMemory:
        return self._sessions[session_id]

    def drop(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def active_sessions(self) -> list[str]:
        return list(self._sessions.keys())
