"""
core/moderation_store.py — очередь исходящих сообщений, удержанных из-за
THREAT-классификации (core/dlp_heuristics.ThreatLevel.THREAT).

КОНТЕКСТ РЕШЕНИЯ (см. обсуждение в чате, пункт 2): автономная блокировка
без пути восстановления не соответствует собственному принципу автономии
(mimir_principles.md — "автономная блокировка, ДАЛЬШЕ человек разбирает"),
а простая пометка без блокировки — это защита постфактум (утечка уже
ушла получателю к моменту, когда кто-то это увидит). Выбран третий путь:
сообщение с THREAT не доставляется сразу, но и не отбрасывается — оно
физически существует здесь до решения человека (одобрить -> доставить
как обычно, отклонить -> отбросить без доставки).

ГРАНИЦА СЛОЯ, тот же принцип, что уже применён к dlp_events_store.py:
это ТОЛЬКО хранилище удержанных сообщений — само не решает, что считать
THREAT (это дело core/dlp_heuristics.py) и не доставляет сообщения само
(доставка — вызов core/messages_store.store(), которым управляет
api/server.py). Модуль не импортирует dlp_heuristics вообще — держит
только messages_store.Message и текстовые причины, полученные готовыми.

РОЛИ (кто может approve/reject) здесь НЕ реализованы — по плану
(MIMIR_development_plan.md, недели 5-6) роли/доступ ещё не построены.
На пилоте это временно делает сам Данила вручную, без разграничения
прав на уровне API — это осознанный временный долг, не потерянный
из виду (см. TODO в api/server.py у эндпоинтов /moderation/*).

Как и остальные *_store.py в проекте — всё в памяти процесса, без БД.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

from core.messages_store import Message

logger = logging.getLogger("mimir.moderation")


class ModerationError(Exception):
    """Ошибка операций с очередью модерации (запись не найдена и т.д.)."""


@dataclass
class PendingMessage:
    """Одно сообщение, ожидающее решения человека."""

    hold_id: str
    message: Message
    threat_reasons: list[str] = field(default_factory=list)
    held_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "hold_id": self.hold_id,
            "message": self.message.to_public_dict(),
            "threat_reasons": self.threat_reasons,
            "held_at": self.held_at,
        }


class ModerationStore:
    """Очередь удержанных сообщений — всё в памяти процесса."""

    def __init__(self):
        self._pending: dict[str, PendingMessage] = {}

    def hold(self, message: Message, threat_reasons: list[str]) -> PendingMessage:
        """Кладёт построенный (build_message), но ещё НЕ сохранённый
        (не store()) Message в очередь на модерацию. Вызывающая сторона
        (api/server.py) обязана НЕ вызывать messages_store.store() для
        этого сообщения — иначе оно станет видимым получателю в обход
        очереди, что и есть та самая дыра, которую эта очередь закрывает."""
        pending = PendingMessage(
            hold_id=secrets.token_hex(8),
            message=message,
            threat_reasons=threat_reasons,
        )
        self._pending[pending.hold_id] = pending
        logger.info(
            "Сообщение %s удержано на модерации: reasons=%s",
            message.message_id, threat_reasons,
        )
        return pending

    def get(self, hold_id: str) -> PendingMessage:
        pending = self._pending.get(hold_id)
        if pending is None:
            raise ModerationError(f"Запись модерации {hold_id} не найдена")
        return pending

    def list_pending(self) -> list[PendingMessage]:
        """Вся очередь, по времени удержания — старейшие первыми (их
        нужно разбирать в первую очередь)."""
        return sorted(self._pending.values(), key=lambda p: p.held_at)

    def resolve(self, hold_id: str) -> Message:
        """Убирает запись из очереди и отдаёт Message вызывающей стороне —
        ОДИНАКОВО для approve и reject, разница только в том, что
        вызывающая сторона (api/server.py) делает с Message дальше:
        approve -> messages_store.store(message) (доставить как обычно),
        reject -> просто не сохранять (Message выбрасывается вызывающей
        стороной, здесь для этого ничего специально не нужно). Этот метод
        сам решения "одобрено/отклонено" не знает и не хранит — он не
        специфичен под approve или под reject по отдельности, что и
        подчёркивает границу: решение принимает человек через server.py,
        не этот стор."""
        pending = self._pending.pop(hold_id, None)
        if pending is None:
            raise ModerationError(f"Запись модерации {hold_id} не найдена")
        logger.info("Модерация %s разрешена (снята из очереди)", hold_id)
        return pending.message
