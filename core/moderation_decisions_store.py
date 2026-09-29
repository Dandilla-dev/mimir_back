"""
core/moderation_decisions_store.py — журнал решений человека по
удержанным на модерации сообщениям (approve/reject в /moderation/*).

ЗАЧЕМ (см. обсуждение в чате, 2026-09-29): раньше moderation_store.resolve()
просто убирал удержание из очереди — после решения не оставалось НИКАКОГО
следа: кто решил, когда, одобрил или отклонил. Это ломало две вещи сразу:
1. Доказательную базу — принцип "автономная блокировка, дальше полная
   документация, решения принимает человек" (principles).
2. Датасет — логирование DLP-событий (MIMIR_development_plan.md, неделя 7)
   без вердикта человека не является обучающими данными: у событий нет
   ground truth. Связь с событиями — через message_id (тот же ключ, под
   которым dlp_events_store.add_check() сохраняет проверки сообщения).

ПОЧЕМУ ОТДЕЛЬНОЕ ХРАНИЛИЩЕ, а не поле в DLPEventRecord (решение Данилы):
- dlp_events_store остаётся чистым хранилищем фактов о событии;
- решение — самостоятельная сущность со своим автором (decided_by) — это
  нужно для статистики согласованности по каждому проверяющему
  (MIMIR_reviewer_consistency.md), которая строится по решениям, а не
  по событиям.

САМООЦЕНКА УВЕРЕННОСТИ (reviewer_confidence) — необязательная, ставит сам
проверяющий. Это человек оценивает СЕБЯ, не машина человека
(MIMIR_reviewer_consistency.md, "машина никогда не оценивает человека").
Это поле — данные для разработчика и для будущего механизма
согласованности, НЕ входной сигнал модели с весом против её уверенности.

СНИМОК НА МОМЕНТ РЕШЕНИЯ: threat_reasons, org_id, sender_id копируются в
запись, а не ссылаются на живые данные — если позже поменяются правила
эвристики или членство отправителя, запись всё равно показывает, на
каком основании решение принималось тогда.

Граница слоя — как у остальных сторов: ничего не решает и не проверяет
права (это api/server.py), только хранит. Записи неизменяемые — решение
не редактируется и не удаляется через API.

Как и остальные *_store.py — всё в памяти процесса, без БД
(mimir_architecture_v2.md §9.7).
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("mimir.moderation_decisions")


class ModerationDecisionError(Exception):
    """Ошибка операций с журналом решений."""


class Decision(str, Enum):
    # approve — человек счёл срабатывание ложным, сообщение доставлено.
    # reject  — человек подтвердил угрозу, сообщение не доставлено.
    APPROVED = "approved"
    REJECTED = "rejected"


class ReviewerConfidence(str, Enum):
    CONFIDENT = "confident"
    UNSURE = "unsure"


@dataclass(frozen=True)
class ModerationDecision:
    """Одно решение человека по одному удержанию. frozen — неизменяемая."""

    decision_id: str
    hold_id: str
    message_id: str
    sender_id: str
    org_id: str | None
    decided_by: str
    decision: Decision
    reviewer_confidence: ReviewerConfidence | None
    threat_reasons: tuple[str, ...]
    held_at: float
    decided_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "hold_id": self.hold_id,
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "org_id": self.org_id,
            "decided_by": self.decided_by,
            "decision": self.decision.value,
            "reviewer_confidence": (
                self.reviewer_confidence.value if self.reviewer_confidence else None
            ),
            "threat_reasons": list(self.threat_reasons),
            "held_at": self.held_at,
            "decided_at": self.decided_at,
        }


class ModerationDecisionsStore:
    """Журнал решений — всё в памяти процесса. Только добавление."""

    def __init__(self):
        self._decisions: dict[str, ModerationDecision] = {}

    def record(
        self,
        *,
        hold_id: str,
        message_id: str,
        sender_id: str,
        org_id: str | None,
        decided_by: str,
        decision: Decision,
        reviewer_confidence: ReviewerConfidence | None,
        threat_reasons: list[str],
        held_at: float,
    ) -> ModerationDecision:
        # По одному удержанию — ровно одно решение. Сейчас повтор и так
        # недостижим (resolve() убирает hold из очереди раньше), проверка —
        # защита от будущего рефакторинга; при переходе на SQL станет
        # UNIQUE(hold_id).
        if any(d.hold_id == hold_id for d in self._decisions.values()):
            raise ModerationDecisionError(f"По удержанию {hold_id} решение уже записано")

        entry = ModerationDecision(
            decision_id=secrets.token_hex(8),
            hold_id=hold_id,
            message_id=message_id,
            sender_id=sender_id,
            org_id=org_id,
            decided_by=decided_by,
            decision=decision,
            reviewer_confidence=reviewer_confidence,
            threat_reasons=tuple(threat_reasons),
            held_at=held_at,
        )
        self._decisions[entry.decision_id] = entry
        logger.info(
            "Решение по модерации %s: %s (решил %s, уверенность=%s)",
            hold_id, decision.value, decided_by,
            reviewer_confidence.value if reviewer_confidence else None,
        )
        return entry

    def list_all(self) -> list[ModerationDecision]:
        """Все решения, новые первыми. Фильтрация по правам (какие
        организации видит конкретный officer) — в api/server.py, тем же
        способом, что /moderation/pending фильтрует list_pending()."""
        return sorted(
            self._decisions.values(),
            key=lambda d: d.decided_at,
            reverse=True,
        )

    def get_by_message(self, message_id: str) -> ModerationDecision | None:
        """Вердикт человека для сообщения — связка с dlp_events_store
        (метка для датасета)."""
        for d in self._decisions.values():
            if d.message_id == message_id:
                return d
        return None

    def list_by_reviewer(self, user_id: str) -> list[ModerationDecision]:
        """Все решения одного проверяющего — вход для статистики
        согласованности (MIMIR_reviewer_consistency.md)."""
        return sorted(
            (d for d in self._decisions.values() if d.decided_by == user_id),
            key=lambda d: d.decided_at,
        )
