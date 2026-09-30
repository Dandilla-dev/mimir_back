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
не редактируется и не удаляется: в БД это закреплено триггером
moderation_decisions_append_only (UPDATE/DELETE -> ошибка).

ХРАНЕНИЕ — PostgreSQL, таблица moderation_decisions
(migrations/001_initial_schema.sql, раздел 10). UNIQUE(hold_id) — одно
решение на удержание на уровне БД; hold_id — FOREIGN KEY на
moderation_holds (строка удержания после resolve() не удаляется).
org_id — снимок из удержания ([РЕШЕНИЕ 7]), поэтому больше не бывает None.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

from core import db

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
    org_id: str
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


_D_COLS = ("decision_id, hold_id, message_id, sender_id, org_id, decided_by, decision, "
           "reviewer_confidence, threat_reasons, held_at, decided_at")


def _row_to_decision(row: dict) -> ModerationDecision:
    return ModerationDecision(
        decision_id=row["decision_id"],
        hold_id=row["hold_id"],
        message_id=row["message_id"],
        sender_id=row["sender_id"],
        org_id=row["org_id"],
        decided_by=row["decided_by"],
        decision=Decision(row["decision"]),
        reviewer_confidence=(
            ReviewerConfidence(row["reviewer_confidence"]) if row["reviewer_confidence"] else None
        ),
        threat_reasons=tuple(row["threat_reasons"]),
        held_at=db.from_db_time(row["held_at"]),
        decided_at=db.from_db_time(row["decided_at"]),
    )


class ModerationDecisionsStore:
    """Журнал решений — PostgreSQL. Только добавление."""

    def record(
        self,
        *,
        hold_id: str,
        message_id: str,
        sender_id: str,
        org_id: str,
        decided_by: str,
        decision: Decision,
        reviewer_confidence: ReviewerConfidence | None,
        threat_reasons: list[str],
        held_at: float,
    ) -> ModerationDecision:
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
        try:
            with db.transaction() as conn:
                conn.execute(
                    f"INSERT INTO moderation_decisions ({_D_COLS}) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (entry.decision_id, hold_id, message_id, sender_id, org_id, decided_by,
                     decision.value,
                     reviewer_confidence.value if reviewer_confidence else None,
                     db.jsonb(threat_reasons), db.to_db_time(held_at),
                     db.to_db_time(entry.decided_at)),
                )
        except db.UniqueViolation as exc:
            # UNIQUE(hold_id): по одному удержанию — ровно одно решение.
            raise ModerationDecisionError(f"По удержанию {hold_id} решение уже записано") from exc
        logger.info(
            "Решение по модерации %s: %s (решил %s, уверенность=%s)",
            hold_id, decision.value, decided_by,
            reviewer_confidence.value if reviewer_confidence else None,
        )
        return entry

    def list_all(self, org_ids: list[str] | None = None) -> list[ModerationDecision]:
        """Все решения, новые первыми. org_ids — фильтр по организациям
        (журнал конкретного officer'а, api/server.py); None — все."""
        query = f"SELECT {_D_COLS} FROM moderation_decisions"
        params: tuple = ()
        if org_ids is not None:
            query += " WHERE org_id = ANY(%s)"
            params = (org_ids,)
        with db.transaction() as conn:
            rows = conn.execute(query + " ORDER BY decided_at DESC", params).fetchall()
        return [_row_to_decision(r) for r in rows]

    def get_by_message(self, message_id: str) -> ModerationDecision | None:
        """Вердикт человека для сообщения — связка с dlp_events_store
        (метка для датасета)."""
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_D_COLS} FROM moderation_decisions WHERE message_id = %s LIMIT 1",
                (message_id,),
            ).fetchone()
        return _row_to_decision(row) if row else None

    def list_by_reviewer(self, user_id: str) -> list[ModerationDecision]:
        """Все решения одного проверяющего — вход для статистики
        согласованности (MIMIR_reviewer_consistency.md)."""
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_D_COLS} FROM moderation_decisions "
                "WHERE decided_by = %s ORDER BY decided_at",
                (user_id,),
            ).fetchall()
        return [_row_to_decision(r) for r in rows]
