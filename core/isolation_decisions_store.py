"""
core/isolation_decisions_store.py — журнал вердиктов при снятии изоляции.

Зеркало core/moderation_decisions_store.py для входящих событий. Officer,
снимая изоляцию (POST /moderation/isolated/{user_id}/lift), указывает,
что это было на самом деле:
- threat_confirmed — угроза подтверждена (фишинг был фишингом);
- false_positive  — ложное срабатывание.
и, по желанию, свою уверенность (ReviewerConfidence — та же шкала, что и
при модерации).

Зачем: метка человека — единственный источник правды для обучения
классификатора (уровень эвристики — её догадка, а не правда). Для
исходящих метки даёт модерация, для входящих раньше не давало ничего:
снятие изоляции записывало только кто и когда. Связь вердикта с
конкретными DLP-событиями — через isolation_triggers (какие сообщения
вызвали изоляцию), готовая выборка — представление dlp_dataset
(migrations/002_roles_and_isolation_verdicts.sql).

Записи неизменяемые: в БД — триггер isolation_decisions_append_only.
UNIQUE(isolation_id) — один вердикт на одну изоляцию.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

from core import db
from core.moderation_decisions_store import ReviewerConfidence

logger = logging.getLogger("mimir.isolation_decisions")


class IsolationDecisionError(Exception):
    """Ошибка журнала вердиктов (повторный вердикт по той же изоляции)."""


class IsolationVerdict(str, Enum):
    THREAT_CONFIRMED = "threat_confirmed"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True)
class IsolationDecision:
    decision_id: str
    isolation_id: str
    user_id: str          # кого изолировали
    org_id: str
    decided_by: str
    verdict: IsolationVerdict
    reviewer_confidence: ReviewerConfidence | None
    threat_reasons: tuple[str, ...]
    isolated_at: float
    decided_at: float = field(default_factory=time.time)


_COLS = ("decision_id, isolation_id, user_id, org_id, decided_by, verdict, "
         "reviewer_confidence, threat_reasons, isolated_at, decided_at")


def _row_to_decision(row: dict) -> IsolationDecision:
    return IsolationDecision(
        decision_id=row["decision_id"],
        isolation_id=row["isolation_id"],
        user_id=row["user_id"],
        org_id=row["org_id"],
        decided_by=row["decided_by"],
        verdict=IsolationVerdict(row["verdict"]),
        reviewer_confidence=(
            ReviewerConfidence(row["reviewer_confidence"]) if row["reviewer_confidence"] else None
        ),
        threat_reasons=tuple(row["threat_reasons"]),
        isolated_at=db.from_db_time(row["isolated_at"]),
        decided_at=db.from_db_time(row["decided_at"]),
    )


class IsolationDecisionsStore:
    """Журнал вердиктов по изоляциям — PostgreSQL. Только добавление."""

    def record(
        self,
        *,
        isolation_id: str,
        user_id: str,
        org_id: str,
        decided_by: str,
        verdict: IsolationVerdict,
        reviewer_confidence: ReviewerConfidence | None,
        threat_reasons: list[str],
        isolated_at: float,
    ) -> IsolationDecision:
        entry = IsolationDecision(
            decision_id=secrets.token_hex(8),
            isolation_id=isolation_id,
            user_id=user_id,
            org_id=org_id,
            decided_by=decided_by,
            verdict=verdict,
            reviewer_confidence=reviewer_confidence,
            threat_reasons=tuple(threat_reasons),
            isolated_at=isolated_at,
        )
        try:
            with db.transaction() as conn:
                conn.execute(
                    f"INSERT INTO isolation_decisions ({_COLS}) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (entry.decision_id, isolation_id, user_id, org_id, decided_by,
                     verdict.value,
                     reviewer_confidence.value if reviewer_confidence else None,
                     db.jsonb(threat_reasons), db.to_db_time(isolated_at),
                     db.to_db_time(entry.decided_at)),
                )
        except db.UniqueViolation as exc:
            raise IsolationDecisionError(
                f"По изоляции {isolation_id} вердикт уже записан"
            ) from exc
        logger.info(
            "Вердикт по изоляции %s: %s (решил %s, уверенность=%s)",
            isolation_id, verdict.value, decided_by,
            reviewer_confidence.value if reviewer_confidence else None,
        )
        return entry

    def list_all(self, org_ids: list[str] | None = None) -> list[IsolationDecision]:
        """Все вердикты, новые первыми. org_ids — фильтр по организациям."""
        query = f"SELECT {_COLS} FROM isolation_decisions"
        params: tuple = ()
        if org_ids is not None:
            query += " WHERE org_id = ANY(%s)"
            params = (org_ids,)
        with db.transaction() as conn:
            rows = conn.execute(query + " ORDER BY decided_at DESC", params).fetchall()
        return [_row_to_decision(r) for r in rows]

    def list_by_reviewer(self, user_id: str) -> list[IsolationDecision]:
        """Все вердикты одного проверяющего — вход для статистики
        согласованности (MIMIR_reviewer_consistency.md), вместе с
        moderation_decisions_store.list_by_reviewer()."""
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_COLS} FROM isolation_decisions "
                "WHERE decided_by = %s ORDER BY decided_at",
                (user_id,),
            ).fetchall()
        return [_row_to_decision(r) for r in rows]
