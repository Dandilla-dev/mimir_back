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

РОЛИ: право approve/reject проверяется в api/server.py
(_require_moderation_access — security_officer организации из
PendingMessage.org_id), не здесь. Решение человека этот стор тоже не
хранит — resolve() только закрывает удержание; кто/когда/что решил
записывается в core/moderation_decisions_store.py.

ХРАНЕНИЕ — PostgreSQL, таблица moderation_holds
(migrations/001_initial_schema.sql, раздел 5). Изменения относительно
in-memory версии, по решениям контракта:
- [РЕШЕНИЕ 4] само сообщение лежит в messages со статусом
  pending_moderation (его пишет messages_store.store(), до hold()),
  здесь — только ссылка message_id + причины. Строка удержания НЕ
  удаляется при resolve(), а получает resolved_at — поэтому на неё
  может ссылаться журнал решений (FOREIGN KEY).
- [РЕШЕНИЕ 7] org_id — снимок организации отправителя на момент
  поступления сообщения. Решает officer ЭТОЙ организации, даже если
  отправителя позже исключили или перевели.
- resolve() атомарен на уровне БД: UPDATE ... WHERE resolved_at IS NULL.
  Второй officer, нажавший одновременно, получит ModerationError (404).
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

from core import db
from core.messages_store import Message, MessagesStore

logger = logging.getLogger("mimir.moderation")


class ModerationError(Exception):
    """Ошибка операций с очередью модерации (запись не найдена и т.д.)."""


@dataclass
class PendingMessage:
    """Одно сообщение, ожидающее решения человека."""

    hold_id: str
    message: Message
    org_id: str  # снимок организации отправителя ([РЕШЕНИЕ 7])
    threat_reasons: list[str] = field(default_factory=list)
    held_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "hold_id": self.hold_id,
            "message": self.message.to_public_dict(),
            "threat_reasons": self.threat_reasons,
            "held_at": self.held_at,
        }


_H_COLS = "hold_id, message_id, org_id, threat_reasons, held_at"


class ModerationStore:
    """Очередь удержанных сообщений — PostgreSQL."""

    def __init__(self, messages_store: MessagesStore):
        # Сообщение живёт в messages; стор читает его через messages_store,
        # а не своими SQL-запросами к чужим таблицам.
        self._messages = messages_store

    def hold(self, message: Message, threat_reasons: list[str], org_id: str) -> PendingMessage:
        """Ставит удержание на сообщение, уже сохранённое через
        messages_store.store(message, status=PENDING_MODERATION) в той же
        транзакции (api/server.py). Сообщение со статусом delivered
        удерживать нельзя — оно уже видно получателю, это и есть дыра,
        которую очередь закрывает."""
        pending = PendingMessage(
            hold_id=secrets.token_hex(8),
            message=message,
            org_id=org_id,
            threat_reasons=list(threat_reasons),
        )
        with db.transaction() as conn:
            conn.execute(
                f"INSERT INTO moderation_holds ({_H_COLS}) VALUES (%s, %s, %s, %s, %s)",
                (pending.hold_id, message.message_id, org_id,
                 db.jsonb(pending.threat_reasons), db.to_db_time(pending.held_at)),
            )
        logger.info(
            "Сообщение %s удержано на модерации (org=%s): reasons=%s",
            message.message_id, org_id, threat_reasons,
        )
        return pending

    def _row_to_pending(self, row: dict) -> PendingMessage:
        return PendingMessage(
            hold_id=row["hold_id"],
            message=self._messages.get_message(row["message_id"]),
            org_id=row["org_id"],
            threat_reasons=list(row["threat_reasons"]),
            held_at=db.from_db_time(row["held_at"]),
        )

    def get(self, hold_id: str) -> PendingMessage:
        """Только открытое (ещё не разрешённое) удержание."""
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_H_COLS} FROM moderation_holds "
                "WHERE hold_id = %s AND resolved_at IS NULL",
                (hold_id,),
            ).fetchone()
        if row is None:
            raise ModerationError(f"Запись модерации {hold_id} не найдена")
        return self._row_to_pending(row)

    def list_pending(self, org_ids: list[str] | None = None) -> list[PendingMessage]:
        """Открытые удержания, старейшие первыми (их нужно разбирать в
        первую очередь). org_ids — фильтр по организациям (для очереди
        конкретного officer'а); None — вся очередь."""
        query = f"SELECT {_H_COLS} FROM moderation_holds WHERE resolved_at IS NULL"
        params: tuple = ()
        if org_ids is not None:
            query += " AND org_id = ANY(%s)"
            params = (org_ids,)
        with db.transaction() as conn:
            rows = conn.execute(query + " ORDER BY held_at", params).fetchall()
        return [self._row_to_pending(r) for r in rows]

    def resolve(self, hold_id: str) -> Message:
        """Закрывает удержание и отдаёт Message вызывающей стороне —
        ОДИНАКОВО для approve и reject. Что делать с сообщением дальше,
        решает api/server.py: approve -> messages_store.mark_delivered(),
        reject -> messages_store.mark_rejected(). Этот метод решения
        "одобрено/отклонено" не знает и не хранит."""
        with db.transaction() as conn:
            row = conn.execute(
                "UPDATE moderation_holds SET resolved_at = now() "
                "WHERE hold_id = %s AND resolved_at IS NULL RETURNING message_id",
                (hold_id,),
            ).fetchone()
        if row is None:
            raise ModerationError(f"Запись модерации {hold_id} не найдена")
        logger.info("Модерация %s разрешена (закрыта)", hold_id)
        return self._messages.get_message(row["message_id"])
