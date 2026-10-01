"""
core/isolation_store.py — автоматическая изоляция аккаунта после входящего
THREAT (фишинг). Закрывает открытый вопрос 1.

КОНТЕКСТ РЕШЕНИЯ: удерживать/блокировать каждое входящее THREAT-сообщение
до решения security_officer не масштабируется — входящий THREAT завязан
на действие АТАКУЮЩЕГО, не сотрудника, поэтому одна фишинговая рассылка
может одновременно задеть сотни получателей почти синхронно (в отличие
от исходящего THREAT, который по конструкции редкий — завязан на
осознанное действие одного сотрудника). Если бы каждое такое письмо
превращалось в отдельный hold, очередь взрывалась бы вместе с масштабом
одной атаки, а не вместе со штатом.

Выбран другой путь: входящее сообщение доставляется как раньше (fail-open,
без изменений в api/server.py в этой части) — но ПОЛУЧАТЕЛЬ автоматически
изолируется. Изолированный аккаунт не может сам отправлять коллегам файлы
и ссылки (только текст/голос) — см. проверку в api/server.py, /messages/send
— пока security_officer не снимет изоляцию. Логика: риск не в том, что
пришло получателю, а в том, что аккаунт разошлёт дальше, если уже
скомпрометирован (перешёл по ссылке/открыл вложение до того, как кто-то
это заметил).

ПРИМЕНИМОСТЬ: изоляция накладывается ТОЛЬКО на
org-linked пользователей. Для personal-аккаунтов (без организации)
автоизоляция не применяется вообще — снять её было бы некому, у personal
нет security_officer (та же логика, что уже применена к moderation_store
для исходящей ветки, только зеркально: там hold без организации у
ОТПРАВИТЕЛЯ не создаётся, здесь изоляция без организации у ПОЛУЧАТЕЛЯ
не накладывается). Эту проверку (есть ли активное membership) делает
вызывающая сторона (api/server.py) ДО isolate() — сам этот модуль
ничего не знает про org_store и не резолвит организации.

ГРАНИЦА СЛОЯ: та же логика, что и moderation_store.py — только состояние.
Не решает, когда изолировать (это api/server.py на основе результата
core/dlp_heuristics.classify()) и не резолвит роли/организации (это
org_store.py). Не знает про core/message_parser.py, core/messages_store.py
и что вообще считается "файлом"/"ссылкой" — эту классификацию делает
message_parser.py (is_audio_attachment/contains_link), а применяет её
api/server.py при гейтинге /messages/send.

ХРАНЕНИЕ — PostgreSQL, таблица isolation_records
(migrations/001_initial_schema.sql, раздел 6). [РЕШЕНИЕ 8]: история
изоляций хранится — isolation_id первичный ключ, user_id обычное поле.
Раньше повторная изоляция после снятия затирала прошлую запись; теперь
создаётся новая строка, старая остаётся. "Не больше одной активной
изоляции на пользователя" держит частичный UNIQUE-индекс в БД.
"""

from __future__ import annotations

import logging
import time
import secrets
from dataclasses import dataclass, field

from core import db

logger = logging.getLogger("mimir.isolation")


class IsolationError(Exception):
    """Ошибка операций с изоляцией (пользователь не изолирован и т.д.)."""


@dataclass
class IsolationRecord:
    """Одна изоляция одного пользователя (у пользователя может быть
    несколько записей — история; активной — не больше одной)."""

    user_id: str
    threat_reasons: list[str] = field(default_factory=list)
    isolated_at: float = field(default_factory=time.time)
    lifted_at: float | None = None
    lifted_by: str | None = None
    isolation_id: str = field(default_factory=lambda: secrets.token_hex(8))

    @property
    def is_active(self) -> bool:
        return self.lifted_at is None

    def to_public_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "threat_reasons": self.threat_reasons,
            "isolated_at": self.isolated_at,
            "is_active": self.is_active,
            "lifted_at": self.lifted_at,
            "lifted_by": self.lifted_by,
        }


_I_COLS = "isolation_id, user_id, threat_reasons, isolated_at, lifted_at, lifted_by"


def _row_to_record(row: dict) -> IsolationRecord:
    return IsolationRecord(
        user_id=row["user_id"],
        threat_reasons=list(row["threat_reasons"]),
        isolated_at=db.from_db_time(row["isolated_at"]),
        lifted_at=db.from_db_time(row["lifted_at"]),
        lifted_by=row["lifted_by"],
        isolation_id=row["isolation_id"],
    )


class IsolationStore:
    """Изоляции пользователей с историей — PostgreSQL."""

    def isolate(
        self, user_id: str, threat_reasons: list[str], message_id: str | None = None,
    ) -> IsolationRecord:
        """Накладывает изоляцию. Если пользователь уже активно изолирован —
        НЕ создаёт вторую запись и не сбрасывает isolated_at: повторный
        THREAT во время уже действующей изоляции — это дополнительное
        подтверждение риска, а не повод начинать отсчёт заново. Новые
        причины добавляются к уже накопленным (без дублей, порядок
        первого появления сохраняется).

        message_id — сообщение, вызвавшее изоляцию (или повторный THREAT
        во время неё). Пишется в isolation_triggers: через эту связь вердикт
        officer'а при снятии изоляции доходит до конкретных DLP-событий —
        метки датасета для входящих (миграция 002, представление
        dlp_dataset). Сообщение в этот момент ещё не сохранено — FK
        отложен до конца транзакции /messages/send.

        Одним запросом (INSERT ... ON CONFLICT по частичному индексу
        активной изоляции) — две одновременные изоляции одного
        пользователя не создадут две активные записи."""
        with db.transaction() as conn:
            row = conn.execute(
                f"""
                INSERT INTO isolation_records (isolation_id, user_id, threat_reasons)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id) WHERE lifted_at IS NULL DO UPDATE SET
                    threat_reasons = (
                        SELECT COALESCE(jsonb_agg(reason ORDER BY first_pos), '[]'::jsonb)
                        FROM (
                            SELECT reason, MIN(pos) AS first_pos
                            FROM jsonb_array_elements_text(
                                     isolation_records.threat_reasons || EXCLUDED.threat_reasons
                                 ) WITH ORDINALITY AS t(reason, pos)
                            GROUP BY reason
                        ) dedup
                    )
                RETURNING {_I_COLS}, (xmax = 0) AS inserted
                """,
                (secrets.token_hex(8), user_id, db.jsonb(threat_reasons)),
            ).fetchone()
            if message_id is not None:
                conn.execute(
                    "INSERT INTO isolation_triggers (isolation_id, message_id) "
                    "VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (row["isolation_id"], message_id),
                )
        if row["inserted"]:
            logger.info("Аккаунт %s изолирован: reasons=%s", user_id, threat_reasons)
        return _row_to_record(row)

    def is_isolated(self, user_id: str) -> bool:
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT 1 FROM isolation_records WHERE user_id = %s AND lifted_at IS NULL",
                (user_id,),
            ).fetchone()
        return row is not None

    def get(self, user_id: str) -> IsolationRecord | None:
        """Текущая изоляция пользователя: активная, а если активной нет —
        последняя снятая (как раньше: одна запись на пользователя)."""
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_I_COLS} FROM isolation_records WHERE user_id = %s "
                "ORDER BY (lifted_at IS NULL) DESC, isolated_at DESC LIMIT 1",
                (user_id,),
            ).fetchone()
        return _row_to_record(row) if row else None

    def history(self, user_id: str) -> list[IsolationRecord]:
        """Все изоляции пользователя, старые первыми — для аудита и
        статистики ([РЕШЕНИЕ 8])."""
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_I_COLS} FROM isolation_records WHERE user_id = %s ORDER BY isolated_at",
                (user_id,),
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def list_active(self) -> list[IsolationRecord]:
        """Все активные изоляции, старейшие первыми (тот же принцип, что
        list_pending() в moderation_store.py: дольше всех ждущие
        разбираются в первую очередь)."""
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_I_COLS} FROM isolation_records WHERE lifted_at IS NULL ORDER BY isolated_at"
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def lift(self, user_id: str, lifted_by: str) -> IsolationRecord:
        with db.transaction() as conn:
            row = conn.execute(
                f"UPDATE isolation_records SET lifted_at = now(), lifted_by = %s "
                f"WHERE user_id = %s AND lifted_at IS NULL RETURNING {_I_COLS}",
                (lifted_by, user_id),
            ).fetchone()
        if row is None:
            raise IsolationError(f"Пользователь {user_id} не изолирован")
        logger.info("Изоляция снята: %s (снял %s)", user_id, lifted_by)
        return _row_to_record(row)
