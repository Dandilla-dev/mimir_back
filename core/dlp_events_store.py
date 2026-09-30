"""
core/dlp_events_store.py — хранилище результатов моста (слой 1 -> слой 3).

Принимает то, что производит core/message_bridge.check_message() —
список DLPCheck, каждый со своим list[DLPEvent] — плюс уже готовый
результат эвристической классификации каждого события
(core/dlp_heuristics.classify(), см. HeuristicResult) — и просто сохраняет,
чтобы результат не терялся в логах (как сейчас). Это ТОЛЬКО хранилище:
по той же логике, что и auth_store.py/org_store.py, этот модуль сам НЕ
вызывает classify() и не решает, когда и зачем классифицировать — решение
принимает и готовый результат передаёт вызывающая сторона (api/server.py).
Импорт HeuristicResult здесь — только форма данных для типа параметра,
тот же паттерн, что уже применён к DLPCheck (импортирован из
message_bridge ниже) — не значит, что стор вычисляет классификацию сам.

Один DLPEvent на строку (не один DLPCheck на строку): у одного check
может быть несколько событий, и будущему обучению датасета нужны
отдельные строки-события, а не вложенные списки.

ХРАНЕНИЕ — PostgreSQL, таблица dlp_event_records
(migrations/001_initial_schema.sql, раздел 7). Поля DLPEvent развёрнуты в
колонки той же строки (не JSON): это будущий датасет, по ним нужны WHERE.
near_termination/on_official_leave — NULL-способные: NULL = "HR-интеграция
недоступна", третье состояние, не false.

message_id — FOREIGN KEY на messages, отложенный до конца транзакции
(DEFERRABLE): для исходящей проверки add_check() вызывается ДО сохранения
сообщения, поэтому api/server.py пишет сообщение, события и удержание
одной транзакцией.

ВАЖНО (граница слоёв, mimir_architecture_v2.md §4): вызывающая сторона
(api/server.py) обязана дергать этот стор из того же места, где вызывается
core/message_bridge.check_message() и core/dlp_heuristics.classify(), а не
наоборот — стор не тянет данные сам, только принимает готовые DLPCheck +
HeuristicResult.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

from core import db
from core.dlp_features import AttachmentCategory, DLPEvent
from core.dlp_heuristics import HeuristicResult, ThreatLevel
from core.message_bridge import DLPCheck

logger = logging.getLogger("mimir.dlp_events")


class DLPEventsError(Exception):
    """Ошибка операций с хранилищем DLP-событий."""


@dataclass
class DLPEventRecord:
    """Одно сохранённое DLP-событие — DLPEvent плюс контекст, в котором
    оно возникло (чьё это событие, направление, из какого сообщения),
    плюс результат эвристической классификации (level/причины) —
    см. обсуждение в чате, пункт 1.2: отдельные поля, не вложенный объект.
    """

    record_id: str
    message_id: str
    subject_user_id: str
    is_incoming: bool
    event: DLPEvent
    recorded_at: float
    level: ThreatLevel
    threat_reasons: list[str] = field(default_factory=list)
    anomaly_reasons: list[str] = field(default_factory=list)

    def to_public_dict(self) -> dict:
        """Для дашборда офицера безопасности нужны три вещи (см.
        обсуждение в чате, пункт 1.3): событие, пользователь,
        классификация — все три теперь разворачиваются наружу.
        event сериализуется через DLPEvent.to_public_dict() — этот
        модуль не знает его внутреннюю структуру и не дублирует её
        руками (см. докстринг dlp_features.DLPEvent.to_public_dict)."""
        return {
            "record_id": self.record_id,
            "message_id": self.message_id,
            "subject_user_id": self.subject_user_id,
            "is_incoming": self.is_incoming,
            "recorded_at": self.recorded_at,
            "event": self.event.to_public_dict(),
            "level": self.level.value,
            "threat_reasons": self.threat_reasons,
            "anomaly_reasons": self.anomaly_reasons,
        }


# Колонки DLPEvent в том же порядке, что и в таблице (кроме is_incoming —
# он хранится один раз, на уровне записи; в DLPEvent и DLPEventRecord он
# всегда совпадает, т.к. событие строится из того же check).
_EVENT_FIELDS = (
    "counterparty_external", "counterparty_new", "counterparty_address_personal",
    "counterparty_domain_watchlisted",
    "has_attachment", "attachment_size_bytes", "attachment_category",
    "has_macro_or_executable_code", "confidentiality_marker_found",
    "attachment_password_protected", "has_external_link", "link_not_whitelisted",
    "event_time", "is_non_working_day", "near_termination", "on_official_leave",
    "device_unregistered", "lacks_legitimate_access", "has_elevated_rights",
)
_RECORD_FIELDS = (
    "record_id", "message_id", "subject_user_id", "is_incoming", "recorded_at",
    "level", "threat_reasons", "anomaly_reasons",
)
_ALL_COLS = ", ".join(_RECORD_FIELDS + _EVENT_FIELDS)


def _event_value(event: DLPEvent, name: str):
    value = getattr(event, name)
    if name == "attachment_category":
        return value.value
    if name == "event_time":
        return db.local_naive_to_db(value)
    return value


def _row_to_record(row: dict) -> DLPEventRecord:
    event_kwargs = {name: row[name] for name in _EVENT_FIELDS}
    event_kwargs["attachment_category"] = AttachmentCategory(row["attachment_category"])
    event_kwargs["event_time"] = db.db_to_local_naive(row["event_time"])
    return DLPEventRecord(
        record_id=row["record_id"],
        message_id=row["message_id"],
        subject_user_id=row["subject_user_id"],
        is_incoming=row["is_incoming"],
        event=DLPEvent(is_incoming=row["is_incoming"], **event_kwargs),
        recorded_at=db.from_db_time(row["recorded_at"]),
        level=ThreatLevel(row["level"]),
        threat_reasons=list(row["threat_reasons"]),
        anomaly_reasons=list(row["anomaly_reasons"]),
    )


class DLPEventsStore:
    """Результаты моста + классификации — PostgreSQL."""

    def add_check(
        self,
        message_id: str,
        check: DLPCheck,
        classifications: list[HeuristicResult],
    ) -> list[DLPEventRecord]:
        """Сохраняет все DLPEvent одного DLPCheck вместе с их
        классификацией. Вызывать по одному разу на каждый DLPCheck,
        которые вернул message_bridge.check_message() (их несколько на
        одно Message — см. docstring message_bridge.py).

        classifications — результат dlp_heuristics.classify() для каждого
        DLPEvent из check.events, В ТОМ ЖЕ ПОРЯДКЕ и той же длины: этот
        метод сам classify() не вызывает (см. докстринг модуля) — только
        сопоставляет по индексу и сохраняет пару (событие, классификация)
        одной строкой."""
        if len(classifications) != len(check.events):
            raise DLPEventsError(
                f"classifications ({len(classifications)}) не совпадает по "
                f"длине с check.events ({len(check.events)}) — вызывающая "
                f"сторона должна классифицировать каждое событие по одному"
            )

        saved: list[DLPEventRecord] = []
        placeholders = ", ".join(["%s"] * (len(_RECORD_FIELDS) + len(_EVENT_FIELDS)))
        with db.transaction() as conn:
            for event, result in zip(check.events, classifications):
                record = DLPEventRecord(
                    record_id=secrets.token_hex(8),
                    message_id=message_id,
                    subject_user_id=check.subject_user_id,
                    is_incoming=check.is_incoming,
                    event=event,
                    recorded_at=time.time(),
                    level=result.level,
                    threat_reasons=list(result.threat_reasons),
                    anomaly_reasons=list(result.anomaly_reasons),
                )
                conn.execute(
                    f"INSERT INTO dlp_event_records ({_ALL_COLS}) VALUES ({placeholders})",
                    (
                        record.record_id, message_id, record.subject_user_id,
                        record.is_incoming, db.to_db_time(record.recorded_at),
                        record.level.value, db.jsonb(record.threat_reasons),
                        db.jsonb(record.anomaly_reasons),
                        *(_event_value(event, name) for name in _EVENT_FIELDS),
                    ),
                )
                saved.append(record)

        if saved:
            logger.info(
                "DLP-события сохранены: message=%s subject=%s incoming=%s "
                "count=%d levels=%s",
                message_id, check.subject_user_id, check.is_incoming,
                len(saved), [r.level.value for r in saved],
            )
        return saved

    def _select(self, where: str = "", params: tuple = (), tail: str = "ORDER BY recorded_at, record_id"):
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_ALL_COLS} FROM dlp_event_records {where} {tail}", params,
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def get(self, record_id: str) -> DLPEventRecord:
        records = self._select("WHERE record_id = %s", (record_id,))
        if not records:
            raise DLPEventsError("Событие не найдено")
        return records[0]

    def list_for_subject(self, user_id: str) -> list[DLPEventRecord]:
        """События конкретного аккаунта — для будущего дашборда
        офицера безопасности (mimir_account_linkage_v1.md §2)."""
        return self._select("WHERE subject_user_id = %s", (user_id,))

    def list_for_message(self, message_id: str) -> list[DLPEventRecord]:
        return self._select("WHERE message_id = %s", (message_id,))

    def list_by_level(self, level: ThreatLevel) -> list[DLPEventRecord]:
        """Записи одного уровня — основа для сводки по ANOMALY (агрегированная
        сводка вместо карточки на каждую запись)."""
        return self._select("WHERE level = %s", (level.value,))

    def list_all(
        self,
        limit: int | None = None,
        after: tuple[float, str] | None = None,
    ) -> list[DLPEventRecord]:
        """Выгрузка для будущего датасета EventClassifier
        (MIMIR_development_plan.md, неделя 7), хронологически.

        Курсорная пагинация: after = (recorded_at, record_id) последней
        записи предыдущей страницы — следующая страница начинается строго
        после неё. Не OFFSET: при большом объёме OFFSET перечитывает все
        пропущенные строки, курсор идёт по индексу dlp_events_cursor_idx."""
        where, params = "", ()
        if after is not None:
            where = "WHERE (recorded_at, record_id) > (%s, %s)"
            params = (db.to_db_time(after[0]), after[1])
        tail = "ORDER BY recorded_at, record_id"
        if limit is not None:
            tail += " LIMIT %s"
            params = (*params, limit)
        return self._select(where, params, tail)
