"""
core/dlp_events_store.py — хранилище результатов моста (слой 1 -> слой 3).

Принимает то, что производит core/message_bridge.check_message() —
список DLPCheck, каждый со своим list[DLPEvent] — и просто сохраняет,
чтобы результат не терялся в логах (как сейчас). Это ТОЛЬКО хранилище:
по той же логике, что и core/org_store.py, этот модуль ничего не знает
про классификацию, encode_event() или EventClassifier — он не решает,
что делать с событием, только отдаёт то, что в нём лежит, по запросу.

Один DLPEvent на строку (не один DLPCheck на строку): у одного check
может быть несколько событий, и будущему обучению датасета нужны
отдельные строки-события, а не вложенные списки.

Логика та же, что и в auth_store.py / org_store.py / messages_store.py:
всё в памяти процесса, никакой БД.

ВАЖНО (граница слоёв, mimir_architecture_v2.md §4): вызывающая сторона
(пока не подключена — см. следующий шаг после этого модуля) обязана
дергать этот стор из того же места, где вызывается
core/message_bridge.check_message(), а не наоборот — стор не тянет
данные сам, только принимает готовые DLPCheck.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass

from core.dlp_features import DLPEvent
from core.message_bridge import DLPCheck

logger = logging.getLogger("mimir.dlp_events")


class DLPEventsError(Exception):
    """Ошибка операций с хранилищем DLP-событий."""


@dataclass
class DLPEventRecord:
    """Одно сохранённое DLP-событие — DLPEvent плюс контекст, в котором
    оно возникло (чьё это событие, направление, из какого сообщения)."""

    record_id: str
    message_id: str
    subject_user_id: str
    is_incoming: bool
    event: DLPEvent
    recorded_at: float

    def to_public_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "message_id": self.message_id,
            "subject_user_id": self.subject_user_id,
            "is_incoming": self.is_incoming,
            "recorded_at": self.recorded_at,
            # event намеренно не разворачиваю в dict целиком здесь —
            # наружу (REST) пока не нужен, а формат появится вместе с
            # первым потребителем (дашборд офицера безопасности и т.п.).
        }


class DLPEventsStore:
    """Результаты моста — всё в памяти процесса."""

    def __init__(self):
        self._records: dict[str, DLPEventRecord] = {}

    def add_check(self, message_id: str, check: DLPCheck) -> list[DLPEventRecord]:
        """Сохраняет все DLPEvent одного DLPCheck. Вызывать по одному разу
        на каждый DLPCheck, которые вернул message_bridge.check_message()
        (их несколько на одно Message — см. docstring message_bridge.py)."""
        saved: list[DLPEventRecord] = []
        for event in check.events:
            record = DLPEventRecord(
                record_id=secrets.token_hex(8),
                message_id=message_id,
                subject_user_id=check.subject_user_id,
                is_incoming=check.is_incoming,
                event=event,
                recorded_at=time.time(),
            )
            self._records[record.record_id] = record
            saved.append(record)

        if saved:
            logger.info(
                "DLP-события сохранены: message=%s subject=%s incoming=%s count=%d",
                message_id, check.subject_user_id, check.is_incoming, len(saved),
            )
        return saved

    def get(self, record_id: str) -> DLPEventRecord:
        record = self._records.get(record_id)
        if record is None:
            raise DLPEventsError("Событие не найдено")
        return record

    def list_for_subject(self, user_id: str) -> list[DLPEventRecord]:
        """События конкретного аккаунта — для будущего дашборда
        офицера безопасности (mimir_account_linkage_v1.md §2)."""
        return sorted(
            (r for r in self._records.values() if r.subject_user_id == user_id),
            key=lambda r: r.recorded_at,
        )

    def list_for_message(self, message_id: str) -> list[DLPEventRecord]:
        return [r for r in self._records.values() if r.message_id == message_id]

    def list_all(self, limit: int | None = None) -> list[DLPEventRecord]:
        """Полная выгрузка — задел под будущий сбор датасета для обучения
        EventClassifier (mimir_dlp_features_v1.md, MIMIR_development_plan.md
        неделя 7). Пока просто хронологический список без пагинации."""
        records = sorted(self._records.values(), key=lambda r: r.recorded_at)
        return records[:limit] if limit is not None else records
