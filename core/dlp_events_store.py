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

Логика та же, что и в auth_store.py / org_store.py / messages_store.py:
всё в памяти процесса, никакой БД.

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

from core.dlp_features import DLPEvent
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


class DLPEventsStore:
    """Результаты моста + классификации — всё в памяти процесса."""

    def __init__(self):
        self._records: dict[str, DLPEventRecord] = {}

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
        for event, result in zip(check.events, classifications):
            record = DLPEventRecord(
                record_id=secrets.token_hex(8),
                message_id=message_id,
                subject_user_id=check.subject_user_id,
                is_incoming=check.is_incoming,
                event=event,
                recorded_at=time.time(),
                level=result.level,
                threat_reasons=result.threat_reasons,
                anomaly_reasons=result.anomaly_reasons,
            )
            self._records[record.record_id] = record
            saved.append(record)

        if saved:
            logger.info(
                "DLP-события сохранены: message=%s subject=%s incoming=%s "
                "count=%d levels=%s",
                message_id, check.subject_user_id, check.is_incoming,
                len(saved), [r.level.value for r in saved],
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

    def list_by_level(self, level: ThreatLevel) -> list[DLPEventRecord]:
        """Записи одного уровня — основа для сводки по ANOMALY (см.
        обсуждение в чате: агрегированная сводка вместо карточки на
        каждую запись) и для будущей очереди THREAT-модерации."""
        return sorted(
            (r for r in self._records.values() if r.level == level),
            key=lambda r: r.recorded_at,
        )

    def list_all(self, limit: int | None = None) -> list[DLPEventRecord]:
        """Полная выгрузка — задел под будущий сбор датасета для обучения
        EventClassifier (mimir_dlp_features_v1.md, MIMIR_development_plan.md
        неделя 7). Пока просто хронологический список без пагинации."""
        records = sorted(self._records.values(), key=lambda r: r.recorded_at)
        return records[:limit] if limit is not None else records
