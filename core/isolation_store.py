"""
core/isolation_store.py — автоматическая изоляция аккаунта после входящего
THREAT (фишинг). Закрывает открытый вопрос 1 (см. обсуждение в чате).

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

ПРИМЕНИМОСТЬ (см. обсуждение в чате): изоляция накладывается ТОЛЬКО на
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

Как и остальные *_store.py в проекте — всё в памяти процесса, без БД.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("mimir.isolation")


class IsolationError(Exception):
    """Ошибка операций с изоляцией (пользователь не изолирован и т.д.)."""


@dataclass
class IsolationRecord:
    """Состояние изоляции одного пользователя. Одна запись на user_id —
    не история holds, а текущее состояние (активна/снята)."""

    user_id: str
    threat_reasons: list[str] = field(default_factory=list)
    isolated_at: float = field(default_factory=time.time)
    lifted_at: float | None = None
    lifted_by: str | None = None

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


class IsolationStore:
    """Состояние изоляции по пользователю — всё в памяти процесса."""

    def __init__(self):
        self._records: dict[str, IsolationRecord] = {}

    def isolate(self, user_id: str, threat_reasons: list[str]) -> IsolationRecord:
        """Накладывает изоляцию. Если пользователь уже активно изолирован —
        НЕ создаёт вторую запись и не сбрасывает isolated_at: повторный
        THREAT во время уже действующей изоляции — это дополнительное
        подтверждение риска, а не повод начинать отсчёт заново. Новые
        причины добавляются к уже накопленным (без дублей)."""
        existing = self._records.get(user_id)
        if existing is not None and existing.is_active:
            for reason in threat_reasons:
                if reason not in existing.threat_reasons:
                    existing.threat_reasons.append(reason)
            return existing

        record = IsolationRecord(user_id=user_id, threat_reasons=list(threat_reasons))
        self._records[user_id] = record
        logger.info("Аккаунт %s изолирован: reasons=%s", user_id, threat_reasons)
        return record

    def is_isolated(self, user_id: str) -> bool:
        record = self._records.get(user_id)
        return record is not None and record.is_active

    def get(self, user_id: str) -> IsolationRecord | None:
        return self._records.get(user_id)

    def list_active(self) -> list[IsolationRecord]:
        """Все активные изоляции, старейшие первыми (см. list_pending()
        в moderation_store.py — тот же принцип: дольше всех ждущие
        разбираются в первую очередь)."""
        return sorted(
            (r for r in self._records.values() if r.is_active),
            key=lambda r: r.isolated_at,
        )

    def lift(self, user_id: str, lifted_by: str) -> IsolationRecord:
        record = self._records.get(user_id)
        if record is None or not record.is_active:
            raise IsolationError(f"Пользователь {user_id} не изолирован")
        record.lifted_at = time.time()
        record.lifted_by = lifted_by
        logger.info("Изоляция снята: %s (снял %s)", user_id, lifted_by)
        return record
