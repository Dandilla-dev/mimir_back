"""
core/message_bridge.py — мост между слоем 1 (транспорт) и слоем 3 (DLP).

Единственное место в системе, которому разрешено видеть одновременно
core/messages_store.py (транспорт), core/org_store.py (членство/флаг),
core/auth_store.py (идентичность) и core/message_parser.py (DLP-парсер) —
см. mimir_architecture_v2.md §4: транспорт и парсер сами по себе друг про
друга не знают, это сознательно.

Правило проверки по направлению (mimir_account_linkage_v1.md §2):
- исходящее сообщение проверяется, только если у отправителя есть
  approved-членство в организации (org_store.is_dlp_active) — это и есть
  тот самый "флаг", живущий на аккаунте, а не на сообщении;
- входящее сообщение проверяется ВСЕГДА, для каждого получателя, вне
  зависимости от типа его аккаунта — это защита получателя (фишинг,
  вредоносные вложения), а не надзор за отправителем.

Один core/messages_store.Message с несколькими получателями порождает:
  - максимум одну проверку "исходящее" (если у отправителя есть флаг) —
    один RawMessage на всех получателей разом, employee_address = отправитель;
  - ровно N проверок "входящее" — по одной на каждого получателя,
    employee_address = этот получатель, отправитель как единственный
    контрагент.

ВАЖНО про адреса: messages_store.Message оперирует внутренними user_id
(хекс-токены из auth_store), а не email. message_parser же (личные домены,
is_known_contact, домен для watchlist-проверки) устроен под email-подобные
адреса — хекс-токен там просто не парсится ни во что осмысленное (домен
всегда получался бы пустым). Поэтому мост обязан резолвить user_id -> email
через auth_store.user_by_id() ДО сборки RawMessage. subject_user_id в
DLPCheck при этом остаётся внутренним user_id — это стабильный ключ,
по которому в будущем будут связываться события с аккаунтом.

Дальше результата (list[DLPEvent]) этот модуль не идёт. Кодирование в
вектор признаков (core/dlp_features.encode_event) и классификация
(models/local_model.EventClassifier) — следующий шаг отдельно; хранилища
для DLPEvent пока тоже нет (тот же долг, что и раньше — EventClassifier
работает на заглушечных весах). Задача моста — только правильно решить,
"проверять или нет" и в каком направлении, и корректно переупаковать формат.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from core.auth_store import AuthStore
from core.dlp_features import DLPEvent
from core.message_parser import (
    DEFAULT_LOOKUPS,
    ParserLookups,
    RawAttachment,
    RawMessage,
    make_lookups_from_contacts_store,
    parse_raw_message,
)
from core.messages_store import Attachment, Message
from core.org_store import OrgStore


class BridgeError(Exception):
    """Не удалось построить RawMessage — например, user_id не резолвится в пользователя."""


@dataclass
class DLPCheck:
    """Один прогон DLP-проверки с точки зрения одного конкретного аккаунта.

    subject_user_id — это внутренний user_id того, чья DLP-политика сейчас
    применяется (employee_address в терминах message_parser — но уже после
    резолва в email, см. docstring модуля). Не обязательно отправитель.
    """
    subject_user_id: str
    is_incoming: bool
    events: list[DLPEvent]


def _to_raw_attachment(attachment: Attachment) -> RawAttachment:
    return RawAttachment(filename=attachment.filename, content=attachment.content)


def _to_datetime(sent_at: float) -> datetime:
    return datetime.fromtimestamp(sent_at)


def _resolve_email(auth_store: AuthStore, user_id: str) -> str:
    user = auth_store.user_by_id(user_id)
    if user is None:
        raise BridgeError(f"Пользователь {user_id} не найден в auth_store")
    return user.email


def check_message(
    message: Message,
    org_store: OrgStore,
    auth_store: AuthStore,
    contacts_store=None,
) -> list[DLPCheck]:
    """Message (транспорт) -> список DLP-проверок, каждая со своими DLPEvent.

    contacts_store опционален: если передан, is_known_contact в каждой
    проверке считается по адресной книге именно subject_user_id (через
    make_lookups_from_contacts_store) — так "новый/известный контакт"
    оценивается с точки зрения того, чей аккаунт защищаем, а не абстрактно.
    Без contacts_store используются DEFAULT_LOOKUPS (см. message_parser.py) —
    так же, как остальные пять признаков без источника данных, до появления
    соответствующих баз (mimir_architecture_v2.md §7).
    """
    checks: list[DLPCheck] = []
    attachments = [_to_raw_attachment(a) for a in message.attachments]
    sent_at = _to_datetime(message.sent_at)

    sender_email = _resolve_email(auth_store, message.sender_id)
    recipient_emails = {
        recipient_id: _resolve_email(auth_store, recipient_id)
        for recipient_id in message.recipient_ids
    }

    def lookups_for(subject_user_id: str) -> ParserLookups:
        if contacts_store is None:
            return DEFAULT_LOOKUPS
        return make_lookups_from_contacts_store(contacts_store, subject_user_id)

    # --- Исходящее: только если у отправителя есть активное членство ---
    if org_store.is_dlp_active(message.sender_id):
        raw = RawMessage(
            sender_address=sender_email,
            recipient_addresses=list(recipient_emails.values()),
            employee_address=sender_email,
            text=message.text,
            attachments=attachments,
            sent_at=sent_at,
        )
        events = parse_raw_message(raw, lookups_for(message.sender_id))
        checks.append(DLPCheck(subject_user_id=message.sender_id, is_incoming=False, events=events))

    # --- Входящее: всегда, для каждого получателя ---
    for recipient_id, recipient_email in recipient_emails.items():
        raw = RawMessage(
            sender_address=sender_email,
            recipient_addresses=[recipient_email],
            employee_address=recipient_email,
            text=message.text,
            attachments=attachments,
            sent_at=sent_at,
        )
        events = parse_raw_message(raw, lookups_for(recipient_id))
        checks.append(DLPCheck(subject_user_id=recipient_id, is_incoming=True, events=events))

    return checks
