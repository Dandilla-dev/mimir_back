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

import logging
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

logger = logging.getLogger("mimir.message_bridge")


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


def _resolve_recipients(auth_store: AuthStore, message: Message) -> dict[str, str]:
    """Резолвит email каждого получателя независимо — один мусорный/
    несуществующий recipient_id не должен гасить проверку для остальных,
    настоящих получателей того же сообщения (см. обсуждение в чате)."""
    recipient_emails: dict[str, str] = {}
    for recipient_id in message.recipient_ids:
        try:
            recipient_emails[recipient_id] = _resolve_email(auth_store, recipient_id)
        except BridgeError:
            logger.warning(
                "Сообщение %s указывает несуществующего получателя %s — "
                "DLP-проверка для него пропущена, для остальных получателей "
                "продолжается", getattr(message, "message_id", "?"), recipient_id,
            )
    return recipient_emails


def _lookups_for(contacts_store, subject_user_id: str) -> ParserLookups:
    if contacts_store is None:
        return DEFAULT_LOOKUPS
    return make_lookups_from_contacts_store(contacts_store, subject_user_id)


def check_outgoing(
    message: Message,
    org_store: OrgStore,
    auth_store: AuthStore,
    contacts_store=None,
) -> DLPCheck | None:
    """Исходящая проверка — утечка конфиденциальных данных от сотрудника.
    Срабатывает, только если у отправителя активное (approved) членство в
    организации (mimir_account_linkage_v1.md §2); для личных/standalone
    аккаунтов возвращает None и НИКОГДА не строит RawMessage — эта ветка
    для них попросту не существует, не просто "пропущена".

    ПОЛИТИКА ПРИ СБОЕ (вызывающая сторона, не этот модуль, её применяет):
    это ядро продукта — защита от утечки — поэтому предназначено для
    fail-closed: исключение отсюда должно останавливать отправку. Нет
    бытового эквивалента "я и так терплю этот риск" — без Mimir утечку
    через сотрудника никто не ловит вообще, в отличие от фишинга ниже.
    """
    if not org_store.is_dlp_active(message.sender_id):
        return None

    sender_email = _resolve_email(auth_store, message.sender_id)
    recipient_emails = _resolve_recipients(auth_store, message)

    raw = RawMessage(
        sender_address=sender_email,
        recipient_addresses=list(recipient_emails.values()),
        employee_address=sender_email,
        text=message.text,
        attachments=[_to_raw_attachment(a) for a in message.attachments],
        sent_at=_to_datetime(message.sent_at),
    )
    events = parse_raw_message(raw, _lookups_for(contacts_store, message.sender_id))
    return DLPCheck(subject_user_id=message.sender_id, is_incoming=False, events=events)


def check_incoming(
    message: Message,
    auth_store: AuthStore,
    contacts_store=None,
) -> list[DLPCheck]:
    """Входящая проверка — фишинг/вредоносные вложения. Срабатывает ВСЕГДА,
    для каждого получателя, независимо от типа аккаунта (в т.ч. личный
    Mimir) — это защита получателя, а не контроль над отправителем
    (mimir_account_linkage_v1.md §2).

    ПОЛИТИКА ПРИ СБОЕ (вызывающая сторона её применяет): это защита сверх
    базового уровня (то же, от чего пользователь и так не защищён в любом
    обычном мессенджере) — поэтому предназначено для fail-open: исключение
    отсюда не должно останавливать отправку, только логироваться. Откат
    при сбое — это откат к уровню риска обычного Telegram, а не новая
    уязвимость (см. обсуждение в чате).
    """
    sender_email = _resolve_email(auth_store, message.sender_id)
    recipient_emails = _resolve_recipients(auth_store, message)
    attachments = [_to_raw_attachment(a) for a in message.attachments]
    sent_at = _to_datetime(message.sent_at)

    checks: list[DLPCheck] = []
    for recipient_id, recipient_email in recipient_emails.items():
        raw = RawMessage(
            sender_address=sender_email,
            recipient_addresses=[recipient_email],
            employee_address=recipient_email,
            text=message.text,
            attachments=attachments,
            sent_at=sent_at,
        )
        events = parse_raw_message(raw, _lookups_for(contacts_store, recipient_id))
        checks.append(DLPCheck(subject_user_id=recipient_id, is_incoming=True, events=events))

    return checks


def check_message(
    message: Message,
    org_store: OrgStore,
    auth_store: AuthStore,
    contacts_store=None,
) -> list[DLPCheck]:
    """Удобный шорткат check_outgoing()+check_incoming() одним вызовом и
    одной политикой отказа — для мест, где различие fail-open/fail-closed
    по направлению не нужно (например, тесты). В api/server.py используются
    check_outgoing()/check_incoming() по отдельности — см. их docstring."""
    checks: list[DLPCheck] = []
    outgoing = check_outgoing(message, org_store, auth_store, contacts_store)
    if outgoing is not None:
        checks.append(outgoing)
    checks.extend(check_incoming(message, auth_store, contacts_store))
    return checks
