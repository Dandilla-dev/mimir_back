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
- входящее сообщение проверяется только для получателей с approved-
  членством — по правилам организации ПОЛУЧАТЕЛЯ: это защита компании
  (фишинг, вредоносные вложения), а не надзор за отправителем, поэтому
  отправитель может быть и standalone-аккаунтом;
- переписку standalone-аккаунтов (без одобренного членства) сервер не
  проверяет ни в одном направлении и DLP-данных о них не собирает
  (Р4/Р5, mimir_e2ee_dlp_model_v1.md §3).

Один core/messages_store.Message с несколькими получателями порождает:
  - максимум одну проверку "исходящее" (если у отправителя есть флаг) —
    один RawMessage на всех получателей разом, employee_address = отправитель;
  - не больше N проверок "входящее" — по одной на каждого получателя с
    флагом, employee_address = этот получатель, отправитель как
    единственный контрагент; standalone-получатели не дают ни одной.

ВАЖНО про адреса: messages_store.Message оперирует внутренними user_id
(хекс-токены из auth_store), а не email. message_parser же (личные домены,
is_known_contact, домен для watchlist-проверки) устроен под email-подобные
адреса — хекс-токен там просто не парсится ни во что осмысленное (домен
всегда получался бы пустым). Поэтому мост обязан резолвить user_id -> email
через auth_store.user_by_id() ДО сборки RawMessage. subject_user_id в
DLPCheck при этом остаётся внутренним user_id — это стабильный ключ,
по которому в будущем будут связываться события с аккаунтом.

Дальше результата (list[DLPEvent]) этот модуль не идёт — кодирование в
вектор признаков (core/dlp_features.encode_event) и классификация
(core/dlp_heuristics.classify(), сейчас; models/local_model.EventClassifier
на обученных весах — позже) происходят в api/server.py, результат уходит
в core/dlp_events_store.py. Задача моста — только правильно решить,
"проверять или нет" и в каком направлении, собрать ParserLookups из всех
источников, которые сейчас подключены (contacts_store, watchlist_store,
access_store — см. _lookups_for ниже; HR всё ещё не подключена, план
отложен, см. MIMIR_development_plan.md), и корректно переупаковать формат.
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
    make_lookups_from_access_store,
    make_lookups_from_contacts_store,
    make_lookups_from_watchlist_store,
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


def _resolve_recipients(
    auth_store: AuthStore, message: Message, recipient_ids=None,
) -> dict[str, str]:
    """Резолвит email каждого получателя независимо — один мусорный/
    несуществующий recipient_id не должен гасить проверку для остальных,
    настоящих получателей того же сообщения.

    recipient_ids — подмножество получателей (check_incoming() передаёт
    только org-linked); None = все получатели сообщения."""
    if recipient_ids is None:
        recipient_ids = message.recipient_ids
    recipient_emails: dict[str, str] = {}
    for recipient_id in recipient_ids:
        try:
            recipient_emails[recipient_id] = _resolve_email(auth_store, recipient_id)
        except BridgeError:
            logger.warning(
                "Сообщение %s указывает несуществующего получателя %s — "
                "DLP-проверка для него пропущена, для остальных получателей "
                "продолжается", getattr(message, "message_id", "?"), recipient_id,
            )
    return recipient_emails


def _lookups_for(
    contacts_store,
    watchlist_store,
    access_store,
    org_id: str | None,
    subject_user_id: str,
) -> ParserLookups:
    """Собирает ParserLookups из всех источников, которые сейчас
    подключены. Каждый источник расширяет свой набор полей независимо
    от остальных (contacts -> is_known_contact, watchlist ->
    is_domain_watchlisted/is_link_whitelisted, access ->
    is_device_registered/has_legitimate_access/has_elevated_rights) —
    поля, для которых источника нет, остаются на нейтральном дефолте
    DEFAULT_LOOKUPS. Со всеми тремя базами (watchlist + access), которые
    зафиксированы в mimir_architecture_v2.md §7, долг закрыт целиком,
    кроме HR (отложено).

    org_id может быть None — тогда watchlist- и access-поля остаются
    нейтральными, ровно как для contacts_store=None. Из check_outgoing()/
    check_incoming() None сюда не приходит: standalone-аккаунты (без
    одобренного членства) отсекаются раньше и до сборки lookups не
    доходят; ветка оставлена как безопасный дефолт для прямых вызовов."""
    is_known_contact = DEFAULT_LOOKUPS.is_known_contact
    if contacts_store is not None:
        is_known_contact = make_lookups_from_contacts_store(
            contacts_store, subject_user_id
        ).is_known_contact

    is_domain_watchlisted = DEFAULT_LOOKUPS.is_domain_watchlisted
    is_link_whitelisted = DEFAULT_LOOKUPS.is_link_whitelisted
    if watchlist_store is not None and org_id is not None:
        watchlist_lookups = make_lookups_from_watchlist_store(watchlist_store, org_id)
        is_domain_watchlisted = watchlist_lookups.is_domain_watchlisted
        is_link_whitelisted = watchlist_lookups.is_link_whitelisted

    is_device_registered = DEFAULT_LOOKUPS.is_device_registered
    has_legitimate_access = DEFAULT_LOOKUPS.has_legitimate_access
    has_elevated_rights = DEFAULT_LOOKUPS.has_elevated_rights
    if access_store is not None and org_id is not None:
        access_lookups = make_lookups_from_access_store(access_store, org_id, subject_user_id)
        is_device_registered = access_lookups.is_device_registered
        has_legitimate_access = access_lookups.has_legitimate_access
        has_elevated_rights = access_lookups.has_elevated_rights

    return ParserLookups(
        is_known_contact=is_known_contact,
        is_domain_watchlisted=is_domain_watchlisted,
        is_link_whitelisted=is_link_whitelisted,
        is_device_registered=is_device_registered,
        has_legitimate_access=has_legitimate_access,
        has_elevated_rights=has_elevated_rights,
    )


def check_outgoing(
    message: Message,
    org_store: OrgStore,
    auth_store: AuthStore,
    contacts_store=None,
    watchlist_store=None,
    access_store=None,
) -> DLPCheck | None:
    """Исходящая проверка — утечка конфиденциальных данных от сотрудника.
    Срабатывает, только если у отправителя активное (approved) членство в
    организации (mimir_account_linkage_v1.md §2); для standalone-
    аккаунтов возвращает None и НИКОГДА не строит RawMessage — эта ветка
    для них попросту не существует, не просто "пропущена".

    ПОЛИТИКА ПРИ СБОЕ (вызывающая сторона, не этот модуль, её применяет):
    это ядро продукта — защита от утечки — поэтому предназначено для
    fail-closed: исключение отсюда должно останавливать отправку. Нет
    бытового эквивалента "я и так терплю этот риск" — без Mimir утечку
    через сотрудника никто не ловит вообще, в отличие от фишинга ниже.
    """
    membership = org_store.get_active_membership(message.sender_id)
    if membership is None:
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
        device_id=message.device_id,  # сотрудник = отправитель здесь, устройство совпадает
    )
    lookups = _lookups_for(
        contacts_store, watchlist_store, access_store, membership.org_id, message.sender_id
    )
    events = parse_raw_message(raw, lookups)
    return DLPCheck(subject_user_id=message.sender_id, is_incoming=False, events=events)


def check_incoming(
    message: Message,
    auth_store: AuthStore,
    org_store: OrgStore,
    contacts_store=None,
    watchlist_store=None,
    access_store=None,
) -> list[DLPCheck]:
    """Входящая проверка — фишинг/вредоносные вложения. Срабатывает только
    для получателей с активным (approved) членством в организации — по
    одной проверке на каждого такого получателя, по правилам ЕГО
    организации (watchlist, реестр устройств, гранты). Это защита
    компании-получателя, а не надзор за отправителем: отправитель может
    быть кем угодно, в т.ч. standalone-аккаунтом (mimir_account_linkage_v1.md
    §2, mimir_e2ee_dlp_model_v1.md §3).

    Standalone-получатель (без одобренного членства, в т.ч. с заявкой в
    статусе pending) пропускается ЦЕЛИКОМ: для него не резолвится email,
    не строится RawMessage, не вызывается парсер и не создаётся DLPCheck —
    значит, вызывающей стороне нечего записать в dlp_event_records (Р4/Р5:
    переписку standalone-аккаунтов сервер не проверяет и DLP-данных о них
    не собирает). Если ни одного такого получателя нет — возвращается
    пустой список, не резолвится даже отправитель.

    org_store здесь — гейтинг "проверять или нет" (зеркально
    check_outgoing(), только по получателю, а не по отправителю), и
    заодно источник org_id для подстановки watchlist/access этого
    получателя.

    ПОЛИТИКА ПРИ СБОЕ (вызывающая сторона её применяет): это защита сверх
    базового уровня (то же, от чего пользователь и так не защищён в любом
    обычном мессенджере) — поэтому предназначено для fail-open: исключение
    отсюда не должно останавливать отправку, только логироваться. Откат
    при сбое — это откат к уровню риска обычного Telegram, а не новая
    уязвимость.
    """
    # Сначала гейтинг по членству — до любой работы с данными получателя.
    # dict, а не list: повторный recipient_id не даёт двух проверок.
    member_org_ids: dict[str, str] = {}
    for recipient_id in message.recipient_ids:
        membership = org_store.get_active_membership(recipient_id)
        if membership is not None:
            member_org_ids[recipient_id] = membership.org_id
    if not member_org_ids:
        return []

    sender_email = _resolve_email(auth_store, message.sender_id)
    recipient_emails = _resolve_recipients(auth_store, message, member_org_ids.keys())
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
            # device_id НЕ пробрасывается: message.device_id — устройство
            # ОТПРАВИТЕЛЯ (контрагента/атакующего), а не получателя-
            # сотрудника (employee_address здесь), чьё устройство и есть
            # единственное осмысленное для проверки регистрации — см.
            # docstring core/message_parser.RawMessage.device_id. Данных
            # об устройстве получателя в этом запросе нет вообще, поэтому
            # оставляем None -> признак остаётся нейтральным.
        )
        org_id = member_org_ids[recipient_id]
        lookups = _lookups_for(contacts_store, watchlist_store, access_store, org_id, recipient_id)
        events = parse_raw_message(raw, lookups)
        checks.append(DLPCheck(subject_user_id=recipient_id, is_incoming=True, events=events))

    return checks


def check_message(
    message: Message,
    org_store: OrgStore,
    auth_store: AuthStore,
    contacts_store=None,
    watchlist_store=None,
    access_store=None,
) -> list[DLPCheck]:
    """Удобный шорткат check_outgoing()+check_incoming() одним вызовом и
    одной политикой отказа — для мест, где различие fail-open/fail-closed
    по направлению не нужно (например, тесты). В api/server.py используются
    check_outgoing()/check_incoming() по отдельности — см. их docstring."""
    checks: list[DLPCheck] = []
    outgoing = check_outgoing(
        message, org_store, auth_store, contacts_store, watchlist_store, access_store
    )
    if outgoing is not None:
        checks.append(outgoing)
    checks.extend(
        check_incoming(message, auth_store, org_store, contacts_store, watchlist_store, access_store)
    )
    return checks
