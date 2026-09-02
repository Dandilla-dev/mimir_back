"""
core/message_parser.py — парсер "сырое сообщение мессенджера" -> DLPEvent(-ы).

Реализует контракт RawMessage, зафиксированный при обсуждении архитектуры
(см. mimir_architecture_v2.md, раздел 7): парсер не зависит от того, как
именно слой 1 (транспорт) хранит сообщения внутри себя — только от этого
контракта. Когда транспортный слой будет реализован полностью, он обязан
уметь превращать своё внутреннее сообщение в RawMessage перед вызовом
parse_raw_message().

Признаки, для которых источника данных пока нет (HR-справочник, список
наблюдаемых доменов, реестр устройств, роли доступа) — подставляются
нейтральным значением 0/False до появления соответствующих баз данных
(решение зафиксировано 2026-09-02, см. mimir_architecture_v2.md §7).
Продукт не выходит в реальную эксплуатацию, пока эти базы не готовы хотя бы
в минимальном виде — на этот период значения по умолчанию условны.

Групповые сообщения: один RawMessage с несколькими получателями порождает
по одному DLPEvent на каждого получателя-контрагента (кроме самого
сотрудника, если он есть среди адресатов) — так каждый контрагент
оценивается отдельно, а не "усредняется" в одно событие.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from core.dlp_features import AttachmentCategory, DLPEvent

# ---------------------------------------------------------------------------
# Контракт входных данных
# ---------------------------------------------------------------------------


@dataclass
class RawAttachment:
    filename: str
    content: bytes | None = None  # если недоступно — используем size_bytes
    size_bytes: int | None = None

    def resolved_size(self) -> int:
        if self.content is not None:
            return len(self.content)
        return self.size_bytes or 0


@dataclass
class RawMessage:
    sender_address: str
    recipient_addresses: list[str]
    employee_address: str  # фиксированная точка отсчёта — какая сторона сотрудник
    text: str = ""
    attachments: list[RawAttachment] = field(default_factory=list)
    sent_at: datetime = field(default_factory=datetime.now)


# ---------------------------------------------------------------------------
# Внешние проверки (lookups) — точки расширения под будущие базы данных.
# По умолчанию все, кроме известности контакта, возвращают "нет данных" (0).
# ---------------------------------------------------------------------------


@dataclass
class ParserLookups:
    """Функции проверки, зависящие от баз данных, которых частично ещё нет.

    Дефолты соответствуют решению "0 до готовности баз" — см. docstring
    модуля. Реальные реализации подключаются извне (см.
    make_lookups_from_contacts_store ниже — единственный источник,
    который уже есть).
    """

    is_known_contact: Callable[[str], bool] = lambda address: False
    is_internal_employee: Callable[[str], bool] = lambda address: True  # ждёт HR, дефолт "внутри" = 0 = тихо
    is_domain_watchlisted: Callable[[str], bool] = lambda domain: False  # ждёт список доменов
    is_link_whitelisted: Callable[[str], bool] = lambda domain: True  # ждёт белый список
    is_device_registered: Callable[[str], bool] = lambda device_id: True  # ждёт реестр устройств
    has_legitimate_access: Callable[[str, str], bool] = lambda user, resource: True  # ждёт роли
    has_elevated_rights: Callable[[str], bool] = lambda user: False  # ждёт роли


def make_lookups_from_contacts_store(contacts_store, owner_user_id: str) -> ParserLookups:
    """Единственная уже существующая реальная проверка — известность контакта
    через core/contacts_store.py. Остальные lookups остаются дефолтными
    (нейтральными), пока соответствующих баз нет.
    """
    known_emails = {
        c.email.lower()
        for c in contacts_store.list_contacts(owner_user_id)
        if c.email
    }
    return ParserLookups(is_known_contact=lambda address: address.lower() in known_emails)


DEFAULT_LOOKUPS = ParserLookups()


# ---------------------------------------------------------------------------
# Справочники для эвристик, не зависящих от внешних баз
# ---------------------------------------------------------------------------

_PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "mail.ru", "yandex.ru", "yandex.com", "bk.ru", "list.ru", "inbox.ru",
    "protonmail.com", "aol.com",
}

_EXECUTABLE_EXTENSIONS = {"exe", "bat", "cmd", "sh", "ps1", "vbs", "js", "msi", "scr"}
_MACRO_EXTENSIONS = {"docm", "xlsm", "pptm"}

_ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz"}
_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "webp", "svg"}
_DOCUMENT_EXTENSIONS = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "csv",
}

_CONFIDENTIALITY_PATTERN = re.compile(
    r"\b(confidential|конфиденциально|коммерческая тайна|nda|не для распространения|"
    r"договор\s*№|contract\s*no\.?)\b",
    re.IGNORECASE,
)

_URL_PATTERN = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)

# Домены, повсеместно ассоциируемые с публичными файлообменниками —
# отдельно от списка watchlist-доменов (которого пока нет как базы),
# это узкий и стабильный список, не требующий отдельной БД.
_FILE_SHARING_DOMAINS = {
    "wetransfer.com", "mega.nz", "mediafire.com", "sendspace.com",
    "dropbox.com", "drive.google.com",
}


def _extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _attachment_category(filename: str) -> AttachmentCategory:
    ext = _extension_of(filename)
    if ext in _ARCHIVE_EXTENSIONS:
        return AttachmentCategory.ARCHIVE
    if ext in _IMAGE_EXTENSIONS:
        return AttachmentCategory.IMAGE
    if ext in _EXECUTABLE_EXTENSIONS:
        return AttachmentCategory.EXECUTABLE
    if ext in _DOCUMENT_EXTENSIONS or ext in _MACRO_EXTENSIONS:
        return AttachmentCategory.DOCUMENT
    return AttachmentCategory.DOCUMENT  # неизвестное расширение — консервативно как документ


def _has_macro_or_executable(filename: str) -> bool:
    ext = _extension_of(filename)
    return ext in _EXECUTABLE_EXTENSIONS or ext in _MACRO_EXTENSIONS


def _is_password_protected(attachment: RawAttachment) -> bool:
    """Best-effort проверка для zip-подобных вложений (включая docx/xlsx,
    которые внутри тоже zip). Требует реального содержимого — если есть
    только размер (content is None), проверка невозможна, возвращаем False.
    """
    if attachment.content is None:
        return False
    ext = _extension_of(attachment.filename)
    if ext not in _ARCHIVE_EXTENSIONS and ext not in {"docx", "xlsx", "pptx"}:
        return False
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(attachment.content)) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # бит шифрования в ZIP-заголовке
                    return True
        return False
    except (zipfile.BadZipFile, RuntimeError):
        # не zip (rar/7z и т.п.) или повреждён — best-effort, не считаем угрозой
        return False


def _primary_attachment(attachments: list[RawAttachment]) -> RawAttachment | None:
    """Вложение с наибольшим размером — как более рискованное по умолчанию."""
    if not attachments:
        return None
    return max(attachments, key=lambda a: a.resolved_size())


def _is_non_working_day(dt: datetime) -> bool:
    # weekday(): 0=понедельник ... 6=воскресенье. Праздники не учитываются —
    # отдельный, более мелкий долг (нужен календарь праздников).
    return dt.weekday() >= 5


def _extract_first_link_domain(text: str) -> str | None:
    match = _URL_PATTERN.search(text)
    if not match:
        return None
    return match.group(1).lower()


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


# ---------------------------------------------------------------------------
# Основной парсер
# ---------------------------------------------------------------------------


def parse_raw_message(
    message: RawMessage,
    lookups: ParserLookups = DEFAULT_LOOKUPS,
) -> list[DLPEvent]:
    """RawMessage -> список DLPEvent (по одному на контрагента-получателя).

    Отправитель или получатель, совпадающий с employee_address, определяет
    направление; сам сотрудник как получатель (например, при массовой
    рассылке "себе и клиенту") не порождает отдельное событие.
    """
    employee_lower = message.employee_address.lower()
    is_outgoing = message.sender_address.lower() == employee_lower

    if is_outgoing:
        counterparties = [
            addr for addr in message.recipient_addresses
            if addr.lower() != employee_lower
        ]
    else:
        # входящее: единственный контрагент — отправитель
        counterparties = [message.sender_address]

    # Общие для всех получателей вычисления делаем один раз
    primary_attachment = _primary_attachment(message.attachments)
    has_attachment = primary_attachment is not None
    attachment_size = primary_attachment.resolved_size() if primary_attachment else 0
    attachment_category = (
        _attachment_category(primary_attachment.filename) if primary_attachment
        else AttachmentCategory.NONE
    )
    has_macro = any(_has_macro_or_executable(a.filename) for a in message.attachments)
    password_protected = any(_is_password_protected(a) for a in message.attachments)
    confidentiality_marker = bool(_CONFIDENTIALITY_PATTERN.search(message.text))
    link_domain = _extract_first_link_domain(message.text)
    has_link = link_domain is not None
    link_not_whitelisted = (
        (not lookups.is_link_whitelisted(link_domain)) or link_domain in _FILE_SHARING_DOMAINS
        if has_link else False
    )
    is_non_working_day = _is_non_working_day(message.sent_at)

    events: list[DLPEvent] = []
    for counterparty in counterparties:
        domain = _domain_of(counterparty)
        events.append(
            DLPEvent(
                is_incoming=not is_outgoing,
                counterparty_external=not lookups.is_internal_employee(counterparty),
                counterparty_new=not lookups.is_known_contact(counterparty),
                counterparty_address_personal=domain in _PERSONAL_EMAIL_DOMAINS,
                counterparty_domain_watchlisted=lookups.is_domain_watchlisted(domain),
                has_attachment=has_attachment,
                attachment_size_bytes=attachment_size,
                attachment_category=attachment_category,
                has_macro_or_executable_code=has_macro,
                confidentiality_marker_found=confidentiality_marker,
                attachment_password_protected=password_protected,
                has_external_link=has_link,
                link_not_whitelisted=link_not_whitelisted,
                event_time=message.sent_at,
                is_non_working_day=is_non_working_day,
                near_termination=None,   # ждёт HR-интеграции
                on_official_leave=None,  # ждёт HR-интеграции
                device_unregistered=not lookups.is_device_registered(message.employee_address),
                lacks_legitimate_access=not lookups.has_legitimate_access(
                    message.employee_address, counterparty
                ),
                has_elevated_rights=lookups.has_elevated_rights(message.employee_address),
            )
        )
    return events
