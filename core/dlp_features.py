"""
core/dlp_features.py — кодировщик "сырое DLP-событие" -> вектор признаков
для EventClassifier.

Реализует схему из mimir_dlp_features_encoding_v1.md (блоки 1, 2, 3, 5, 6).
Итоговый вектор — 24 числа, порядок клеток зафиксирован в FEATURE_ORDER.

Признаки блока 3, зависящие от HR-интеграции (near_termination,
on_official_leave), принимают bool | None: None означает "HR-интеграция
недоступна" и кодируется нейтральным нулём — так же, как False.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class AttachmentCategory(str, Enum):
    NONE = "none"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    IMAGE = "image"
    EXECUTABLE = "executable"


@dataclass
class DLPEvent:
    """Сырые факты о событии — то, что бэкенд знает о письме/сообщении
    ДО перевода в числовой вектор.
    """

    # --- Блок 1: участники события ---
    is_incoming: bool
    counterparty_external: bool
    counterparty_new: bool
    counterparty_address_personal: bool
    counterparty_domain_watchlisted: bool

    # --- Блок 2: содержимое / вложение ---
    has_attachment: bool = False
    attachment_size_bytes: int = 0
    attachment_category: AttachmentCategory = AttachmentCategory.NONE
    has_macro_or_executable_code: bool = False
    confidentiality_marker_found: bool = False
    attachment_password_protected: bool = False
    has_external_link: bool = False
    link_not_whitelisted: bool = False

    # --- Блок 3: временной контекст ---
    event_time: datetime = field(default_factory=datetime.now)
    is_non_working_day: bool = False
    near_termination: bool | None = None   # None = HR-интеграция недоступна
    on_official_leave: bool | None = None  # None = HR-интеграция недоступна

    # --- Блок 5: контекст устройства ---
    device_unregistered: bool = False

    # --- Блок 6: роль и права доступа ---
    lacks_legitimate_access: bool = False
    has_elevated_rights: bool = False


# Потолок логарифмической нормализации размера вложения. Всё крупнее —
# схлопывается к 1.0 (для DLP важен сам факт "необычно большой файл",
# а не точная величина сверх этого порога).
_ATTACHMENT_SIZE_CAP_BYTES = 50 * 1024 * 1024  # 50 МБ


def _normalize_size_log(size_bytes: int) -> float:
    """Логарифмическая нормализация размера вложения -> [0, 1].

    log1p(size) вместо log(size), чтобы 0 байт не давал -inf.
    """
    if size_bytes <= 0:
        return 0.0
    capped = min(size_bytes, _ATTACHMENT_SIZE_CAP_BYTES)
    return math.log1p(capped) / math.log1p(_ATTACHMENT_SIZE_CAP_BYTES)


def _cyclical_time_of_day(event_time: datetime) -> tuple[float, float]:
    """Время суток -> (sin, cos) координаты точки на окружности.

    Убирает ложный "разрыв" между 23:59 и 00:01: в обычных числах это
    противоположные полюса, а по смыслу — соседние моменты.
    """
    minutes = event_time.hour * 60 + event_time.minute
    angle = 2 * math.pi * (minutes / 1440)  # 1440 минут в сутках
    return math.sin(angle), math.cos(angle)


def _one_hot_category(category: AttachmentCategory) -> tuple[float, float, float, float]:
    """document / archive / image / executable -> one-hot, 4 клетки.

    NONE (вложения нет) -> все нули; признак "наличие вложения"
    уже сообщает об этом модели отдельно.
    """
    order = (
        AttachmentCategory.DOCUMENT,
        AttachmentCategory.ARCHIVE,
        AttachmentCategory.IMAGE,
        AttachmentCategory.EXECUTABLE,
    )
    values = tuple(1.0 if category == c else 0.0 for c in order)
    return values  # type: ignore[return-value]


# Порядок клеток итогового вектора — фиксирован. Менять только синхронно
# с EventClassifier.input_dim и mimir_dlp_features_encoding_v1.md.
FEATURE_ORDER: tuple[str, ...] = (
    # Блок 1 (5)
    "direction",
    "counterparty_internal_external",
    "counterparty_known_new",
    "address_type",
    "domain_watchlisted",
    # Блок 2 (11)
    "has_attachment",
    "attachment_size_norm",
    "category_document",
    "category_archive",
    "category_image",
    "category_executable",
    "has_macro_or_executable_code",
    "confidentiality_marker",
    "attachment_password_protected",
    "has_external_link",
    "link_not_whitelisted",
    # Блок 3 (5)
    "time_of_day_sin",
    "time_of_day_cos",
    "is_non_working_day",
    "near_termination",
    "on_official_leave",
    # Блок 5 (1)
    "device_unregistered",
    # Блок 6 (2)
    "lacks_legitimate_access",
    "has_elevated_rights",
)

assert len(FEATURE_ORDER) == 24


def encode_event(event: DLPEvent) -> list[float]:
    """Сырое DLP-событие -> вектор из 24 чисел для EventClassifier.classify().

    Порядок клеток соответствует FEATURE_ORDER и
    mimir_dlp_features_encoding_v1.md.
    """
    size_norm = _normalize_size_log(event.attachment_size_bytes) if event.has_attachment else 0.0
    category = event.attachment_category if event.has_attachment else AttachmentCategory.NONE
    cat_document, cat_archive, cat_image, cat_executable = _one_hot_category(category)
    time_sin, time_cos = _cyclical_time_of_day(event.event_time)
    link_flag = event.link_not_whitelisted if event.has_external_link else False

    vector = [
        # Блок 1
        1.0 if event.is_incoming else 0.0,
        1.0 if event.counterparty_external else 0.0,
        1.0 if event.counterparty_new else 0.0,
        1.0 if event.counterparty_address_personal else 0.0,
        1.0 if event.counterparty_domain_watchlisted else 0.0,
        # Блок 2
        1.0 if event.has_attachment else 0.0,
        size_norm,
        cat_document,
        cat_archive,
        cat_image,
        cat_executable,
        1.0 if event.has_macro_or_executable_code else 0.0,
        1.0 if event.confidentiality_marker_found else 0.0,
        1.0 if event.attachment_password_protected else 0.0,
        1.0 if event.has_external_link else 0.0,
        1.0 if link_flag else 0.0,
        # Блок 3
        time_sin,
        time_cos,
        1.0 if event.is_non_working_day else 0.0,
        1.0 if event.near_termination else 0.0,   # None -> 0.0 (неактивен)
        1.0 if event.on_official_leave else 0.0,  # None -> 0.0 (неактивен)
        # Блок 5
        1.0 if event.device_unregistered else 0.0,
        # Блок 6
        1.0 if event.lacks_legitimate_access else 0.0,
        1.0 if event.has_elevated_rights else 0.0,
    ]

    assert len(vector) == len(FEATURE_ORDER)
    return vector
