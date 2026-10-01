"""
api/schemas.py — модели запросов и ответов API (pydantic) и функции
перевода объектов сторов в эти модели.

Здесь только форма данных на границе HTTP: никакой логики и проверок
прав (они в api/deps.py и api/routes/*).
"""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

from core.contacts_store import Contact
from core.isolation_decisions_store import IsolationVerdict
from core.messages_store import Message
from core.moderation_decisions_store import ReviewerConfidence
from core.org_store import Membership, Organization
# --------- Схемы запросов/ответов ---------

# session_id не приходит от клиента: ключ памяти разговора с Мимиром =
# user_id из токена (раньше клиент мог подставить чужой session_id и
# прочитать/стереть чужой диалог).

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    reply: str


class SensorEventRequest(BaseModel):
    features: list[float]


class SensorEventResponse(BaseModel):
    source: str
    text: str
    event_class: str | None = None
    confidence: float | None = None


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=4)
    name: str = ""


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class AuthResponse(BaseModel):
    """Общий формат ответа для /auth/register и /auth/login."""

    user: dict
    token: str


class ContactIn(BaseModel):
    """Один контакт из телефонной книги клиента."""

    name: str = Field(..., min_length=1)
    phone: str | None = None
    email: str | None = None


class ContactsSyncRequest(BaseModel):
    contacts: list[ContactIn]


class ContactOut(BaseModel):
    contact_id: str
    name: str
    phone: str | None
    email: str | None
    is_mimir_user: bool
    linked_user_id: str | None


class ContactsListResponse(BaseModel):
    contacts: list[ContactOut]


class AttachmentOut(BaseModel):
    attachment_id: str
    filename: str
    size_bytes: int


class MessageOut(BaseModel):
    message_id: str
    sender_id: str
    recipient_ids: list[str]
    text: str
    attachments: list[AttachmentOut]
    sent_at: float
    device_id: str | None = None


class MessagesListResponse(BaseModel):
    messages: list[MessageOut]
    # Курсор следующей (более старой) страницы: передать как ?before=...
    # None — старее сообщений нет.
    next_before: str | None = None


class ConversationOut(BaseModel):
    conversation_key: str
    participant_ids: list[str]
    last_message_id: str
    last_sender_id: str
    last_text_preview: str
    last_sent_at: float
    last_has_attachments: bool
    message_count: int


class ConversationsListResponse(BaseModel):
    conversations: list[ConversationOut]
    next_before: str | None = None


class UserPublicOut(BaseModel):
    user_id: str
    email: str
    name: str


class UsersListResponse(BaseModel):
    users: list[UserPublicOut]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class MessagePendingModerationOut(BaseModel):
    """Ответ на /messages/send, когда исходящая эвристика вернула THREAT
    хотя бы для одного события — сообщение НЕ доставлено, удержано в
    core/moderation_store.py до решения человека."""

    status: str = "pending_moderation"
    hold_id: str
    threat_reasons: list[str]


class PendingModerationOut(BaseModel):
    hold_id: str
    message: MessageOut
    threat_reasons: list[str]
    held_at: float


class ModerationQueueResponse(BaseModel):
    pending: list[PendingModerationOut]


class ModerationDecisionRequest(BaseModel):
    """Необязательное тело approve/reject. Без тела (как раньше) —
    reviewer_confidence = None. Самооценка проверяющего, не оценка
    человека машиной (MIMIR_reviewer_consistency.md)."""

    reviewer_confidence: ReviewerConfidence | None = None


class ModerationResolveResponse(BaseModel):
    status: str
    message: MessageOut
    decision_id: str


class ModerationDecisionOut(BaseModel):
    decision_id: str
    hold_id: str
    message_id: str
    sender_id: str
    org_id: str | None
    decided_by: str
    decision: str
    reviewer_confidence: str | None
    threat_reasons: list[str]
    held_at: float
    decided_at: float


class ModerationDecisionsListResponse(BaseModel):
    decisions: list[ModerationDecisionOut]


class AnomalySubjectSummary(BaseModel):
    """Сводка по одному отправителю — агрегация вместо карточки на
    каждое событие, в отличие от THREAT-модерации по одной карточке."""

    user_id: str
    email: str
    name: str
    count: int
    reason_counts: dict[str, int]
    last_recorded_at: float


class AnomalySummaryResponse(BaseModel):
    summary: list[AnomalySubjectSummary]


class IsolatedUserOut(BaseModel):
    """Один изолированный пользователь — с резолвнутым email/именем,
    тем же паттерном, что и AnomalySubjectSummary выше."""

    user_id: str
    email: str
    name: str
    threat_reasons: list[str]
    isolated_at: float


class IsolatedListResponse(BaseModel):
    isolated: list[IsolatedUserOut]


class LiftIsolationResponse(BaseModel):
    status: str = "lifted"
    user_id: str
    decision_id: str


class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=1)


class OrgOut(BaseModel):
    org_id: str
    name: str
    created_by: str


class MembershipOut(BaseModel):
    membership_id: str
    user_id: str
    org_id: str
    role: str
    status: str
    requested_at: float
    decided_by: str | None
    decided_at: float | None


class MembershipsListResponse(BaseModel):
    memberships: list[MembershipOut]


class AddDomainRequest(BaseModel):
    domain: str = Field(..., min_length=1)
    reason: str = ""


class WatchlistDomainOut(BaseModel):
    entry_id: str
    org_id: str
    domain: str
    reason: str
    added_by: str
    added_at: float


class WatchlistListResponse(BaseModel):
    domains: list[WatchlistDomainOut]


class WhitelistDomainOut(BaseModel):
    entry_id: str
    org_id: str
    domain: str
    reason: str
    added_by: str
    added_at: float


class WhitelistListResponse(BaseModel):
    domains: list[WhitelistDomainOut]


class RegisterDeviceRequest(BaseModel):
    device_id: str = Field(..., min_length=1)
    user_id: str = Field(..., min_length=1)
    label: str = ""


class DeviceOut(BaseModel):
    entry_id: str
    org_id: str
    device_id: str
    user_id: str
    label: str
    registered_by: str
    registered_at: float


class DevicesListResponse(BaseModel):
    devices: list[DeviceOut]


class GrantAccessRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    note: str = ""


class AccessGrantOut(BaseModel):
    entry_id: str
    org_id: str
    user_id: str
    granted_by: str
    note: str
    granted_at: float


class AccessGrantsListResponse(BaseModel):
    grants: list[AccessGrantOut]


# --------- Снятие изоляции с вердиктом (миграция 002) ---------

class LiftIsolationRequest(BaseModel):
    """Вердикт обязателен: это метка датасета для входящих событий.
    reviewer_confidence — необязательна, та же шкала, что при модерации."""
    verdict: IsolationVerdict
    reviewer_confidence: ReviewerConfidence | None = None


class IsolationDecisionOut(BaseModel):
    decision_id: str
    isolation_id: str
    user_id: str
    org_id: str
    decided_by: str
    verdict: str
    reviewer_confidence: str | None
    threat_reasons: list[str]
    isolated_at: float
    decided_at: float


class IsolationDecisionsListResponse(BaseModel):
    decisions: list[IsolationDecisionOut]


# --------- Роли: officer'ы и заместитель владельца ---------

class UserRefRequest(BaseModel):
    user_id: str


class DeputyOut(BaseModel):
    org_id: str
    user_id: str | None


def contact_to_out(contact: Contact) -> ContactOut:
    return ContactOut(**contact.to_public_dict())


def message_to_out(message: Message) -> MessageOut:
    return MessageOut(**message.to_public_dict())


def org_to_out(org: Organization) -> OrgOut:
    return OrgOut(**org.to_public_dict())


def membership_to_out(membership: Membership) -> MembershipOut:
    return MembershipOut(**membership.to_public_dict())