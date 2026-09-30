"""
api/server.py — FastAPI сервер, единая точка входа для всех приложений
(веб-панель, мобильное, Telegram и т.д. через sdk/mimir.js или прямой HTTP).

Запуск:
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from core import db
from core.mimir import Mimir
from core.config import get_settings
from core.auth_store import AuthError, AuthStore, User
from core.contacts_store import Contact, ContactsError, ContactsStore
from core.messages_store import Message, MessagesError, MessageStatus, MessagesStore
from core.org_store import Membership, Organization, OrgError, OrgStore
from core.message_bridge import check_incoming, check_outgoing
from core.dlp_events_store import DLPEventsStore
from core.dlp_heuristics import ThreatLevel, classify
from core.moderation_store import ModerationError, ModerationStore
from core.moderation_decisions_store import (
    Decision, ModerationDecision, ModerationDecisionsStore, ReviewerConfidence,
)
from core.isolation_store import IsolationError, IsolationStore
from core.watchlist_store import WatchlistError, WatchlistStore
from core.access_store import AccessError, AccessStore
from core.message_parser import is_audio_attachment, contains_link

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mimir.api")

settings = get_settings()

# [РЕШЕНИЕ 10] Как часто фоновая задача стирает содержимое отклонённых
# сообщений (сам срок хранения — сутки — в messages_store).
PURGE_INTERVAL_SECONDS = int(os.getenv("PURGE_INTERVAL_SECONDS", "3600"))


async def _purge_rejected_loop() -> None:
    """Раз в PURGE_INTERVAL_SECONDS стирает текст и вложения сообщений,
    отклонённых модерацией больше суток назад. Синхронный запрос к БД
    выполняется в отдельном потоке, чтобы не блокировать event loop.
    Сбой одной итерации логируется и не останавливает цикл."""
    while True:
        try:
            await asyncio.to_thread(messages_store.purge_rejected_content)
        except Exception:
            logger.exception("Фоновое стирание отклонённых сообщений не удалось")
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    purge_task = asyncio.create_task(_purge_rejected_loop())
    try:
        yield
    finally:
        purge_task.cancel()
        db.close_pool()


app = FastAPI(title="Mimir API", version="0.1.0", lifespan=lifespan)

# CORS: разрешаем доступ SDK из браузерных приложений.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # сузить до конкретных доменов в проде
    allow_methods=["*"],
    allow_headers=["*"],
)

mimir = Mimir(settings=settings)
auth_store = AuthStore()
contacts_store = ContactsStore(auth_store)
messages_store = MessagesStore()
org_store = OrgStore()
dlp_events_store = DLPEventsStore()
moderation_store = ModerationStore(messages_store)
moderation_decisions_store = ModerationDecisionsStore()
isolation_store = IsolationStore()
watchlist_store = WatchlistStore()
access_store = AccessStore()


def get_current_user(authorization: str | None = Header(default=None)) -> User:
    """Достаёт пользователя по заголовку Authorization: Bearer <token>."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Не передан токен авторизации")

    token = authorization.removeprefix("Bearer ").strip()
    user = auth_store.user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Недействительный токен")
    return user


# --------- Схемы запросов/ответов ---------

# session_id больше НЕ приходит от клиента (см. обсуждение в чате,
# 2026-09-29): раньше клиент сам выбирал ключ памяти разговора и мог
# подставить чужой — прочитать/стереть чужой диалог с Мимиром. Теперь
# ключ памяти = user_id из токена (см. эндпоинты /chat, /sensor-event,
# /session/reset и /ws/chat ниже).

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


class MessagePendingModerationOut(BaseModel):
    """Ответ на /messages/send, когда исходящая эвристика вернула THREAT
    хотя бы для одного события — сообщение НЕ доставлено, удержано в
    core/moderation_store.py до решения человека (см. обсуждение в чате,
    пункт 2)."""

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
    каждое событие (см. обсуждение в чате: вариант 2 для ANOMALY,
    в отличие от THREAT-модерации по одной карточке)."""

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


# --------- REST эндпоинты ---------

@app.get("/health")
async def health():
    return {"status": "ok", "model": settings.claude.model}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, current_user: User = Depends(get_current_user)):
    try:
        reply = await mimir.chat(current_user.user_id, req.message)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ошибка в /chat")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return ChatResponse(reply=reply)


@app.post("/sensor-event", response_model=SensorEventResponse)
async def sensor_event(req: SensorEventRequest, current_user: User = Depends(get_current_user)):
    try:
        result = await mimir.handle_sensor_event(current_user.user_id, req.features)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ошибка в /sensor-event")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return SensorEventResponse(
        source=result.source,
        text=result.text,
        event_class=result.event_class.value if result.event_class else None,
        confidence=result.confidence,
    )


@app.post("/session/reset")
async def reset_session(current_user: User = Depends(get_current_user)):
    """Очищает память разговора с Мимиром ТЕКУЩЕГО пользователя — чужую
    сессию сбросить больше нельзя (раньше session_id был в пути запроса)."""
    mimir.reset_session(current_user.user_id)
    return {"status": "reset"}


# --------- Авторизация (заглушка: данные в памяти процесса) ---------

@app.post("/auth/register", response_model=AuthResponse)
async def register(req: RegisterRequest):
    try:
        user = auth_store.register(req.email, req.password, req.name)
        # Автологин сразу после регистрации — удобно для проверки фронта.
        _, token = auth_store.login(req.email, req.password)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AuthResponse(user=user.to_public_dict(), token=token)


@app.post("/auth/login", response_model=AuthResponse)
async def login(req: LoginRequest):
    try:
        user, token = auth_store.login(req.email, req.password)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return AuthResponse(user=user.to_public_dict(), token=token)


@app.post("/auth/logout")
async def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        auth_store.logout(authorization.removeprefix("Bearer ").strip())
    return {"status": "logged_out"}


@app.get("/auth/me")
async def me(current_user: User = Depends(get_current_user)):
    return current_user.to_public_dict()


# --------- Контакты (заглушка: данные в памяти процесса) ---------

def _contact_to_out(contact: Contact) -> ContactOut:
    return ContactOut(**contact.to_public_dict())


@app.post("/contacts/sync", response_model=ContactsListResponse)
async def sync_contacts(
    req: ContactsSyncRequest, current_user: User = Depends(get_current_user)
):
    """Принимает список контактов из телефонной книги клиента, полностью
    заменяет ими контакты текущего пользователя и отмечает, кто из них
    уже зарегистрирован в Мимире (по email)."""
    raw = [c.model_dump() for c in req.contacts]
    contacts = contacts_store.sync_contacts(current_user.user_id, raw)
    return ContactsListResponse(contacts=[_contact_to_out(c) for c in contacts])


@app.get("/contacts", response_model=ContactsListResponse)
async def list_contacts(current_user: User = Depends(get_current_user)):
    contacts = contacts_store.list_contacts(current_user.user_id)
    return ContactsListResponse(contacts=[_contact_to_out(c) for c in contacts])


@app.delete("/contacts/{contact_id}")
async def delete_contact(contact_id: str, current_user: User = Depends(get_current_user)):
    try:
        contacts_store.remove_contact(current_user.user_id, contact_id)
    except ContactsError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "deleted", "contact_id": contact_id}


# --------- Сообщения (транспортный слой / слой 1) ---------
#
# Хранение и доставка — messages_store.send_message() сам по себе ничего
# не знает о DLP (mimir_architecture_v2.md §4). После успешной отправки
# эндпоинт (не сам messages_store!) вызывает core/message_bridge.py —
# единственный модуль, которому разрешено видеть транспорт, auth и org
# одновременно — классифицирует каждое событие через core/dlp_heuristics.py
# и сохраняет результат через core/dlp_events_store.py. Сбой моста
# (BridgeError) логируется, но не должен ронять уже состоявшуюся отправку
# сообщения — см. обсуждение в чате.
#
# THREAT для ИСХОДЯЩЕЙ проверки (утечка от сотрудника) — сообщение не
# доставляется сразу, но и не отбрасывается: удерживается в
# core/moderation_store.py до решения человека (см. обсуждение в чате,
# пункт 2 — не автономная блокировка без пути назад, и не молчаливая
# пометка постфактум).
#
# THREAT для ВХОДЯЩЕЙ проверки (фишинг) — закрывает открытый вопрос 1
# (см. обсуждение в чате). Держать/блокировать каждое такое сообщение до
# решения человека не масштабируется: входящий THREAT завязан на действие
# АТАКУЮЩЕГО, не сотрудника — одна фишинговая рассылка может одновременно
# задеть сотни получателей, в отличие от исходящего THREAT, который по
# конструкции редкий. Поэтому сообщение доставляется как раньше
# (fail-open, без изменений) — но ПОЛУЧАТЕЛЬ автоматически изолируется
# через core/isolation_store.py, если он org-linked (для personal-
# аккаунтов автоизоляция не применяется вообще — снять было бы некому).
# Изолированный аккаунт не может сам отправлять коллегам файлы (кроме
# аудио) и ссылки — см. проверку в начале send_message() ниже — пока
# security_officer не снимет изоляцию через /moderation/isolated/{id}/lift.
# Изоляция также закрывает доступ к данным организации (см.
# _require_not_isolated) — на сегодня единственный такой ресурс в проекте
# — GET /orgs/{org_id}/pending.
#

# РОЛИ (MIMIR_development_plan.md недели 5-6, закрывает открытый вопрос
# из обсуждения в чате): /moderation/* доступны только security_officer
# ОРГАНИЗАЦИИ ОТПРАВИТЕЛЯ удержанного сообщения — та же роль
# (org_store.MembershipRole.SECURITY_OFFICER), что уже решает заявки на
# членство в /orgs/memberships/*, отдельной DLP-роли сознательно нет
# (см. обсуждение в чате). Hold без организации у отправителя не бывает:
# check_outgoing() возвращает None ещё до всякой классификации для
# personal-аккаунтов (org_store.is_dlp_active() == False) — см.
# _require_moderation_access() ниже.
#
# /messages/send принимает multipart/form-data, а не JSON — вложения
# идут как настоящие файлы (UploadFile), без base64-раздувания.
# recipient_ids передаётся как повторяющееся form-поле:
#   recipient_ids=u2&recipient_ids=u3 (или несколько частей формы с
#   одним и тем же именем при отправке через FormData на фронте).

def _message_to_out(message: Message) -> MessageOut:
    return MessageOut(**message.to_public_dict())


def _require_not_isolated(current_user: User) -> None:
    """Изолированный аккаунт теряет доступ не только к отправке файлов/
    ссылок (см. проверку в send_message() ниже), но и к данным
    организации — см. обсуждение в чате. Ресурсы уровня организации,
    гейтящиеся этим способом (обновлено 2026-09-16, список рос по мере
    появления org-данных): GET /orgs/{org_id}/pending (заявки на
    членство), watchlist/link-whitelist доменов и устройства/роли доступа
    (см. _require_security_officer ниже — она сама вызывает эту функцию
    первым делом). Личные данные (contacts_store.py/messages_store.py/
    memory.py) по-прежнему не org-scoped и сюда не входят."""
    if isolation_store.is_isolated(current_user.user_id):
        raise HTTPException(
            status_code=403,
            detail=(
                "Аккаунт изолирован — доступ к данным организации ограничен, "
                "пока security_officer не снимет изоляцию"
            ),
        )


def _require_officer_for_user(target_user_id: str, current_user: User) -> None:
    """Общая проверка прав: current_user должен быть security_officer
    организации, где target_user_id состоит (approved membership), И САМ
    НЕ ИЗОЛИРОВАН (см. обсуждение в чате: изоляция закрывает доступ ко
    ВСЕМУ в организации, включая собственные officer-права — иначе
    скомпрометированный officer снимает изоляцию сам с себя одним вызовом
    API, и весь механизм бессмысленен). Используется и для модерации
    исходящих holds (target = отправитель), и для снятия изоляции
    (target = изолированный получатель) — в обоих случаях право
    разбирать принадлежит НЕ-изолированному officer'у той же организации.

    Если изолированный — единственный officer организации, снять с него
    изоляцию через API не сможет никто — известный временный долг пилота
    (см. MIMIR_development_plan.md: полноценных ролей владелец/сотрудники/
    разработчик ещё нет), не решается в рамках этой сессии."""
    if isolation_store.is_isolated(current_user.user_id):
        raise HTTPException(
            status_code=403,
            detail=(
                "Аккаунт изолирован — officer-права недоступны, пока другой "
                "security_officer этой организации не снимет изоляцию"
            ),
        )
    membership = org_store.get_active_membership(target_user_id)
    if membership is None or not org_store.is_security_officer(
        current_user.user_id, membership.org_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Только security_officer организации этого пользователя может это сделать",
        )


def _require_moderation_access(org_id: str, current_user: User) -> None:
    """Право модерировать hold принадлежит НЕ изолированному
    security_officer организации из hold.org_id — снимка организации
    отправителя на момент поступления сообщения ([РЕШЕНИЕ 7],
    mimir_db_migration_contract.md), а не его текущего членства: если
    отправителя исключили или перевели, пока сообщение ждёт решения,
    разбирает всё равно officer той организации."""
    if isolation_store.is_isolated(current_user.user_id):
        raise HTTPException(
            status_code=403,
            detail=(
                "Аккаунт изолирован — officer-права недоступны, пока другой "
                "security_officer этой организации не снимет изоляцию"
            ),
        )
    if not org_store.is_security_officer(current_user.user_id, org_id):
        raise HTTPException(
            status_code=403,
            detail="Только security_officer организации отправителя может это сделать",
        )


def _officer_org_ids(current_user: User) -> list[str]:
    """Организации, где current_user — security_officer. Сейчас у
    пользователя не больше одного активного членства (инвариант БД
    memberships_one_active_per_user), поэтому список из 0 или 1 элемента."""
    membership = org_store.get_active_membership(current_user.user_id)
    if membership is None or not org_store.is_security_officer(
        current_user.user_id, membership.org_id
    ):
        return []
    return [membership.org_id]


@app.post("/messages/send", response_model=MessageOut | MessagePendingModerationOut)
async def send_message(
    recipient_ids: list[str] = Form(...),
    text: str = Form(""),
    files: list[UploadFile] = File(default=[]),
    device_id: str | None = Form(default=None),
    current_user: User = Depends(get_current_user),
):
    attachments = [
        {"filename": f.filename, "content": await f.read()}
        for f in files
    ]

    # Изоляция (core/isolation_store.py, см. обсуждение в чате, закрывает
    # открытый вопрос 1): изолированный аккаунт не может сам отправлять
    # файлы (кроме аудио) и ссылки — только текст/голос — пока
    # security_officer не снимет изоляцию. Проверяется ДО build_message:
    # нет смысла строить сообщение, которое всё равно будет отклонено.
    if isolation_store.is_isolated(current_user.user_id):
        disallowed_files = [
            a["filename"] for a in attachments if not is_audio_attachment(a["filename"])
        ]
        if disallowed_files:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Аккаунт изолирован после получения сообщения с признаками угрозы — "
                    "отправлять файлы (кроме аудио) нельзя, пока security_officer не "
                    f"снимет изоляцию: {', '.join(disallowed_files)}"
                ),
            )
        if contains_link(text):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Аккаунт изолирован после получения сообщения с признаками угрозы — "
                    "отправка ссылок недоступна, пока security_officer не снимет изоляцию"
                ),
            )

    # Всё, что ниже пишет в БД — сообщение, DLP-события, удержание,
    # изоляция получателя — одна транзакция: либо записано всё, либо
    # ничего (раньше падение процесса посередине оставляло, например,
    # DLP-события без сообщения). HTTPException внутри блока откатывает
    # транзакцию.
    with db.transaction():
        return _send_message_tx(current_user, recipient_ids, text, attachments, device_id)


def _threat_decision(classifications: list) -> tuple[bool, list[str]]:
    """Есть ли среди классификаций угроза и чем её объяснить.

    Решение принимается по ВЕРДИКТУ (level == THREAT), а не по наличию
    threat_reasons. У classify() два пути к THREAT (core/dlp_heuristics.py):
    - прямой: сработало самодостаточное THREAT-правило -> причины в
      threat_reasons;
    - эскалация: сошлись слабые сигналы (2+ ANOMALY-правила или одно при
      повышенных правах) -> уровень THREAT, но threat_reasons ПУСТОЙ,
      причины лежат в anomaly_reasons.
    Раньше решение принималось по непустому threat_reasons, и THREAT,
    полученный эскалацией, проходил без удержания/изоляции — и при этом
    не попадал ни в очередь модерации, ни в ANOMALY-сводку (там только
    level == anomaly), то есть был не виден человеку вообще.

    Причины для человека берутся из той графы, которая привела к вердикту:
    threat_reasons, если они есть, иначе anomaly_reasons — чтобы карточка
    удержания/изоляции не была пустой. Дубли (одинаковые причины от
    нескольких получателей) убираются, порядок сохраняется.
    """
    threat_results = [r for r in classifications if r.level == ThreatLevel.THREAT]
    reasons = [
        reason
        for r in threat_results
        for reason in (r.threat_reasons or r.anomaly_reasons)
    ]
    return bool(threat_results), list(dict.fromkeys(reasons))


def _send_message_tx(
    current_user: User,
    recipient_ids: list[str],
    text: str,
    attachments: list[dict],
    device_id: str | None,
) -> MessageOut | MessagePendingModerationOut:
    """Тело /messages/send внутри транзакции (см. send_message выше)."""
    try:
        message = messages_store.build_message(
            sender_id=current_user.user_id,
            recipient_ids=recipient_ids,
            text=text,
            attachments=attachments,
            device_id=device_id,
        )
    except MessagesError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # (check, classifications) пары — classify() вызывается здесь, снаружи
    # dlp_events_store.py (стор ничего не решает и не вычисляет сам).
    dlp_checks: list[tuple] = []

    # Исходящая — fail-closed на СБОЕ проверки (ядро продукта, утечка от
    # сотрудника): если проверка не отработала, сообщение НЕ сохраняется и
    # не доставляется вообще никому. check_outgoing() сама возвращает None
    # для личных/standalone аккаунтов — для них этот блок не бросает и не
    # блокирует.
    try:
        outgoing_check = check_outgoing(
            message, org_store, auth_store, contacts_store, watchlist_store, access_store
        )
    except Exception:
        logger.exception(
            "Исходящая DLP-проверка сообщения %s провалилась — сообщение "
            "НЕ сохранено и не доставлено (fail-closed)", message.message_id,
        )
        raise HTTPException(
            status_code=503,
            detail="Проверка сообщения временно недоступна, попробуйте ещё раз",
        )

    if outgoing_check is not None:
        outgoing_classifications = [classify(event) for event in outgoing_check.events]
        # Событие/классификацию сохраняем В ЛЮБОМ СЛУЧАЕ, даже если ниже
        # сообщение уйдёт на модерацию — это данные для будущего датасета
        # (неделя 7). Сообщения в БД ещё нет — FOREIGN KEY событий на
        # messages отложен до конца транзакции (DEFERRABLE).
        dlp_events_store.add_check(message.message_id, outgoing_check, outgoing_classifications)

        is_threat, threat_reasons = _threat_decision(outgoing_classifications)
        if is_threat:
            # THREAT на исходящем -> сообщение сохраняется со статусом
            # pending_moderation (невидимо никому) и удерживается до
            # решения officer'а. org_id — снимок организации отправителя
            # на этот момент ([РЕШЕНИЕ 7]); check_outgoing() не вернул бы
            # проверку без активного членства, поэтому оно здесь есть.
            sender_membership = org_store.get_active_membership(message.sender_id)
            if sender_membership is None:
                raise HTTPException(
                    status_code=503,
                    detail="Проверка сообщения временно недоступна, попробуйте ещё раз",
                )
            messages_store.store(message, status=MessageStatus.PENDING_MODERATION)
            pending = moderation_store.hold(message, threat_reasons, sender_membership.org_id)
            return MessagePendingModerationOut(
                hold_id=pending.hold_id, threat_reasons=threat_reasons,
            )

    # Входящая — fail-open на СБОЕ проверки: если проверка не отработала,
    # сообщение всё равно доставляется как обычно. Вложенная транзакция
    # (SAVEPOINT): ошибка БД внутри проверки откатывает только её, а не
    # всю отправку — иначе транзакция осталась бы в сломанном состоянии.
    try:
        with db.transaction():
            incoming_checks = check_incoming(
                message, auth_store, org_store, contacts_store, watchlist_store, access_store
            )
    except Exception:
        incoming_checks = []
        logger.exception(
            "Входящая DLP-проверка сообщения %s провалилась — сообщение "
            "всё равно будет доставлено (fail-open)", message.message_id,
        )
    for check in incoming_checks:
        classifications = [classify(event) for event in check.events]
        dlp_checks.append((check, classifications))

        # Автоизоляция получателя: входящий THREAT сообщение НЕ блокирует
        # (fail-open), но получателя изолирует — если он org-linked. Для
        # personal-аккаунтов изоляция не применяется — снять её было бы
        # некому, у personal нет security_officer.
        is_threat, threat_reasons = _threat_decision(classifications)
        if is_threat and org_store.get_active_membership(check.subject_user_id) is not None:
            isolation_store.isolate(check.subject_user_id, threat_reasons)

    messages_store.store(message)
    for check, classifications in dlp_checks:
        dlp_events_store.add_check(message.message_id, check, classifications)

    return _message_to_out(message)


@app.get("/moderation/pending", response_model=ModerationQueueResponse)
async def moderation_pending(current_user: User = Depends(get_current_user)):
    """Очередь сообщений, удержанных из-за THREAT на исходящей проверке.
    Разбор ЕДИНИЧНЫЙ по карточкам (в отличие от ANOMALY-сводки — см.
    обсуждение в чате, пункт про масштаб на 1000 сотрудников): THREAT
    рассчитан на редкие самодостаточные сигналы, каждый требует решения
    человека по отдельности, не пачкой."""
    _require_not_isolated(current_user)
    # Видна только очередь ТЕХ организаций, где current_user —
    # security_officer (см. _require_moderation_access) — не глобальная
    # очередь всей системы вне зависимости от того, кто спрашивает.
    # Фильтр — по hold.org_id (снимок, [РЕШЕНИЕ 7]), не по текущему
    # членству отправителя.
    pending = moderation_store.list_pending(org_ids=_officer_org_ids(current_user))
    return ModerationQueueResponse(
        pending=[
            PendingModerationOut(
                hold_id=p.hold_id,
                message=_message_to_out(p.message),
                threat_reasons=p.threat_reasons,
                held_at=p.held_at,
            )
            for p in pending
        ]
    )


def _resolve_hold(
    hold_id: str,
    decision: Decision,
    req: ModerationDecisionRequest | None,
    current_user: User,
) -> tuple[Message, ModerationDecision]:
    """Общая часть approve/reject — одна транзакция: проверка прав ->
    закрытие удержания -> смена статуса сообщения -> запись решения в
    журнал (core/moderation_decisions_store.py). Упало любое звено —
    откатывается всё, удержание остаётся открытым.

    resolve() — UPDATE ... WHERE resolved_at IS NULL: второй officer,
    нажавший одновременно, дождётся блокировки строки, получит 0 строк
    -> 404 и второе решение не запишет.

    org_id решения — из удержания (снимок, [РЕШЕНИЕ 7]), не из текущего
    членства отправителя, поэтому всегда заполнен."""
    with db.transaction():
        try:
            pending = moderation_store.get(hold_id)  # сперва право, потом resolve
        except ModerationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        _require_moderation_access(pending.org_id, current_user)
        try:
            message = moderation_store.resolve(hold_id)
        except ModerationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        if decision == Decision.APPROVED:
            messages_store.mark_delivered(message.message_id)  # теперь видно получателю
        else:
            messages_store.mark_rejected(message.message_id)   # невидимо; стирание через сутки

        entry = moderation_decisions_store.record(
            hold_id=pending.hold_id,
            message_id=message.message_id,
            sender_id=message.sender_id,
            org_id=pending.org_id,
            decided_by=current_user.user_id,
            decision=decision,
            reviewer_confidence=req.reviewer_confidence if req else None,
            threat_reasons=pending.threat_reasons,
            held_at=pending.held_at,
        )
    return message, entry


@app.post("/moderation/{hold_id}/approve", response_model=ModerationResolveResponse)
async def moderation_approve(
    hold_id: str,
    req: ModerationDecisionRequest | None = None,
    current_user: User = Depends(get_current_user),
):
    """Человек подтвердил, что сообщение можно доставить (ложное
    срабатывание эвристики) — удержание закрывается, решение пишется в
    журнал, статус сообщения становится delivered — оно видно получателю."""
    message, entry = _resolve_hold(hold_id, Decision.APPROVED, req, current_user)
    return ModerationResolveResponse(
        status="approved", message=_message_to_out(message), decision_id=entry.decision_id,
    )


@app.post("/moderation/{hold_id}/reject", response_model=ModerationResolveResponse)
async def moderation_reject(
    hold_id: str,
    req: ModerationDecisionRequest | None = None,
    current_user: User = Depends(get_current_user),
):
    """Человек подтвердил угрозу — удержание закрывается, решение пишется
    в журнал, статус сообщения становится rejected: получатель его не
    увидит никогда, содержимое стирается через сутки ([РЕШЕНИЕ 10]),
    метаданные и решение остаются."""
    message, entry = _resolve_hold(hold_id, Decision.REJECTED, req, current_user)
    return ModerationResolveResponse(
        status="rejected", message=_message_to_out(message), decision_id=entry.decision_id,
    )


@app.get("/moderation/decisions", response_model=ModerationDecisionsListResponse)
async def moderation_decisions(current_user: User = Depends(get_current_user)):
    """Журнал решений по удержаниям — только по организациям, где
    current_user — security_officer (тот же принцип, что
    /moderation/pending). Новые первыми. Только чтение: решение не
    редактируется и не удаляется через API."""
    _require_not_isolated(current_user)
    visible = moderation_decisions_store.list_all(org_ids=_officer_org_ids(current_user))
    return ModerationDecisionsListResponse(
        decisions=[ModerationDecisionOut(**d.to_public_dict()) for d in visible]
    )


@app.get("/moderation/anomaly-summary", response_model=AnomalySummaryResponse)
async def anomaly_summary(current_user: User = Depends(get_current_user)):
    """Агрегированная сводка по ANOMALY-событиям, сгруппированная по
    отправителю (см. обсуждение в чате: решение — вариант 2, сводка
    вместо карточки на каждое событие; при 1000 сотрудниках одиночные
    ANOMALY идут пачкой, не по одной записи, в отличие от THREAT).

    Это ТОЛЬКО группировка при чтении поверх уже сохранённых
    core/dlp_events_store.DLPEventRecord — отдельного хранилища под
    сводку нет и не нужно, полей level/anomaly_reasons уже достаточно.

    subject_user_id для ANOMALY-записи — всегда отправитель (все
    ANOMALY-правила в core/dlp_heuristics.py срабатывают только на
    исходящей проверке, is_incoming=False) — то есть тот, кто фактически
    создал аномальную отправку, а не случайный третий пользователь.

    Видна только та часть сводки, что относится к организациям, где
    current_user — security_officer (тот же принцип гейтинга, что и
    /moderation/*, см. _require_moderation_access) — офицер одной
    компании не должен видеть нарушителей другой.

    user_id резолвится в email/имя через auth_store.user_by_id() — тот
    же паттерн резолва, что уже применён в core/message_bridge.py при
    построении RawMessage."""
    _require_not_isolated(current_user)
    records = dlp_events_store.list_by_level(ThreatLevel.ANOMALY)

    grouped: dict[str, list] = {}
    for record in records:
        grouped.setdefault(record.subject_user_id, []).append(record)

    summary: list[AnomalySubjectSummary] = []
    for user_id, user_records in grouped.items():
        membership = org_store.get_active_membership(user_id)
        if membership is None or not org_store.is_security_officer(
            current_user.user_id, membership.org_id
        ):
            continue  # не организация current_user — не его дело разбирать

        user = auth_store.user_by_id(user_id)
        if user is None:
            continue  # защитная ветка: аккаунт мог быть удалён, событие осталось

        reason_counts: dict[str, int] = {}
        for record in user_records:
            for reason in record.anomaly_reasons:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

        summary.append(
            AnomalySubjectSummary(
                user_id=user_id,
                email=user.email,
                name=user.name,
                count=len(user_records),
                reason_counts=reason_counts,
                last_recorded_at=max(r.recorded_at for r in user_records),
            )
        )

    # Больше всего нарушений — первым: офицеру интереснее всего разобрать
    # сначала самый заметный паттерн, не хронологию по алфавиту user_id.
    summary.sort(key=lambda s: s.count, reverse=True)
    return AnomalySummaryResponse(summary=summary)


@app.get("/moderation/isolated", response_model=IsolatedListResponse)
async def isolated_list(current_user: User = Depends(get_current_user)):
    """Активные изоляции (core/isolation_store.py) — видны только те, что
    относятся к организациям, где current_user — security_officer (тот
    же принцип, что и /moderation/pending, /moderation/anomaly-summary)."""
    _require_not_isolated(current_user)
    isolated: list[IsolatedUserOut] = []
    for record in isolation_store.list_active():
        membership = org_store.get_active_membership(record.user_id)
        if membership is None or not org_store.is_security_officer(
            current_user.user_id, membership.org_id
        ):
            continue

        user = auth_store.user_by_id(record.user_id)
        if user is None:
            continue  # защитная ветка: аккаунт мог быть удалён

        isolated.append(
            IsolatedUserOut(
                user_id=record.user_id,
                email=user.email,
                name=user.name,
                threat_reasons=record.threat_reasons,
                isolated_at=record.isolated_at,
            )
        )

    isolated.sort(key=lambda i: i.isolated_at)
    return IsolatedListResponse(isolated=isolated)


@app.post("/moderation/isolated/{user_id}/lift", response_model=LiftIsolationResponse)
async def lift_isolation(user_id: str, current_user: User = Depends(get_current_user)):
    """Снимает изоляцию. Право зависит от того, КТО изолирован (см.
    обсуждение в чате):
    - обычный сотрудник -> любой НЕ изолированный security_officer его
      организации (как и раньше, _require_officer_for_user);
    - сам security_officer -> только владелец организации
      (org_store.is_owner). Если бы officer мог разблокировать другого
      officer'а (или тем более себя), скомпрометированный officer снимал
      бы изоляцию сам с собой или через сговор — ответственность за этот
      случай явно передаётся человеку (владельцу бизнеса), не автоматике.
    """
    _require_not_isolated(current_user)  # актёр сам не должен быть изолирован ни в одной ветке

    membership = org_store.get_active_membership(user_id)
    if membership is None:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден или не состоит в организации",
        )

    if org_store.is_security_officer(user_id, membership.org_id):
        if current_user.user_id == user_id:
            raise HTTPException(
                status_code=403,
                detail="Владелец не может быть тем же лицом, что и разблокируемый security_officer",
            )
        if not org_store.is_owner(current_user.user_id, membership.org_id):
            raise HTTPException(
                status_code=403,
                detail="Изолированного security_officer может разблокировать только владелец организации",
            )
    else:
        _require_officer_for_user(user_id, current_user)

    try:
        isolation_store.lift(user_id, lifted_by=current_user.user_id)
    except IsolationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return LiftIsolationResponse(user_id=user_id)


@app.get("/messages/history/{other_user_id}", response_model=MessagesListResponse)
async def message_history(
    other_user_id: str, current_user: User = Depends(get_current_user)
):
    """История 1-на-1 переписки. Групповая история (3+ участников) через REST
    пока не открыта — messages_store.conversation_history() уже это умеет,
    эндпоинт для неё можно добавить отдельно, когда появятся групповые чаты
    на фронте."""
    history = messages_store.conversation_history(
        [current_user.user_id, other_user_id]
    )
    return MessagesListResponse(messages=[_message_to_out(m) for m in history])


@app.get("/messages/inbox", response_model=MessagesListResponse)
async def message_inbox(current_user: User = Depends(get_current_user)):
    inbox = messages_store.inbox(current_user.user_id)
    return MessagesListResponse(messages=[_message_to_out(m) for m in inbox])


# --------- Организации и членство (слой 4) ---------
#
# Флаг DLP-проверки — свойство аккаунта, реализованное здесь (approved-
# членство), а не сообщения. См. mimir_account_linkage_v1.md. Эти эндпоинты
# сами не вызывают ни message_parser, ни claude_adapter — только хранят
# и отдают факт привязки. Решение "проверять ли это исходящее сообщение"
# принимает мост (ещё не реализован), опираясь на org_store.is_dlp_active().

def _require_security_officer(org_id: str, current_user: User) -> None:
    """Гейтинг для org-scoped ресурсов DLP-баз: watchlist/link-whitelist
    доменов (core/watchlist_store.py) и устройства/роли доступа
    (core/access_store.py) — та же роль, что уже переиспользуется для
    всего DLP-контура (mimir_architecture_v2.md,
    org_store.MembershipRole.SECURITY_OFFICER, без отдельной DLP-роли).
    Изолированный аккаунт тоже не должен менять org-данные — см.
    _require_not_isolated."""
    _require_not_isolated(current_user)
    if not org_store.is_security_officer(current_user.user_id, org_id):
        raise HTTPException(
            status_code=403,
            detail="Только security_officer этой организации может это сделать",
        )


def _org_to_out(org: Organization) -> OrgOut:
    return OrgOut(**org.to_public_dict())


def _membership_to_out(membership: Membership) -> MembershipOut:
    return MembershipOut(**membership.to_public_dict())


@app.post("/orgs", response_model=OrgOut)
async def create_org(
    req: CreateOrgRequest, current_user: User = Depends(get_current_user)
):
    """Создатель автоматически становится первым security_officer (см.
    org_store.py docstring про долг "кто назначает первого офицера")."""
    try:
        org = org_store.create_organization(current_user.user_id, req.name)
    except OrgError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _org_to_out(org)


@app.post("/orgs/{org_id}/join", response_model=MembershipOut)
async def request_membership(
    org_id: str, current_user: User = Depends(get_current_user)
):
    try:
        membership = org_store.request_membership(current_user.user_id, org_id)
    except OrgError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _membership_to_out(membership)


@app.get("/orgs/{org_id}/pending", response_model=MembershipsListResponse)
async def list_pending_memberships(
    org_id: str, current_user: User = Depends(get_current_user)
):
    """Список заявок на рассмотрении — только security_officer этой
    организации (те же права, что у approve/reject). Раньше просмотр был
    открыт любому залогиненному пользователю — утечка: посторонний видел,
    кто подаёт заявки в чужую организацию. _require_security_officer сама
    первым делом вызывает _require_not_isolated, изоляция по-прежнему
    закрывает доступ."""
    _require_security_officer(org_id, current_user)
    pending = org_store.list_pending(org_id)
    return MembershipsListResponse(memberships=[_membership_to_out(m) for m in pending])


@app.post("/orgs/memberships/{membership_id}/approve", response_model=MembershipOut)
async def approve_membership(
    membership_id: str, current_user: User = Depends(get_current_user)
):
    """Только security_officer организации может одобрить — проверяется
    внутри org_store.approve()."""
    try:
        membership = org_store.approve(membership_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return _membership_to_out(membership)


@app.post("/orgs/memberships/{membership_id}/reject", response_model=MembershipOut)
async def reject_membership(
    membership_id: str, current_user: User = Depends(get_current_user)
):
    try:
        membership = org_store.reject(membership_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return _membership_to_out(membership)


@app.post("/orgs/{org_id}/watchlist", response_model=WatchlistDomainOut)
async def add_watchlisted_domain(
    org_id: str, req: AddDomainRequest, current_user: User = Depends(get_current_user)
):
    """Блок 1 (mimir_dlp_features_v1.md) — домен под наблюдением: конкурент
    для исходящих, известный источник фишинга для входящих. Только
    security_officer организации — см. _require_security_officer."""
    _require_security_officer(org_id, current_user)
    try:
        entry = watchlist_store.add_watchlisted(org_id, req.domain, current_user.user_id, req.reason)
    except WatchlistError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return WatchlistDomainOut(**entry.to_public_dict())


@app.get("/orgs/{org_id}/watchlist", response_model=WatchlistListResponse)
async def list_watchlisted_domains(org_id: str, current_user: User = Depends(get_current_user)):
    _require_security_officer(org_id, current_user)
    domains = watchlist_store.list_watchlisted(org_id)
    return WatchlistListResponse(domains=[WatchlistDomainOut(**e.to_public_dict()) for e in domains])


@app.delete("/orgs/{org_id}/watchlist/{entry_id}")
async def remove_watchlisted_domain(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    _require_security_officer(org_id, current_user)
    try:
        watchlist_store.remove_watchlisted(org_id, entry_id, current_user.user_id)
    except WatchlistError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


@app.get("/link-whitelist/default", response_model=list[str])
async def default_whitelisted_link_domains(current_user: User = Depends(get_current_user)):
    """Общий read-only список для всех организаций (см. docstring
    core/watchlist_store.py, "проблема холодного старта") — фронтенду
    нужен отдельно от org-специфичного /orgs/{org_id}/link-whitelist,
    чтобы показать officer'у, что уже разрешено, а что можно добавить."""
    return watchlist_store.list_default_whitelisted()


@app.post("/orgs/{org_id}/link-whitelist", response_model=WhitelistDomainOut)
async def add_whitelisted_link_domain(
    org_id: str, req: AddDomainRequest, current_user: User = Depends(get_current_user)
):
    """Блок 2 (mimir_dlp_features_v1.md) — одобренный домен для внешних
    ссылок в сообщениях. Полярность обратная watchlist: домен, НЕ
    внесённый сюда, трактуется парсером как "не в белом списке" (см.
    docstring core/watchlist_store.py)."""
    _require_security_officer(org_id, current_user)
    try:
        entry = watchlist_store.add_whitelisted_link(org_id, req.domain, current_user.user_id, req.reason)
    except WatchlistError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return WhitelistDomainOut(**entry.to_public_dict())


@app.get("/orgs/{org_id}/link-whitelist", response_model=WhitelistListResponse)
async def list_whitelisted_link_domains(org_id: str, current_user: User = Depends(get_current_user)):
    _require_security_officer(org_id, current_user)
    domains = watchlist_store.list_whitelisted(org_id)
    return WhitelistListResponse(domains=[WhitelistDomainOut(**e.to_public_dict()) for e in domains])


@app.delete("/orgs/{org_id}/link-whitelist/{entry_id}")
async def remove_whitelisted_link_domain(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    _require_security_officer(org_id, current_user)
    try:
        watchlist_store.remove_whitelisted_link(org_id, entry_id, current_user.user_id)
    except WatchlistError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


# --------- Устройства + роли доступа (core/access_store.py, блоки 5 и 6) ---------


@app.post("/orgs/{org_id}/devices", response_model=DeviceOut)
async def register_device(
    org_id: str, req: RegisterDeviceRequest, current_user: User = Depends(get_current_user)
):
    """Блок 5 — зарегистрированное рабочее устройство. Для пилота
    регистрирует только security_officer (самостоятельная регистрация
    сотрудником не предусмотрена, см. docstring core/access_store.py)."""
    _require_security_officer(org_id, current_user)
    try:
        entry = access_store.register_device(
            org_id, req.device_id, req.user_id, current_user.user_id, req.label
        )
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DeviceOut(**entry.to_public_dict())


@app.get("/orgs/{org_id}/devices", response_model=DevicesListResponse)
async def list_devices(org_id: str, current_user: User = Depends(get_current_user)):
    _require_security_officer(org_id, current_user)
    devices = access_store.list_devices(org_id)
    return DevicesListResponse(devices=[DeviceOut(**d.to_public_dict()) for d in devices])


@app.delete("/orgs/{org_id}/devices/{entry_id}")
async def unregister_device(org_id: str, entry_id: str, current_user: User = Depends(get_current_user)):
    _require_security_officer(org_id, current_user)
    try:
        access_store.unregister_device(org_id, entry_id, current_user.user_id)
    except AccessError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


@app.post("/orgs/{org_id}/access/legitimate", response_model=AccessGrantOut)
async def grant_legitimate_access(
    org_id: str, req: GrantAccessRequest, current_user: User = Depends(get_current_user)
):
    """Блок 6 — согласованный security_officer доступ сотрудника к данным
    организации (уточнено в чате 2026-09-16, см. docstring
    core/access_store.py: грант на уровне сотрудника, не на конкретное
    дело/контрагента — такого понятия в системе нет)."""
    _require_security_officer(org_id, current_user)
    try:
        grant = access_store.grant_legitimate_access(org_id, req.user_id, current_user.user_id, req.note)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AccessGrantOut(**grant.to_public_dict())


@app.get("/orgs/{org_id}/access/legitimate", response_model=AccessGrantsListResponse)
async def list_legitimate_access(org_id: str, current_user: User = Depends(get_current_user)):
    _require_security_officer(org_id, current_user)
    grants = access_store.list_legitimate_access(org_id)
    return AccessGrantsListResponse(grants=[AccessGrantOut(**g.to_public_dict()) for g in grants])


@app.delete("/orgs/{org_id}/access/legitimate/{entry_id}")
async def revoke_legitimate_access(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    _require_security_officer(org_id, current_user)
    try:
        access_store.revoke_legitimate_access(org_id, entry_id, current_user.user_id)
    except AccessError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


@app.post("/orgs/{org_id}/access/elevated", response_model=AccessGrantOut)
async def grant_elevated_rights(
    org_id: str, req: GrantAccessRequest, current_user: User = Depends(get_current_user)
):
    _require_security_officer(org_id, current_user)
    try:
        grant = access_store.grant_elevated_rights(org_id, req.user_id, current_user.user_id, req.note)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AccessGrantOut(**grant.to_public_dict())


@app.get("/orgs/{org_id}/access/elevated", response_model=AccessGrantsListResponse)
async def list_elevated_rights(org_id: str, current_user: User = Depends(get_current_user)):
    _require_security_officer(org_id, current_user)
    grants = access_store.list_elevated_rights(org_id)
    return AccessGrantsListResponse(grants=[AccessGrantOut(**g.to_public_dict()) for g in grants])


@app.delete("/orgs/{org_id}/access/elevated/{entry_id}")
async def revoke_elevated_rights(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    _require_security_officer(org_id, current_user)
    try:
        access_store.revoke_elevated_rights(org_id, entry_id, current_user.user_id)
    except AccessError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


@app.get("/me/membership", response_model=MembershipOut | None)
async def my_membership(current_user: User = Depends(get_current_user)):
    """Активное (approved) членство текущего пользователя, если есть — сам
    и есть тот самый "флаг", включающий DLP-проверку исходящих (ещё не
    подключено ни к чему — просто отдаёт состояние)."""
    membership = org_store.get_active_membership(current_user.user_id)
    return _membership_to_out(membership) if membership else None


# --------- WebSocket: потоковый чат для голоса/реального времени ---------

WS_AUTH_TIMEOUT_SECONDS = 10


@app.websocket("/ws/chat")
async def ws_chat(websocket: WebSocket):
    """Авторизация — ПЕРВЫМ сообщением после подключения:
        {"token": "<тот же токен, что в Authorization: Bearer>"}
    Браузерный new WebSocket(url) не умеет передавать заголовки, поэтому
    Depends(get_current_user) здесь не работает. Токен в URL (?token=)
    сознательно не используется — он оседает в логах Nginx и истории
    браузера. Нет валидного токена за WS_AUTH_TIMEOUT_SECONDS -> закрываем
    с кодом 1008 (policy violation), память не трогаем."""
    await websocket.accept()
    try:
        auth_msg = await asyncio.wait_for(
            websocket.receive_json(), timeout=WS_AUTH_TIMEOUT_SECONDS
        )
        token = auth_msg.get("token") if isinstance(auth_msg, dict) else None
        user = auth_store.user_by_token(token) if isinstance(token, str) else None
    except (asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        user = None
    if user is None:
        await websocket.close(code=1008)
        return

    await websocket.send_json({"event": "authenticated"})
    session = mimir.memory.get(user.user_id)
    try:
        while True:
            user_message = await websocket.receive_text()
            session.add("user", user_message)

            full_reply = ""
            async for chunk in mimir.claude.reply_stream(session.to_api_messages()):
                full_reply += chunk
                await websocket.send_text(chunk)

            session.add("assistant", full_reply)
            await websocket.send_json({"event": "done"})
    except WebSocketDisconnect:
        logger.info("WebSocket отключён: user_id=%s", user.user_id)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.debug,
    )
