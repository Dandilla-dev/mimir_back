"""
api/server.py — FastAPI сервер, единая точка входа для всех приложений
(веб-панель, мобильное, Telegram и т.д. через sdk/mimir.js или прямой HTTP).

Запуск:
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from core.mimir import Mimir
from core.config import get_settings
from core.auth_store import AuthError, AuthStore, User
from core.contacts_store import Contact, ContactsError, ContactsStore
from core.messages_store import Message, MessagesError, MessagesStore
from core.org_store import Membership, Organization, OrgError, OrgStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mimir.api")

settings = get_settings()
app = FastAPI(title="Mimir API", version="0.1.0")

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

class ChatRequest(BaseModel):
    session_id: str = Field(..., description="Идентификатор сессии/пользователя")
    message: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    session_id: str
    reply: str


class SensorEventRequest(BaseModel):
    session_id: str
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


class MessagesListResponse(BaseModel):
    messages: list[MessageOut]


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


# --------- REST эндпоинты ---------

@app.get("/health")
async def health():
    return {"status": "ok", "model": settings.claude.model}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    try:
        reply = await mimir.chat(req.session_id, req.message)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ошибка в /chat")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return ChatResponse(session_id=req.session_id, reply=reply)


@app.post("/sensor-event", response_model=SensorEventResponse)
async def sensor_event(req: SensorEventRequest):
    try:
        result = await mimir.handle_sensor_event(req.session_id, req.features)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ошибка в /sensor-event")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return SensorEventResponse(
        source=result.source,
        text=result.text,
        event_class=result.event_class.value if result.event_class else None,
        confidence=result.confidence,
    )


@app.post("/session/{session_id}/reset")
async def reset_session(session_id: str):
    mimir.reset_session(session_id)
    return {"status": "reset", "session_id": session_id}


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
# Только хранение и доставка — без обращений к DLP или Claude (см.
# core/messages_store.py и mimir_architecture_v2.md, раздел 4). Мост
# к DLP-парсеру и учёт флага "проверять исходящие" (см.
# mimir_account_linkage_v1.md) сюда сознательно не входят — отдельный
# следующий шаг.
#
# /messages/send принимает multipart/form-data, а не JSON — вложения
# идут как настоящие файлы (UploadFile), без base64-раздувания.
# recipient_ids передаётся как повторяющееся form-поле:
#   recipient_ids=u2&recipient_ids=u3 (или несколько частей формы с
#   одним и тем же именем при отправке через FormData на фронте).

def _message_to_out(message: Message) -> MessageOut:
    return MessageOut(**message.to_public_dict())


@app.post("/messages/send", response_model=MessageOut)
async def send_message(
    recipient_ids: list[str] = Form(...),
    text: str = Form(""),
    files: list[UploadFile] = File(default=[]),
    current_user: User = Depends(get_current_user),
):
    attachments = [
        {"filename": f.filename, "content": await f.read()}
        for f in files
    ]
    try:
        message = messages_store.send_message(
            sender_id=current_user.user_id,
            recipient_ids=recipient_ids,
            text=text,
            attachments=attachments,
        )
    except MessagesError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _message_to_out(message)


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
    """Список заявок на рассмотрении. Доступ не ограничен ролью на уровне
    самого просмотра (заглушка) — проверка роли встаёт в approve/reject."""
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


@app.get("/me/membership", response_model=MembershipOut | None)
async def my_membership(current_user: User = Depends(get_current_user)):
    """Активное (approved) членство текущего пользователя, если есть — сам
    и есть тот самый "флаг", включающий DLP-проверку исходящих (ещё не
    подключено ни к чему — просто отдаёт состояние)."""
    membership = org_store.get_active_membership(current_user.user_id)
    return _membership_to_out(membership) if membership else None


# --------- WebSocket: потоковый чат для голоса/реального времени ---------

@app.websocket("/ws/chat/{session_id}")
async def ws_chat(websocket: WebSocket, session_id: str):
    await websocket.accept()
    session = mimir.memory.get(session_id)
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
        logger.info("WebSocket отключён: session_id=%s", session_id)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.debug,
    )
