"""
api/server.py — FastAPI сервер, единая точка входа для всех приложений
(веб-панель, мобильное, Telegram и т.д. через sdk/mimir.js или прямой HTTP).

Запуск:
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from core.mimir import Mimir
from core.config import get_settings
from core.auth_store import AuthError, AuthStore, User

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
