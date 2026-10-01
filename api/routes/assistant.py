"""
api/routes/assistant.py — разговор с Мимиром: /chat, /sensor-event,
/session/reset и потоковый /ws/chat.

Память разговора (core/memory.py) — в оперативной памяти процесса, в БД
сознательно не переносится (требование не хранить переписку с ИИ на
сервере, mimir_encryption_architecture.md).
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool

from api.deps import auth_store, get_current_user, mimir
from api.schemas import ChatRequest, ChatResponse, SensorEventRequest, SensorEventResponse
from core.auth_store import User

logger = logging.getLogger("mimir.api")

router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, current_user: User = Depends(get_current_user)):
    try:
        reply = await mimir.chat(current_user.user_id, req.message)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ошибка в /chat")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return ChatResponse(reply=reply)


@router.post("/sensor-event", response_model=SensorEventResponse)
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


@router.post("/session/reset")
def reset_session(current_user: User = Depends(get_current_user)):
    """Очищает память разговора с Мимиром ТЕКУЩЕГО пользователя — чужую
    сессию сбросить больше нельзя (раньше session_id был в пути запроса)."""
    mimir.reset_session(current_user.user_id)
    return {"status": "reset"}


# --------- WebSocket: потоковый чат для голоса/реального времени ---------

WS_AUTH_TIMEOUT_SECONDS = 10


@router.websocket("/ws/chat")
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
        user = (
            await run_in_threadpool(auth_store.user_by_token, token)
            if isinstance(token, str) else None
        )
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