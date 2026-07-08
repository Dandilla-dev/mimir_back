"""
api/server.py — FastAPI сервер, единая точка входа для всех приложений
(веб-панель, мобильное, Telegram и т.д. через sdk/mimir.js или прямой HTTP).

Запуск:
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.mimir import Mimir
from core.config import get_settings

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

# LOAD_LOCAL_MODEL=false в .env — пропустить загрузку PyTorch-классификатора
# (удобно при тестировании только текстового чата, без /sensor-event).
_load_local_model = os.getenv("LOAD_LOCAL_MODEL", "true").lower() not in ("0", "false", "no")

mimir = Mimir(settings=settings, load_local_model=_load_local_model)


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
