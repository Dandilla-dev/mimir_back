"""
api/server.py — FastAPI-приложение, единая точка входа для всех клиентов
(веб, мобильное, Telegram и т.д. через прямой HTTP).

Здесь только сборка: жизненный цикл (фоновые задачи, пул БД), CORS и
подключение маршрутов. Маршруты — api/routes/*, общие проверки прав и
экземпляры сторов — api/deps.py, модели запросов/ответов — api/schemas.py.

Запуск:
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.deps import auth_store, messages_store, settings
from api.routes import assistant, auth, contacts, messages, moderation, org_dlp, orgs
from core import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mimir.api")

# Как часто фоновая задача убирает просроченное: содержимое сообщений,
# отклонённых модерацией больше суток назад ([РЕШЕНИЕ 10]), и
# просроченные сессии.
PURGE_INTERVAL_SECONDS = int(os.getenv("PURGE_INTERVAL_SECONDS", "3600"))


async def _purge_loop() -> None:
    """Раз в PURGE_INTERVAL_SECONDS. Синхронные запросы к БД — в отдельном
    потоке, чтобы не блокировать event loop. Сбой одной итерации
    логируется и не останавливает цикл."""
    while True:
        for job in (messages_store.purge_rejected_content, auth_store.purge_expired_sessions):
            try:
                await asyncio.to_thread(job)
            except Exception:
                logger.exception("Фоновая уборка не удалась: %s", job.__name__)
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    purge_task = asyncio.create_task(_purge_loop())
    try:
        yield
    finally:
        purge_task.cancel()
        db.close_pool()


app = FastAPI(title="Mimir API", version="0.2.0", lifespan=lifespan)

# CORS: браузер пускает к API только фронтенд с этих адресов
# (CORS_ORIGINS в .env, по умолчанию — Vite dev-сервер).
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.server.cors_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in (auth, contacts, messages, moderation, orgs, org_dlp, assistant):
    app.include_router(module.router)


@app.get("/health")
def health():
    return {"status": "ok", "model": settings.claude.model}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.debug,
    )
