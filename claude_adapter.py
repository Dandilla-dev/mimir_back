"""
models/claude_adapter.py — подключение Claude API.

Отвечает за: общение с пользователем, сложный анализ, отчёты.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import AsyncIterator

from core.config import ClaudeConfig

logger = logging.getLogger("mimir.claude")

SYSTEM_PROMPT = (
    "Ты — Мимир, AI-ассистент системы безопасности. "
    "Отвечай кратко, по делу, без лишней воды. "
    "Если запрос касается тревоги/угрозы — сначала дай практический совет."
)

# Канонные ответы заглушки — используются, когда нет ключа/включён mock-режим.
# Нужны только чтобы проверить весь путь frontend -> backend -> ответ -> рендер,
# без реального похода в Claude API.
_MOCK_REPLIES = [
    "Мимир (заглушка): принял сообщение «{last}». Реального ответа Claude пока нет — "
    "работает mock-режим, чтобы проверить связку фронта и бэкенда.",
    "Это тестовый ответ Мимира без обращения к Claude API. Ты написал: «{last}».",
    "Заглушка на связи. Как только подключишь ANTHROPIC_API_KEY, здесь будет настоящий ответ.",
]


class ClaudeAdapter:
    """Тонкая обёртка над Anthropic SDK для нужд Мимира.

    Если ключа нет или явно включён mock-режим (MOCK_CLAUDE=true в .env) —
    работает без сети и без SDK, возвращая канонные ответы. Интерфейс
    (reply/reply_stream) не меняется, так что router.py и server.py
    ничего не замечают.
    """

    def __init__(self, config: ClaudeConfig, system_prompt: str = SYSTEM_PROMPT):
        self._config = config
        self._system_prompt = system_prompt
        self._mock = config.mock or not config.api_key
        self._client = None

        if self._mock:
            logger.warning(
                "ClaudeAdapter работает в MOCK-режиме (ключ не найден или "
                "MOCK_CLAUDE=true) — реальные запросы к Claude не отправляются."
            )
        else:
            import anthropic  # локальный импорт: не нужен в mock-режиме

            self._client = anthropic.AsyncAnthropic(api_key=config.api_key)

    async def reply(self, messages: list[dict], system_prompt: str | None = None) -> str:
        """Синхронный (не потоковый) ответ Мимира на историю сообщений."""
        if self._mock:
            return await self._mock_reply(messages)

        response = await self._client.messages.create(
            model=self._config.model,
            max_tokens=self._config.max_tokens,
            temperature=self._config.temperature,
            system=system_prompt or self._system_prompt,
            messages=messages,
        )
        return "".join(block.text for block in response.content if block.type == "text")

    async def reply_stream(
        self, messages: list[dict], system_prompt: str | None = None
    ) -> AsyncIterator[str]:
        """Потоковый ответ — для стриминга в чат/голос по мере генерации."""
        if self._mock:
            text = await self._mock_reply(messages)
            for word in text.split(" "):
                await asyncio.sleep(0.03)
                yield word + " "
            return

        async with self._client.messages.stream(
            model=self._config.model,
            max_tokens=self._config.max_tokens,
            temperature=self._config.temperature,
            system=system_prompt or self._system_prompt,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                yield text

    async def _mock_reply(self, messages: list[dict]) -> str:
        last_user = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"), ""
        )
        await asyncio.sleep(0.2)  # имитация задержки сети
        template = random.choice(_MOCK_REPLIES)
        return template.format(last=last_user)
