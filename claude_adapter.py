"""
models/claude_adapter.py — подключение Claude API.

Отвечает за: общение с пользователем, сложный анализ, отчёты.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator

import anthropic

from core.config import ClaudeConfig

logger = logging.getLogger("mimir.claude")

SYSTEM_PROMPT = (
    "Ты — Мимир, AI-ассистент системы безопасности. "
    "Отвечай кратко, по делу, без лишней воды. "
    "Если запрос касается тревоги/угрозы — сначала дай практический совет."
)


class ClaudeAdapter:
    """Тонкая обёртка над Anthropic SDK для нужд Мимира."""

    def __init__(self, config: ClaudeConfig, system_prompt: str = SYSTEM_PROMPT):
        if not config.api_key:
            logger.warning("ANTHROPIC_API_KEY не найден — Claude adapter работать не будет.")
        self._config = config
        self._system_prompt = system_prompt
        self._client = anthropic.AsyncAnthropic(api_key=config.api_key)

    async def reply(self, messages: list[dict], system_prompt: str | None = None) -> str:
        """Синхронный (не потоковый) ответ Мимира на историю сообщений."""
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
        async with self._client.messages.stream(
            model=self._config.model,
            max_tokens=self._config.max_tokens,
            temperature=self._config.temperature,
            system=system_prompt or self._system_prompt,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                yield text
