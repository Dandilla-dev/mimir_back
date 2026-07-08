"""
core/router.py — роутер: кому передать запрос.

Логика:
  - события с числовыми признаками сенсоров -> локальная сеть (быстро, офлайн)
  - обычные текстовые сообщения -> Claude API (диалог, анализ, отчёты)
  - явные ключевые слова тревоги -> сначала локальная сеть, затем Claude
    для развёрнутого ответа/рекомендаций
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from models.claude_adapter import ClaudeAdapter
from models.local_model import EventClass, LocalModel

logger = logging.getLogger("mimir.router")


@dataclass
class RouteResult:
    source: str  # "local" | "claude" | "local+claude"
    text: str
    event_class: Optional[EventClass] = None
    confidence: Optional[float] = None


class Router:
    def __init__(self, claude: ClaudeAdapter, local_model: LocalModel | None = None):
        self._claude = claude
        self._local_model = local_model

    async def route_text(self, session_messages: list[dict]) -> RouteResult:
        """Обычное текстовое сообщение пользователя -> Claude."""
        text = await self._claude.reply(session_messages)
        return RouteResult(source="claude", text=text)

    def route_sensor_event(self, features: list[float]) -> RouteResult:
        """Сырые данные сенсоров -> локальная сеть, без похода в сеть/Claude."""
        if self._local_model is None:
            raise RuntimeError("Локальная модель не инициализирована.")
        event_class, confidence = self._local_model.classify(features)
        return RouteResult(
            source="local",
            text=f"Событие классифицировано как: {event_class.value}",
            event_class=event_class,
            confidence=confidence,
        )

    async def route_sensor_event_with_analysis(
        self, features: list[float], session_messages: list[dict]
    ) -> RouteResult:
        """
        Данные сенсоров -> локальная сеть для быстрой классификации,
        затем при аномалии/угрозе -> Claude для развёрнутого анализа и рекомендаций.
        """
        local_result = self.route_sensor_event(features)

        if local_result.event_class == EventClass.NORMAL:
            return local_result

        prompt_messages = session_messages + [
            {
                "role": "user",
                "content": (
                    f"Локальная модель обнаружила событие класса "
                    f"'{local_result.event_class.value}' "
                    f"с уверенностью {local_result.confidence:.2f}. "
                    "Дай краткий анализ и рекомендации по дальнейшим действиям."
                ),
            }
        ]
        analysis = await self._claude.reply(prompt_messages)
        return RouteResult(
            source="local+claude",
            text=analysis,
            event_class=local_result.event_class,
            confidence=local_result.confidence,
        )
