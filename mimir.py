"""
core/mimir.py — главный класс. Точка сборки всех слоёв ядра:
конфиг, память, роутер, модели.
"""

from __future__ import annotations

import logging

from core.config import Settings, get_settings
from core.memory import MemoryStore
from core.router import Router, RouteResult
from models.claude_adapter import ClaudeAdapter
from models.local_model import LocalModel

logger = logging.getLogger("mimir.core")


class Mimir:
    """Главная точка входа для приложений: один Mimir на процесс/сервер."""

    def __init__(
        self,
        settings: Settings | None = None,
        local_model_weights: str | None = None,
        load_local_model: bool = True,
    ):
        self.settings = settings or get_settings()
        self.memory = MemoryStore()

        self.claude = ClaudeAdapter(self.settings.claude)
        self.local_model = LocalModel(weights_path=local_model_weights) if load_local_model else None
        self.router = Router(claude=self.claude, local_model=self.local_model)

        logger.info(
            "Мимир инициализирован (модель: %s, локальная сеть: %s)",
            self.settings.claude.model,
            "включена" if self.local_model else "выключена",
        )

    async def chat(self, session_id: str, user_message: str) -> str:
        """Обычное текстовое сообщение от пользователя -> ответ Мимира."""
        session = self.memory.get(session_id)
        session.add("user", user_message)

        result = await self.router.route_text(session.to_api_messages())

        session.add("assistant", result.text)
        return result.text

    async def handle_sensor_event(self, session_id: str, features: list[float]) -> RouteResult:
        """Данные сенсоров -> классификация (+ анализ Claude при аномалии/угрозе)."""
        session = self.memory.get(session_id)
        result = await self.router.route_sensor_event_with_analysis(
            features, session.to_api_messages()
        )
        return result

    def reset_session(self, session_id: str) -> None:
        self.memory.drop(session_id)
