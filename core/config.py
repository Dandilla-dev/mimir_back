"""
core/config.py — настройки и переменные окружения.

Читает:
- config.yaml  (общие, не секретные параметры)
- .env         (секреты и то, что отличается между машинами: API-ключи,
                DATABASE_URL, CORS_ORIGINS, LOAD_LOCAL_MODEL)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.yaml"

load_dotenv(BASE_DIR / ".env")


@dataclass
class ClaudeConfig:
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 2048
    temperature: float = 0.7
    api_key: str | None = None
    # Режим заглушки: не ходит в Claude API, отвечает канонными фразами.
    # Включается автоматически, если нет ключа, либо явно через MOCK_CLAUDE=true в .env
    mock: bool = False


@dataclass
class WhisperConfig:
    model: str = "small"
    language: str = "auto"


@dataclass
class VoiceConfig:
    provider: str = "pyttsx3"
    elevenlabs_api_key: str | None = None
    elevenlabs_voice_id: str | None = None


DEFAULT_CORS_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes")


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    # Адреса фронтенда, которым браузер разрешит обращаться к API.
    # CORS_ORIGINS в .env — через запятую. По умолчанию — Vite dev-сервер
    # фронтенда (npm run dev). Раньше было "*" — любой сайт мог слать
    # запросы от имени вошедшего пользователя.
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    # Локальная нейросеть (models/local_model.py). Нужен PyTorch
    # (requirements-ml.txt). По умолчанию выключена: обученных весов ещё
    # нет, со случайными весами она только тратит память и время запуска.
    load_local_model: bool = False


@dataclass
class Settings:
    claude: ClaudeConfig = field(default_factory=ClaudeConfig)
    whisper: WhisperConfig = field(default_factory=WhisperConfig)
    voice: VoiceConfig = field(default_factory=VoiceConfig)
    server: ServerConfig = field(default_factory=ServerConfig)

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "Settings":
        raw: dict[str, Any] = {}
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}

        claude_raw = raw.get("claude", {})
        whisper_raw = raw.get("whisper", {})
        voice_raw = raw.get("voice", {})
        server_raw = raw.get("server", {})

        return cls(
            claude=ClaudeConfig(
                model=claude_raw.get("model", ClaudeConfig.model),
                max_tokens=claude_raw.get("max_tokens", ClaudeConfig.max_tokens),
                temperature=claude_raw.get("temperature", ClaudeConfig.temperature),
                api_key=os.getenv("ANTHROPIC_API_KEY"),
                mock=os.getenv("MOCK_CLAUDE", "").lower() in ("1", "true", "yes"),
            ),
            whisper=WhisperConfig(
                model=whisper_raw.get("model", WhisperConfig.model),
                language=whisper_raw.get("language", WhisperConfig.language),
            ),
            voice=VoiceConfig(
                provider=voice_raw.get("provider", VoiceConfig.provider),
                elevenlabs_api_key=os.getenv("ELEVENLABS_API_KEY"),
                elevenlabs_voice_id=os.getenv("ELEVENLABS_VOICE_ID"),
            ),
            server=ServerConfig(
                host=server_raw.get("host", ServerConfig.host),
                port=server_raw.get("port", ServerConfig.port),
                debug=server_raw.get("debug", ServerConfig.debug),
                cors_origins=tuple(
                    o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()
                ) or DEFAULT_CORS_ORIGINS,
                load_local_model=_env_flag("LOAD_LOCAL_MODEL", ServerConfig.load_local_model),
            ),
        )


@lru_cache
def get_settings() -> Settings:
    """Кэшированный доступ к настройкам (singleton на процесс)."""
    return Settings.load()
