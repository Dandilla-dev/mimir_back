"""
voice/speech_to_text.py — микрофон -> текст (Whisper, локально).
"""

from __future__ import annotations

import logging

import whisper

from core.config import WhisperConfig

logger = logging.getLogger("mimir.stt")


class SpeechToText:
    def __init__(self, config: WhisperConfig):
        self._config = config
        logger.info("Загрузка модели Whisper: %s", config.model)
        self._model = whisper.load_model(config.model)

    def transcribe_file(self, audio_path: str) -> str:
        """Распознаёт речь из аудиофайла (wav/mp3/ogg...) в текст."""
        language = None if self._config.language == "auto" else self._config.language
        result = self._model.transcribe(audio_path, language=language)
        return result["text"].strip()

    def transcribe_bytes(self, audio_bytes: bytes, suffix: str = ".wav") -> str:
        """Распознаёт речь из аудио в байтах (например, полученных по WebSocket)."""
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            tmp.write(audio_bytes)
            tmp.flush()
            return self.transcribe_file(tmp.name)
