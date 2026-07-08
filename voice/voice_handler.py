"""
voice/voice_handler.py — соединяет speech_to_text и text_to_speech
с ядром Мимира, чтобы получить полный голосовой цикл:

    Микрофон -> текст -> Мимир -> текст ответа -> голос -> Динамик
"""

from __future__ import annotations

import logging

from core.mimir import Mimir
from voice.speech_to_text import SpeechToText
from voice.text_to_speech import TextToSpeech

logger = logging.getLogger("mimir.voice_handler")


class VoiceHandler:
    def __init__(self, mimir: Mimir):
        self._mimir = mimir
        self._stt = SpeechToText(mimir.settings.whisper)
        self._tts = TextToSpeech(mimir.settings.voice)

    async def handle_audio_file(self, session_id: str, audio_path: str) -> tuple[str, str]:
        """
        Принимает путь к аудиофайлу с речью пользователя, возвращает
        (текст ответа Мимира, путь к аудиофайлу с озвученным ответом).
        """
        user_text = self._stt.transcribe_file(audio_path)
        logger.info("Распознано: %s", user_text)

        reply_text = await self._mimir.chat(session_id, user_text)

        output_path = f"/tmp/mimir_reply_{session_id}.wav"
        self._tts.synthesize_to_file(reply_text, output_path)

        return reply_text, output_path

    async def handle_audio_bytes(self, session_id: str, audio_bytes: bytes) -> tuple[str, str]:
        user_text = self._stt.transcribe_bytes(audio_bytes)
        logger.info("Распознано: %s", user_text)

        reply_text = await self._mimir.chat(session_id, user_text)

        output_path = f"/tmp/mimir_reply_{session_id}.wav"
        self._tts.synthesize_to_file(reply_text, output_path)

        return reply_text, output_path
