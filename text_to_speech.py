"""
voice/text_to_speech.py — текст -> голос Мимира (ElevenLabs / pyttsx3).
"""

from __future__ import annotations

import logging

from core.config import VoiceConfig

logger = logging.getLogger("mimir.tts")


class TextToSpeech:
    def __init__(self, config: VoiceConfig):
        self._config = config
        self._engine = None

        if config.provider == "pyttsx3":
            import pyttsx3

            self._engine = pyttsx3.init()
        elif config.provider == "elevenlabs":
            if not config.elevenlabs_api_key:
                logger.warning("ELEVENLABS_API_KEY не задан — TTS через ElevenLabs не сработает.")
        else:
            raise ValueError(f"Неизвестный провайдер голоса: {config.provider}")

    def speak(self, text: str) -> None:
        """Произносит текст сразу через колонки (используется для локального pyttsx3)."""
        if self._config.provider != "pyttsx3":
            raise RuntimeError("speak() доступен только для провайдера pyttsx3.")
        self._engine.say(text)
        self._engine.runAndWait()

    def synthesize_to_file(self, text: str, output_path: str) -> str:
        """Синтезирует речь в аудиофайл. Для pyttsx3 и ElevenLabs."""
        if self._config.provider == "pyttsx3":
            self._engine.save_to_file(text, output_path)
            self._engine.runAndWait()
            return output_path

        # ElevenLabs
        import requests

        url = f"https://api.elevenlabs.io/v1/text-to-speech/{self._config.elevenlabs_voice_id}"
        headers = {
            "xi-api-key": self._config.elevenlabs_api_key,
            "Content-Type": "application/json",
        }
        payload = {"text": text, "model_id": "eleven_multilingual_v2"}

        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()

        with open(output_path, "wb") as f:
            f.write(response.content)
        return output_path
