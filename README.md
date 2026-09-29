# Mimir — backend

Реализация ядра по `mimir_architecture.md`: FastAPI-сервер, роутер между
локальной сетью и Claude API, память сессий, голосовой модуль.

## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# затем впишите ANTHROPIC_API_KEY в .env
```

## Запуск

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
```

## Эндпоинты

- `GET  /health` — проверка живости и текущей модели
- `POST /chat` — `{"message": "..."}` -> `{"reply": "..."}` (нужен `Authorization: Bearer <token>`; память разговора привязана к пользователю из токена)
- `POST /sensor-event` — `{"features": [0.1, 0.2, ...]}` (нужен токен)
  -> классификация локальной сетью (+ анализ Claude при аномалии/угрозе)
- `POST /session/reset` — очистить память своего разговора (нужен токен)
- `WS   /ws/chat` — потоковый чат; первым сообщением отправить `{"token": "..."}`, сервер ответит `{"event": "authenticated"}` (иначе закроет с кодом 1008)

## Структура

Соответствует `mimir_architecture.md`:

```
core/    — config, memory, router, mimir (главный класс)
models/  — claude_adapter (Claude API), local_model (PyTorch-классификатор)
voice/   — speech_to_text (Whisper), text_to_speech (pyttsx3/ElevenLabs), voice_handler
api/     — server.py (FastAPI, REST + WebSocket)
```

## Заметки

- `models/local_model.py` содержит рабочий каркас классификатора на
  случайных весах — его нужно дообучить на реальных данных сенсоров
  и передать путь к весам в `Mimir(local_model_weights="...")`.
- `voice/text_to_speech.py` поддерживает `pyttsx3` (офлайн) и `elevenlabs`
  (нужен `ELEVENLABS_API_KEY`/`ELEVENLABS_VOICE_ID` в `.env`) — выбор
  через `voice.provider` в `config.yaml`.
- CORS в `api/server.py` открыт на `*` для разработки — сузьте домены в проде.
