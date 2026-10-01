# Mimir — backend

Сервер Mimir: корпоративная DLP-система с транспортом защищённого
мессенджера. FastAPI + PostgreSQL. Архитектура — `mimir_architecture_v2.md`,
схема данных и решения по ней — `mimir_db_migration_contract.md`.

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt        # сервер
pip install -r requirements-dev.txt    # + автотесты (для разработки)

cp .env.example .env                   # и заполнить, см. комментарии внутри
```

Дополнительно, только если нужно:
`requirements-ml.txt` — локальная нейросеть (PyTorch, ~2 ГБ; включается
`LOAD_LOCAL_MODEL=true`), `requirements-voice.txt` — голосовой модуль
(API его не использует).

## База данных

PostgreSQL 16 в Docker, схема — файлы `migrations/NNN_*.sql`.

```bash
docker compose up -d db        # локальный PostgreSQL (mimir/mimir/mimir)
python -m core.migrate         # применить новые миграции (повторный запуск безопасен)
```

Правило: применённый файл `migrations/NNN_*.sql` не редактируется —
изменения схемы только новым файлом со следующим номером.

## Запуск

```bash
uvicorn api.server:app --reload
```

За обратным прокси (Nginx) добавьте `--proxy-headers --forwarded-allow-ips=<адрес прокси>`:
иначе сервер будет видеть адрес прокси вместо адреса клиента, и лимит
попыток входа по IP станет общим для всех пользователей.

Интерактивная документация всех эндпоинтов: http://localhost:8000/docs

## Автотесты

Тесты работают с настоящим PostgreSQL, но с отдельной базой, которая
очищается перед каждым тестом. Создать её один раз:

```bash
docker compose exec db createdb -U mimir mimir_test
pytest
```

## Структура

```
api/
  server.py      — сборка приложения: жизненный цикл, CORS, подключение маршрутов
  deps.py        — экземпляры сторов, текущий пользователь, проверки прав
  schemas.py     — модели запросов/ответов
  routes/        — маршруты по областям (auth, contacts, messages,
                   moderation, orgs, org_dlp, assistant)
core/
  db.py, migrate.py          — подключение к PostgreSQL, транзакции, миграции
  *_store.py                 — хранилища (по одному на сущность)
  message_parser.py,
  message_bridge.py,
  dlp_features.py,
  dlp_heuristics.py          — DLP: признаки сообщения и их классификация
  mimir.py, router.py,
  memory.py, config.py       — ассистент Мимир и настройки
models/   — claude_adapter (Claude API), local_model (PyTorch-классификатор)
voice/    — голосовой модуль (не подключён к API)
migrations/ — схема БД
tests/      — автотесты (pytest)
```

## Эндпоинты

Все, кроме `/health`, `/auth/register`, `/auth/login` и
`/link-whitelist/default`, требуют `Authorization: Bearer <token>`.

**Авторизация.** Пароль — от 8 символов, сессия действует 30 дней.
После 5 неудачных попыток входа по одному email (или 20 с одного IP) за
15 минут вход временно закрыт — ответ `429` с заголовком `Retry-After`.
- `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`
- `POST /auth/password` `{"current_password", "new_password"}` — сменить пароль; все остальные сессии завершаются

**Пользователи.** Профиль виден только связанным: коллегам по организации,
собеседникам и тем, у кого человек в контактах.
- `GET /users/{user_id}`, `GET /users?ids=a&ids=b` — имя и email

**Контакты.**
- `POST /contacts/sync` — заменить список контактов присланным
- `POST /contacts` `{"name", "email", "phone"}` — добавить один (если email принадлежит пользователю Мимира, контакт с ним сопоставляется)
- `GET /contacts`, `DELETE /contacts/{contact_id}`

**Сообщения** (с DLP-проверкой на отправке).
- `POST /messages/send` — multipart/form-data: `recipient_ids` (повторяющееся поле), `text`, `files`, `device_id`. Исходящий THREAT → ответ `pending_moderation` и удержание до решения officer'а; входящий THREAT → сообщение доставляется, получатель изолируется
- `GET /conversations` — список чатов с последним сообщением, свежие первыми
- `GET /conversations/{conversation_key}/messages` — сообщения чата (и группового)
- `GET /messages/history/{other_user_id}` — переписка 1-на-1
- `GET /messages/inbox` — общая лента всех сообщений
- `GET /messages/{message_id}/attachments/{attachment_id}` — скачать вложение (получатель — только доставленного; officer — удержанного в своей организации)

Списки постраничные: `?limit=50` (до 200) и `?before=<next_before из прошлого ответа>`.
Первая страница — самые свежие, внутри страницы — от старых к новым.

**Модерация** (security_officer своей организации).
- `GET /moderation/pending` — очередь удержанных
- `POST /moderation/{hold_id}/approve`, `POST /moderation/{hold_id}/reject` — тело `{"reviewer_confidence": "confident" | "unsure"}` по желанию
- `GET /moderation/decisions` — журнал решений
- `GET /moderation/anomaly-summary` — сводка ANOMALY по сотрудникам
- `GET /moderation/isolated` — изолированные аккаунты
- `POST /moderation/isolated/{user_id}/lift` — снять изоляцию, тело `{"verdict": "threat_confirmed" | "false_positive", "reviewer_confidence": ...}`; изолированного officer'а снимает владелец или его заместитель
- `GET /moderation/isolation-decisions` — журнал вердиктов по изоляциям

**Организации и роли.**
- `POST /orgs` — создать (создатель — владелец и первый security_officer)
- `POST /orgs/{org_id}/join`, `GET /orgs/{org_id}/pending`, `POST /orgs/memberships/{id}/approve`, `POST /orgs/memberships/{id}/reject`
- `GET /me/membership` — своё активное членство
- `GET /orgs/{org_id}/members` — состав организации
- `POST /orgs/{org_id}/officers` `{"user_id"}`, `DELETE /orgs/{org_id}/officers/{user_id}` — назначить/снять officer'а (владелец или заместитель)
- `GET|PUT|DELETE /orgs/{org_id}/deputy` — заместитель владельца (назначает и снимает только владелец)

**DLP-базы организации** (security_officer; удаление мягкое — запись остаётся для статистики).
- `/orgs/{org_id}/watchlist` — домены под наблюдением
- `/orgs/{org_id}/link-whitelist`, `GET /link-whitelist/default` — разрешённые ссылки
- `/orgs/{org_id}/devices` — зарегистрированные устройства
- `/orgs/{org_id}/access/legitimate`, `/orgs/{org_id}/access/elevated` — согласованный доступ и повышенные права

Каждая группа: `POST` — добавить, `GET` — список, `DELETE .../{entry_id}` — убрать.

**Ассистент Мимир.**
- `POST /chat` `{"message"}` → `{"reply"}`; `POST /session/reset`
- `POST /sensor-event` `{"features": [...]}` — классификация (нужна локальная сеть)
- `WS /ws/chat` — потоковый чат; первым сообщением `{"token": "..."}`

**Служебное.** `GET /health`

## Датасет для обучения классификатора

Представление `dlp_dataset` в БД: каждое DLP-событие (24 признака) и
метка человека — `threat` / `not_threat` / `NULL` (не размечено). Метки
дают решения модерации (исходящие) и вердикты при снятии изоляции
(входящие). Уровень эвристики (`level`) — не метка, а её догадка.

```sql
SELECT * FROM dlp_dataset WHERE label IS NOT NULL;
```
