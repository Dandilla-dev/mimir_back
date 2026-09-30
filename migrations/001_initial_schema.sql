-- =============================================================================
-- Mimir — начальная SQL-схема (PostgreSQL 16)
-- Файл: migrations/001_initial_schema.sql
--
-- Источник: mimir_db_migration_contract.md + прямое чтение всех десяти
-- core/*_store.py на коммите d05c628 ("eight", mimir_back/master).
--
-- Принятые в схеме решения по открытым вопросам контракта помечены
-- [РЕШЕНИЕ N] — каждое можно откатить независимо от остальных.
--
-- Общие правила:
--   * PK — существующие строковые id (secrets.token_hex), TEXT, без изменений.
--   * Время — TIMESTAMPTZ везде (вместо float time.time()) [РЕШЕНИЕ 1].
--   * Списки причин — JSONB-массив строк [РЕШЕНИЕ 2].
--   * ENUM-ы — TEXT + CHECK, а не CREATE TYPE: новое значение = правка CHECK,
--     без ALTER TYPE; тот же вид, что str-Enum в Python.
--   * Драйвер синхронный (psycopg 3 sync), §9.7 архитектуры.
--
-- Файл применяется через `python -m core.migrate` — он сам оборачивает
-- файл и отметку в schema_migrations в одну транзакцию, поэтому здесь
-- нет BEGIN/COMMIT.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. users  (core/auth_store.py)
-- -----------------------------------------------------------------------------
CREATE TABLE users (
    user_id        TEXT        PRIMARY KEY,
    email          TEXT        NOT NULL,
    name           TEXT        NOT NULL,
    password_hash  TEXT        NOT NULL,
    salt           TEXT        NULL,          -- NULL после перехода на bcrypt/argon2 (соль внутри хэша)
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT users_email_unique     UNIQUE (email),
    -- register() нормализует email: strip().lower() — закрепляем на уровне БД
    CONSTRAINT users_email_normalized CHECK (email = lower(btrim(email)) AND email LIKE '%@%')
);

-- Сессии [РЕШЕНИЕ 3]: отдельная таблица в той же БД, без Redis на этапе прототипа.
-- Хранится sha256(token), а не сам токен: утечка дампа БД не даёт войти.
CREATE TABLE sessions (
    token_hash  TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NULL          -- NULL = бессрочно (как сейчас в коде)
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- -----------------------------------------------------------------------------
-- 2. organizations, memberships  (core/org_store.py)
-- -----------------------------------------------------------------------------
CREATE TABLE organizations (
    org_id      TEXT        PRIMARY KEY,
    name        TEXT        NOT NULL CHECK (btrim(name) <> ''),
    created_by  TEXT        NOT NULL REFERENCES users (user_id),  -- = владелец (is_owner)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    membership_id  TEXT        PRIMARY KEY,
    user_id        TEXT        NOT NULL REFERENCES users (user_id),
    org_id         TEXT        NOT NULL REFERENCES organizations (org_id),
    role           TEXT        NOT NULL CHECK (role   IN ('member', 'security_officer')),
    status         TEXT        NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by     TEXT        NULL REFERENCES users (user_id),
    decided_at     TIMESTAMPTZ NULL,

    -- pending <=> решения ещё нет
    CONSTRAINT memberships_decision_consistent CHECK (
        (status = 'pending') = (decided_by IS NULL AND decided_at IS NULL)
    )
);

-- _pending_or_approved_in_org(): не больше одной pending/approved записи на
-- (user, org); rejected копятся свободно (повторная заявка после отказа).
CREATE UNIQUE INDEX memberships_one_open_per_org
    ON memberships (user_id, org_id)
    WHERE status IN ('pending', 'approved');

-- approve(): "один пользователь — не более одной активной организации"
-- (mimir_account_linkage_v1.md §4 п.3). Сейчас это проверка в Python,
-- здесь — гарантия БД, закрывает гонку двух одновременных approve.
-- Он же — индекс под get_active_membership(user_id), самый частый запрос.
CREATE UNIQUE INDEX memberships_one_active_per_user
    ON memberships (user_id)
    WHERE status = 'approved';

-- list_pending(org_id) ORDER BY requested_at
CREATE INDEX memberships_pending_by_org
    ON memberships (org_id, requested_at)
    WHERE status = 'pending';

-- -----------------------------------------------------------------------------
-- 3. contacts  (core/contacts_store.py) — перенос как есть, без UNIQUE
-- -----------------------------------------------------------------------------
CREATE TABLE contacts (
    contact_id      TEXT        PRIMARY KEY,
    owner_user_id   TEXT        NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    name            TEXT        NOT NULL CHECK (btrim(name) <> ''),
    phone           TEXT        NULL,
    email           TEXT        NULL CHECK (email IS NULL OR email = lower(btrim(email))),
    linked_user_id  TEXT        NULL REFERENCES users (user_id) ON DELETE SET NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX contacts_owner_idx ON contacts (owner_user_id);

-- -----------------------------------------------------------------------------
-- 4. messages, message_recipients, attachments  (core/messages_store.py)
-- -----------------------------------------------------------------------------
-- [РЕШЕНИЕ 4, подтверждено] Модерация по варианту (б) контракта: сообщение пишется в
-- messages сразу, видимость решает status. Причина, найденная в коде
-- api/server.py: dlp_events_store.add_check() вызывается ДО hold(), т.е.
-- DLP-события исходящего THREAT ссылаются на message_id, которого при
-- варианте (а) в messages нет вообще (а у отклонённых — не будет никогда).
-- При (а) FK dlp_event_records -> messages невозможен.
--
-- inbox()/conversation_history() обязаны фильтровать status = 'delivered'.
CREATE TABLE messages (
    message_id        TEXT        PRIMARY KEY,
    sender_id         TEXT        NOT NULL REFERENCES users (user_id),
    text              TEXT        NULL DEFAULT '',   -- NULL только после стирания (см. ниже)
    -- sha256 текста, считается при создании. Остаётся после стирания:
    -- факт и отпечаток попытки доказуемы, содержимое — нет.
    text_sha256       TEXT        NOT NULL,
    device_id         TEXT        NULL,       -- устройство ОТПРАВИТЕЛЯ; NULL = клиент не прислал
    -- [РЕШЕНИЕ 5] денормализованный ключ диалога = _conversation_key()
    -- (отсортированные уникальные id отправителя и получателей через ':').
    -- Считается в приложении той же функцией. Точное совпадение набора
    -- участников — простой WHERE по индексу, без GROUP BY ... HAVING.
    conversation_key  TEXT        NOT NULL,
    status            TEXT        NOT NULL DEFAULT 'delivered'
                      CHECK (status IN ('pending_moderation', 'delivered', 'rejected')),
    sent_at           TIMESTAMPTZ NOT NULL DEFAULT now(),   -- момент build_message()
    delivered_at      TIMESTAMPTZ NULL,                     -- для одобренных — позже sent_at
    -- [РЕШЕНИЕ 10] Отклонённые: текст и вложения хранятся сутки с момента
    -- отклонения, затем стираются фоновой задачей (раз в час). Метаданные,
    -- получатели, хэши, DLP-события и решение остаются навсегда.
    rejected_at       TIMESTAMPTZ NULL,
    content_purged_at TIMESTAMPTZ NULL,

    CONSTRAINT messages_delivered_consistent CHECK (
        (status = 'delivered') = (delivered_at IS NOT NULL)
    ),
    CONSTRAINT messages_rejected_consistent CHECK (
        (status = 'rejected') = (rejected_at IS NOT NULL)
    ),
    -- стирать можно только отклонённые; стёртый текст обязан быть NULL,
    -- нестёртый — не NULL
    CONSTRAINT messages_purge_consistent CHECK (
        (content_purged_at IS NULL OR status = 'rejected')
        AND ((content_purged_at IS NULL) = (text IS NOT NULL))
    )
);
CREATE INDEX messages_conversation_idx ON messages (conversation_key, sent_at)
    WHERE status = 'delivered';
CREATE INDEX messages_sender_idx ON messages (sender_id, sent_at)
    WHERE status = 'delivered';
-- Очередь фоновой задачи стирания:
--   UPDATE messages SET text = NULL, content_purged_at = now()
--    WHERE status = 'rejected' AND content_purged_at IS NULL
--      AND rejected_at < now() - interval '1 day'
--   RETURNING message_id;
-- + для этих message_id: attachments SET content = NULL, storage_uri = NULL,
--   purged_at = now() (при S3 — сначала удалить объект, потом строку).
CREATE INDEX messages_purge_queue_idx ON messages (rejected_at)
    WHERE status = 'rejected' AND content_purged_at IS NULL;

CREATE TABLE message_recipients (
    message_id    TEXT NOT NULL REFERENCES messages (message_id) ON DELETE CASCADE,
    recipient_id  TEXT NOT NULL REFERENCES users (user_id),
    PRIMARY KEY (message_id, recipient_id)
);
CREATE INDEX message_recipients_recipient_idx ON message_recipients (recipient_id);

-- [РЕШЕНИЕ 6] Вложения: ровно одно из двух — байты в БД (прототип) или
-- ссылка на объектное хранилище (S3, позже). Переход на S3 не ломает схему.
CREATE TABLE attachments (
    attachment_id   TEXT   PRIMARY KEY,
    message_id      TEXT   NOT NULL REFERENCES messages (message_id) ON DELETE CASCADE,
    filename        TEXT   NOT NULL,
    size_bytes      BIGINT NOT NULL CHECK (size_bytes >= 0),
    content_sha256  TEXT   NOT NULL,
    content         BYTEA  NULL,
    storage_uri     TEXT   NULL,
    purged_at       TIMESTAMPTZ NULL,   -- см. [РЕШЕНИЕ 10]; content_sha256 и size_bytes остаются

    -- до стирания — ровно одно место хранения, после — ни одного
    CONSTRAINT attachments_one_location CHECK (
        CASE WHEN purged_at IS NULL
             THEN (content IS NULL) <> (storage_uri IS NULL)
             ELSE content IS NULL AND storage_uri IS NULL
        END
    )
);
CREATE INDEX attachments_message_idx ON attachments (message_id);

-- -----------------------------------------------------------------------------
-- 5. moderation_holds  (core/moderation_store.py)
-- -----------------------------------------------------------------------------
-- Строка удержания не удаляется при resolve(), а получает resolved_at —
-- это даёт FK из moderation_decisions (см. раздел 10).
-- Атомарный resolve() = UPDATE ... WHERE resolved_at IS NULL RETURNING:
-- второй officer получит 0 строк -> 404, как сейчас.
CREATE TABLE moderation_holds (
    hold_id         TEXT        PRIMARY KEY,
    message_id      TEXT        NOT NULL UNIQUE REFERENCES messages (message_id),
    -- [РЕШЕНИЕ 7, подтверждено] снимок организации отправителя на момент
    -- поступления сообщения на сервер. Решает офицер ЭТОЙ организации, даже
    -- если отправителя позже исключили/перевели. /moderation/pending и
    -- approve/reject проверяют право по этому полю, а не по живому членству.
    org_id          TEXT        NOT NULL REFERENCES organizations (org_id),
    threat_reasons  JSONB       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(threat_reasons) = 'array'),
    held_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ NULL
);
-- list_pending() ORDER BY held_at
CREATE INDEX moderation_holds_open_idx ON moderation_holds (org_id, held_at)
    WHERE resolved_at IS NULL;

-- -----------------------------------------------------------------------------
-- 6. isolation_records  (core/isolation_store.py)
-- -----------------------------------------------------------------------------
-- [РЕШЕНИЕ 8, подтверждено] С историей: isolation_id — PK, user_id — обычное поле.
-- Сейчас повторная изоляция после снятия ПЕРЕЗАПИСЫВАЕТ старую запись;
-- для security-продукта история нужна, задним числом её не восстановить.
-- Инвариант "не больше одной активной изоляции" — частичный UNIQUE.
CREATE TABLE isolation_records (
    isolation_id    TEXT        PRIMARY KEY,
    user_id         TEXT        NOT NULL REFERENCES users (user_id),
    threat_reasons  JSONB       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(threat_reasons) = 'array'),
    isolated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    lifted_at       TIMESTAMPTZ NULL,
    lifted_by       TEXT        NULL REFERENCES users (user_id),

    CONSTRAINT isolation_lift_consistent CHECK ((lifted_at IS NULL) = (lifted_by IS NULL))
);
-- is_isolated(user_id) + гарантия одной активной записи.
-- isolate() при активной изоляции = INSERT ... ON CONFLICT (user_id)
-- WHERE lifted_at IS NULL DO UPDATE (дописать причины без дублей).
CREATE UNIQUE INDEX isolation_one_active_per_user
    ON isolation_records (user_id)
    WHERE lifted_at IS NULL;
-- list_active() ORDER BY isolated_at
CREATE INDEX isolation_active_by_time
    ON isolation_records (isolated_at)
    WHERE lifted_at IS NULL;

-- -----------------------------------------------------------------------------
-- 7. dlp_event_records  (core/dlp_events_store.py + DLPEvent из dlp_features.py)
-- -----------------------------------------------------------------------------
-- Одна строка = одно DLPEvent + его классификация. Поля DLPEvent развёрнуты
-- в колонки (не JSON) — это и есть будущий датасет, по ним нужны WHERE.
CREATE TABLE dlp_event_records (
    record_id        TEXT        PRIMARY KEY,
    -- DEFERRABLE: сообщение, DLP-события и hold пишутся одной транзакцией
    -- в любом порядке (сейчас add_check() идёт раньше hold()/store()).
    message_id       TEXT        NOT NULL REFERENCES messages (message_id)
                                 DEFERRABLE INITIALLY DEFERRED,
    subject_user_id  TEXT        NOT NULL REFERENCES users (user_id),
    is_incoming      BOOLEAN     NOT NULL,
    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- классификация (dlp_heuristics.HeuristicResult)
    level            TEXT        NOT NULL CHECK (level IN ('normal', 'anomaly', 'threat')),
    threat_reasons   JSONB       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(threat_reasons)  = 'array'),
    anomaly_reasons  JSONB       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(anomaly_reasons) = 'array'),

    -- Блок 1: участники
    counterparty_external            BOOLEAN NOT NULL,
    counterparty_new                 BOOLEAN NOT NULL,
    counterparty_address_personal    BOOLEAN NOT NULL,
    counterparty_domain_watchlisted  BOOLEAN NOT NULL,
    -- Блок 2: содержимое / вложение
    has_attachment                   BOOLEAN NOT NULL DEFAULT false,
    attachment_size_bytes            BIGINT  NOT NULL DEFAULT 0 CHECK (attachment_size_bytes >= 0),
    attachment_category              TEXT    NOT NULL DEFAULT 'none'
        CHECK (attachment_category IN ('none', 'document', 'archive', 'image', 'executable')),
    has_macro_or_executable_code     BOOLEAN NOT NULL DEFAULT false,
    confidentiality_marker_found     BOOLEAN NOT NULL DEFAULT false,
    attachment_password_protected    BOOLEAN NOT NULL DEFAULT false,
    has_external_link                BOOLEAN NOT NULL DEFAULT false,
    link_not_whitelisted             BOOLEAN NOT NULL DEFAULT false,
    -- Блок 3: время
    event_time                       TIMESTAMPTZ NOT NULL,
    is_non_working_day               BOOLEAN NOT NULL DEFAULT false,
    -- NULL = HR-интеграция недоступна; это ТРЕТЬЕ состояние, не false.
    -- Специально без NOT NULL и без DEFAULT.
    near_termination                 BOOLEAN NULL,
    on_official_leave                BOOLEAN NULL,
    -- Блок 5: устройство
    device_unregistered              BOOLEAN NOT NULL DEFAULT false,
    -- Блок 6: роль и доступ
    lacks_legitimate_access          BOOLEAN NOT NULL DEFAULT false,
    has_elevated_rights              BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX dlp_events_message_idx ON dlp_event_records (message_id);                  -- list_for_message
CREATE INDEX dlp_events_subject_idx ON dlp_event_records (subject_user_id, recorded_at); -- list_for_subject
CREATE INDEX dlp_events_level_idx   ON dlp_event_records (level, recorded_at);           -- list_by_level (ANOMALY-сводка)
-- list_all() с курсорной пагинацией: WHERE (recorded_at, record_id) > (:ts, :id)
CREATE INDEX dlp_events_cursor_idx  ON dlp_event_records (recorded_at, record_id);

-- -----------------------------------------------------------------------------
-- 8. watchlisted_domains, whitelisted_link_domains  (core/watchlist_store.py)
-- -----------------------------------------------------------------------------
-- DEFAULT_WHITELISTED_LINK_DOMAINS остаётся константой в коде, не таблица.
-- UNIQUE(org_id, domain) одновременно и индекс под lookup на каждое сообщение.
CREATE TABLE watchlisted_domains (
    entry_id  TEXT        PRIMARY KEY,
    org_id    TEXT        NOT NULL REFERENCES organizations (org_id),
    domain    TEXT        NOT NULL CHECK (domain = lower(btrim(domain)) AND domain <> ''),
    reason    TEXT        NOT NULL DEFAULT '',
    added_by  TEXT        NOT NULL REFERENCES users (user_id),
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- [РЕШЕНИЕ 11] Мягкое удаление: "удалить/отозвать" = заполнить
    -- revoked_at/revoked_by. Проверки на каждое сообщение фильтруют
    -- revoked_at IS NULL. Уникальность — только среди действующих.
    revoked_at  TIMESTAMPTZ NULL,
    revoked_by  TEXT        NULL REFERENCES users (user_id),
    CONSTRAINT watchlisted_domains_revoke_consistent CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
-- уникальность + индекс под is_domain_watchlisted(org_id, domain)
CREATE UNIQUE INDEX watchlisted_domains_active_unique
    ON watchlisted_domains (org_id, domain) WHERE revoked_at IS NULL;

CREATE TABLE whitelisted_link_domains (
    entry_id  TEXT        PRIMARY KEY,
    org_id    TEXT        NOT NULL REFERENCES organizations (org_id),
    domain    TEXT        NOT NULL CHECK (domain = lower(btrim(domain)) AND domain <> ''),
    reason    TEXT        NOT NULL DEFAULT '',
    added_by  TEXT        NOT NULL REFERENCES users (user_id),
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ NULL,        -- [РЕШЕНИЕ 11]
    revoked_by  TEXT        NULL REFERENCES users (user_id),
    CONSTRAINT whitelisted_link_domains_revoke_consistent CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX whitelisted_link_domains_active_unique
    ON whitelisted_link_domains (org_id, domain) WHERE revoked_at IS NULL;

-- -----------------------------------------------------------------------------
-- 9. registered_devices, access_grants  (core/access_store.py)
-- -----------------------------------------------------------------------------
CREATE TABLE registered_devices (
    entry_id       TEXT        PRIMARY KEY,
    org_id         TEXT        NOT NULL REFERENCES organizations (org_id),
    device_id      TEXT        NOT NULL CHECK (device_id = btrim(device_id) AND device_id <> ''),
    user_id        TEXT        NOT NULL REFERENCES users (user_id),   -- владелец устройства
    label          TEXT        NOT NULL DEFAULT '',
    registered_by  TEXT        NOT NULL REFERENCES users (user_id),
    registered_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ NULL,     -- [РЕШЕНИЕ 11] снято с учёта
    revoked_by     TEXT        NULL REFERENCES users (user_id),
    CONSTRAINT registered_devices_revoke_consistent CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX registered_devices_active_unique
    ON registered_devices (org_id, device_id) WHERE revoked_at IS NULL;

-- [РЕШЕНИЕ 9] Одна таблица с grant_type вместо двух: новый тип гранта =
-- новое значение в CHECK, без новой таблицы и нового набора методов.
CREATE TABLE access_grants (
    entry_id    TEXT        PRIMARY KEY,
    org_id      TEXT        NOT NULL REFERENCES organizations (org_id),
    user_id     TEXT        NOT NULL REFERENCES users (user_id),
    grant_type  TEXT        NOT NULL CHECK (grant_type IN ('legitimate_access', 'elevated_rights')),
    granted_by  TEXT        NOT NULL REFERENCES users (user_id),
    note        TEXT        NOT NULL DEFAULT '',
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ NULL,        -- [РЕШЕНИЕ 11] отозван
    revoked_by  TEXT        NULL REFERENCES users (user_id),
    CONSTRAINT access_grants_revoke_consistent CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX access_grants_active_unique
    ON access_grants (org_id, user_id, grant_type) WHERE revoked_at IS NULL;

-- -----------------------------------------------------------------------------
-- 10. moderation_decisions  (core/moderation_decisions_store.py)
-- -----------------------------------------------------------------------------
CREATE TABLE moderation_decisions (
    decision_id          TEXT        PRIMARY KEY,
    hold_id              TEXT        NOT NULL UNIQUE REFERENCES moderation_holds (hold_id),
    message_id           TEXT        NOT NULL REFERENCES messages (message_id),
    -- снимки на момент решения (см. докстринг стора)
    sender_id            TEXT        NOT NULL REFERENCES users (user_id),
    -- копируется из moderation_holds.org_id (РЕШЕНИЕ 7), не из живого
    -- членства — поэтому больше не бывает NULL
    org_id               TEXT        NOT NULL REFERENCES organizations (org_id),
    decided_by           TEXT        NOT NULL REFERENCES users (user_id),
    decision             TEXT        NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reviewer_confidence  TEXT        NULL CHECK (reviewer_confidence IN ('confident', 'unsure')),
    threat_reasons       JSONB       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(threat_reasons) = 'array'),
    held_at              TIMESTAMPTZ NOT NULL,
    decided_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX moderation_decisions_message_idx  ON moderation_decisions (message_id);              -- get_by_message
CREATE INDEX moderation_decisions_reviewer_idx ON moderation_decisions (decided_by, decided_at);   -- list_by_reviewer
CREATE INDEX moderation_decisions_org_idx      ON moderation_decisions (org_id, decided_at DESC); -- /moderation/decisions

-- Журнал доказательной базы: только INSERT. Закреплено на уровне БД,
-- не только отсутствием эндпоинта.
CREATE FUNCTION forbid_modification() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP;
END;
$$;

CREATE TRIGGER moderation_decisions_append_only
    BEFORE UPDATE OR DELETE ON moderation_decisions
    FOR EACH ROW EXECUTE FUNCTION forbid_modification();
