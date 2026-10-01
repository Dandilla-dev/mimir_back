-- =============================================================================
-- Mimir — миграция 003: учёт попыток входа (защита от перебора паролей).
--
-- Каждая попытка /auth/login пишется сюда — удачная или нет. Вход
-- временно блокируется (HTTP 429), если за последние 15 минут:
--   * по одному email — 5 неудачных попыток подряд (после последнего
--     удачного входа);
--   * с одного IP — 20 неудачных попыток по любым email.
-- Пороги — константы в core/auth_store.py. Записи старше суток удаляет
-- фоновая уборка (api/server.py).
--
-- Пишется и email, которого нет в базе: блокировка по несуществующему
-- адресу ведёт себя так же, как по существующему, — по ответам нельзя
-- понять, зарегистрирован ли email.
-- =============================================================================

CREATE TABLE login_attempts (
    attempt_id    BIGSERIAL   PRIMARY KEY,
    email         TEXT        NOT NULL,     -- нормализованный (lower/strip), как в users
    ip            TEXT        NULL,         -- NULL — адрес клиента неизвестен
    succeeded     BOOLEAN     NOT NULL,
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_email_idx ON login_attempts (email, attempted_at);
CREATE INDEX login_attempts_ip_idx    ON login_attempts (ip, attempted_at) WHERE NOT succeeded;
