-- =============================================================================
-- Mimir — миграция 002: роли (заместитель владельца, назначение officer'ов)
-- и вердикт человека при снятии изоляции.
--
-- Решения (2026-10-01):
--   * security_officer назначает и снимает только владелец организации
--     или его заместитель — не другой officer (скомпрометированный officer
--     не должен назначать сообщников);
--   * у владельца не больше одного действующего заместителя; заместитель
--     может всё, что только владелец (назначать/снимать officer'ов,
--     разблокировать изолированного officer'а), но не может назначить
--     своего заместителя и не может передать владение;
--   * при снятии изоляции officer указывает вердикт ("угроза подтверждена"
--     / "ложное срабатывание") — это метки датасета для входящих событий,
--     так же как moderation_decisions — для исходящих.
-- Применяется через `python -m core.migrate`.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Заместитель владельца — с историей (как мягкое удаление, [РЕШЕНИЕ 11]:
--    кто, когда назначил и снял — нужно для разбора инцидентов).
-- -----------------------------------------------------------------------------
CREATE TABLE org_deputies (
    entry_id      TEXT        PRIMARY KEY,
    org_id        TEXT        NOT NULL REFERENCES organizations (org_id),
    user_id       TEXT        NOT NULL REFERENCES users (user_id),
    appointed_by  TEXT        NOT NULL REFERENCES users (user_id),
    appointed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at    TIMESTAMPTZ NULL,
    revoked_by    TEXT        NULL REFERENCES users (user_id),
    CONSTRAINT org_deputies_revoke_consistent CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
-- не больше одного действующего заместителя на организацию
CREATE UNIQUE INDEX org_deputies_one_active
    ON org_deputies (org_id) WHERE revoked_at IS NULL;

-- -----------------------------------------------------------------------------
-- 2. Журнал смены ролей — назначение/снятие security_officer.
--    memberships.role хранит только текущее состояние; кто и когда его
--    менял — здесь. Только добавление.
-- -----------------------------------------------------------------------------
CREATE TABLE role_changes (
    change_id      TEXT        PRIMARY KEY,
    membership_id  TEXT        NOT NULL REFERENCES memberships (membership_id),
    old_role       TEXT        NOT NULL CHECK (old_role IN ('member', 'security_officer')),
    new_role       TEXT        NOT NULL CHECK (new_role IN ('member', 'security_officer')),
    changed_by     TEXT        NOT NULL REFERENCES users (user_id),
    changed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT role_changes_actual_change CHECK (old_role <> new_role)
);
CREATE INDEX role_changes_membership_idx ON role_changes (membership_id, changed_at);

CREATE TRIGGER role_changes_append_only
    BEFORE UPDATE OR DELETE ON role_changes
    FOR EACH ROW EXECUTE FUNCTION forbid_modification();

-- -----------------------------------------------------------------------------
-- 3. Какие сообщения вызвали изоляцию.
--    Изоляция копит причины от нескольких входящих THREAT (повторный THREAT
--    во время активной изоляции дописывается в ту же запись). Без этой
--    связи вердикт officer'а нельзя донести до конкретных DLP-событий.
--    FK на messages отложенный: изоляция ставится ДО сохранения сообщения,
--    в той же транзакции /messages/send.
-- -----------------------------------------------------------------------------
CREATE TABLE isolation_triggers (
    isolation_id  TEXT NOT NULL REFERENCES isolation_records (isolation_id),
    message_id    TEXT NOT NULL REFERENCES messages (message_id)
                  DEFERRABLE INITIALLY DEFERRED,
    PRIMARY KEY (isolation_id, message_id)
);
CREATE INDEX isolation_triggers_message_idx ON isolation_triggers (message_id);

-- -----------------------------------------------------------------------------
-- 4. Вердикт при снятии изоляции — журнал, только добавление
--    (зеркало moderation_decisions для входящих событий).
-- -----------------------------------------------------------------------------
CREATE TABLE isolation_decisions (
    decision_id          TEXT        PRIMARY KEY,
    isolation_id         TEXT        NOT NULL UNIQUE REFERENCES isolation_records (isolation_id),
    user_id              TEXT        NOT NULL REFERENCES users (user_id),    -- изолированный
    org_id               TEXT        NOT NULL REFERENCES organizations (org_id),
    decided_by           TEXT        NOT NULL REFERENCES users (user_id),
    verdict              TEXT        NOT NULL CHECK (verdict IN ('threat_confirmed', 'false_positive')),
    reviewer_confidence  TEXT        NULL CHECK (reviewer_confidence IN ('confident', 'unsure')),
    threat_reasons       JSONB       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(threat_reasons) = 'array'),
    isolated_at          TIMESTAMPTZ NOT NULL,
    decided_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX isolation_decisions_org_idx      ON isolation_decisions (org_id, decided_at DESC);
CREATE INDEX isolation_decisions_reviewer_idx ON isolation_decisions (decided_by, decided_at);

CREATE TRIGGER isolation_decisions_append_only
    BEFORE UPDATE OR DELETE ON isolation_decisions
    FOR EACH ROW EXECUTE FUNCTION forbid_modification();

-- -----------------------------------------------------------------------------
-- 5. Датасет: DLP-событие + метка человека, одним запросом.
--    label: 'threat' | 'not_threat' | NULL (человек не решал — событие без
--    метки, для обучения с учителем не годится).
--    Исходящие: reject = угроза, approve = ложное срабатывание.
--    Входящие: вердикт снятия изоляции, только для того, кого изолировали
--    (subject_user_id = изолированный), по сообщениям, вызвавшим изоляцию.
--    Уровень эвристики (level) — НЕ метка: это догадка эвристики, рядом
--    с правдой для сравнения.
-- -----------------------------------------------------------------------------
CREATE VIEW dlp_dataset AS
SELECT
    e.*,
    CASE
        WHEN NOT e.is_incoming AND md.decision = 'rejected'           THEN 'threat'
        WHEN NOT e.is_incoming AND md.decision = 'approved'           THEN 'not_threat'
        WHEN e.is_incoming     AND idc.verdict = 'threat_confirmed'   THEN 'threat'
        WHEN e.is_incoming     AND idc.verdict = 'false_positive'     THEN 'not_threat'
    END AS label,
    CASE
        WHEN NOT e.is_incoming AND md.decision_id  IS NOT NULL THEN 'moderation'
        WHEN e.is_incoming     AND idc.decision_id IS NOT NULL THEN 'isolation_lift'
    END AS label_source,
    COALESCE(md.reviewer_confidence, idc.reviewer_confidence) AS label_confidence
FROM dlp_event_records e
LEFT JOIN moderation_decisions md
       ON NOT e.is_incoming AND md.message_id = e.message_id
LEFT JOIN LATERAL (
    SELECT d.decision_id, d.verdict, d.reviewer_confidence
    FROM isolation_triggers t
    JOIN isolation_records r   ON r.isolation_id = t.isolation_id
    JOIN isolation_decisions d ON d.isolation_id = t.isolation_id
    WHERE e.is_incoming
      AND t.message_id = e.message_id
      AND r.user_id = e.subject_user_id
    LIMIT 1
) idc ON true;
