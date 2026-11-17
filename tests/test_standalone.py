"""Standalone-аккаунты (без одобренного членства) и DLP — аудит Б7.

Правила (mimir_account_linkage_v1.md §2, mimir_e2ee_dlp_model_v1.md §3):
- Р4: о человеке, который просто пользуется мессенджером, DLP-данные не
  собираются;
- Р5: переписку standalone-аккаунтов сервер не проверяет — ни исходящую,
  ни входящую;
- standalone -> сотрудник проверяется DLP организации ПОЛУЧАТЕЛЯ (защита
  компании, а не надзор за отправителем).
"""

from pathlib import Path

from api import deps
from core import db

PHISH = "жми http://evil-phish.example/login"

MIGRATION_004 = (
    Path(__file__).resolve().parent.parent
    / "migrations" / "004_remove_standalone_dlp_events.sql"
)


def _dlp_rows(user_id: str | None = None) -> list[dict]:
    sql = "SELECT subject_user_id, is_incoming, level FROM dlp_event_records"
    params: tuple = ()
    if user_id is not None:
        sql += " WHERE subject_user_id = %s"
        params = (user_id,)
    with db.transaction() as conn:
        return conn.execute(sql, params).fetchall()


def _isolation_count() -> int:
    with db.transaction() as conn:
        return conn.execute("SELECT count(*) AS n FROM isolation_records").fetchone()["n"]


def test_standalone_to_standalone_collects_nothing(api, corp):
    """Два standalone переписываются, в т.ч. с фишинговой ссылкой и
    вложением — ни одной DLP-записи, никакой изоляции, всё доставлено."""
    solo, h_solo = api.register("solo@gmail.com", "Solo")
    docx = [("files", ("a.docx", b"PK\x03\x04 dummy", "application/octet-stream"))]

    assert api.send(corp["h_ext"], [solo], PHISH).status_code == 200
    assert api.send(h_solo, [corp["ext"]], "ответ " + PHISH).status_code == 200
    assert api.send(h_solo, [corp["ext"]], "файл", files=docx).status_code == 200

    assert _dlp_rows() == []
    assert _isolation_count() == 0
    assert len(api.inbox(h_solo)) == 3
    assert not deps.isolation_store.is_isolated(solo)
    assert not deps.isolation_store.is_isolated(corp["ext"])


def test_standalone_to_employee_phishing_is_checked(api, corp):
    """standalone -> сотрудник с фишинговой ссылкой: проверка по правилам
    организации получателя срабатывает, запись есть, субъект — сотрудник;
    о standalone-отправителе не записано ничего."""
    r = api.send(corp["h_ext"], [corp["emp"]], PHISH)
    assert r.status_code == 200, "входящий фишинг доставляется (fail-open)"

    rows = _dlp_rows()
    assert rows, "входящая проверка сотрудника должна записаться"
    assert {row["subject_user_id"] for row in rows} == {corp["emp"]}
    assert all(row["is_incoming"] for row in rows)
    assert any(row["level"] == "threat" for row in rows)
    assert deps.isolation_store.is_isolated(corp["emp"])
    assert _dlp_rows(corp["ext"]) == []


def test_employee_to_standalone_no_incoming_record(api, corp):
    """сотрудник -> standalone: исходящая проверка сотрудника есть,
    входящей записи на standalone-получателя нет."""
    r = api.send(corp["h_emp"], [corp["ext"]], "привет")
    assert r.status_code == 200
    assert r.json().get("status") != "pending_moderation"

    assert _dlp_rows(corp["ext"]) == []
    rows = _dlp_rows()
    assert rows and all(
        row["subject_user_id"] == corp["emp"] and not row["is_incoming"] for row in rows
    )


def test_mixed_recipients_only_employee_checked(api, corp):
    """Одно сообщение от standalone сразу сотруднику и standalone —
    проверка ровно одна, у сотрудника; standalone-получатель изоляцию не
    получает и записей о нём нет."""
    solo, _ = api.register("solo@gmail.com", "Solo")
    assert api.send(corp["h_ext"], [corp["emp"], solo], PHISH).status_code == 200

    rows = _dlp_rows()
    assert [row["subject_user_id"] for row in rows] == [corp["emp"]]
    assert not deps.isolation_store.is_isolated(solo)


def test_pending_membership_counts_as_standalone(api, corp):
    """Заявка в организацию ещё не одобрена — аккаунт остаётся standalone:
    входящее ему не проверяется."""
    newbie, h_newbie = api.register("newbie@corp.com", "Newbie")
    assert api.c.post(f"/orgs/{corp['org']}/join", headers=h_newbie).status_code == 200

    assert api.send(corp["h_ext"], [newbie], PHISH).status_code == 200
    assert _dlp_rows() == []
    assert not deps.isolation_store.is_isolated(newbie)


def test_migration_004_removes_only_standalone_records(api, corp):
    """Миграция 004 удаляет записи, накопленные по старому правилу
    («входящее проверяется всегда»): записи standalone-субъектов уходят,
    записи сотрудников и метка датасета остаются."""
    # Запись сотрудника по новым правилам + изоляция со снятием (метка).
    api.send(corp["h_ext"], [corp["emp"]], PHISH)
    r = api.c.post(
        f"/moderation/isolated/{corp['emp']}/lift",
        json={"verdict": "threat_confirmed"}, headers=corp["h_owner"],
    )
    assert r.status_code == 200, r.text

    # Имитация старой записи о standalone: копия записи сотрудника с
    # другим record_id и субъектом-standalone.
    with db.transaction() as conn:
        conn.execute(
            "CREATE TEMP TABLE old_rec ON COMMIT DROP AS "
            "SELECT * FROM dlp_event_records LIMIT 1"
        )
        conn.execute(
            "UPDATE old_rec SET record_id = 'legacy-standalone', subject_user_id = %s",
            (corp["ext"],),
        )
        conn.execute("INSERT INTO dlp_event_records SELECT * FROM old_rec")
    assert _dlp_rows(corp["ext"])
    employee_rows_before = _dlp_rows(corp["emp"])

    with db.transaction() as conn:
        conn.execute(MIGRATION_004.read_text(encoding="utf-8"))
        labeled = conn.execute(
            "SELECT count(*) AS n FROM dlp_dataset WHERE label IS NOT NULL"
        ).fetchone()["n"]

    assert _dlp_rows(corp["ext"]) == []
    assert _dlp_rows(corp["emp"]) == employee_rows_before
    assert labeled == 1
