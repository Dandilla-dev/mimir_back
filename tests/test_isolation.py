"""Изоляция при входящем THREAT и снятие с вердиктом (метки датасета)."""

import pytest

from api import deps
from core import db

PHISH = "жми http://evil-phish.example/login"


def _isolate(api, corp, text=PHISH):
    r = api.send(corp["h_ext"], [corp["emp"]], text)
    assert r.status_code == 200, "входящий фишинг доставляется (fail-open)"
    return r.json()["message_id"]


def test_incoming_threat_isolates_recipient(api, corp):
    _isolate(api, corp)
    assert deps.isolation_store.is_isolated(corp["emp"])
    assert api.send(corp["h_emp"], [corp["emp2"]], "http://x.example").status_code == 403


def test_lift_requires_verdict(api, client, corp):
    _isolate(api, corp)
    r = client.post(f"/moderation/isolated/{corp['emp']}/lift", headers=corp["h_owner"])
    assert r.status_code == 422
    assert deps.isolation_store.is_isolated(corp["emp"])


def test_lift_with_verdict_labels_dataset(api, client, corp):
    m1 = _isolate(api, corp)
    m2 = _isolate(api, corp, "и ещё http://evil2.example/a")
    r = client.post(
        f"/moderation/isolated/{corp['emp']}/lift",
        json={"verdict": "threat_confirmed", "reviewer_confidence": "confident"},
        headers=corp["h_owner"],
    )
    assert r.status_code == 200 and r.json()["decision_id"]
    assert not deps.isolation_store.is_isolated(corp["emp"])

    with db.transaction() as conn:
        rows = conn.execute(
            "SELECT message_id, label, label_source, label_confidence FROM dlp_dataset "
            "WHERE is_incoming AND subject_user_id = %s",
            (corp["emp"],),
        ).fetchall()
    labeled = {r["message_id"]: r for r in rows if r["label"]}
    assert set(labeled) == {m1, m2}, "оба сообщения, вызвавшие изоляцию, получили метку"
    assert all(r["label"] == "threat" and r["label_source"] == "isolation_lift" for r in labeled.values())

    journal = client.get("/moderation/isolation-decisions", headers=corp["h_owner"]).json()["decisions"]
    assert len(journal) == 1 and journal[0]["verdict"] == "threat_confirmed"


def test_history_kept_and_journal_append_only(api, client, corp):
    _isolate(api, corp)
    client.post(f"/moderation/isolated/{corp['emp']}/lift", json={"verdict": "false_positive"}, headers=corp["h_owner"])
    _isolate(api, corp, "снова http://evil3.example")
    assert len(deps.isolation_store.history(corp["emp"])) == 2
    with pytest.raises(Exception, match="append-only"):
        with db.transaction() as conn:
            conn.execute("DELETE FROM isolation_decisions")


def test_isolated_officer_lifted_by_deputy_not_by_officer(api, client, corp):
    org = corp["org"]
    client.post(f"/orgs/{org}/officers", json={"user_id": corp["emp2"]}, headers=corp["h_owner"])
    _isolate(api, {**corp, "h_ext": corp["h_ext"], "emp": corp["emp2"]})
    body = {"verdict": "false_positive"}
    # другой officer (владелец пока единственный другой) — проверим через сотрудника-заместителя
    r = client.post(f"/moderation/isolated/{corp['emp2']}/lift", json=body, headers=corp["h_emp"])
    assert r.status_code == 403, "рядовой сотрудник не снимает"
    client.put(f"/orgs/{org}/deputy", json={"user_id": corp["emp"]}, headers=corp["h_owner"])
    r = client.post(f"/moderation/isolated/{corp['emp2']}/lift", json=body, headers=corp["h_emp"])
    assert r.status_code == 200, "заместитель владельца снимает изоляцию с officer'а"
