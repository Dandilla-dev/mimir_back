"""Отправка сообщений и DLP на отправке (api/routes/messages.py)."""

from api import deps

DOCX = [("files", ("clients.docx", b"PK\x03\x04 dummy", "application/octet-stream"))]


def test_plain_message_delivered(api, corp):
    r = api.send(corp["h_emp"], [corp["emp2"]], "привет")
    assert r.status_code == 200 and "message_id" in r.json()
    assert len(api.inbox(corp["h_emp2"])) == 1


def test_unknown_recipient_rejected(api, corp):
    assert api.send(corp["h_emp"], ["nope"], "x").status_code == 400


def test_watchlisted_domain_is_held(api, client, corp):
    rival, _ = api.register("x@rival.com")
    client.post(f"/orgs/{corp['org']}/watchlist", json={"domain": "Rival.com"}, headers=corp["h_owner"])
    r = api.send(corp["h_emp"], [rival], "отчёт")
    assert r.json()["status"] == "pending_moderation"


def test_escalated_threat_is_held_with_anomaly_reasons(api, client, corp):
    """Регрессия: THREAT, полученный эскалацией двух ANOMALY-сигналов
    (нет легитимного доступа + личный адрес), раньше уходил получателю
    без модерации и не был виден офицеру нигде."""
    r = api.send(corp["h_emp"], [corp["ext"]], "вот файл", files=DOCX)
    assert r.json()["status"] == "pending_moderation"
    assert api.inbox(corp["h_ext"]) == []
    pending = client.get("/moderation/pending", headers=corp["h_owner"]).json()["pending"]
    assert len(pending) == 1
    assert "вложение отправлено на личный (некорпоративный) адрес" in pending[0]["threat_reasons"]


def test_device_rule_ignores_incoming(api, client, corp):
    """Регрессия: правило "вложение с незарегистрированного устройства"
    срабатывало и на входящих, где device_id — устройство отправителя."""
    r = client.post(
        "/messages/send",
        data={"recipient_ids": [corp["emp"]], "text": "файл", "device_id": "ext-phone"},
        files=DOCX,
        headers=corp["h_ext"],
    )
    assert r.status_code == 200
    incoming = [e for e in deps.dlp_events_store.list_for_message(r.json()["message_id"]) if e.is_incoming]
    assert incoming
    for e in incoming:
        assert "вложение с незарегистрированного устройства" not in e.anomaly_reasons


def test_failed_send_writes_nothing(api, corp, monkeypatch):
    """fail-closed: сбой исходящей проверки — в БД не остаётся ни
    сообщения, ни DLP-событий (одна транзакция)."""
    import api.routes.messages as m

    def boom(*a, **k):
        raise RuntimeError("bridge down")

    monkeypatch.setattr(m, "check_outgoing", boom)
    assert api.send(corp["h_emp"], [corp["emp2"]], "x").status_code == 503
    from core import db
    with db.transaction() as conn:
        assert conn.execute("SELECT count(*) AS n FROM messages").fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM dlp_event_records").fetchone()["n"] == 0
