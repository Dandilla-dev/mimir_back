"""Модерация удержанных исходящих (api/routes/moderation.py)."""

import pytest

from api import deps
from core import db


@pytest.fixture
def held(api, client, corp):
    """Два удержанных сообщения сотрудника на домен из watchlist."""
    rival, h_rival = api.register("x@rival.com")
    client.post(f"/orgs/{corp['org']}/watchlist", json={"domain": "rival.com"}, headers=corp["h_owner"])
    holds = [api.send(corp["h_emp"], [rival], f"секрет {i}").json()["hold_id"] for i in range(2)]
    return {**corp, "rival": rival, "h_rival": h_rival, "holds": holds}


def test_queue_visible_only_to_officer(client, held):
    assert len(client.get("/moderation/pending", headers=held["h_owner"]).json()["pending"]) == 2
    assert client.get("/moderation/pending", headers=held["h_emp2"]).json()["pending"] == []


def test_approve_delivers_once(api, client, held):
    hold = held["holds"][0]
    assert client.post(f"/moderation/{hold}/approve", headers=held["h_emp2"]).status_code == 403
    r = client.post(f"/moderation/{hold}/approve", json={"reviewer_confidence": "unsure"}, headers=held["h_owner"])
    assert r.status_code == 200
    assert client.post(f"/moderation/{hold}/approve", headers=held["h_owner"]).status_code == 404
    assert len(api.inbox(held["h_rival"])) == 1


def test_reject_hides_and_purges_after_a_day(api, client, held):
    hold = held["holds"][1]
    client.post(f"/moderation/{hold}/reject", headers=held["h_owner"])
    assert api.inbox(held["h_rival"]) == []
    decision = client.get("/moderation/decisions", headers=held["h_owner"]).json()["decisions"][0]
    message_id = decision["message_id"]
    assert decision["org_id"] == held["org"]

    assert deps.messages_store.purge_rejected_content() == 0, "свежее не стирается"
    with db.transaction() as conn:
        conn.execute("UPDATE messages SET rejected_at = now() - interval '25 hours' WHERE message_id = %s", (message_id,))
    assert deps.messages_store.purge_rejected_content() == 1
    with db.transaction() as conn:
        row = conn.execute("SELECT text, text_sha256 FROM messages WHERE message_id = %s", (message_id,)).fetchone()
    assert row["text"] is None and len(row["text_sha256"]) == 64
    assert deps.dlp_events_store.list_for_message(message_id), "DLP-события остаются"


def test_sender_removed_from_org_stays_in_officer_queue(client, held):
    """[РЕШЕНИЕ 7]: решает officer организации на момент поступления."""
    with db.transaction() as conn:
        conn.execute("UPDATE memberships SET status = 'rejected' WHERE user_id = %s", (held["emp"],))
    pending = client.get("/moderation/pending", headers=held["h_owner"]).json()["pending"]
    assert len(pending) == 2
    assert client.post(f"/moderation/{held['holds'][0]}/reject", headers=held["h_owner"]).status_code == 200


def test_decisions_journal_is_append_only(client, held):
    client.post(f"/moderation/{held['holds'][0]}/approve", headers=held["h_owner"])
    with pytest.raises(Exception, match="append-only"):
        with db.transaction() as conn:
            conn.execute("UPDATE moderation_decisions SET decision = 'rejected'")


def test_anomaly_summary_available(client, held):
    assert client.get("/moderation/anomaly-summary", headers=held["h_owner"]).status_code == 200
