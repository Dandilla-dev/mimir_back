"""Контакты, health, CORS, персистентность."""

from core.auth_store import AuthStore
from core import db


def test_contacts_sync_links_users(api, client):
    other, _ = api.register("x@rival.com")
    _, h = api.register("emp@corp.com")
    client.post("/contacts/sync", json={"contacts": [
        {"name": "Rival", "email": "X@rival.com"}, {"name": "Phone only", "phone": "1"},
    ]}, headers=h)
    contacts = client.get("/contacts", headers=h).json()["contacts"]
    assert len(contacts) == 2
    assert any(c["linked_user_id"] == other for c in contacts)


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_cors_only_allowed_origin(client):
    ok = client.options("/health", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    bad = client.options("/health", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers


def test_data_survives_new_pool(api):
    user_id, _ = api.register("anna@example.com")
    db.close_pool()
    assert AuthStore().user_by_id(user_id).email == "anna@example.com"
