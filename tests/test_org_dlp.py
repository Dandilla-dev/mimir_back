"""DLP-базы организации и мягкое удаление ([РЕШЕНИЕ 11])."""

from api import deps
from core import db


def test_watchlist_soft_delete(client, corp):
    org, h = corp["org"], corp["h_owner"]
    entry = client.post(f"/orgs/{org}/watchlist", json={"domain": " Evil.COM "}, headers=h).json()
    assert entry["domain"] == "evil.com"
    assert client.post(f"/orgs/{org}/watchlist", json={"domain": "evil.com"}, headers=h).status_code == 400
    assert client.delete(f"/orgs/{org}/watchlist/{entry['entry_id']}", headers=h).status_code == 200
    assert not deps.watchlist_store.is_domain_watchlisted(org, "evil.com")
    assert client.post(f"/orgs/{org}/watchlist", json={"domain": "evil.com"}, headers=h).status_code == 200
    with db.transaction() as conn:
        assert conn.execute("SELECT count(*) AS n FROM watchlisted_domains").fetchone()["n"] == 2


def test_only_officer_manages_dlp_bases(client, corp):
    r = client.post(f"/orgs/{corp['org']}/watchlist", json={"domain": "x.com"}, headers=corp["h_emp"])
    assert r.status_code == 403


def test_devices_and_grants(client, corp):
    org, h, emp = corp["org"], corp["h_owner"], corp["emp"]
    d = client.post(f"/orgs/{org}/devices", json={"device_id": "dev-1", "user_id": emp}, headers=h)
    assert d.status_code == 200
    assert client.post(f"/orgs/{org}/devices", json={"device_id": "dev-1", "user_id": emp}, headers=h).status_code == 400
    client.delete(f"/orgs/{org}/devices/{d.json()['entry_id']}", headers=h)
    assert client.post(f"/orgs/{org}/devices", json={"device_id": "dev-1", "user_id": emp}, headers=h).status_code == 200

    g = client.post(f"/orgs/{org}/access/legitimate", json={"user_id": emp}, headers=h)
    assert client.post(f"/orgs/{org}/access/elevated", json={"user_id": emp}, headers=h).status_code == 200
    client.delete(f"/orgs/{org}/access/legitimate/{g.json()['entry_id']}", headers=h)
    assert not deps.access_store.has_legitimate_access(org, emp)
    assert deps.access_store.has_elevated_rights(org, emp)


def test_link_whitelist(client, corp):
    org, h = corp["org"], corp["h_owner"]
    assert client.post(f"/orgs/{org}/link-whitelist", json={"domain": "partner.example"}, headers=h).status_code == 200
    assert deps.watchlist_store.is_link_whitelisted(org, "partner.example")
    assert client.get("/link-whitelist/default", headers=h).status_code == 200
