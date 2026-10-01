"""Роли: заявки на членство, security_officer, заместитель владельца."""

import pytest

from core import db


def test_membership_flow(api, client):
    owner, h_owner = api.register("owner@corp.com")
    emp, h_emp = api.register("emp@corp.com")
    org = api.create_org(h_owner)
    m = client.post(f"/orgs/{org}/join", headers=h_emp).json()
    assert client.post(f"/orgs/{org}/join", headers=h_emp).status_code in (400, 403)
    assert len(client.get(f"/orgs/{org}/pending", headers=h_owner).json()["memberships"]) == 1
    assert client.post(f"/orgs/memberships/{m['membership_id']}/approve", headers=h_owner).status_code == 200
    assert client.post("/orgs", json={"name": "Second"}, headers=h_emp).status_code in (400, 403), \
        "одна активная организация на пользователя"


def test_only_owner_or_deputy_appoints_officers(client, corp):
    org = corp["org"]
    r = client.post(f"/orgs/{org}/officers", json={"user_id": corp["emp"]}, headers=corp["h_owner"])
    assert r.status_code == 200 and r.json()["role"] == "security_officer"
    # новый officer не может назначить сообщника
    r = client.post(f"/orgs/{org}/officers", json={"user_id": corp["emp2"]}, headers=corp["h_emp"])
    assert r.status_code == 403
    # снять роль
    r = client.delete(f"/orgs/{org}/officers/{corp['emp']}", headers=corp["h_owner"])
    assert r.status_code == 200 and r.json()["role"] == "member"
    with db.transaction() as conn:
        changes = conn.execute("SELECT old_role, new_role, changed_by FROM role_changes ORDER BY changed_at").fetchall()
    assert [(c["old_role"], c["new_role"]) for c in changes] == [
        ("member", "security_officer"), ("security_officer", "member"),
    ]


def test_owner_cannot_be_demoted(client, corp):
    org = corp["org"]
    client.put(f"/orgs/{org}/deputy", json={"user_id": corp["emp"]}, headers=corp["h_owner"])
    r = client.delete(f"/orgs/{org}/officers/{corp['owner']}", headers=corp["h_emp"])
    assert r.status_code == 400


def test_deputy_lifecycle(client, corp):
    org = corp["org"]
    # назначает только владелец
    assert client.put(f"/orgs/{org}/deputy", json={"user_id": corp["emp2"]}, headers=corp["h_emp"]).status_code == 403
    assert client.put(f"/orgs/{org}/deputy", json={"user_id": corp["emp"]}, headers=corp["h_owner"]).status_code == 200
    # заместитель может назначать officer'ов…
    assert client.post(f"/orgs/{org}/officers", json={"user_id": corp["emp2"]}, headers=corp["h_emp"]).status_code == 200
    # …но не своего заместителя
    assert client.put(f"/orgs/{org}/deputy", json={"user_id": corp["emp2"]}, headers=corp["h_emp"]).status_code == 403
    # замена заместителя — прежний снимается, история остаётся
    client.put(f"/orgs/{org}/deputy", json={"user_id": corp["emp2"]}, headers=corp["h_owner"])
    assert client.get(f"/orgs/{org}/deputy", headers=corp["h_owner"]).json()["user_id"] == corp["emp2"]
    client.delete(f"/orgs/{org}/deputy", headers=corp["h_owner"])
    assert client.get(f"/orgs/{org}/deputy", headers=corp["h_owner"]).json()["user_id"] is None
    with db.transaction() as conn:
        assert conn.execute("SELECT count(*) AS n FROM org_deputies").fetchone()["n"] == 2


def test_deputy_must_be_member(api, client, corp):
    stranger, _ = api.register("stranger@else.com")
    r = client.put(f"/orgs/{corp['org']}/deputy", json={"user_id": stranger}, headers=corp["h_owner"])
    assert r.status_code == 403


def test_members_list(client, corp):
    members = client.get(f"/orgs/{corp['org']}/members", headers=corp["h_owner"]).json()["memberships"]
    assert {m["user_id"] for m in members} == {corp["owner"], corp["emp"], corp["emp2"]}
    assert client.get(f"/orgs/{corp['org']}/members", headers=corp["h_emp"]).status_code == 403


@pytest.mark.parametrize("path", ["/orgs/{org}/officers", "/orgs/{org}/deputy"])
def test_isolated_owner_loses_role_rights(api, client, corp, path):
    from api import deps
    deps.isolation_store.isolate(corp["owner"], ["тест"])
    method = client.post if path.endswith("officers") else client.put
    r = method(path.format(org=corp["org"]), json={"user_id": corp["emp"]}, headers=corp["h_owner"])
    assert r.status_code == 403
