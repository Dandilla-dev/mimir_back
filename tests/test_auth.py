"""Регистрация, вход, сессии, пароли (core/auth_store.py)."""

import hashlib

from core import db
from core.auth_store import AuthStore
from tests.conftest import PASSWORD


def test_register_login_me(api, client):
    user_id, headers = api.register("anna@example.com", "Анна")
    me = client.get("/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["user_id"] == user_id

    r = client.post("/auth/login", json={"email": "ANNA@example.com", "password": PASSWORD})
    assert r.status_code == 200, "email не зависит от регистра"


def test_duplicate_email_case_insensitive(api, client):
    api.register("anna@example.com")
    r = client.post("/auth/register", json={"email": "Anna@Example.com", "password": PASSWORD})
    assert r.status_code == 400


def test_password_min_length(client):
    r = client.post("/auth/register", json={"email": "a@b.com", "password": "1234567"})
    assert r.status_code == 400
    assert "8" in r.json()["detail"]


def test_wrong_password_same_error_as_unknown_user(api, client):
    api.register("anna@example.com")
    wrong = client.post("/auth/login", json={"email": "anna@example.com", "password": "nope-nope"})
    unknown = client.post("/auth/login", json={"email": "nobody@example.com", "password": PASSWORD})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_password_stored_as_bcrypt(api):
    user_id, _ = api.register("anna@example.com")
    with db.transaction() as conn:
        row = conn.execute("SELECT password_hash, salt FROM users WHERE user_id = %s", (user_id,)).fetchone()
    assert row["password_hash"].startswith("$2") and row["salt"] is None


def test_legacy_sha256_user_is_rehashed_on_login(client):
    """Пользователь, зарегистрированный до перехода на bcrypt, входит со
    старым паролем, и его хэш прозрачно пересчитывается."""
    salt = "abcd1234"
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO users (user_id, email, name, password_hash, salt) VALUES (%s, %s, %s, %s, %s)",
            ("legacy1", "old@example.com", "Old",
             hashlib.sha256((salt + "1234").encode()).hexdigest(), salt),
        )
    r = client.post("/auth/login", json={"email": "old@example.com", "password": "1234"})
    assert r.status_code == 200, "старый короткий пароль продолжает работать"
    with db.transaction() as conn:
        row = conn.execute("SELECT password_hash, salt FROM users WHERE user_id = 'legacy1'").fetchone()
    assert row["password_hash"].startswith("$2") and row["salt"] is None
    r = client.post("/auth/login", json={"email": "old@example.com", "password": "1234"})
    assert r.status_code == 200, "после пересчёта вход по bcrypt"


def test_raw_token_not_stored_and_logout(api, client):
    _, headers = api.register("anna@example.com")
    token = headers["Authorization"].removeprefix("Bearer ")
    with db.transaction() as conn:
        assert conn.execute("SELECT count(*) AS n FROM sessions WHERE token_hash = %s", (token,)).fetchone()["n"] == 0
    client.post("/auth/logout", headers=headers)
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_session_expires(api, client):
    _, headers = api.register("anna@example.com")
    with db.transaction() as conn:
        expires = conn.execute("SELECT expires_at - created_at AS ttl FROM sessions").fetchone()["ttl"]
        assert expires.days == 30
        conn.execute("UPDATE sessions SET expires_at = now() - interval '1 second'")
    assert client.get("/auth/me", headers=headers).status_code == 401
    assert AuthStore().purge_expired_sessions() == 1


def test_login_throttled_after_five_failures(api, client):
    api.register("anna@example.com")
    for _ in range(5):
        r = client.post("/auth/login", json={"email": "anna@example.com", "password": "wrong-pass"})
        assert r.status_code == 401
    r = client.post("/auth/login", json={"email": "anna@example.com", "password": PASSWORD})
    assert r.status_code == 429, "даже верный пароль — после 5 неудач"
    assert int(r.headers["retry-after"]) > 0
    # для несуществующего email — то же поведение (не выдаём, кто зарегистрирован)
    for _ in range(5):
        client.post("/auth/login", json={"email": "ghost@example.com", "password": "wrong-pass"})
    assert client.post("/auth/login", json={"email": "ghost@example.com", "password": "x"}).status_code == 429


def test_lock_expires_and_success_resets(api, client):
    api.register("anna@example.com")
    for _ in range(4):
        client.post("/auth/login", json={"email": "anna@example.com", "password": "wrong-pass"})
    assert client.post("/auth/login", json={"email": "anna@example.com", "password": PASSWORD}).status_code == 200
    for _ in range(4):
        r = client.post("/auth/login", json={"email": "anna@example.com", "password": "wrong-pass"})
    assert r.status_code == 401, "счёт после удачного входа начался заново"
    client.post("/auth/login", json={"email": "anna@example.com", "password": "wrong-pass"})
    assert client.post("/auth/login", json={"email": "anna@example.com", "password": PASSWORD}).status_code == 429
    with db.transaction() as conn:
        conn.execute("UPDATE login_attempts SET attempted_at = attempted_at - interval '16 minutes'")
    assert client.post("/auth/login", json={"email": "anna@example.com", "password": PASSWORD}).status_code == 200


def test_change_password(api, client):
    _, h1 = api.register("anna@example.com")
    token2 = client.post("/auth/login", json={"email": "anna@example.com", "password": PASSWORD}).json()["token"]
    h2 = {"Authorization": f"Bearer {token2}"}

    bad = client.post("/auth/password", json={"current_password": "wrong-pass", "new_password": "newpassword1"}, headers=h1)
    assert bad.status_code == 400
    short = client.post("/auth/password", json={"current_password": PASSWORD, "new_password": "short"}, headers=h1)
    assert short.status_code == 400

    r = client.post("/auth/password", json={"current_password": PASSWORD, "new_password": "newpassword1"}, headers=h1)
    assert r.status_code == 200 and r.json()["other_sessions_revoked"] == 1
    assert client.get("/auth/me", headers=h1).status_code == 200, "текущая сессия остаётся"
    assert client.get("/auth/me", headers=h2).status_code == 401, "другие завершены"
    assert client.post("/auth/login", json={"email": "anna@example.com", "password": "newpassword1"}).status_code == 200
