"""Чтение: постраничная история, список чатов, вложения, профили."""

from core import db

PDF = [("files", ("report.pdf", b"%PDF-1.4 hello", "application/pdf"))]


def _ids(page):
    return [m["text"] for m in page["messages"]]


def test_history_paging(api, client, corp):
    for i in range(5):
        api.send(corp["h_emp"], [corp["emp2"]], f"m{i}")
    first = client.get(f"/messages/history/{corp['emp']}?limit=2", headers=corp["h_emp2"]).json()
    assert _ids(first) == ["m3", "m4"], "первая страница — самые свежие, по порядку"
    second = client.get(
        f"/messages/history/{corp['emp']}?limit=2&before={first['next_before']}", headers=corp["h_emp2"],
    ).json()
    assert _ids(second) == ["m1", "m2"]
    last = client.get(
        f"/messages/history/{corp['emp']}?limit=2&before={second['next_before']}", headers=corp["h_emp2"],
    ).json()
    assert _ids(last) == ["m0"] and last["next_before"] is None


def test_inbox_paging(api, client, corp):
    for i in range(3):
        api.send(corp["h_emp"], [corp["emp2"]], f"m{i}")
    page = client.get("/messages/inbox?limit=2", headers=corp["h_emp2"]).json()
    assert len(page["messages"]) == 2 and page["next_before"]


def test_conversations_list(api, client, corp):
    api.send(corp["h_emp"], [corp["emp2"]], "старое 1-на-1")
    api.send(corp["h_emp"], [corp["emp2"], corp["owner"]], "группа")
    api.send(corp["h_emp2"], [corp["emp"]], "свежее 1-на-1", files=PDF)
    convs = client.get("/conversations", headers=corp["h_emp"]).json()["conversations"]
    assert [c["last_text_preview"] for c in convs] == ["свежее 1-на-1", "группа"]
    assert convs[0]["message_count"] == 2 and convs[0]["last_has_attachments"]
    group = convs[1]
    assert set(group["participant_ids"]) == {corp["emp"], corp["emp2"], corp["owner"]}

    msgs = client.get(f"/conversations/{group['conversation_key']}/messages", headers=corp["h_owner"]).json()
    assert _ids(msgs) == ["группа"]
    outsider = client.get(f"/conversations/{group['conversation_key']}/messages", headers=corp["h_ext"])
    assert outsider.status_code == 404

    page = client.get("/conversations?limit=1", headers=corp["h_emp"]).json()
    nxt = client.get(f"/conversations?limit=1&before={page['next_before']}", headers=corp["h_emp"]).json()
    assert nxt["conversations"][0]["last_text_preview"] == "группа" and nxt["next_before"] is None


def _attachment_url(message):
    return f"/messages/{message['message_id']}/attachments/{message['attachments'][0]['attachment_id']}"


def test_attachment_download(api, client, corp):
    sent = api.send(corp["h_emp"], [corp["emp2"]], "файл", files=PDF).json()
    url = _attachment_url(sent)
    r = client.get(url, headers=corp["h_emp2"])
    assert r.status_code == 200 and r.content == b"%PDF-1.4 hello"
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get(url, headers=corp["h_emp"]).status_code == 200, "отправитель"
    assert client.get(url, headers=corp["h_owner"]).status_code == 404, "посторонний"


def test_held_attachment_visible_to_officer_not_recipient(api, client, corp):
    """Эскалация (нет легитимного доступа + личный адрес) — удержание."""
    r = api.send(corp["h_emp"], [corp["ext"]], "база", files=[("files", ("clients.docx", b"PK..", "x"))])
    assert r.json()["status"] == "pending_moderation"
    pending = client.get("/moderation/pending", headers=corp["h_owner"]).json()["pending"][0]
    url = _attachment_url(pending["message"])
    assert client.get(url, headers=corp["h_ext"]).status_code == 404, "получатель не видит удержанное"
    assert client.get(url, headers=corp["h_owner"]).status_code == 200, "officer видит для решения"
    assert client.get(url, headers=corp["h_emp"]).status_code == 200, "отправитель видит своё"
    assert client.get(url, headers=corp["h_emp2"]).status_code == 404, "рядовой коллега — нет"


def test_purged_attachment_gone(api, client, corp):
    r = api.send(corp["h_emp"], [corp["ext"]], "база", files=[("files", ("clients.docx", b"PK..", "x"))])
    pending = client.get("/moderation/pending", headers=corp["h_owner"]).json()["pending"][0]
    client.post(f"/moderation/{r.json()['hold_id']}/reject", headers=corp["h_owner"])
    from api import deps
    with db.transaction() as conn:
        conn.execute("UPDATE messages SET rejected_at = now() - interval '2 days'")
    deps.messages_store.purge_rejected_content()
    assert client.get(_attachment_url(pending["message"]), headers=corp["h_emp"]).status_code == 410


def test_user_profiles_visibility(api, client, corp):
    stranger, h_stranger = api.register("stranger@else.com", "Stranger")
    # коллега по организации
    assert client.get(f"/users/{corp['emp2']}", headers=corp["h_emp"]).json()["name"] == "Emp2"
    # посторонний — не виден
    assert client.get(f"/users/{stranger}", headers=corp["h_emp"]).status_code == 404
    # после переписки — виден обоим
    api.send(corp["h_emp"], [stranger], "привет")
    assert client.get(f"/users/{stranger}", headers=corp["h_emp"]).status_code == 200
    assert client.get(f"/users/{corp['emp']}", headers=h_stranger).status_code == 200
    # пакетно: невидимые и несуществующие пропускаются
    r = client.get(f"/users?ids={corp['emp2']}&ids={corp['ext']}&ids=nope", headers=corp["h_emp"]).json()
    assert {u["user_id"] for u in r["users"]} == {corp["emp2"]}


def test_add_single_contact_links_user(api, client, corp):
    r = client.post("/contacts", json={"name": "Внешний", "email": "SOMEONE@gmail.com"}, headers=corp["h_emp"])
    assert r.json()["linked_user_id"] == corp["ext"]
    assert client.get(f"/users/{corp['ext']}", headers=corp["h_emp"]).status_code == 200, \
        "контакт делает профиль видимым"
