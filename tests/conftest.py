"""
Общие фикстуры автотестов.

Тесты работают с НАСТОЯЩИМ PostgreSQL, но с отдельной базой
(TEST_DATABASE_URL), которая полностью очищается перед каждым тестом —
рабочая база не затрагивается. Создать её один раз:
    docker compose exec db createdb -U mimir mimir_test

Запуск из корня репозитория:
    pip install -r requirements-dev.txt
    pytest
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

load_dotenv()  # .env из корня репозитория — там TEST_DATABASE_URL

TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL", "postgresql://mimir:mimir@localhost:5432/mimir_test"
)
# Подменить ДО импорта приложения: core/db.py читает DATABASE_URL при
# первом подключении, core/config.py не перезаписывает уже заданные
# переменные окружения значениями из .env.
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["MOCK_CLAUDE"] = "true"
os.environ["LOAD_LOCAL_MODEL"] = "false"
os.environ["BCRYPT_ROUNDS"] = "4"

from fastapi.testclient import TestClient  # noqa: E402

from api.server import app  # noqa: E402
from core import db  # noqa: E402
from core.migrate import migrate  # noqa: E402

PASSWORD = "password123"


@pytest.fixture(scope="session", autouse=True)
def _schema():
    migrate()
    yield
    db.close_pool()


@pytest.fixture(autouse=True)
def _clean_db():
    """Каждый тест — с пустой базой. TRUNCATE не запускает построчные
    триггеры, поэтому журналы "только добавление" тоже очищаются."""
    with db.transaction() as conn:
        tables = [
            r["tablename"]
            for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                "AND tablename <> 'schema_migrations'"
            ).fetchall()
        ]
        conn.execute(f"TRUNCATE {', '.join(tables)} CASCADE")
    yield


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


class Api:
    """Короткие обёртки над частыми вызовами, чтобы тесты читались как
    сценарии, а не как набор HTTP-запросов."""

    def __init__(self, client: TestClient):
        self.c = client

    def register(self, email: str, name: str = "") -> tuple[str, dict]:
        r = self.c.post("/auth/register", json={"email": email, "password": PASSWORD, "name": name})
        assert r.status_code == 200, r.text
        body = r.json()
        return body["user"]["user_id"], {"Authorization": f"Bearer {body['token']}"}

    def create_org(self, headers: dict, name: str = "Corp") -> str:
        r = self.c.post("/orgs", json={"name": name}, headers=headers)
        assert r.status_code == 200, r.text
        return r.json()["org_id"]

    def join(self, org_id: str, member_headers: dict, officer_headers: dict) -> None:
        r = self.c.post(f"/orgs/{org_id}/join", headers=member_headers)
        assert r.status_code == 200, r.text
        r = self.c.post(
            f"/orgs/memberships/{r.json()['membership_id']}/approve", headers=officer_headers,
        )
        assert r.status_code == 200, r.text

    def send(self, headers: dict, recipients: list[str], text: str = "", files=None):
        return self.c.post(
            "/messages/send",
            data={"recipient_ids": recipients, "text": text},
            files=files or [],
            headers=headers,
        )

    def inbox(self, headers: dict) -> list[dict]:
        return self.c.get("/messages/inbox", headers=headers).json()["messages"]


@pytest.fixture
def api(client) -> Api:
    return Api(client)


@pytest.fixture
def corp(api):
    """Типовая организация: владелец (officer), два сотрудника и внешний
    пользователь с личной почтой."""
    owner, h_owner = api.register("owner@corp.com", "Owner")
    emp, h_emp = api.register("emp@corp.com", "Emp")
    emp2, h_emp2 = api.register("emp2@corp.com", "Emp2")
    ext, h_ext = api.register("someone@gmail.com", "External")
    org = api.create_org(h_owner)
    api.join(org, h_emp, h_owner)
    api.join(org, h_emp2, h_owner)
    return {
        "org": org,
        "owner": owner, "h_owner": h_owner,
        "emp": emp, "h_emp": h_emp,
        "emp2": emp2, "h_emp2": h_emp2,
        "ext": ext, "h_ext": h_ext,
    }
