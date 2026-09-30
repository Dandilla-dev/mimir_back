"""
core/migrate.py — применение миграций из migrations/*.sql.

Запуск (из корня mimir_back, при заданном DATABASE_URL или .env):
    python -m core.migrate

Правило (mimir_db_migration_contract.md): уже применённый где-либо файл
не редактируется — изменения только новым файлом со следующим номером
(002_..., 003_...). Этот скрипт применяет по порядку имён только те
файлы, которых ещё нет в таблице schema_migrations. Каждый файл и
отметка о нём — одна транзакция: упал посередине — не применено ничего,
отметки нет, можно исправить и запустить снова.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from core import db
from core.config import BASE_DIR  # noqa: F401 — загружает .env (DATABASE_URL)

logger = logging.getLogger("mimir.migrate")

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def applied_versions() -> set[str]:
    with db.transaction() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version     TEXT        PRIMARY KEY,
                applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {r["version"] for r in rows}


def migrate() -> list[str]:
    done = applied_versions()
    applied: list[str] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = path.stem
        if version in done:
            continue
        logger.info("Применяю миграцию %s", version)
        with db.transaction() as conn:
            conn.execute(path.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
        applied.append(version)
    if not applied:
        logger.info("Новых миграций нет")
    return applied


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        migrate()
    finally:
        db.close_pool()
    sys.exit(0)
