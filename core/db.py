"""
core/db.py — подключение к PostgreSQL для всех *_store.py.

Решения (mimir_architecture_v2.md §9.7, mimir_db_migration_contract.md):
- синхронный драйвер psycopg 3 + пул соединений psycopg_pool: методы
  сторов остаются синхронными, async не тянется вверх до
  core/message_parser.parse_raw_message();
- схема — migrations/*.sql, применяется отдельно: python -m core.migrate.

ТРАНЗАКЦИИ — главное, что даёт этот модуль:

    with db.transaction() as conn:
        conn.execute(...)

Если транзакция уже открыта выше по стеку (например, api/server.py
обернул весь /messages/send в db.transaction()), вложенный вызов НЕ
берёт новое соединение из пула, а переиспользует текущее и открывает
SAVEPOINT. Поэтому каждый метод стора сам по себе атомарен, а несколько
методов разных сторов, вызванных внутри одной внешней транзакции,
атомарны вместе — фиксируются или откатываются целиком. Сторам не нужно
знать, вызваны они внутри внешней транзакции или нет.

Текущее соединение хранится в contextvars: у каждого запроса FastAPI
(asyncio-задачи) свой контекст, запросы друг другу соединения не
подменяют.

ВРЕМЯ: в БД — TIMESTAMPTZ, в dataclass'ах сторов и в API — float
(unix-эпоха), как было до миграции. Переводят туда-обратно to_db_time()
/ from_db_time() на границе стора — API и фронтенд миграцию не замечают.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

logger = logging.getLogger("mimir.db")

DEFAULT_DATABASE_URL = "postgresql://mimir:mimir@localhost:5432/mimir"

_pool: ConnectionPool | None = None
_current_conn: ContextVar[psycopg.Connection | None] = ContextVar("mimir_db_conn", default=None)

# Переэкспорт, чтобы сторы ловили ошибки БД, не импортируя psycopg сами.
UniqueViolation = psycopg.errors.UniqueViolation
ForeignKeyViolation = psycopg.errors.ForeignKeyViolation


def database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def get_pool() -> ConnectionPool:
    """Пул открывается лениво при первом обращении — импорт сторов не
    требует работающей БД (удобно для тестов и инструментов)."""
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=database_url(),
            min_size=1,
            max_size=int(os.getenv("DATABASE_POOL_SIZE", "10")),
            # autocommit=True: границы транзакций задаёт только
            # transaction() ниже, явно — никаких неявных BEGIN драйвера.
            kwargs={"autocommit": True, "row_factory": dict_row},
            open=True,
        )
        logger.info("Пул соединений с БД открыт")
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
        logger.info("Пул соединений с БД закрыт")


@contextmanager
def transaction() -> Iterator[psycopg.Connection]:
    """Атомарный блок. Вложенный вызов = SAVEPOINT в текущей транзакции
    (ошибка внутри откатывает только вложенный блок, если её поймали)."""
    conn = _current_conn.get()
    if conn is not None:
        with conn.transaction():
            yield conn
        return

    with get_pool().connection() as conn:
        token = _current_conn.set(conn)
        try:
            with conn.transaction():
                yield conn
        finally:
            _current_conn.reset(token)


# --------- Время: float (эпоха) <-> TIMESTAMPTZ ---------

def to_db_time(ts: float | None) -> datetime | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def from_db_time(value: datetime | None) -> float | None:
    if value is None:
        return None
    return value.timestamp()


def local_naive_to_db(dt: datetime) -> datetime:
    """DLPEvent.event_time — наивное локальное время сервера
    (datetime.now() / datetime.fromtimestamp() в message_bridge.py).
    Хранится как момент времени с зоной, читается обратно в то же
    наивное локальное — признаки времени суток (cyclical encoding)
    при повторном кодировании из БД совпадают с исходными."""
    return dt.astimezone() if dt.tzinfo is None else dt


def db_to_local_naive(value: datetime) -> datetime:
    return value.astimezone().replace(tzinfo=None)


def jsonb(value) -> Jsonb:
    """Обёртка для записи списков причин в JSONB-колонки."""
    return Jsonb(list(value))
