"""
core/auth_store.py — пользователи и сессионные токены (PostgreSQL).

Таблицы: users, sessions (migrations/001_initial_schema.sql, раздел 1).
Интерфейс (методы, User, AuthError) не изменился с in-memory версии —
вызывающий код (api/server.py, message_bridge.py, contacts_store.py) не
трогается.

Токены: клиенту отдаётся сам токен, в БД хранится только его sha256
([РЕШЕНИЕ 3]) — утечка дампа БД не даёт войти под чужой сессией.
Срок жизни токенов пока не ограничен (expires_at = NULL), как и было.

ВАЖНО: всё ещё заглушка в части криптографии — перед продакшеном:
- sha256+соль -> bcrypt/argon2 (колонка salt тогда станет NULL);
- срок жизни сессий (expires_at) и их очистка.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field

from core import db

logger = logging.getLogger("mimir.auth")


class AuthError(Exception):
    """Ошибка регистрации/логина (email занят, неверный пароль и т.д.)."""


@dataclass
class User:
    user_id: str
    email: str
    name: str
    password_hash: str
    salt: str | None
    created_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        """Данные о пользователе, безопасные для отдачи клиенту (без хэша/соли)."""
        return {"user_id": self.user_id, "email": self.email, "name": self.name}


def _hash_password(password: str, salt: str) -> str:
    """Заглушка хеширования — sha256 с солью. Для продакшена: bcrypt/argon2."""
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _row_to_user(row: dict) -> User:
    return User(
        user_id=row["user_id"],
        email=row["email"],
        name=row["name"],
        password_hash=row["password_hash"],
        salt=row["salt"],
        created_at=db.from_db_time(row["created_at"]),
    )


_USER_COLUMNS = "user_id, email, name, password_hash, salt, created_at"


class AuthStore:
    """Реестр пользователей и токенов сессий — PostgreSQL."""

    def register(self, email: str, password: str, name: str = "") -> User:
        email = email.strip().lower()
        if not email or "@" not in email:
            raise AuthError("Некорректный email")
        if len(password) < 4:
            raise AuthError("Пароль слишком короткий (мин. 4 символа)")

        salt = secrets.token_hex(8)
        user = User(
            user_id=secrets.token_hex(8),
            email=email,
            name=name.strip() or email.split("@")[0],
            password_hash=_hash_password(password, salt),
            salt=salt,
        )
        try:
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO users (user_id, email, name, password_hash, salt, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (user.user_id, user.email, user.name, user.password_hash,
                     user.salt, db.to_db_time(user.created_at)),
                )
        except db.UniqueViolation as exc:
            # UNIQUE(email) — проверка на уровне БД, без гонки двух
            # одновременных регистраций (раньше: if email in dict).
            raise AuthError("Пользователь с таким email уже зарегистрирован") from exc
        logger.info("Зарегистрирован пользователь: %s (%s)", user.email, user.user_id)
        return user

    def login(self, email: str, password: str) -> tuple[User, str]:
        email = email.strip().lower()
        user = self._user_by_email(email)
        if user is None or user.password_hash != _hash_password(password, user.salt):
            # Намеренно одна и та же ошибка для "нет юзера" и "неверный пароль",
            # чтобы не палить, какие email зарегистрированы.
            raise AuthError("Неверный email или пароль")

        token = secrets.token_urlsafe(24)
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id) VALUES (%s, %s)",
                (_token_hash(token), user.user_id),
            )
        logger.info("Вход выполнен: %s", user.email)
        return user, token

    def user_by_token(self, token: str) -> User | None:
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {', '.join('u.' + c for c in _USER_COLUMNS.split(', '))} "
                "FROM sessions s JOIN users u ON u.user_id = s.user_id "
                "WHERE s.token_hash = %s AND (s.expires_at IS NULL OR s.expires_at > now())",
                (_token_hash(token),),
            ).fetchone()
        return _row_to_user(row) if row else None

    def user_by_id(self, user_id: str) -> User | None:
        """Нужен мосту (core/message_bridge.py) — чтобы превратить внутренний
        user_id из messages_store в реальный email-адрес для RawMessage."""
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_USER_COLUMNS} FROM users WHERE user_id = %s", (user_id,),
            ).fetchone()
        return _row_to_user(row) if row else None

    def user_by_email(self, email: str) -> User | None:
        """Поиск по email — нужен contacts_store (сопоставление контакта с
        пользователем Мимира) вместо перебора all_users()."""
        return self._user_by_email(email.strip().lower())

    def _user_by_email(self, email: str) -> User | None:
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_USER_COLUMNS} FROM users WHERE email = %s", (email,),
            ).fetchone()
        return _row_to_user(row) if row else None

    def logout(self, token: str) -> None:
        with db.transaction() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = %s", (_token_hash(token),))

    def all_users(self) -> list[User]:
        """Для отладки/тестов — список всех зарегистрированных пользователей."""
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_USER_COLUMNS} FROM users ORDER BY created_at"
            ).fetchall()
        return [_row_to_user(r) for r in rows]
