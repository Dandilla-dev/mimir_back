"""
core/auth_store.py — пользователи и сессионные токены (PostgreSQL).

Таблицы: users, sessions (migrations/001_initial_schema.sql, раздел 1).
Интерфейс (методы, User, AuthError) не изменился с in-memory версии —
вызывающий код (api/server.py, message_bridge.py, contacts_store.py) не
трогается.

ПАРОЛИ — bcrypt (с 2026-10-01). Соль bcrypt хранится внутри самого
хэша, поэтому users.salt для новых пользователей NULL. Пользователи,
зарегистрированные раньше (sha256 + отдельная соль в users.salt),
входят как прежде; при первом успешном входе их хэш прозрачно
пересчитывается в bcrypt, а salt обнуляется — без принудительной смены
пароля. Минимальная длина нового пароля — MIN_PASSWORD_LENGTH; старым
коротким паролям вход не закрывается, требование действует при
регистрации.

СЕССИИ: клиенту отдаётся сам токен, в БД хранится только его sha256
([РЕШЕНИЕ 3]) — утечка дампа БД не даёт войти под чужой сессией. Токен
действует SESSION_LIFETIME с момента входа (sessions.expires_at), потом
нужен повторный вход. Просроченные строки чистит
purge_expired_sessions() из той же фоновой задачи, что и стирание
отклонённых сообщений (api/server.py).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import timedelta

import bcrypt

from core import db

logger = logging.getLogger("mimir.auth")


MIN_PASSWORD_LENGTH = 8
SESSION_LIFETIME = timedelta(days=int(os.getenv("SESSION_LIFETIME_DAYS", "30")))
# Стоимость bcrypt (2^rounds итераций). 12 — разумно для сервера; автотесты
# ставят 4, чтобы не ждать по ~0.3 с на каждую регистрацию.
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))


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


def _hash_password(password: str) -> str:
    """bcrypt: медленный намеренно — перебор утёкших хэшей становится
    дорогим. Соль генерируется и хранится внутри результата."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def _legacy_hash(password: str, salt: str) -> str:
    """Старая схема (до 2026-10-01): sha256(соль + пароль). Только для
    проверки паролей пользователей, ещё не перешедших на bcrypt."""
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def _password_matches(user: "User", password: str) -> bool:
    if user.salt is not None:
        return secrets.compare_digest(user.password_hash, _legacy_hash(password, user.salt))
    return bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("ascii"))


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
        if len(password) < MIN_PASSWORD_LENGTH:
            raise AuthError(f"Пароль слишком короткий (мин. {MIN_PASSWORD_LENGTH} символов)")

        user = User(
            user_id=secrets.token_hex(8),
            email=email,
            name=name.strip() or email.split("@")[0],
            password_hash=_hash_password(password),
            salt=None,
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
        if user is None or not _password_matches(user, password):
            # Намеренно одна и та же ошибка для "нет юзера" и "неверный пароль",
            # чтобы не палить, какие email зарегистрированы.
            raise AuthError("Неверный email или пароль")

        token = secrets.token_urlsafe(24)
        with db.transaction() as conn:
            if user.salt is not None:
                # Пароль только что проверен по старой схеме — пересчитываем
                # хэш в bcrypt, пока открытый пароль у нас в руках.
                conn.execute(
                    "UPDATE users SET password_hash = %s, salt = NULL WHERE user_id = %s",
                    (_hash_password(password), user.user_id),
                )
                logger.info("Хэш пароля переведён на bcrypt: %s", user.email)
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) "
                "VALUES (%s, %s, now() + %s)",
                (_token_hash(token), user.user_id, SESSION_LIFETIME),
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

    def purge_expired_sessions(self) -> int:
        """Удаляет просроченные сессии. Возвращает их число. Сами по себе
        просроченные токены и так не работают (user_by_token проверяет
        expires_at) — это только уборка таблицы."""
        with db.transaction() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE expires_at <= now()")
            count = cur.rowcount
        if count:
            logger.info("Удалено просроченных сессий: %d", count)
        return count

    def all_users(self) -> list[User]:
        """Для отладки/тестов — список всех зарегистрированных пользователей."""
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_USER_COLUMNS} FROM users ORDER BY created_at"
            ).fetchall()
        return [_row_to_user(r) for r in rows]
