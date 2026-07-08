"""
core/auth_store.py — заглушка авторизации: регистрация, логин, токены.

Хранит пользователей в памяти процесса, по тому же принципу, что и
MemoryStore для истории чата, и mock-режим в claude_adapter.py.

ВАЖНО: это заглушка для проверки связки фронт -> бэк -> ответ.
Перед продакшеном заменить:
- sha256+соль -> bcrypt/argon2
- dict в памяти -> реальная БД (Postgres/SQLite)
- token_urlsafe -> нормальные JWT с истечением срока
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field

logger = logging.getLogger("mimir.auth")


class AuthError(Exception):
    """Ошибка регистрации/логина (email занят, неверный пароль и т.д.)."""


@dataclass
class User:
    user_id: str
    email: str
    name: str
    password_hash: str
    salt: str
    created_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        """Данные о пользователе, безопасные для отдачи клиенту (без хэша/соли)."""
        return {"user_id": self.user_id, "email": self.email, "name": self.name}


def _hash_password(password: str, salt: str) -> str:
    """Заглушка хеширования — sha256 с солью. Для продакшена: bcrypt/argon2."""
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


class AuthStore:
    """Реестр пользователей и токенов сессий — всё в памяти процесса.

    При перезапуске сервера все пользователи и токены пропадают —
    это ожидаемо для заглушки.
    """

    def __init__(self):
        self._users_by_email: dict[str, User] = {}
        self._users_by_id: dict[str, User] = {}
        self._tokens: dict[str, str] = {}  # token -> user_id

    def register(self, email: str, password: str, name: str = "") -> User:
        email = email.strip().lower()
        if not email or "@" not in email:
            raise AuthError("Некорректный email")
        if email in self._users_by_email:
            raise AuthError("Пользователь с таким email уже зарегистрирован")
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
        self._users_by_email[email] = user
        self._users_by_id[user.user_id] = user
        logger.info("Зарегистрирован пользователь: %s (%s)", user.email, user.user_id)
        return user

    def login(self, email: str, password: str) -> tuple[User, str]:
        email = email.strip().lower()
        user = self._users_by_email.get(email)
        if user is None or user.password_hash != _hash_password(password, user.salt):
            # Намеренно одна и та же ошибка для "нет юзера" и "неверный пароль",
            # чтобы не палить, какие email зарегистрированы.
            raise AuthError("Неверный email или пароль")

        token = secrets.token_urlsafe(24)
        self._tokens[token] = user.user_id
        logger.info("Вход выполнен: %s", user.email)
        return user, token

    def user_by_token(self, token: str) -> User | None:
        user_id = self._tokens.get(token)
        if user_id is None:
            return None
        return self._users_by_id.get(user_id)

    def logout(self, token: str) -> None:
        self._tokens.pop(token, None)

    def all_users(self) -> list[User]:
        """Для отладки/тестов — список всех зарегистрированных пользователей."""
        return list(self._users_by_id.values())
