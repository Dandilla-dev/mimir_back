"""
core/contacts_store.py — заглушка контактов: хранение и "синхронизация".

Хранение — PostgreSQL, таблица contacts (migrations/001_initial_schema.sql,
раздел 3). Уникальности нет, как и раньше (дубликат контакта возможен).

"Синхронизация" здесь — это приём списка контактов из телефонной книги
клиента (name/phone/email) и:
  1. сохранение их как контактов текущего пользователя;
  2. попытка сопоставить каждый контакт с уже зарегистрированным
     пользователем Мимира по email — если совпал, помечаем
     is_mimir_user=True и подставляем linked_user_id.

Реальная синхронизация (двусторонняя, с диффом, паролем на доступ к
книге и т.д.) — отдельная большая тема, здесь только путь
клиент -> бэкенд -> сохранил -> вернул с отметкой "это пользователь Мимира".
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

from core import db
from core.auth_store import AuthStore

logger = logging.getLogger("mimir.contacts")


class ContactsError(Exception):
    """Ошибка операций с контактами (не найден, некорректные данные и т.д.)."""


@dataclass
class Contact:
    contact_id: str
    owner_user_id: str
    name: str
    phone: str | None = None
    email: str | None = None
    linked_user_id: str | None = None  # user_id в AuthStore, если контакт — пользователь Мимира
    added_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "contact_id": self.contact_id,
            "name": self.name,
            "phone": self.phone,
            "email": self.email,
            "is_mimir_user": self.linked_user_id is not None,
            "linked_user_id": self.linked_user_id,
        }


def _row_to_contact(row: dict) -> Contact:
    return Contact(
        contact_id=row["contact_id"],
        owner_user_id=row["owner_user_id"],
        name=row["name"],
        phone=row["phone"],
        email=row["email"],
        linked_user_id=row["linked_user_id"],
        added_at=db.from_db_time(row["added_at"]),
    )


_C_COLS = "contact_id, owner_user_id, name, phone, email, linked_user_id, added_at"


class ContactsStore:
    """Контакты каждого пользователя — PostgreSQL."""

    def __init__(self, auth_store: AuthStore):
        self._auth_store = auth_store

    def _match_mimir_user(self, email: str | None) -> str | None:
        """Ищет зарегистрированного пользователя Мимира по email контакта."""
        if not email:
            return None
        user = self._auth_store.user_by_email(email)
        return user.user_id if user else None

    def _build(self, owner_user_id: str, name: str, phone: str | None, email: str | None) -> Contact:
        contact = Contact(
            contact_id=secrets.token_hex(6),
            owner_user_id=owner_user_id,
            name=name.strip(),
            phone=phone.strip() if phone else None,
            email=email.strip().lower() if email else None,
        )
        contact.linked_user_id = self._match_mimir_user(contact.email)
        return contact

    @staticmethod
    def _insert(conn, contact: Contact) -> None:
        conn.execute(
            f"INSERT INTO contacts ({_C_COLS}) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (contact.contact_id, contact.owner_user_id, contact.name, contact.phone,
             contact.email, contact.linked_user_id, db.to_db_time(contact.added_at)),
        )

    def add_contact(
        self, owner_user_id: str, name: str, phone: str | None = None, email: str | None = None
    ) -> Contact:
        if not name.strip():
            raise ContactsError("Имя контакта не может быть пустым")

        contact = self._build(owner_user_id, name, phone, email)
        with db.transaction() as conn:
            self._insert(conn, contact)
        logger.info("Добавлен контакт %s для пользователя %s", contact.name, owner_user_id)
        return contact

    def sync_contacts(self, owner_user_id: str, raw_contacts: list[dict]) -> list[Contact]:
        """Массовая синхронизация: принимает [{"name","phone","email"}, ...]
        из телефонной книги клиента, заменяет текущий список контактов
        пользователя на присланный (упрощённо — без диффа/мержа).
        Удаление старых и вставка новых — одна транзакция: при сбое
        посередине список остаётся прежним, а не пустым."""
        contacts: list[Contact] = []
        for raw in raw_contacts:
            name = (raw.get("name") or "").strip()
            if not name:
                continue  # пропускаем записи без имени — не с чем работать
            contacts.append(self._build(owner_user_id, name, raw.get("phone"), raw.get("email")))

        with db.transaction() as conn:
            conn.execute("DELETE FROM contacts WHERE owner_user_id = %s", (owner_user_id,))
            for contact in contacts:
                self._insert(conn, contact)

        logger.info(
            "Синхронизировано %d контактов для пользователя %s", len(contacts), owner_user_id
        )
        return contacts

    def list_contacts(self, owner_user_id: str) -> list[Contact]:
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_C_COLS} FROM contacts WHERE owner_user_id = %s ORDER BY added_at",
                (owner_user_id,),
            ).fetchall()
        return [_row_to_contact(r) for r in rows]

    def has_linked_contact(self, owner_user_id: str, linked_user_id: str) -> bool:
        """Есть ли у владельца контакт, сопоставленный с этим пользователем
        Мимира — используется для видимости профилей (api/routes/users.py)."""
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT 1 FROM contacts WHERE owner_user_id = %s AND linked_user_id = %s LIMIT 1",
                (owner_user_id, linked_user_id),
            ).fetchone()
        return row is not None

    def remove_contact(self, owner_user_id: str, contact_id: str) -> None:
        with db.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM contacts WHERE owner_user_id = %s AND contact_id = %s",
                (owner_user_id, contact_id),
            )
            if cur.rowcount == 0:
                raise ContactsError("Контакт не найден")
