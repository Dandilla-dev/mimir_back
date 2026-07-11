"""
core/contacts_store.py — заглушка контактов: хранение и "синхронизация".

Логика та же, что и в auth_store.py: всё в памяти процесса, никакой БД.

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


class ContactsStore:
    """Контакты каждого пользователя — в памяти процесса, ключ owner_user_id."""

    def __init__(self, auth_store: AuthStore):
        self._auth_store = auth_store
        # owner_user_id -> {contact_id: Contact}
        self._contacts: dict[str, dict[str, Contact]] = {}

    def _bucket(self, owner_user_id: str) -> dict[str, Contact]:
        return self._contacts.setdefault(owner_user_id, {})

    def _match_mimir_user(self, email: str | None) -> str | None:
        """Ищет зарегистрированного пользователя Мимира по email контакта."""
        if not email:
            return None
        for user in self._auth_store.all_users():
            if user.email == email.strip().lower():
                return user.user_id
        return None

    def add_contact(
        self, owner_user_id: str, name: str, phone: str | None = None, email: str | None = None
    ) -> Contact:
        if not name.strip():
            raise ContactsError("Имя контакта не может быть пустым")

        contact = Contact(
            contact_id=secrets.token_hex(6),
            owner_user_id=owner_user_id,
            name=name.strip(),
            phone=phone.strip() if phone else None,
            email=email.strip().lower() if email else None,
        )
        contact.linked_user_id = self._match_mimir_user(contact.email)

        self._bucket(owner_user_id)[contact.contact_id] = contact
        logger.info("Добавлен контакт %s для пользователя %s", contact.name, owner_user_id)
        return contact

    def sync_contacts(self, owner_user_id: str, raw_contacts: list[dict]) -> list[Contact]:
        """Массовая синхронизация: принимает [{"name","phone","email"}, ...]
        из телефонной книги клиента, заменяет текущий список контактов
        пользователя на присланный (упрощённо — без диффа/мержа)."""
        bucket: dict[str, Contact] = {}
        for raw in raw_contacts:
            name = (raw.get("name") or "").strip()
            if not name:
                continue  # пропускаем записи без имени — не с чем работать
            phone = raw.get("phone")
            email = raw.get("email")

            contact = Contact(
                contact_id=secrets.token_hex(6),
                owner_user_id=owner_user_id,
                name=name,
                phone=phone.strip() if phone else None,
                email=email.strip().lower() if email else None,
            )
            contact.linked_user_id = self._match_mimir_user(contact.email)
            bucket[contact.contact_id] = contact

        self._contacts[owner_user_id] = bucket
        logger.info(
            "Синхронизировано %d контактов для пользователя %s", len(bucket), owner_user_id
        )
        return list(bucket.values())

    def list_contacts(self, owner_user_id: str) -> list[Contact]:
        return list(self._bucket(owner_user_id).values())

    def remove_contact(self, owner_user_id: str, contact_id: str) -> None:
        bucket = self._bucket(owner_user_id)
        if contact_id not in bucket:
            raise ContactsError("Контакт не найден")
        del bucket[contact_id]
