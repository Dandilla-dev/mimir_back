"""
core/messages_store.py — заглушка транспортного слоя: отправка сообщений
между пользователями, история переписки.

Логика та же, что и в auth_store.py/contacts_store.py: всё в памяти
процесса, никакой БД. При перезапуске сервера вся переписка пропадает —
это ожидаемо для заглушки.

Это первый шаг слоя 1 (см. mimir_architecture_v2.md) — минимум, достаточный
для того, чтобы через реальную отправку сообщения запускалась DLP-труба
(core/message_parser.py). Статусы доставки/прочтения, WebSocket-доставка
в реальном времени и E2EE — следующие шаги, сюда не входят.

ВАЖНО: как и auth_store.py — заглушка. Перед продакшеном заменить:
- dict в памяти -> реальная БД
- вложения в памяти -> объектное хранилище (S3-совместимое или локальный
  зашифрованный диск)
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

logger = logging.getLogger("mimir.messages")


class MessagesError(Exception):
    """Ошибка операций с сообщениями (не найден адресат, пустое сообщение и т.д.)."""


@dataclass
class Attachment:
    attachment_id: str
    filename: str
    content: bytes

    def to_public_dict(self) -> dict:
        return {
            "attachment_id": self.attachment_id,
            "filename": self.filename,
            "size_bytes": len(self.content),
        }


@dataclass
class Message:
    message_id: str
    sender_id: str
    recipient_ids: list[str]
    text: str
    attachments: list[Attachment] = field(default_factory=list)
    sent_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "recipient_ids": self.recipient_ids,
            "text": self.text,
            "attachments": [a.to_public_dict() for a in self.attachments],
            "sent_at": self.sent_at,
        }


def _conversation_key(participant_ids: list[str]) -> str:
    """Ключ переписки — не зависит от порядка участников и от того, кто
    сейчас отправитель, а кто получатель (симметричный ключ пары/группы).
    """
    return ":".join(sorted(set(participant_ids)))


class MessagesStore:
    """Реестр сообщений — всё в памяти процесса, сгруппировано по переписке."""

    def __init__(self):
        self._messages_by_id: dict[str, Message] = {}
        self._conversations: dict[str, list[str]] = {}  # conversation_key -> [message_id, ...]

    def build_message(
        self,
        sender_id: str,
        recipient_ids: list[str],
        text: str = "",
        attachments: list[dict] | None = None,
    ) -> Message:
        """Валидирует и строит Message, но НЕ сохраняет его — оно ещё не
        существует ни в одном индексе, значит его ещё никто не может
        увидеть через inbox()/conversation_history(). Использовать вместе
        со store(): построить -> дать вызывающей стороне шанс отказаться
        от сохранения (например, если DLP-проверка провалилась) -> store().
        """
        recipient_ids = [r for r in recipient_ids if r != sender_id]
        if not recipient_ids:
            raise MessagesError("Нужен хотя бы один получатель, отличный от отправителя")
        if not text.strip() and not attachments:
            raise MessagesError("Сообщение не может быть пустым (нет ни текста, ни вложений)")

        return Message(
            message_id=secrets.token_hex(8),
            sender_id=sender_id,
            recipient_ids=recipient_ids,
            text=text,
            attachments=[
                Attachment(
                    attachment_id=secrets.token_hex(6),
                    filename=a["filename"],
                    content=a["content"],
                )
                for a in (attachments or [])
            ],
        )

    def store(self, message: Message) -> None:
        """Сохраняет уже построенный (build_message) объект — после этого
        момента он появляется в inbox() и conversation_history(). Отдельный
        шаг от build_message() специально для того, чтобы вызывающая
        сторона могла вставить проверку между "построили" и "доставили"."""
        self._messages_by_id[message.message_id] = message

        key = _conversation_key([message.sender_id, *message.recipient_ids])
        self._conversations.setdefault(key, []).append(message.message_id)

        logger.info(
            "Сообщение отправлено: %s -> %s (%d вложений)",
            message.sender_id, message.recipient_ids, len(message.attachments),
        )

    def send_message(
        self,
        sender_id: str,
        recipient_ids: list[str],
        text: str = "",
        attachments: list[dict] | None = None,
    ) -> Message:
        """Удобный шорткат build_message()+store() одним вызовом — для
        случаев, где отдельный шаг проверки между ними не нужен."""
        message = self.build_message(sender_id, recipient_ids, text, attachments)
        self.store(message)
        return message

    def get_message(self, message_id: str) -> Message:
        message = self._messages_by_id.get(message_id)
        if message is None:
            raise MessagesError(f"Сообщение {message_id} не найдено")
        return message

    def conversation_history(self, participant_ids: list[str]) -> list[Message]:
        """История переписки между заданными участниками, по времени отправки."""
        key = _conversation_key(participant_ids)
        message_ids = self._conversations.get(key, [])
        return [self._messages_by_id[mid] for mid in message_ids]

    def inbox(self, user_id: str) -> list[Message]:
        """Все сообщения, где user_id — отправитель или получатель, по времени."""
        messages = [
            m for m in self._messages_by_id.values()
            if m.sender_id == user_id or user_id in m.recipient_ids
        ]
        return sorted(messages, key=lambda m: m.sent_at)
