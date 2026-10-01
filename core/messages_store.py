"""
core/messages_store.py — транспортный слой: отправка сообщений между
пользователями, история переписки (PostgreSQL).

Таблицы: messages, message_recipients, attachments
(migrations/001_initial_schema.sql, раздел 4).

Это первый шаг слоя 1 (см. mimir_architecture_v2.md) — минимум, достаточный
для того, чтобы через реальную отправку сообщения запускалась DLP-труба
(core/message_parser.py). Статусы доставки/прочтения, WebSocket-доставка
в реальном времени и E2EE — следующие шаги, сюда не входят.

СТАТУС СООБЩЕНИЯ ([РЕШЕНИЕ 4], вариант (б) контракта): сообщение пишется
в БД сразу, а видимость решает status:
- delivered           — видно в inbox()/conversation_history();
- pending_moderation  — удержано (core/moderation_store.py), не видно никому;
- rejected            — отклонено officer'ом, не видно никому.
Раньше видимость решал сам факт вызова store(); теперь store() принимает
статус, а approve/reject меняют его (mark_delivered/mark_rejected).

ОТКЛОНЁННЫЕ ([РЕШЕНИЕ 10]): текст и вложения хранятся сутки после
отклонения, затем purge_rejected_content() их стирает. Остаются
метаданные, получатели, sha256 текста и вложений, размеры.

ПОЛУЧАТЕЛИ: message_recipients ссылается на users (FOREIGN KEY), поэтому
build_message() теперь отклоняет несуществующих получателей сразу
(MessagesError), а не пропускает их молча, как было в памяти.

conversation_key ([РЕШЕНИЕ 5]) — тот же ключ _conversation_key(), что и
раньше, но теперь колонка с индексом: история "ровно этот набор
участников" — простой WHERE.

Вложения пока хранятся байтами в БД (attachments.content, [РЕШЕНИЕ 6]);
переход на объектное хранилище (S3) — storage_uri, без изменения схемы.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

from core import db

logger = logging.getLogger("mimir.messages")


class MessagesError(Exception):
    """Ошибка операций с сообщениями (не найден адресат, пустое сообщение и т.д.)."""


class MessageStatus(str, Enum):
    PENDING_MODERATION = "pending_moderation"
    DELIVERED = "delivered"
    REJECTED = "rejected"


@dataclass
class Attachment:
    attachment_id: str
    filename: str
    content: bytes
    # Заполняется при чтении из БД без байтов (списки сообщений не тянут
    # содержимое вложений); None — размер считается по content.
    size_bytes: int | None = None

    @property
    def size(self) -> int:
        return self.size_bytes if self.size_bytes is not None else len(self.content)

    def to_public_dict(self) -> dict:
        return {
            "attachment_id": self.attachment_id,
            "filename": self.filename,
            "size_bytes": self.size,
        }


@dataclass
class Message:
    message_id: str
    sender_id: str
    recipient_ids: list[str]
    text: str
    attachments: list[Attachment] = field(default_factory=list)
    sent_at: float = field(default_factory=time.time)
    device_id: str | None = None  # устройство ОТПРАВИТЕЛЯ на момент отправки, см. docstring build_message()
    status: MessageStatus = MessageStatus.DELIVERED  # внутреннее поле, наружу не отдаётся

    def to_public_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "recipient_ids": self.recipient_ids,
            "text": self.text,
            "attachments": [a.to_public_dict() for a in self.attachments],
            "sent_at": self.sent_at,
            "device_id": self.device_id,
        }


def _conversation_key(participant_ids: list[str]) -> str:
    """Ключ переписки — не зависит от порядка участников и от того, кто
    сейчас отправитель, а кто получатель (симметричный ключ пары/группы).
    """
    return ":".join(sorted(set(participant_ids)))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_MSG_COLS = "message_id, sender_id, text, device_id, status, sent_at"
CONVERSATION_PREVIEW_CHARS = 100


@dataclass
class MessagePage:
    """Страница сообщений: от старых к новым; next_before — курсор для
    следующей (более старой) страницы, None — это последняя."""
    messages: list[Message]
    next_before: str | None = None


@dataclass
class ConversationSummary:
    """Один чат в списке чатов: набор участников и последнее сообщение."""
    conversation_key: str
    participant_ids: list[str]
    last_message_id: str
    last_sender_id: str
    last_text_preview: str
    last_sent_at: float
    last_has_attachments: bool
    message_count: int


@dataclass
class ConversationPage:
    conversations: list[ConversationSummary]
    next_before: str | None = None


class MessagesStore:
    """Реестр сообщений — PostgreSQL."""

    def build_message(
        self,
        sender_id: str,
        recipient_ids: list[str],
        text: str = "",
        attachments: list[dict] | None = None,
        device_id: str | None = None,
    ) -> Message:
        """Валидирует и строит Message, но НЕ сохраняет его — его ещё никто
        не может увидеть через inbox()/conversation_history(). Использовать
        вместе со store(): построить -> дать вызывающей стороне шанс
        проверить (DLP) -> store() с нужным статусом.

        device_id — устройство ОТПРАВИТЕЛЯ на момент отправки (см.
        Message.device_id). None — клиент не прислал идентификатор
        устройства, тогда признак "устройство не зарегистрировано"
        остаётся нейтральным (см. docstring
        core/message_parser.RawMessage.device_id).

        Несуществующие получатели — MessagesError (раньше пропускались
        молча; теперь message_recipients -> users это FOREIGN KEY)."""
        recipient_ids = list(dict.fromkeys(r for r in recipient_ids if r != sender_id))
        if not recipient_ids:
            raise MessagesError("Нужен хотя бы один получатель, отличный от отправителя")
        if not text.strip() and not attachments:
            raise MessagesError("Сообщение не может быть пустым (нет ни текста, ни вложений)")

        with db.transaction() as conn:
            rows = conn.execute(
                "SELECT user_id FROM users WHERE user_id = ANY(%s)", (recipient_ids,),
            ).fetchall()
        missing = set(recipient_ids) - {r["user_id"] for r in rows}
        if missing:
            raise MessagesError(f"Получатели не найдены: {', '.join(sorted(missing))}")

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
            device_id=device_id,
        )

    def store(
        self, message: Message, status: MessageStatus = MessageStatus.DELIVERED,
    ) -> None:
        """Сохраняет построенный (build_message) объект. С status=DELIVERED
        (по умолчанию, как раньше) сообщение сразу появляется в inbox() и
        conversation_history(); с PENDING_MODERATION — сохранено, но
        невидимо до mark_delivered()/mark_rejected()."""
        message.status = status
        conversation_key = _conversation_key([message.sender_id, *message.recipient_ids])
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO messages (message_id, sender_id, text, text_sha256, device_id, "
                "conversation_key, status, sent_at, delivered_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CASE WHEN %s THEN now() END)",
                (message.message_id, message.sender_id, message.text,
                 _sha256(message.text.encode("utf-8")), message.device_id,
                 conversation_key, status.value, db.to_db_time(message.sent_at),
                 status == MessageStatus.DELIVERED),
            )
            for recipient_id in message.recipient_ids:
                conn.execute(
                    "INSERT INTO message_recipients (message_id, recipient_id) VALUES (%s, %s)",
                    (message.message_id, recipient_id),
                )
            for a in message.attachments:
                conn.execute(
                    "INSERT INTO attachments (attachment_id, message_id, filename, size_bytes, "
                    "content_sha256, content) VALUES (%s, %s, %s, %s, %s, %s)",
                    (a.attachment_id, message.message_id, a.filename, len(a.content),
                     _sha256(a.content), a.content),
                )

        logger.info(
            "Сообщение сохранено (%s): %s -> %s (%d вложений)",
            status.value, message.sender_id, message.recipient_ids, len(message.attachments),
        )

    def send_message(
        self,
        sender_id: str,
        recipient_ids: list[str],
        text: str = "",
        attachments: list[dict] | None = None,
        device_id: str | None = None,
    ) -> Message:
        """Удобный шорткат build_message()+store() одним вызовом — для
        случаев, где отдельный шаг проверки между ними не нужен."""
        message = self.build_message(sender_id, recipient_ids, text, attachments, device_id)
        self.store(message)
        return message

    # --------- Смена статуса (модерация) ---------

    def mark_delivered(self, message_id: str) -> None:
        """approve: удержанное сообщение становится видимым получателям."""
        self._transition(message_id, MessageStatus.DELIVERED,
                         "delivered_at = now()")

    def mark_rejected(self, message_id: str) -> None:
        """reject: сообщение остаётся невидимым; через сутки содержимое
        стирается (purge_rejected_content)."""
        self._transition(message_id, MessageStatus.REJECTED,
                         "rejected_at = now()")

    def _transition(self, message_id: str, new_status: MessageStatus, set_time: str) -> None:
        with db.transaction() as conn:
            cur = conn.execute(
                f"UPDATE messages SET status = %s, {set_time} "
                "WHERE message_id = %s AND status = 'pending_moderation'",
                (new_status.value, message_id),
            )
            if cur.rowcount == 0:
                raise MessagesError(
                    f"Сообщение {message_id} не найдено или не ожидает модерации"
                )

    def purge_rejected_content(self, retention_seconds: int = 24 * 60 * 60) -> int:
        """[РЕШЕНИЕ 10] Стирает текст и вложения отклонённых сообщений,
        отклонённых раньше чем retention_seconds назад. Возвращает число
        затронутых сообщений. Вызывается фоновой задачей api/server.py."""
        with db.transaction() as conn:
            rows = conn.execute(
                "UPDATE messages SET text = NULL, content_purged_at = now() "
                "WHERE status = 'rejected' AND content_purged_at IS NULL "
                "AND rejected_at < now() - make_interval(secs => %s) "
                "RETURNING message_id",
                (retention_seconds,),
            ).fetchall()
            ids = [r["message_id"] for r in rows]
            if ids:
                # При переходе на S3: сначала удалить объекты по storage_uri.
                conn.execute(
                    "UPDATE attachments SET content = NULL, storage_uri = NULL, purged_at = now() "
                    "WHERE message_id = ANY(%s) AND purged_at IS NULL",
                    (ids,),
                )
        if ids:
            logger.info("Стёрто содержимое %d отклонённых сообщений", len(ids))
        return len(ids)

    # --------- Чтение ---------

    def get_message(self, message_id: str, with_content: bool = False) -> Message:
        """Сообщение в любом статусе (нужно модерации для удержанных).
        with_content=True — вместе с байтами вложений."""
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_MSG_COLS} FROM messages WHERE message_id = %s", (message_id,),
            ).fetchone()
            if row is None:
                raise MessagesError(f"Сообщение {message_id} не найдено")
            return self._hydrate(conn, [row], with_content)[0]

    def conversation_history(
        self,
        participant_ids: list[str],
        limit: int | None = None,
        before: str | None = None,
    ) -> MessagePage:
        """История переписки ровно этого набора участников (1-на-1 или
        группа). Постранично, см. MessagePage."""
        return self._page(
            "m.conversation_key = %(key)s",
            {"key": _conversation_key(participant_ids)},
            limit, before,
        )

    def inbox(
        self, user_id: str, limit: int | None = None, before: str | None = None,
    ) -> MessagePage:
        """Все доставленные сообщения, где user_id — отправитель или
        получатель. Постранично, см. MessagePage."""
        return self._page(
            "(m.sender_id = %(me)s OR EXISTS ("
            "  SELECT 1 FROM message_recipients r "
            "  WHERE r.message_id = m.message_id AND r.recipient_id = %(me)s))",
            {"me": user_id},
            limit, before,
        )

    def _page(
        self, where: str, params: dict, limit: int | None, before: str | None,
    ) -> MessagePage:
        """Общая постраничная выборка доставленных сообщений.

        Курсор — message_id: страница = limit сообщений, отправленных
        строго раньше сообщения before (или самых новых, если before нет).
        Не OFFSET: при новых сообщениях OFFSET сдвигает страницы и даёт
        дубли/пропуски, курсор — нет. Внутри страницы порядок — от старых
        к новым (как показывать в чате); next_before — курсор следующей,
        более старой страницы, None — старее ничего нет."""
        query = (
            f"SELECT {', '.join('m.' + c for c in _MSG_COLS.split(', '))} FROM messages m "
            f"WHERE m.status = 'delivered' AND {where}"
        )
        params = dict(params)
        if before is not None:
            query += (
                " AND (m.sent_at, m.message_id) < "
                "(SELECT sent_at, message_id FROM messages WHERE message_id = %(before)s)"
            )
            params["before"] = before
        query += " ORDER BY m.sent_at DESC, m.message_id DESC"
        if limit is not None:
            query += " LIMIT %(limit)s"
            params["limit"] = limit + 1  # +1 — узнать, есть ли следующая страница
        with db.transaction() as conn:
            rows = conn.execute(query, params).fetchall()
            has_more = limit is not None and len(rows) > limit
            rows = rows[:limit] if limit is not None else rows
            messages = self._hydrate(conn, list(reversed(rows)))
        return MessagePage(
            messages=messages,
            next_before=messages[0].message_id if has_more and messages else None,
        )

    def conversations(
        self, user_id: str, limit: int = 50, before: str | None = None,
    ) -> ConversationPage:
        """Список чатов пользователя: по одному на каждый набор участников,
        с последним сообщением, сначала самые свежие. Постранично: before —
        last_message_id последнего чата предыдущей страницы."""
        params: dict = {"me": user_id, "limit": limit + 1}
        cursor = ""
        if before is not None:
            cursor = (
                "WHERE (last.sent_at, last.message_id) < "
                "(SELECT sent_at, message_id FROM messages WHERE message_id = %(before)s)"
            )
            params["before"] = before
        with db.transaction() as conn:
            rows = conn.execute(
                f"""
                WITH mine AS (
                    SELECT m.message_id, m.conversation_key, m.sender_id, m.text, m.sent_at
                    FROM messages m
                    WHERE m.status = 'delivered' AND (m.sender_id = %(me)s OR EXISTS (
                        SELECT 1 FROM message_recipients r
                        WHERE r.message_id = m.message_id AND r.recipient_id = %(me)s))
                ),
                last AS (
                    SELECT DISTINCT ON (conversation_key) *
                    FROM mine
                    ORDER BY conversation_key, sent_at DESC, message_id DESC
                )
                SELECT last.*,
                       (SELECT count(*) FROM mine
                        WHERE mine.conversation_key = last.conversation_key) AS message_count,
                       EXISTS (SELECT 1 FROM attachments a
                               WHERE a.message_id = last.message_id) AS has_attachments
                FROM last
                {cursor}
                ORDER BY last.sent_at DESC, last.message_id DESC
                LIMIT %(limit)s
                """,
                params,
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [
            ConversationSummary(
                conversation_key=r["conversation_key"],
                participant_ids=r["conversation_key"].split(":"),
                last_message_id=r["message_id"],
                last_sender_id=r["sender_id"],
                last_text_preview=(r["text"] or "")[:CONVERSATION_PREVIEW_CHARS],
                last_sent_at=db.from_db_time(r["sent_at"]),
                last_has_attachments=r["has_attachments"],
                message_count=r["message_count"],
            )
            for r in rows
        ]
        return ConversationPage(
            conversations=items,
            next_before=items[-1].last_message_id if has_more and items else None,
        )

    def get_attachment(self, message_id: str, attachment_id: str) -> tuple[Message, Attachment]:
        """Вложение с байтами + его сообщение (в любом статусе — права
        проверяет api/, см. api/routes/messages.py). Стёртое вложение
        отклонённого сообщения ([РЕШЕНИЕ 10]) — MessagesError."""
        message = self.get_message(message_id)
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT attachment_id, filename, size_bytes, content, purged_at "
                "FROM attachments WHERE message_id = %s AND attachment_id = %s",
                (message_id, attachment_id),
            ).fetchone()
        if row is None:
            raise MessagesError("Вложение не найдено")
        if row["purged_at"] is not None or row["content"] is None:
            raise MessagesError("Содержимое вложения удалено")
        return message, Attachment(
            attachment_id=row["attachment_id"],
            filename=row["filename"],
            content=bytes(row["content"]),
            size_bytes=row["size_bytes"],
        )

    def have_conversed(self, user_a: str, user_b: str) -> bool:
        """Есть ли хоть одно доставленное сообщение между двумя
        пользователями (в любую сторону, в том числе в группе)."""
        with db.transaction() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM messages m
                JOIN message_recipients r ON r.message_id = m.message_id
                WHERE m.status = 'delivered'
                  AND ((m.sender_id = %(a)s AND r.recipient_id = %(b)s)
                    OR (m.sender_id = %(b)s AND r.recipient_id = %(a)s)
                    OR (r.recipient_id = %(a)s AND EXISTS (
                          SELECT 1 FROM message_recipients r2
                          WHERE r2.message_id = m.message_id AND r2.recipient_id = %(b)s)))
                LIMIT 1
                """,
                {"a": user_a, "b": user_b},
            ).fetchone()
        return row is not None

    @staticmethod
    def _hydrate(conn, rows: list[dict], with_content: bool = False) -> list[Message]:
        """Строки messages -> Message с получателями и вложениями (два
        запроса на весь список, а не по два на каждое сообщение)."""
        if not rows:
            return []
        ids = [r["message_id"] for r in rows]

        recipients: dict[str, list[str]] = {i: [] for i in ids}
        for r in conn.execute(
            "SELECT message_id, recipient_id FROM message_recipients "
            "WHERE message_id = ANY(%s) ORDER BY recipient_id",
            (ids,),
        ).fetchall():
            recipients[r["message_id"]].append(r["recipient_id"])

        content_col = "content" if with_content else "NULL::bytea AS content"
        attachments: dict[str, list[Attachment]] = {i: [] for i in ids}
        for a in conn.execute(
            f"SELECT message_id, attachment_id, filename, size_bytes, {content_col} "
            "FROM attachments WHERE message_id = ANY(%s) ORDER BY attachment_id",
            (ids,),
        ).fetchall():
            attachments[a["message_id"]].append(Attachment(
                attachment_id=a["attachment_id"],
                filename=a["filename"],
                content=bytes(a["content"]) if a["content"] is not None else b"",
                size_bytes=a["size_bytes"],
            ))

        return [
            Message(
                message_id=r["message_id"],
                sender_id=r["sender_id"],
                recipient_ids=recipients[r["message_id"]],
                text=r["text"] if r["text"] is not None else "",
                attachments=attachments[r["message_id"]],
                sent_at=db.from_db_time(r["sent_at"]),
                device_id=r["device_id"],
                status=MessageStatus(r["status"]),
            )
            for r in rows
        ]
