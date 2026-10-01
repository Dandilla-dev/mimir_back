"""
api/routes/messages.py — отправка сообщений и их чтение (транспорт,
слой 1) вместе с DLP-проверкой на отправке.

Поток /messages/send:
1. Изолированный отправитель не может слать файлы (кроме аудио) и ссылки.
2. Исходящая DLP-проверка (core/message_bridge.py -> dlp_heuristics.classify):
   сбой проверки — сообщение не сохраняется (fail-closed, утечка от
   сотрудника — ядро продукта); THREAT — сообщение сохраняется со
   статусом pending_moderation и удерживается до решения security_officer
   (не блокировка без пути назад и не молчаливая пометка постфактум).
3. Входящая проверка для каждого получателя: сбой — сообщение всё равно
   доставляется (fail-open); THREAT (фишинг) — сообщение доставляется, но
   org-linked ПОЛУЧАТЕЛЬ изолируется. Держать каждое входящее THREAT до
   решения человека не масштабируется: одна фишинговая рассылка задевает
   сотни получателей, а исходящий THREAT по конструкции редкий.
4. Всё это — одна транзакция БД: либо записано всё, либо ничего.

THREAT определяется по вердикту classify(), а не по наличию
threat_reasons — см. _threat_decision().

/messages/send принимает multipart/form-data: вложения — настоящие файлы
(UploadFile), recipient_ids — повторяющееся поле формы
(recipient_ids=u2&recipient_ids=u3).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool

from api.deps import (
    access_store, auth_store, contacts_store, dlp_events_store, get_current_user,
    isolation_store, messages_store, moderation_store, org_store, watchlist_store,
)
from api.schemas import (
    MessageOut, MessagePendingModerationOut, MessagesListResponse, message_to_out,
)
from core import db
from core.auth_store import User
from core.dlp_heuristics import ThreatLevel, classify
from core.message_bridge import check_incoming, check_outgoing
from core.message_parser import contains_link, is_audio_attachment
from core.messages_store import MessagesError, MessageStatus

logger = logging.getLogger("mimir.api")

router = APIRouter()


@router.post("/messages/send", response_model=MessageOut | MessagePendingModerationOut)
async def send_message(
    recipient_ids: list[str] = Form(...),
    text: str = Form(""),
    files: list[UploadFile] = File(default=[]),
    device_id: str | None = Form(default=None),
    current_user: User = Depends(get_current_user),
):
    attachments = [
        {"filename": f.filename, "content": await f.read()}
        for f in files
    ]

    # Чтение файлов — асинхронное; всё остальное (запросы к БД) — в
    # отдельном потоке, чтобы не блокировать event loop на время запросов.
    return await run_in_threadpool(
        _send_message_sync, current_user, recipient_ids, text, attachments, device_id,
    )


def _send_message_sync(
    current_user: User,
    recipient_ids: list[str],
    text: str,
    attachments: list[dict],
    device_id: str | None,
) -> MessageOut | MessagePendingModerationOut:
    # Изоляция (core/isolation_store.py): изолированный аккаунт не может сам отправлять
    # файлы (кроме аудио) и ссылки — только текст/голос — пока
    # security_officer не снимет изоляцию. Проверяется ДО build_message:
    # нет смысла строить сообщение, которое всё равно будет отклонено.
    if isolation_store.is_isolated(current_user.user_id):
        disallowed_files = [
            a["filename"] for a in attachments if not is_audio_attachment(a["filename"])
        ]
        if disallowed_files:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Аккаунт изолирован после получения сообщения с признаками угрозы — "
                    "отправлять файлы (кроме аудио) нельзя, пока security_officer не "
                    f"снимет изоляцию: {', '.join(disallowed_files)}"
                ),
            )
        if contains_link(text):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Аккаунт изолирован после получения сообщения с признаками угрозы — "
                    "отправка ссылок недоступна, пока security_officer не снимет изоляцию"
                ),
            )

    # Всё, что ниже пишет в БД — сообщение, DLP-события, удержание,
    # изоляция получателя — одна транзакция: либо записано всё, либо
    # ничего (раньше падение процесса посередине оставляло, например,
    # DLP-события без сообщения). HTTPException внутри блока откатывает
    # транзакцию.
    with db.transaction():
        return _send_message_tx(current_user, recipient_ids, text, attachments, device_id)


def _threat_decision(classifications: list) -> tuple[bool, list[str]]:
    """Есть ли среди классификаций угроза и чем её объяснить.

    Решение принимается по ВЕРДИКТУ (level == THREAT), а не по наличию
    threat_reasons. У classify() два пути к THREAT (core/dlp_heuristics.py):
    - прямой: сработало самодостаточное THREAT-правило -> причины в
      threat_reasons;
    - эскалация: сошлись слабые сигналы (2+ ANOMALY-правила или одно при
      повышенных правах) -> уровень THREAT, но threat_reasons ПУСТОЙ,
      причины лежат в anomaly_reasons.
    Раньше решение принималось по непустому threat_reasons, и THREAT,
    полученный эскалацией, проходил без удержания/изоляции — и при этом
    не попадал ни в очередь модерации, ни в ANOMALY-сводку (там только
    level == anomaly), то есть был не виден человеку вообще.

    Причины для человека берутся из той графы, которая привела к вердикту:
    threat_reasons, если они есть, иначе anomaly_reasons — чтобы карточка
    удержания/изоляции не была пустой. Дубли (одинаковые причины от
    нескольких получателей) убираются, порядок сохраняется.
    """
    threat_results = [r for r in classifications if r.level == ThreatLevel.THREAT]
    reasons = [
        reason
        for r in threat_results
        for reason in (r.threat_reasons or r.anomaly_reasons)
    ]
    return bool(threat_results), list(dict.fromkeys(reasons))


def _send_message_tx(
    current_user: User,
    recipient_ids: list[str],
    text: str,
    attachments: list[dict],
    device_id: str | None,
) -> MessageOut | MessagePendingModerationOut:
    """Тело /messages/send внутри транзакции (см. send_message выше)."""
    try:
        message = messages_store.build_message(
            sender_id=current_user.user_id,
            recipient_ids=recipient_ids,
            text=text,
            attachments=attachments,
            device_id=device_id,
        )
    except MessagesError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # (check, classifications) пары — classify() вызывается здесь, снаружи
    # dlp_events_store.py (стор ничего не решает и не вычисляет сам).
    dlp_checks: list[tuple] = []

    # Исходящая — fail-closed на СБОЕ проверки (ядро продукта, утечка от
    # сотрудника): если проверка не отработала, сообщение НЕ сохраняется и
    # не доставляется вообще никому. check_outgoing() сама возвращает None
    # для личных/standalone аккаунтов — для них этот блок не бросает и не
    # блокирует.
    try:
        outgoing_check = check_outgoing(
            message, org_store, auth_store, contacts_store, watchlist_store, access_store
        )
    except Exception:
        logger.exception(
            "Исходящая DLP-проверка сообщения %s провалилась — сообщение "
            "НЕ сохранено и не доставлено (fail-closed)", message.message_id,
        )
        raise HTTPException(
            status_code=503,
            detail="Проверка сообщения временно недоступна, попробуйте ещё раз",
        )

    if outgoing_check is not None:
        outgoing_classifications = [classify(event) for event in outgoing_check.events]
        # Событие/классификацию сохраняем В ЛЮБОМ СЛУЧАЕ, даже если ниже
        # сообщение уйдёт на модерацию — это данные для будущего датасета
        # (неделя 7). Сообщения в БД ещё нет — FOREIGN KEY событий на
        # messages отложен до конца транзакции (DEFERRABLE).
        dlp_events_store.add_check(message.message_id, outgoing_check, outgoing_classifications)

        is_threat, threat_reasons = _threat_decision(outgoing_classifications)
        if is_threat:
            # THREAT на исходящем -> сообщение сохраняется со статусом
            # pending_moderation (невидимо никому) и удерживается до
            # решения officer'а. org_id — снимок организации отправителя
            # на этот момент ([РЕШЕНИЕ 7]); check_outgoing() не вернул бы
            # проверку без активного членства, поэтому оно здесь есть.
            sender_membership = org_store.get_active_membership(message.sender_id)
            if sender_membership is None:
                raise HTTPException(
                    status_code=503,
                    detail="Проверка сообщения временно недоступна, попробуйте ещё раз",
                )
            messages_store.store(message, status=MessageStatus.PENDING_MODERATION)
            pending = moderation_store.hold(message, threat_reasons, sender_membership.org_id)
            return MessagePendingModerationOut(
                hold_id=pending.hold_id, threat_reasons=threat_reasons,
            )

    # Входящая — fail-open на СБОЕ проверки: если проверка не отработала,
    # сообщение всё равно доставляется как обычно. Вложенная транзакция
    # (SAVEPOINT): ошибка БД внутри проверки откатывает только её, а не
    # всю отправку — иначе транзакция осталась бы в сломанном состоянии.
    try:
        with db.transaction():
            incoming_checks = check_incoming(
                message, auth_store, org_store, contacts_store, watchlist_store, access_store
            )
    except Exception:
        incoming_checks = []
        logger.exception(
            "Входящая DLP-проверка сообщения %s провалилась — сообщение "
            "всё равно будет доставлено (fail-open)", message.message_id,
        )
    for check in incoming_checks:
        classifications = [classify(event) for event in check.events]
        dlp_checks.append((check, classifications))

        # Автоизоляция получателя: входящий THREAT сообщение НЕ блокирует
        # (fail-open), но получателя изолирует — если он org-linked. Для
        # personal-аккаунтов изоляция не применяется — снять её было бы
        # некому, у personal нет security_officer.
        is_threat, threat_reasons = _threat_decision(classifications)
        if is_threat and org_store.get_active_membership(check.subject_user_id) is not None:
            isolation_store.isolate(check.subject_user_id, threat_reasons, message.message_id)

    messages_store.store(message)
    for check, classifications in dlp_checks:
        dlp_events_store.add_check(message.message_id, check, classifications)

    return message_to_out(message)


@router.get("/messages/history/{other_user_id}", response_model=MessagesListResponse)
def message_history(
    other_user_id: str, current_user: User = Depends(get_current_user)
):
    """История 1-на-1 переписки. Групповая история (3+ участников) через REST
    пока не открыта — messages_store.conversation_history() уже это умеет,
    эндпоинт для неё можно добавить отдельно, когда появятся групповые чаты
    на фронте."""
    history = messages_store.conversation_history(
        [current_user.user_id, other_user_id]
    )
    return MessagesListResponse(messages=[message_to_out(m) for m in history])


@router.get("/messages/inbox", response_model=MessagesListResponse)
def message_inbox(current_user: User = Depends(get_current_user)):
    inbox = messages_store.inbox(current_user.user_id)
    return MessagesListResponse(messages=[message_to_out(m) for m in inbox])