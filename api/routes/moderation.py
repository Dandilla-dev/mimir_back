"""
api/routes/moderation.py — работа security_officer с тем, что нашла DLP:
очередь удержанных исходящих (approve/reject), журнал решений,
ANOMALY-сводка, изолированные аккаунты и снятие изоляции с вердиктом.

Права: всё здесь — только НЕ изолированному security_officer той
организации, к которой относится событие (отдельной DLP-роли нет —
та же роль, что решает заявки на членство). Изолированного officer'а
разблокирует владелец или его заместитель, не другой officer.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import (
    auth_store, dlp_events_store, get_current_user, isolation_decisions_store,
    isolation_store, messages_store, moderation_decisions_store, moderation_store,
    officer_org_ids, org_store, require_moderation_access, require_not_isolated,
    require_officer_for_user,
)
from api.schemas import (
    AnomalySubjectSummary,
    AnomalySummaryResponse,
    IsolatedListResponse,
    IsolatedUserOut,
    IsolationDecisionOut,
    IsolationDecisionsListResponse,
    LiftIsolationRequest,
    LiftIsolationResponse,
    ModerationDecisionOut,
    ModerationDecisionRequest,
    ModerationDecisionsListResponse,
    ModerationQueueResponse,
    ModerationResolveResponse,
    PendingModerationOut,
    message_to_out,
)
from core import db
from core.auth_store import User
from core.dlp_heuristics import ThreatLevel
from core.isolation_decisions_store import IsolationDecisionError
from core.isolation_store import IsolationError
from core.messages_store import Message
from core.moderation_decisions_store import Decision, ModerationDecision
from core.moderation_store import ModerationError

router = APIRouter()


@router.get("/moderation/pending", response_model=ModerationQueueResponse)
def moderation_pending(current_user: User = Depends(get_current_user)):
    """Очередь сообщений, удержанных из-за THREAT на исходящей проверке.
    Разбор ЕДИНИЧНЫЙ по карточкам, в отличие от ANOMALY-сводки (та
    рассчитана на масштаб в сотни сотрудников): THREAT — редкий сигнал,
    каждый требует решения человека по отдельности, не пачкой. Сюда
    попадает и THREAT, полученный эскалацией ANOMALY-сигналов."""
    require_not_isolated(current_user)
    # Видна только очередь ТЕХ организаций, где current_user —
    # security_officer (см. require_moderation_access) — не глобальная
    # очередь всей системы вне зависимости от того, кто спрашивает.
    # Фильтр — по hold.org_id (снимок, [РЕШЕНИЕ 7]), не по текущему
    # членству отправителя.
    pending = moderation_store.list_pending(org_ids=officer_org_ids(current_user))
    return ModerationQueueResponse(
        pending=[
            PendingModerationOut(
                hold_id=p.hold_id,
                message=message_to_out(p.message),
                threat_reasons=p.threat_reasons,
                held_at=p.held_at,
            )
            for p in pending
        ]
    )


def _resolve_hold(
    hold_id: str,
    decision: Decision,
    req: ModerationDecisionRequest | None,
    current_user: User,
) -> tuple[Message, ModerationDecision]:
    """Общая часть approve/reject — одна транзакция: проверка прав ->
    закрытие удержания -> смена статуса сообщения -> запись решения в
    журнал (core/moderation_decisions_store.py). Упало любое звено —
    откатывается всё, удержание остаётся открытым.

    resolve() — UPDATE ... WHERE resolved_at IS NULL: второй officer,
    нажавший одновременно, дождётся блокировки строки, получит 0 строк
    -> 404 и второе решение не запишет.

    org_id решения — из удержания (снимок, [РЕШЕНИЕ 7]), не из текущего
    членства отправителя, поэтому всегда заполнен."""
    with db.transaction():
        try:
            pending = moderation_store.get(hold_id)  # сперва право, потом resolve
        except ModerationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        require_moderation_access(pending.org_id, current_user)
        try:
            message = moderation_store.resolve(hold_id)
        except ModerationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        if decision == Decision.APPROVED:
            messages_store.mark_delivered(message.message_id)  # теперь видно получателю
        else:
            messages_store.mark_rejected(message.message_id)   # невидимо; стирание через сутки

        entry = moderation_decisions_store.record(
            hold_id=pending.hold_id,
            message_id=message.message_id,
            sender_id=message.sender_id,
            org_id=pending.org_id,
            decided_by=current_user.user_id,
            decision=decision,
            reviewer_confidence=req.reviewer_confidence if req else None,
            threat_reasons=pending.threat_reasons,
            held_at=pending.held_at,
        )
    return message, entry


@router.post("/moderation/{hold_id}/approve", response_model=ModerationResolveResponse)
def moderation_approve(
    hold_id: str,
    req: ModerationDecisionRequest | None = None,
    current_user: User = Depends(get_current_user),
):
    """Человек подтвердил, что сообщение можно доставить (ложное
    срабатывание эвристики) — удержание закрывается, решение пишется в
    журнал, статус сообщения становится delivered — оно видно получателю."""
    message, entry = _resolve_hold(hold_id, Decision.APPROVED, req, current_user)
    return ModerationResolveResponse(
        status="approved", message=message_to_out(message), decision_id=entry.decision_id,
    )


@router.post("/moderation/{hold_id}/reject", response_model=ModerationResolveResponse)
def moderation_reject(
    hold_id: str,
    req: ModerationDecisionRequest | None = None,
    current_user: User = Depends(get_current_user),
):
    """Человек подтвердил угрозу — удержание закрывается, решение пишется
    в журнал, статус сообщения становится rejected: получатель его не
    увидит никогда, содержимое стирается через сутки ([РЕШЕНИЕ 10]),
    метаданные и решение остаются."""
    message, entry = _resolve_hold(hold_id, Decision.REJECTED, req, current_user)
    return ModerationResolveResponse(
        status="rejected", message=message_to_out(message), decision_id=entry.decision_id,
    )


@router.get("/moderation/decisions", response_model=ModerationDecisionsListResponse)
def moderation_decisions(current_user: User = Depends(get_current_user)):
    """Журнал решений по удержаниям — только по организациям, где
    current_user — security_officer (тот же принцип, что
    /moderation/pending). Новые первыми. Только чтение: решение не
    редактируется и не удаляется через API."""
    require_not_isolated(current_user)
    visible = moderation_decisions_store.list_all(org_ids=officer_org_ids(current_user))
    return ModerationDecisionsListResponse(
        decisions=[ModerationDecisionOut(**d.to_public_dict()) for d in visible]
    )


@router.get("/moderation/anomaly-summary", response_model=AnomalySummaryResponse)
def anomaly_summary(current_user: User = Depends(get_current_user)):
    """Агрегированная сводка по ANOMALY-событиям, сгруппированная по
    отправителю — сводка вместо карточки на каждое событие (при 1000 сотрудниках одиночные
    ANOMALY идут пачкой, не по одной записи, в отличие от THREAT).

    Это ТОЛЬКО группировка при чтении поверх уже сохранённых
    core/dlp_events_store.DLPEventRecord — отдельного хранилища под
    сводку нет и не нужно, полей level/anomaly_reasons уже достаточно.

    subject_user_id для ANOMALY-записи — всегда отправитель (все
    ANOMALY-правила в core/dlp_heuristics.py срабатывают только на
    исходящей проверке, is_incoming=False) — то есть тот, кто фактически
    создал аномальную отправку, а не случайный третий пользователь.

    Видна только та часть сводки, что относится к организациям, где
    current_user — security_officer (тот же принцип гейтинга, что и
    /moderation/*, см. require_moderation_access) — офицер одной
    компании не должен видеть нарушителей другой.

    user_id резолвится в email/имя через auth_store.user_by_id() — тот
    же паттерн резолва, что уже применён в core/message_bridge.py при
    построении RawMessage."""
    require_not_isolated(current_user)
    records = dlp_events_store.list_by_level(ThreatLevel.ANOMALY)

    grouped: dict[str, list] = {}
    for record in records:
        grouped.setdefault(record.subject_user_id, []).append(record)

    summary: list[AnomalySubjectSummary] = []
    for user_id, user_records in grouped.items():
        membership = org_store.get_active_membership(user_id)
        if membership is None or not org_store.is_security_officer(
            current_user.user_id, membership.org_id
        ):
            continue  # не организация current_user — не его дело разбирать

        user = auth_store.user_by_id(user_id)
        if user is None:
            continue  # защитная ветка: аккаунт мог быть удалён, событие осталось

        reason_counts: dict[str, int] = {}
        for record in user_records:
            for reason in record.anomaly_reasons:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

        summary.append(
            AnomalySubjectSummary(
                user_id=user_id,
                email=user.email,
                name=user.name,
                count=len(user_records),
                reason_counts=reason_counts,
                last_recorded_at=max(r.recorded_at for r in user_records),
            )
        )

    # Больше всего нарушений — первым: офицеру интереснее всего разобрать
    # сначала самый заметный паттерн, не хронологию по алфавиту user_id.
    summary.sort(key=lambda s: s.count, reverse=True)
    return AnomalySummaryResponse(summary=summary)


@router.get("/moderation/isolated", response_model=IsolatedListResponse)
def isolated_list(current_user: User = Depends(get_current_user)):
    """Активные изоляции (core/isolation_store.py) — видны только те, что
    относятся к организациям, где current_user — security_officer (тот
    же принцип, что и /moderation/pending, /moderation/anomaly-summary)."""
    require_not_isolated(current_user)
    isolated: list[IsolatedUserOut] = []
    for record in isolation_store.list_active():
        membership = org_store.get_active_membership(record.user_id)
        if membership is None or not org_store.is_security_officer(
            current_user.user_id, membership.org_id
        ):
            continue

        user = auth_store.user_by_id(record.user_id)
        if user is None:
            continue  # защитная ветка: аккаунт мог быть удалён

        isolated.append(
            IsolatedUserOut(
                user_id=record.user_id,
                email=user.email,
                name=user.name,
                threat_reasons=record.threat_reasons,
                isolated_at=record.isolated_at,
            )
        )

    isolated.sort(key=lambda i: i.isolated_at)
    return IsolatedListResponse(isolated=isolated)


@router.post("/moderation/isolated/{user_id}/lift", response_model=LiftIsolationResponse)
def lift_isolation(
    user_id: str,
    req: LiftIsolationRequest,
    current_user: User = Depends(get_current_user),
):
    """Снимает изоляцию и записывает вердикт человека — метку датасета для
    входящих событий (core/isolation_decisions_store.py).

    Право зависит от того, КТО изолирован:
    - обычный сотрудник -> любой НЕ изолированный security_officer его
      организации;
    - сам security_officer -> только владелец организации или его
      заместитель, и не он сам. Если бы officer мог разблокировать
      другого officer'а (или себя), скомпрометированный officer снимал
      бы изоляцию сам с себя или через сговор — этот случай решает
      человек, отвечающий за бизнес, не автоматика.

    Снятие и вердикт — одна транзакция: без вердикта изоляция не снимается.
    """
    require_not_isolated(current_user)  # актёр сам не должен быть изолирован ни в одной ветке

    membership = org_store.get_active_membership(user_id)
    if membership is None:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден или не состоит в организации",
        )

    if org_store.is_security_officer(user_id, membership.org_id):
        if current_user.user_id == user_id:
            raise HTTPException(
                status_code=403,
                detail="Снять изоляцию с самого себя нельзя",
            )
        if not org_store.is_owner_or_deputy(current_user.user_id, membership.org_id):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Изолированного security_officer может разблокировать только "
                    "владелец организации или его заместитель"
                ),
            )
    else:
        require_officer_for_user(user_id, current_user)

    with db.transaction():
        try:
            record = isolation_store.lift(user_id, lifted_by=current_user.user_id)
        except IsolationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        try:
            decision = isolation_decisions_store.record(
                isolation_id=record.isolation_id,
                user_id=user_id,
                org_id=membership.org_id,
                decided_by=current_user.user_id,
                verdict=req.verdict,
                reviewer_confidence=req.reviewer_confidence,
                threat_reasons=record.threat_reasons,
                isolated_at=record.isolated_at,
            )
        except IsolationDecisionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return LiftIsolationResponse(user_id=user_id, decision_id=decision.decision_id)


@router.get("/moderation/isolation-decisions", response_model=IsolationDecisionsListResponse)
def isolation_decisions(current_user: User = Depends(get_current_user)):
    """Журнал вердиктов по снятым изоляциям — только организаций, где
    current_user — security_officer (как /moderation/decisions)."""
    require_not_isolated(current_user)
    entries = isolation_decisions_store.list_all(org_ids=officer_org_ids(current_user))
    return IsolationDecisionsListResponse(
        decisions=[
            IsolationDecisionOut(
                decision_id=d.decision_id,
                isolation_id=d.isolation_id,
                user_id=d.user_id,
                org_id=d.org_id,
                decided_by=d.decided_by,
                verdict=d.verdict.value,
                reviewer_confidence=d.reviewer_confidence.value if d.reviewer_confidence else None,
                threat_reasons=list(d.threat_reasons),
                isolated_at=d.isolated_at,
                decided_at=d.decided_at,
            )
            for d in entries
        ]
    )
