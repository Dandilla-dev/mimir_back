"""
api/routes/orgs.py — организации, заявки на членство, роли.

Флаг DLP-проверки — свойство аккаунта (approved-членство), а не
сообщения (mimir_account_linkage_v1.md). Эти маршруты только хранят и
отдают факт привязки; проверять ли сообщение, решает core/message_bridge.py
по org_store.is_dlp_active().

Роли (миграция 002): security_officer назначает и снимает владелец или
его заместитель; заместителя назначает и снимает только владелец.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import (
    get_current_user, org_store, require_not_isolated, require_owner_or_deputy,
    require_security_officer,
)
from api.schemas import (
    CreateOrgRequest,
    DeputyOut,
    MembershipOut,
    MembershipsListResponse,
    OrgOut,
    UserRefRequest,
    membership_to_out,
    org_to_out,
)
from core.auth_store import User
from core.org_store import OrgError

router = APIRouter()


@router.post("/orgs", response_model=OrgOut)
def create_org(
    req: CreateOrgRequest, current_user: User = Depends(get_current_user)
):
    """Создатель автоматически становится первым security_officer (см.
    org_store.py docstring про долг "кто назначает первого офицера")."""
    try:
        org = org_store.create_organization(current_user.user_id, req.name)
    except OrgError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return org_to_out(org)


@router.post("/orgs/{org_id}/join", response_model=MembershipOut)
def request_membership(
    org_id: str, current_user: User = Depends(get_current_user)
):
    try:
        membership = org_store.request_membership(current_user.user_id, org_id)
    except OrgError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return membership_to_out(membership)


@router.get("/orgs/{org_id}/pending", response_model=MembershipsListResponse)
def list_pending_memberships(
    org_id: str, current_user: User = Depends(get_current_user)
):
    """Список заявок на рассмотрении — только security_officer этой
    организации (те же права, что у approve/reject). Раньше просмотр был
    открыт любому залогиненному пользователю — утечка: посторонний видел,
    кто подаёт заявки в чужую организацию. require_security_officer сама
    первым делом вызывает require_not_isolated, изоляция по-прежнему
    закрывает доступ."""
    require_security_officer(org_id, current_user)
    pending = org_store.list_pending(org_id)
    return MembershipsListResponse(memberships=[membership_to_out(m) for m in pending])


@router.post("/orgs/memberships/{membership_id}/approve", response_model=MembershipOut)
def approve_membership(
    membership_id: str, current_user: User = Depends(get_current_user)
):
    """Только security_officer организации может одобрить — проверяется
    внутри org_store.approve()."""
    try:
        membership = org_store.approve(membership_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return membership_to_out(membership)


@router.post("/orgs/memberships/{membership_id}/reject", response_model=MembershipOut)
def reject_membership(
    membership_id: str, current_user: User = Depends(get_current_user)
):
    try:
        membership = org_store.reject(membership_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return membership_to_out(membership)


@router.get("/me/membership", response_model=MembershipOut | None)
def my_membership(current_user: User = Depends(get_current_user)):
    """Активное (approved) членство текущего пользователя, если есть. Это
    и есть "флаг", включающий DLP-проверку его исходящих сообщений."""
    membership = org_store.get_active_membership(current_user.user_id)
    return membership_to_out(membership) if membership else None


# --------- Роли: участники, security_officer, заместитель владельца ---------

@router.get("/orgs/{org_id}/members", response_model=MembershipsListResponse)
def list_members(org_id: str, current_user: User = Depends(get_current_user)):
    """Одобренные члены организации с ролями — чтобы выбрать, кого
    назначить officer'ом или заместителем. Видят officer'ы, владелец и
    заместитель."""
    require_not_isolated(current_user)
    if not (
        org_store.is_security_officer(current_user.user_id, org_id)
        or org_store.is_owner_or_deputy(current_user.user_id, org_id)
    ):
        raise HTTPException(status_code=403, detail="Нет доступа к составу организации")
    return MembershipsListResponse(
        memberships=[membership_to_out(m) for m in org_store.list_members(org_id)]
    )


@router.post("/orgs/{org_id}/officers", response_model=MembershipOut)
def appoint_officer(
    org_id: str, req: UserRefRequest, current_user: User = Depends(get_current_user),
):
    """Назначить security_officer: только владелец или заместитель."""
    require_owner_or_deputy(org_id, current_user)
    try:
        membership = org_store.appoint_officer(org_id, req.user_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return membership_to_out(membership)


@router.delete("/orgs/{org_id}/officers/{user_id}", response_model=MembershipOut)
def demote_officer(org_id: str, user_id: str, current_user: User = Depends(get_current_user)):
    """Снять роль security_officer (вернуть в member): только владелец или
    заместитель. С владельца роль не снимается."""
    require_owner_or_deputy(org_id, current_user)
    try:
        membership = org_store.demote_officer(org_id, user_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return membership_to_out(membership)


@router.get("/orgs/{org_id}/deputy", response_model=DeputyOut)
def get_deputy(org_id: str, current_user: User = Depends(get_current_user)):
    require_not_isolated(current_user)
    if not (
        org_store.is_security_officer(current_user.user_id, org_id)
        or org_store.is_owner_or_deputy(current_user.user_id, org_id)
    ):
        raise HTTPException(status_code=403, detail="Нет доступа к составу организации")
    return DeputyOut(org_id=org_id, user_id=org_store.get_deputy(org_id))


@router.put("/orgs/{org_id}/deputy", response_model=DeputyOut)
def set_deputy(org_id: str, req: UserRefRequest, current_user: User = Depends(get_current_user)):
    """Назначить заместителя владельца (прежний, если был, снимается).
    Только владелец."""
    require_not_isolated(current_user)
    try:
        org_store.set_deputy(org_id, req.user_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return DeputyOut(org_id=org_id, user_id=req.user_id)


@router.delete("/orgs/{org_id}/deputy", response_model=DeputyOut)
def revoke_deputy(org_id: str, current_user: User = Depends(get_current_user)):
    """Снять заместителя. Только владелец."""
    require_not_isolated(current_user)
    try:
        org_store.revoke_deputy(org_id, current_user.user_id)
    except OrgError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return DeputyOut(org_id=org_id, user_id=None)

