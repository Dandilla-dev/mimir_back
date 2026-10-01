"""
api/routes/org_dlp.py — DLP-базы организации, которые ведёт
security_officer: домены под наблюдением (блок 1), белый список ссылок
(блок 2), реестр устройств (блок 5), согласованный доступ и повышенные
права (блок 6). Удаление везде мягкое ([РЕШЕНИЕ 11]).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import access_store, get_current_user, require_security_officer, watchlist_store
from api.schemas import (
    AccessGrantOut,
    AccessGrantsListResponse,
    AddDomainRequest,
    DeviceOut,
    DevicesListResponse,
    GrantAccessRequest,
    RegisterDeviceRequest,
    WatchlistDomainOut,
    WatchlistListResponse,
    WhitelistDomainOut,
    WhitelistListResponse,
)
from core.access_store import AccessError
from core.auth_store import User
from core.watchlist_store import WatchlistError

router = APIRouter()


@router.post("/orgs/{org_id}/watchlist", response_model=WatchlistDomainOut)
def add_watchlisted_domain(
    org_id: str, req: AddDomainRequest, current_user: User = Depends(get_current_user)
):
    """Блок 1 (mimir_dlp_features_v1.md) — домен под наблюдением: конкурент
    для исходящих, известный источник фишинга для входящих. Только
    security_officer организации — см. require_security_officer."""
    require_security_officer(org_id, current_user)
    try:
        entry = watchlist_store.add_watchlisted(org_id, req.domain, current_user.user_id, req.reason)
    except WatchlistError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return WatchlistDomainOut(**entry.to_public_dict())


@router.get("/orgs/{org_id}/watchlist", response_model=WatchlistListResponse)
def list_watchlisted_domains(org_id: str, current_user: User = Depends(get_current_user)):
    require_security_officer(org_id, current_user)
    domains = watchlist_store.list_watchlisted(org_id)
    return WatchlistListResponse(domains=[WatchlistDomainOut(**e.to_public_dict()) for e in domains])


@router.delete("/orgs/{org_id}/watchlist/{entry_id}")
def remove_watchlisted_domain(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    require_security_officer(org_id, current_user)
    try:
        watchlist_store.remove_watchlisted(org_id, entry_id, current_user.user_id)
    except WatchlistError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


@router.get("/link-whitelist/default", response_model=list[str])
def default_whitelisted_link_domains(current_user: User = Depends(get_current_user)):
    """Общий read-only список для всех организаций (см. docstring
    core/watchlist_store.py, "проблема холодного старта") — фронтенду
    нужен отдельно от org-специфичного /orgs/{org_id}/link-whitelist,
    чтобы показать officer'у, что уже разрешено, а что можно добавить."""
    return watchlist_store.list_default_whitelisted()


@router.post("/orgs/{org_id}/link-whitelist", response_model=WhitelistDomainOut)
def add_whitelisted_link_domain(
    org_id: str, req: AddDomainRequest, current_user: User = Depends(get_current_user)
):
    """Блок 2 (mimir_dlp_features_v1.md) — одобренный домен для внешних
    ссылок в сообщениях. Полярность обратная watchlist: домен, НЕ
    внесённый сюда, трактуется парсером как "не в белом списке" (см.
    docstring core/watchlist_store.py)."""
    require_security_officer(org_id, current_user)
    try:
        entry = watchlist_store.add_whitelisted_link(org_id, req.domain, current_user.user_id, req.reason)
    except WatchlistError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return WhitelistDomainOut(**entry.to_public_dict())


@router.get("/orgs/{org_id}/link-whitelist", response_model=WhitelistListResponse)
def list_whitelisted_link_domains(org_id: str, current_user: User = Depends(get_current_user)):
    require_security_officer(org_id, current_user)
    domains = watchlist_store.list_whitelisted(org_id)
    return WhitelistListResponse(domains=[WhitelistDomainOut(**e.to_public_dict()) for e in domains])


@router.delete("/orgs/{org_id}/link-whitelist/{entry_id}")
def remove_whitelisted_link_domain(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    require_security_officer(org_id, current_user)
    try:
        watchlist_store.remove_whitelisted_link(org_id, entry_id, current_user.user_id)
    except WatchlistError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


# --------- Устройства + роли доступа (core/access_store.py, блоки 5 и 6) ---------


@router.post("/orgs/{org_id}/devices", response_model=DeviceOut)
def register_device(
    org_id: str, req: RegisterDeviceRequest, current_user: User = Depends(get_current_user)
):
    """Блок 5 — зарегистрированное рабочее устройство. Для пилота
    регистрирует только security_officer (самостоятельная регистрация
    сотрудником не предусмотрена, см. docstring core/access_store.py)."""
    require_security_officer(org_id, current_user)
    try:
        entry = access_store.register_device(
            org_id, req.device_id, req.user_id, current_user.user_id, req.label
        )
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DeviceOut(**entry.to_public_dict())


@router.get("/orgs/{org_id}/devices", response_model=DevicesListResponse)
def list_devices(org_id: str, current_user: User = Depends(get_current_user)):
    require_security_officer(org_id, current_user)
    devices = access_store.list_devices(org_id)
    return DevicesListResponse(devices=[DeviceOut(**d.to_public_dict()) for d in devices])


@router.delete("/orgs/{org_id}/devices/{entry_id}")
def unregister_device(org_id: str, entry_id: str, current_user: User = Depends(get_current_user)):
    require_security_officer(org_id, current_user)
    try:
        access_store.unregister_device(org_id, entry_id, current_user.user_id)
    except AccessError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


@router.post("/orgs/{org_id}/access/legitimate", response_model=AccessGrantOut)
def grant_legitimate_access(
    org_id: str, req: GrantAccessRequest, current_user: User = Depends(get_current_user)
):
    """Блок 6 — согласованный security_officer доступ сотрудника к данным
    организации (уточнено в чате 2026-09-16, см. docstring
    core/access_store.py: грант на уровне сотрудника, не на конкретное
    дело/контрагента — такого понятия в системе нет)."""
    require_security_officer(org_id, current_user)
    try:
        grant = access_store.grant_legitimate_access(org_id, req.user_id, current_user.user_id, req.note)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AccessGrantOut(**grant.to_public_dict())


@router.get("/orgs/{org_id}/access/legitimate", response_model=AccessGrantsListResponse)
def list_legitimate_access(org_id: str, current_user: User = Depends(get_current_user)):
    require_security_officer(org_id, current_user)
    grants = access_store.list_legitimate_access(org_id)
    return AccessGrantsListResponse(grants=[AccessGrantOut(**g.to_public_dict()) for g in grants])


@router.delete("/orgs/{org_id}/access/legitimate/{entry_id}")
def revoke_legitimate_access(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    require_security_officer(org_id, current_user)
    try:
        access_store.revoke_legitimate_access(org_id, entry_id, current_user.user_id)
    except AccessError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}


@router.post("/orgs/{org_id}/access/elevated", response_model=AccessGrantOut)
def grant_elevated_rights(
    org_id: str, req: GrantAccessRequest, current_user: User = Depends(get_current_user)
):
    require_security_officer(org_id, current_user)
    try:
        grant = access_store.grant_elevated_rights(org_id, req.user_id, current_user.user_id, req.note)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AccessGrantOut(**grant.to_public_dict())


@router.get("/orgs/{org_id}/access/elevated", response_model=AccessGrantsListResponse)
def list_elevated_rights(org_id: str, current_user: User = Depends(get_current_user)):
    require_security_officer(org_id, current_user)
    grants = access_store.list_elevated_rights(org_id)
    return AccessGrantsListResponse(grants=[AccessGrantOut(**g.to_public_dict()) for g in grants])


@router.delete("/orgs/{org_id}/access/elevated/{entry_id}")
def revoke_elevated_rights(
    org_id: str, entry_id: str, current_user: User = Depends(get_current_user)
):
    require_security_officer(org_id, current_user)
    try:
        access_store.revoke_elevated_rights(org_id, entry_id, current_user.user_id)
    except AccessError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "removed"}