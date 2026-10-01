"""
api/routes/users.py — профили пользователей (имя и email по user_id).

Сообщения и чаты содержат только user_id — клиенту нужно показать имена.
Профиль виден не всем подряд, а только тому, кто с этим человеком уже
как-то связан:
- это он сам;
- они в одной организации;
- между ними есть доставленные сообщения (в любую сторону или в общей
  группе);
- он есть в контактах смотрящего и сопоставлен с аккаунтом.
Иначе — как будто пользователя нет (404 для одного, пропуск в списке):
по случайному id нельзя выяснить чужой email.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.deps import auth_store, contacts_store, get_current_user, messages_store, org_store
from api.schemas import UserPublicOut, UsersListResponse
from core.auth_store import User

router = APIRouter()

MAX_BATCH = 100


def _can_see(viewer: User, target_id: str) -> bool:
    if viewer.user_id == target_id:
        return True
    mine = org_store.get_active_membership(viewer.user_id)
    theirs = org_store.get_active_membership(target_id)
    if mine is not None and theirs is not None and mine.org_id == theirs.org_id:
        return True
    if contacts_store.has_linked_contact(viewer.user_id, target_id):
        return True
    return messages_store.have_conversed(viewer.user_id, target_id)


def _profile(viewer: User, target_id: str) -> UserPublicOut | None:
    if not _can_see(viewer, target_id):
        return None
    user = auth_store.user_by_id(target_id)
    return UserPublicOut(**user.to_public_dict()) if user else None


@router.get("/users/{user_id}", response_model=UserPublicOut)
def get_user(user_id: str, current_user: User = Depends(get_current_user)):
    profile = _profile(current_user, user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return profile


@router.get("/users", response_model=UsersListResponse)
def get_users(
    ids: list[str] = Query(..., max_length=MAX_BATCH),
    current_user: User = Depends(get_current_user),
):
    """Несколько профилей разом: /users?ids=a&ids=b — например, все
    участники списка чатов одним запросом. Невидимые и несуществующие id
    молча пропускаются."""
    profiles = [_profile(current_user, uid) for uid in dict.fromkeys(ids)]
    return UsersListResponse(users=[p for p in profiles if p is not None])
