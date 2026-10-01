"""
api/routes/auth.py — регистрация, вход, выход, текущий пользователь.
Пароли — bcrypt, сессии — 30 дней (core/auth_store.py).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException

from api.deps import auth_store, get_current_user
from api.schemas import AuthResponse, LoginRequest, RegisterRequest
from core.auth_store import AuthError, User

router = APIRouter()



@router.post("/auth/register", response_model=AuthResponse)
def register(req: RegisterRequest):
    try:
        user = auth_store.register(req.email, req.password, req.name)
        # Автологин сразу после регистрации — удобно для проверки фронта.
        _, token = auth_store.login(req.email, req.password)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AuthResponse(user=user.to_public_dict(), token=token)


@router.post("/auth/login", response_model=AuthResponse)
def login(req: LoginRequest):
    try:
        user, token = auth_store.login(req.email, req.password)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return AuthResponse(user=user.to_public_dict(), token=token)


@router.post("/auth/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        auth_store.logout(authorization.removeprefix("Bearer ").strip())
    return {"status": "logged_out"}


@router.get("/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return current_user.to_public_dict()