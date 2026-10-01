"""
api/routes/auth.py — регистрация, вход, выход, текущий пользователь,
смена пароля. Пароли — bcrypt, сессии — 30 дней, перебор паролей
ограничен (core/auth_store.py).

IP клиента для ограничения попыток — request.client.host. За обратным
прокси (Nginx) это будет адрес самого прокси, и лимит по IP станет общим
для всех — uvicorn нужно запускать с --proxy-headers
--forwarded-allow-ips=<адрес прокси>, тогда здесь будет настоящий адрес.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from api.deps import auth_store, get_current_user
from api.schemas import AuthResponse, ChangePasswordRequest, LoginRequest, RegisterRequest
from core.auth_store import AuthError, LoginThrottled, User

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
def login(req: LoginRequest, request: Request):
    try:
        user, token = auth_store.login(req.email, req.password, ip=_client_ip(request))
    except LoginThrottled as exc:
        raise HTTPException(
            status_code=429, detail=str(exc), headers={"Retry-After": str(exc.retry_after)},
        ) from exc
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


@router.post("/auth/password")
def change_password(
    req: ChangePasswordRequest,
    request: Request,
    authorization: str = Header(...),
    current_user: User = Depends(get_current_user),
):
    """Смена пароля: нужен текущий пароль. Все ОСТАЛЬНЫЕ сессии
    пользователя завершаются (если старый пароль утёк и кто-то уже вошёл
    — его выкинет), текущая остаётся."""
    token = authorization.removeprefix("Bearer ").strip()
    try:
        revoked = auth_store.change_password(
            current_user, req.current_password, req.new_password,
            keep_token=token, ip=_client_ip(request),
        )
    except LoginThrottled as exc:
        raise HTTPException(
            status_code=429, detail=str(exc), headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "password_changed", "other_sessions_revoked": revoked}


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None

