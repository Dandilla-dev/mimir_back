"""
api/deps.py — общее для всех маршрутов: экземпляры сторов и Мимира (один
набор на процесс), текущий пользователь по токену и проверки прав.

Проверки прав собраны здесь, а не в каждом маршруте, чтобы правило
"кто что может" было в одном месте:
- require_not_isolated      — изолированный аккаунт не трогает данные организации;
- require_security_officer  — officer этой организации (и не изолирован);
- require_officer_for_user  — officer организации, где состоит этот пользователь;
- require_moderation_access — officer организации из удержания (снимок, [РЕШЕНИЕ 7]);
- require_owner_or_deputy   — владелец или его заместитель (роли, миграция 002).
"""

from __future__ import annotations

from fastapi import Header, HTTPException

from core.access_store import AccessStore
from core.auth_store import AuthStore, User
from core.config import get_settings
from core.contacts_store import ContactsStore
from core.dlp_events_store import DLPEventsStore
from core.isolation_decisions_store import IsolationDecisionsStore
from core.isolation_store import IsolationStore
from core.messages_store import MessagesStore
from core.mimir import Mimir
from core.moderation_decisions_store import ModerationDecisionsStore
from core.moderation_store import ModerationStore
from core.org_store import OrgStore
from core.watchlist_store import WatchlistStore

settings = get_settings()

mimir = Mimir(settings=settings, load_local_model=settings.server.load_local_model)
auth_store = AuthStore()
contacts_store = ContactsStore(auth_store)
messages_store = MessagesStore()
org_store = OrgStore()
dlp_events_store = DLPEventsStore()
moderation_store = ModerationStore(messages_store)
moderation_decisions_store = ModerationDecisionsStore()
isolation_store = IsolationStore()
watchlist_store = WatchlistStore()
access_store = AccessStore()
isolation_decisions_store = IsolationDecisionsStore()


def get_current_user(authorization: str | None = Header(default=None)) -> User:
    """Достаёт пользователя по заголовку Authorization: Bearer <token>."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Не передан токен авторизации")

    token = authorization.removeprefix("Bearer ").strip()
    user = auth_store.user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Недействительный токен")
    return user


def require_not_isolated(current_user: User) -> None:
    """Изолированный аккаунт теряет доступ не только к отправке файлов и
    ссылок (api/routes/messages.py), но и ко всему уровня организации:
    заявки на членство, DLP-базы (watchlist, whitelist ссылок, устройства,
    гранты), роли, модерация. Личные данные (контакты, свои сообщения,
    чат с Мимиром) не org-scoped и сюда не входят."""
    if isolation_store.is_isolated(current_user.user_id):
        raise HTTPException(
            status_code=403,
            detail=(
                "Аккаунт изолирован — доступ к данным организации ограничен, "
                "пока security_officer не снимет изоляцию"
            ),
        )


def require_officer_for_user(target_user_id: str, current_user: User) -> None:
    """Общая проверка прав: current_user должен быть security_officer
    организации, где target_user_id состоит (approved membership), И САМ
    НЕ ИЗОЛИРОВАН (изоляция закрывает доступ ко
    ВСЕМУ в организации, включая собственные officer-права — иначе
    скомпрометированный officer снимает изоляцию сам с себя одним вызовом
    API, и весь механизм бессмысленен). Используется и для модерации
    исходящих holds (target = отправитель), и для снятия изоляции
    (target = изолированный получатель) — в обоих случаях право
    разбирать принадлежит НЕ-изолированному officer'у той же организации.

    Изолированного officer'а снимает не другой officer, а владелец или его
    заместитель — см. api/routes/moderation.py, lift_isolation()."""
    if isolation_store.is_isolated(current_user.user_id):
        raise HTTPException(
            status_code=403,
            detail=(
                "Аккаунт изолирован — officer-права недоступны, пока другой "
                "security_officer этой организации не снимет изоляцию"
            ),
        )
    membership = org_store.get_active_membership(target_user_id)
    if membership is None or not org_store.is_security_officer(
        current_user.user_id, membership.org_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Только security_officer организации этого пользователя может это сделать",
        )


def require_moderation_access(org_id: str, current_user: User) -> None:
    """Право модерировать hold принадлежит НЕ изолированному
    security_officer организации из hold.org_id — снимка организации
    отправителя на момент поступления сообщения ([РЕШЕНИЕ 7],
    mimir_db_migration_contract.md), а не его текущего членства: если
    отправителя исключили или перевели, пока сообщение ждёт решения,
    разбирает всё равно officer той организации."""
    if isolation_store.is_isolated(current_user.user_id):
        raise HTTPException(
            status_code=403,
            detail=(
                "Аккаунт изолирован — officer-права недоступны, пока другой "
                "security_officer этой организации не снимет изоляцию"
            ),
        )
    if not org_store.is_security_officer(current_user.user_id, org_id):
        raise HTTPException(
            status_code=403,
            detail="Только security_officer организации отправителя может это сделать",
        )


def officer_org_ids(current_user: User) -> list[str]:
    """Организации, где current_user — security_officer. Сейчас у
    пользователя не больше одного активного членства (инвариант БД
    memberships_one_active_per_user), поэтому список из 0 или 1 элемента."""
    membership = org_store.get_active_membership(current_user.user_id)
    if membership is None or not org_store.is_security_officer(
        current_user.user_id, membership.org_id
    ):
        return []
    return [membership.org_id]


def require_security_officer(org_id: str, current_user: User) -> None:
    """Гейтинг для org-scoped ресурсов DLP-баз: watchlist/link-whitelist
    доменов (core/watchlist_store.py) и устройства/роли доступа
    (core/access_store.py) — та же роль, что уже переиспользуется для
    всего DLP-контура (mimir_architecture_v2.md,
    org_store.MembershipRole.SECURITY_OFFICER, без отдельной DLP-роли).
    Изолированный аккаунт тоже не должен менять org-данные — см.
    require_not_isolated."""
    require_not_isolated(current_user)
    if not org_store.is_security_officer(current_user.user_id, org_id):
        raise HTTPException(
            status_code=403,
            detail="Только security_officer этой организации может это сделать",
        )


def require_owner_or_deputy(org_id: str, current_user: User) -> None:
    """Действия "только владелец": назначение/снятие security_officer,
    разблокировка изолированного officer'а. Владелец или его заместитель,
    сам не изолированный."""
    require_not_isolated(current_user)
    if not org_store.is_owner_or_deputy(current_user.user_id, org_id):
        raise HTTPException(
            status_code=403,
            detail="Только владелец организации или его заместитель может это сделать",
        )
