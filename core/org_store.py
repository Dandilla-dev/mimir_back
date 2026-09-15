"""
core/org_store.py — организации и привязка аккаунтов к ним (слой 4).

Реализует решение, зафиксированное в mimir_account_linkage_v1.md: флаг
DLP-проверки — свойство аккаунта, а не сообщения. Аккаунт пользователя
считается "привязанным" к организации только при наличии Membership со
статусом approved; только тогда мост (Message -> RawMessage, ещё не
реализован) должен начинать проверять исходящие сообщения этого
пользователя через core/message_parser.py.

Логика та же, что и в auth_store.py / contacts_store.py / messages_store.py:
всё в памяти процесса, никакой БД.

ВАЖНО (граница слоёв, mimir_architecture_v2.md §4): этот модуль ничего не
знает про DLP или транспорт. Он только хранит и отдаёт факт "у пользователя
X есть одобренное членство в организации Y" — использовать этот факт для
решения "проверять ли сообщение" будет мост, а не этот модуль.

Заглушка сознательно упрощена там, где mimir_account_linkage_v1.md §4
явно отмечает долг:
- кто может создать организацию и стать первым security_officer —
  не спроектировано; здесь создатель организации автоматически становится
  первым security_officer (тот же принцип, что и "любой email может
  зарегистрироваться" в auth_store.py — контроль легитимности вынесен
  за пределы заглушки).
- один пользователь — не более одной активной (approved) организации
  одновременно (долг §4, пункт 3) — проверяется на approve, не на request:
  подать заявку можно в несколько организаций, но одобрить можно только
  одну, пока остальные не отклонены/отозваны.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("mimir.org")


class OrgError(Exception):
    """Ошибка операций с организациями/членством (не найдено, нет прав и т.д.)."""


class MembershipStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class MembershipRole(str, Enum):
    MEMBER = "member"
    SECURITY_OFFICER = "security_officer"  # право решать по заявкам (см. account_linkage §2)


@dataclass
class Organization:
    org_id: str
    name: str
    created_by: str  # user_id
    created_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {"org_id": self.org_id, "name": self.name, "created_by": self.created_by}


@dataclass
class Membership:
    membership_id: str
    user_id: str
    org_id: str
    role: MembershipRole
    status: MembershipStatus
    requested_at: float = field(default_factory=time.time)
    decided_by: str | None = None
    decided_at: float | None = None

    def to_public_dict(self) -> dict:
        return {
            "membership_id": self.membership_id,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "role": self.role.value,
            "status": self.status.value,
            "requested_at": self.requested_at,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
        }


class OrgStore:
    """Организации и членства — всё в памяти процесса."""

    def __init__(self):
        self._orgs: dict[str, Organization] = {}
        self._memberships: dict[str, Membership] = {}

    # --------- Организации ---------

    def create_organization(self, creator_user_id: str, name: str) -> Organization:
        if not name.strip():
            raise OrgError("Название организации не может быть пустым")

        org = Organization(
            org_id=secrets.token_hex(8),
            name=name.strip(),
            created_by=creator_user_id,
        )
        self._orgs[org.org_id] = org

        # Создатель автоматически становится первым security_officer —
        # см. docstring модуля про долг "кто назначает первого офицера".
        membership = Membership(
            membership_id=secrets.token_hex(8),
            user_id=creator_user_id,
            org_id=org.org_id,
            role=MembershipRole.SECURITY_OFFICER,
            status=MembershipStatus.APPROVED,
            decided_by=creator_user_id,
            decided_at=time.time(),
        )
        self._memberships[membership.membership_id] = membership

        logger.info("Организация создана: %s (%s), первый security_officer: %s",
                    org.name, org.org_id, creator_user_id)
        return org

    def get_organization(self, org_id: str) -> Organization:
        org = self._orgs.get(org_id)
        if org is None:
            raise OrgError("Организация не найдена")
        return org

    # --------- Заявки на членство ---------

    def request_membership(self, user_id: str, org_id: str) -> Membership:
        self.get_organization(org_id)  # бросит OrgError, если организации нет

        existing = self._pending_or_approved_in_org(user_id, org_id)
        if existing is not None:
            raise OrgError(
                f"У пользователя уже есть заявка/членство в этой организации "
                f"(статус: {existing.status.value})"
            )

        membership = Membership(
            membership_id=secrets.token_hex(8),
            user_id=user_id,
            org_id=org_id,
            role=MembershipRole.MEMBER,
            status=MembershipStatus.PENDING,
        )
        self._memberships[membership.membership_id] = membership
        logger.info("Заявка на членство: user=%s -> org=%s", user_id, org_id)
        return membership

    def _pending_or_approved_in_org(self, user_id: str, org_id: str) -> Membership | None:
        for m in self._memberships.values():
            if (
                m.user_id == user_id
                and m.org_id == org_id
                and m.status in (MembershipStatus.PENDING, MembershipStatus.APPROVED)
            ):
                return m
        return None

    def list_pending(self, org_id: str) -> list[Membership]:
        return sorted(
            (
                m for m in self._memberships.values()
                if m.org_id == org_id and m.status == MembershipStatus.PENDING
            ),
            key=lambda m: m.requested_at,
        )

    # --------- Решение по заявке ---------

    def _require_security_officer(self, decider_user_id: str, org_id: str) -> None:
        for m in self._memberships.values():
            if (
                m.user_id == decider_user_id
                and m.org_id == org_id
                and m.status == MembershipStatus.APPROVED
                and m.role == MembershipRole.SECURITY_OFFICER
            ):
                return
        raise OrgError("Только security_officer этой организации может решать по заявкам")

    def is_security_officer(self, user_id: str, org_id: str) -> bool:
        """Публичная проверка роли, без исключения — для гейтинга на
        уровне API (см. api/server.py, /moderation/*), где отказ должен
        стать HTTP 403, а не внутренней ошибкой стора. В отличие от
        _require_security_officer() ниже (используется для /orgs/* —
        решений по заявкам на членство) просто отвечает bool; логика
        поиска членства та же."""
        for m in self._memberships.values():
            if (
                m.user_id == user_id
                and m.org_id == org_id
                and m.status == MembershipStatus.APPROVED
                and m.role == MembershipRole.SECURITY_OFFICER
            ):
                return True
        return False

    def is_owner(self, user_id: str, org_id: str) -> bool:
        """Владелец организации — тот, кто её создал (Organization.created_by),
        см. обсуждение в чате: изолированного security_officer может
        разблокировать только владелец, не другой officer (иначе
        скомпрометированный officer снимает изоляцию через другого
        officer'а или сам с собой, если officer'ов несколько).

        ПИЛОТНАЯ ЗАГЛУШКА: делегирование прав владельца отдельному
        назначенному лицу ("либо назначенное им лицо", см. обсуждение в
        чате) пока не реализовано — тот же класс долга, что и "кто
        назначает первого security_officer" (docstring create_organization
        выше). Публичная проверка без исключения — тот же паттерн, что
        is_security_officer()."""
        try:
            org = self.get_organization(org_id)
        except OrgError:
            return False
        return org.created_by == user_id

    def approve(self, membership_id: str, decider_user_id: str) -> Membership:
        membership = self._get_membership(membership_id)
        self._require_security_officer(decider_user_id, membership.org_id)

        if membership.status != MembershipStatus.PENDING:
            raise OrgError(f"Заявка уже решена (статус: {membership.status.value})")

        active_elsewhere = self.get_active_membership(membership.user_id)
        if active_elsewhere is not None:
            raise OrgError(
                "У пользователя уже есть активное членство в другой организации "
                "(один пользователь — не более одной активной организации, см. "
                "mimir_account_linkage_v1.md §4)"
            )

        membership.status = MembershipStatus.APPROVED
        membership.decided_by = decider_user_id
        membership.decided_at = time.time()
        logger.info("Заявка одобрена: %s (решил %s)", membership.membership_id, decider_user_id)
        return membership

    def reject(self, membership_id: str, decider_user_id: str) -> Membership:
        membership = self._get_membership(membership_id)
        self._require_security_officer(decider_user_id, membership.org_id)

        if membership.status != MembershipStatus.PENDING:
            raise OrgError(f"Заявка уже решена (статус: {membership.status.value})")

        membership.status = MembershipStatus.REJECTED
        membership.decided_by = decider_user_id
        membership.decided_at = time.time()
        logger.info("Заявка отклонена: %s (решил %s)", membership.membership_id, decider_user_id)
        return membership

    def _get_membership(self, membership_id: str) -> Membership:
        membership = self._memberships.get(membership_id)
        if membership is None:
            raise OrgError("Заявка/членство не найдено")
        return membership

    # --------- Запросы состояния (сюда будет обращаться будущий мост) ---------

    def get_active_membership(self, user_id: str) -> Membership | None:
        """Единственное approved-членство пользователя, если оно есть.

        Это именно тот факт, который мост (Message -> RawMessage) будет
        проверять перед вызовом core/message_parser.py для исходящих
        сообщений — см. mimir_account_linkage_v1.md §2. Сам этот метод
        ничего не знает о DLP и не вызывает parse_raw_message().
        """
        for m in self._memberships.values():
            if m.user_id == user_id and m.status == MembershipStatus.APPROVED:
                return m
        return None

    def is_dlp_active(self, user_id: str) -> bool:
        """Удобный булев хелпер поверх get_active_membership() — то же самое,
        что "нужно ли проверять исходящие сообщения этого пользователя"."""
        return self.get_active_membership(user_id) is not None
