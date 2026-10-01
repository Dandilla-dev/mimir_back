"""
core/org_store.py — организации и привязка аккаунтов к ним (слой 4).

Реализует решение, зафиксированное в mimir_account_linkage_v1.md: флаг
DLP-проверки — свойство аккаунта, а не сообщения. Аккаунт пользователя
считается "привязанным" к организации только при наличии Membership со
статусом approved; только тогда мост (Message -> RawMessage) должен начинать проверять исходящие сообщения этого
пользователя через core/message_parser.py (это делает
core/message_bridge.py).

Хранение — PostgreSQL, таблицы organizations и memberships
(migrations/001_initial_schema.sql, раздел 2). Два инварианта, которые
раньше проверялись циклами в Python, теперь держит сама БД (частичные
UNIQUE-индексы) — без гонки при одновременных запросах:
- memberships_one_open_per_org: не больше одной pending/approved заявки
  на пару (user, org);
- memberships_one_active_per_user: не больше одного approved членства
  на пользователя (долг §4 п.3 ниже).
Python-проверки перед записью оставлены ради понятных сообщений об
ошибке; нарушение, проскочившее между проверкой и записью, ловится как
UniqueViolation и превращается в тот же OrgError.

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

РОЛИ (решения 2026-10-01, миграция 002):
- владелец — создатель организации (Organization.created_by), всегда
  security_officer, снять с него роль нельзя;
- заместитель владельца — не больше одного действующего (таблица
  org_deputies, с историей). Назначает и снимает только владелец.
  Заместитель может всё, что только владелец: назначать и снимать
  security_officer, разблокировать изолированного officer'а. Не может
  назначить своего заместителя и не может передать владение;
- security_officer назначает и снимает только владелец или заместитель —
  НЕ другой officer: скомпрометированный officer не должен иметь
  возможности назначить сообщника. Каждая смена роли пишется в
  неизменяемый журнал role_changes.
Права проверяются здесь, в сторе (как и решения по заявкам) — api/
только превращает OrgError в HTTP-ответ. Изоляция актёра проверяется
выше, в api/ (стор про изоляцию не знает).
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

from core import db

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


def _row_to_org(row: dict) -> Organization:
    return Organization(
        org_id=row["org_id"],
        name=row["name"],
        created_by=row["created_by"],
        created_at=db.from_db_time(row["created_at"]),
    )


def _row_to_membership(row: dict) -> Membership:
    return Membership(
        membership_id=row["membership_id"],
        user_id=row["user_id"],
        org_id=row["org_id"],
        role=MembershipRole(row["role"]),
        status=MembershipStatus(row["status"]),
        requested_at=db.from_db_time(row["requested_at"]),
        decided_by=row["decided_by"],
        decided_at=db.from_db_time(row["decided_at"]),
    )


_M_COLS = "membership_id, user_id, org_id, role, status, requested_at, decided_by, decided_at"


class OrgStore:
    """Организации и членства — PostgreSQL."""

    # --------- Организации ---------

    def create_organization(self, creator_user_id: str, name: str) -> Organization:
        if not name.strip():
            raise OrgError("Название организации не может быть пустым")

        org = Organization(
            org_id=secrets.token_hex(8),
            name=name.strip(),
            created_by=creator_user_id,
        )
        # Создатель автоматически становится первым security_officer —
        # см. docstring модуля про долг "кто назначает первого офицера".
        # Организация и членство создателя — одна транзакция.
        now = time.time()
        try:
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO organizations (org_id, name, created_by, created_at) "
                    "VALUES (%s, %s, %s, %s)",
                    (org.org_id, org.name, org.created_by, db.to_db_time(org.created_at)),
                )
                conn.execute(
                    f"INSERT INTO memberships ({_M_COLS}) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (secrets.token_hex(8), creator_user_id, org.org_id,
                     MembershipRole.SECURITY_OFFICER.value, MembershipStatus.APPROVED.value,
                     db.to_db_time(now), creator_user_id, db.to_db_time(now)),
                )
        except db.UniqueViolation as exc:
            # memberships_one_active_per_user: создатель уже состоит в
            # другой организации (approved). Раньше это молча создавало
            # второе активное членство в обход правила §4 п.3.
            raise OrgError(
                "У пользователя уже есть активное членство в другой организации — "
                "создать новую организацию нельзя (один пользователь — не более "
                "одной активной организации, см. mimir_account_linkage_v1.md §4)"
            ) from exc

        logger.info("Организация создана: %s (%s), первый security_officer: %s",
                    org.name, org.org_id, creator_user_id)
        return org

    def get_organization(self, org_id: str) -> Organization:
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT org_id, name, created_by, created_at FROM organizations WHERE org_id = %s",
                (org_id,),
            ).fetchone()
        if row is None:
            raise OrgError("Организация не найдена")
        return _row_to_org(row)

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
        try:
            with db.transaction() as conn:
                conn.execute(
                    f"INSERT INTO memberships ({_M_COLS}) VALUES (%s, %s, %s, %s, %s, %s, NULL, NULL)",
                    (membership.membership_id, user_id, org_id, membership.role.value,
                     membership.status.value, db.to_db_time(membership.requested_at)),
                )
        except db.UniqueViolation as exc:
            raise OrgError("У пользователя уже есть заявка/членство в этой организации") from exc
        logger.info("Заявка на членство: user=%s -> org=%s", user_id, org_id)
        return membership

    def _pending_or_approved_in_org(self, user_id: str, org_id: str) -> Membership | None:
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_M_COLS} FROM memberships "
                "WHERE user_id = %s AND org_id = %s AND status IN ('pending', 'approved') LIMIT 1",
                (user_id, org_id),
            ).fetchone()
        return _row_to_membership(row) if row else None

    def list_pending(self, org_id: str) -> list[Membership]:
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_M_COLS} FROM memberships "
                "WHERE org_id = %s AND status = 'pending' ORDER BY requested_at",
                (org_id,),
            ).fetchall()
        return [_row_to_membership(r) for r in rows]

    # --------- Решение по заявке ---------

    def _require_security_officer(self, decider_user_id: str, org_id: str) -> None:
        if not self.is_security_officer(decider_user_id, org_id):
            raise OrgError("Только security_officer этой организации может решать по заявкам")

    def is_security_officer(self, user_id: str, org_id: str) -> bool:
        """Публичная проверка роли, без исключения — для гейтинга на
        уровне API (см. api/server.py, /moderation/*), где отказ должен
        стать HTTP 403, а не внутренней ошибкой стора. В отличие от
        _require_security_officer() (используется для /orgs/* —
        решений по заявкам на членство) просто отвечает bool; логика
        поиска членства та же."""
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT 1 FROM memberships WHERE user_id = %s AND org_id = %s "
                "AND status = 'approved' AND role = 'security_officer' LIMIT 1",
                (user_id, org_id),
            ).fetchone()
        return row is not None

    def is_owner(self, user_id: str, org_id: str) -> bool:
        """Владелец организации — тот, кто её создал (Organization.created_by)."""
        try:
            org = self.get_organization(org_id)
        except OrgError:
            return False
        return org.created_by == user_id

    def is_owner_or_deputy(self, user_id: str, org_id: str) -> bool:
        """Право на действия "только владелец": назначение/снятие
        security_officer, разблокировка изолированного officer'а."""
        return self.is_owner(user_id, org_id) or self.get_deputy(org_id) == user_id

    # --------- Заместитель владельца ---------

    def get_deputy(self, org_id: str) -> str | None:
        """user_id действующего заместителя или None."""
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT user_id FROM org_deputies WHERE org_id = %s AND revoked_at IS NULL",
                (org_id,),
            ).fetchone()
        return row["user_id"] if row else None

    def set_deputy(self, org_id: str, user_id: str, owner_user_id: str) -> None:
        """Назначает заместителя. Прежний заместитель, если был, снимается
        в той же транзакции (заменяется). Только владелец; заместителем
        может быть только одобренный член этой организации, не сам
        владелец."""
        if not self.is_owner(owner_user_id, org_id):
            raise OrgError("Назначить заместителя может только владелец организации")
        if user_id == owner_user_id:
            raise OrgError("Владелец не может быть собственным заместителем")
        self._require_member_of(user_id, org_id)
        with db.transaction() as conn:
            conn.execute(
                "UPDATE org_deputies SET revoked_at = now(), revoked_by = %s "
                "WHERE org_id = %s AND revoked_at IS NULL",
                (owner_user_id, org_id),
            )
            conn.execute(
                "INSERT INTO org_deputies (entry_id, org_id, user_id, appointed_by) "
                "VALUES (%s, %s, %s, %s)",
                (secrets.token_hex(8), org_id, user_id, owner_user_id),
            )
        logger.info("Заместитель владельца назначен: %s (org=%s)", user_id, org_id)

    def revoke_deputy(self, org_id: str, owner_user_id: str) -> None:
        if not self.is_owner(owner_user_id, org_id):
            raise OrgError("Снять заместителя может только владелец организации")
        with db.transaction() as conn:
            cur = conn.execute(
                "UPDATE org_deputies SET revoked_at = now(), revoked_by = %s "
                "WHERE org_id = %s AND revoked_at IS NULL",
                (owner_user_id, org_id),
            )
            if cur.rowcount == 0:
                raise OrgError("У организации нет заместителя")
        logger.info("Заместитель владельца снят (org=%s)", org_id)

    # --------- Назначение / снятие security_officer ---------

    def appoint_officer(self, org_id: str, user_id: str, actor_user_id: str) -> Membership:
        """member -> security_officer. Только владелец или заместитель."""
        return self._change_role(
            org_id, user_id, actor_user_id,
            MembershipRole.MEMBER, MembershipRole.SECURITY_OFFICER,
        )

    def demote_officer(self, org_id: str, user_id: str, actor_user_id: str) -> Membership:
        """security_officer -> member. Только владелец или заместитель;
        с владельца роль не снимается."""
        if self.is_owner(user_id, org_id):
            raise OrgError("Владелец организации всегда security_officer — снять роль нельзя")
        return self._change_role(
            org_id, user_id, actor_user_id,
            MembershipRole.SECURITY_OFFICER, MembershipRole.MEMBER,
        )

    def _change_role(
        self, org_id: str, user_id: str, actor_user_id: str,
        old_role: MembershipRole, new_role: MembershipRole,
    ) -> Membership:
        if not self.is_owner_or_deputy(actor_user_id, org_id):
            raise OrgError(
                "Назначать и снимать security_officer может только владелец "
                "организации или его заместитель"
            )
        membership = self._require_member_of(user_id, org_id)
        if membership.role != old_role:
            raise OrgError(
                f"У пользователя роль {membership.role.value}, ожидалась {old_role.value}"
            )
        with db.transaction() as conn:
            row = conn.execute(
                f"UPDATE memberships SET role = %s "
                f"WHERE membership_id = %s AND role = %s AND status = 'approved' "
                f"RETURNING {_M_COLS}",
                (new_role.value, membership.membership_id, old_role.value),
            ).fetchone()
            if row is None:
                raise OrgError("Роль уже изменена другим запросом")
            conn.execute(
                "INSERT INTO role_changes (change_id, membership_id, old_role, new_role, changed_by) "
                "VALUES (%s, %s, %s, %s, %s)",
                (secrets.token_hex(8), membership.membership_id,
                 old_role.value, new_role.value, actor_user_id),
            )
        logger.info(
            "Роль изменена: user=%s org=%s %s -> %s (изменил %s)",
            user_id, org_id, old_role.value, new_role.value, actor_user_id,
        )
        return _row_to_membership(row)

    def _require_member_of(self, user_id: str, org_id: str) -> Membership:
        membership = self.get_active_membership(user_id)
        if membership is None or membership.org_id != org_id:
            raise OrgError("Пользователь не состоит в этой организации")
        return membership

    def list_members(self, org_id: str) -> list[Membership]:
        """Одобренные члены организации — для выбора, кого назначить
        officer'ом или заместителем."""
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_M_COLS} FROM memberships "
                "WHERE org_id = %s AND status = 'approved' ORDER BY requested_at",
                (org_id,),
            ).fetchall()
        return [_row_to_membership(r) for r in rows]

    def approve(self, membership_id: str, decider_user_id: str) -> Membership:
        return self._decide(membership_id, decider_user_id, MembershipStatus.APPROVED)

    def reject(self, membership_id: str, decider_user_id: str) -> Membership:
        return self._decide(membership_id, decider_user_id, MembershipStatus.REJECTED)

    def _decide(
        self, membership_id: str, decider_user_id: str, new_status: MembershipStatus,
    ) -> Membership:
        """Общая часть approve/reject. UPDATE ... WHERE status = 'pending' —
        атомарно: два officer'а, решающих одну заявку одновременно, не
        получат два решения — второй увидит "уже решена"."""
        membership = self._get_membership(membership_id)
        self._require_security_officer(decider_user_id, membership.org_id)

        if membership.status != MembershipStatus.PENDING:
            raise OrgError(f"Заявка уже решена (статус: {membership.status.value})")

        if new_status == MembershipStatus.APPROVED:
            active_elsewhere = self.get_active_membership(membership.user_id)
            if active_elsewhere is not None:
                raise OrgError(
                    "У пользователя уже есть активное членство в другой организации "
                    "(один пользователь — не более одной активной организации, см. "
                    "mimir_account_linkage_v1.md §4)"
                )

        try:
            with db.transaction() as conn:
                row = conn.execute(
                    f"UPDATE memberships SET status = %s, decided_by = %s, decided_at = now() "
                    f"WHERE membership_id = %s AND status = 'pending' RETURNING {_M_COLS}",
                    (new_status.value, decider_user_id, membership_id),
                ).fetchone()
        except db.UniqueViolation as exc:
            raise OrgError(
                "У пользователя уже есть активное членство в другой организации "
                "(один пользователь — не более одной активной организации, см. "
                "mimir_account_linkage_v1.md §4)"
            ) from exc
        if row is None:
            raise OrgError("Заявка уже решена")

        logger.info("Заявка %s: %s (решил %s)", new_status.value, membership_id, decider_user_id)
        return _row_to_membership(row)

    def _get_membership(self, membership_id: str) -> Membership:
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_M_COLS} FROM memberships WHERE membership_id = %s", (membership_id,),
            ).fetchone()
        if row is None:
            raise OrgError("Заявка/членство не найдено")
        return _row_to_membership(row)

    # --------- Запросы состояния (сюда обращается мост) ---------

    def get_active_membership(self, user_id: str) -> Membership | None:
        """Единственное approved-членство пользователя, если оно есть.

        Это именно тот факт, который мост (Message -> RawMessage) проверяет
        перед вызовом core/message_parser.py — см. mimir_account_linkage_v1.md
        §2. Самый частый запрос стора (на каждое сообщение) — обслуживается
        частичным уникальным индексом memberships_one_active_per_user.
        """
        with db.transaction() as conn:
            row = conn.execute(
                f"SELECT {_M_COLS} FROM memberships WHERE user_id = %s AND status = 'approved'",
                (user_id,),
            ).fetchone()
        return _row_to_membership(row) if row else None

    def is_dlp_active(self, user_id: str) -> bool:
        """Удобный булев хелпер поверх get_active_membership() — то же самое,
        что "нужно ли проверять исходящие сообщения этого пользователя"."""
        return self.get_active_membership(user_id) is not None
