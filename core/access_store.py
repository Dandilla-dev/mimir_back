"""
core/access_store.py — реестр устройств (блок 5 mimir_dlp_features_v1.md)
и роли доступа (блок 6): легитимный доступ к данным организации,
повышенные/административные права.

Закрывает третью, последнюю из трёх баз, зафиксированных как долг в
mimir_architecture_v2.md §7 ("реестр устройств + роли доступа") — те же
две базы, которые архитектурный документ сознательно объединяет в одну
(в отличие от watchlist доменов, вынесенного в core/watchlist_store.py
отдельным долгом).

ХРАНЕНИЕ — PostgreSQL, таблицы registered_devices и access_grants
(migrations/001_initial_schema.sql, раздел 9). Решения контракта:
- [РЕШЕНИЕ 9] оба вида грантов — одна таблица access_grants с колонкой
  grant_type ('legitimate_access' | 'elevated_rights'); публичные методы
  остались раздельными, как раньше;
- [РЕШЕНИЕ 11] мягкое удаление: unregister/revoke заполняют
  revoked_at/revoked_by вместо удаления строки; проверки и списки видят
  только действующие записи, уникальность — тоже только среди них.

--- Устройства (блок 5) ---

"Зарегистрированное рабочее устройство" — просто пара (org_id, device_id),
привязанная к user_id, кто её зарегистрировал (для пилота — только
security_officer, самостоятельная регистрация сотрудником не
предусмотрена: официальная политика "только
корпоративные устройства" упомянута в mimir_dlp_features_v1.md блок 5 как
рекомендация продукта клиентам).

--- Легитимный доступ (блок 6) ---

Уточнено в чате 2026-09-16 (до этого была открытая архитектурная
развилка, см. mimir_dlp_features_v1.md блок 6 и обсуждение о том, что
такое "resource"): легитимный доступ — это **согласованный контролирующим
лицом (security_officer) доступ сотрудника к данным, имеющимся в
распоряжении организации**, а не грант на конкретное дело/контрагента.
Поэтому здесь это ПРОСТОЙ грант уровня (org_id, user_id) — есть или нет,
без второго измерения "к чему именно". ParserLookups.has_legitimate_access
по контракту принимает (user, resource) — сигнатура не меняется (см.
make_lookups_from_access_store в message_parser.py), но resource этой
базой игнорируется целиком: она не про конкретный ресурс, а про сотрудника
в принципе. Если позже понятие "дело/кейс" всё же появится в системе —
это станет отдельным следующим измерением гранта, не переделкой этого.

Повышенные права — тот же паттерн гранта, независимый флаг: сотрудник
может иметь легитимный доступ без повышенных прав и наоборот.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

from core import db

logger = logging.getLogger("mimir.access")


class AccessError(Exception):
    """Ошибка операций с реестром устройств/ролей (не найдено, дубликат и т.д.)."""


@dataclass
class RegisteredDevice:
    """Зарегистрированное рабочее устройство — блок 5."""

    entry_id: str
    org_id: str
    device_id: str
    user_id: str  # чьё устройство
    label: str
    registered_by: str  # user_id того, кто зарегистрировал (officer)
    registered_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "label": self.label,
            "registered_by": self.registered_by,
            "registered_at": self.registered_at,
        }


@dataclass
class AccessGrant:
    """Один грант — легитимный доступ ИЛИ повышенные права (два раздельных
    набора в сторе ниже, но одна и та же форма записи)."""

    entry_id: str
    org_id: str
    user_id: str
    granted_by: str  # user_id security_officer, согласовавшего доступ
    note: str
    granted_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "org_id": self.org_id,
            "user_id": self.user_id,
            "granted_by": self.granted_by,
            "note": self.note,
            "granted_at": self.granted_at,
        }


_D_COLS = "entry_id, org_id, device_id, user_id, label, registered_by, registered_at"
_G_COLS = "entry_id, org_id, user_id, granted_by, note, granted_at"

LEGITIMATE_ACCESS = "legitimate_access"
ELEVATED_RIGHTS = "elevated_rights"


def _row_to_device(r: dict) -> RegisteredDevice:
    return RegisteredDevice(
        entry_id=r["entry_id"], org_id=r["org_id"], device_id=r["device_id"],
        user_id=r["user_id"], label=r["label"], registered_by=r["registered_by"],
        registered_at=db.from_db_time(r["registered_at"]),
    )


def _row_to_grant(r: dict) -> AccessGrant:
    return AccessGrant(
        entry_id=r["entry_id"], org_id=r["org_id"], user_id=r["user_id"],
        granted_by=r["granted_by"], note=r["note"],
        granted_at=db.from_db_time(r["granted_at"]),
    )


class AccessStore:
    """Устройства + легитимный доступ + повышенные права — по
    организациям, PostgreSQL."""

    # --------- Устройства (блок 5) ---------

    def register_device(
        self, org_id: str, device_id: str, user_id: str, registered_by: str, label: str = "",
    ) -> RegisteredDevice:
        device_id = device_id.strip()
        if not device_id:
            raise AccessError("device_id не может быть пустым")

        entry = RegisteredDevice(
            entry_id=secrets.token_hex(8),
            org_id=org_id,
            device_id=device_id,
            user_id=user_id,
            label=label.strip(),
            registered_by=registered_by,
        )
        try:
            with db.transaction() as conn:
                conn.execute(
                    f"INSERT INTO registered_devices ({_D_COLS}) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (entry.entry_id, org_id, device_id, user_id, entry.label, registered_by,
                     db.to_db_time(entry.registered_at)),
                )
        except db.UniqueViolation as exc:
            raise AccessError(f"Устройство {device_id} уже зарегистрировано в этой организации") from exc
        except db.ForeignKeyViolation as exc:
            raise AccessError("Пользователь не найден") from exc
        logger.info(
            "Устройство зарегистрировано: %s (org=%s, владелец=%s, зарегистрировал=%s)",
            device_id, org_id, user_id, registered_by,
        )
        return entry

    def unregister_device(self, org_id: str, entry_id: str, remover_user_id: str) -> None:
        with db.transaction() as conn:
            row = conn.execute(
                "UPDATE registered_devices SET revoked_at = now(), revoked_by = %s "
                "WHERE entry_id = %s AND org_id = %s AND revoked_at IS NULL RETURNING device_id",
                (remover_user_id, entry_id, org_id),
            ).fetchone()
        if row is None:
            raise AccessError("Устройство не найдено")
        logger.info(
            "Устройство снято с учёта: %s (org=%s, снял=%s)",
            row["device_id"], org_id, remover_user_id,
        )

    def is_device_registered(self, org_id: str, device_id: str) -> bool:
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT 1 FROM registered_devices WHERE org_id = %s AND device_id = %s "
                "AND revoked_at IS NULL LIMIT 1",
                (org_id, device_id.strip()),
            ).fetchone()
        return row is not None

    def list_devices(self, org_id: str) -> list[RegisteredDevice]:
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_D_COLS} FROM registered_devices WHERE org_id = %s "
                "AND revoked_at IS NULL ORDER BY registered_at",
                (org_id,),
            ).fetchall()
        return [_row_to_device(r) for r in rows]

    # --------- Гранты (блок 6): общая логика для двух типов ---------

    @staticmethod
    def _grant(grant_type: str, org_id: str, user_id: str, granted_by: str,
               note: str, duplicate_message: str) -> AccessGrant:
        grant = AccessGrant(
            entry_id=secrets.token_hex(8), org_id=org_id, user_id=user_id,
            granted_by=granted_by, note=note.strip(),
        )
        try:
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO access_grants (entry_id, org_id, user_id, grant_type, "
                    "granted_by, note, granted_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (grant.entry_id, org_id, user_id, grant_type, granted_by, grant.note,
                     db.to_db_time(grant.granted_at)),
                )
        except db.UniqueViolation as exc:
            raise AccessError(duplicate_message) from exc
        except db.ForeignKeyViolation as exc:
            raise AccessError("Пользователь не найден") from exc
        return grant

    @staticmethod
    def _revoke(grant_type: str, org_id: str, entry_id: str, revoked_by: str) -> str:
        with db.transaction() as conn:
            row = conn.execute(
                "UPDATE access_grants SET revoked_at = now(), revoked_by = %s "
                "WHERE entry_id = %s AND org_id = %s AND grant_type = %s "
                "AND revoked_at IS NULL RETURNING user_id",
                (revoked_by, entry_id, org_id, grant_type),
            ).fetchone()
        if row is None:
            raise AccessError("Грант не найден")
        return row["user_id"]

    @staticmethod
    def _has(grant_type: str, org_id: str, user_id: str) -> bool:
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT 1 FROM access_grants WHERE org_id = %s AND user_id = %s "
                "AND grant_type = %s AND revoked_at IS NULL LIMIT 1",
                (org_id, user_id, grant_type),
            ).fetchone()
        return row is not None

    @staticmethod
    def _list(grant_type: str, org_id: str) -> list[AccessGrant]:
        with db.transaction() as conn:
            rows = conn.execute(
                f"SELECT {_G_COLS} FROM access_grants WHERE org_id = %s AND grant_type = %s "
                "AND revoked_at IS NULL ORDER BY granted_at",
                (org_id, grant_type),
            ).fetchall()
        return [_row_to_grant(r) for r in rows]

    # --------- Легитимный доступ (блок 6) ---------

    def grant_legitimate_access(
        self, org_id: str, user_id: str, granted_by: str, note: str = "",
    ) -> AccessGrant:
        grant = self._grant(
            LEGITIMATE_ACCESS, org_id, user_id, granted_by, note,
            "У пользователя уже есть согласованный доступ в этой организации",
        )
        logger.info(
            "Легитимный доступ согласован: user=%s (org=%s, согласовал=%s)",
            user_id, org_id, granted_by,
        )
        return grant

    def revoke_legitimate_access(self, org_id: str, entry_id: str, revoked_by: str) -> None:
        user_id = self._revoke(LEGITIMATE_ACCESS, org_id, entry_id, revoked_by)
        logger.info(
            "Легитимный доступ отозван: user=%s (org=%s, отозвал=%s)", user_id, org_id, revoked_by,
        )

    def has_legitimate_access(self, org_id: str, user_id: str) -> bool:
        return self._has(LEGITIMATE_ACCESS, org_id, user_id)

    def list_legitimate_access(self, org_id: str) -> list[AccessGrant]:
        return self._list(LEGITIMATE_ACCESS, org_id)

    # --------- Повышенные права (блок 6) ---------

    def grant_elevated_rights(
        self, org_id: str, user_id: str, granted_by: str, note: str = "",
    ) -> AccessGrant:
        grant = self._grant(
            ELEVATED_RIGHTS, org_id, user_id, granted_by, note,
            "У пользователя уже есть повышенные права в этой организации",
        )
        logger.info(
            "Повышенные права выданы: user=%s (org=%s, выдал=%s)", user_id, org_id, granted_by,
        )
        return grant

    def revoke_elevated_rights(self, org_id: str, entry_id: str, revoked_by: str) -> None:
        user_id = self._revoke(ELEVATED_RIGHTS, org_id, entry_id, revoked_by)
        logger.info(
            "Повышенные права отозваны: user=%s (org=%s, отозвал=%s)", user_id, org_id, revoked_by,
        )

    def has_elevated_rights(self, org_id: str, user_id: str) -> bool:
        return self._has(ELEVATED_RIGHTS, org_id, user_id)

    def list_elevated_rights(self, org_id: str) -> list[AccessGrant]:
        return self._list(ELEVATED_RIGHTS, org_id)
