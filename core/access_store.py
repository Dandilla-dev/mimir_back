"""
core/access_store.py — реестр устройств (блок 5 mimir_dlp_features_v1.md)
и роли доступа (блок 6): легитимный доступ к данным организации,
повышенные/административные права.

Закрывает третью, последнюю из трёх баз, зафиксированных как долг в
mimir_architecture_v2.md §7 ("реестр устройств + роли доступа") — те же
две базы, которые архитектурный документ сознательно объединяет в одну
(в отличие от watchlist доменов, вынесенного в core/watchlist_store.py
отдельным долгом).

Логика та же, что и в auth_store.py / org_store.py / watchlist_store.py:
всё в памяти процесса, org-scoped, никакой БД.

--- Устройства (блок 5) ---

"Зарегистрированное рабочее устройство" — просто пара (org_id, device_id),
привязанная к user_id, кто её зарегистрировал (для пилота — только
security_officer, самостоятельная регистрация сотрудником не
предусмотрена, см. обсуждение в чате: официальная политика "только
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


class AccessStore:
    """Устройства + легитимный доступ + повышенные права — по
    организациям, всё в памяти процесса."""

    def __init__(self):
        self._devices: dict[str, RegisteredDevice] = {}
        self._legitimate_access: dict[str, AccessGrant] = {}
        self._elevated_rights: dict[str, AccessGrant] = {}

    # --------- Устройства (блок 5) ---------

    def register_device(
        self, org_id: str, device_id: str, user_id: str, registered_by: str, label: str = "",
    ) -> RegisteredDevice:
        device_id = device_id.strip()
        if not device_id:
            raise AccessError("device_id не может быть пустым")
        if self._find_device(org_id, device_id) is not None:
            raise AccessError(f"Устройство {device_id} уже зарегистрировано в этой организации")

        entry = RegisteredDevice(
            entry_id=secrets.token_hex(8),
            org_id=org_id,
            device_id=device_id,
            user_id=user_id,
            label=label.strip(),
            registered_by=registered_by,
        )
        self._devices[entry.entry_id] = entry
        logger.info(
            "Устройство зарегистрировано: %s (org=%s, владелец=%s, зарегистрировал=%s)",
            device_id, org_id, user_id, registered_by,
        )
        return entry

    def unregister_device(self, org_id: str, entry_id: str, remover_user_id: str) -> None:
        entry = self._devices.get(entry_id)
        if entry is None or entry.org_id != org_id:
            raise AccessError("Устройство не найдено")
        del self._devices[entry_id]
        logger.info(
            "Устройство снято с учёта: %s (org=%s, снял=%s)",
            entry.device_id, org_id, remover_user_id,
        )

    def is_device_registered(self, org_id: str, device_id: str) -> bool:
        return self._find_device(org_id, device_id.strip()) is not None

    def list_devices(self, org_id: str) -> list[RegisteredDevice]:
        return sorted(
            (d for d in self._devices.values() if d.org_id == org_id),
            key=lambda d: d.registered_at,
        )

    def _find_device(self, org_id: str, device_id: str) -> RegisteredDevice | None:
        for d in self._devices.values():
            if d.org_id == org_id and d.device_id == device_id:
                return d
        return None

    # --------- Легитимный доступ (блок 6) ---------

    def grant_legitimate_access(
        self, org_id: str, user_id: str, granted_by: str, note: str = "",
    ) -> AccessGrant:
        if self._find_grant(self._legitimate_access, org_id, user_id) is not None:
            raise AccessError("У пользователя уже есть согласованный доступ в этой организации")
        grant = AccessGrant(
            entry_id=secrets.token_hex(8), org_id=org_id, user_id=user_id,
            granted_by=granted_by, note=note.strip(),
        )
        self._legitimate_access[grant.entry_id] = grant
        logger.info(
            "Легитимный доступ согласован: user=%s (org=%s, согласовал=%s)",
            user_id, org_id, granted_by,
        )
        return grant

    def revoke_legitimate_access(self, org_id: str, entry_id: str, revoked_by: str) -> None:
        grant = self._legitimate_access.get(entry_id)
        if grant is None or grant.org_id != org_id:
            raise AccessError("Грант не найден")
        del self._legitimate_access[entry_id]
        logger.info(
            "Легитимный доступ отозван: user=%s (org=%s, отозвал=%s)",
            grant.user_id, org_id, revoked_by,
        )

    def has_legitimate_access(self, org_id: str, user_id: str) -> bool:
        return self._find_grant(self._legitimate_access, org_id, user_id) is not None

    def list_legitimate_access(self, org_id: str) -> list[AccessGrant]:
        return sorted(
            (g for g in self._legitimate_access.values() if g.org_id == org_id),
            key=lambda g: g.granted_at,
        )

    # --------- Повышенные права (блок 6) ---------

    def grant_elevated_rights(
        self, org_id: str, user_id: str, granted_by: str, note: str = "",
    ) -> AccessGrant:
        if self._find_grant(self._elevated_rights, org_id, user_id) is not None:
            raise AccessError("У пользователя уже есть повышенные права в этой организации")
        grant = AccessGrant(
            entry_id=secrets.token_hex(8), org_id=org_id, user_id=user_id,
            granted_by=granted_by, note=note.strip(),
        )
        self._elevated_rights[grant.entry_id] = grant
        logger.info(
            "Повышенные права выданы: user=%s (org=%s, выдал=%s)",
            user_id, org_id, granted_by,
        )
        return grant

    def revoke_elevated_rights(self, org_id: str, entry_id: str, revoked_by: str) -> None:
        grant = self._elevated_rights.get(entry_id)
        if grant is None or grant.org_id != org_id:
            raise AccessError("Грант не найден")
        del self._elevated_rights[entry_id]
        logger.info(
            "Повышенные права отозваны: user=%s (org=%s, отозвал=%s)",
            grant.user_id, org_id, revoked_by,
        )

    def has_elevated_rights(self, org_id: str, user_id: str) -> bool:
        return self._find_grant(self._elevated_rights, org_id, user_id) is not None

    def list_elevated_rights(self, org_id: str) -> list[AccessGrant]:
        return sorted(
            (g for g in self._elevated_rights.values() if g.org_id == org_id),
            key=lambda g: g.granted_at,
        )

    @staticmethod
    def _find_grant(grants: dict[str, AccessGrant], org_id: str, user_id: str) -> AccessGrant | None:
        for g in grants.values():
            if g.org_id == org_id and g.user_id == user_id:
                return g
        return None
