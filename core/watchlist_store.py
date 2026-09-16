"""
core/watchlist_store.py — списки доменов, зависящие от организации:
домены под наблюдением (блок 1 mimir_dlp_features_v1.md — конкуренты
для исходящих, известные источники фишинга для входящих) и белый
список доменов ссылок (блок 2 — одобренные внешние сервисы).

Закрывает первую из трёх баз, зафиксированных как долг в
mimir_architecture_v2.md §7 ("список наблюдаемых доменов"). Не путать
с _FILE_SHARING_DOMAINS в message_parser.py — тот список фиксирован и
не зависит от организации (mimir_dlp_features_v1.md, блок 2, решение
по файлообменникам: "узкий и стабильный список, не требующий отдельной
БД"), эта база — про то, что каждый клиент настраивает сам под себя.

Логика та же, что и в auth_store.py / org_store.py / contacts_store.py /
dlp_events_store.py: всё в памяти процесса, никакой БД.

Оба списка org-scoped: у организации A нет доступа к списку организации
B и наоборот — та же изоляция клиентских данных, что и во всех остальных
org-зависимых сущностях (см. org_store.py). Личные (standalone, без
организации) аккаунты не имеют watchlist/whitelist вообще: как и с
contacts_store, это ожидаемо — для них соответствующие lookups остаются
нейтральными по умолчанию (core/message_parser.DEFAULT_LOOKUPS), этот
стор для них просто не вызывается (см. core/message_bridge._lookups_for).

ВАЖНО про полярность двух списков — она разная, и это сознательно:
- watchlist: отсутствие домена в списке = "не подозрительный" (False) —
  нейтрально и безопасно по умолчанию, ровно как сейчас в ParserLookups.
- link whitelist: используется в message_parser.py как
  `not lookups.is_link_whitelisted(...)` — то есть отсутствие домена в
  списке трактуется как "не в белом списке" = тревожный флаг. Это
  осознанный сдвиг относительно временной заглушки ParserLookups
  (`is_link_whitelisted` по умолчанию `True`, то есть "все домены
  разрешены, пока список не появится") в сторону allow-list поведения:
  когда для организации подключена реальная база (см.
  make_lookups_from_watchlist_store в message_parser.py), домен, не
  внесённый явно, теперь считается неразрешённым. Согласуется с
  принципом mimir_dlp_features_v1.md, блок 1: "при сомнении — считать
  меньшим злом ложное срабатывание, чем пропуск угрозы".

  ПРОБЛЕМА ХОЛОДНОГО СТАРТА (см. обсуждение в чате): allow-list пустой
  в первый день у любой новой организации — значит абсолютно все
  внешние ссылки у всех сотрудников флагились бы как "не в белом
  списке", включая самые обычные (видеозвонок, совместный документ).
  Решение — DEFAULT_WHITELISTED_LINK_DOMAINS ниже: небольшой фиксированный
  список общеизвестных легитимных сервисов, подмешиваемый ко ВСЕМ
  организациям сразу, тот же паттерн, что уже есть у _FILE_SHARING_DOMAINS
  в message_parser.py, только в обратную сторону (не флаг, а
  нейтрализация). is_link_whitelisted() ниже возвращает True, если домен
  либо в этом общем списке, либо явно добавлен именно в эту организацию —
  officer не может ни убрать, ни переопределить общий список, только
  расширить его своими записями.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

logger = logging.getLogger("mimir.watchlist")


# Небольшой фиксированный список общеизвестных легитимных сервисов —
# подмешивается ко всем организациям, чтобы whitelist не флагил всё
# подряд в первый день после подключения клиента (см. docstring выше).
# Сознательно НЕ включает drive.google.com/dropbox.com и подобные —
# эти домены уже отдельно и всегда флагятся через _FILE_SHARING_DOMAINS
# в message_parser.py (пересылка файлов через личный аккаунт — риск
# независимо от того, что домен "известный"), совмещать их здесь с
# whitelist было бы прямым противоречием той более ранней проверке.
# Список стоит пересматривать по мере накопления реального опыта
# пилотов, а не считать финальным.
DEFAULT_WHITELISTED_LINK_DOMAINS: frozenset[str] = frozenset({
    # видеозвонки/встречи
    "zoom.us", "meet.google.com", "teams.microsoft.com",
    # офисные/совместная работа (без файлообменных доменов, см. выше)
    "docs.google.com", "sheets.google.com", "slides.google.com",
    "sharepoint.com", "office.com", "outlook.com",
    # корпоративные коммуникации и разработка
    "slack.com", "atlassian.net", "github.com", "gitlab.com",
    "notion.so", "figma.com", "calendly.com",
})




class WatchlistError(Exception):
    """Ошибка операций с базой доменов (не найдено, дубликат и т.д.)."""


@dataclass
class WatchlistedDomain:
    """Домен под наблюдением — блок 1: конкурент (для исходящих) или
    известный источник фишинга (для входящих)."""

    entry_id: str
    org_id: str
    domain: str
    reason: str
    added_by: str  # user_id
    added_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "org_id": self.org_id,
            "domain": self.domain,
            "reason": self.reason,
            "added_by": self.added_by,
            "added_at": self.added_at,
        }


@dataclass
class WhitelistedLinkDomain:
    """Одобренный домен для внешних ссылок в сообщениях — блок 2."""

    entry_id: str
    org_id: str
    domain: str
    reason: str
    added_by: str  # user_id
    added_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "org_id": self.org_id,
            "domain": self.domain,
            "reason": self.reason,
            "added_by": self.added_by,
            "added_at": self.added_at,
        }


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower()


class WatchlistStore:
    """Домены под наблюдением + белый список ссылок, по организациям —
    всё в памяти процесса."""

    def __init__(self):
        self._watchlisted: dict[str, WatchlistedDomain] = {}
        self._whitelisted: dict[str, WhitelistedLinkDomain] = {}

    # --------- Watchlist (блок 1) ---------

    def add_watchlisted(
        self, org_id: str, domain: str, added_by: str, reason: str = "",
    ) -> WatchlistedDomain:
        domain = _normalize_domain(domain)
        if not domain:
            raise WatchlistError("Домен не может быть пустым")
        if self._find_watchlisted(org_id, domain) is not None:
            raise WatchlistError(
                f"Домен {domain} уже в списке наблюдения этой организации"
            )

        entry = WatchlistedDomain(
            entry_id=secrets.token_hex(8),
            org_id=org_id,
            domain=domain,
            reason=reason.strip(),
            added_by=added_by,
        )
        self._watchlisted[entry.entry_id] = entry
        logger.info(
            "Домен добавлен в watchlist: %s (org=%s, добавил=%s)",
            domain, org_id, added_by,
        )
        return entry

    def remove_watchlisted(self, org_id: str, entry_id: str, remover_user_id: str) -> None:
        entry = self._watchlisted.get(entry_id)
        if entry is None or entry.org_id != org_id:
            raise WatchlistError("Запись не найдена")
        del self._watchlisted[entry_id]
        logger.info(
            "Домен убран из watchlist: %s (org=%s, убрал=%s)",
            entry.domain, org_id, remover_user_id,
        )

    def is_domain_watchlisted(self, org_id: str, domain: str) -> bool:
        return self._find_watchlisted(org_id, _normalize_domain(domain)) is not None

    def list_watchlisted(self, org_id: str) -> list[WatchlistedDomain]:
        return sorted(
            (e for e in self._watchlisted.values() if e.org_id == org_id),
            key=lambda e: e.added_at,
        )

    def _find_watchlisted(self, org_id: str, domain: str) -> WatchlistedDomain | None:
        for e in self._watchlisted.values():
            if e.org_id == org_id and e.domain == domain:
                return e
        return None

    # --------- Link whitelist (блок 2) ---------

    def add_whitelisted_link(
        self, org_id: str, domain: str, added_by: str, reason: str = "",
    ) -> WhitelistedLinkDomain:
        domain = _normalize_domain(domain)
        if not domain:
            raise WatchlistError("Домен не может быть пустым")
        if domain in DEFAULT_WHITELISTED_LINK_DOMAINS:
            raise WatchlistError(
                f"Домен {domain} уже разрешён по умолчанию для всех организаций"
            )
        if self._find_whitelisted(org_id, domain) is not None:
            raise WatchlistError(
                f"Домен {domain} уже в белом списке ссылок этой организации"
            )

        entry = WhitelistedLinkDomain(
            entry_id=secrets.token_hex(8),
            org_id=org_id,
            domain=domain,
            reason=reason.strip(),
            added_by=added_by,
        )
        self._whitelisted[entry.entry_id] = entry
        logger.info(
            "Домен добавлен в whitelist ссылок: %s (org=%s, добавил=%s)",
            domain, org_id, added_by,
        )
        return entry

    def remove_whitelisted_link(self, org_id: str, entry_id: str, remover_user_id: str) -> None:
        entry = self._whitelisted.get(entry_id)
        if entry is None or entry.org_id != org_id:
            raise WatchlistError("Запись не найдена")
        del self._whitelisted[entry_id]
        logger.info(
            "Домен убран из whitelist ссылок: %s (org=%s, убрал=%s)",
            entry.domain, org_id, remover_user_id,
        )

    def is_link_whitelisted(self, org_id: str, domain: str) -> bool:
        domain = _normalize_domain(domain)
        if domain in DEFAULT_WHITELISTED_LINK_DOMAINS:
            return True
        return self._find_whitelisted(org_id, domain) is not None

    def list_whitelisted(self, org_id: str) -> list[WhitelistedLinkDomain]:
        """Записи, добавленные именно этой организацией — БЕЗ
        DEFAULT_WHITELISTED_LINK_DOMAINS (у тех нет entry_id/added_by,
        это не записи стора). Для отображения общего списка на фронтенде
        используй list_default_whitelisted()."""
        return sorted(
            (e for e in self._whitelisted.values() if e.org_id == org_id),
            key=lambda e: e.added_at,
        )

    @staticmethod
    def list_default_whitelisted() -> list[str]:
        """Общий для всех организаций список — read-only, officer не
        может ни убрать из него домен, ни переопределить (см. docstring
        модуля, "проблема холодного старта")."""
        return sorted(DEFAULT_WHITELISTED_LINK_DOMAINS)

    def _find_whitelisted(self, org_id: str, domain: str) -> WhitelistedLinkDomain | None:
        for e in self._whitelisted.values():
            if e.org_id == org_id and e.domain == domain:
                return e
        return None
