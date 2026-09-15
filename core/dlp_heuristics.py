"""
core/dlp_heuristics.py — эвристический классификатор DLP-событий (слой 3).

Временная замена EventClassifier (models/local_model.py) на период, пока
нет датасета для обучения (MIMIR_development_plan.md, Фаза 1 неделя 4).
core/dlp_events_store.py — параллельный сбор данных на будущее (неделя 7),
не подготовка к немедленному запуску классификатора; эти две вещи не
связаны напрямую, кроме общего источника (DLPEvent).

ГРАНИЦА СЛОЯ (mimir_architecture_v2.md §4, §6): этот модуль знает только
про core/dlp_features.DLPEvent — ничего не знает про messages_store,
message_bridge, auth_store или org_store. Не резолвит ничего сам, не
решает, откуда брать DLPEvent, не блокирует и не уведомляет — только
классифицирует то, что ему уже дали, и возвращает результат с
человекочитаемым обоснованием (см. HeuristicResult).

ПРАВИЛА взяты из mimir_dlp_features_v1.md (блоки 1, 2, 3, 5, 6) и
mimir_dlp_features_encoding_v1.md (какие поля реально что означают).
Раскладка на "самодостаточные" (THREAT) и "составные" (ANOMALY) сигналы —
дизайн-решение этого модуля, а не пересказ доков; описано ниже у каждого
правила, откуда взят вес.

АВТОНОМНОСТЬ (mimir_principles.md): "угроза" (THREAT) — единственный
уровень, который в принципе может стать основанием для автономного
действия (саму блокировку реализует не этот модуль, а вызывающая сторона
— см. правило "автономная блокировка только для активных угроз, дальше
человек разбирает" из mimir_principles.md). "Аномалия" (ANOMALY) — это
только сигнал в очередь на ручной разбор, не повод для автономного
действия. Человек — конечный арбитр классификации и в том, и в другом
случае; этот модуль сортирует, не решает.

ПРИНЦИП "ложное срабатывание — меньшее зло, чем пропуск угрозы"
(mimir_principles.md) впрямую определяет логику combine(): несколько
слабых (ANOMALY) сигналов вместе эскалируются до THREAT, а не остаются
суммой аномалий — компаундирование слабых сигналов само по себе весомый
довод, отдельно от силы любого сигнала по отдельности.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from core.dlp_features import DLPEvent

logger = logging.getLogger("mimir.dlp_heuristics")


class ThreatLevel(str, Enum):
    NORMAL = "normal"
    ANOMALY = "anomaly"
    THREAT = "threat"


@dataclass
class HeuristicResult:
    """Результат эвристической классификации одного DLPEvent.

    threat_reasons/anomaly_reasons — человекочитаемые причины (на русском,
    как и остальные логи/докстринги проекта), не машинные коды: конечный
    потребитель — человек, разбирающий очередь (mimir_principles.md,
    "issue -> cause -> options -> consequences -> human decides").
    """

    level: ThreatLevel
    threat_reasons: list[str] = field(default_factory=list)
    anomaly_reasons: list[str] = field(default_factory=list)

    def to_public_dict(self) -> dict:
        return {
            "level": self.level.value,
            "threat_reasons": self.threat_reasons,
            "anomaly_reasons": self.anomaly_reasons,
        }


# ---------------------------------------------------------------------------
# Правила уровня THREAT — каждое самодостаточно: одного срабатывания
# достаточно для эскалации до "угроза", без учёта остальных сигналов.
# Это сигналы, у которых по своей природе почти нет безобидного объяснения
# ЛИБО источник — уже человеческое решение (watchlist), а не догадка
# эвристики.
# ---------------------------------------------------------------------------

def _rule_executable_content(event: DLPEvent) -> str | None:
    """Блок 2, п.4 (mimir_dlp_features_v1.md): макрос/исполняемый код —
    "применимо и к офисным документам с макросами, и к архивам с
    исполняемым файлом внутри". Для входящих — классический вектор
    вредоносного вложения (фишинг); для исходящих тоже почти нет
    легитимного сценария для обычной переписки. Одного факта достаточно."""
    if not event.has_macro_or_executable_code:
        return None
    direction = "во входящем" if event.is_incoming else "в исходящем"
    return f"исполняемый код/макрос {direction} вложении"


def _rule_password_protected_outgoing(event: DLPEvent) -> str | None:
    """Блок 2, п.6: "частый приём обхода DLP-сканирования" — формулировка
    из доки прямо называет это техникой уклонения именно для утечки
    (исходящее). Для исходящего защищённого паролем файла легитимных
    сценариев меньше, чем подозрительных (сотрудник специально прячет
    содержимое от проверки) — самодостаточный сигнал."""
    if event.is_incoming or not event.attachment_password_protected:
        return None
    return "исходящее вложение защищено паролем (обход DLP-сканирования)"


def _rule_domain_watchlisted(event: DLPEvent) -> str | None:
    """Блок 1, п.5: домен контрагента в списке наблюдения — конкуренты
    (для исходящих) или известные источники фишинга (для входящих).
    Список курируется человеком заранее (org_store/watchlist, вне этого
    модуля) — раз домен уже в списке, эвристике незачем взвешивать
    вероятность, решение по существу уже принято на входе."""
    if not event.counterparty_domain_watchlisted:
        return None
    direction = "источник во входящем" if event.is_incoming else "получатель в исходящем"
    return f"{direction} — домен в списке наблюдения"


def _rule_confidential_marker_outgoing_external(event: DLPEvent) -> str | None:
    """Блок 2, п.5 + блок 1, п.2: маркер конфиденциальности («confidential»,
    номер договора, метка NDA) в исходящем сообщении внешнему контрагенту —
    это ядро продукта (утечка от сотрудника, mimir_dlp_features_v1.md блок
    1 описывает исходящее как "утечка конфиденциальных данных"). Требую
    оба условия (маркер + внешний) вместе: маркер во внутренней переписке
    не про утечку наружу."""
    if event.is_incoming or not event.confidentiality_marker_found:
        return None
    if not event.counterparty_external:
        return None
    return "маркер конфиденциальности в исходящем сообщении внешнему контрагенту"


def _rule_untrusted_link_incoming(event: DLPEvent) -> str | None:
    """Блок 2, п.7-8: внешняя ссылка + не в белом списке, во входящем —
    классический признак фишинговой ссылки. Для исходящих то же сочетание
    не показатель угрозы само по себе (сотрудник просто шлёт ссылку на
    внешний сервис) — поэтому направление здесь обязательное условие,
    в отличие от watchlist-правила выше, где домен уже проверен человеком."""
    if not event.is_incoming or not event.has_external_link:
        return None
    if not event.link_not_whitelisted:
        return None
    return "входящая ссылка на непроверенный (не whitelisted) домен"


_THREAT_RULES = (
    _rule_executable_content,
    _rule_password_protected_outgoing,
    _rule_domain_watchlisted,
    _rule_confidential_marker_outgoing_external,
    _rule_untrusted_link_incoming,
)


# ---------------------------------------------------------------------------
# Правила уровня ANOMALY — по отдельности недостаточно весомы для THREAT
# (у каждого есть обычный безобидный сценарий), но составляются: 2+ разных
# сработавших правила из этого набора эскалируют результат до THREAT
# (см. combine() и принцип "ложное срабатывание лучше пропуска" выше).
# ---------------------------------------------------------------------------

def _rule_new_counterparty_with_attachment(event: DLPEvent) -> str | None:
    """Блок 1, п.3 + блок 2, п.1: вложение впервые появившемуся внешнему
    контрагенту. Обычный сценарий (первая отправка договора новому
    клиенту) не отличим по одному этому признаку от разведки/утечки —
    поэтому не THREAT сам по себе, но весомый компонент составного
    сигнала."""
    if event.is_incoming or not event.has_attachment:
        return None
    if not event.counterparty_new or not event.counterparty_external:
        return None
    return "вложение отправлено новому внешнему контрагенту"


def _rule_off_hours_outgoing_attachment(event: DLPEvent) -> str | None:
    """Блок 3, п.2: исходящее вложение в нерабочий день — сотрудники
    иногда легитимно работают в выходные, поэтому не самостоятельный
    THREAT, но заметный компонент при совпадении с другими сигналами
    (например, новый контрагент в выходной день — более странно, чем
    любое из двух по отдельности)."""
    if event.is_incoming or not event.has_attachment:
        return None
    if not event.is_non_working_day:
        return None
    return "исходящее вложение отправлено в нерабочий день"


def _rule_unregistered_device_with_attachment(event: DLPEvent) -> str | None:
    """Блок 5, п.1: вложение с незарегистрированного устройства.
    mimir_dlp_features_v1.md явно оговаривает: без политики "только
    корпоративные устройства" у клиента это может быть просто личный
    телефон с рабочей почтой — обычный BYOD-случай, не самостоятельная
    угроза."""
    if not event.has_attachment or not event.device_unregistered:
        return None
    return "вложение с незарегистрированного устройства"


def _rule_no_legitimate_access_outgoing(event: DLPEvent) -> str | None:
    """Блок 6, п.1: исходящая передача данных без зафиксированного
    легитимного доступа к делу. Само по себе может быть дырой в учёте
    прав (роли не всегда точно отражают фактический доступ), поэтому
    составной сигнал, не самостоятельный."""
    if event.is_incoming or not event.has_attachment:
        return None
    if event.lacks_legitimate_access:
        return "исходящее вложение без зафиксированного легитимного доступа к данным"
    return None


def _rule_personal_address_outgoing_attachment(event: DLPEvent) -> str | None:
    """Блок 1, п.4 + блок 2, п.1: вложение на личный (не корпоративный)
    адрес контрагента — классический паттерн "себе на личную почту" при
    утечке, но также обычный сценарий переписки с внештатным подрядчиком
    или клиентом-физлицом, поэтому не самостоятельная угроза."""
    if event.is_incoming or not event.has_attachment:
        return None
    if not event.counterparty_address_personal:
        return None
    return "вложение отправлено на личный (некорпоративный) адрес"


_ANOMALY_RULES = (
    _rule_new_counterparty_with_attachment,
    _rule_off_hours_outgoing_attachment,
    _rule_unregistered_device_with_attachment,
    _rule_no_legitimate_access_outgoing,
    _rule_personal_address_outgoing_attachment,
)


# ---------------------------------------------------------------------------
# Пороги эскалации ANOMALY -> THREAT. Не взяты из доков (там расписаны
# только сами признаки, не правила их комбинирования) — это решение этого
# модуля, см. обсуждение в чате. Вынесены сюда отдельными именами, чтобы
# менять поведение эскалации без правки логики в classify() ниже —
# например, добавить/убрать elevated_rights как усилитель, или изменить
# порог по количеству совпавших anomaly-правил.
# ---------------------------------------------------------------------------

# Столько РАЗНЫХ anomaly-правил должно сработать одновременно на одном
# событии, чтобы результат эскалировался до THREAT, даже если ни одно
# THREAT-правило не сработало. Компаундирование слабых сигналов само по
# себе повод для эскалации (см. докстринг модуля).
ANOMALY_COUNT_THRESHOLD_FOR_THREAT = 2

# Если True: наличие повышенных/административных прав (has_elevated_rights)
# эскалирует ЛЮБУЮ одну сработавшую anomaly-причину сразу до THREAT, даже
# если порог ANOMALY_COUNT_THRESHOLD_FOR_THREAT не достигнут — сама по себе
# elevated_rights не сигнал (у многих ролей права законны), но делает
# любую другую аномалию весомее (шире потенциальный ущерб). Поставить
# False, чтобы отключить этот усилитель и оставить только счётчик выше.
ESCALATE_ANOMALY_ON_ELEVATED_RIGHTS = True


def classify(event: DLPEvent) -> HeuristicResult:
    """Точка входа модуля. Берёт готовый DLPEvent и возвращает
    HeuristicResult с уровнем и обоснованием — ничего не сохраняет и
    не вызывает других слоёв (см. докстринг модуля про границу слоя).

    Логика combine() (пороги эскалации — см. константы выше классов правил,
    ANOMALY_COUNT_THRESHOLD_FOR_THREAT и ESCALATE_ANOMALY_ON_ELEVATED_RIGHTS):
    - любое сработавшее правило THREAT -> уровень THREAT сразу;
    - иначе, если ESCALATE_ANOMALY_ON_ELEVATED_RIGHTS включён и
      есть хотя бы один сработавший ANOMALY при has_elevated_rights ->
      эскалация до THREAT;
    - иначе, если сработало >= ANOMALY_COUNT_THRESHOLD_FOR_THREAT разных
      правил ANOMALY -> уровень эскалируется до THREAT (компаундирование
      слабых сигналов — само по себе повод для эскалации, см. докстринг
      модуля);
    - иначе, если сработало хотя бы 1 правило ANOMALY -> уровень ANOMALY;
    - иначе (ничего не сработало) -> NORMAL.
    """
    threat_reasons = [r for r in (rule(event) for rule in _THREAT_RULES) if r]
    anomaly_reasons = [r for r in (rule(event) for rule in _ANOMALY_RULES) if r]

    if threat_reasons:
        level = ThreatLevel.THREAT
    elif anomaly_reasons and ESCALATE_ANOMALY_ON_ELEVATED_RIGHTS and event.has_elevated_rights:
        level = ThreatLevel.THREAT
        anomaly_reasons = anomaly_reasons + ["повышенные права усиливают аномалию до угрозы"]
    elif len(anomaly_reasons) >= ANOMALY_COUNT_THRESHOLD_FOR_THREAT:
        level = ThreatLevel.THREAT
    elif anomaly_reasons:
        level = ThreatLevel.ANOMALY
    else:
        level = ThreatLevel.NORMAL

    if level != ThreatLevel.NORMAL:
        logger.info(
            "Эвристика: %s (threat=%s, anomaly=%s)",
            level.value, threat_reasons, anomaly_reasons,
        )

    return HeuristicResult(
        level=level,
        threat_reasons=threat_reasons,
        anomaly_reasons=anomaly_reasons,
    )
