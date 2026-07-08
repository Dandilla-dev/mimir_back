"""
models/local_model.py — своя нейросеть.

Отвечает за: классификацию событий (угроза/норма/аномалия),
быстрые офлайн-решения. Здесь — минимальный рабочий каркас на PyTorch,
который нужно дообучить/заменить реальными весами.
"""

from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import torch

logger = logging.getLogger("mimir.local_model")


class EventClass(str, Enum):
    NORMAL = "normal"
    ANOMALY = "anomaly"
    THREAT = "threat"


def _build_classifier(input_dim: int, hidden_dim: int, num_classes: int):
    """Строит EventClassifier лениво — torch импортируется только здесь,
    то есть только когда реально нужна локальная модель."""
    import torch.nn as nn

    class EventClassifier(nn.Module):
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, num_classes),
            )

        def forward(self, x):
            return self.net(x)

    return EventClassifier()


class LocalModel:
    """Обёртка для инференса: вектор признаков -> класс события."""

    LABELS = [EventClass.NORMAL, EventClass.ANOMALY, EventClass.THREAT]

    def __init__(self, weights_path: str | Path | None = None, input_dim: int = 32):
        import torch  # ленивый импорт: нужен только если LocalModel реально создаётся

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = _build_classifier(input_dim, 64, len(self.LABELS)).to(self.device)
        self.model.eval()

        if weights_path and Path(weights_path).exists():
            state = torch.load(weights_path, map_location=self.device)
            self.model.load_state_dict(state)
            logger.info("Веса локальной модели загружены из %s", weights_path)
        else:
            logger.warning(
                "Веса локальной модели не найдены — используются случайные веса "
                "(модель не обучена, только для проверки пайплайна)."
            )

    def classify(self, features: list[float]) -> tuple[EventClass, float]:
        """Возвращает (класс события, уверенность)."""
        import torch

        with torch.no_grad():
            x = torch.tensor(features, dtype=torch.float32, device=self.device).unsqueeze(0)
            logits = self.model(x)
            probs = torch.softmax(logits, dim=-1)
            confidence, idx = probs.max(dim=-1)
            return self.LABELS[int(idx.item())], float(confidence.item())
