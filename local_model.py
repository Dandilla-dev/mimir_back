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

import torch
import torch.nn as nn

logger = logging.getLogger("mimir.local_model")


class EventClass(str, Enum):
    NORMAL = "normal"
    ANOMALY = "anomaly"
    THREAT = "threat"


class EventClassifier(nn.Module):
    """Простой MLP-классификатор событий по вектору признаков сенсоров."""

    def __init__(self, input_dim: int = 32, hidden_dim: int = 64, num_classes: int = 3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class LocalModel:
    """Обёртка для инференса: вектор признаков -> класс события."""

    LABELS = [EventClass.NORMAL, EventClass.ANOMALY, EventClass.THREAT]

    def __init__(self, weights_path: str | Path | None = None, input_dim: int = 32):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = EventClassifier(input_dim=input_dim).to(self.device)
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

    @torch.no_grad()
    def classify(self, features: list[float]) -> tuple[EventClass, float]:
        """Возвращает (класс события, уверенность)."""
        x = torch.tensor(features, dtype=torch.float32, device=self.device).unsqueeze(0)
        logits = self.model(x)
        probs = torch.softmax(logits, dim=-1)
        confidence, idx = probs.max(dim=-1)
        return self.LABELS[int(idx.item())], float(confidence.item())
