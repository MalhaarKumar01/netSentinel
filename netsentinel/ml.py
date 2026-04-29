from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .schemas import FeatureVector
from .security import stable_sha256

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "avg_packet_size",
    "packets_per_sec",
    "bytes_per_sec",
    "syn_count",
    "ack_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "port_entropy",
]


@dataclass(slots=True)
class Prediction:
    is_anomaly: bool
    anomaly_score: float


class MLService:
    def __init__(self, model_path: Path) -> None:
        self.model_path = model_path
        self.model, self.version = self._load_or_bootstrap(model_path)

    def predict(self, features: list[FeatureVector]) -> list[Prediction]:
        if not features:
            return []
        matrix = np.array([[getattr(feature, column) for column in FEATURE_COLUMNS] for feature in features])
        decision_scores = self.model.decision_function(matrix)
        predictions = self.model.predict(matrix)
        return [
            Prediction(
                is_anomaly=prediction == -1,
                anomaly_score=float(-score),
            )
            for prediction, score in zip(predictions, decision_scores, strict=True)
        ]

    def _load_or_bootstrap(self, model_path: Path) -> tuple[IsolationForest, str]:
        if model_path.exists():
            payload = joblib.load(model_path)
            return payload["model"], payload["version"]

        model = IsolationForest(
            contamination=0.08,
            n_estimators=200,
            random_state=42,
        )
        baseline = self._synthetic_baseline()
        model.fit(baseline)
        version = stable_sha256(
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "feature_columns": FEATURE_COLUMNS,
                "samples": len(baseline),
            }
        )[:12]
        joblib.dump({"model": model, "version": version}, model_path)
        return model, version

    @staticmethod
    def _synthetic_baseline(samples: int = 2000) -> np.ndarray:
        rng = np.random.default_rng(42)
        packet_count = rng.integers(1, 80, size=samples)
        avg_packet_size = rng.normal(750, 180, size=samples).clip(60, 1500)
        duration = rng.uniform(1.0, 10.0, size=samples)
        byte_count = packet_count * avg_packet_size
        packets_per_sec = packet_count / duration
        bytes_per_sec = byte_count / duration
        syn_count = rng.integers(0, 8, size=samples)
        ack_count = (syn_count + rng.integers(1, 10, size=samples)).clip(1, None)
        unique_dst_ports = rng.integers(1, 5, size=samples)
        unique_dst_ips = rng.integers(1, 4, size=samples)
        port_entropy = rng.uniform(0.0, 1.3, size=samples)
        return np.column_stack(
            [
                packet_count,
                byte_count,
                duration,
                avg_packet_size,
                packets_per_sec,
                bytes_per_sec,
                syn_count,
                ack_count,
                unique_dst_ports,
                unique_dst_ips,
                port_entropy,
            ]
        )
