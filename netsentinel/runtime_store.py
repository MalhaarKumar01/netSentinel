from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .config import Settings
from .schemas import AlertRecord, HealthStatus


class RuntimeStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.settings.ensure_directories()
        self._lock = threading.Lock()
        self.alerts_path = self.settings.runtime_dir / "alerts.json"
        self.health_path = self.settings.runtime_dir / "health.json"
        self.alert_log_path = self.settings.log_dir / "alerts.log"
        self.event_log_path = self.settings.log_dir / "events.log"
        self._init_file(self.alerts_path, [])

    def _init_file(self, path: Path, default: Any) -> None:
        if not path.exists():
            path.write_text(json.dumps(default, indent=2), encoding="utf-8")

    def write_alerts(self, alerts: list[AlertRecord]) -> None:
        serialized = [alert.model_dump(mode="json") for alert in alerts]
        with self._lock:
            self.alerts_path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
            with self.alert_log_path.open("a", encoding="utf-8") as handle:
                for alert in serialized:
                    handle.write(json.dumps(alert) + "\n")

    def read_alerts(self) -> list[dict[str, Any]]:
        if not self.alerts_path.exists():
            return []
        return json.loads(self.alerts_path.read_text(encoding="utf-8"))

    def write_health(self, health: HealthStatus) -> None:
        with self._lock:
            self.health_path.write_text(
                health.model_dump_json(indent=2),
                encoding="utf-8",
            )

    def read_health(self) -> dict[str, Any]:
        if not self.health_path.exists():
            return {}
        return json.loads(self.health_path.read_text(encoding="utf-8"))

    def log_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            with self.event_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, default=str) + "\n")
