from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Settings:
    project_root: Path = Path(__file__).resolve().parent.parent
    runtime_dir: Path = project_root / "runtime"
    log_dir: Path = project_root / "logs"
    model_dir: Path = project_root / "models"
    model_path: Path = model_dir / "isolation_forest.joblib"
    window_seconds: int = int(os.getenv("NETSENTINEL_WINDOW_SECONDS", "10"))
    queue_size: int = int(os.getenv("NETSENTINEL_QUEUE_SIZE", "50000"))
    alert_buffer_size: int = int(os.getenv("NETSENTINEL_ALERT_BUFFER_SIZE", "200"))
    log_level: str = os.getenv("NETSENTINEL_LOG_LEVEL", "INFO")
    capture_mode: str = os.getenv("NETSENTINEL_CAPTURE_MODE", "live").lower()
    interface: str | None = os.getenv("NETSENTINEL_INTERFACE")
    bpf_filter: str | None = os.getenv("NETSENTINEL_BPF_FILTER")
    api_autostart: bool = os.getenv("NETSENTINEL_API_AUTOSTART", "0") == "1"

    def ensure_directories(self) -> None:
        for path in (self.runtime_dir, self.log_dir, self.model_dir):
            path.mkdir(parents=True, exist_ok=True)
