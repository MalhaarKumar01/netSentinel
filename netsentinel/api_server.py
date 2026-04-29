from __future__ import annotations

from contextlib import suppress

from fastapi import FastAPI, Query

from .config import Settings
from .monitor import NetSentinelMonitor
from .runtime_store import RuntimeStore
from .schemas import HealthStatus, utc_now

settings = Settings()
runtime_store = RuntimeStore(settings)
monitor: NetSentinelMonitor | None = None
app = FastAPI(title="NetSentinel API", version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    global monitor
    if settings.api_autostart:
        monitor = NetSentinelMonitor(settings)
        monitor.start()


@app.on_event("shutdown")
def shutdown() -> None:
    global monitor
    if monitor is not None:
        with suppress(Exception):
            monitor.stop()
        monitor = None


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "NetSentinel", "status": "ok"}


@app.get("/health", response_model=HealthStatus)
def health() -> HealthStatus:
    payload = runtime_store.read_health()
    if payload:
        return HealthStatus.model_validate(payload)
    return HealthStatus(
        status="idle",
        started_at=utc_now(),
        updated_at=utc_now(),
        capture_mode=settings.capture_mode,
        model_version="uninitialized",
    )


@app.get("/alerts")
def alerts(limit: int = Query(default=50, ge=1, le=200)) -> list[dict]:
    payload = runtime_store.read_alerts()
    return payload[:limit]
