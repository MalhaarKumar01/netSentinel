from __future__ import annotations

import queue
import threading
import time
from collections import deque

from .alerts import AlertEngine
from .config import Settings
from .flow import FlowEngine
from .ml import MLService
from .packet_agent import BasePacketAgent, LivePacketAgent, SyntheticPacketAgent
from .runtime_store import RuntimeStore
from .schemas import AlertRecord, HealthStatus, PacketRecord, utc_now


class NetSentinelMonitor:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self.settings.ensure_directories()
        self.flow_engine = FlowEngine()
        self.runtime_store = RuntimeStore(self.settings)
        self.ml_service = MLService(self.settings.model_path)
        self.alert_engine = AlertEngine()
        self.packet_queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=self.settings.queue_size)
        self._alerts: deque[AlertRecord] = deque(maxlen=self.settings.alert_buffer_size)
        self._alerts_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._processor_thread: threading.Thread | None = None
        self._window_thread: threading.Thread | None = None
        self._packet_agent = self._build_packet_agent()
        self.started_at = utc_now()
        self.packets_processed = 0
        self.dropped_packets = 0
        self.alerts_generated = 0
        self.last_error: str | None = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._write_health("starting")
        self._processor_thread = threading.Thread(target=self._processor_loop, name="netsentinel-processor", daemon=True)
        self._window_thread = threading.Thread(target=self._window_loop, name="netsentinel-window", daemon=True)
        self._processor_thread.start()
        self._window_thread.start()
        try:
            self._packet_agent.start()
        except Exception as exc:
            self.last_error = str(exc)
            self._write_health("degraded")
            self._running = False
            self._stop_event.set()
            raise
        self._write_health("running")

    def stop(self) -> None:
        if not self._running:
            return
        self._stop_event.set()
        self._packet_agent.stop()
        if self._processor_thread is not None:
            self._processor_thread.join(timeout=3)
        if self._window_thread is not None:
            self._window_thread.join(timeout=3)
        self._flush_window()
        self._write_health("stopped")
        self._running = False

    def latest_alerts(self, limit: int = 50) -> list[AlertRecord]:
        with self._alerts_lock:
            return list(self._alerts)[:limit]

    def _build_packet_agent(self) -> BasePacketAgent:
        if self.settings.capture_mode == "synthetic":
            return SyntheticPacketAgent(self._enqueue_packet)
        return LivePacketAgent(
            callback=self._enqueue_packet,
            interface=self.settings.interface,
            bpf_filter=self.settings.bpf_filter,
        )

    def _enqueue_packet(self, packet: PacketRecord) -> None:
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.dropped_packets += 1
            self.last_error = "packet-queue-full"

    def _processor_loop(self) -> None:
        while not self._stop_event.is_set() or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.flow_engine.process_packet(packet)
                self.packets_processed += 1
            except Exception as exc:  # pragma: no cover
                self.last_error = str(exc)
                self.runtime_store.log_event({"event": "processor_error", "error": str(exc), "at": utc_now()})
            finally:
                self.packet_queue.task_done()

    def _window_loop(self) -> None:
        while not self._stop_event.wait(self.settings.window_seconds):
            self._flush_window()

    def _flush_window(self) -> None:
        try:
            features = self.flow_engine.flush()
            predictions = self.ml_service.predict(features)
            for feature, prediction in zip(features, predictions, strict=True):
                alert = self.alert_engine.build_alert(feature, prediction.anomaly_score, prediction.is_anomaly)
                if alert is None:
                    continue
                self._push_alert(alert)
                self.runtime_store.log_event(
                    {
                        "event": "anomaly",
                        "severity": alert.severity,
                        "score": alert.anomaly_score,
                        "protocol": alert.protocol,
                        "reasons": alert.reasons,
                        "at": alert.created_at,
                    }
                )
                print(
                    f"[{alert.created_at.isoformat()}] {alert.severity} anomaly "
                    f"{alert.src_ip} -> {alert.dst_ip} "
                    f"packets={alert.packet_count} bytes={alert.byte_count} score={alert.anomaly_score:.4f}"
                )
            self.runtime_store.write_alerts(self.latest_alerts(self.settings.alert_buffer_size))
            self._write_health("running")
        except Exception as exc:  # pragma: no cover
            self.last_error = str(exc)
            self.runtime_store.log_event({"event": "flush_error", "error": str(exc), "at": utc_now()})
            self._write_health("degraded")

    def _push_alert(self, alert: AlertRecord) -> None:
        with self._alerts_lock:
            self._alerts.appendleft(alert)
            self.alerts_generated += 1

    def _write_health(self, status: str) -> None:
        health = HealthStatus(
            status=status,
            started_at=self.started_at,
            updated_at=utc_now(),
            capture_mode=self.settings.capture_mode,
            model_version=self.ml_service.version,
            packets_processed=self.packets_processed,
            flows_seen=self.flow_engine.total_flows_seen,
            alerts_generated=self.alerts_generated,
            dropped_packets=self.dropped_packets,
            queue_depth=self.packet_queue.qsize(),
            last_error=self.last_error,
        )
        self.runtime_store.write_health(health)
