from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class PacketRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class SourceProfile:
    unique_dst_ports: int
    unique_dst_ips: int
    port_entropy: float
    syn_packets: int
    ack_packets: int


@dataclass(slots=True)
class FlowSnapshot:
    src_ip: str
    dst_ip: str
    protocol: str
    packet_count: int
    byte_count: int
    start_time: datetime
    end_time: datetime
    syn_count: int
    ack_count: int
    source_profile: SourceProfile


class FeatureVector(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    flow_duration: float = Field(ge=0.0)
    avg_packet_size: float = Field(ge=0.0)
    packets_per_sec: float = Field(ge=0.0)
    bytes_per_sec: float = Field(ge=0.0)
    syn_count: int = Field(ge=0)
    ack_count: int = Field(ge=0)
    unique_dst_ports: int = Field(ge=0)
    unique_dst_ips: int = Field(ge=0)
    port_entropy: float = Field(ge=0.0)


class AlertRecord(BaseModel):
    id: str
    created_at: datetime
    severity: str
    src_ip: str
    dst_ip: str
    protocol: str
    packet_count: int
    byte_count: int
    anomaly_score: float
    reasons: list[str]
    alert_hash: str
    flow: dict[str, Any]


class HealthStatus(BaseModel):
    status: str
    started_at: datetime
    updated_at: datetime
    capture_mode: str
    model_version: str
    packets_processed: int = 0
    flows_seen: int = 0
    alerts_generated: int = 0
    dropped_packets: int = 0
    queue_depth: int = 0
    last_error: str | None = None
