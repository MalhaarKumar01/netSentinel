from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from .schemas import FeatureVector, FlowSnapshot, PacketRecord, SourceProfile


@dataclass(slots=True)
class FlowAccumulator:
    src_ip: str
    dst_ip: str
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    syn_count: int = 0
    ack_count: int = 0

    def add_packet(self, packet: PacketRecord) -> None:
        self.packet_count += 1
        self.byte_count += packet.length
        self.start_time = self.start_time or packet.timestamp
        self.end_time = packet.timestamp
        if "S" in packet.tcp_flags:
            self.syn_count += 1
        if "A" in packet.tcp_flags:
            self.ack_count += 1


@dataclass(slots=True)
class SourceAccumulator:
    dst_ports: Counter[int] = field(default_factory=Counter)
    dst_ips: set[str] = field(default_factory=set)
    syn_packets: int = 0
    ack_packets: int = 0

    def add_packet(self, packet: PacketRecord) -> None:
        if packet.dst_port is not None:
            self.dst_ports[packet.dst_port] += 1
        self.dst_ips.add(packet.dst_ip)
        if "S" in packet.tcp_flags:
            self.syn_packets += 1
        if "A" in packet.tcp_flags:
            self.ack_packets += 1

    def profile(self) -> SourceProfile:
        total = sum(self.dst_ports.values())
        entropy = 0.0
        if total:
            for count in self.dst_ports.values():
                probability = count / total
                entropy -= probability * math.log2(probability)
        return SourceProfile(
            unique_dst_ports=len(self.dst_ports),
            unique_dst_ips=len(self.dst_ips),
            port_entropy=entropy,
            syn_packets=self.syn_packets,
            ack_packets=self.ack_packets,
        )


class FlowEngine:
    def __init__(self) -> None:
        self._flows: dict[tuple[str, str, str], FlowAccumulator] = {}
        self._sources: dict[str, SourceAccumulator] = defaultdict(SourceAccumulator)
        self.total_flows_seen = 0

    def process_packet(self, packet: PacketRecord) -> None:
        key = (packet.src_ip, packet.dst_ip, packet.protocol)
        flow = self._flows.get(key)
        if flow is None:
            flow = FlowAccumulator(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol=packet.protocol,
            )
            self._flows[key] = flow
            self.total_flows_seen += 1

        flow.add_packet(packet)
        self._sources[packet.src_ip].add_packet(packet)

    def flush(self) -> list[FeatureVector]:
        source_profiles = {src_ip: source.profile() for src_ip, source in self._sources.items()}
        feature_vectors: list[FeatureVector] = []

        for flow in self._flows.values():
            if flow.start_time is None or flow.end_time is None:
                continue
            duration = max((flow.end_time - flow.start_time).total_seconds(), 1.0)
            source_profile = source_profiles.get(flow.src_ip, SourceProfile(0, 0, 0.0, 0, 0))
            snapshot = FlowSnapshot(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                protocol=flow.protocol,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
                start_time=flow.start_time,
                end_time=flow.end_time,
                syn_count=flow.syn_count,
                ack_count=flow.ack_count,
                source_profile=source_profile,
            )
            feature_vectors.append(self._to_feature_vector(snapshot))

        self._flows = {}
        self._sources = defaultdict(SourceAccumulator)
        return feature_vectors

    @staticmethod
    def _to_feature_vector(snapshot: FlowSnapshot) -> FeatureVector:
        duration = max((snapshot.end_time - snapshot.start_time).total_seconds(), 1.0)
        return FeatureVector(
            src_ip=snapshot.src_ip,
            dst_ip=snapshot.dst_ip,
            protocol=snapshot.protocol,
            packet_count=snapshot.packet_count,
            byte_count=snapshot.byte_count,
            flow_duration=duration,
            avg_packet_size=snapshot.byte_count / max(snapshot.packet_count, 1),
            packets_per_sec=snapshot.packet_count / duration,
            bytes_per_sec=snapshot.byte_count / duration,
            syn_count=snapshot.syn_count,
            ack_count=snapshot.ack_count,
            unique_dst_ports=snapshot.source_profile.unique_dst_ports,
            unique_dst_ips=snapshot.source_profile.unique_dst_ips,
            port_entropy=snapshot.source_profile.port_entropy,
        )
