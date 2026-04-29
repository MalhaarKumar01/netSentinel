from __future__ import annotations

import random
import threading
import time
from datetime import timedelta
from typing import Callable

from .schemas import PacketRecord, utc_now


PacketCallback = Callable[[PacketRecord], None]


class BasePacketAgent:
    def __init__(self, callback: PacketCallback) -> None:
        self.callback = callback

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


class LivePacketAgent(BasePacketAgent):
    def __init__(self, callback: PacketCallback, interface: str | None = None, bpf_filter: str | None = None) -> None:
        super().__init__(callback)
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._sniffer = None

    def start(self) -> None:
        try:
            from scapy.all import AsyncSniffer  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Scapy is required for live capture mode.") from exc

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            store=False,
            prn=self._handle_packet,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()

    def _handle_packet(self, packet: object) -> None:
        record = self._packet_to_record(packet)
        if record is not None:
            self.callback(record)

    @staticmethod
    def _packet_to_record(packet: object) -> PacketRecord | None:
        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
            from scapy.layers.inet6 import IPv6  # type: ignore
        except ImportError:
            return None

        ip_layer = None
        protocol = "OTHER"
        src_port = None
        dst_port = None
        tcp_flags: set[str] = set()

        if IP in packet:
            ip_layer = packet[IP]
        elif IPv6 in packet:
            ip_layer = packet[IPv6]

        if ip_layer is None:
            return None

        if TCP in packet:
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            raw_flags = str(tcp_layer.flags)
            tcp_flags = {flag for flag in raw_flags if flag.isalpha()}
        elif UDP in packet:
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
        elif ICMP in packet:
            protocol = "ICMP"

        return PacketRecord(
            timestamp=utc_now(),
            src_ip=str(ip_layer.src),
            dst_ip=str(ip_layer.dst),
            protocol=protocol,
            length=len(packet),
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
        )


class SyntheticPacketAgent(BasePacketAgent):
    def __init__(self, callback: PacketCallback) -> None:
        super().__init__(callback)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="netsentinel-synthetic", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        burst_counter = 0
        while not self._stop_event.is_set():
            burst_counter += 1
            self._emit_normal_traffic()
            if burst_counter % 5 == 0:
                self._emit_port_scan()
            if burst_counter % 7 == 0:
                self._emit_traffic_spike()
            time.sleep(0.2)

    def _emit_normal_traffic(self) -> None:
        now = utc_now()
        flows = [
            ("10.0.0.10", "192.168.1.20", 443),
            ("10.0.0.11", "192.168.1.21", 80),
            ("10.0.0.12", "192.168.1.22", 53),
            ("10.0.0.13", "192.168.1.23", 123),
        ]
        for src_ip, dst_ip, dst_port in flows:
            for _ in range(random.randint(2, 5)):
                size = random.randint(80, 1200)
                flags = {"A"} if random.random() > 0.2 else {"S", "A"}
                self.callback(
                    PacketRecord(
                        timestamp=now + timedelta(milliseconds=random.randint(0, 900)),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="TCP",
                        length=size,
                        src_port=44000,
                        dst_port=dst_port,
                        tcp_flags=flags,
                    )
                )

    def _emit_port_scan(self) -> None:
        now = utc_now()
        src_ip = "172.16.0.99"
        dst_ip = "192.168.1.10"
        for port in range(20, 70):
            self.callback(
                PacketRecord(
                    timestamp=now,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    length=60,
                    src_port=random.randint(32000, 65000),
                    dst_port=port,
                    tcp_flags={"S"},
                )
            )

    def _emit_traffic_spike(self) -> None:
        now = utc_now()
        for _ in range(120):
            self.callback(
                PacketRecord(
                    timestamp=now,
                    src_ip="10.10.10.10",
                    dst_ip="192.168.1.44",
                    protocol="UDP",
                    length=1450,
                    src_port=random.randint(1024, 65535),
                    dst_port=443,
                    tcp_flags=set(),
                )
            )
