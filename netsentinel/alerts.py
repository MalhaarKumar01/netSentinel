from __future__ import annotations

from datetime import timezone
from uuid import uuid4

from .schemas import AlertRecord, FeatureVector, utc_now
from .security import anonymize_ip, stable_sha256


class AlertEngine:
    def build_alert(self, feature: FeatureVector, anomaly_score: float, is_anomaly: bool) -> AlertRecord | None:
        reasons: list[str] = []
        severity = "LOW"

        if is_anomaly:
            reasons.append("ml-anomaly-detected")

        if feature.unique_dst_ports >= 20 or feature.port_entropy >= 2.5:
            severity = "HIGH"
            reasons.append("possible-port-scan")

        if feature.packets_per_sec >= 100 or feature.bytes_per_sec >= 100_000:
            severity = "HIGH"
            reasons.append("traffic-spike")

        if feature.syn_count >= max(feature.ack_count * 3, 15):
            severity = "HIGH"
            reasons.append("syn-dominant-flow")

        if anomaly_score >= 0.10 and severity != "HIGH":
            severity = "MEDIUM"
        if anomaly_score >= 0.20:
            severity = "HIGH"

        if reasons == ["ml-anomaly-detected"] and anomaly_score < 0.05:
            return None

        if not reasons and not is_anomaly:
            return None

        created_at = utc_now()
        flow = {
            "src_ip": anonymize_ip(feature.src_ip),
            "dst_ip": anonymize_ip(feature.dst_ip),
            "protocol": feature.protocol,
            "packet_count": feature.packet_count,
            "byte_count": feature.byte_count,
            "flow_duration": round(feature.flow_duration, 4),
            "avg_packet_size": round(feature.avg_packet_size, 2),
            "packets_per_sec": round(feature.packets_per_sec, 2),
            "bytes_per_sec": round(feature.bytes_per_sec, 2),
            "syn_count": feature.syn_count,
            "ack_count": feature.ack_count,
            "unique_dst_ports": feature.unique_dst_ports,
            "unique_dst_ips": feature.unique_dst_ips,
            "port_entropy": round(feature.port_entropy, 4),
        }
        alert_hash = stable_sha256(
            {
                "created_at": created_at.astimezone(timezone.utc).isoformat(),
                "severity": severity,
                "flow": flow,
                "reasons": reasons,
                "anomaly_score": round(anomaly_score, 6),
            }
        )
        return AlertRecord(
            id=str(uuid4()),
            created_at=created_at,
            severity=severity,
            src_ip=flow["src_ip"],
            dst_ip=flow["dst_ip"],
            protocol=feature.protocol,
            packet_count=feature.packet_count,
            byte_count=feature.byte_count,
            anomaly_score=round(anomaly_score, 6),
            reasons=reasons,
            alert_hash=alert_hash,
            flow=flow,
        )
