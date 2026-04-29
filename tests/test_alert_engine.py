import unittest

from netsentinel.alerts import AlertEngine
from netsentinel.schemas import FeatureVector


class AlertEngineTests(unittest.TestCase):
    def test_escalates_high_severity_on_scan_like_flow(self) -> None:
        feature = FeatureVector(
            src_ip="10.0.0.50",
            dst_ip="192.168.1.10",
            protocol="TCP",
            packet_count=50,
            byte_count=3000,
            flow_duration=1.0,
            avg_packet_size=60.0,
            packets_per_sec=50.0,
            bytes_per_sec=3000.0,
            syn_count=50,
            ack_count=0,
            unique_dst_ports=40,
            unique_dst_ips=1,
            port_entropy=3.0,
        )

        alert = AlertEngine().build_alert(feature, anomaly_score=0.32, is_anomaly=True)

        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.src_ip, "10.0.0.x")
        self.assertIn("possible-port-scan", alert.reasons)
        self.assertIn("ml-anomaly-detected", alert.reasons)
        self.assertEqual(len(alert.alert_hash), 64)


if __name__ == "__main__":
    unittest.main()
