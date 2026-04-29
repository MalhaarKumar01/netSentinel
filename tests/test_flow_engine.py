import unittest
from datetime import timedelta

from netsentinel.flow import FlowEngine
from netsentinel.schemas import PacketRecord, utc_now


class FlowEngineTests(unittest.TestCase):
    def test_flush_extracts_expected_features(self) -> None:
        engine = FlowEngine()
        start = utc_now()
        packets = [
            PacketRecord(
                timestamp=start,
                src_ip="10.0.0.5",
                dst_ip="192.168.1.10",
                protocol="TCP",
                length=100,
                src_port=40000,
                dst_port=80,
                tcp_flags={"S"},
            ),
            PacketRecord(
                timestamp=start + timedelta(seconds=2),
                src_ip="10.0.0.5",
                dst_ip="192.168.1.10",
                protocol="TCP",
                length=300,
                src_port=40000,
                dst_port=443,
                tcp_flags={"A"},
            ),
        ]

        for packet in packets:
            engine.process_packet(packet)

        features = engine.flush()

        self.assertEqual(len(features), 1)
        feature = features[0]
        self.assertEqual(feature.packet_count, 2)
        self.assertEqual(feature.byte_count, 400)
        self.assertEqual(feature.avg_packet_size, 200)
        self.assertEqual(feature.unique_dst_ports, 2)
        self.assertEqual(feature.unique_dst_ips, 1)
        self.assertEqual(feature.flow_duration, 2.0)
        self.assertEqual(feature.packets_per_sec, 1.0)


if __name__ == "__main__":
    unittest.main()
