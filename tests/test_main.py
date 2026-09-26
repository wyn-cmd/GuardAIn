import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, UDP, Ether  # noqa: E402
import main  # noqa: E402


class ScanTrackerTests(unittest.TestCase):
    def setUp(self):
        main.scan_tracker.clear()

    def test_a_burst_of_syn_packets_to_many_ports_is_flagged(self):
        src = "9.9.9.1"
        result = False
        for port in range(1, 30):
            pkt = IP(src=src, dst="5.6.7.8") / TCP(dport=port, flags="S")
            result = main.detect_scan(pkt)
        self.assertEqual(result, "Likely port scan (many ports, low ACK)")

    def test_a_quiet_source_is_not_flagged_forever(self):
        src = "9.9.9.2"
        for port in range(1, 30):
            pkt = IP(src=src, dst="5.6.7.8") / TCP(dport=port, flags="S")
            main.detect_scan(pkt)
        # Simulate the 10 second sliding window fully draining.
        main.scan_tracker[src]["timestamps"].clear()
        later = IP(src=src, dst="5.6.7.8") / TCP(dport=443, flags="S")
        result = main.detect_scan(later)
        self.assertFalse(result)

    def test_a_single_normal_packet_is_not_flagged(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=80, flags="S")
        self.assertFalse(main.detect_scan(pkt))


class FeatureExtractionTests(unittest.TestCase):
    def test_a_tcp_packet_extracts_three_features(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=80, flags="S")
        self.assertEqual(main.extract_features(pkt), [1, 1, 40])

    def test_a_udp_packet_uses_udp_dport(self):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(dport=12345)
        proto, port_type, length = main.extract_features(pkt)
        self.assertEqual(proto, 2)
        self.assertEqual(port_type, 3)

    def test_a_packet_with_no_ip_layer_returns_none(self):
        self.assertIsNone(main.extract_features(Ether()))


class NoiseFilterTests(unittest.TestCase):
    def test_multicast_destination_is_noise(self):
        pkt = IP(src="1.2.3.4", dst="224.0.0.1") / UDP(dport=1900)
        self.assertTrue(main.is_noise(pkt))

    def test_a_regular_packet_is_not_noise(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=80, flags="S")
        self.assertFalse(main.is_noise(pkt))


if __name__ == "__main__":
    unittest.main(verbosity=2)
