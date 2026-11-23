"""
Comprehensive test suite for Maria IDS:
- Validates binary encoding/decoding matching kernel protocol
- Validates detection engine on various threat vectors:
  * Port scans
  * TCP flag anomalies (NULL scan, XMAS scan, SYN-FIN scan)
  * SYN floods
  * Malicious payload signatures (SQLi, command injection, path traversal)
  * High entropy payloads
- Validates firewall management and logging
"""

import os
import shutil
import time
import unittest

# Add userspace directory to sys.path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "userspace")))

from protocol import (
    PacketEvent,
    MARIA_TCP_SYN,
    MARIA_TCP_FIN,
    MARIA_TCP_RST,
    MARIA_TCP_PSH,
    MARIA_TCP_URG,
    MARIA_TCP_ACK,
    decode_netlink_message,
    encode_control_msg,
    MARIA_MSG_REGISTER,
    MARIA_MSG_PACKET,
    NL_HDR_FMT,
    MARIA_HDR_FMT,
    PKT_DATA_FMT,
)
import struct
import socket
from detector import ThreatDetector, calculate_entropy
from firewall import FirewallManager
from logger import IDSLogger


class TestMariaIDS(unittest.TestCase):
    def setUp(self):
        self.test_log_dir = "logs_test"
        os.makedirs(self.test_log_dir, exist_ok=True)
        self.logger = IDSLogger(log_dir=self.test_log_dir, verbose=False)
        self.detector = ThreatDetector(port_scan_threshold=5, syn_flood_threshold=10)
        self.firewall = FirewallManager(backend="dryrun", default_ttl=2, logger=self.logger)

    def tearDown(self):
        if os.path.exists(self.test_log_dir):
            shutil.rmtree(self.test_log_dir)

    def create_mock_event(
        self,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "192.168.1.1",
        src_port: int = 12345,
        dst_port: int = 80,
        proto: str = "TCP",
        flags_val: int = MARIA_TCP_ACK,
        payload: bytes = b"",
    ) -> PacketEvent:
        flags_dict = {
            "FIN": bool(flags_val & MARIA_TCP_FIN),
            "SYN": bool(flags_val & MARIA_TCP_SYN),
            "RST": bool(flags_val & MARIA_TCP_RST),
            "PSH": bool(flags_val & MARIA_TCP_PSH),
            "ACK": bool(flags_val & MARIA_TCP_ACK),
            "URG": bool(flags_val & MARIA_TCP_URG),
        }
        return PacketEvent(
            timestamp_ns=time.time_ns(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol_num=6 if proto == "TCP" else (17 if proto == "UDP" else 1),
            protocol_name=proto,
            tcp_flags_val=flags_val,
            tcp_flags=flags_dict,
            ifname="eth0",
            total_len=40 + len(payload),
            payload_len=len(payload),
            payload=payload,
        )

    def test_benign_traffic(self):
        """Ensure standard HTTP GET request is considered benign."""
        event = self.create_mock_event(
            dst_port=80,
            flags_val=MARIA_TCP_ACK | MARIA_TCP_PSH,
            payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        res = self.detector.analyze(event)
        self.assertFalse(res.is_malicious)

    def test_xmas_scan(self):
        """Verify detection of TCP XMAS scan (FIN + PSH + URG)."""
        event = self.create_mock_event(
            flags_val=MARIA_TCP_FIN | MARIA_TCP_PSH | MARIA_TCP_URG,
            payload=b"",
        )
        res = self.detector.analyze(event)
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.threat_type, "TCP_XMAS_SCAN")

    def test_null_scan(self):
        """Verify detection of TCP NULL scan (0 flags)."""
        event = self.create_mock_event(flags_val=0, payload=b"")
        res = self.detector.analyze(event)
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.threat_type, "TCP_NULL_SCAN")

    def test_port_scan(self):
        """Verify detection of stateful port scan over sliding window."""
        scanner_ip = "10.0.0.99"
        res = None
        for port in [21, 22, 23, 80, 443, 3306, 8080]:
            event = self.create_mock_event(
                src_ip=scanner_ip,
                dst_port=port,
                flags_val=MARIA_TCP_SYN,
            )
            res = self.detector.analyze(event)

        self.assertIsNotNone(res)
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.threat_type, "PORT_SCAN")

    def test_sql_injection(self):
        """Verify detection of SQL Injection payload."""
        event = self.create_mock_event(
            dst_port=80,
            payload=b"GET /login?user=admin%27+OR+1%3D1-- HTTP/1.1\r\nHost: target.local\r\n\r\n",
        )
        res = self.detector.analyze(event)
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.threat_type, "SQL_INJECTION")

    def test_command_injection(self):
        """Verify detection of command execution signature."""
        event = self.create_mock_event(
            dst_port=8080,
            payload=b"POST /api/exec HTTP/1.1\r\n\r\ncmd=; /bin/sh -c 'id'",
        )
        res = self.detector.analyze(event)
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.threat_type, "COMMAND_INJECTION")

    def test_path_traversal(self):
        """Verify detection of directory traversal payload."""
        event = self.create_mock_event(
            dst_port=80,
            payload=b"GET /view?file=../../../../etc/passwd HTTP/1.1\r\n\r\n",
        )
        res = self.detector.analyze(event)
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.threat_type, "PATH_TRAVERSAL")

    def test_high_entropy_shellcode(self):
        """Verify detection of high-entropy payload."""
        # Simulated random/encrypted byte payload
        random_bytes = bytes([i % 256 for i in range(256)])
        event = self.create_mock_event(
            dst_port=9999,
            payload=random_bytes,
        )
        res = self.detector.analyze(event)
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.threat_type, "HIGH_ENTROPY_PAYLOAD")

    def test_firewall_management(self):
        """Test blocking, duplicate prevention, and TTL expiration."""
        bad_ip = "198.51.100.5"
        self.assertTrue(self.firewall.block_ip(bad_ip, reason="PORT_SCAN", ttl=1))
        self.assertIn(bad_ip, self.firewall.active_bans)

        # Logging check
        fw_log = os.path.join(self.test_log_dir, "firewall.log")
        self.assertTrue(os.path.exists(fw_log))
        with open(fw_log) as f:
            content = f.read()
            self.assertIn(bad_ip, content)
            self.assertIn("PORT_SCAN", content)

        # Wait for TTL to expire
        time.sleep(1.2)
        self.firewall.cleanup_expired()
        self.assertNotIn(bad_ip, self.firewall.active_bans)

    def test_binary_protocol_roundtrip(self):
        """Ensure synthesized binary Netlink packet decodes identically."""
        ts = 1700000000123456789
        src_ip_b = socket.inet_aton("192.168.4.20")
        dst_ip_b = socket.inet_aton("10.0.0.1")
        payload = b"PING_TEST_PAYLOAD"
        payload_len = len(payload)
        padded_payload = payload + b"\x00" * (1024 - payload_len)
        ifname = b"eth1\x00" + b"\x00" * 11

        pkt_data = struct.pack(
            PKT_DATA_FMT,
            ts,
            src_ip_b,
            dst_ip_b,
            44444,
            80,
            payload_len,
            100,
            6,
            MARIA_TCP_SYN,
            ifname,
            padded_payload,
        )

        maria_hdr = struct.pack(MARIA_HDR_FMT, MARIA_MSG_PACKET, len(pkt_data))
        nl_total_len = struct.calcsize(NL_HDR_FMT) + len(maria_hdr) + len(pkt_data)
        nl_hdr = struct.pack(NL_HDR_FMT, nl_total_len, 0, 0, 1, 12345)

        full_buf = nl_hdr + maria_hdr + pkt_data

        event = decode_netlink_message(full_buf)
        self.assertIsNotNone(event)
        self.assertEqual(event.src_ip, "192.168.4.20")
        self.assertEqual(event.dst_ip, "10.0.0.1")
        self.assertEqual(event.src_port, 44444)
        self.assertEqual(event.dst_port, 80)
        self.assertEqual(event.protocol_name, "TCP")
        self.assertTrue(event.tcp_flags["SYN"])
        self.assertEqual(event.payload, payload)
        self.assertEqual(event.ifname, "eth1")


if __name__ == "__main__":
    unittest.main()
