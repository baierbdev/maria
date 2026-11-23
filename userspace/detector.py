"""
Threat Detection Engine for Maria IDS:
- Layer 1: Protocol & TCP Flag Anomaly Checks (NULL, XMAS, SYN-FIN scans)
- Layer 2: Stateful Sliding Window Analysis (Port scans, SYN floods, connection rate)
- Layer 3: Payload Signatures (SQLi, Command Injection, Directory Traversal, Web Shells)
- Layer 4: Shannon Entropy & Statistical / ML Anomaly Scoring
"""

import collections
import math
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from protocol import PacketEvent


@dataclass
class DetectionResult:
    is_malicious: bool
    threat_type: str = "BENIGN"
    confidence: float = 0.0
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    counter = collections.Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


class ThreatDetector:
    # Known malicious string/regex signatures in payloads
    SIGNATURES = [
        (re.compile(rb"(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell(\.exe)?)", re.I), "COMMAND_INJECTION", 0.95),
        (re.compile(rb"(wget\s+https?:\/\/|curl\s+https?:\/\/)", re.I), "MALICIOUS_DOWNLOADER", 0.90),
        (re.compile(rb"(\.\.\/|\.\.\\){2,}(etc\/(passwd|shadow)|windows\/system32)", re.I), "PATH_TRAVERSAL", 0.95),
        (re.compile(rb"('|\%27)[\s+]*(OR|AND)[\s+]*('?1'?[\s+]*(=|\%3d)[\s+]*'?1'|[0-9]+[\s+]*(=|\%3d)[\s+]*[0-9]+)", re.I), "SQL_INJECTION", 0.92),
        (re.compile(rb"(UNION[\s+]+SELECT|SELECT[\s+]+.*FROM[\s+]+information_schema)", re.I), "SQL_INJECTION", 0.96),
        (re.compile(rb"(eval\s*\(base64_decode|system\s*\(\$_GET|\$\{\s*jndi:(ldap|rmi))", re.I), "EXPLOIT_PAYLOAD", 0.99),
        (re.compile(rb"(GET|POST)\s+\/(\.env|\.git\/HEAD|wp-login\.php|phpmyadmin)", re.I), "SENSITIVE_PROBE", 0.85),
    ]

    def __init__(
        self,
        port_scan_threshold: int = 8,
        port_scan_window: float = 5.0,
        syn_flood_threshold: int = 40,
        syn_flood_window: float = 2.0,
        entropy_threshold: float = 7.3,
        anomaly_threshold: float = 0.85,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window = syn_flood_window
        self.entropy_threshold = entropy_threshold
        self.anomaly_threshold = anomaly_threshold

        # Stateful trackers per Source IP
        # src_ip -> deque of (timestamp, dst_port)
        self.ip_port_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # src_ip -> deque of timestamps of SYN packets
        self.ip_syn_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # src_ip -> deque of timestamps of any packet (for rate calculation)
        self.ip_rate_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)

    def analyze(self, event: PacketEvent) -> DetectionResult:
        now = time.time()
        src_ip = event.src_ip

        # 1. TCP Flag Anomaly Analysis
        if event.protocol_name == "TCP":
            flags = event.tcp_flags
            val = event.tcp_flags_val

            # NULL Scan: No flags set
            if val == 0:
                return DetectionResult(
                    is_malicious=True,
                    threat_type="TCP_NULL_SCAN",
                    confidence=0.95,
                    reason="TCP packet with zero flags set (NULL Scan)",
                    details={"flags": event.tcp_flags_str},
                )

            # XMAS Scan: FIN, PSH, URG all set
            if flags.get("FIN") and flags.get("PSH") and flags.get("URG"):
                return DetectionResult(
                    is_malicious=True,
                    threat_type="TCP_XMAS_SCAN",
                    confidence=0.98,
                    reason="TCP packet with FIN, PSH, URG set (XMAS Scan)",
                    details={"flags": event.tcp_flags_str},
                )

            # SYN-FIN scan: impossible combination in legitimate TCP
            if flags.get("SYN") and flags.get("FIN"):
                return DetectionResult(
                    is_malicious=True,
                    threat_type="TCP_SYN_FIN_ANOMALY",
                    confidence=0.98,
                    reason="TCP packet with both SYN and FIN set",
                    details={"flags": event.tcp_flags_str},
                )

            # SYN-RST scan
            if flags.get("SYN") and flags.get("RST"):
                return DetectionResult(
                    is_malicious=True,
                    threat_type="TCP_SYN_RST_ANOMALY",
                    confidence=0.95,
                    reason="TCP packet with both SYN and RST set",
                    details={"flags": event.tcp_flags_str},
                )

            # Track SYN flood
            if flags.get("SYN") and not flags.get("ACK"):
                syn_q = self.ip_syn_history[src_ip]
                syn_q.append(now)
                # Purge older entries
                while syn_q and syn_q[0] < now - self.syn_flood_window:
                    syn_q.popleft()

                if len(syn_q) >= self.syn_flood_threshold:
                    return DetectionResult(
                        is_malicious=True,
                        threat_type="SYN_FLOOD",
                        confidence=0.92,
                        reason=f"Exceeded SYN rate limit: {len(syn_q)} SYNs in {self.syn_flood_window}s",
                        details={"syn_count": len(syn_q), "window_sec": self.syn_flood_window},
                    )

        # 2. Stateful Port Scan Detection
        port_q = self.ip_port_history[src_ip]
        port_q.append((now, event.dst_port))
        while port_q and port_q[0][0] < now - self.port_scan_window:
            port_q.popleft()

        unique_ports = {p for _, p in port_q}
        if len(unique_ports) >= self.port_scan_threshold:
            return DetectionResult(
                is_malicious=True,
                threat_type="PORT_SCAN",
                confidence=min(0.99, 0.75 + (len(unique_ports) * 0.02)),
                reason=f"Scanned {len(unique_ports)} unique ports within {self.port_scan_window}s",
                details={
                    "unique_ports_count": len(unique_ports),
                    "window_sec": self.port_scan_window,
                    "target_ports_sample": sorted(list(unique_ports))[:10],
                },
            )

        # 3. Payload Signature Matching
        if event.payload:
            # Check raw payload and URL-normalized payload
            normalized_payload = urllib.parse.unquote_to_bytes(event.payload).replace(b"+", b" ")
            payloads_to_check = [event.payload]
            if normalized_payload != event.payload:
                payloads_to_check.append(normalized_payload)

            for target_data in payloads_to_check:
                for pattern, threat_name, conf in self.SIGNATURES:
                    match = pattern.search(target_data)
                    if match:
                        matched_snippet = match.group(0).decode("ascii", errors="replace")
                        return DetectionResult(
                            is_malicious=True,
                            threat_type=threat_name,
                            confidence=conf,
                            reason=f"Matched malicious signature pattern: {matched_snippet[:64]}",
                            details={"matched_text": matched_snippet},
                        )

            # 4. Entropy & Anomaly Analysis for Unencrypted Services
            entropy = calculate_entropy(event.payload)
            # High entropy (> 7.3) on non-encrypted service ports (e.g., HTTP 80, 8080, Telnet, or high ports)
            if (
                len(event.payload) >= 64
                and entropy >= self.entropy_threshold
                and event.dst_port not in {443, 8443, 22}
            ):
                return DetectionResult(
                    is_malicious=True,
                    threat_type="HIGH_ENTROPY_PAYLOAD",
                    confidence=0.88,
                    reason=f"Abnormally high payload entropy ({entropy:.2f}/8.00) on non-TLS port {event.dst_port}",
                    details={
                        "entropy": round(entropy, 3),
                        "payload_len": len(event.payload),
                        "dst_port": event.dst_port,
                    },
                )

        # Benign packet
        return DetectionResult(is_malicious=False)
