"""
Logging system for Maria IDS:
- Structured JSONL logging for malicious packets and threat detections
- Firewall action audit log
- Standard console logging with color support
"""

import json
import logging
import os
import sys
import time
from typing import Dict, Any, Optional
from protocol import PacketEvent


class IDSLogger:
    def __init__(self, log_dir: str = "logs", verbose: bool = False):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)

        self.packet_log_path = os.path.join(self.log_dir, "malicious_packets.jsonl")
        self.firewall_log_path = os.path.join(self.log_dir, "firewall.log")

        # Setup standard logger
        self.logger = logging.getLogger("maria_ids")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers = []

        console_handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def info(self, msg: str):
        self.logger.info(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def error(self, msg: str):
        self.logger.error(msg)

    def debug(self, msg: str):
        self.logger.debug(msg)

    def log_malicious_packet(
        self,
        event: PacketEvent,
        threat_type: str,
        confidence: float,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Append a JSON record to malicious_packets.jsonl."""
        # Create safe ASCII representation of payload preview
        ascii_preview = "".join(
            chr(b) if 32 <= b <= 126 else "." for b in event.payload[:128]
        )

        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event.timestamp_ns / 1e9)),
            "timestamp_ns": event.timestamp_ns,
            "threat_type": threat_type,
            "confidence": round(confidence, 4),
            "reason": reason,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "protocol": event.protocol_name,
            "tcp_flags": event.tcp_flags,
            "ifname": event.ifname,
            "total_len": event.total_len,
            "payload_len": event.payload_len,
            "payload_ascii_preview": ascii_preview,
            "payload_hex": event.payload[:128].hex(),
            "details": details or {},
        }

        try:
            with open(self.packet_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write to malicious packet log: {e}")

        self.logger.warning(
            f"THREAT DETECTED: [{threat_type}] from {event.src_ip}:{event.src_port} -> "
            f"{event.dst_ip}:{event.dst_port} ({event.protocol_name}) "
            f"Confidence: {confidence:.2f} | Reason: {reason}"
        )

    def log_firewall_action(
        self,
        action: str,
        target_ip: str,
        backend: str,
        reason: str,
        rule_spec: str,
        ttl_seconds: int = 0,
    ):
        """Append an entry to firewall.log."""
        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ttl_str = f"TTL: {ttl_seconds}s" if ttl_seconds > 0 else "TTL: permanent"
        line = (
            f"[{now_str}] [{action.upper()}] IP: {target_ip} | Backend: {backend} | "
            f"{ttl_str} | Reason: {reason} | Command: {rule_spec}\n"
        )

        try:
            with open(self.firewall_log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            self.logger.error(f"Failed to write to firewall log: {e}")

        self.logger.info(f"FIREWALL {action.upper()}: {target_ip} via {backend} ({ttl_str})")
