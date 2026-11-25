#!/usr/bin/env python3
"""
Maria IDS User Space Daemon:
Receives network packets streamed from the kernel module via Netlink,
analyzes traffic for malicious activity with heuristic and ML detectors,
dynamically provisions firewall rules (nftables/iptables),
and produces structured threat & audit logs.
"""

import argparse
import os
import select
import signal
import socket
import sys
import time

from protocol import (
    MARIA_NL_UNIT,
    MARIA_MSG_REGISTER,
    MARIA_MSG_UNREGISTER,
    MARIA_MSG_HEARTBEAT,
    encode_control_msg,
    decode_netlink_message,
)
from logger import IDSLogger
from detector import ThreatDetector
from firewall import FirewallManager


class MariaDaemon:
    def __init__(
        self,
        backend: str = "nftables",
        dry_run: bool = False,
        default_ttl: int = 300,
        log_dir: str = "logs",
        verbose: bool = False,
        port_scan_threshold: int = 8,
        syn_flood_threshold: int = 40,
        entropy_threshold: float = 7.3,
        ml_model_file: Optional[str] = None,
    ):
        self.running = False
        self.logger = IDSLogger(log_dir=log_dir, verbose=verbose)
        self.detector = ThreatDetector(
            port_scan_threshold=port_scan_threshold,
            syn_flood_threshold=syn_flood_threshold,
            entropy_threshold=entropy_threshold,
            ml_model_file=ml_model_file,
        )
        self.firewall = FirewallManager(
            backend=backend,
            default_ttl=default_ttl,
            dry_run=dry_run,
            logger=self.logger,
        )
        self.sock: Optional[socket.socket] = None
        self.last_cleanup = time.time()
        self.last_heartbeat = time.time()

    def _setup_socket(self) -> bool:
        """Create and bind AF_NETLINK socket and register with kernel."""
        try:
            # AF_NETLINK = 16, SOCK_RAW = 3, protocol = NETLINK_USERSOCK (2)
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, MARIA_NL_UNIT)
            self.sock.bind((0, 0))  # (pid 0 for OS to assign, multicast groups 0)
            self.sock.setblocking(False)

            assigned_pid, _ = self.sock.getsockname()
            self.logger.info(f"Netlink socket bound with PID {assigned_pid} on unit {MARIA_NL_UNIT}")

            # Send REGISTER message to kernel (if module is loaded)
            try:
                reg_msg = encode_control_msg(MARIA_MSG_REGISTER, pid=assigned_pid)
                self.sock.sendto(reg_msg, (0, 0))  # Send to kernel (pid 0)
                self.logger.info("Sent registration handshake to Maria kernel module.")
            except ConnectionRefusedError:
                self.logger.warning("Maria kernel module is not currently loaded. Running in standalone/simulation mode.")

            return True
        except PermissionError:
            self.logger.error("Permission denied opening Netlink socket. Try running with sudo / CAP_NET_ADMIN.")
            return False
        except Exception as e:
            self.logger.error(f"Failed to open Netlink socket: {e}")
            return False

    def shutdown(self, signum=None, frame=None):
        """Clean shutdown handler."""
        if not self.running:
            return
        self.running = False
        self.logger.info("Shutting down Maria IDS daemon...")

        if self.sock:
            try:
                assigned_pid, _ = self.sock.getsockname()
                unreg_msg = encode_control_msg(MARIA_MSG_UNREGISTER, pid=assigned_pid)
                self.sock.sendto(unreg_msg, (0, 0))
                self.logger.info("Sent unregister notification to kernel module.")
            except Exception:
                pass
            finally:
                self.sock.close()
                self.sock = None

        self.firewall.flush_all()
        self.logger.info("Maria IDS daemon terminated cleanly.")
        sys.exit(0)

    def run(self):
        """Main event loop."""
        if not self._setup_socket():
            sys.exit(1)

        self.running = True
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        self.logger.info("Maria IDS daemon listening for packet stream... Press Ctrl+C to stop.")

        rx_buffer_size = 65536
        while self.running:
            try:
                readable, _, _ = select.select([self.sock], [], [], 1.0)
                now = time.time()

                if readable:
                    data, _ = self.sock.recvfrom(rx_buffer_size)
                    event = decode_netlink_message(data)
                    if event:
                        # Analyze packet
                        result = self.detector.analyze(event)
                        if result.is_malicious:
                            self.logger.log_malicious_packet(
                                event=event,
                                threat_type=result.threat_type,
                                confidence=result.confidence,
                                reason=result.reason,
                                details=result.details,
                            )
                            # Create firewall block rule
                            self.firewall.block_ip(
                                ip=event.src_ip,
                                reason=f"{result.threat_type}: {result.reason}",
                            )
                        else:
                            self.logger.debug(
                                f"OK: {event.src_ip}:{event.src_port} -> "
                                f"{event.dst_ip}:{event.dst_port} ({event.protocol_name})"
                            )

                # Periodic TTL expiration cleanup
                if now - self.last_cleanup >= 5.0:
                    self.firewall.cleanup_expired()
                    self.last_cleanup = now

                # Periodic heartbeat to kernel module
                if now - self.last_heartbeat >= 30.0:
                    try:
                        assigned_pid, _ = self.sock.getsockname()
                        hb_msg = encode_control_msg(MARIA_MSG_HEARTBEAT, pid=assigned_pid)
                        self.sock.sendto(hb_msg, (0, 0))
                    except Exception:
                        pass
                    self.last_heartbeat = now

            except KeyboardInterrupt:
                break
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in event loop: {e}")
                    time.sleep(0.5)

        self.shutdown()


def main():
    parser = argparse.ArgumentParser(description="Maria IDS - Kernel-assisted Intrusion Prevention Daemon")
    parser.add_argument(
        "--backend",
        choices=["nftables", "iptables", "dryrun"],
        default="dryrun",
        help="Firewall backend to provision rules (default: dryrun)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate firewall rules without modifying system tables",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=300,
        help="Default block rule duration in seconds (0 for permanent, default: 300)",
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=8,
        help="Unique ports scanned within 5s to trigger block (default: 8)",
    )
    parser.add_argument(
        "--syn-flood-threshold",
        type=int,
        default=40,
        help="SYN packets within 2s to trigger flood block (default: 40)",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=7.3,
        help="Shannon entropy threshold on unencrypted payload (default: 7.3)",
    )
    parser.add_argument(
        "--ml-model",
        type=str,
        default=None,
        help="Path to pre-trained LightGBM or custom ML model file (e.g. userspace/models/maria_lgbm_model.txt)",
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="logs",
        help="Directory to write logs (default: logs)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose / debug logging",
    )

    args = parser.parse_args()

    # If --dry-run is set, override backend
    backend = "dryrun" if args.dry_run else args.backend

    daemon = MariaDaemon(
        backend=backend,
        dry_run=(backend == "dryrun"),
        default_ttl=args.ttl,
        log_dir=args.log_dir,
        verbose=args.verbose,
        port_scan_threshold=args.port_scan_threshold,
        syn_flood_threshold=args.syn_flood_threshold,
        entropy_threshold=args.entropy_threshold,
        ml_model_file=args.ml_model,
    )
    daemon.run()


if __name__ == "__main__":
    main()
