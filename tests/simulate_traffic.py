#!/usr/bin/env python3
"""
Traffic Simulator for Maria IDS:
Generates synthetic packet events over Netlink to test the detection engine,
firewall provisioning, and logging without needing external attack tools.
"""

import argparse
import os
import socket
import struct
import sys
import time

# Add userspace to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "userspace")))

from protocol import (
    MARIA_NL_UNIT,
    MARIA_MSG_PACKET,
    MARIA_TCP_SYN,
    MARIA_TCP_FIN,
    MARIA_TCP_PSH,
    MARIA_TCP_URG,
    MARIA_TCP_ACK,
    NL_HDR_FMT,
    MARIA_HDR_FMT,
    PKT_DATA_FMT,
)


def create_packet_buffer(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int,
    tcp_flags: int,
    payload: bytes,
    ifname: str = "eth0",
) -> bytes:
    ts_ns = time.time_ns()
    src_ip_b = socket.inet_aton(src_ip)
    dst_ip_b = socket.inet_aton(dst_ip)
    payload_len = min(len(payload), 1024)
    padded_payload = payload[:1024] + b"\x00" * (1024 - payload_len)
    ifname_b = ifname.encode("ascii")[:15] + b"\x00" * (16 - len(ifname[:15]))

    pkt_data = struct.pack(
        PKT_DATA_FMT,
        ts_ns,
        src_ip_b,
        dst_ip_b,
        src_port,
        dst_port,
        payload_len,
        40 + payload_len,
        protocol,
        tcp_flags,
        ifname_b,
        padded_payload,
    )

    maria_hdr = struct.pack(MARIA_HDR_FMT, MARIA_MSG_PACKET, len(pkt_data))
    nl_len = struct.calcsize(NL_HDR_FMT) + len(maria_hdr) + len(pkt_data)
    nl_hdr = struct.pack(NL_HDR_FMT, nl_len, 0, 0, 0, 0)

    return nl_hdr + maria_hdr + pkt_data


def main():
    parser = argparse.ArgumentParser(description="Maria IDS Synthetic Traffic Injector")
    parser.add_argument("--pid", type=int, required=True, help="Netlink PID of the running Maria daemon")
    parser.add_argument("--scenario", choices=["all", "benign", "portscan", "sqli", "cmdi", "xmas", "entropy"], default="all")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, MARIA_NL_UNIT)
    sock.bind((0, 0))
    target = (args.pid, 0)

    print(f"[*] Connected. Injecting traffic to Maria daemon PID {args.pid}...")

    def send(buf, desc):
        print(f"  -> Sending: {desc}")
        sock.sendto(buf, target)
        time.sleep(0.1)

    if args.scenario in ("all", "benign"):
        print("\n[Scenario 1: Benign Web Traffic]")
        send(
            create_packet_buffer(
                src_ip="192.168.1.50",
                dst_ip="192.168.1.1",
                src_port=51234,
                dst_port=80,
                protocol=6,
                tcp_flags=MARIA_TCP_ACK | MARIA_TCP_PSH,
                payload=b"GET /style.css HTTP/1.1\r\nHost: intranet.local\r\n\r\n",
            ),
            "Normal HTTP GET request",
        )

    if args.scenario in ("all", "portscan"):
        print("\n[Scenario 2: Port Scanning Attack]")
        attacker = "10.0.5.88"
        for port in [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]:
            send(
                create_packet_buffer(
                    src_ip=attacker,
                    dst_ip="192.168.1.1",
                    src_port=40000 + port,
                    dst_port=port,
                    protocol=6,
                    tcp_flags=MARIA_TCP_SYN,
                    payload=b"",
                ),
                f"TCP SYN probe to port {port}",
            )

    if args.scenario in ("all", "sqli"):
        print("\n[Scenario 3: SQL Injection Web Attack]")
        send(
            create_packet_buffer(
                src_ip="203.0.113.42",
                dst_ip="192.168.1.1",
                src_port=48210,
                dst_port=80,
                protocol=6,
                tcp_flags=MARIA_TCP_ACK | MARIA_TCP_PSH,
                payload=b"POST /api/search HTTP/1.1\r\n\r\nq=' UNION SELECT username,password FROM users--",
            ),
            "SQL Injection payload with UNION SELECT",
        )

    if args.scenario in ("all", "cmdi"):
        print("\n[Scenario 4: Remote Command Execution / Web Shell]")
        send(
            create_packet_buffer(
                src_ip="198.51.100.77",
                dst_ip="192.168.1.1",
                src_port=39211,
                dst_port=8080,
                protocol=6,
                tcp_flags=MARIA_TCP_ACK | MARIA_TCP_PSH,
                payload=b"POST /upload.php HTTP/1.1\r\n\r\n<?php system('/bin/sh -i'); ?>",
            ),
            "Web shell reverse shell payload",
        )

    if args.scenario in ("all", "xmas"):
        print("\n[Scenario 5: TCP XMAS Scan Anomaly]")
        send(
            create_packet_buffer(
                src_ip="198.51.100.99",
                dst_ip="192.168.1.1",
                src_port=55123,
                dst_port=80,
                protocol=6,
                tcp_flags=MARIA_TCP_FIN | MARIA_TCP_PSH | MARIA_TCP_URG,
                payload=b"",
            ),
            "TCP packet with FIN, PSH, URG flags",
        )

    if args.scenario in ("all", "entropy"):
        print("\n[Scenario 6: High-Entropy Packed Shellcode]")
        high_entropy_bytes = bytes([((i * 137 + 53) % 256) for i in range(300)])
        send(
            create_packet_buffer(
                src_ip="192.0.2.66",
                dst_ip="192.168.1.1",
                src_port=60111,
                dst_port=9001,
                protocol=6,
                tcp_flags=MARIA_TCP_ACK | MARIA_TCP_PSH,
                payload=high_entropy_bytes,
            ),
            "High-entropy binary payload to port 9001",
        )

    print("\n[✓] Traffic injection complete!")
    sock.close()


if __name__ == "__main__":
    main()
