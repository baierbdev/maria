"""
Binary protocol and data structures for Maria IDS (Kernel <-> User space Netlink IPC)
"""

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

# Netlink constants
MARIA_NL_UNIT = 2  # NETLINK_USERSOCK

# Message types
MARIA_MSG_REGISTER = 1
MARIA_MSG_UNREGISTER = 2
MARIA_MSG_HEARTBEAT = 3
MARIA_MSG_PACKET = 4
MARIA_MSG_ACK = 5

# TCP flags bitmasks
MARIA_TCP_FIN = 0x01
MARIA_TCP_SYN = 0x02
MARIA_TCP_RST = 0x04
MARIA_TCP_PSH = 0x08
MARIA_TCP_ACK = 0x10
MARIA_TCP_URG = 0x20

# Binary format definitions
# Netlink header: len (4B), type (2B), flags (2B), seq (4B), pid (4B) = 16B
NL_HDR_FMT = "<IHHII"
NL_HDR_SIZE = struct.calcsize(NL_HDR_FMT)

# Maria Netlink msg header: type (4B), len (4B) = 8B
MARIA_HDR_FMT = "<II"
MARIA_HDR_SIZE = struct.calcsize(MARIA_HDR_FMT)

# Packet data:
# Q: timestamp_ns (8B)
# 4s: src_ip (4B)
# 4s: dst_ip (4B)
# H: src_port (2B)
# H: dst_port (2B)
# H: payload_len (2B)
# H: total_len (2B)
# B: protocol (1B)
# B: tcp_flags (1B)
# 16s: ifname (16B)
# 1024s: payload (1024B)
# Total: 1066B
PKT_DATA_FMT = "<Q4s4sHHHHBB16s1024s"
PKT_DATA_SIZE = struct.calcsize(PKT_DATA_FMT)

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


@dataclass
class PacketEvent:
    timestamp_ns: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol_num: int
    protocol_name: str
    tcp_flags_val: int
    tcp_flags: Dict[str, bool]
    ifname: str
    total_len: int
    payload_len: int
    payload: bytes
    raw_packet_hex: str = ""

    @property
    def timestamp_str(self) -> str:
        sec = self.timestamp_ns / 1_000_000_000.0
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sec))

    @property
    def tcp_flags_str(self) -> str:
        if self.protocol_name != "TCP":
            return "-"
        active = [k for k, v in self.tcp_flags.items() if v]
        return ",".join(active) if active else "NONE"


def parse_tcp_flags(flags_byte: int) -> Dict[str, bool]:
    return {
        "FIN": bool(flags_byte & MARIA_TCP_FIN),
        "SYN": bool(flags_byte & MARIA_TCP_SYN),
        "RST": bool(flags_byte & MARIA_TCP_RST),
        "PSH": bool(flags_byte & MARIA_TCP_PSH),
        "ACK": bool(flags_byte & MARIA_TCP_ACK),
        "URG": bool(flags_byte & MARIA_TCP_URG),
    }


def decode_netlink_message(data: bytes) -> Optional[PacketEvent]:
    """Decode raw buffer received from Netlink socket into PacketEvent."""
    if len(data) < NL_HDR_SIZE + MARIA_HDR_SIZE:
        return None

    # Unpack Netlink Header
    nl_len, nl_type, nl_flags, nl_seq, nl_pid = struct.unpack_from(NL_HDR_FMT, data, 0)

    # Unpack Maria Header
    msg_type, msg_len = struct.unpack_from(MARIA_HDR_FMT, data, NL_HDR_SIZE)

    if msg_type != MARIA_MSG_PACKET:
        return None

    offset = NL_HDR_SIZE + MARIA_HDR_SIZE
    if len(data) < offset + PKT_DATA_SIZE:
        return None

    (
        timestamp_ns,
        src_ip_bytes,
        dst_ip_bytes,
        src_port,
        dst_port,
        payload_len,
        total_len,
        protocol_num,
        tcp_flags_val,
        ifname_bytes,
        payload_bytes,
    ) = struct.unpack_from(PKT_DATA_FMT, data, offset)

    try:
        src_ip = socket.inet_ntoa(src_ip_bytes)
        dst_ip = socket.inet_ntoa(dst_ip_bytes)
    except Exception:
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"

    ifname = ifname_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
    actual_payload = payload_bytes[: min(payload_len, 1024)]
    proto_name = IP_PROTOCOLS.get(protocol_num, f"PROTO_{protocol_num}")

    return PacketEvent(
        timestamp_ns=timestamp_ns,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol_num=protocol_num,
        protocol_name=proto_name,
        tcp_flags_val=tcp_flags_val,
        tcp_flags=parse_tcp_flags(tcp_flags_val),
        ifname=ifname,
        total_len=total_len,
        payload_len=payload_len,
        payload=actual_payload,
        raw_packet_hex=actual_payload.hex(),
    )


def encode_control_msg(msg_type: int, pid: int = 0) -> bytes:
    """Encode control message (REGISTER, UNREGISTER, HEARTBEAT) with Netlink header."""
    maria_payload = struct.pack(MARIA_HDR_FMT, msg_type, 0)
    total_len = NL_HDR_SIZE + len(maria_payload)
    nl_hdr = struct.pack(NL_HDR_FMT, total_len, 0, 0, 0, pid)
    return nl_hdr + maria_payload
