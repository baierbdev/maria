# AGENTS.md - Developer & Agent Guide for Maria IDS

This document provides instructions, architectural guidelines, and conventions for AI agents and human developers maintaining or extending **Maria IDS**.

---

## 1. Project Overview

**Maria IDS** is a Kernel-Assisted Network Intrusion Detection & Prevention System (NIDS/NIPS).
It is composed of two primary layers:
1. **Kernel Space (`src/`)**: A Linux Kernel Module (LKM) that captures raw socket buffers (`sk_buff`) directly at the device layer using `dev_add_pack` (operating in parallel with the Linux network stack and Netfilter) and streams packet data to user space via a Netlink socket (`NETLINK_USERSOCK`, unit 2).
2. **User Space (`userspace/`)**: A daemon that receives packet data over Netlink, analyzes traffic using multi-layered heuristic, signature, and entropy-based anomaly models, dynamically manages firewall rules (`nftables` / `iptables`), and logs forensic details.

---

## 2. Core Architectural Principles & Rules

> [!IMPORTANT]
> **No Netfilter in Kernel Space**:
> Do NOT register Netfilter hooks (`nf_register_net_hook`, `nf_hook_ops`) inside the kernel module. Packet interception MUST remain based on `struct packet_type` registered via `dev_add_pack()`.

### Kernel Layer Constraints
* **Parallel Packet Processing**: The packet handler `maria_packet_rcv()` runs inside the kernel receive path.
* **Reference Counting**: The kernel increments `skb->users` before calling `func` in `struct packet_type`. Therefore, the handler MUST release this reference by calling `kfree_skb(skb)` before returning `NET_RX_SUCCESS` (0).
* **Safe Header Parsing**: Never cast `skb->data` directly without length and boundary verification. Always use `skb_header_pointer()` or verify `skb->len` before reading protocol headers.
* **Clean Unregistration**: Always pair `dev_add_pack(&maria_packet_type)` with `dev_remove_pack(&maria_packet_type)` and release the Netlink socket with `netlink_kernel_release()` in `maria_exit()`.

### Binary Protocol Synchronization
The binary protocol is defined in:
* C: `src/packet_protocol.h`
* Python: `userspace/protocol.py`

When modifying packet fields or adding new control message types:
1. Update `src/packet_protocol.h` with exact `__attribute__((packed))` layouts.
2. Update the corresponding `struct.unpack_from` format strings (`PKT_DATA_FMT`, `NL_HDR_FMT`, `MARIA_HDR_FMT`) in `userspace/protocol.py`.
3. Verify byte sizes match between C `sizeof` and Python `struct.calcsize`.
4. Run `python3 tests/test_detection.py` to ensure protocol roundtrip integrity.

---

## 3. Directory Layout

```text
maria/
├── AGENTS.md                    # This agent reference guide
├── README.md                    # User-facing overview and quickstart
├── Makefile                     # Kernel build system (dynamic header detection)
├── src/
│   ├── main.c                   # Kernel module (dev_add_pack + Netlink sender)
│   └── packet_protocol.h        # Shared C struct definitions
├── userspace/
│   ├── daemon.py                # Main user-space daemon and event loop
│   ├── detector.py              # Multi-layer threat analysis engine
│   ├── firewall.py              # nftables / iptables / dryrun rule manager
│   ├── logger.py                # Structured JSONL and audit logging
│   └── protocol.py              # Python Netlink binary serializer/deserializer
├── tests/
│   ├── test_detection.py        # Automated unit test suite
│   └── simulate_traffic.py      # Synthetic traffic injector over Netlink
└── logs/                        # Runtime generated logs (firewall & malicious packets)
```

---

## 4. Key Workflows & Commands

### Building the Kernel Module
```bash
make
```
To clean build artifacts:
```bash
make clean
```

### Running Unit Tests
Always run unit tests after modifying detection algorithms, firewall logic, or protocol definitions:
```bash
python3 tests/test_detection.py
```

### Running End-to-End Simulation
To test the entire pipeline without loading the kernel module into the running kernel or requiring root privileges:
1. Launch daemon in dry-run mode:
   ```bash
   python3 userspace/daemon.py --backend dryrun -v
   ```
2. Note the Netlink PID printed in the log (e.g. `21105`).
3. Inject synthetic attack scenarios:
   ```bash
   python3 tests/simulate_traffic.py --pid <NETLINK_PID> --scenario all
   ```
4. Verify output in `logs/firewall.log` and `logs/malicious_packets.jsonl`.

### Live Deployment (Requires Root)
```bash
# Load module (capture_loopback=1 optional for local interface testing)
sudo insmod src/main.ko capture_loopback=1

# Start daemon with nftables backend
sudo python3 userspace/daemon.py --backend nftables

# Unload module
sudo rmmod main
```

---

## 5. Threat Detection Reference

Detection logic is centralized in `userspace/detector.py`:

| Threat Type | Mechanism | Key Parameters / Trigger |
| :--- | :--- | :--- |
| `TCP_NULL_SCAN` | TCP flags inspection | Flags value == 0 |
| `TCP_XMAS_SCAN` | TCP flags inspection | FIN, PSH, and URG all set |
| `TCP_SYN_FIN_ANOMALY` | TCP flags inspection | Both SYN and FIN set |
| `PORT_SCAN` | Sliding window (`deque`) | $\ge 8$ unique ports targeted within 5.0s |
| `SYN_FLOOD` | Rate tracker (`deque`) | $\ge 40$ SYN packets within 2.0s |
| `SQL_INJECTION` | Regex signature matching | `UNION SELECT`, `' OR 1=1`, `information_schema` |
| `COMMAND_INJECTION` | Regex signature matching | `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell` |
| `PATH_TRAVERSAL` | Regex signature matching | `../../etc/passwd`, `../../windows/system32` |
| `HIGH_ENTROPY_PAYLOAD` | Shannon entropy $H(X)$ | Entropy $\ge 7.3$ on non-TLS ports |

---

## 6. Firewall Management Reference

Firewall logic is centralized in `userspace/firewall.py`:

* **`nftables` Mode (Recommended for modern Linux)**:
  * Table: `inet maria_filter`
  * Set: `blocked_ipv4 { type ipv4_addr; }`
  * Chain: `input { type filter hook input priority -10; policy accept; }`
  * Drop Rule: `ip saddr @blocked_ipv4 drop`
  * Add IP: `nft add element inet maria_filter blocked_ipv4 { <IP> }`
* **`iptables` Mode**:
  * Chain: `MARIA_BLOCK`
  * Jump rule: `iptables -I INPUT 1 -j MARIA_BLOCK`
  * Drop rule: `iptables -I MARIA_BLOCK 1 -s <IP> -j DROP`
* **`dryrun` Mode**:
  * Emulates all firewall rules without altering system packet filters.
* **TTL Handling**:
  * Active bans are tracked in `active_bans[ip]`.
  * The daemon calls `cleanup_expired()` periodically to unblock expired IPs.
  * On shutdown (`SIGINT`/`SIGTERM`), `flush_all()` cleanly deletes active rules.
