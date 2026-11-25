# Maria IDS

**Maria** is a Kernel-Assisted Network Intrusion Detection & Prevention System (NIDS/NIPS). It captures raw socket buffers (`sk_buff`) in parallel with the network stack without using the Netfilter infrastructure, streams packet metadata to a user-space detection model over a Netlink socket, dynamically provisions firewall rules (`nftables` / `iptables`), and generates forensic logs.

---

## Architecture

```
                  +-----------------------------------------+
                  |         Network Interface Card          |
                  +-----------------------------------------+
                                       |
                                       v
                             __netif_receive_skb()
                                       |
                   +-------------------+-------------------+
                   |                                       |
       [Parallel Kernel Tap]                    [Standard Network Stack]
       dev_add_pack(&maria_pt)                  Kernel IP Stack & Netfilter
                   |                                       |
         maria_packet_rcv()                                |
     (Parses skb, L3/L4, Payload)                          |
                   |                                       |
           Netlink Message                                 |
        (NETLINK_USERSOCK unit 2)                          |
                   |                                       |
                   v                                       v
    +-----------------------------+               Legitimate Traffic
    |  User Space Daemon (Maria)  |               passes uninterrupted
    +-----------------------------+
                   |
     +-------------+-------------+
     |                           |
     v                           v
Threat Detection Engine   Firewall Provisioner
- TCP Anomaly (NULL/XMAS) - nftables atomic sets
- Stateful Port Scan      - iptables chain
- Signature Matching      - Configurable TTL
- Shannon Entropy         - Auto unblock
     |                           |
     +-------------+-------------+
                   |
                   v
        Structured Logging
        - logs/malicious_packets.jsonl
        - logs/firewall.log
```

---

## Directory Structure

* **`src/`**
  * `main.c`: Linux Kernel Module (LKM) using `dev_add_pack` (`struct packet_type`) and Netlink socket (`NETLINK_USERSOCK`).
  * `packet_protocol.h`: Shared C struct definitions for Netlink message serialization between kernel and user space.
* **`userspace/`**
  * `daemon.py`: Main entrypoint for the user space daemon.
  * `protocol.py`: Python Netlink decoder and binary deserializer matching kernel structs.
  * `detector.py`: Multi-layered threat analysis (TCP flag anomalies, sliding window port scan detection, payload signatures, Shannon entropy).
  * `firewall.py`: Automated firewall manager supporting `nftables`, `iptables`, and `dryrun`.
  * `logger.py`: Structured JSONL logging for malicious packets and text audit logging for firewall events.
* **`tests/`**
  * `test_detection.py`: Automated unit tests covering all threat vectors and protocol decoding.
  * `simulate_traffic.py`: Synthetic packet injector over Netlink for end-to-end testing without external network equipment.

---

## Quick Start

### 1. Build the Kernel Module

```bash
make
```

### 2. Run Automated Unit Tests

```bash
python3 tests/test_detection.py
```

### 3. Load the Kernel Module (Requires Root)

```bash
# Insert module (optional: capture_loopback=1 to capture loopback traffic)
sudo insmod maria.ko capture_loopback=1

# Check kernel logs
dmesg | tail -n 10
```

### 4. Run User-Space Daemon

```bash
# Run with nftables (requires root)
sudo python3 userspace/daemon.py --backend nftables

# Or run with iptables
sudo python3 userspace/daemon.py --backend iptables

# Or run in simulated dry-run mode (no root required)
python3 userspace/daemon.py --backend dryrun -v
```

### 5. Test with Traffic Simulator

In a separate terminal, inject synthetic test traffic scenarios (benign, portscan, SQL injection, command injection, XMAS scan, high-entropy shellcode):

```bash
python3 tests/simulate_traffic.py --pid <DAEMON_NETLINK_PID> --scenario all
```

### 6. Inspect Generated Logs

* **Firewall Actions**:
  ```bash
  cat logs/firewall.log
  ```
* **Malicious Packet Details**:
  ```bash
  cat logs/malicious_packets.jsonl | jq .
  ```

---

## Unloading the Kernel Module

```bash
sudo rmmod maria
```
