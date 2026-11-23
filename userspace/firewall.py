"""
Automated Firewall Rule Manager for Maria IDS:
- Supports modern nftables (atomic sets) and classic iptables (dedicated chain)
- Dry-run simulation mode for testing without root
- TTL-based automatic expiration of banned IPs
- State tracking and duplicate prevention
"""

import subprocess
import time
from typing import Dict, Any, Optional
from logger import IDSLogger


class FirewallManager:
    def __init__(
        self,
        backend: str = "nftables",
        default_ttl: int = 300,
        dry_run: bool = False,
        logger: Optional[IDSLogger] = None,
    ):
        self.backend = backend.lower()
        self.default_ttl = default_ttl
        self.dry_run = dry_run
        self.logger = logger or IDSLogger()

        # ip -> {"banned_at": float, "ttl": int, "reason": str}
        self.active_bans: Dict[str, Dict[str, Any]] = {}

        self._init_firewall()

    def _exec(self, cmd: list) -> bool:
        cmd_str = " ".join(cmd)
        if self.dry_run:
            self.logger.debug(f"[DRY-RUN] Executing: {cmd_str}")
            return True

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                self.logger.error(f"Firewall command failed ({cmd_str}): {res.stderr.strip()}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Execution error on '{cmd_str}': {e}")
            return False

    def _init_firewall(self):
        """Set up necessary chains/tables."""
        if self.backend == "nftables":
            self.logger.info("Initializing nftables table and set (inet maria_filter)...")
            self._exec(["nft", "add", "table", "inet", "maria_filter"])
            self._exec(["nft", "add", "set", "inet", "maria_filter", "blocked_ipv4", "{ type ipv4_addr; }"])
            self._exec(["nft", "add", "chain", "inet", "maria_filter", "input", "{ type filter hook input priority -10; policy accept; }"])
            self._exec(["nft", "add", "rule", "inet", "maria_filter", "input", "ip", "saddr", "@blocked_ipv4", "drop"])
        elif self.backend == "iptables":
            self.logger.info("Initializing iptables chain (MARIA_BLOCK)...")
            # Create chain if not exists
            self._exec(["iptables", "-N", "MARIA_BLOCK"])
            # Ensure jump rule exists at beginning of INPUT
            check_res = subprocess.run(["iptables", "-C", "INPUT", "-j", "MARIA_BLOCK"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) if not self.dry_run else None
            if self.dry_run or (check_res and check_res.returncode != 0):
                self._exec(["iptables", "-I", "INPUT", "1", "-j", "MARIA_BLOCK"])
        elif self.backend == "dryrun":
            self.dry_run = True
            self.logger.info("Firewall backend set to simulated dry-run mode.")
        else:
            self.logger.error(f"Unknown firewall backend '{self.backend}', falling back to dryrun.")
            self.backend = "dryrun"
            self.dry_run = True

    def block_ip(self, ip: str, reason: str, ttl: Optional[int] = None) -> bool:
        """Add IP to firewall blocklist."""
        # Avoid blocking private loopback / multicast / zero
        if ip in {"127.0.0.1", "0.0.0.0"} or ip.startswith("127."):
            self.logger.warning(f"Refusing to block loopback IP {ip}")
            return False

        now = time.time()
        effective_ttl = self.default_ttl if ttl is None else ttl

        if ip in self.active_bans:
            # Refresh TTL
            self.active_bans[ip]["banned_at"] = now
            self.active_bans[ip]["ttl"] = effective_ttl
            self.logger.debug(f"Refreshed ban TTL for {ip}")
            return True

        rule_cmd = ""
        success = False

        if self.backend == "nftables":
            cmd = ["nft", "add", "element", "inet", "maria_filter", "blocked_ipv4", f"{{ {ip} }}"]
            rule_cmd = " ".join(cmd)
            success = self._exec(cmd)
        elif self.backend == "iptables":
            cmd = ["iptables", "-I", "MARIA_BLOCK", "1", "-s", ip, "-j", "DROP"]
            rule_cmd = " ".join(cmd)
            success = self._exec(cmd)
        elif self.backend == "dryrun":
            rule_cmd = f"SIMULATED_DROP {ip}"
            success = True

        if success:
            self.active_bans[ip] = {
                "banned_at": now,
                "ttl": effective_ttl,
                "reason": reason,
                "rule_spec": rule_cmd,
            }
            self.logger.log_firewall_action(
                action="BLOCK",
                target_ip=ip,
                backend=self.backend,
                reason=reason,
                rule_spec=rule_cmd,
                ttl_seconds=effective_ttl,
            )

        return success

    def unblock_ip(self, ip: str, reason: str = "MANUAL_OR_EXPIRED") -> bool:
        """Remove IP from firewall blocklist."""
        if ip not in self.active_bans:
            return False

        ban_info = self.active_bans.pop(ip)
        rule_cmd = ""
        success = False

        if self.backend == "nftables":
            cmd = ["nft", "delete", "element", "inet", "maria_filter", "blocked_ipv4", f"{{ {ip} }}"]
            rule_cmd = " ".join(cmd)
            success = self._exec(cmd)
        elif self.backend == "iptables":
            cmd = ["iptables", "-D", "MARIA_BLOCK", "-s", ip, "-j", "DROP"]
            rule_cmd = " ".join(cmd)
            success = self._exec(cmd)
        elif self.backend == "dryrun":
            rule_cmd = f"SIMULATED_UNDROP {ip}"
            success = True

        if success:
            self.logger.log_firewall_action(
                action="UNBLOCK",
                target_ip=ip,
                backend=self.backend,
                reason=reason,
                rule_spec=rule_cmd,
            )

        return success

    def cleanup_expired(self):
        """Check for expired IP bans and unblock them."""
        now = time.time()
        expired_ips = [
            ip
            for ip, info in self.active_bans.items()
            if info["ttl"] > 0 and (now - info["banned_at"]) >= info["ttl"]
        ]
        for ip in expired_ips:
            self.unblock_ip(ip, reason="TTL_EXPIRED")

    def flush_all(self):
        """Cleanly remove all active rules and tear down firewall objects."""
        self.logger.info(f"Flushing all active firewall rules ({len(self.active_bans)} bans)...")
        for ip in list(self.active_bans.keys()):
            self.unblock_ip(ip, reason="SHUTDOWN_FLUSH")

        if self.backend == "nftables":
            self._exec(["nft", "delete", "table", "inet", "maria_filter"])
        elif self.backend == "iptables":
            self._exec(["iptables", "-D", "INPUT", "-j", "MARIA_BLOCK"])
            self._exec(["iptables", "-F", "MARIA_BLOCK"])
            self._exec(["iptables", "-X", "MARIA_BLOCK"])
