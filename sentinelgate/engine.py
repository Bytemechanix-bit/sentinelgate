"""Deterministic policy simulation and guarded nftables deployment."""
from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - required for guarded nftables deployment
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .rules import Action, Packet, Policy


@dataclass(frozen=True)
class Verdict:
    packet: Packet
    action: Action
    matched_rule: str
    reason: str


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str, max_per_second: int) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        hits[:] = [t for t in hits if now - t < 1.0]
        if len(hits) >= max_per_second:
            return False
        hits.append(now)
        return True


class FirewallEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._rate_limiter = RateLimiter()
        self._established: set[tuple] = set()
        self.log: list[Verdict] = []

    @staticmethod
    def _flow_key(pkt: Packet) -> tuple:
        return (pkt.src_ip, pkt.dst_ip, pkt.protocol.lower(), pkt.src_port, pkt.dst_port)

    @staticmethod
    def _reverse_key(pkt: Packet) -> tuple:
        return (pkt.dst_ip, pkt.src_ip, pkt.protocol.lower(), pkt.dst_port, pkt.src_port)

    def evaluate(self, pkt: Packet) -> Verdict:
        if self._flow_key(pkt) in self._established or self._reverse_key(pkt) in self._established:
            return self._record(Verdict(pkt, Action.ALLOW, "ESTABLISHED", "existing connection"))
        for rule in self.policy.ordered_rules():
            if not rule.matches(pkt):
                continue
            if rule.action == Action.RATE_LIMIT:
                limit = int(str(rule.rate_limit).split("/", 1)[0])
                if not self._rate_limiter.allow(pkt.src_ip, limit):
                    return self._record(Verdict(pkt, Action.DENY, rule.name, "rate limit exceeded"))
                return self._record(Verdict(pkt, Action.ALLOW, rule.name, "rate limit permitted"))
            if rule.action == Action.ALLOW:
                self._established.add(self._flow_key(pkt))
            return self._record(Verdict(pkt, rule.action, rule.name, f"matched priority {rule.priority}"))
        return self._record(Verdict(pkt, Action.DENY, "DEFAULT_DENY", "no rule matched"))

    def _record(self, verdict: Verdict) -> Verdict:
        self.log.append(verdict)
        return verdict

    def simulate(self, packets: list[Packet]) -> list[Verdict]:
        return [self.evaluate(packet) for packet in packets]

    def apply_live(self, ruleset_path: str = "/etc/sentinelgate/ruleset.nft") -> None:
        nft = shutil.which("nft")
        if nft is None:
            raise RuntimeError("nft binary not found; live mode requires nftables on Linux")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError("live apply requires root privileges")
        path = Path(ruleset_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.policy.to_nftables(), encoding="utf-8")
        check = subprocess.run([nft, "-c", "-f", str(path)], capture_output=True, text=True, check=False)  # nosec B603
        if check.returncode != 0:
            raise RuntimeError(f"nft validation failed: {check.stderr.strip()}")
        result = subprocess.run([nft, "-f", str(path)], capture_output=True, text=True, check=False)  # nosec B603
        if result.returncode != 0:
            raise RuntimeError(f"nft load failed: {result.stderr.strip()}")
