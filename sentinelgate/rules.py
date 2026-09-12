"""Policy model, validation, and nftables rendering for SentinelGate."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    RATE_LIMIT = "rate_limit"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


@dataclass
class Rule:
    name: str
    action: Action
    protocol: Protocol = Protocol.ANY
    src: str = "any"
    dst: str = "any"
    dst_port: str | None = None
    rate_limit: str | None = None
    comment: str = ""
    pci_dss_ref: str | None = None
    priority: int = 100

    def matches(self, pkt: Packet) -> bool:
        if self.protocol != Protocol.ANY and pkt.protocol.lower() != self.protocol.value:
            return False
        if not self._ip_matches(self.src, pkt.src_ip):
            return False
        if not self._ip_matches(self.dst, pkt.dst_ip):
            return False
        return not self.dst_port or self._port_matches(self.dst_port, pkt.dst_port)

    @staticmethod
    def _ip_matches(rule_val: str, pkt_ip: str) -> bool:
        if rule_val.strip().lower() == "any":
            return True
        try:
            address = ipaddress.ip_address(pkt_ip)
        except ValueError:
            return False
        for candidate in rule_val.split(","):
            candidate = candidate.strip()
            try:
                if address in ipaddress.ip_network(candidate, strict=False):
                    return True
            except ValueError:
                if candidate == pkt_ip:
                    return True
        return False

    @staticmethod
    def _port_matches(rule_val: str, pkt_port: int | None) -> bool:
        if pkt_port is None:
            return False
        for part in rule_val.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo <= pkt_port <= hi:
                    return True
            elif int(part) == pkt_port:
                return True
        return False

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.name.strip():
            errors.append("rule name cannot be empty")
        if self.priority < 0:
            errors.append("priority must be >= 0")
        for field_name, value in (("src", self.src), ("dst", self.dst)):
            if value != "any":
                for candidate in value.split(","):
                    try:
                        ipaddress.ip_network(candidate.strip(), strict=False)
                    except ValueError:
                        errors.append(f"{field_name} contains invalid IP/CIDR: {candidate.strip()}")
        if self.dst_port:
            try:
                for part in self.dst_port.split(","):
                    part = part.strip()
                    if "-" in part:
                        lo, hi = (int(x) for x in part.split("-", 1))
                        if not (1 <= lo <= hi <= 65535):
                            raise ValueError
                    elif not (1 <= int(part) <= 65535):
                        raise ValueError
            except ValueError:
                errors.append("dst_port must contain ports/ranges from 1-65535")
            if self.protocol not in (Protocol.TCP, Protocol.UDP):
                errors.append("dst_port requires protocol tcp or udp")
        if self.action == Action.RATE_LIMIT:
            if not self.rate_limit:
                errors.append("rate_limit action requires rate_limit, e.g. 10/second")
            elif not re.fullmatch(r"[1-9][0-9]*/(second|minute)", str(self.rate_limit)):
                errors.append("rate_limit must look like 10/second or 100/minute")
        elif self.rate_limit:
            errors.append("rate_limit is only valid when action is rate_limit")
        if not self.comment.strip():
            errors.append("comment/justification is required")
        return errors


@dataclass(frozen=True)
class Packet:
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: int | None = None
    src_port: int | None = None


@dataclass
class Policy:
    name: str
    rules: list[Rule] = field(default_factory=list)
    default_action: Action = Action.DENY

    def __post_init__(self) -> None:
        if self.default_action != Action.DENY:
            raise ValueError("SentinelGate policies must be default-deny")
        self.validate()

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise TypeError("policy YAML must contain an object at the top level")
        default_action = Action(raw.get("default_action", "deny"))
        rules = []
        for r in raw.get("rules", []):
            rules.append(Rule(
                name=str(r["name"]), action=Action(r.get("action", "deny")),
                protocol=Protocol(r.get("protocol", "any")), src=str(r.get("src", "any")),
                dst=str(r.get("dst", "any")), dst_port=str(r["dst_port"]) if r.get("dst_port") is not None else None,
                rate_limit=r.get("rate_limit"), comment=str(r.get("comment", "")),
                pci_dss_ref=r.get("pci_dss_ref"), priority=int(r.get("priority", 100)),
            ))
        return cls(name=str(raw.get("name", "unnamed-policy")), rules=rules, default_action=default_action)

    def validate(self) -> None:
        errors: list[str] = []
        seen: set[str] = set()
        for rule in self.rules:
            if rule.name in seen:
                errors.append(f"duplicate rule name: {rule.name}")
            seen.add(rule.name)
            errors.extend(f"{rule.name}: {e}" for e in rule.validate())
        if errors:
            raise ValueError("Invalid policy:\n- " + "\n- ".join(errors))

    def ordered_rules(self) -> list[Rule]:
        return sorted(self.rules, key=lambda r: (r.priority, r.name))

    def to_nftables(self, table: str = "inet sentinelgate") -> str:
        self.validate()
        lines = [
            f"# Generated by SentinelGate — policy: {self.name}",
            f"# Default action: {self.default_action.value.upper()}",
            "flush ruleset",
            f"table {table} {{",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            "",
            "        ct state invalid drop",
            "        ct state established,related accept",
            "        iif lo accept",
            "",
        ]
        for rule in self.ordered_rules():
            lines.append(f"        # [{rule.priority}] {rule.name} — {rule.comment}")
            lines.append(f"        {self._rule_to_nft(rule)}")
        lines += [
            "",
            '        log prefix "SentinelGate-DROP: " drop',
            "    }",
            "}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _rule_to_nft(rule: Rule) -> str:
        parts: list[str] = []
        if rule.protocol != Protocol.ANY:
            parts.append(rule.protocol.value)
        for field_name, value in (("saddr", rule.src), ("daddr", rule.dst)):
            if value != "any":
                vals = [v.strip() for v in value.split(",")]
                keyword = "ip6" if vals and all(":" in v for v in vals) else "ip"
                rendered = f"{{ {', '.join(vals)} }}" if len(vals) > 1 else vals[0]
                parts.append(f"{keyword} {field_name} {rendered}")
        if rule.dst_port:
            ports = ", ".join(x.strip() for x in rule.dst_port.split(","))
            rendered = f"{{ {ports} }}" if "," in rule.dst_port else ports
            parts.append(f"dport {rendered}")
        if rule.action == Action.RATE_LIMIT:
            parts.append(f"limit rate {rule.rate_limit}")
        verb = "accept" if rule.action in (Action.ALLOW, Action.RATE_LIMIT) else "drop"
        return f"{' '.join(parts)} {verb}".strip()
